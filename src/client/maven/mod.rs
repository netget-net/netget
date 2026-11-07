//! Maven client implementation
pub mod actions;

pub use actions::MavenClientProtocol;

use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use crate::client::http_fetch::FetchClient;
use crate::client::llm_budget::call_llm_for_client;
use crate::client::maven::actions::MAVEN_CLIENT_CONNECTED_EVENT;
use crate::llm::actions::client_trait::{Client, ClientActionResult};
use crate::llm::ollama_client::OllamaClient;
use crate::llm::ClientLlmResult;
use crate::logging::emit::Log;
use crate::protocol::Event;
use crate::state::app_state::AppState;
use crate::state::client_handles::{ClientCommand, ClientSendOutcome};
use crate::state::{AccessLogOwner, ClientId, ClientStatus};

/// One completed Maven fetch: the payload its response event will carry, plus a summary
/// of what the repository actually answered.
///
/// Split out of the operations below so the injected-command loop can await the HTTP
/// round-trip - and report a truthful outcome - without also awaiting the LLM call the
/// response event triggers.
pub struct MavenFetch {
    pub event_data: serde_json::Value,
    pub summary: String,
}

/// What one executed action did.
enum Applied {
    /// The action ran; `detail` says what it did.
    Executed(String),
    /// The action asked to end the session.
    Disconnect,
}

/// How a Maven operation is issued.
#[derive(Clone, Copy)]
enum Dispatch {
    /// Spawn the whole operation and return immediately. Used by the connected-event
    /// handler, which runs inline in `connect()` and must not block client creation on a
    /// download that can take the full 30s timeout.
    Spawn,
    /// Await the HTTP exchange so the caller can report what actually happened, then raise
    /// the response event from its own registered task. Used by the injected-command loop,
    /// so a parked manual handler cannot wedge it for the length of a human's think time.
    Await,
}

/// Cap a repository document before it becomes event data.
///
/// `pom_content` and `metadata_content` went into the event verbatim, hence into the
/// LLM prompt verbatim. `maven-metadata.xml` for a busy artifact is routinely hundreds
/// of kilobytes and a hostile repository can return arbitrarily more, so this was an
/// unbounded prompt driven by a remote peer — and, before the depth bound below, an
/// amplifier: every follow-up turn shipped another full document.
///
/// Char-boundary truncation via `truncate_for_log`, never `&s[..N]`.
fn truncate_document(body: String) -> String {
    const MAX_DOCUMENT_BYTES: usize = 16 * 1024;
    if body.len() <= MAX_DOCUMENT_BYTES {
        return body;
    }
    crate::utils::truncate_for_log(&body, MAX_DOCUMENT_BYTES)
}

/// The one `reqwest::Client` this protocol uses, built once.
///
/// Building a client is a **blocking** operation: it sets up the rustls stack and
/// loads the platform root store, which on macOS reads the keychain through
/// Security.framework, synchronously and serialised across processes. Every request
/// here used to build a fresh one on the async runtime, which parks a tokio worker —
/// the systemic defect `CLAUDE.md` records as having stalled a whole client runtime.
///
/// So: `OnceCell`, and `spawn_blocking` for the build itself.
#[cfg(not(target_arch = "wasm32"))]
static SHARED_HTTP_CLIENT: tokio::sync::OnceCell<reqwest::Client> =
    tokio::sync::OnceCell::const_new();

#[cfg(not(target_arch = "wasm32"))]
async fn reqwest_client() -> Result<reqwest::Client> {
    SHARED_HTTP_CLIENT
        .get_or_try_init(|| async {
            tokio::task::spawn_blocking(|| {
                reqwest::Client::builder()
                    .timeout(std::time::Duration::from_secs(30))
                    .user_agent("NetGet-Maven/1.0")
                    .build()
            })
            .await
            .context("building the HTTP client panicked")?
            .context("failed to build the HTTP client")
        })
        .await
        .cloned()
}

/// The HTTP client every request here uses: the shared reqwest client natively
/// ([`reqwest_client`]), and in the browser build the hyper HTTP/1.1 transport over the page's
/// virtual loopback ([`crate::client::http_fetch`]) with the same timeout and User-Agent.
async fn shared_http_client() -> Result<FetchClient> {
    #[cfg(not(target_arch = "wasm32"))]
    let client = FetchClient::from_reqwest(reqwest_client().await?);
    #[cfg(target_arch = "wasm32")]
    let client = FetchClient::transport(std::time::Duration::from_secs(30))
        .with_user_agent("NetGet-Maven/1.0");
    Ok(client)
}

/// How many model turns a single injected action may spawn before the chain is cut.
///
/// The Maven follow-up cycle is genuinely self-referential: `notify_maven` asks the
/// model, `execute_maven_action` runs what it answered, `apply_action` awaits the HTTP
/// exchange and then `spawn_notify` raises a response event — which is `notify_maven`
/// again. Nothing counted the turns, so a model (or the static handler this protocol's
/// own `get_startup_examples()` documents) that answers `maven_pom_received` with
/// another `download_pom` looped forever, burning one HTTP request *and one LLM call*
/// per turn, and registering two fresh tasks each time so the abort set grew without
/// bound too.
///
/// npm and pypi bound this structurally — their `run_follow_ups` routes only through
/// `perform_*` helpers that raise no event, so the chain is one deep. Maven's shape
/// cannot do that (its whole point is that a follow-up *is* a new turn), so it takes
/// the other answer CLAUDE.md gives: a depth bound, not silence. No boxing is needed
/// because the cycle already passes through `tokio::spawn`.
const MAX_FOLLOWUP_DEPTH: u8 = 6;

/// Maven client that interacts with Maven repositories
pub struct MavenClient;

impl MavenClient {
    /// Apply one already-parsed action against the live Maven client.
    ///
    /// The single place Maven actions become repository traffic, so an action injected
    /// from the dashboard behaves exactly like one the model produced. Under
    /// [`Dispatch::Await`] only the **network** half is awaited; the response event - and
    /// the LLM call it makes - is raised from its own registered task afterwards, so a
    /// `*` -> manual routing rule parking that event cannot wedge the command loop for the
    /// length of a human's think time. The outcome stays truthful because it describes what
    /// the repository actually answered, which is known before the event is raised.
    async fn apply_action(
        client_id: ClientId,
        result: ClientActionResult,
        dispatch: Dispatch,
        depth: u8,
        app_state: &Arc<AppState>,
        llm_client: &OllamaClient,
        status_tx: &mpsc::UnboundedSender<String>,
    ) -> Result<Applied> {
        let (name, data) = match result {
            ClientActionResult::Custom { name, data } => (name, data),
            ClientActionResult::Disconnect => return Ok(Applied::Disconnect),
            ClientActionResult::NoAction => return Ok(Applied::Executed("no_action".to_string())),
            ClientActionResult::WaitForMore => {
                return Ok(Applied::Executed("wait_for_more".to_string()))
            }
            ClientActionResult::SendData(_) => {
                return Ok(Applied::Executed(
                    "Maven owns no socket; raw send_data cannot be put on the wire".to_string(),
                ))
            }
            ClientActionResult::Multiple(_) => {
                return Ok(Applied::Executed(
                    "Maven produces no Multiple results; nothing executed".to_string(),
                ))
            }
        };

        let group_id = data["group_id"].as_str().unwrap_or_default().to_string();
        let artifact_id = data["artifact_id"].as_str().unwrap_or_default().to_string();
        let version = data["version"].as_str().unwrap_or_default().to_string();
        let packaging = data["packaging"].as_str().map(|s| s.to_string());

        match name.as_str() {
            "maven_download_artifact" => {
                let coords = format!("{group_id}:{artifact_id}:{version}");
                match dispatch {
                    Dispatch::Spawn => {
                        Self::spawn_operation(
                            client_id,
                            app_state,
                            Self::download_artifact(
                                client_id,
                                depth + 1,
                                group_id,
                                artifact_id,
                                version,
                                packaging,
                                app_state.clone(),
                                llm_client.clone(),
                                status_tx.clone(),
                            ),
                        )
                        .await;
                        Ok(Applied::Executed(format!(
                            "download_artifact {coords} dispatched"
                        )))
                    }
                    Dispatch::Await => {
                        let fetch = Self::perform_download_artifact(
                            client_id,
                            group_id,
                            artifact_id,
                            version,
                            packaging,
                            app_state,
                            status_tx,
                        )
                        .await?;
                        let detail = format!("download_artifact {coords} -> {}", fetch.summary);
                        Self::spawn_notify(
                            client_id,
                            depth + 1,
                            app_state,
                            &crate::client::maven::actions::MAVEN_CLIENT_ARTIFACT_DOWNLOADED_EVENT,
                            fetch.event_data,
                            llm_client,
                            status_tx,
                        )
                        .await;
                        Ok(Applied::Executed(detail))
                    }
                }
            }
            "maven_download_pom" => {
                let coords = format!("{group_id}:{artifact_id}:{version}");
                match dispatch {
                    Dispatch::Spawn => {
                        Self::spawn_operation(
                            client_id,
                            app_state,
                            Self::download_pom(
                                client_id,
                                depth + 1,
                                group_id,
                                artifact_id,
                                version,
                                app_state.clone(),
                                llm_client.clone(),
                                status_tx.clone(),
                            ),
                        )
                        .await;
                        Ok(Applied::Executed(format!(
                            "download_pom {coords} dispatched"
                        )))
                    }
                    Dispatch::Await => {
                        let fetch = Self::perform_download_pom(
                            client_id,
                            group_id,
                            artifact_id,
                            version,
                            app_state,
                            status_tx,
                        )
                        .await?;
                        let detail = format!("download_pom {coords} -> {}", fetch.summary);
                        Self::spawn_notify(
                            client_id,
                            depth + 1,
                            app_state,
                            &crate::client::maven::actions::MAVEN_CLIENT_POM_RECEIVED_EVENT,
                            fetch.event_data,
                            llm_client,
                            status_tx,
                        )
                        .await;
                        Ok(Applied::Executed(detail))
                    }
                }
            }
            "maven_search_versions" => {
                let coords = format!("{group_id}:{artifact_id}");
                match dispatch {
                    Dispatch::Spawn => {
                        Self::spawn_operation(
                            client_id,
                            app_state,
                            Self::search_versions(
                                client_id,
                                depth + 1,
                                group_id,
                                artifact_id,
                                app_state.clone(),
                                llm_client.clone(),
                                status_tx.clone(),
                            ),
                        )
                        .await;
                        Ok(Applied::Executed(format!(
                            "search_versions {coords} dispatched"
                        )))
                    }
                    Dispatch::Await => {
                        let fetch = Self::perform_search_versions(
                            client_id,
                            group_id,
                            artifact_id,
                            app_state,
                            status_tx,
                        )
                        .await?;
                        let detail = format!("search_versions {coords} -> {}", fetch.summary);
                        Self::spawn_notify(
                            client_id,
                            depth + 1,
                            app_state,
                            &crate::client::maven::actions::MAVEN_CLIENT_METADATA_RECEIVED_EVENT,
                            fetch.event_data,
                            llm_client,
                            status_tx,
                        )
                        .await;
                        Ok(Applied::Executed(detail))
                    }
                }
            }
            other => {
                warn!("Unknown Maven custom action: {}", other);
                Ok(Applied::Executed(format!(
                    "unknown Maven custom result '{other}' was not executed"
                )))
            }
        }
    }

    /// Run a whole operation (network + response event) as a registered background task.
    async fn spawn_operation(
        client_id: ClientId,
        app_state: &Arc<AppState>,
        operation: impl std::future::Future<Output = Result<()>> + Send + 'static,
    ) {
        // Registered with AppState so stop_client can abort this task —
        // dropping a JoinHandle only detaches it in Tokio.
        let handle = tokio::spawn(async move {
            if let Err(e) = operation.await {
                error!("Maven client {} operation failed: {}", client_id, e);
            }
        });
        app_state.register_client_task(client_id, handle).await;
    }

    /// Raise a response event from its own registered task, so the caller does not wait on
    /// the LLM call (which a manual routing rule can park for the intercept timeout).
    async fn spawn_notify(
        client_id: ClientId,
        depth: u8,
        app_state: &Arc<AppState>,
        event_type: &'static crate::protocol::EventType,
        event_data: serde_json::Value,
        llm_client: &OllamaClient,
        status_tx: &mpsc::UnboundedSender<String>,
    ) {
        let state = app_state.clone();
        let llm = llm_client.clone();
        let tx = status_tx.clone();
        let handle = tokio::spawn(async move {
            Self::notify_maven(client_id, depth, event_type, event_data, state, llm, tx).await;
        });
        app_state.register_client_task(client_id, handle).await;
    }

    /// Raise one response event, hand it to the LLM and dispatch whatever the model
    /// answers. The single LLM entry point for every Maven operation.
    async fn notify_maven(
        client_id: ClientId,
        depth: u8,
        event_type: &'static crate::protocol::EventType,
        event_data: serde_json::Value,
        app_state: Arc<AppState>,
        llm_client: OllamaClient,
        status_tx: mpsc::UnboundedSender<String>,
    ) {
        if depth > MAX_FOLLOWUP_DEPTH {
            Log::to(&status_tx).warn(format!(
                "Maven client {} follow-up chain cut at depth {} (limit {}): the model \
                 kept answering each response event with another repository operation. \
                 The chain is stopped, not the client.",
                client_id, depth, MAX_FOLLOWUP_DEPTH
            ));
            return;
        }

        let Some(instruction) = app_state.get_instruction_for_client(client_id).await else {
            return;
        };

        let protocol = Arc::new(crate::client::maven::actions::MavenClientProtocol::new());
        let event = Event::new(event_type, event_data);

        let memory = app_state
            .get_memory_for_client(client_id)
            .await
            .unwrap_or_default();

        match call_llm_for_client(
            &llm_client,
            &app_state,
            client_id.to_string(),
            &instruction,
            &memory,
            Some(&event),
            protocol.as_ref(),
            &status_tx,
        )
        .await
        {
            Ok(ClientLlmResult {
                actions,
                memory_updates,
            }) => {
                if let Some(mem) = memory_updates {
                    app_state.set_memory_for_client(client_id, mem).await;
                }

                // Execute actions from LLM response
                for action in actions {
                    match protocol.as_ref().execute_action(action) {
                        Ok(ClientActionResult::Custom { name, data }) => {
                            Self::execute_maven_action(
                                client_id,
                                depth,
                                name,
                                data,
                                app_state.clone(),
                                llm_client.clone(),
                                status_tx.clone(),
                            );
                        }
                        Ok(ClientActionResult::Disconnect) => {
                            // This arm used to log the disconnect and do nothing else,
                            // so the log asserted something that had not happened.
                            info!("Maven client {} disconnecting", client_id);
                            app_state
                                .update_client_status(client_id, ClientStatus::Disconnected)
                                .await;
                        }
                        Ok(other) => {
                            debug!("Maven client {} action result: {:?}", client_id, other);
                        }
                        Err(e) => {
                            // `_ => {}` swallowed this: a model answering with an unknown
                            // or malformed action produced no log at all.
                            warn!(
                                "Maven client {} could not execute the model's action: {}",
                                client_id, e
                            );
                        }
                    }
                }
            }
            Err(e) => {
                error!("LLM error for Maven client {}: {}", client_id, e);
            }
        }
    }

    /// Run [`Self::apply_action`] as a background task.
    ///
    /// Deliberately **synchronous**: it is called from [`Self::notify_maven`], which
    /// `apply_action` itself schedules, and an `async fn` there would make the future type
    /// infinitely recursive. Registering the handle is done from a second tiny task for the
    /// same reason — `register_client_task` is async.
    fn execute_maven_action(
        client_id: ClientId,
        depth: u8,
        name: String,
        data: serde_json::Value,
        app_state: Arc<AppState>,
        llm_client: OllamaClient,
        status_tx: mpsc::UnboundedSender<String>,
    ) {
        let registrar = app_state.clone();
        let handle = tokio::spawn(async move {
            let result = ClientActionResult::Custom { name, data };
            if let Err(e) = Self::apply_action(
                client_id,
                result,
                Dispatch::Await,
                depth,
                &app_state,
                &llm_client,
                &status_tx,
            )
            .await
            {
                error!("Maven client {} action failed: {}", client_id, e);
            }
        });
        // Registered with AppState so stop_client can abort this task —
        // dropping a JoinHandle only detaches it in Tokio.
        tokio::spawn(async move {
            registrar.register_client_task(client_id, handle).await;
        });
    }

    /// Serve injected commands until the client goes away.
    async fn command_loop(
        mut command_rx: mpsc::Receiver<ClientCommand>,
        client_id: ClientId,
        app_state: Arc<AppState>,
        llm_client: OllamaClient,
        status_tx: mpsc::UnboundedSender<String>,
    ) {
        use crate::llm::actions::protocol_trait::Protocol;
        let protocol = crate::client::maven::actions::MavenClientProtocol::new();

        while let Some(command) = command_rx.recv().await {
            let action = command.action.clone();
            let outcome = match protocol.execute_action(action.clone()) {
                Err(e) => Ok(ClientSendOutcome::Rejected {
                    error: e.to_string(),
                }),
                // Never `Sent`: reqwest owns the socket and does not report how many bytes
                // the request serialised to, so a byte count here would be invented.
                Ok(result) => match Self::apply_action(
                    client_id,
                    result,
                    Dispatch::Await,
                    0,
                    &app_state,
                    &llm_client,
                    &status_tx,
                )
                .await
                {
                    Ok(Applied::Executed(detail)) => Ok(ClientSendOutcome::Executed { detail }),
                    Ok(Applied::Disconnect) => Ok(ClientSendOutcome::Disconnected),
                    Err(e) => Err(e),
                },
            };

            let outcome_json = match &outcome {
                Ok(outcome) => serde_json::to_value(outcome).unwrap_or(serde_json::Value::Null),
                Err(e) => serde_json::json!({"error": e.to_string()}),
            };
            app_state
                .record_access_log(
                    AccessLogOwner::Client(client_id.as_u32()),
                    protocol.protocol_name(),
                    None,
                    "injected_action",
                    action,
                    vec![outcome_json],
                )
                .await;

            let disconnect = matches!(outcome, Ok(ClientSendOutcome::Disconnected));
            if let Err(e) = &outcome {
                Log::to(&status_tx).warn(format!(
                    "Maven client {} injected action failed: {}",
                    client_id, e
                ));
            }
            let _ = status_tx.send("__UPDATE_UI__".to_string());
            crate::client::command_support::reply(command, outcome);

            if disconnect {
                app_state
                    .update_client_status(client_id, ClientStatus::Disconnected)
                    .await;
                break;
            }
        }

        info!("Maven client {} command loop finished", client_id);
        app_state.remove_client_handle(client_id).await;
        let _ = status_tx.send("__UPDATE_UI__".to_string());
    }

    /// Connect to a Maven repository with integrated LLM actions
    pub async fn connect_with_llm_actions(
        repository_url: String,
        _llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        client_id: ClientId,
    ) -> Result<SocketAddr> {
        // For Maven, "connection" is logical - we interact with HTTP-based repositories
        // Default to Maven Central if no specific URL provided
        let repo_url = if repository_url.is_empty()
            || repository_url == "maven"
            || repository_url == "maven-central"
        {
            "https://repo.maven.apache.org/maven2".to_string()
        } else if repository_url.contains("://") {
            repository_url
        } else {
            // A bare `host:port` (what the dashboard's `[ + Maven client ]` and a model asked to
            // "connect to 127.0.0.1:8080" produce) gets a scheme: every URL built from it is
            // absolute, and without one reqwest refused each request as a relative URL.
            // `https://` natively, like npm and pypi; `http://` in the browser build, whose
            // transport speaks nothing else and whose repositories are servers on the page's
            // virtual network.
            let scheme = if cfg!(target_arch = "wasm32") {
                "http"
            } else {
                "https"
            };
            format!("{scheme}://{}", repository_url.trim_end_matches('/'))
        };
        // In the browser build the transport has no TLS: an `https://` repository — Maven
        // Central included — is refused here, with the reason, rather than on the first request.
        crate::client::http_fetch::check_url(&repo_url)?;

        info!(
            "Maven client {} initialized for repository: {}",
            client_id, repo_url
        );

        // Store client in protocol_data
        app_state
            .with_client_mut(client_id, |client| {
                client.set_protocol_field(
                    "http_client".to_string(),
                    serde_json::json!("initialized"),
                );
                client.set_protocol_field(
                    "repository_url".to_string(),
                    serde_json::json!(repo_url.clone()),
                );
            })
            .await;

        // Update status
        app_state
            .update_client_status(client_id, ClientStatus::Connected)
            .await;
        Log::new(Some(&status_tx)).info(format!(
            "Maven client {} connected to repository: {}",
            client_id, repo_url
        ));
        let _ = status_tx.send("__UPDATE_UI__".to_string());

        // Command channel for injected actions (the dashboard's [ send ] row).
        // Registered and *served* before the maven_connected LLM call below: a
        // dashboard-created client defaults to a `*` -> manual routing rule, so that
        // call can park for minutes and [ send ] has to work for the whole park.
        let command_rx =
            crate::client::command_support::register_command_channel(&app_state, client_id).await;

        // The command loop replaces the old 5s "is the client gone yet?" poll: when the
        // client is removed its handle is dropped, the channel closes and `recv()`
        // returns None, so the loop notices removal immediately instead of up to 5s later.
        // Registered with AppState so stop_client can abort it —
        // dropping a JoinHandle only detaches it in Tokio.
        let command_task = tokio::spawn(Self::command_loop(
            command_rx,
            client_id,
            app_state.clone(),
            _llm_client.clone(),
            status_tx.clone(),
        ));
        app_state
            .register_client_task(client_id, command_task)
            .await;

        // Call LLM with connected event
        if let Some(instruction) = app_state.get_instruction_for_client(client_id).await {
            let protocol = Arc::new(crate::client::maven::actions::MavenClientProtocol::new());
            let event = Event::new(
                &MAVEN_CLIENT_CONNECTED_EVENT,
                serde_json::json!({
                    "repository_url": repo_url,
                }),
            );

            let memory = app_state
                .get_memory_for_client(client_id)
                .await
                .unwrap_or_default();

            match call_llm_for_client(
                &_llm_client,
                &app_state,
                client_id.to_string(),
                &instruction,
                &memory,
                Some(&event),
                protocol.as_ref(),
                &status_tx,
            )
            .await
            {
                Ok(ClientLlmResult {
                    actions,
                    memory_updates,
                }) => {
                    // Update memory
                    if let Some(mem) = memory_updates {
                        app_state.set_memory_for_client(client_id, mem).await;
                    }

                    // Execute actions through the same path injected commands use.
                    // Dispatch::Spawn so connect() is not blocked on a download.
                    for action in actions {
                        match protocol.as_ref().execute_action(action) {
                            Ok(result) => match Self::apply_action(
                                client_id,
                                result,
                                Dispatch::Spawn,
                                0,
                                &app_state,
                                &_llm_client,
                                &status_tx,
                            )
                            .await
                            {
                                Ok(Applied::Disconnect) => {
                                    info!("Maven client {} disconnecting", client_id);
                                }
                                Ok(Applied::Executed(detail)) => {
                                    info!("Maven client {} after connect: {}", client_id, detail);
                                }
                                Err(e) => {
                                    error!("Maven client {} action failed: {}", client_id, e);
                                }
                            },
                            Err(e) => {
                                error!("Maven client {} rejected action: {}", client_id, e);
                            }
                        }
                    }
                }
                Err(e) => {
                    error!("LLM error for Maven client {}: {}", client_id, e);
                }
            }
        }

        // Return a dummy local address (Maven is HTTP-based)
        Ok("0.0.0.0:0".parse().unwrap())
    }

    /// Construct Maven artifact URL
    ///
    /// Converts Maven coordinates (groupId:artifactId:version) into repository URL
    /// Example: org.apache.commons:commons-lang3:3.12.0 ->
    ///   https://repo.maven.apache.org/maven2/org/apache/commons/commons-lang3/3.12.0/commons-lang3-3.12.0.jar
    pub fn artifact_url(
        repository_url: &str,
        group_id: &str,
        artifact_id: &str,
        version: &str,
        packaging: &str,
    ) -> String {
        let group_path = group_id.replace('.', "/");
        format!(
            "{}/{}/{}/{}/{}-{}.{}",
            repository_url.trim_end_matches('/'),
            group_path,
            artifact_id,
            version,
            artifact_id,
            version,
            packaging
        )
    }

    /// Construct POM URL
    pub fn pom_url(
        repository_url: &str,
        group_id: &str,
        artifact_id: &str,
        version: &str,
    ) -> String {
        Self::artifact_url(repository_url, group_id, artifact_id, version, "pom")
    }

    /// Construct metadata URL
    pub fn metadata_url(repository_url: &str, group_id: &str, artifact_id: &str) -> String {
        let group_path = group_id.replace('.', "/");
        format!(
            "{}/{}/{}/maven-metadata.xml",
            repository_url.trim_end_matches('/'),
            group_path,
            artifact_id
        )
    }

    /// Download artifact from Maven repository and hand the result to the LLM.
    #[allow(clippy::too_many_arguments)]
    pub async fn download_artifact(
        client_id: ClientId,
        depth: u8,
        group_id: String,
        artifact_id: String,
        version: String,
        packaging: Option<String>,
        app_state: Arc<AppState>,
        llm_client: OllamaClient,
        status_tx: mpsc::UnboundedSender<String>,
    ) -> Result<()> {
        let fetch = Self::perform_download_artifact(
            client_id,
            group_id,
            artifact_id,
            version,
            packaging,
            &app_state,
            &status_tx,
        )
        .await?;
        Self::notify_maven(
            client_id,
            depth,
            &crate::client::maven::actions::MAVEN_CLIENT_ARTIFACT_DOWNLOADED_EVENT,
            fetch.event_data,
            app_state,
            llm_client,
            status_tx,
        )
        .await;
        Ok(())
    }

    /// Download the artifact only. No LLM involvement, so a caller can await this and know
    /// exactly what the repository answered.
    pub async fn perform_download_artifact(
        client_id: ClientId,
        group_id: String,
        artifact_id: String,
        version: String,
        packaging: Option<String>,
        app_state: &AppState,
        status_tx: &mpsc::UnboundedSender<String>,
    ) -> Result<MavenFetch> {
        let packaging = packaging.unwrap_or_else(|| "jar".to_string());
        let repository_url = Self::repository_url(app_state, client_id).await?;

        let artifact_url = Self::artifact_url(
            &repository_url,
            &group_id,
            &artifact_id,
            &version,
            &packaging,
        );

        Log::new(Some(status_tx)).info(format!(
            "Maven client {} downloading artifact {}:{}:{} from {}",
            client_id, group_id, artifact_id, version, artifact_url
        ));

        match Self::http_client().await?.get(&artifact_url).send().await {
            Ok(response) => {
                let status = response.status();
                let status_code = status.as_u16();

                if status.is_success() {
                    let content_length = response.content_length().unwrap_or(0);
                    // `unwrap_or_default()` here turned a reset or a timeout
                    // mid-body into `""`, and the caller then reported
                    // "HTTP 200 (0 bytes)" and raised the response event with an empty
                    // artifact. The model reasoned about a repository answer that never
                    // arrived, and nothing was logged. Propagate instead: every caller
                    // already handles `Err`.
                    let body_bytes = response
                        .bytes()
                        .await
                        .context("reading the artifact body")?;

                    info!(
                        "Maven client {} artifact downloaded: {} bytes",
                        client_id,
                        body_bytes.len()
                    );

                    Ok(MavenFetch {
                        summary: format!("HTTP {} ({} bytes)", status_code, body_bytes.len()),
                        event_data: serde_json::json!({
                            "group_id": group_id,
                            "artifact_id": artifact_id,
                            "version": version,
                            "packaging": packaging,
                            "url": artifact_url,
                            "size_bytes": body_bytes.len(),
                            "content_length": content_length,
                        }),
                    })
                } else {
                    let error_msg = format!("Artifact not found: HTTP {}", status_code);
                    Log::new(Some(status_tx))
                        .error(format!("Maven client {} error: {}", client_id, error_msg));
                    Err(anyhow::anyhow!(error_msg))
                }
            }
            Err(e) => {
                Log::new(Some(status_tx))
                    .error(format!("Maven client {} download failed: {}", client_id, e));
                Err(e)
            }
        }
    }

    /// Download and parse POM file, then hand it to the LLM.
    pub async fn download_pom(
        client_id: ClientId,
        depth: u8,
        group_id: String,
        artifact_id: String,
        version: String,
        app_state: Arc<AppState>,
        llm_client: OllamaClient,
        status_tx: mpsc::UnboundedSender<String>,
    ) -> Result<()> {
        let fetch = Self::perform_download_pom(
            client_id,
            group_id,
            artifact_id,
            version,
            &app_state,
            &status_tx,
        )
        .await?;
        Self::notify_maven(
            client_id,
            depth,
            &crate::client::maven::actions::MAVEN_CLIENT_POM_RECEIVED_EVENT,
            fetch.event_data,
            app_state,
            llm_client,
            status_tx,
        )
        .await;
        Ok(())
    }

    /// Download the POM only. No LLM involvement.
    pub async fn perform_download_pom(
        client_id: ClientId,
        group_id: String,
        artifact_id: String,
        version: String,
        app_state: &AppState,
        status_tx: &mpsc::UnboundedSender<String>,
    ) -> Result<MavenFetch> {
        let repository_url = Self::repository_url(app_state, client_id).await?;
        let pom_url = Self::pom_url(&repository_url, &group_id, &artifact_id, &version);

        Log::new(Some(status_tx)).info(format!(
            "Maven client {} downloading POM {}:{}:{} from {}",
            client_id, group_id, artifact_id, version, pom_url
        ));

        match Self::http_client().await?.get(&pom_url).send().await {
            Ok(response) => {
                let status = response.status();
                let status_code = status.as_u16();

                if status.is_success() {
                    // See the note in `perform_download_artifact`: a failed body read
                    // must not be reported as an empty-but-successful POM.
                    let pom_content =
                        truncate_document(response.text().await.context("reading the POM body")?);

                    info!(
                        "Maven client {} POM downloaded: {} bytes",
                        client_id,
                        pom_content.len()
                    );

                    Ok(MavenFetch {
                        summary: format!("HTTP {} ({} bytes)", status_code, pom_content.len()),
                        event_data: serde_json::json!({
                            "group_id": group_id,
                            "artifact_id": artifact_id,
                            "version": version,
                            "url": pom_url,
                            "pom_content": pom_content,
                        }),
                    })
                } else {
                    let error_msg = format!("POM not found: HTTP {}", status_code);
                    Log::new(Some(status_tx))
                        .error(format!("Maven client {} error: {}", client_id, error_msg));
                    Err(anyhow::anyhow!(error_msg))
                }
            }
            Err(e) => {
                Log::new(Some(status_tx)).error(format!(
                    "Maven client {} POM download failed: {}",
                    client_id, e
                ));
                Err(e)
            }
        }
    }

    /// Search for artifact versions (via maven-metadata.xml) and hand them to the LLM.
    pub async fn search_versions(
        client_id: ClientId,
        depth: u8,
        group_id: String,
        artifact_id: String,
        app_state: Arc<AppState>,
        llm_client: OllamaClient,
        status_tx: mpsc::UnboundedSender<String>,
    ) -> Result<()> {
        let fetch =
            Self::perform_search_versions(client_id, group_id, artifact_id, &app_state, &status_tx)
                .await?;
        Self::notify_maven(
            client_id,
            depth,
            &crate::client::maven::actions::MAVEN_CLIENT_METADATA_RECEIVED_EVENT,
            fetch.event_data,
            app_state,
            llm_client,
            status_tx,
        )
        .await;
        Ok(())
    }

    /// Fetch maven-metadata.xml only. No LLM involvement.
    pub async fn perform_search_versions(
        client_id: ClientId,
        group_id: String,
        artifact_id: String,
        app_state: &AppState,
        status_tx: &mpsc::UnboundedSender<String>,
    ) -> Result<MavenFetch> {
        let repository_url = Self::repository_url(app_state, client_id).await?;
        let metadata_url = Self::metadata_url(&repository_url, &group_id, &artifact_id);

        Log::new(Some(status_tx)).info(format!(
            "Maven client {} searching versions {}:{} via {}",
            client_id, group_id, artifact_id, metadata_url
        ));

        match Self::http_client().await?.get(&metadata_url).send().await {
            Ok(response) => {
                let status = response.status();
                let status_code = status.as_u16();

                if status.is_success() {
                    // See the note in `perform_download_artifact`: a failed body read
                    // must not be reported as empty-but-successful metadata.
                    let metadata_content = truncate_document(
                        response
                            .text()
                            .await
                            .context("reading the maven-metadata.xml body")?,
                    );

                    info!(
                        "Maven client {} metadata received: {} bytes",
                        client_id,
                        metadata_content.len()
                    );

                    Ok(MavenFetch {
                        summary: format!(
                            "HTTP {} ({} bytes of maven-metadata.xml)",
                            status_code,
                            metadata_content.len()
                        ),
                        event_data: serde_json::json!({
                            "group_id": group_id,
                            "artifact_id": artifact_id,
                            "url": metadata_url,
                            "metadata_content": metadata_content,
                        }),
                    })
                } else {
                    let error_msg = format!("Metadata not found: HTTP {}", status_code);
                    Log::new(Some(status_tx))
                        .error(format!("Maven client {} error: {}", client_id, error_msg));
                    Err(anyhow::anyhow!(error_msg))
                }
            }
            Err(e) => {
                Log::new(Some(status_tx)).error(format!(
                    "Maven client {} metadata fetch failed: {}",
                    client_id, e
                ));
                Err(e)
            }
        }
    }

    /// The client's configured repository URL.
    async fn repository_url(app_state: &AppState, client_id: ClientId) -> Result<String> {
        app_state
            .with_client_mut(client_id, |client| {
                client
                    .get_protocol_field("repository_url")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
            })
            .await
            .flatten()
            .context("No repository URL found")
    }

    /// The shared client, not a fresh one per request.
    ///
    /// This used to build a `reqwest::Client` on every call — a blocking rustls +
    /// platform-root-store setup on the async runtime. See `shared_http_client`.
    async fn http_client() -> Result<FetchClient> {
        shared_http_client().await
    }
}
