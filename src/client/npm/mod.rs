//! NPM Registry client implementation
pub mod actions;

pub use actions::NpmClientProtocol;

use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{error, info, warn};

use crate::client::http_fetch::FetchClient;
use crate::client::llm_budget::call_llm_for_client;
use crate::client::npm::actions::{
    NPM_CLIENT_PACKAGE_INFO_RECEIVED_EVENT, NPM_CLIENT_SEARCH_RESULTS_RECEIVED_EVENT,
};
use crate::llm::actions::client_trait::{Client, ClientActionResult};
use crate::llm::ollama_client::OllamaClient;
use crate::llm::ClientLlmResult;
use crate::logging::emit::Log;
use crate::protocol::Event;
use crate::state::app_state::AppState;
use crate::state::client_handles::{ClientCommand, ClientSendOutcome};
use crate::state::{AccessLogOwner, ClientId, ClientStatus};

/// One completed package-info fetch.
///
/// Split out of [`NpmClient::get_package_info`] so the injected-command loop can await the
/// registry round-trip - and report a truthful outcome - without also awaiting the LLM call
/// the `npm_package_info_received` event triggers.
pub struct NpmPackageInfo {
    pub package_name: String,
    pub version: String,
    pub description: String,
    pub versions: Vec<String>,
    pub dist: Option<serde_json::Value>,
}

/// One completed package search, split from its event for the same reason.
pub struct NpmSearchResults {
    pub query: String,
    pub results: Vec<serde_json::Value>,
    pub total: u64,
}

/// What one executed action did.
enum Applied {
    /// The action ran; `detail` says what it did.
    Executed(String),
    /// The action asked to end the session.
    Disconnect,
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
                    .timeout(std::time::Duration::from_secs(120))
                    .user_agent("NetGet NPM Client/1.0")
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
/// virtual loopback ([`crate::client::http_fetch`]) with the same timeout and User-Agent. The body bound is the 64 MiB tarball cap (`MAX_TARBALL_BYTES`) rather than the transport's 8 MiB default, so the protocol's own bound is the one that governs.
async fn shared_http_client() -> Result<FetchClient> {
    #[cfg(not(target_arch = "wasm32"))]
    let client = FetchClient::from_reqwest(reqwest_client().await?);
    #[cfg(target_arch = "wasm32")]
    let client = FetchClient::transport(std::time::Duration::from_secs(120))
        .with_user_agent("NetGet NPM Client/1.0")
        .with_max_body(MAX_TARBALL_BYTES as usize);
    Ok(client)
}

/// Ceiling on a tarball fetched by `download_tarball`.
///
/// The tarball URL comes out of the registry's own packument, so its size is
/// chosen by whatever this client was pointed at rather than by us. 64 MiB is
/// well past any real npm package and far short of exhausting the process.
const MAX_TARBALL_BYTES: u64 = 64 * 1024 * 1024;

/// Turn an operator- or model-supplied address into a registry base URL, **or refuse**.
///
/// There is no default, and that is deliberate. A client that loses its target must fail
/// rather than reach the real service: an address that merely failed to arrive is
/// indistinguishable, further down, from one the caller deliberately omitted, so a fallback
/// turns "I forgot to say where" into "talk to the public registry" with nothing logged that
/// an operator would read as a problem. It is the DynamoDB shape from the root `CLAUDE.md`,
/// milder only because nothing here is signed with anybody's credentials. `openai`'s
/// `api_base_for` faced the identical choice and refuses; this is the same exit.
///
/// Serving the public registry is a legitimate thing to ask this client for — say so, with
/// `remote_addr: "registry.npmjs.org"`, and it is honoured. Arriving there because nobody said
/// otherwise is not.
///
/// A scheme is left as given; without one, `https://` is added natively — and `http://` in
/// the browser build, whose transport speaks nothing else and whose registrys are servers on the
/// page's virtual network — rather than the address being discarded, which was an earlier
/// incarnation of this same bug (`127.0.0.1:8080` silently
/// became the public registry).
fn resolve_registry_url(remote_addr: &str) -> Result<String> {
    let trimmed = remote_addr.trim().trim_end_matches('/');
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        return Ok(trimmed.to_string());
    }
    // `"npm"` is the protocol's own name, not an address — it reaches here when a caller fills
    // `remote_addr` with the thing it is starting rather than the thing it is talking to.
    if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("npm") {
        anyhow::bail!(
            "NPM client needs a registry in remote_addr (for example \
             http://127.0.0.1:4873 for a local Verdaccio, or name the public registry \
             explicitly if that is what you want); refusing to reach the public npm registry \
             by omission"
        );
    }
    let scheme = if cfg!(target_arch = "wasm32") {
        "http"
    } else {
        "https"
    };
    Ok(format!("{scheme}://{trimmed}"))
}

/// NPM Registry client that queries packages
pub struct NpmClient;

impl NpmClient {
    /// Connect to NPM registry with integrated LLM actions
    pub async fn connect_with_llm_actions(
        remote_addr: String,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        client_id: ClientId,
    ) -> Result<SocketAddr> {
        // For NPM, "connection" is logical - we're accessing a REST API.
        //
        // A scheme-less address used to be **discarded** and silently replaced with
        // the public registry, so an operator who typed `127.0.0.1:8080` had their
        // requests sent there with no warning — and this protocol's own startup
        // example (`"remote_addr": "registry.npmjs.org"`) takes exactly that branch.
        // A host is now given the `https://` it was missing, and an address that is
        // missing entirely is an error rather than a silent trip to the vendor.
        let registry_url = resolve_registry_url(&remote_addr)?;
        // In the browser build the transport has no TLS: an `https://` registry is refused here,
        // with the reason, rather than on the first request.
        crate::client::http_fetch::check_url(&registry_url)?;

        info!("NPM client {} initialized for {}", client_id, registry_url);

        // No client is built here. One used to be, bound to `_http_client` and
        // dropped immediately — paying the blocking rustls/keychain cost at connect
        // for a value nothing read. The shared client above is built on first use.

        // Store client in protocol_data
        app_state
            .with_client_mut(client_id, |client| {
                client
                    .set_protocol_field("npm_client".to_string(), serde_json::json!("initialized"));
                client.set_protocol_field(
                    "registry_url".to_string(),
                    serde_json::json!(registry_url),
                );
            })
            .await;

        // Update status
        app_state
            .update_client_status(client_id, ClientStatus::Connected)
            .await;
        Log::new(Some(&status_tx)).info(format!(
            "NPM client {} ready for {}",
            client_id, registry_url
        ));
        let _ = status_tx.send("__UPDATE_UI__".to_string());

        // Command channel for injected actions (the dashboard's [ send ] row).
        // Registered as soon as the client is usable and *before* anything that can
        // block for a human: a dashboard-created client defaults to a `*` -> manual
        // routing rule, and [ send ] must work while such an event is parked.
        let command_rx =
            crate::client::command_support::register_command_channel(&app_state, client_id).await;

        // The command loop replaces the old 5s "is the client gone yet?" poll: when the
        // client is removed its handle is dropped, the channel closes and `recv()`
        // returns None, so the loop notices removal immediately instead of up to 5s later.
        // Registered with AppState so stop_client can abort it —
        // dropping a JoinHandle only detaches it in Tokio.
        let task_registrar = app_state.clone();
        let connected_llm_client = llm_client.clone();
        let connected_status_tx = status_tx.clone();
        let task_handle = tokio::spawn(Self::command_loop(
            command_rx, client_id, app_state, llm_client, status_tx,
        ));
        task_registrar
            .register_client_task(client_id, task_handle)
            .await;

        // Raise the connected event.
        //
        // It was declared and never emitted, so the model was never consulted when a
        // NPM client came up -- and this protocol's own
        // `get_startup_examples()` shows a `npm_connected` handler, which could not
        // possibly have fired.
        //
        // Raised from its own registered task rather than inline: a dashboard-created
        // client defaults to a `*` -> manual rule, and awaiting a parked answer here would
        // block client creation itself.
        let connected_state = task_registrar.clone();
        let connected_llm = connected_llm_client;
        let connected_status = connected_status_tx;
        let connected = tokio::spawn(async move {
            let Some(instruction) = connected_state.get_instruction_for_client(client_id).await
            else {
                return;
            };
            let protocol = crate::client::npm::actions::NpmClientProtocol::new();
            let event = Event::new(
                &crate::client::npm::actions::NPM_CLIENT_CONNECTED_EVENT,
                serde_json::json!({ "registry_url": registry_url.clone(), }),
            );
            match crate::client::llm_budget::call_llm_for_client(
                &connected_llm,
                &connected_state,
                client_id.to_string(),
                &instruction,
                "",
                Some(&event),
                &protocol,
                &connected_status,
            )
            .await
            {
                Ok(result) => {
                    if let Some(mem) = result.memory_updates {
                        connected_state.set_memory_for_client(client_id, mem).await;
                    }
                    Self::run_follow_ups(
                        client_id,
                        result.actions,
                        &connected_state,
                        &connected_status,
                    )
                    .await;
                }
                Err(e) => error!(
                    "NPM client {} LLM error on connected event: {}",
                    client_id, e
                ),
            }
        });
        task_registrar
            .register_client_task(client_id, connected)
            .await;

        // Return a dummy local address (NPM is HTTP-based)
        Ok("0.0.0.0:0".parse().unwrap())
    }

    /// Get information about a package and hand it to the LLM.
    pub async fn get_package_info(
        client_id: ClientId,
        package_name: String,
        version: String,
        app_state: Arc<AppState>,
        llm_client: OllamaClient,
        status_tx: mpsc::UnboundedSender<String>,
    ) -> Result<()> {
        let info = Self::perform_get_package_info(
            client_id,
            package_name,
            version,
            &app_state,
            &status_tx,
        )
        .await?;
        Self::notify_package_info(client_id, info, app_state, llm_client, status_tx).await;
        Ok(())
    }

    /// Fetch package metadata only. No LLM involvement, so a caller can await this and
    /// know exactly what the registry answered.
    pub async fn perform_get_package_info(
        client_id: ClientId,
        package_name: String,
        version: String,
        app_state: &AppState,
        status_tx: &mpsc::UnboundedSender<String>,
    ) -> Result<NpmPackageInfo> {
        // Get registry URL from client
        let registry_url = app_state
            .with_client_mut(client_id, |client| {
                client
                    .get_protocol_field("registry_url")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
            })
            .await
            .flatten()
            .context("No registry URL found")?;

        // Encode package name for URL (handles scoped packages like @types/node)
        let encoded_name = package_name.replace("/", "%2f");

        let url = if version == "latest" {
            format!("{}/{}", registry_url, encoded_name)
        } else {
            format!("{}/{}/{}", registry_url, encoded_name, version)
        };

        info!(
            "NPM client {} getting package info: {} ({})",
            client_id, package_name, version
        );

        // Build HTTP client
        let http_client = shared_http_client().await?;

        // Make request
        match http_client.get(&url).send().await {
            Ok(response) => {
                let status = response.status();

                if !status.is_success() {
                    let error_text = response
                        .text()
                        .await
                        .unwrap_or_else(|_| "Unknown error".to_string());
                    Log::new(Some(status_tx)).error(format!(
                        "NPM client {} failed to get package {}: {} - {}",
                        client_id, package_name, status, error_text
                    ));
                    return Err(anyhow::anyhow!("NPM request failed: {}", status));
                }

                // Parse JSON response
                let package_data: serde_json::Value = response
                    .json()
                    .await
                    .context("Failed to parse NPM response")?;

                info!(
                    "NPM client {} received package info for {}",
                    client_id, package_name
                );

                // Extract relevant fields
                let description = package_data
                    .get("description")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();

                let dist_tags = package_data.get("dist-tags");
                let latest_version = dist_tags
                    .and_then(|dt| dt.get("latest"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown")
                    .to_string();

                let versions = package_data
                    .get("versions")
                    .and_then(|v| v.as_object())
                    .map(|obj| obj.keys().cloned().collect::<Vec<_>>())
                    .unwrap_or_default();

                let dist = if version == "latest" {
                    package_data
                        .get("dist-tags")
                        .and_then(|dt| dt.get("latest"))
                        .and_then(|lv| {
                            package_data
                                .get("versions")
                                .and_then(|vs| vs.get(lv.as_str().unwrap_or("")))
                        })
                        .and_then(|v| v.get("dist"))
                        .cloned()
                } else {
                    package_data.get("dist").cloned()
                };

                let resolved_version = if version == "latest" {
                    latest_version
                } else {
                    version
                };

                Ok(NpmPackageInfo {
                    package_name,
                    version: resolved_version,
                    description,
                    versions,
                    dist,
                })
            }
            Err(e) => {
                Log::new(Some(status_tx))
                    .error(format!("NPM client {} request failed: {}", client_id, e));
                Err(e)
            }
        }
    }

    /// Raise `npm_package_info_received` for a completed fetch.
    /// Run the actions the model returned for a response event.
    ///
    /// They were discarded at both notify sites (`actions: _`), so answering
    /// npm_package_info_received or npm_search_results did nothing at all -- the whole
    /// point of raising those events.
    ///
    /// Everything here goes through the `perform_*` round-trips, which raise no event.
    /// That bounds the loop -- a follow-up cannot trigger another response event and drive
    /// the model in circles -- and it is also the only shape that compiles, since routing
    /// back through the notifying entry points makes notify -> perform -> notify a
    /// self-referential async chain rustc cannot prove `Send`.
    async fn run_follow_ups(
        client_id: ClientId,
        actions: Vec<serde_json::Value>,
        app_state: &Arc<AppState>,
        status_tx: &mpsc::UnboundedSender<String>,
    ) {
        use crate::llm::actions::client_trait::{Client, ClientActionResult};
        let protocol = crate::client::npm::actions::NpmClientProtocol::new();
        for action in actions {
            // `Disconnect` used to be filtered out here by a `let ... else { continue }`
            // that only admitted `Custom`, so a model answering a response event with
            // `{"type": "disconnect"}` — which this protocol's own `get_startup_examples()`
            // documents as a static handler — did nothing at all.
            let (name, data) = match protocol.execute_action(action.clone()) {
                Ok(ClientActionResult::Custom { name, data }) => (name, data),
                Ok(ClientActionResult::Disconnect) => {
                    info!(
                        "NPM client {} disconnecting on the model's answer",
                        client_id
                    );
                    app_state
                        .update_client_status(client_id, ClientStatus::Disconnected)
                        .await;
                    return;
                }
                Ok(_) => continue,
                Err(e) => {
                    warn!(
                        "NPM client {} could not execute the model's follow-up action: {}",
                        client_id, e
                    );
                    continue;
                }
            };
            let outcome: Result<()> = match name.as_str() {
                "npm_get_package" => Self::perform_get_package_info(
                    client_id,
                    data["package_name"]
                        .as_str()
                        .unwrap_or_default()
                        .to_string(),
                    data["version"].as_str().unwrap_or("latest").to_string(),
                    app_state,
                    status_tx,
                )
                .await
                .map(|_| ()),
                "npm_search" => Self::perform_search_packages(
                    client_id,
                    data["query"].as_str().unwrap_or_default().to_string(),
                    data["limit"].as_u64().unwrap_or(10),
                    app_state,
                    status_tx,
                )
                .await
                .map(|_| ()),
                // `download_tarball` raises no event and makes no LLM call, so it is
                // safe here — it was reaching the catch-all below and being logged as
                // "has no non-notifying path", which was simply untrue.
                "npm_download_tarball" => Self::download_tarball(
                    client_id,
                    data["package_name"]
                        .as_str()
                        .unwrap_or_default()
                        .to_string(),
                    data["version"].as_str().unwrap_or("latest").to_string(),
                    app_state.clone(),
                    status_tx.clone(),
                )
                .await
                .map(|_| ()),
                other => {
                    info!(
                        "NPM client {} follow-up '{}' has no non-notifying path; skipped",
                        client_id, other
                    );
                    Ok(())
                }
            };
            if let Err(e) = outcome {
                error!("NPM client {} follow-up action failed: {}", client_id, e);
            }
        }
    }

    async fn notify_package_info(
        client_id: ClientId,
        info: NpmPackageInfo,
        app_state: Arc<AppState>,
        llm_client: OllamaClient,
        status_tx: mpsc::UnboundedSender<String>,
    ) {
        let Some(instruction) = app_state.get_instruction_for_client(client_id).await else {
            return;
        };

        let protocol = Arc::new(crate::client::npm::actions::NpmClientProtocol::new());
        let event = Event::new(
            &NPM_CLIENT_PACKAGE_INFO_RECEIVED_EVENT,
            serde_json::json!({
                "package_name": info.package_name,
                "version": info.version,
                "description": info.description,
                "versions": info.versions,
                "dist": info.dist,
            }),
        );

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
                // Update memory
                if let Some(mem) = memory_updates {
                    app_state.set_memory_for_client(client_id, mem).await;
                }
                Self::run_follow_ups(client_id, actions, &app_state, &status_tx).await;
            }
            Err(e) => {
                error!("LLM error for NPM client {}: {}", client_id, e);
            }
        }
    }

    /// Search for packages and hand the results to the LLM.
    pub async fn search_packages(
        client_id: ClientId,
        query: String,
        limit: u64,
        app_state: Arc<AppState>,
        llm_client: OllamaClient,
        status_tx: mpsc::UnboundedSender<String>,
    ) -> Result<()> {
        let results =
            Self::perform_search_packages(client_id, query, limit, &app_state, &status_tx).await?;
        Self::notify_search_results(client_id, results, app_state, llm_client, status_tx).await;
        Ok(())
    }

    /// Run the search only. No LLM involvement, so a caller can await this and know
    /// exactly what the registry answered.
    pub async fn perform_search_packages(
        client_id: ClientId,
        query: String,
        limit: u64,
        app_state: &AppState,
        status_tx: &mpsc::UnboundedSender<String>,
    ) -> Result<NpmSearchResults> {
        // Search the registry this client was configured with, not always the public one.
        // The `registry_url` startup parameter was declared and honoured by every other
        // verb, but search hardcoded https://registry.npmjs.org/-/v1/search -- so a client
        // pointed at a private registry (or, in a test, at a loopback listener) silently
        // queried the public registry instead.
        let registry_url = app_state
            .with_client_mut(client_id, |client| {
                client
                    .get_protocol_field("registry_url")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
            })
            .await
            .flatten()
            .context("No registry URL found")?;
        let search_url = format!("{}/-/v1/search", registry_url.trim_end_matches('/'));

        info!(
            "NPM client {} searching for: {} (limit: {})",
            client_id, query, limit
        );

        // Build HTTP client
        let http_client = shared_http_client().await?;

        // Build query parameters
        let url = format!(
            "{}?text={}&size={}",
            search_url,
            urlencoding::encode(&query),
            limit
        );

        // Make request
        match http_client.get(&url).send().await {
            Ok(response) => {
                let status = response.status();

                if !status.is_success() {
                    let error_text = response
                        .text()
                        .await
                        .unwrap_or_else(|_| "Unknown error".to_string());
                    Log::new(Some(status_tx)).error(format!(
                        "NPM client {} search failed: {} - {}",
                        client_id, status, error_text
                    ));
                    return Err(anyhow::anyhow!("NPM search failed: {}", status));
                }

                // Parse JSON response
                let search_data: serde_json::Value = response
                    .json()
                    .await
                    .context("Failed to parse NPM search response")?;

                let results = search_data.get("objects")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter().map(|obj| {
                            let package = obj.get("package");
                            serde_json::json!({
                                "name": package.and_then(|p| p.get("name")).and_then(|v| v.as_str()).unwrap_or(""),
                                "version": package.and_then(|p| p.get("version")).and_then(|v| v.as_str()).unwrap_or(""),
                                "description": package.and_then(|p| p.get("description")).and_then(|v| v.as_str()).unwrap_or(""),
                            })
                        }).collect::<Vec<_>>()
                    })
                    .unwrap_or_default();

                let total = search_data
                    .get("total")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(results.len() as u64);

                info!(
                    "NPM client {} received {} search results",
                    client_id,
                    results.len()
                );

                Ok(NpmSearchResults {
                    query,
                    results,
                    total,
                })
            }
            Err(e) => {
                Log::new(Some(status_tx))
                    .error(format!("NPM client {} search failed: {}", client_id, e));
                Err(e)
            }
        }
    }

    /// Raise `npm_search_results_received` for a completed search.
    async fn notify_search_results(
        client_id: ClientId,
        results: NpmSearchResults,
        app_state: Arc<AppState>,
        llm_client: OllamaClient,
        status_tx: mpsc::UnboundedSender<String>,
    ) {
        let Some(instruction) = app_state.get_instruction_for_client(client_id).await else {
            return;
        };

        let protocol = Arc::new(crate::client::npm::actions::NpmClientProtocol::new());
        let event = Event::new(
            &NPM_CLIENT_SEARCH_RESULTS_RECEIVED_EVENT,
            serde_json::json!({
                "query": results.query,
                "results": results.results,
                "total": results.total,
            }),
        );

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
                // Update memory
                if let Some(mem) = memory_updates {
                    app_state.set_memory_for_client(client_id, mem).await;
                }
                Self::run_follow_ups(client_id, actions, &app_state, &status_tx).await;
            }
            Err(e) => {
                error!("LLM error for NPM client {}: {}", client_id, e);
            }
        }
    }

    /// Fetch a package tarball and report what came back.
    ///
    /// **Nothing is written to disk.** This used to end in
    /// `tokio::fs::write(&output_path, bytes)` with `output_path` taken verbatim from
    /// the model's action - an arbitrary-file-write driven by LLM output, and a
    /// straight violation of the rule that a protocol implements no storage. A model
    /// that merely misunderstood the parameter could overwrite `~/.ssh/authorized_keys`.
    /// PyPI's equivalent (`perform_download_package`) already fetched and reported
    /// without persisting, so this is the family's own precedent rather than a new
    /// design.
    ///
    /// What the caller gets instead is the byte count and the integrity string the
    /// registry advertised, which is what a model can actually reason about.
    pub async fn download_tarball(
        client_id: ClientId,
        package_name: String,
        version: String,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
    ) -> Result<String> {
        // First get package info to find tarball URL
        let registry_url = app_state
            .with_client_mut(client_id, |client| {
                client
                    .get_protocol_field("registry_url")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
            })
            .await
            .flatten()
            .context("No registry URL found")?;

        let encoded_name = package_name.replace("/", "%2f");
        let info_url = format!("{}/{}", registry_url, encoded_name);

        info!(
            "NPM client {} downloading tarball for {} ({})",
            client_id, package_name, version
        );

        let http_client = shared_http_client().await?;

        // Get package info
        let package_data: serde_json::Value = http_client
            .get(&info_url)
            .send()
            .await?
            .json()
            .await
            .context("Failed to get package info")?;

        // Find the `dist` block for the requested version, and the tarball URL in it.
        let dist = if version == "latest" {
            package_data
                .get("dist-tags")
                .and_then(|dt| dt.get("latest"))
                .and_then(|lv| {
                    package_data
                        .get("versions")
                        .and_then(|vs| vs.get(lv.as_str().unwrap_or("")))
                })
                .and_then(|v| v.get("dist"))
        } else {
            package_data
                .get("versions")
                .and_then(|vs| vs.get(&version))
                .and_then(|v| v.get("dist"))
        }
        .context("Could not find a dist block for the requested version")?
        .clone();

        let tarball_url = dist
            .get("tarball")
            .and_then(|t| t.as_str())
            .context("Could not find tarball URL")?
            .to_string();

        // The integrity the registry claims for these bytes, reported alongside the
        // size so the model sees what it was promised as well as what arrived.
        let advertised = dist
            .get("integrity")
            .or_else(|| dist.get("shasum"))
            .and_then(|v| v.as_str())
            .unwrap_or("(none advertised)")
            .to_string();

        info!("NPM client {} downloading from: {}", client_id, tarball_url);

        // Bounded. The URL comes from the registry's own JSON, so its size is chosen
        // by whatever we are pointed at, and `bytes()` would buffer all of it.
        // Streaming with a cap means a hostile or merely enormous tarball costs at
        // most the cap.
        let mut response = http_client.get(&tarball_url).send().await?;
        if let Some(len) = response.content_length() {
            if len > MAX_TARBALL_BYTES {
                anyhow::bail!(
                    "{} advertises {} bytes, over the {} byte limit; refusing to download it",
                    tarball_url,
                    len,
                    MAX_TARBALL_BYTES
                );
            }
        }
        let mut received: u64 = 0;
        while let Some(chunk) = response.chunk().await? {
            received += chunk.len() as u64;
            if received > MAX_TARBALL_BYTES {
                anyhow::bail!(
                    "{} exceeded the {} byte limit mid-transfer; aborting",
                    tarball_url,
                    MAX_TARBALL_BYTES
                );
            }
        }

        let summary = format!(
            "{}@{}: {} bytes from {} (registry integrity: {}); not saved - NetGet stores nothing",
            package_name, version, received, tarball_url, advertised
        );
        Log::new(Some(&status_tx)).info(format!(
            "NPM client {} fetched tarball {}",
            client_id, summary
        ));

        Ok(summary)
    }

    /// Apply one already-parsed action against the live NPM client.
    ///
    /// The single place NPM actions are turned into registry traffic, so an action injected
    /// from the dashboard behaves exactly like one the model produced.
    ///
    /// Only the **network** half is awaited. The response event - and the LLM call it makes -
    /// is raised from its own registered task afterwards, so a `*` -> manual routing rule
    /// parking that event cannot wedge the command loop for the length of a human's think
    /// time. The outcome stays truthful because it describes what the registry actually
    /// answered, which is known before the event is raised.
    async fn apply_action(
        client_id: ClientId,
        result: ClientActionResult,
        app_state: &Arc<AppState>,
        llm_client: &OllamaClient,
        status_tx: &mpsc::UnboundedSender<String>,
    ) -> Result<Applied> {
        match result {
            ClientActionResult::Custom { name, data } => match name.as_str() {
                "npm_get_package" => {
                    let package_name = data["package_name"]
                        .as_str()
                        .unwrap_or_default()
                        .to_string();
                    let version = data["version"].as_str().unwrap_or("latest").to_string();
                    let requested = format!("{package_name}@{version}");

                    let info = Self::perform_get_package_info(
                        client_id,
                        package_name,
                        version,
                        app_state,
                        status_tx,
                    )
                    .await?;
                    let detail = format!(
                        "get_package_info {requested} -> version {}, {} published version(s)",
                        info.version,
                        info.versions.len()
                    );
                    Self::spawn_notify(
                        client_id,
                        app_state,
                        Self::notify_package_info(
                            client_id,
                            info,
                            app_state.clone(),
                            llm_client.clone(),
                            status_tx.clone(),
                        ),
                    )
                    .await;
                    Ok(Applied::Executed(detail))
                }
                "npm_search" => {
                    let query = data["query"].as_str().unwrap_or_default().to_string();
                    let limit = data["limit"].as_u64().unwrap_or(20);
                    let requested = query.clone();

                    let results = Self::perform_search_packages(
                        client_id, query, limit, app_state, status_tx,
                    )
                    .await?;
                    let detail = format!(
                        "search_packages {requested:?} -> {} result(s) of {} total",
                        results.results.len(),
                        results.total
                    );
                    Self::spawn_notify(
                        client_id,
                        app_state,
                        Self::notify_search_results(
                            client_id,
                            results,
                            app_state.clone(),
                            llm_client.clone(),
                            status_tx.clone(),
                        ),
                    )
                    .await;
                    Ok(Applied::Executed(detail))
                }
                "npm_download_tarball" => {
                    // No split needed: download_tarball raises no event and makes no LLM
                    // call, so awaiting it awaits nothing but the network.
                    let package_name = data["package_name"]
                        .as_str()
                        .unwrap_or_default()
                        .to_string();
                    let version = data["version"].as_str().unwrap_or("latest").to_string();
                    let summary = Self::download_tarball(
                        client_id,
                        package_name,
                        version,
                        app_state.clone(),
                        status_tx.clone(),
                    )
                    .await?;
                    Ok(Applied::Executed(format!("download_tarball {summary}")))
                }
                other => Ok(Applied::Executed(format!(
                    "unknown NPM custom result '{other}' was not executed"
                ))),
            },
            ClientActionResult::Disconnect => Ok(Applied::Disconnect),
            ClientActionResult::NoAction => Ok(Applied::Executed("no_action".to_string())),
            ClientActionResult::WaitForMore => Ok(Applied::Executed("wait_for_more".to_string())),
            ClientActionResult::SendData(_) => Ok(Applied::Executed(
                "NPM owns no socket; raw send_data cannot be put on the wire".to_string(),
            )),
            ClientActionResult::Multiple(_) => Ok(Applied::Executed(
                "NPM produces no Multiple results; nothing executed".to_string(),
            )),
        }
    }

    /// Raise a response event from its own task, registered so `stop_client` aborts it.
    async fn spawn_notify(
        client_id: ClientId,
        app_state: &Arc<AppState>,
        notify: impl std::future::Future<Output = ()> + Send + 'static,
    ) {
        let handle = tokio::spawn(notify);
        app_state.register_client_task(client_id, handle).await;
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
        let protocol = crate::client::npm::actions::NpmClientProtocol::new();

        while let Some(command) = command_rx.recv().await {
            let action = command.action.clone();
            let outcome = match protocol.execute_action(action.clone()) {
                Err(e) => Ok(ClientSendOutcome::Rejected {
                    error: e.to_string(),
                }),
                // Never `Sent`: reqwest owns the socket and does not report how many bytes
                // the request serialised to, so a byte count here would be invented.
                // `Executed` carries what the registry answered instead, which is both
                // true and more useful.
                Ok(result) => {
                    match Self::apply_action(client_id, result, &app_state, &llm_client, &status_tx)
                        .await
                    {
                        Ok(Applied::Executed(detail)) => Ok(ClientSendOutcome::Executed { detail }),
                        Ok(Applied::Disconnect) => Ok(ClientSendOutcome::Disconnected),
                        Err(e) => Err(e),
                    }
                }
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
                    "NPM client {} injected action failed: {}",
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

        info!("NPM client {} command loop finished", client_id);
        app_state.remove_client_handle(client_id).await;
        let _ = status_tx.send("__UPDATE_UI__".to_string());
    }
}
