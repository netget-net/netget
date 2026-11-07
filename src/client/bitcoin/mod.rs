//! Bitcoin RPC client implementation
pub mod actions;

pub use actions::BitcoinClientProtocol;

use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{error, info};

use crate::client::bitcoin::actions::BITCOIN_CLIENT_RESPONSE_RECEIVED_EVENT;
use crate::client::http_fetch::FetchClient;
use crate::client::llm_budget::call_llm_for_client;
use crate::llm::actions::client_trait::{Client, ClientActionResult};
use crate::llm::ollama_client::OllamaClient;
use crate::llm::ClientLlmResult;
use crate::logging::emit::Log;
use crate::protocol::Event;
use crate::state::app_state::AppState;
use crate::state::client_handles::{ClientCommand, ClientSendOutcome};
use crate::state::{AccessLogOwner, ClientId, ClientStatus};

/// Bitcoin RPC client that connects to Bitcoin Core node
pub struct BitcoinClient;

impl BitcoinClient {
    /// Connect to a Bitcoin Core RPC server with integrated LLM actions
    #[allow(clippy::too_many_arguments)]
    pub async fn connect_with_llm_actions(
        remote_addr: String,
        rpc_user: Option<String>,
        rpc_password: Option<String>,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        client_id: ClientId,
    ) -> Result<SocketAddr> {
        // For Bitcoin RPC, "connection" is logical (HTTP-based JSON-RPC)
        // We don't maintain a persistent connection, but verify connectivity

        info!(
            "Bitcoin RPC client {} initialized for {}",
            client_id,
            redact_userinfo(&remote_addr)
        );

        // Parse remote_addr to extract RPC URL
        // Expected format: "http://user:pass@host:port" or "host:port"
        let base_url = if remote_addr.starts_with("http://") || remote_addr.starts_with("https://")
        {
            remote_addr.clone()
        } else {
            // Default to http://
            format!("http://{}", remote_addr)
        };

        // `rpc_user` and `rpc_password` are declared startup parameters that nothing read, and
        // bitcoind's RPC is auth-mandatory — it answers every unauthenticated request with 401 —
        // so authenticated Bitcoin Core RPC could not work at all through this client.
        //
        // They are folded into the URL's userinfo rather than stored separately, because
        // `http://user:pass@host:port` is the format this client already documents and accepts.
        // One place therefore carries the credential and one place applies it, which is what
        // makes the documented form work too: see `split_userinfo`.
        let rpc_url = match (rpc_user, rpc_password) {
            (Some(user), pass) if !user.trim().is_empty() && !has_userinfo(&base_url) => {
                let (scheme, rest) = base_url
                    .split_once("://")
                    .map(|(a, b)| (a.to_string(), b.to_string()))
                    .unwrap_or_else(|| ("http".to_string(), base_url.clone()));
                match pass {
                    Some(pass) => format!("{scheme}://{user}:{pass}@{rest}"),
                    None => format!("{scheme}://{user}@{rest}"),
                }
            }
            _ => base_url,
        };

        // The credential must not leave this function in anything anyone reads. `rpc_url` is
        // rendered in the dashboard's facts line, and the connected event below is handed to the
        // **model**, so a userinfo URL put a password into the prompt and onto the screen. Both
        // now carry the redacted form; `perform_rpc` re-reads the real one from `rpc_url`.
        let display_url = redact_userinfo(&rpc_url);
        // In the browser build the transport has no TLS: an `https://` node is refused here, with
        // the reason (and without the credential), rather than on the first call.
        crate::client::http_fetch::check_url(&split_userinfo(&rpc_url).0)?;

        // Store RPC URL and auth in protocol_data
        app_state
            .with_client_mut(client_id, |client| {
                client.set_protocol_field("rpc_url".to_string(), serde_json::json!(rpc_url));
                client.set_protocol_field(
                    "rpc_url_display".to_string(),
                    serde_json::json!(display_url),
                );
                client.set_protocol_field("initialized".to_string(), serde_json::json!(true));
            })
            .await;

        // Update status
        app_state
            .update_client_status(client_id, ClientStatus::Connected)
            .await;
        let _ = status_tx.send(format!(
            "[CLIENT] Bitcoin RPC client {} ready for {}",
            client_id, display_url
        ));
        let _ = status_tx.send("__UPDATE_UI__".to_string());

        // Command channel for injected actions (the dashboard's [ send ] / composer).
        // Registered BEFORE the connected-event LLM call, which a manual `*` routing rule
        // can park for minutes - the operator must be able to issue an RPC while it waits.
        let command_rx =
            crate::client::command_support::register_command_channel(&app_state, client_id).await;
        let cmd_task = tokio::spawn(Self::command_loop(
            command_rx,
            client_id,
            app_state.clone(),
            llm_client.clone(),
            status_tx.clone(),
        ));
        app_state.register_client_task(client_id, cmd_task).await;

        // Call LLM to decide initial action
        if let Some(instruction) = app_state.get_instruction_for_client(client_id).await {
            let protocol = Arc::new(crate::client::bitcoin::actions::BitcoinClientProtocol::new());
            let event = Event::new(
                &crate::client::bitcoin::actions::BITCOIN_CLIENT_CONNECTED_EVENT,
                serde_json::json!({
                    // Redacted: this goes to the model.
                    "rpc_url": display_url,
                }),
            );

            let llm_client_clone = llm_client.clone();
            let app_state_clone = app_state.clone();
            let status_tx_clone = status_tx.clone();
            // Registered with AppState so stop_client can abort this task —
            // dropping a JoinHandle only detaches it in Tokio.
            let task_registrar = app_state.clone();
            let task_handle = tokio::spawn(async move {
                match call_llm_for_client(
                    &llm_client_clone,
                    &app_state_clone,
                    client_id.to_string(),
                    &instruction,
                    &String::new(),
                    Some(&event),
                    protocol.as_ref(),
                    &status_tx_clone,
                )
                .await
                {
                    Ok(ClientLlmResult {
                        actions,
                        memory_updates,
                    }) => {
                        // Update memory
                        if let Some(mem) = memory_updates {
                            app_state_clone.set_memory_for_client(client_id, mem).await;
                        }

                        // Execute actions through the same path injected commands use, so
                        // the JSON-RPC encoding exists exactly once.
                        for action in actions {
                            let result = match protocol.execute_action(action) {
                                Ok(result) => result,
                                Err(e) => {
                                    error!(
                                        "Bitcoin RPC client {} rejected action: {}",
                                        client_id, e
                                    );
                                    continue;
                                }
                            };
                            match Self::apply_action(
                                result,
                                client_id,
                                &app_state_clone,
                                &llm_client_clone,
                                &status_tx_clone,
                            )
                            .await
                            {
                                Ok(Applied::Ran(detail)) => {
                                    info!("Bitcoin RPC client {}: {}", client_id, detail);
                                }
                                Ok(Applied::Disconnect) => break,
                                Err(e) => {
                                    error!("Bitcoin RPC request failed: {}", e);
                                }
                            }
                        }
                    }
                    Err(e) => {
                        error!("LLM error for Bitcoin RPC client {}: {}", client_id, e);
                    }
                }
            });
            task_registrar
                .register_client_task(client_id, task_handle)
                .await;
        }

        // No idle-poll task: the command loop above is this client's only long-lived task
        // and it ends when the client is removed (`remove_client` drops the command sender,
        // so `recv()` returns `None`).

        // Return a dummy local address (Bitcoin RPC is connectionless HTTP)
        Ok("0.0.0.0:0".parse().unwrap())
    }

    /// Drain injected commands until the channel closes (the client was removed) or an
    /// injected `disconnect` ends the session.
    ///
    /// `command_support::handle_stream_client_command` cannot serve this client: there is
    /// no write half, and every Bitcoin verb yields `ClientActionResult::Custom`. So the
    /// action goes through [`Self::apply_action`] - the same function the connected-event
    /// path uses - and the outcome is recorded and replied exactly the way the generic arm
    /// does it.
    async fn command_loop(
        mut command_rx: mpsc::Receiver<ClientCommand>,
        client_id: ClientId,
        app_state: Arc<AppState>,
        llm_client: OllamaClient,
        status_tx: mpsc::UnboundedSender<String>,
    ) {
        use crate::llm::actions::protocol_trait::Protocol;

        let protocol = crate::client::bitcoin::actions::BitcoinClientProtocol::new();

        while let Some(command) = command_rx.recv().await {
            let action = command.action.clone();
            let outcome = match protocol.execute_action(action.clone()) {
                Err(e) => Ok(ClientSendOutcome::Rejected {
                    error: e.to_string(),
                }),
                Ok(result) => {
                    match Self::apply_action(result, client_id, &app_state, &llm_client, &status_tx)
                        .await
                    {
                        // Never `Sent`: reqwest owns the socket and never reports how many
                        // bytes the request serialised to, so a byte count here would be
                        // invented. `Executed` carries the JSON-RPC method and the HTTP
                        // status instead, which is both true and more useful.
                        Ok(Applied::Ran(detail)) => Ok(ClientSendOutcome::Executed { detail }),
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
                    "Bitcoin RPC client {} injected action failed: {}",
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

        // Nothing can be injected any more: stop the dashboard offering [ send ].
        app_state.remove_client_handle(client_id).await;
        let _ = status_tx.send("__UPDATE_UI__".to_string());
        info!("Bitcoin RPC client {} command loop ended", client_id);
    }

    /// Turn one executed action into a JSON-RPC call (or a session end).
    ///
    /// Shared by the connected-event handler and the injected-command loop so the
    /// `bitcoin_rpc` decoding exists exactly once. The HTTP round-trip is awaited - so
    /// the reported detail describes an exchange that really happened - while the
    /// `bitcoin_response_received` LLM call it triggers runs in its own registered task.
    /// That split matters: a client whose events are routed to a manual handler would
    /// otherwise park the command loop for the length of a human's think time.
    async fn apply_action(
        result: ClientActionResult,
        client_id: ClientId,
        app_state: &Arc<AppState>,
        llm_client: &OllamaClient,
        status_tx: &mpsc::UnboundedSender<String>,
    ) -> Result<Applied> {
        match result {
            ClientActionResult::Custom { name, data } if name == "bitcoin_rpc" => {
                let method = data
                    .get("method")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let params = data
                    .get("params")
                    .and_then(|v| v.as_array())
                    .cloned()
                    .unwrap_or_default();

                let exchange =
                    Self::perform_rpc(client_id, method.clone(), params, app_state, status_tx)
                        .await?;
                let detail = format!(
                    "bitcoin_rpc '{}' -> HTTP {} ({})",
                    method,
                    exchange.status_code,
                    if exchange.error.as_ref().is_some_and(|e| !e.is_null()) {
                        "JSON-RPC error"
                    } else {
                        "result"
                    }
                );

                let state_clone = app_state.clone();
                let llm_clone = llm_client.clone();
                let status_clone = status_tx.clone();
                let notify_handle = tokio::spawn(async move {
                    Self::notify_response(
                        client_id,
                        exchange,
                        state_clone,
                        llm_clone,
                        status_clone,
                    )
                    .await;
                });
                app_state
                    .register_client_task(client_id, notify_handle)
                    .await;

                Ok(Applied::Ran(detail))
            }
            ClientActionResult::Disconnect => {
                info!("Bitcoin RPC client {} disconnecting", client_id);
                Ok(Applied::Disconnect)
            }
            ClientActionResult::WaitForMore => Ok(Applied::Ran("wait_for_more".to_string())),
            ClientActionResult::NoAction => Ok(Applied::Ran("no_action".to_string())),
            // Not swallowed: an action this client cannot carry out says so, rather than
            // looking identical to success.
            ClientActionResult::Custom { name, .. } => Ok(Applied::Ran(format!(
                "custom result '{name}' is not handled by the Bitcoin RPC client"
            ))),
            ClientActionResult::SendData(_) => Ok(Applied::Ran(
                "send_data has no meaning for a JSON-RPC-over-HTTP client".to_string(),
            )),
            ClientActionResult::Multiple(_) => Ok(Applied::Ran(
                "multiple results are not produced by the Bitcoin RPC client".to_string(),
            )),
        }
    }

    /// Execute a Bitcoin RPC command and hand the response to the LLM.
    pub async fn execute_rpc_command(
        client_id: ClientId,
        method: String,
        params: Vec<serde_json::Value>,
        app_state: Arc<AppState>,
        llm_client: OllamaClient,
        status_tx: mpsc::UnboundedSender<String>,
    ) -> Result<()> {
        let exchange = Self::perform_rpc(client_id, method, params, &app_state, &status_tx).await?;
        Self::notify_response(client_id, exchange, app_state, llm_client, status_tx).await;
        Ok(())
    }

    /// Do the JSON-RPC round-trip. No LLM involvement, so a caller can await it and
    /// report truthfully what the node answered.
    async fn perform_rpc(
        client_id: ClientId,
        method: String,
        params: Vec<serde_json::Value>,
        app_state: &Arc<AppState>,
        status_tx: &mpsc::UnboundedSender<String>,
    ) -> Result<BitcoinRpcExchange> {
        // Get RPC URL from client
        let rpc_url = app_state
            .with_client_mut(client_id, |client| {
                client
                    .get_protocol_field("rpc_url")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
            })
            .await
            .flatten()
            .context("No RPC URL found")?;

        info!(
            "Bitcoin RPC client {} executing: {} {:?}",
            client_id, method, params
        );

        // Build JSON-RPC request
        let request_body = serde_json::json!({
            "jsonrpc": "1.0",
            "id": "netget",
            "method": method,
            "params": params,
        });

        // Make HTTP POST request to Bitcoin RPC
        // reqwest natively; in the browser build the shared hyper transport over the virtual
        // loopback (`crate::client::http_fetch`), with the same 60-second bound.
        #[cfg(not(target_arch = "wasm32"))]
        let http_client = FetchClient::from_reqwest(
            reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(60))
                .build()?,
        );
        #[cfg(target_arch = "wasm32")]
        let http_client = FetchClient::transport(std::time::Duration::from_secs(60));

        // Split the credential out of the URL and send it as a real `Authorization: Basic`
        // header. reqwest does **not** derive Basic auth from URL userinfo, so posting the
        // userinfo URL straight at bitcoind produced a 401 on every call — the
        // `http://user:pass@host:port` form this client documents has never worked.
        let (clean_url, credential) = split_userinfo(&rpc_url);

        let mut request = http_client
            .post(&clean_url)
            .header("Content-Type", "application/json")
            .json(&request_body);
        if let Some((user, pass)) = credential {
            request = request.basic_auth(user, pass);
        }

        match request.send().await {
            Ok(response) => {
                let status = response.status();

                // Get response body
                let response_text = response.text().await?;

                info!(
                    "Bitcoin RPC client {} received response: {}",
                    client_id, status
                );

                // Parse JSON-RPC response
                let response_json: serde_json::Value = serde_json::from_str(&response_text)
                    .unwrap_or(serde_json::json!({
                        "error": "Failed to parse response",
                        "raw": response_text
                    }));

                Ok(BitcoinRpcExchange {
                    method,
                    status_code: status.as_u16(),
                    result: response_json.get("result").cloned(),
                    error: response_json.get("error").cloned(),
                })
            }
            Err(e) => {
                Log::new(Some(status_tx)).error(format!(
                    "Bitcoin RPC client {} request failed: {}",
                    client_id, e
                ));
                Err(e)
            }
        }
    }

    /// Raise `bitcoin_response_received` for a completed exchange.
    /// Run the actions the model returned for a response event.
    ///
    /// They were discarded (`actions: _`), so answering bitcoin_response_received did nothing -- the whole
    /// point of raising it. Dispatch goes through `perform_rpc`, which raises no event: that
    /// bounds the loop, and avoids a notify -> perform -> notify chain that rustc cannot
    /// prove `Send`.
    async fn run_follow_ups(
        client_id: ClientId,
        actions: Vec<serde_json::Value>,
        app_state: &Arc<AppState>,
        status_tx: &mpsc::UnboundedSender<String>,
    ) {
        use crate::llm::actions::client_trait::{Client, ClientActionResult};
        let protocol = crate::client::bitcoin::actions::BitcoinClientProtocol::new();
        for action in actions {
            let Ok(ClientActionResult::Custom { name, data }) =
                protocol.execute_action(action.clone())
            else {
                continue;
            };
            if name != "bitcoin_rpc" {
                info!(
                    "Bitcoin client {} follow-up '{}' has no non-notifying path; skipped",
                    client_id, name
                );
                continue;
            }
            if let Err(e) = Self::perform_rpc(
                client_id,
                data["method"].as_str().unwrap_or_default().to_string(),
                data["params"].as_array().cloned().unwrap_or_default(),
                app_state,
                status_tx,
            )
            .await
            {
                error!(
                    "Bitcoin client {} follow-up action failed: {}",
                    client_id, e
                );
            }
        }
    }

    async fn notify_response(
        client_id: ClientId,
        exchange: BitcoinRpcExchange,
        app_state: Arc<AppState>,
        llm_client: OllamaClient,
        status_tx: mpsc::UnboundedSender<String>,
    ) {
        let Some(instruction) = app_state.get_instruction_for_client(client_id).await else {
            return;
        };

        let protocol = Arc::new(crate::client::bitcoin::actions::BitcoinClientProtocol::new());
        let event = Event::new(
            &BITCOIN_CLIENT_RESPONSE_RECEIVED_EVENT,
            serde_json::json!({
                "method": exchange.method,
                "result": exchange.result,
                "error": exchange.error,
                "status_code": exchange.status_code,
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

                // Note: We don't execute follow-up actions here.
                // The LLM will be called again on the next response or user interaction.
                // This avoids recursion complexity and keeps the action flow simple.
            }
            Err(e) => {
                error!("LLM error for Bitcoin RPC client {}: {}", client_id, e);
            }
        }
    }
}

/// One completed Bitcoin JSON-RPC exchange.
///
/// Split out of [`BitcoinClient::execute_rpc_command`] so the injected-command loop can
/// await the network round-trip - and report a truthful outcome - without also awaiting
/// the LLM call the response event triggers.
struct BitcoinRpcExchange {
    method: String,
    status_code: u16,
    result: Option<serde_json::Value>,
    error: Option<serde_json::Value>,
}

/// What one executed action did. Shared vocabulary between the connected-event handler
/// and the injected-command loop.
enum Applied {
    /// The action ran; `detail` says what it did.
    Ran(String),
    /// The action asked to end the session.
    Disconnect,
}

/// Does this URL already carry userinfo (`scheme://user:pass@host`)?
///
/// Only the authority is considered: an `@` in the path is not userinfo.
pub fn has_userinfo(url: &str) -> bool {
    let after_scheme = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    let authority = after_scheme.split(['/', '?', '#']).next().unwrap_or("");
    authority.contains('@')
}

/// Split `scheme://user:pass@host/path` into the URL without the credential, and the credential.
///
/// The credential must not stay in the request URL: some servers log the request line, and
/// bitcoind wants it in `Authorization` regardless. Returns the URL unchanged and `None` when
/// there is no userinfo.
///
/// Splitting is done by hand rather than with a URL crate because the only decision here is
/// where the authority ends, and a parser would also percent-decode — which this deliberately
/// does not do, since it would change a password containing `%` into a different password.
/// A credential needing percent-encoding should be passed through `rpc_user`/`rpc_password`,
/// where no encoding is involved at all.
pub type Credential = Option<(String, Option<String>)>;

pub fn split_userinfo(url: &str) -> (String, Credential) {
    let Some((scheme, rest)) = url.split_once("://") else {
        return (url.to_string(), None);
    };
    // The authority ends at the first `/`, `?` or `#`.
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(authority_end);
    // Last `@` wins: a password may legitimately contain one.
    let Some((userinfo, host)) = authority.rsplit_once('@') else {
        return (url.to_string(), None);
    };
    let (user, pass) = match userinfo.split_once(':') {
        Some((u, p)) => (u.to_string(), Some(p.to_string())),
        None => (userinfo.to_string(), None),
    };
    (format!("{scheme}://{host}{tail}"), Some((user, pass)))
}

/// Replace a URL's userinfo with `***` for anything a human or the model will read.
///
/// `http://alice:hunter2@127.0.0.1:8332` becomes `http://***@127.0.0.1:8332`. A URL with no
/// userinfo comes back unchanged.
pub fn redact_userinfo(url: &str) -> String {
    let (clean, credential) = split_userinfo(url);
    match credential {
        None => clean,
        Some(_) => match clean.split_once("://") {
            Some((scheme, rest)) => format!("{scheme}://***@{rest}"),
            None => format!("***@{clean}"),
        },
    }
}
