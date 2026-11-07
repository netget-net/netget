//! JSON-RPC 2.0 client implementation
pub mod actions;

pub use actions::JsonRpcClientProtocol;

use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{error, info};

use crate::client::http_fetch::FetchClient;
use crate::client::jsonrpc::actions::JSONRPC_CLIENT_RESPONSE_RECEIVED_EVENT;
use crate::client::llm_budget::call_llm_for_client;
use crate::llm::actions::client_trait::{Client, ClientActionResult};
use crate::llm::ollama_client::OllamaClient;
use crate::llm::ClientLlmResult;
use crate::logging::emit::Log;
use crate::protocol::Event;
use crate::state::app_state::AppState;
use crate::state::client_handles::{ClientCommand, ClientSendOutcome};
use crate::state::{AccessLogOwner, ClientId, ClientStatus};

/// What [`JsonRpcClient::apply_action`] did with one executed action. JSON-RPC rides on
/// HTTP request/response, so there is no persistent socket whose byte count could be
/// reported - every variant carries a description of what actually happened instead.
enum Applied {
    /// The action ran; the string describes the effect (request made, nothing to do, ...).
    Ran(String),
    /// The action asked to end the session.
    Disconnect,
}

/// Whether the response event is raised inline or from its own task.
#[derive(Clone, Copy)]
enum Dispatch {
    /// Raise it here and now. Used by the connected-event LLM path, which already runs in
    /// its own task and whose ordering the E2E tests rely on.
    Inline,
    /// Hand it to a registered task. Used by the injected-command loop so that a manual
    /// (human-answered) routing rule on `jsonrpc_response_received` cannot hold up the
    /// command's outcome, or the next injected command.
    Deferred,
}

/// One completed exchange waiting to be reported to the LLM.
enum Notification {
    Single((u16, Option<serde_json::Value>)),
    Batch((u16, Option<serde_json::Value>)),
}

/// How many times a `jsonrpc_response_received` answer may itself provoke another request.
///
/// The chain `request -> response event -> the model's next request` is genuinely
/// self-referential, and an `async fn` that awaits itself has an infinitely-sized future
/// (E0391). The answer is a depth bound, not silence: the follow-up path used to dispatch
/// through the `perform_*` cores, which raise no event, so the chain was exactly one step
/// deep — a `get` issued in reply to a `put` confirmation ran and its result went nowhere.
/// That is the `elasticsearch`/`http2` defect the root CLAUDE.md names.
const MAX_FOLLOWUP_DEPTH: usize = 6;

/// JSON-RPC 2.0 client that makes RPC calls to remote servers
pub struct JsonRpcClient;

impl JsonRpcClient {
    /// The HTTP client for one host, built once and kept.
    ///
    /// This client used to build a fresh `reqwest::Client` **on every single request** — and
    /// additionally built one at connect and dropped it immediately (`let _http_client = …`),
    /// which did nothing but pay the cost. Three things that cost:
    ///
    /// - `Client::builder().build()` sets up the rustls stack and loads the platform root
    ///   store; on macOS that reads the system keychain through Security.framework,
    ///   synchronously and serialised across processes. On the async runtime it parks a tokio
    ///   worker, so it runs on `spawn_blocking` here.
    /// - Keeping it means later requests reuse the connection pool instead of paying for a
    ///   fresh TLS stack and handshake each time. "Each request creates new HTTP connection"
    ///   was listed as a limitation of this client; it was a consequence of this.
    /// - **The literal-IP resolver bypass.** `reqwest` hands the URL host to its DNS resolver
    ///   unconditionally and `hyper-util`'s `GaiResolver` does not special-case a dotted quad,
    ///   so `http://127.0.0.1:8080` performs a real `getaddrinfo` — on macOS through libinfo
    ///   to mDNSResponder, one system-wide daemon, measured blocking for 8.25 seconds under
    ///   ~100 concurrent processes. A NetGet JSON-RPC client is pointed at a literal IP more
    ///   often than not.
    ///
    /// That last point is why the cache is keyed by host rather than being one process-wide
    /// client: `ClientBuilder::resolve` is a per-host override. Copied from
    /// `src/client/http/mod.rs`, which carries the full reasoning.
    #[cfg(not(target_arch = "wasm32"))]
    async fn reqwest_client(base_url: &str) -> Result<reqwest::Client> {
        use std::collections::HashMap;
        use std::sync::{Mutex, OnceLock};

        static CLIENTS: OnceLock<Mutex<HashMap<String, reqwest::Client>>> = OnceLock::new();
        let clients = CLIENTS.get_or_init(|| Mutex::new(HashMap::new()));

        let host = crate::llm::ollama_client::host_of(base_url).to_string();
        if let Some(client) = clients.lock().ok().and_then(|map| map.get(&host).cloned()) {
            return Ok(client);
        }

        let build_host = host.clone();
        let built = tokio::task::spawn_blocking(move || {
            let mut builder = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .use_rustls_tls();
            // Only when the host *is* an address. A hostname is left alone: resolving it is
            // the resolver's job, and /etc/hosts or split-horizon DNS may legitimately point
            // it somewhere unexpected.
            if let Ok(ip) = build_host.parse::<std::net::IpAddr>() {
                // The port is irrelevant — hyper overwrites it from the URL — so one override
                // serves every port this client is later pointed at.
                builder = builder.resolve(&build_host, std::net::SocketAddr::new(ip, 0));
            }
            builder
                .build()
                .context("Failed to build HTTP client for JSON-RPC")
        })
        .await
        .context("JSON-RPC HTTP client build task panicked")??;

        // A concurrent builder may have won the race; either client is equally valid, so keep
        // whichever landed first rather than replacing it and orphaning its pool.
        match clients.lock() {
            Ok(mut map) => Ok(map.entry(host).or_insert(built).clone()),
            Err(_) => Ok(built),
        }
    }

    /// The HTTP client for `base_url`: the cached reqwest client natively
    /// ([`Self::reqwest_client`]), the shared hyper transport over the virtual loopback in the
    /// browser build ([`crate::client::http_fetch`]), with the same 30-second bound.
    async fn http_client(base_url: &str) -> Result<FetchClient> {
        #[cfg(not(target_arch = "wasm32"))]
        let client = FetchClient::from_reqwest(Self::reqwest_client(base_url).await?);
        #[cfg(target_arch = "wasm32")]
        let client = {
            let _ = base_url;
            FetchClient::transport(std::time::Duration::from_secs(30))
        };
        Ok(client)
    }

    /// Connect to a JSON-RPC server with integrated LLM actions
    pub async fn connect_with_llm_actions(
        remote_addr: String,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        client_id: ClientId,
        startup_params: Option<crate::protocol::StartupParams>,
    ) -> Result<SocketAddr> {
        // JSON-RPC is HTTP-based, so "connection" is logical
        // We'll create an HTTP client and store it in protocol_data

        // Every other client protocol takes a bare `host:port`, and that is what a model
        // asked to "connect to 127.0.0.1:8080" produces. reqwest requires an absolute URL,
        // so a bare authority reached the wire as `builder error` (relative URL without a
        // base) on every single request -- with nothing in the message naming the address.
        // An explicit scheme is left exactly as given, including https.
        let remote_addr = if remote_addr.contains("://") {
            remote_addr
        } else {
            format!("http://{remote_addr}")
        };
        // In the browser build the transport has no TLS: an `https://` endpoint is refused here,
        // with the reason, rather than on the first call.
        crate::client::http_fetch::check_url(&remote_addr)?;

        info!(
            "JSON-RPC client {} initialized for {}",
            client_id, remote_addr
        );

        // The HTTP client is built lazily and cached per host by `Self::http_client`, on the
        // blocking pool. A client was built here and dropped on the next line
        // (`let _http_client = …`), paying the whole rustls/keychain cost for nothing, while
        // every request built another one of its own.

        // `default_headers` is declared as "headers included in all requests" - the one
        // place this protocol's own docs point at for API keys and bearer tokens - and
        // nothing read it, so an authenticated endpoint refused every call. Stored here and
        // applied by `perform_request` / `perform_batch_request`.
        let default_headers = match &startup_params {
            Some(params) => params.get_optional_object("default_headers")?.cloned(),
            None => None,
        };

        // Store client in protocol_data
        app_state
            .with_client_mut(client_id, |client| {
                client.set_protocol_field(
                    "jsonrpc_client".to_string(),
                    serde_json::json!("initialized"),
                );
                client.set_protocol_field(
                    "endpoint".to_string(),
                    serde_json::json!(remote_addr.clone()),
                );
                client.set_protocol_field("next_id".to_string(), serde_json::json!(1));
                if let Some(headers) = &default_headers {
                    client.set_protocol_field(
                        "default_headers".to_string(),
                        serde_json::Value::Object(headers.clone()),
                    );
                }
            })
            .await;

        // Update status
        app_state
            .update_client_status(client_id, ClientStatus::Connected)
            .await;
        let _ = status_tx.send(format!(
            "[CLIENT] JSON-RPC client {} ready for {}",
            client_id, remote_addr
        ));
        let _ = status_tx.send("__UPDATE_UI__".to_string());

        // Command channel for injected actions (the dashboard's [ send_jsonrpc_request ] /
        // [ disconnect ]). Registered BEFORE the connected-event LLM call, which a manual
        // `*` routing rule can park for minutes - the operator must be able to send a
        // request while it waits.
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

        // Call LLM with initial connected event
        if let Some(instruction) = app_state.get_instruction_for_client(client_id).await {
            let protocol = Arc::new(crate::client::jsonrpc::actions::JsonRpcClientProtocol::new());
            let event = Event::new(
                &crate::client::jsonrpc::actions::JSONRPC_CLIENT_CONNECTED_EVENT,
                serde_json::json!({
                    "endpoint": remote_addr,
                }),
            );

            let memory = app_state
                .get_memory_for_client(client_id)
                .await
                .unwrap_or_default();

            // Spawn task to process initial actions
            let app_state_clone = app_state.clone();
            let llm_client_clone = llm_client.clone();
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
                    &memory,
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

                        // Execute actions through the same path injected commands use.
                        for action in actions {
                            let result = match protocol.execute_action(action) {
                                Ok(result) => result,
                                Err(e) => {
                                    error!("JSON-RPC client {} rejected action: {}", client_id, e);
                                    continue;
                                }
                            };
                            match Self::apply_action(
                                result,
                                Dispatch::Inline,
                                client_id,
                                &app_state_clone,
                                &llm_client_clone,
                                &status_tx_clone,
                                0,
                            )
                            .await
                            {
                                Ok(Applied::Ran(detail)) => {
                                    info!("JSON-RPC client {}: {}", client_id, detail);
                                }
                                Ok(Applied::Disconnect) => break,
                                Err(e) => {
                                    error!("JSON-RPC client {} action failed: {}", client_id, e);
                                }
                            }
                        }
                    }
                    Err(e) => {
                        error!("LLM error for JSON-RPC client {}: {}", client_id, e);
                    }
                }
            });
            task_registrar
                .register_client_task(client_id, task_handle)
                .await;
        }

        // No idle-poll task: the command loop above is this client's only long-lived task
        // and it ends when the client is removed (`remove_client` drops the command
        // sender, so `recv()` returns `None`).

        // Return a dummy local address (JSON-RPC is connectionless over HTTP)
        Ok("0.0.0.0:0".parse().unwrap())
    }

    /// Run one executed action. Shared by the connected-event LLM path and injected
    /// commands so the request encoding exists exactly once.
    ///
    /// `dispatch` decides only *when the response event is raised*, never what goes on the
    /// wire: the LLM path keeps raising it inline, while an injected command awaits the
    /// HTTP round-trip and hands the event to its own task, so a manual routing rule
    /// parking on `jsonrpc_response_received` cannot wedge the command loop.
    ///
    /// `depth` is how many response events already led here; see [`MAX_FOLLOWUP_DEPTH`].
    ///
    /// Returns a boxed future rather than being a plain `async fn`. The chain
    /// `apply_action -> deliver_response -> notify_response -> run_follow_ups ->
    /// apply_action` is a real cycle, and an `async fn` that awaits itself has an
    /// infinitely-sized future (E0391); erasing the type at one edge makes it finite, and
    /// `+ Send` has to be named explicitly because the deferred arm awaits it inside a
    /// `tokio::spawn`.
    fn apply_action<'a>(
        result: ClientActionResult,
        dispatch: Dispatch,
        client_id: ClientId,
        app_state: &'a Arc<AppState>,
        llm_client: &'a OllamaClient,
        status_tx: &'a mpsc::UnboundedSender<String>,
        depth: usize,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Applied>> + Send + 'a>> {
        Box::pin(async move {
            match result {
                ClientActionResult::Custom { name, data } if name == "jsonrpc_request" => {
                    let method = data
                        .get("method")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let params = data.get("params").cloned();
                    let id = data.get("id").cloned();

                    let exchange =
                        Self::perform_request(client_id, &method, params, id, app_state).await?;
                    let detail = format!(
                        "jsonrpc_request '{}' sent; HTTP {} ({})",
                        method,
                        exchange.0,
                        if exchange.1.is_some() {
                            "JSON-RPC response received"
                        } else {
                            "body was not valid JSON"
                        }
                    );
                    Self::deliver_response(
                        Notification::Single(exchange),
                        dispatch,
                        client_id,
                        app_state,
                        llm_client,
                        status_tx,
                        depth,
                    )
                    .await;
                    Ok(Applied::Ran(detail))
                }
                ClientActionResult::Custom { name, data } if name == "jsonrpc_batch" => {
                    let requests = data
                        .get("requests")
                        .and_then(|v| v.as_array())
                        .cloned()
                        .unwrap_or_default();
                    let count = requests.len();

                    let exchange =
                        Self::perform_batch_request(client_id, requests, app_state).await?;
                    let detail = format!(
                        "jsonrpc_batch of {} request(s) sent; HTTP {} ({})",
                        count,
                        exchange.0,
                        if exchange.1.is_some() {
                            "batch response received"
                        } else {
                            "body was not valid JSON"
                        }
                    );
                    Self::deliver_response(
                        Notification::Batch(exchange),
                        dispatch,
                        client_id,
                        app_state,
                        llm_client,
                        status_tx,
                        depth,
                    )
                    .await;
                    Ok(Applied::Ran(detail))
                }
                ClientActionResult::Disconnect => {
                    info!("JSON-RPC client {} disconnecting", client_id);
                    app_state
                        .update_client_status(client_id, ClientStatus::Disconnected)
                        .await;
                    let _ = status_tx.send("__UPDATE_UI__".to_string());
                    Ok(Applied::Disconnect)
                }
                ClientActionResult::Custom { name, .. } => Err(anyhow::anyhow!(
                    "JSON-RPC client cannot execute custom result '{}'",
                    name
                )),
                // WaitForMore / NoAction / SendData / nested Multiple: nothing to put on the
                // wire for a request/response protocol.
                _ => Ok(Applied::Ran(
                    "no request made (action produced no JSON-RPC call)".to_string(),
                )),
            }
        })
    }

    /// Raise the response event, inline or from a registered task.
    async fn deliver_response(
        notification: Notification,
        dispatch: Dispatch,
        client_id: ClientId,
        app_state: &Arc<AppState>,
        llm_client: &OllamaClient,
        status_tx: &mpsc::UnboundedSender<String>,
        depth: usize,
    ) {
        match dispatch {
            Dispatch::Inline => match notification {
                Notification::Single(exchange) => {
                    Self::notify_response(
                        client_id, exchange, app_state, llm_client, status_tx, depth,
                    )
                    .await
                }
                Notification::Batch(exchange) => {
                    Self::notify_batch_response(
                        client_id, exchange, app_state, llm_client, status_tx, depth,
                    )
                    .await
                }
            },
            Dispatch::Deferred => {
                let state = app_state.clone();
                let llm = llm_client.clone();
                let tx = status_tx.clone();
                let handle = tokio::spawn(async move {
                    match notification {
                        Notification::Single(exchange) => {
                            Self::notify_response(client_id, exchange, &state, &llm, &tx, depth)
                                .await
                        }
                        Notification::Batch(exchange) => {
                            Self::notify_batch_response(
                                client_id, exchange, &state, &llm, &tx, depth,
                            )
                            .await
                        }
                    }
                });
                // Registered so stop_client aborts an in-flight LLM call for this event.
                app_state.register_client_task(client_id, handle).await;
            }
        }
    }

    /// Drain injected commands until the channel closes (the client was removed) or an
    /// injected `disconnect` ends the session. The request is awaited, so the reported
    /// [`ClientSendOutcome`] describes a round-trip that really happened.
    async fn command_loop(
        mut command_rx: mpsc::Receiver<ClientCommand>,
        client_id: ClientId,
        app_state: Arc<AppState>,
        llm_client: OllamaClient,
        status_tx: mpsc::UnboundedSender<String>,
    ) {
        use crate::llm::actions::protocol_trait::Protocol;

        let protocol = crate::client::jsonrpc::actions::JsonRpcClientProtocol::new();

        while let Some(command) = command_rx.recv().await {
            let action = command.action.clone();
            let outcome = match protocol.execute_action(action.clone()) {
                Err(e) => Ok(ClientSendOutcome::Rejected {
                    error: e.to_string(),
                }),
                Ok(result) => Self::apply_action(
                    result,
                    Dispatch::Deferred,
                    client_id,
                    &app_state,
                    &llm_client,
                    &status_tx,
                    0,
                )
                .await
                .map(|applied| match applied {
                    Applied::Disconnect => ClientSendOutcome::Disconnected,
                    Applied::Ran(detail) => ClientSendOutcome::Executed { detail },
                }),
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
                    "JSON-RPC client {} injected action failed: {}",
                    client_id, e
                ));
            }
            let _ = status_tx.send("__UPDATE_UI__".to_string());
            crate::client::command_support::reply(command, outcome);

            if disconnect {
                break;
            }
        }

        // Nothing can be injected any more: stop the dashboard offering [ send ].
        app_state.remove_client_handle(client_id).await;
        let _ = status_tx.send("__UPDATE_UI__".to_string());
        info!("JSON-RPC client {} command loop ended", client_id);
    }

    /// Make a JSON-RPC request and hand the response to the LLM.
    pub async fn make_request(
        client_id: ClientId,
        method: String,
        params: Option<serde_json::Value>,
        id: Option<serde_json::Value>,
        app_state: Arc<AppState>,
        llm_client: OllamaClient,
        status_tx: mpsc::UnboundedSender<String>,
    ) -> Result<()> {
        let exchange = Self::perform_request(client_id, &method, params, id, &app_state).await?;
        Self::notify_response(client_id, exchange, &app_state, &llm_client, &status_tx, 0).await;
        Ok(())
    }

    /// POST one JSON-RPC request and return `(http_status, parsed_body)`. Split out of
    /// [`Self::make_request`] so the injected-command loop can await the round-trip - and
    /// report what really happened - without also awaiting the LLM call the response event
    /// triggers, which a manual routing rule can park for minutes.
    /// Endpoint plus the request headers to send: the `default_headers` startup parameter
    /// with JSON-RPC's mandatory `content-type` on top of it, so a default can carry an API
    /// key or bearer token but cannot make the body unparseable to the server.
    ///
    /// Keys are lowercased before merging because HTTP header names are case-insensitive,
    /// and applied from one map because `RequestBuilder::header` appends rather than
    /// replaces.
    async fn endpoint_and_headers(
        client_id: ClientId,
        app_state: &Arc<AppState>,
    ) -> Result<(String, serde_json::Map<String, serde_json::Value>)> {
        let (endpoint, defaults) = app_state
            .with_client_mut(client_id, |client| {
                (
                    client
                        .get_protocol_field("endpoint")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                    client
                        .get_protocol_field("default_headers")
                        .and_then(|v| v.as_object().cloned()),
                )
            })
            .await
            .unwrap_or((None, None));
        let endpoint = endpoint.context("No endpoint found")?;

        let mut headers = serde_json::Map::new();
        for (key, value) in defaults.unwrap_or_default() {
            headers.insert(key.to_ascii_lowercase(), value);
        }
        headers.insert(
            "content-type".to_string(),
            serde_json::json!("application/json"),
        );
        Ok((endpoint, headers))
    }

    async fn perform_request(
        client_id: ClientId,
        method: &str,
        params: Option<serde_json::Value>,
        id: Option<serde_json::Value>,
        app_state: &Arc<AppState>,
    ) -> Result<(u16, Option<serde_json::Value>)> {
        let (endpoint, headers) = Self::endpoint_and_headers(client_id, app_state).await?;

        info!("JSON-RPC client {} calling method: {}", client_id, method);

        // Build JSON-RPC request
        let mut request = serde_json::json!({
            "jsonrpc": "2.0",
            "method": method,
        });

        if let Some(p) = params {
            request["params"] = p;
        }

        if let Some(request_id) = id {
            request["id"] = request_id.clone();
        }

        // Built once per host and kept; see `Self::http_client`.
        let http_client = Self::http_client(&endpoint).await?;

        let mut http_request = http_client.post(&endpoint);
        for (key, value) in &headers {
            if let Some(val_str) = value.as_str() {
                http_request = http_request.header(key, val_str);
            }
        }
        let response = http_request.json(&request).send().await?;

        let status_code = response.status().as_u16();
        let body_text = response.text().await?;

        info!(
            "JSON-RPC client {} received response: {}",
            client_id, status_code
        );

        match serde_json::from_str::<serde_json::Value>(&body_text) {
            Ok(response_json) => Ok((status_code, Some(response_json))),
            Err(_) => {
                error!(
                    "JSON-RPC client {} received invalid JSON response",
                    client_id
                );
                Ok((status_code, None))
            }
        }
    }

    /// Run the actions the model returned for a response event.
    ///
    /// They were discarded outright (`actions: _`) at both notify sites, so answering
    /// `jsonrpc_response_received` did nothing — the whole point of raising it. The first
    /// repair dispatched through the `perform_*` cores, which raise no event: that bounded
    /// the loop, but it made the chain exactly **one** step deep, so a request the model
    /// issued in reply to a response got its own reply thrown away. That is the
    /// `elasticsearch`/`http2` shape the root CLAUDE.md names, and the prescribed answer is a
    /// depth bound rather than silence.
    ///
    /// So follow-ups now go through the ordinary [`Self::apply_action`] path — they raise
    /// their own response event and can be chained — capped at [`MAX_FOLLOWUP_DEPTH`]. The
    /// bound is checked here rather than before raising the event, so the model always learns
    /// what a request answered; only its next request is refused, and it is refused loudly.
    async fn run_follow_ups(
        client_id: ClientId,
        actions: Vec<serde_json::Value>,
        app_state: &Arc<AppState>,
        llm_client: &OllamaClient,
        status_tx: &mpsc::UnboundedSender<String>,
        depth: usize,
    ) {
        use crate::llm::actions::client_trait::Client;

        if actions.is_empty() {
            return;
        }
        if depth >= MAX_FOLLOWUP_DEPTH {
            Log::to(&status_tx).warn(format!(
                "JSON-RPC client {} stopped chaining requests at the follow-up depth bound \
                 ({}); {} action(s) from this response were not run",
                client_id,
                MAX_FOLLOWUP_DEPTH,
                actions.len()
            ));
            return;
        }

        let protocol = crate::client::jsonrpc::actions::JsonRpcClientProtocol::new();
        for action in actions {
            let result = match protocol.execute_action(action) {
                Ok(result) => result,
                Err(e) => {
                    error!(
                        "JSON-RPC client {} rejected follow-up action: {}",
                        client_id, e
                    );
                    continue;
                }
            };
            match Self::apply_action(
                result,
                Dispatch::Inline,
                client_id,
                app_state,
                llm_client,
                status_tx,
                depth + 1,
            )
            .await
            {
                Ok(Applied::Ran(detail)) => info!("JSON-RPC client {}: {}", client_id, detail),
                Ok(Applied::Disconnect) => break,
                Err(e) => error!(
                    "JSON-RPC client {} follow-up action failed: {}",
                    client_id, e
                ),
            }
        }
    }

    /// Raise `jsonrpc_response_received` for a completed exchange.
    async fn notify_response(
        client_id: ClientId,
        exchange: (u16, Option<serde_json::Value>),
        app_state: &Arc<AppState>,
        llm_client: &OllamaClient,
        status_tx: &mpsc::UnboundedSender<String>,
        depth: usize,
    ) {
        let Some(response_json) = exchange.1 else {
            return;
        };
        let Some(instruction) = app_state.get_instruction_for_client(client_id).await else {
            return;
        };

        let protocol = Arc::new(crate::client::jsonrpc::actions::JsonRpcClientProtocol::new());
        let event = Event::new(&JSONRPC_CLIENT_RESPONSE_RECEIVED_EVENT, response_json);

        let memory = app_state
            .get_memory_for_client(client_id)
            .await
            .unwrap_or_default();

        match call_llm_for_client(
            llm_client,
            app_state,
            client_id.to_string(),
            &instruction,
            &memory,
            Some(&event),
            protocol.as_ref(),
            status_tx,
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
                Self::run_follow_ups(client_id, actions, app_state, llm_client, status_tx, depth)
                    .await;
            }
            Err(e) => {
                error!("LLM error for JSON-RPC client {}: {}", client_id, e);
            }
        }
    }

    /// Make a batch JSON-RPC request and hand the responses to the LLM.
    pub async fn make_batch_request(
        client_id: ClientId,
        requests: Vec<serde_json::Value>,
        app_state: Arc<AppState>,
        llm_client: OllamaClient,
        status_tx: mpsc::UnboundedSender<String>,
    ) -> Result<()> {
        let exchange = Self::perform_batch_request(client_id, requests, &app_state).await?;
        Self::notify_batch_response(client_id, exchange, &app_state, &llm_client, &status_tx, 0)
            .await;
        Ok(())
    }

    /// POST one JSON-RPC batch and return `(http_status, parsed_body)`. Same split (and
    /// same reason) as [`Self::perform_request`].
    async fn perform_batch_request(
        client_id: ClientId,
        requests: Vec<serde_json::Value>,
        app_state: &Arc<AppState>,
    ) -> Result<(u16, Option<serde_json::Value>)> {
        let (endpoint, headers) = Self::endpoint_and_headers(client_id, app_state).await?;

        info!(
            "JSON-RPC client {} sending batch with {} requests",
            client_id,
            requests.len()
        );

        // Build batch request (array of JSON-RPC requests)
        let mut batch = Vec::new();
        for req in requests {
            let mut request = serde_json::json!({
                "jsonrpc": "2.0",
            });

            // Merge the request fields
            if let Some(method) = req.get("method") {
                request["method"] = method.clone();
            }
            if let Some(params) = req.get("params") {
                request["params"] = params.clone();
            }
            if let Some(id) = req.get("id") {
                request["id"] = id.clone();
            }

            batch.push(request);
        }

        // Built once per host and kept; see `Self::http_client`.
        let http_client = Self::http_client(&endpoint).await?;

        let mut http_request = http_client.post(&endpoint);
        for (key, value) in &headers {
            if let Some(val_str) = value.as_str() {
                http_request = http_request.header(key, val_str);
            }
        }
        let response = http_request.json(&batch).send().await?;

        let status_code = response.status().as_u16();
        let body_text = response.text().await?;

        info!(
            "JSON-RPC client {} received batch response: {}",
            client_id, status_code
        );

        match serde_json::from_str::<serde_json::Value>(&body_text) {
            Ok(response_json) => Ok((status_code, Some(response_json))),
            Err(_) => {
                error!(
                    "JSON-RPC client {} received invalid JSON batch response",
                    client_id
                );
                Ok((status_code, None))
            }
        }
    }

    /// Raise `jsonrpc_response_received` for a completed batch exchange.
    async fn notify_batch_response(
        client_id: ClientId,
        exchange: (u16, Option<serde_json::Value>),
        app_state: &Arc<AppState>,
        llm_client: &OllamaClient,
        status_tx: &mpsc::UnboundedSender<String>,
        depth: usize,
    ) {
        let Some(response_json) = exchange.1 else {
            return;
        };
        let Some(instruction) = app_state.get_instruction_for_client(client_id).await else {
            return;
        };

        let protocol = Arc::new(crate::client::jsonrpc::actions::JsonRpcClientProtocol::new());
        let event = Event::new(
            &JSONRPC_CLIENT_RESPONSE_RECEIVED_EVENT,
            serde_json::json!({
                "batch": true,
                "responses": response_json,
            }),
        );

        let memory = app_state
            .get_memory_for_client(client_id)
            .await
            .unwrap_or_default();

        match call_llm_for_client(
            llm_client,
            app_state,
            client_id.to_string(),
            &instruction,
            &memory,
            Some(&event),
            protocol.as_ref(),
            status_tx,
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
                Self::run_follow_ups(client_id, actions, app_state, llm_client, status_tx, depth)
                    .await;
            }
            Err(e) => {
                error!("LLM error for JSON-RPC client {}: {}", client_id, e);
            }
        }
    }
}
