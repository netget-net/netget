//! WebDAV client implementation
pub mod actions;

pub use actions::WebdavClientProtocol;

use anyhow::{Context, Result};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::OnceLock;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{error, info};

use crate::client::llm_budget::call_llm_for_client;
use crate::client::webdav::actions::WEBDAV_CLIENT_RESPONSE_RECEIVED_EVENT;
use crate::llm::actions::client_trait::{Client, ClientActionResult};
use crate::llm::actions::protocol_trait::Protocol;
use crate::llm::ollama_client::OllamaClient;
use crate::llm::ClientLlmResult;
use crate::logging::emit::Log;
use crate::protocol::Event;
use crate::state::app_state::AppState;
use crate::state::client_handles::{ClientCommand, ClientSendOutcome};
use crate::state::{AccessLogOwner, ClientId, ClientStatus};

/// One `reqwest::Client` per base URL, built once and reused.
///
/// `Client::builder().build()` is a *blocking* operation: it sets up the rustls stack and
/// loads the platform root store, which on macOS reads the keychain through
/// Security.framework, synchronously and serialised across processes. It used to run inside
/// `perform_request` -- on the async runtime, once per WebDAV request -- parking a tokio
/// worker every time, and a second one was built at connect and dropped unused. It also
/// bypassed `client_for_endpoint_with_timeout`, so a base URL that is a literal IP still went
/// through `getaddrinfo`; that has been measured at 8.25s under concurrency on macOS.
static HTTP_CLIENTS: OnceLock<tokio::sync::Mutex<HashMap<String, reqwest::Client>>> =
    OnceLock::new();

/// How long a single WebDAV request may take.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Return the shared client for `base_url`, building it off the runtime the first time.
async fn http_client_for(base_url: &str) -> reqwest::Client {
    let clients = HTTP_CLIENTS.get_or_init(|| tokio::sync::Mutex::new(HashMap::new()));

    // Scoped so the guard is dropped before the `spawn_blocking` await below; a guard held
    // across an await that does work is the deadlock shape this tree keeps rediscovering.
    let existing = { clients.lock().await.get(base_url).cloned() };
    if let Some(client) = existing {
        return client;
    }

    let owned = base_url.to_string();
    let built = tokio::task::spawn_blocking(move || {
        crate::llm::ollama_client::configured_for_endpoint(
            reqwest::Client::builder()
                .timeout(REQUEST_TIMEOUT)
                .redirect(crate::client::http_fetch::same_origin_redirects()),
            &owned,
        )
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
    })
    .await
    .unwrap_or_else(|_| reqwest::Client::new());

    clients
        .lock()
        .await
        .entry(base_url.to_string())
        .or_insert(built)
        .clone()
}

/// WebDAV client that makes requests to remote WebDAV servers
pub struct WebdavClient;

impl WebdavClient {
    /// Connect to a WebDAV server with integrated LLM actions
    pub async fn connect_with_llm_actions(
        remote_addr: String,
        _llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        client_id: ClientId,
        startup_params: Option<crate::protocol::StartupParams>,
    ) -> Result<SocketAddr> {
        // For WebDAV, "connection" is logical, not a persistent TCP connection
        // We'll create an HTTP client and store it in protocol_data

        info!(
            "WebDAV client {} initialized for {}",
            client_id, remote_addr
        );

        // No client is built here. `perform_request` asks `http_client_for` for the one
        // belonging to this base URL, which builds it once, off the runtime. The client that
        // used to be built on this line was bound to `_http_client` and dropped immediately,
        // so it cost a synchronous keychain read at connect and served nothing.

        // `default_headers` and `auth` were both declared and both unread: headers promised
        // on every request never reached the wire, and a `username:password` handed to
        // `auth` was simply dropped, so an authenticated share answered 401 with no hint
        // why. Both are resolved once here into the header set `perform_request` sends.
        //
        // `auth` becomes an `Authorization: Basic <base64(user:pass)>` header, which is
        // what its `username:password` shape describes. It is stored resolved rather than
        // as the raw credential so the password is not re-encoded per request; it is still
        // in this client's `protocol_data` either way, exactly like every other client's
        // credentials.
        let (default_headers, auth) = match &startup_params {
            Some(params) => (
                params.get_optional_object("default_headers")?.cloned(),
                params.get_optional_string("auth")?,
            ),
            None => (None, None),
        };

        let mut startup_headers = serde_json::Map::new();
        for (key, value) in default_headers.unwrap_or_default() {
            startup_headers.insert(key.to_ascii_lowercase(), value);
        }
        if let Some(credentials) = auth {
            use base64::Engine;
            let encoded = base64::engine::general_purpose::STANDARD.encode(credentials.as_bytes());
            startup_headers.insert(
                "authorization".to_string(),
                serde_json::json!(format!("Basic {encoded}")),
            );
        }

        // Store client in protocol_data
        app_state
            .with_client_mut(client_id, |client| {
                client.set_protocol_field(
                    "http_client".to_string(),
                    serde_json::json!("initialized"),
                );
                client.set_protocol_field("base_url".to_string(), serde_json::json!(remote_addr));
                if !startup_headers.is_empty() {
                    client.set_protocol_field(
                        "startup_headers".to_string(),
                        serde_json::Value::Object(startup_headers.clone()),
                    );
                }
            })
            .await;

        // Update status
        app_state
            .update_client_status(client_id, ClientStatus::Connected)
            .await;
        Log::new(Some(&status_tx)).info(format!(
            "WebDAV client {} ready for {}",
            client_id, remote_addr
        ));
        let _ = status_tx.send("__UPDATE_UI__".to_string());

        // Command channel for injected actions (the dashboard's [ send ] row).
        // Registered - and already being drained by its own task - BEFORE the
        // connected-event LLM call, which a manual `*` rule can park for minutes: the
        // operator must be able to reach the client while it waits.
        let command_rx =
            crate::client::command_support::register_command_channel(&app_state, client_id).await;
        let cmd_task = tokio::spawn(Self::command_loop(
            command_rx,
            client_id,
            app_state.clone(),
            _llm_client.clone(),
            status_tx.clone(),
        ));
        app_state.register_client_task(client_id, cmd_task).await;

        // Send initial connected event to LLM
        // Registered with AppState so stop_client can abort this task —
        // dropping a JoinHandle only detaches it in Tokio.
        let task_registrar = app_state.clone();
        let task_handle = tokio::spawn(async move {
            if let Some(instruction) = app_state.get_instruction_for_client(client_id).await {
                let protocol =
                    Arc::new(crate::client::webdav::actions::WebdavClientProtocol::new());
                let event = Event::new(
                    &crate::client::webdav::actions::WEBDAV_CLIENT_CONNECTED_EVENT,
                    serde_json::json!({
                        "base_url": app_state.with_client_mut(client_id, |c|
                            c.get_protocol_field("base_url").and_then(|v| v.as_str().map(|s| s.to_string()))
                        ).await.flatten().unwrap_or_default(),
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

                        // Execute actions
                        for action in actions {
                            match protocol.as_ref().execute_action(action.clone()) {
                                Ok(result) => {
                                    if let Err(e) = Self::apply_action(
                                        result,
                                        Dispatch::Spawn,
                                        &_llm_client,
                                        &app_state,
                                        &status_tx,
                                        client_id,
                                    )
                                    .await
                                    {
                                        error!("Failed to execute WebDAV action: {}", e);
                                    }
                                }
                                Err(e) => {
                                    error!("WebDAV action execution error: {}", e);
                                }
                            }
                        }
                    }
                    Err(e) => {
                        error!("LLM error for WebDAV client {}: {}", client_id, e);
                    }
                }
            }
        });
        task_registrar
            .register_client_task(client_id, task_handle)
            .await;

        // Return a dummy local address (WebDAV is connectionless)
        Ok("0.0.0.0:0".parse().unwrap())
    }

    /// Drain injected commands until the channel closes (client removed) or an injected
    /// `disconnect` ends the session.
    ///
    /// `command_support::handle_stream_client_command` cannot serve this client: it writes
    /// `SendData` to a socket, and every WebDAV verb yields `ClientActionResult::Custom`
    /// that has to become an HTTP request. So the action goes through
    /// [`Self::apply_action`] - the same function the connected-event path uses - and the
    /// outcome is recorded and replied exactly the way the generic arm does it.
    async fn command_loop(
        mut command_rx: tokio::sync::mpsc::Receiver<ClientCommand>,
        client_id: ClientId,
        app_state: Arc<AppState>,
        llm_client: OllamaClient,
        status_tx: mpsc::UnboundedSender<String>,
    ) {
        let protocol = crate::client::webdav::actions::WebdavClientProtocol::new();

        while let Some(command) = command_rx.recv().await {
            let action = command.action.clone();
            let outcome = match protocol.execute_action(action.clone()) {
                Err(e) => Ok(ClientSendOutcome::Rejected {
                    error: e.to_string(),
                }),
                // Dispatch::Await: the request is awaited, so the reported outcome
                // describes a round-trip that has actually completed. The
                // webdav_response_received event is delivered from its own registered
                // task, so a manual handler parked for a human's think time cannot wedge
                // this loop or time out the dashboard's [ send ].
                Ok(result) => Self::apply_action(
                    result,
                    Dispatch::Await,
                    &llm_client,
                    &app_state,
                    &status_tx,
                    client_id,
                )
                .await
                .map(|applied| match applied {
                    Applied::Disconnect => ClientSendOutcome::Disconnected,
                    Applied::Executed(detail) => ClientSendOutcome::Executed { detail },
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
                    "WebDAV client {} injected action failed: {}",
                    client_id, e
                ));
            }
            let _ = status_tx.send("__UPDATE_UI__".to_string());
            crate::client::command_support::reply(command, outcome);

            if disconnect {
                break;
            }
        }

        info!("WebDAV client {} command loop stopped", client_id);
        app_state.remove_client_handle(client_id).await;
        let _ = status_tx.send("__UPDATE_UI__".to_string());
    }

    /// Apply one already-executed action result. The single place a WebDAV request is
    /// built and sent from, so an injected action behaves exactly like an LLM-produced one.
    async fn apply_action(
        result: ClientActionResult,
        dispatch: Dispatch,
        llm_client: &OllamaClient,
        app_state: &Arc<AppState>,
        status_tx: &mpsc::UnboundedSender<String>,
        client_id: ClientId,
    ) -> Result<Applied> {
        match result {
            ClientActionResult::Custom { name, data } if name == "webdav_request" => {
                let method = data
                    .get("method")
                    .and_then(|v| v.as_str())
                    .context("Missing 'method' in webdav_request")?
                    .to_string();

                let path = data
                    .get("path")
                    .and_then(|v| v.as_str())
                    .context("Missing 'path' in webdav_request")?
                    .to_string();

                // Build headers from action data
                let mut headers = Vec::new();

                // Add Depth header for PROPFIND/COPY
                if let Some(depth) = data.get("depth").and_then(|v| v.as_str()) {
                    headers.push(("Depth".to_string(), depth.to_string()));
                }

                // Add Destination header for COPY/MOVE
                if let Some(destination) = data.get("destination").and_then(|v| v.as_str()) {
                    // Get base URL and construct full destination URL
                    let base_url = app_state
                        .with_client_mut(client_id, |c| {
                            c.get_protocol_field("base_url")
                                .and_then(|v| v.as_str().map(|s| s.to_string()))
                        })
                        .await
                        .flatten()
                        .unwrap_or_default();

                    // On the client's own origin or refused, like the request URL itself.
                    let dest_url =
                        crate::client::http_fetch::resolve_same_origin(&base_url, destination)?;
                    headers.push(("Destination".to_string(), dest_url));
                }

                // Add Overwrite header for COPY/MOVE
                if let Some(overwrite) = data.get("overwrite").and_then(|v| v.as_bool()) {
                    headers.push((
                        "Overwrite".to_string(),
                        if overwrite { "T" } else { "F" }.to_string(),
                    ));
                }

                // Add Content-Type for PUT
                if let Some(content_type) = data.get("content_type").and_then(|v| v.as_str()) {
                    headers.push(("Content-Type".to_string(), content_type.to_string()));
                } else if method == "PUT" {
                    headers.push((
                        "Content-Type".to_string(),
                        "application/octet-stream".to_string(),
                    ));
                } else if method == "PROPFIND" {
                    headers.push(("Content-Type".to_string(), "application/xml".to_string()));
                }

                // Build request body
                let body = if method == "PROPFIND" {
                    // Build PROPFIND XML body
                    let properties = data
                        .get("properties")
                        .and_then(|v| v.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                                .collect::<Vec<String>>()
                        });
                    Some(Self::build_propfind_body(properties))
                } else if method == "PUT" {
                    // Use content from action
                    data.get("content")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string())
                } else {
                    None
                };

                match dispatch {
                    Dispatch::Spawn => {
                        let state_clone = Arc::clone(app_state);
                        let llm_clone = llm_client.clone();
                        let status_clone = status_tx.clone();
                        let (spawn_method, spawn_path) = (method.clone(), path.clone());
                        let request_handle = tokio::spawn(async move {
                            if let Err(e) = WebdavClient::make_request(
                                client_id,
                                spawn_method,
                                spawn_path,
                                Some(headers),
                                body,
                                state_clone,
                                llm_clone,
                                status_clone,
                            )
                            .await
                            {
                                error!("WebDAV request failed: {}", e);
                            }
                        });
                        app_state
                            .register_client_task(client_id, request_handle)
                            .await;
                        Ok(Applied::Executed(format!("{method} {path} dispatched")))
                    }
                    Dispatch::Await => {
                        let exchange = Self::perform_request(
                            client_id,
                            method.clone(),
                            path.clone(),
                            Some(headers),
                            body,
                            app_state,
                            status_tx,
                        )
                        .await?;
                        let detail = format!(
                            "{method} {path} completed -> {} ({} byte body)",
                            exchange.status_code, exchange.body_len
                        );
                        Self::spawn_notify(
                            client_id,
                            exchange.event_data,
                            app_state,
                            llm_client,
                            status_tx,
                        )
                        .await;
                        Ok(Applied::Executed(detail))
                    }
                }
            }
            ClientActionResult::Disconnect => {
                app_state
                    .update_client_status(client_id, ClientStatus::Disconnected)
                    .await;
                app_state.remove_client_handle(client_id).await;
                Log::new(Some(status_tx)).info(format!("WebDAV client {} disconnected", client_id));
                let _ = status_tx.send("__UPDATE_UI__".to_string());
                Ok(Applied::Disconnect)
            }
            other => Err(anyhow::anyhow!("Unexpected action result: {:?}", other)),
        }
    }

    /// Make a WebDAV request and hand the response to the LLM.
    #[allow(clippy::too_many_arguments)]
    pub async fn make_request(
        client_id: ClientId,
        method: String,
        path: String,
        headers: Option<Vec<(String, String)>>,
        body: Option<String>,
        app_state: Arc<AppState>,
        llm_client: OllamaClient,
        status_tx: mpsc::UnboundedSender<String>,
    ) -> Result<()> {
        let exchange = Self::perform_request(
            client_id, method, path, headers, body, &app_state, &status_tx,
        )
        .await?;
        Self::notify_response(
            client_id,
            exchange.event_data,
            app_state,
            llm_client,
            status_tx,
        )
        .await;
        Ok(())
    }

    /// Deliver one exchange's `webdav_response_received` event from **its own registered
    /// task** and return immediately.
    ///
    /// This is the point of the perform/notify split. The injected-command loop already
    /// holds the truthful network result and must reply to the operator before that
    /// event's handler runs: a dashboard-created client defaults to a `*` -> manual rule,
    /// so the handler can park for a human's think time (300s by default), far longer
    /// than the composer's 30s send timeout.
    async fn spawn_notify(
        client_id: ClientId,
        event_data: serde_json::Value,
        app_state: &Arc<AppState>,
        llm_client: &OllamaClient,
        status_tx: &mpsc::UnboundedSender<String>,
    ) {
        let state_clone = Arc::clone(app_state);
        let llm_clone = llm_client.clone();
        let status_clone = status_tx.clone();
        let notify_handle = tokio::spawn(async move {
            WebdavClient::notify_response(
                client_id,
                event_data,
                state_clone,
                llm_clone,
                status_clone,
            )
            .await;
        });
        // Registered so the notification - and the LLM call it makes - is aborted when
        // the client is stopped.
        app_state
            .register_client_task(client_id, notify_handle)
            .await;
    }

    /// Fire one `webdav_response_received` event at the LLM and apply any memory update.
    /// Run the actions the model returned for a response event.
    ///
    /// They were discarded (`actions: _`), so answering webdav_response_received did nothing -- the whole
    /// point of raising it. Dispatch goes through `perform_request`, which raises no event: that
    /// bounds the loop, and avoids a notify -> perform -> notify chain that rustc cannot
    /// prove `Send`.
    async fn run_follow_ups(
        client_id: ClientId,
        actions: Vec<serde_json::Value>,
        app_state: &Arc<AppState>,
        status_tx: &mpsc::UnboundedSender<String>,
    ) {
        use crate::llm::actions::client_trait::{Client, ClientActionResult};
        let protocol = crate::client::webdav::actions::WebdavClientProtocol::new();
        for action in actions {
            let Ok(ClientActionResult::Custom { name, data }) =
                protocol.execute_action(action.clone())
            else {
                continue;
            };
            if name != "webdav_request" {
                info!(
                    "WebDAV client {} follow-up '{}' has no non-notifying path; skipped",
                    client_id, name
                );
                continue;
            }
            if let Err(e) = Self::perform_request(
                client_id,
                data["method"].as_str().unwrap_or("GET").to_string(),
                data["path"].as_str().unwrap_or("/").to_string(),
                None,
                data["body"].as_str().map(|s| s.to_string()),
                app_state,
                status_tx,
            )
            .await
            {
                error!("WebDAV client {} follow-up action failed: {}", client_id, e);
            }
        }
    }

    async fn notify_response(
        client_id: ClientId,
        event_data: serde_json::Value,
        app_state: Arc<AppState>,
        llm_client: OllamaClient,
        status_tx: mpsc::UnboundedSender<String>,
    ) {
        let Some(instruction) = app_state.get_instruction_for_client(client_id).await else {
            return;
        };
        let protocol = Arc::new(crate::client::webdav::actions::WebdavClientProtocol::new());
        let event = Event::new(&WEBDAV_CLIENT_RESPONSE_RECEIVED_EVENT, event_data);
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
                Self::run_follow_ups(client_id, actions, &app_state, &status_tx).await;
            }
            Err(e) => {
                error!("LLM error for WebDAV client {}: {}", client_id, e);
            }
        }
    }

    /// Perform the WebDAV round-trip only. No LLM involvement, so a caller can await this
    /// and know exactly what the server answered.
    #[allow(clippy::too_many_arguments)]
    pub async fn perform_request(
        client_id: ClientId,
        method: String,
        path: String,
        headers: Option<Vec<(String, String)>>,
        body: Option<String>,
        app_state: &Arc<AppState>,
        status_tx: &mpsc::UnboundedSender<String>,
    ) -> Result<WebdavExchange> {
        // Base URL and the startup headers (`default_headers` plus the `auth` credential,
        // already resolved to an `authorization` value), read together under one guard.
        let (base_url, startup_headers) = app_state
            .with_client_mut(client_id, |client| {
                (
                    client
                        .get_protocol_field("base_url")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                    client
                        .get_protocol_field("startup_headers")
                        .and_then(|v| v.as_object().cloned()),
                )
            })
            .await
            .unwrap_or((None, None));
        let base_url = base_url.context("No base URL found")?;

        // Same origin as `remote_addr` or refused: see `resolve_same_origin`. The `auth`
        // credential rides on every request as `Authorization: Basic`, so a request to
        // another host would hand the share password to it.
        let url = crate::client::http_fetch::resolve_same_origin(&base_url, &path)?;

        info!(
            "WebDAV client {} making request: {} {}",
            client_id, method, url
        );

        // Build request with custom method support for WebDAV
        let http_client = http_client_for(&base_url).await;

        let method_upper = method.to_uppercase();
        let request_method = match method_upper.as_str() {
            "GET" => reqwest::Method::GET,
            "PUT" => reqwest::Method::PUT,
            "POST" => reqwest::Method::POST,
            "DELETE" => reqwest::Method::DELETE,
            "HEAD" => reqwest::Method::HEAD,
            "OPTIONS" => reqwest::Method::OPTIONS,
            "PROPFIND" => reqwest::Method::from_bytes(b"PROPFIND")?,
            "PROPPATCH" => reqwest::Method::from_bytes(b"PROPPATCH")?,
            "MKCOL" => reqwest::Method::from_bytes(b"MKCOL")?,
            "COPY" => reqwest::Method::from_bytes(b"COPY")?,
            "MOVE" => reqwest::Method::from_bytes(b"MOVE")?,
            "LOCK" => reqwest::Method::from_bytes(b"LOCK")?,
            "UNLOCK" => reqwest::Method::from_bytes(b"UNLOCK")?,
            _ => return Err(anyhow::anyhow!("Unsupported WebDAV method: {}", method)),
        };

        let mut request = http_client.request(request_method, &url);

        // Startup headers merged *underneath* the per-request ones (Depth, Destination,
        // Content-Type, ...), keyed by the lowercased name. Merged into one map before
        // anything is applied, because `RequestBuilder::header` appends: a per-request
        // `Content-Type` alongside a default one would send both.
        let mut merged = serde_json::Map::new();
        for (key, value) in startup_headers.unwrap_or_default() {
            merged.insert(key.to_ascii_lowercase(), value);
        }
        if let Some(hdrs) = headers {
            for (key, value) in hdrs {
                merged.insert(key.to_ascii_lowercase(), serde_json::json!(value));
            }
        }
        for (key, value) in merged {
            if let Some(val_str) = value.as_str() {
                request = request.header(&key, val_str);
            }
        }

        // Add body
        if let Some(body_str) = body {
            request = request.body(body_str);
        }

        // Make request
        match request.send().await {
            Ok(response) => {
                let status = response.status();
                let status_code = status.as_u16();

                // Get headers
                let mut resp_headers = serde_json::Map::new();
                for (name, value) in response.headers() {
                    if let Ok(val_str) = value.to_str() {
                        resp_headers.insert(name.to_string(), serde_json::json!(val_str));
                    }
                }

                // Get body
                let body_text = response.text().await?;

                info!(
                    "WebDAV client {} received response: {} ({})",
                    client_id, status_code, status
                );

                // Built here, delivered by `notify_response` - inline for the LLM path,
                // from its own task for the injected-command path.
                let body_len = body_text.len();
                Ok(WebdavExchange {
                    status_code,
                    body_len,
                    event_data: serde_json::json!({
                        "method": method,
                        "status_code": status_code,
                        "status_text": status.to_string(),
                        "headers": resp_headers,
                        "body": body_text,
                    }),
                })
            }
            Err(e) => {
                Log::new(Some(status_tx))
                    .error(format!("WebDAV client {} request failed: {}", client_id, e));
                Err(e.into())
            }
        }
    }

    /// Build XML body for PROPFIND request
    pub fn build_propfind_body(properties: Option<Vec<String>>) -> String {
        match properties {
            Some(props) => {
                let mut prop_elements = String::new();
                for prop in props {
                    prop_elements.push_str(&format!("<D:{}/>\n", prop));
                }
                format!(
                    r#"<?xml version="1.0" encoding="utf-8"?>
<D:propfind xmlns:D="DAV:">
  <D:prop>
{}
  </D:prop>
</D:propfind>"#,
                    prop_elements
                )
            }
            None => {
                // Request all properties
                r#"<?xml version="1.0" encoding="utf-8"?>
<D:propfind xmlns:D="DAV:">
  <D:allprop/>
</D:propfind>"#
                    .to_string()
            }
        }
    }
}

/// How a WebDAV request is issued.
#[derive(Clone, Copy)]
enum Dispatch {
    /// Spawn the request and return immediately. Used by the connected-event handler.
    Spawn,
    /// Await the round-trip so the caller can report what actually happened. Used by the
    /// injected-command loop. The response event is still delivered to the LLM, from its
    /// own registered task, so a parked manual handler cannot wedge the command loop.
    Await,
}

/// One completed WebDAV exchange.
///
/// Split out of [`WebdavClient::make_request`] so the injected-command loop can await the
/// network round-trip - and report a truthful outcome - without also awaiting the LLM call
/// the response event triggers.
pub struct WebdavExchange {
    pub status_code: u16,
    pub body_len: usize,
    /// The `webdav_response_received` payload this exchange produced.
    pub event_data: serde_json::Value,
}

/// What [`WebdavClient::apply_action`] did with one action. The WebDAV client owns no
/// socket - reqwest does - so there is no honest byte count to report, only "the request
/// ran" or "the session should end".
enum Applied {
    /// The action ran; the string says what, for the injected action's outcome detail.
    Executed(String),
    /// The session should end.
    Disconnect,
}
