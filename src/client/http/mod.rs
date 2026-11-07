//! HTTP client implementation.
//!
//! Natively every request goes through reqwest (TLS, HTTP/2, a pooled client per host). In the
//! browser build it goes through [`transport`], hyper 1's HTTP/1.1 client over the page's
//! virtual loopback — reqwest's wasm backend is the browser's `fetch`, which is not `Send` and
//! cannot reach NetGet's in-page servers. Everything above the round trip — the command
//! channel, the model's answers, the follow-up chain — is the same code on both.
pub mod actions;
/// The browser transport, shared with the other HTTP-family clients through
/// [`crate::client::http_fetch`].
pub use crate::client::http_fetch::transport;
pub use crate::client::http_fetch::transport::HttpExchange;

pub use actions::HttpClientProtocol;

use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use crate::client::http::actions::{
    HTTP_CLIENT_CONNECTED_EVENT, HTTP_CLIENT_RESPONSE_RECEIVED_EVENT,
};
use crate::client::llm_budget::call_llm_for_client;
use crate::llm::actions::client_trait::{Client, ClientActionResult};
use crate::llm::actions::protocol_trait::Protocol;
use crate::llm::ollama_client::OllamaClient;
use crate::llm::ClientLlmResult;
use crate::logging::emit::Log;
use crate::protocol::Event;
use crate::state::app_state::AppState;
use crate::state::client_handles::{ClientCommand, ClientSendOutcome};
use crate::state::{AccessLogOwner, ClientId, ClientStatus};

/// How often the command loop re-checks that its client still exists. HTTP has no
/// socket to notice a close on, so this is what the old idle task was for.
const REMOVAL_CHECK_INTERVAL: Duration = Duration::from_secs(5);

/// What one executed action did. Shared vocabulary between the connected-event
/// handler and the injected-command loop.
enum Applied {
    /// The action ran; `detail` says what it did.
    Executed(String),
    /// The action asked to end the session.
    Disconnect,
}

/// How an `http_request` is issued.
#[derive(Clone, Copy)]
enum Dispatch {
    /// Spawn the request and return immediately. Used by the connected-event
    /// handler, which runs inline in `connect()` and must not block client creation
    /// on a request that can take the full 30s timeout.
    Spawn,
    /// Await the HTTP exchange so the caller can report what actually happened. Used
    /// by the injected-command loop. The response event is still delivered to the
    /// LLM, from its own registered task, so a parked manual handler cannot wedge the
    /// command loop for the length of a human's think time.
    Await,
}

/// HTTP client that makes requests to remote HTTP servers
pub struct HttpClient;

impl HttpClient {
    /// The HTTP client for one host, built once and kept.
    ///
    /// Three things this avoids, all of which cost real time on every request before:
    ///
    /// - `reqwest::Client::builder().build()` sets up the rustls stack and loads the
    ///   platform root store — on macOS that reads the system keychain through
    ///   Security.framework, which is synchronous and serialises across processes — so it
    ///   runs on `spawn_blocking` rather than parking a tokio worker.
    /// - It is kept, so requests after the first reuse the connection pool instead of
    ///   paying for a fresh TLS stack and handshake each time.
    /// - **The literal-IP resolver bypass.** `reqwest` hands the URL host to its DNS
    ///   resolver unconditionally and `hyper-util`'s `GaiResolver` does not special-case a
    ///   dotted quad, so `http://127.0.0.1:8080` performs a real `getaddrinfo`. On macOS
    ///   that goes through libinfo to mDNSResponder — one system-wide daemon, measured
    ///   blocking for **8.25 seconds** under ~100 concurrent processes. A NetGet HTTP
    ///   client is pointed at a literal IP more often than not, so this is the common case,
    ///   not the exotic one.
    ///
    /// That last point is why the cache is **keyed by host** rather than being a single
    /// process-wide client: `ClientBuilder::resolve` is a per-host override, so a single
    /// shared client cannot carry one for a host it has not been told about. The map is
    /// only ever as large as the set of hosts this process has been pointed at.
    ///
    /// The override logic mirrors `ollama_client::without_dns_for_literal_ip`, which is
    /// private and builds a client with reqwest's default TLS backend; this one keeps
    /// `use_rustls_tls()` deliberately, since native-tls on macOS is the keychain path the
    /// first bullet is about. `host_of` — the part that is easy to get wrong, and did get
    /// wrong once by leaving the port on — is shared.
    ///
    /// Protocol versions are negotiated via ALPN during the handshake, so one client
    /// serves both HTTP/1.1 and HTTP/2.
    #[cfg(not(target_arch = "wasm32"))]
    async fn http_client(base_url: &str) -> Result<reqwest::Client> {
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
                .redirect(crate::client::http_fetch::same_origin_redirects())
                .use_rustls_tls();
            // Only when the host *is* an address. A hostname is left alone: resolving
            // `localhost` or a real name is the resolver's job, and /etc/hosts or
            // split-horizon DNS may legitimately point it somewhere unexpected.
            if let Ok(ip) = build_host.parse::<std::net::IpAddr>() {
                // The port is irrelevant — hyper overwrites it from the URL — so one
                // override serves every port this client is later pointed at.
                builder = builder.resolve(&build_host, std::net::SocketAddr::new(ip, 0));
            }
            builder.build().context("Failed to build HTTP client")
        })
        .await
        .context("HTTP client build task panicked")??;

        // A concurrent builder may have won the race; either client is equally valid, so
        // keep whichever landed first rather than replacing it and orphaning its pool.
        match clients.lock() {
            Ok(mut map) => Ok(map.entry(host).or_insert(built).clone()),
            // Poisoned only if another thread panicked while holding the map. The freshly
            // built client is still usable; it just does not get cached.
            Err(_) => Ok(built),
        }
    }

    /// Connect to an HTTP server with integrated LLM actions
    pub async fn connect_with_llm_actions(
        remote_addr: String,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        client_id: ClientId,
        startup_params: Option<crate::protocol::StartupParams>,
    ) -> Result<SocketAddr> {
        // For HTTP, "connection" is logical, not a persistent TCP connection
        // We'll create an HTTP client and store it in protocol_data

        info!("HTTP client {} initialized for {}", client_id, remote_addr);

        // Store client in protocol_data
        // Ensure base_url has http:// scheme
        let base_url = if remote_addr.starts_with("http://") || remote_addr.starts_with("https://")
        {
            remote_addr.clone()
        } else {
            format!("http://{}", remote_addr)
        };

        // Warm the client for this host here rather than building one and dropping it.
        // This used to bind to `_http_client`: a full rustls stack constructed at connect
        // time and immediately discarded, while every request built another one. It is
        // warmed *after* `base_url` exists, because the cache is keyed by host — warming
        // an unrelated entry would leave the first real request paying the build cost.
        #[cfg(not(target_arch = "wasm32"))]
        Self::http_client(&base_url).await?;
        // The browser transport has no TLS; say so at connect time rather than on the first
        // request, so the dashboard's form shows why instead of a client that never works.
        #[cfg(target_arch = "wasm32")]
        transport::parse_http_url(&base_url)?;

        // `default_headers` is declared in `get_startup_parameters()` as "headers included
        // in all requests". It was never read, so setting it changed nothing. It is stored
        // here and merged in `perform_request`, where a header the model names on the
        // request itself wins over the default of the same name.
        let default_headers = match &startup_params {
            Some(params) => params.get_optional_object("default_headers")?.cloned(),
            None => None,
        };

        app_state
            .with_client_mut(client_id, |client| {
                client.set_protocol_field(
                    "http_client".to_string(),
                    serde_json::json!("initialized"),
                );
                client.set_protocol_field("base_url".to_string(), serde_json::json!(base_url));
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
            "[CLIENT] HTTP client {} ready for {}",
            client_id, remote_addr
        ));
        let _ = status_tx.send("__UPDATE_UI__".to_string());

        // Injected commands (the dashboard's [ send ]). Registered BEFORE the
        // connected-event LLM call below: a dashboard-created client defaults to a
        // `*` manual rule, so that call can park for minutes waiting for a human and
        // [ send ] has to work for the whole park.
        //
        // This task also replaces the old "poll get_client() every 5s" idle task -
        // that check is now one arm of the command loop's select!.
        let command_rx =
            crate::client::command_support::register_command_channel(&app_state, client_id).await;
        let cmd_state = app_state.clone();
        let cmd_llm = llm_client.clone();
        let cmd_tx = status_tx.clone();
        let cmd_task = tokio::spawn(async move {
            Self::command_loop(command_rx, client_id, cmd_state, cmd_llm, cmd_tx).await;
        });
        app_state.register_client_task(client_id, cmd_task).await;

        // Call LLM with http_connected event
        if let Some(instruction) = app_state.get_instruction_for_client(client_id).await {
            let event = Event::new(
                &HTTP_CLIENT_CONNECTED_EVENT,
                serde_json::json!({
                    "base_url": base_url.clone(),
                }),
            );

            match call_llm_for_client(
                &llm_client,
                &app_state,
                client_id.to_string(),
                &instruction,
                "", // No memory yet for initial connection
                Some(&event),
                &crate::client::http::actions::HttpClientProtocol,
                &status_tx,
            )
            .await
            {
                Ok(result) => {
                    // Execute actions from LLM response
                    let protocol = crate::client::http::actions::HttpClientProtocol;

                    for action in result.actions {
                        match protocol.execute_action(action.clone()) {
                            Ok(action_result) => {
                                match Self::apply_action(
                                    action_result,
                                    Dispatch::Spawn,
                                    client_id,
                                    &app_state,
                                    &llm_client,
                                    &status_tx,
                                )
                                .await
                                {
                                    Ok(Applied::Disconnect) => {
                                        info!("LLM requested disconnect after connect");
                                        // Drop the command handle so the dashboard stops
                                        // offering [ send ]; that also ends the command loop.
                                        app_state.remove_client_handle(client_id).await;
                                        app_state
                                            .update_client_status(
                                                client_id,
                                                ClientStatus::Disconnected,
                                            )
                                            .await;
                                        let _ = status_tx.send("__UPDATE_UI__".to_string());
                                        return Ok("0.0.0.0:0".parse().unwrap());
                                    }
                                    Ok(Applied::Executed(detail)) => {
                                        debug!(
                                            "HTTP client {} after connect: {}",
                                            client_id, detail
                                        );
                                    }
                                    Err(e) => {
                                        error!(
                                            "HTTP client {} request after connect failed: {}",
                                            client_id, e
                                        );
                                    }
                                }
                            }
                            Err(e) => {
                                error!("Action execution error: {}", e);
                            }
                        }
                    }
                }
                Err(e) => {
                    error!("LLM error on http_connected event: {}", e);
                }
            }
        }

        // Return a dummy local address (HTTP is connectionless)
        Ok("0.0.0.0:0".parse().unwrap())
    }

    /// Drain injected commands until the channel closes (client removed) or an
    /// injected `disconnect` ends the session.
    ///
    /// `command_support::handle_stream_client_command` cannot serve this client:
    /// there is no write half, and `send_http_request` yields
    /// `ClientActionResult::Custom`. So the action goes through [`Self::apply_action`]
    /// - the same function the connected-event path uses - and the outcome is
    /// recorded and replied exactly the way the generic arm does it.
    async fn command_loop(
        mut command_rx: mpsc::Receiver<ClientCommand>,
        client_id: ClientId,
        app_state: Arc<AppState>,
        llm_client: OllamaClient,
        status_tx: mpsc::UnboundedSender<String>,
    ) {
        let protocol = HttpClientProtocol;
        let mut removal_check = tokio::time::interval(REMOVAL_CHECK_INTERVAL);
        removal_check.tick().await; // the first tick completes immediately

        loop {
            tokio::select! {
                received = command_rx.recv() => {
                    let Some(command) = received else { break };
                    if Self::handle_command(
                        &protocol,
                        command,
                        client_id,
                        &app_state,
                        &llm_client,
                        &status_tx,
                    )
                    .await
                    {
                        break;
                    }
                }
                _ = removal_check.tick() => {
                    if app_state.get_client(client_id).await.is_none() {
                        info!("HTTP client {} stopped", client_id);
                        break;
                    }
                }
            }
        }

        app_state.remove_client_handle(client_id).await;
        let _ = status_tx.send("__UPDATE_UI__".to_string());
    }

    /// Execute one injected action, record it, and reply. Returns `true` when the
    /// command loop should stop.
    async fn handle_command(
        protocol: &HttpClientProtocol,
        command: ClientCommand,
        client_id: ClientId,
        app_state: &Arc<AppState>,
        llm_client: &OllamaClient,
        status_tx: &mpsc::UnboundedSender<String>,
    ) -> bool {
        let action = command.action.clone();
        let outcome = match protocol.execute_action(action.clone()) {
            Err(e) => Ok(ClientSendOutcome::Rejected {
                error: e.to_string(),
            }),
            Ok(action_result) => match Self::apply_action(
                action_result,
                Dispatch::Await,
                client_id,
                app_state,
                llm_client,
                status_tx,
            )
            .await
            {
                // Never `Sent`: reqwest owns the socket and does not report how many
                // bytes the request serialised to, so a byte count here would be
                // invented. `Executed` carries the response status instead, which is
                // both true and more useful.
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
                "HTTP client {} injected action failed: {}",
                client_id, e
            ));
        }
        let _ = status_tx.send("__UPDATE_UI__".to_string());
        crate::client::command_support::reply(command, outcome);

        if disconnect {
            app_state
                .update_client_status(client_id, ClientStatus::Disconnected)
                .await;
        }
        disconnect
    }

    /// Turn one executed action into an HTTP request (or a session end).
    ///
    /// Shared by the connected-event handler and the injected-command loop so the
    /// `http_request` decoding exists exactly once.
    async fn apply_action(
        action_result: ClientActionResult,
        dispatch: Dispatch,
        client_id: ClientId,
        app_state: &Arc<AppState>,
        llm_client: &OllamaClient,
        status_tx: &mpsc::UnboundedSender<String>,
    ) -> Result<Applied> {
        match action_result {
            ClientActionResult::Custom { name, data } if name == "http_request" => {
                let method = data["method"].as_str().unwrap_or("GET").to_string();
                let path = data["path"].as_str().unwrap_or("/").to_string();
                let headers = data["headers"].as_object().cloned();
                let body = data["body"].as_str().map(|s| s.to_string());

                match dispatch {
                    Dispatch::Spawn => {
                        let llm_clone = llm_client.clone();
                        let state_clone = app_state.clone();
                        let status_clone = status_tx.clone();
                        let (log_method, log_path) = (method.clone(), path.clone());

                        let request_handle = tokio::spawn(async move {
                            if let Err(e) = HttpClient::make_request(
                                client_id,
                                method,
                                path,
                                headers,
                                body,
                                state_clone,
                                llm_clone,
                                status_clone,
                            )
                            .await
                            {
                                error!("HTTP request failed: {}", e);
                            }
                        });
                        // Registered so an in-flight request (and the LLM call it makes
                        // on completion) is aborted when the client is stopped.
                        app_state
                            .register_client_task(client_id, request_handle)
                            .await;
                        Ok(Applied::Executed(format!(
                            "http_request {} {} dispatched",
                            log_method, log_path
                        )))
                    }
                    Dispatch::Await => {
                        let exchange = Self::perform_request(
                            client_id,
                            method.clone(),
                            path.clone(),
                            headers,
                            body,
                            app_state,
                            status_tx,
                        )
                        .await?;
                        let detail = format!(
                            "http_request {} {} -> {} ({} byte body)",
                            method,
                            path,
                            exchange.status_code,
                            exchange.body.len()
                        );

                        let llm_clone = llm_client.clone();
                        let state_clone = app_state.clone();
                        let status_clone = status_tx.clone();
                        let notify_handle = tokio::spawn(async move {
                            HttpClient::notify_response(
                                client_id,
                                exchange,
                                state_clone,
                                llm_clone,
                                status_clone,
                                0,
                            )
                            .await;
                        });
                        app_state
                            .register_client_task(client_id, notify_handle)
                            .await;
                        Ok(Applied::Executed(detail))
                    }
                }
            }
            ClientActionResult::Disconnect => Ok(Applied::Disconnect),
            ClientActionResult::WaitForMore => Ok(Applied::Executed("wait_for_more".to_string())),
            ClientActionResult::NoAction => Ok(Applied::Executed("no_action".to_string())),
            // Not swallowed: an action this client cannot carry out says so, rather
            // than looking identical to success.
            ClientActionResult::Custom { name, .. } => Ok(Applied::Executed(format!(
                "custom result '{name}' is not handled by the HTTP client"
            ))),
            ClientActionResult::SendData(_) => Ok(Applied::Executed(
                "send_data has no meaning for a request/response HTTP client".to_string(),
            )),
            ClientActionResult::Multiple(_) => Ok(Applied::Executed(
                "multiple results are not produced by the HTTP client".to_string(),
            )),
        }
    }

    /// Make an HTTP request and hand the response to the LLM.
    #[allow(clippy::too_many_arguments)]
    pub async fn make_request(
        client_id: ClientId,
        method: String,
        path: String,
        headers: Option<serde_json::Map<String, serde_json::Value>>,
        body: Option<String>,
        app_state: Arc<AppState>,
        llm_client: OllamaClient,
        status_tx: mpsc::UnboundedSender<String>,
    ) -> Result<()> {
        let exchange = Self::perform_request(
            client_id, method, path, headers, body, &app_state, &status_tx,
        )
        .await?;
        Self::notify_response(client_id, exchange, app_state, llm_client, status_tx, 0).await;
        Ok(())
    }

    /// Perform the HTTP round-trip only. No LLM involvement, so a caller can await
    /// this and know exactly what the server answered.
    #[allow(clippy::too_many_arguments)]
    pub async fn perform_request(
        client_id: ClientId,
        method: String,
        path: String,
        headers: Option<serde_json::Map<String, serde_json::Value>>,
        body: Option<String>,
        app_state: &AppState,
        status_tx: &mpsc::UnboundedSender<String>,
    ) -> Result<HttpExchange> {
        // Base URL and the startup `default_headers`, read together under one guard.
        let (base_url, default_headers) = app_state
            .with_client_mut(client_id, |client| {
                (
                    client
                        .get_protocol_field("base_url")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                    client
                        .get_protocol_field("default_headers")
                        .and_then(|v| v.as_object().cloned()),
                )
            })
            .await
            .unwrap_or((None, None));
        let base_url = base_url.context("No base URL found")?;

        // Same origin as `remote_addr` or refused: see `resolve_same_origin`. The startup
        // `default_headers` go on every request, so a request to another host would carry
        // the operator's API key there.
        let url = crate::client::http_fetch::resolve_same_origin(&base_url, &path)?;

        info!(
            "HTTP client {} making request: {} {}",
            client_id, method, url
        );

        // Startup defaults merged *underneath* the request's own headers. Merged into one
        // map before anything is applied, because `RequestBuilder::header` appends: setting
        // the same name twice would put both values on the wire instead of overriding.
        // Keyed by lowercased name, because HTTP header names are case-insensitive and
        // `Accept` from the request must replace `accept` from the defaults.
        let mut merged = serde_json::Map::new();
        for (key, value) in default_headers.unwrap_or_default() {
            merged.insert(key.to_ascii_lowercase(), value);
        }
        if let Some(hdrs) = headers {
            for (key, value) in hdrs {
                merged.insert(key.to_ascii_lowercase(), value);
            }
        }
        let merged: Vec<(String, String)> = merged
            .into_iter()
            .filter_map(|(key, value)| value.as_str().map(|v| (key, v.to_string())))
            .collect();

        let result = Self::round_trip(&method, &url, merged, body).await;
        match result {
            Ok(exchange) => {
                info!(
                    "HTTP client {} received response: {}",
                    client_id, exchange.status_text
                );
                Ok(exchange)
            }
            Err(e) => {
                Log::new(Some(status_tx))
                    .error(format!("HTTP client {} request failed: {}", client_id, e));
                Err(e)
            }
        }
    }

    /// The network round trip through reqwest: the native transport.
    #[cfg(not(target_arch = "wasm32"))]
    async fn round_trip(
        method: &str,
        url: &str,
        headers: Vec<(String, String)>,
        body: Option<String>,
    ) -> Result<HttpExchange> {
        // Keyed on the *request* URL, not the base: `path` may be an absolute URL
        // pointing at a different host, and that host needs its own resolver override.
        let http_client = Self::http_client(url).await?;

        let mut request = match method.to_uppercase().as_str() {
            "GET" => http_client.get(url),
            "POST" => http_client.post(url),
            "PUT" => http_client.put(url),
            "DELETE" => http_client.delete(url),
            "HEAD" => http_client.head(url),
            "PATCH" => http_client.patch(url),
            _ => return Err(anyhow::anyhow!("Unsupported HTTP method: {}", method)),
        };
        for (key, value) in headers {
            request = request.header(&key, value);
        }
        if let Some(body_str) = body {
            request = request.body(body_str);
        }

        let mut response = request.send().await?;
        let status = response.status();
        let mut resp_headers = serde_json::Map::new();
        for (name, value) in response.headers() {
            if let Ok(val_str) = value.to_str() {
                resp_headers.insert(name.to_string(), serde_json::json!(val_str));
            }
        }
        // Read chunk by chunk against the same bound the browser transport enforces, so a
        // server that streams without end is refused rather than buffered until the process
        // dies.
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            if body.len() + chunk.len() > transport::MAX_RESPONSE_BODY_BYTES {
                anyhow::bail!(
                    "response body exceeds the {}-byte limit; refused",
                    transport::MAX_RESPONSE_BODY_BYTES
                );
            }
            body.extend_from_slice(&chunk);
        }

        Ok(HttpExchange {
            status_code: status.as_u16(),
            status_text: status.to_string(),
            headers: resp_headers,
            body: String::from_utf8_lossy(&body).into_owned(),
        })
    }

    /// The network round trip in the browser: hyper's HTTP/1.1 client over the page's
    /// virtual loopback, see [`transport`].
    #[cfg(target_arch = "wasm32")]
    async fn round_trip(
        method: &str,
        url: &str,
        headers: Vec<(String, String)>,
        body: Option<String>,
    ) -> Result<HttpExchange> {
        transport::fetch(
            method,
            url,
            &headers,
            body,
            transport::REQUEST_TIMEOUT,
            transport::MAX_RESPONSE_BODY_BYTES,
        )
        .await
    }

    /// How many exchanges deep this client keeps following the model's answers. Each
    /// response can ask for another request, which produces another response; without a
    /// bound a model that answers every response with a request never stops.
    const MAX_FOLLOWUP_DEPTH: u8 = 4;

    /// Hand a completed exchange to the LLM as an `http_response_received` event.
    ///
    /// Boxed with an explicit `+ Send` because the chain is genuinely self-referential
    /// (report → request → report) and the future is awaited inside a `tokio::spawn`,
    /// which inference will not give `Send` on its own. This is the shape root
    /// `CLAUDE.md` prescribes for the "client asks the model and throws the answer away"
    /// family of defects: **a depth bound, not silence.**
    fn notify_response(
        client_id: ClientId,
        exchange: HttpExchange,
        app_state: Arc<AppState>,
        llm_client: OllamaClient,
        status_tx: mpsc::UnboundedSender<String>,
        depth: u8,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> {
        Box::pin(async move {
            let Some(instruction) = app_state.get_instruction_for_client(client_id).await else {
                return;
            };

            let protocol = Arc::new(crate::client::http::actions::HttpClientProtocol::new());
            let event = Event::new(
                &HTTP_CLIENT_RESPONSE_RECEIVED_EVENT,
                serde_json::json!({
                    "status_code": exchange.status_code,
                    "status_text": exchange.status_text,
                    "headers": exchange.headers,
                    "body": exchange.body,
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

                    // Execute what the model asked for, and report each result back to it
                    // until the depth bound. Reporting used to stop after one hop: the
                    // follow-up ran but its response raised no event, so a model that read
                    // a 302 and asked for the redirect target never learned what it got.
                    use crate::llm::actions::client_trait::{Client, ClientActionResult};
                    for action in actions {
                        let Ok(ClientActionResult::Custom { name, data }) =
                            protocol.execute_action(action.clone())
                        else {
                            continue;
                        };
                        if name != "http_request" {
                            continue;
                        }
                        match Self::perform_request(
                            client_id,
                            data["method"].as_str().unwrap_or("GET").to_string(),
                            data["path"].as_str().unwrap_or("/").to_string(),
                            data["headers"].as_object().cloned(),
                            data["body"].as_str().map(|s| s.to_string()),
                            &app_state,
                            &status_tx,
                        )
                        .await
                        {
                            Ok(exchange) => {
                                if depth + 1 < Self::MAX_FOLLOWUP_DEPTH {
                                    Self::notify_response(
                                        client_id,
                                        exchange,
                                        app_state.clone(),
                                        llm_client.clone(),
                                        status_tx.clone(),
                                        depth + 1,
                                    )
                                    .await;
                                } else {
                                    warn!(
                                        "HTTP client {} reached the follow-up depth limit \
                                         ({}); not reporting the response to the model",
                                        client_id,
                                        Self::MAX_FOLLOWUP_DEPTH
                                    );
                                }
                            }
                            Err(e) => {
                                error!("HTTP client {} follow-up request failed: {}", client_id, e)
                            }
                        }
                    }
                }
                Err(e) => {
                    error!("LLM error for HTTP client {}: {}", client_id, e);
                }
            }
        })
    }
}
