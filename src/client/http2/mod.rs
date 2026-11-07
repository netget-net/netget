//! HTTP/2 client implementation
pub mod actions;

pub use actions::Http2ClientProtocol;

use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{error, info, warn};

use crate::client::http2::actions::HTTP2_CLIENT_RESPONSE_RECEIVED_EVENT;
use crate::client::http_fetch::FetchClient;
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

/// How often the command loop re-checks that its client still exists. HTTP/2 here is
/// request/response over reqwest with no read loop, so this is what the old idle task
/// was for.
const REMOVAL_CHECK_INTERVAL: Duration = Duration::from_secs(5);

/// One completed HTTP/2 exchange.
///
/// Split out of [`Http2Client::make_request`] so the injected-command loop can await
/// the network round-trip - and report a truthful outcome - without also awaiting the
/// LLM call the response event triggers.
pub struct Http2Exchange {
    pub status_code: u16,
    pub status_text: String,
    pub http_version: String,
    pub headers: serde_json::Map<String, serde_json::Value>,
    pub body: String,
}

/// What one executed action did.
enum Applied {
    /// The action ran; `detail` says what it did.
    Executed(String),
    /// The action asked to end the session.
    Disconnect,
}

/// HTTP/2 client that makes requests to remote HTTP/2 servers
pub struct Http2Client;

impl Http2Client {
    /// The HTTP/2 client for one host, built once and kept.
    ///
    /// This used to be built **per request**, plus one more at connect that was bound to
    /// `_http_client` and immediately dropped — both on the async runtime. Three costs,
    /// all of which root `CLAUDE.md` records as measured rather than theoretical:
    ///
    /// - `reqwest::Client::builder().build()` sets up the rustls stack and loads the
    ///   platform root store. On macOS that reads the keychain through Security.framework,
    ///   synchronously and serialised across processes; called on the async runtime it
    ///   parks a tokio worker, which is how the `doh` client's whole runtime stalled. It
    ///   now runs on `spawn_blocking`.
    /// - A fresh client per request means a fresh connection pool per request, so every
    ///   request paid for a new TCP + TLS handshake — the opposite of what HTTP/2 is for.
    /// - **The literal-IP resolver bypass.** `reqwest` hands the URL host to its resolver
    ///   unconditionally and `hyper-util`'s `GaiResolver` does not special-case a dotted
    ///   quad, so `http://127.0.0.1:8080` performs a real `getaddrinfo` — measured at 8.25
    ///   seconds through mDNSResponder under ~100 concurrent processes. `ClientBuilder::
    ///   resolve` is a per-host override, which is why this cache is keyed by host rather
    ///   than being one process-wide client.
    ///
    /// `http2_prior_knowledge()` is kept: this client speaks cleartext h2c and does not
    /// negotiate via ALPN, which is what makes it usable against NetGet's own HTTP/2
    /// server (that server never advertises ALPN).
    #[cfg(not(target_arch = "wasm32"))]
    async fn reqwest_client(url: &str) -> Result<reqwest::Client> {
        use std::collections::HashMap;
        use std::sync::{Mutex, OnceLock};

        static CLIENTS: OnceLock<Mutex<HashMap<String, reqwest::Client>>> = OnceLock::new();
        let clients = CLIENTS.get_or_init(|| Mutex::new(HashMap::new()));

        let host = crate::llm::ollama_client::host_of(url).to_string();
        if let Some(client) = clients.lock().ok().and_then(|map| map.get(&host).cloned()) {
            return Ok(client);
        }

        let build_host = host.clone();
        let built = tokio::task::spawn_blocking(move || {
            let mut builder = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .redirect(crate::client::http_fetch::same_origin_redirects())
                .http2_prior_knowledge();
            // Only when the host *is* an address. A hostname is left alone: resolving it
            // is the resolver's job, and /etc/hosts may legitimately redirect it.
            if let Ok(ip) = build_host.parse::<std::net::IpAddr>() {
                // The port is irrelevant — hyper overwrites it from the URL.
                builder = builder.resolve(&build_host, std::net::SocketAddr::new(ip, 0));
            }
            builder.build().context("Failed to build HTTP/2 client")
        })
        .await
        .context("HTTP/2 client build task panicked")??;

        match clients.lock() {
            Ok(mut map) => Ok(map.entry(host).or_insert(built).clone()),
            // Poisoned only if another thread panicked holding the map; the client is
            // still usable, it just does not get cached.
            Err(_) => Ok(built),
        }
    }
    /// The HTTP/2 client for `url`'s host: the cached reqwest client natively
    /// ([`Self::reqwest_client`]); in the browser build the shared hyper transport
    /// ([`crate::client::http_fetch`]) speaking HTTP/2 with prior knowledge over the page's
    /// virtual loopback, with the same 30-second bound.
    async fn http2_client(url: &str) -> Result<FetchClient> {
        #[cfg(not(target_arch = "wasm32"))]
        let client = FetchClient::from_reqwest(Self::reqwest_client(url).await?);
        #[cfg(target_arch = "wasm32")]
        let client = {
            let _ = url;
            FetchClient::transport(Duration::from_secs(30)).http2_prior_knowledge()
        };
        Ok(client)
    }

    /// Connect to an HTTP/2 server with integrated LLM actions
    pub async fn connect_with_llm_actions(
        remote_addr: String,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        client_id: ClientId,
        startup_params: Option<crate::protocol::StartupParams>,
    ) -> Result<SocketAddr> {
        // For HTTP/2, "connection" is logical, with persistent multiplexed streams
        // We'll create an HTTP/2 client and store it in protocol_data

        info!(
            "HTTP/2 client {} initialized for {}",
            client_id, remote_addr
        );

        // Warm the client for this host rather than building one and dropping it: this
        // used to bind to `_http_client`, a full rustls stack constructed at connect time
        // and discarded, while `perform_request` built another one for every request.
        Self::http2_client(&remote_addr).await?;
        // In the browser build the transport has no TLS: an `https://` server is refused here,
        // with the reason, rather than on the first request. A bare address is spoken to as
        // cleartext h2c, as `perform_request` does.
        crate::client::http_fetch::check_url(&if remote_addr.contains("://") {
            remote_addr.clone()
        } else {
            format!("http://{remote_addr}")
        })?;

        // `default_headers` is declared as "headers included in all requests" and nothing
        // read it, so setting it changed nothing. Stored here, merged in `perform_request`.
        let default_headers = match &startup_params {
            Some(params) => params.get_optional_object("default_headers")?.cloned(),
            None => None,
        };

        // Store client in protocol_data
        app_state
            .with_client_mut(client_id, |client| {
                client.set_protocol_field(
                    "http2_client".to_string(),
                    serde_json::json!("initialized"),
                );
                client.set_protocol_field("base_url".to_string(), serde_json::json!(remote_addr));
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
            "[CLIENT] HTTP/2 client {} ready for {}",
            client_id, remote_addr
        ));
        let _ = status_tx.send("__UPDATE_UI__".to_string());

        // Injected commands (the dashboard's [ send ]). This client raises no
        // connected event, so there is no LLM call to register ahead of - but the
        // handle still has to exist before `connect()` returns, or the dashboard
        // greys out [ send ] on a client that is up.
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

        // Raise the connected event.
        //
        // It was declared and nothing ever raised it, and nothing else called this
        // client's request code either -- so a HTTP/2 client initialised itself and
        // then did nothing for the rest of its life. The command channel was, until now,
        // the only thing that could reach the wire at all.
        //
        // Raised from a registered task rather than inline: a dashboard-created client
        // defaults to a `*` -> manual rule, and awaiting a parked answer here would block
        // client creation itself. Requests go through `perform_request`, which raises no
        // event, so a connect instruction cannot start an unbounded chain.
        let conn_base_url = remote_addr.clone();
        let conn_state = app_state.clone();
        let conn_llm = llm_client.clone();
        let status_tx_c = status_tx.clone();
        let conn_task = tokio::spawn(async move {
            let Some(instruction) = conn_state.get_instruction_for_client(client_id).await else {
                return;
            };
            let protocol = crate::client::http2::actions::Http2ClientProtocol::new();
            let event = Event::new(
                &crate::client::http2::actions::HTTP2_CLIENT_CONNECTED_EVENT,
                serde_json::json!({ "base_url": conn_base_url.clone() }),
            );
            match crate::client::llm_budget::call_llm_for_client(
                &conn_llm,
                &conn_state,
                client_id.to_string(),
                &instruction,
                "",
                Some(&event),
                &protocol,
                &status_tx_c,
            )
            .await
            {
                Ok(result) => {
                    if let Some(mem) = result.memory_updates {
                        conn_state.set_memory_for_client(client_id, mem).await;
                    }
                    use crate::llm::actions::client_trait::{Client, ClientActionResult};
                    for action in result.actions {
                        let Ok(ClientActionResult::Custom { name, data }) =
                            protocol.execute_action(action.clone())
                        else {
                            continue;
                        };
                        if name != "http2_request" {
                            continue;
                        }
                        match Self::perform_request(
                            client_id,
                            data["method"].as_str().unwrap_or("GET").to_string(),
                            data["path"].as_str().unwrap_or("/").to_string(),
                            data["headers"].as_object().cloned(),
                            data["body"].as_str().map(|s| s.to_string()),
                            &conn_state,
                            &status_tx_c,
                        )
                        .await
                        {
                            // The exchange used to be dropped here, so the very first
                            // request -- the one the connect instruction asks for -- never
                            // raised `http2_response_received`. The model was told to make
                            // a request and then never told what came back.
                            Ok(exchange) => {
                                Self::notify_response(
                                    client_id,
                                    exchange,
                                    conn_state.clone(),
                                    conn_llm.clone(),
                                    status_tx_c.clone(),
                                    0,
                                )
                                .await;
                            }
                            Err(e) => error!(
                                "HTTP/2 client {} connect-time request failed: {}",
                                client_id, e
                            ),
                        }
                    }
                }
                Err(e) => error!(
                    "HTTP/2 client {} LLM error on connected event: {}",
                    client_id, e
                ),
            }
        });
        app_state.register_client_task(client_id, conn_task).await;

        // Return a dummy local address (HTTP/2 is connectionless)
        Ok("0.0.0.0:0".parse().unwrap())
    }

    /// Drain injected commands until the channel closes (client removed) or an
    /// injected `disconnect` ends the session.
    ///
    /// `command_support::handle_stream_client_command` cannot serve this client:
    /// there is no write half, and `send_http2_request` yields
    /// `ClientActionResult::Custom`. So the action goes through [`Self::apply_action`]
    /// and the outcome is recorded and replied the way the generic arm does it.
    async fn command_loop(
        mut command_rx: mpsc::Receiver<ClientCommand>,
        client_id: ClientId,
        app_state: Arc<AppState>,
        llm_client: OllamaClient,
        status_tx: mpsc::UnboundedSender<String>,
    ) {
        let protocol = Http2ClientProtocol::new();
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
                        info!("HTTP/2 client {} stopped", client_id);
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
        protocol: &Http2ClientProtocol,
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
            Ok(action_result) => {
                match Self::apply_action(action_result, client_id, app_state, llm_client, status_tx)
                    .await
                {
                    // Never `Sent`: reqwest owns the socket and does not report how
                    // many bytes the request serialised to, so a byte count here would
                    // be invented. `Executed` carries the response status instead.
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
                "HTTP/2 client {} injected action failed: {}",
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

    /// Turn one executed action into an HTTP/2 request (or a session end).
    ///
    /// The exchange is awaited so the caller can report what the server actually
    /// answered; the response event is delivered from its own registered task, so a
    /// parked manual handler cannot wedge the command loop for a human's think time.
    async fn apply_action(
        action_result: ClientActionResult,
        client_id: ClientId,
        app_state: &Arc<AppState>,
        llm_client: &OllamaClient,
        status_tx: &mpsc::UnboundedSender<String>,
    ) -> Result<Applied> {
        match action_result {
            ClientActionResult::Custom { name, data } if name == "http2_request" => {
                let method = data["method"].as_str().unwrap_or("GET").to_string();
                let path = data["path"].as_str().unwrap_or("/").to_string();
                let headers = data["headers"].as_object().cloned();
                let body = data["body"].as_str().map(|s| s.to_string());

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
                    "http2_request {} {} -> {} ({} byte body)",
                    method,
                    path,
                    exchange.status_code,
                    exchange.body.len()
                );

                let llm_clone = llm_client.clone();
                let state_clone = app_state.clone();
                let status_clone = status_tx.clone();
                let notify_handle = tokio::spawn(async move {
                    Http2Client::notify_response(
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
            ClientActionResult::Disconnect => Ok(Applied::Disconnect),
            ClientActionResult::WaitForMore => Ok(Applied::Executed("wait_for_more".to_string())),
            ClientActionResult::NoAction => Ok(Applied::Executed("no_action".to_string())),
            // Not swallowed: an action this client cannot carry out says so, rather
            // than looking identical to success.
            ClientActionResult::Custom { name, .. } => Ok(Applied::Executed(format!(
                "custom result '{name}' is not handled by the HTTP/2 client"
            ))),
            ClientActionResult::SendData(_) => Ok(Applied::Executed(
                "send_data has no meaning for a request/response HTTP/2 client".to_string(),
            )),
            ClientActionResult::Multiple(_) => Ok(Applied::Executed(
                "multiple results are not produced by the HTTP/2 client".to_string(),
            )),
        }
    }

    /// Make an HTTP/2 request and hand the response to the LLM.
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

    /// Perform the HTTP/2 round-trip only. No LLM involvement, so a caller can await
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
    ) -> Result<Http2Exchange> {
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

        // Same origin as `remote_addr` or refused: see `resolve_same_origin`. `base_url` is
        // whatever the client was opened on, often a bare host:port; the helper prefixes
        // http://, which is right for cleartext h2c. The startup `default_headers` go on
        // every request, so a request to another host would carry the operator's API key.
        let url = crate::client::http_fetch::resolve_same_origin(&base_url, &path)?;

        info!(
            "HTTP/2 client {} making request: {} {}",
            client_id, method, url
        );

        let http_client = Self::http2_client(&url).await?;

        let mut request = match method.to_uppercase().as_str() {
            "GET" => http_client.get(&url),
            "POST" => http_client.post(&url),
            "PUT" => http_client.put(&url),
            "DELETE" => http_client.delete(&url),
            "HEAD" => http_client.head(&url),
            "PATCH" => http_client.patch(&url),
            _ => return Err(anyhow::anyhow!("Unsupported HTTP method: {}", method)),
        };

        // Startup defaults merged *underneath* the request's own headers, keyed by the
        // lowercased name. Merged before anything is applied because
        // `RequestBuilder::header` appends - applying both sets in turn would put two
        // values of the same header on the wire instead of overriding.
        let mut merged = serde_json::Map::new();
        for (key, value) in default_headers.unwrap_or_default() {
            merged.insert(key.to_ascii_lowercase(), value);
        }
        if let Some(hdrs) = headers {
            for (key, value) in hdrs {
                merged.insert(key.to_ascii_lowercase(), value);
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
                let version = response.version();

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
                    "HTTP/2 client {} received response: {} ({}) version: {:?}",
                    client_id, status_code, status, version
                );

                Ok(Http2Exchange {
                    status_code,
                    status_text: status.to_string(),
                    http_version: format!("{:?}", version),
                    headers: resp_headers,
                    body: body_text,
                })
            }
            Err(e) => {
                Log::new(Some(status_tx))
                    .error(format!("HTTP/2 client {} request failed: {}", client_id, e));
                Err(e)
            }
        }
    }

    /// How many exchanges deep this client keeps following the model's answers. Each
    /// response can ask for another request, which produces another response; without a
    /// bound a model that answers every response with a request never stops.
    const MAX_FOLLOWUP_DEPTH: u8 = 4;

    /// Hand a completed exchange to the LLM as an `http2_response_received` event.
    ///
    /// Boxed with an explicit `+ Send` because the chain is genuinely self-referential
    /// (report -> request -> report) and the future is awaited inside a `tokio::spawn`.
    fn notify_response(
        client_id: ClientId,
        exchange: Http2Exchange,
        app_state: Arc<AppState>,
        llm_client: OllamaClient,
        status_tx: mpsc::UnboundedSender<String>,
        depth: u8,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> {
        Box::pin(async move {
            let Some(instruction) = app_state.get_instruction_for_client(client_id).await else {
                return;
            };

            let protocol = Arc::new(crate::client::http2::actions::Http2ClientProtocol::new());
            let event = Event::new(
                &HTTP2_CLIENT_RESPONSE_RECEIVED_EVENT,
                serde_json::json!({
                    "status_code": exchange.status_code,
                    "status_text": exchange.status_text,
                    "http_version": exchange.http_version,
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
                    // until the depth bound above. These used to be discarded, so a model
                    // that read a response and wanted to follow it with another request
                    // was silently ignored — the entire purpose of raising the event.
                    use crate::llm::actions::client_trait::{Client, ClientActionResult};
                    for action in actions {
                        let Ok(ClientActionResult::Custom { name, data }) =
                            protocol.execute_action(action.clone())
                        else {
                            continue;
                        };
                        if name != "http2_request" {
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
                                        "HTTP/2 client {} reached the follow-up depth limit \
                                     ({}); not reporting the response to the model",
                                        client_id,
                                        Self::MAX_FOLLOWUP_DEPTH
                                    );
                                }
                            }
                            Err(e) => error!(
                                "HTTP/2 client {} follow-up request failed: {}",
                                client_id, e
                            ),
                        }
                    }
                }
                Err(e) => {
                    error!("LLM error for HTTP/2 client {}: {}", client_id, e);
                }
            }
        })
    }
}
