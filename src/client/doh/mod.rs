//! DNS-over-HTTPS (DoH) client implementation
pub mod actions;

pub use actions::DohClientProtocol;

use anyhow::{Context, Result};
use hickory_proto::op::{Message, Query};
use hickory_proto::rr::{Name, RecordType};
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, error, info, trace, warn};

use crate::client::doh::actions::{DOH_CLIENT_CONNECTED_EVENT, DOH_CLIENT_RESPONSE_RECEIVED_EVENT};
use crate::client::llm_budget::call_llm_for_client;
use crate::llm::actions::client_trait::{Client, ClientActionResult};
use crate::llm::actions::protocol_trait::Protocol;
use crate::llm::ollama_client::OllamaClient;
use crate::llm::ClientLlmResult;
use crate::protocol::Event;
use crate::state::app_state::AppState;
use crate::state::client_handles::{ClientCommand, ClientSendOutcome};
use crate::state::{AccessLogOwner, ClientId, ClientStatus};

/// How often the command loop re-checks that its client still exists. DoH is
/// request/response over HTTPS with no read loop, so nothing else would notice.
const REMOVAL_CHECK_INTERVAL: Duration = Duration::from_secs(5);

/// What one executed action did. Shared vocabulary between the LLM action path and
/// the injected-command loop.
enum Applied {
    /// A DNS query completed. `detail` describes it; `event_data` is the payload for
    /// the `doh_response_received` event, which the caller delivers on its own terms
    /// (inline for the LLM chain, from a separate task for an injected command).
    Queried {
        detail: String,
        event_data: serde_json::Value,
    },
    /// The action asked to end the session.
    Disconnect,
    /// The model asked to wait for more.
    WaitForMore,
    /// The action ran but this client has nothing to do with the result.
    Ignored(String),
}

/// DoH client that makes DNS queries over HTTPS
pub struct DohClient;

impl DohClient {
    /// Connect to a DoH server with integrated LLM actions
    pub async fn connect_with_llm_actions(
        server_url: String,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        client_id: ClientId,
        startup_params: Option<crate::protocol::StartupParams>,
    ) -> Result<SocketAddr> {
        info!("DoH client {} initializing for {}", client_id, server_url);

        // Trust settings, read once and stored for the per-query HTTP client.
        let ca_cert_pem = startup_params
            .as_ref()
            .and_then(|p| p.get_optional_string("ca_cert_pem").ok().flatten());
        let insecure_skip_verify = startup_params
            .as_ref()
            .and_then(|p| p.get_optional_bool("insecure_skip_verify").ok().flatten())
            .unwrap_or(false);

        // Store server URL in client state
        app_state
            .with_client_mut(client_id, |client| {
                client.set_protocol_field(
                    "server_url".to_string(),
                    serde_json::json!(server_url.clone()),
                );
                if let Some(pem) = &ca_cert_pem {
                    client.set_protocol_field(
                        "ca_cert_pem".to_string(),
                        serde_json::json!(pem.clone()),
                    );
                }
                client.set_protocol_field(
                    "insecure_skip_verify".to_string(),
                    serde_json::json!(insecure_skip_verify),
                );
            })
            .await;

        // Update status to connected
        app_state
            .update_client_status(client_id, ClientStatus::Connected)
            .await;
        let _ = status_tx.send(format!(
            "[CLIENT] DoH client {} connected to {}",
            client_id, server_url
        ));
        let _ = status_tx.send("__UPDATE_UI__".to_string());

        info!("DoH client {} connected to {}", client_id, server_url);

        let protocol = Arc::new(DohClientProtocol::new());

        // Injected commands (the dashboard's [ send ]). Registered BEFORE the
        // connected-event LLM call below: a dashboard-created client defaults to a
        // `*` manual rule, so that call can park for minutes waiting for a human and
        // [ send ] has to work for the whole park.
        let command_rx =
            crate::client::command_support::register_command_channel(&app_state, client_id).await;
        let cmd_state = app_state.clone();
        let cmd_llm = llm_client.clone();
        let cmd_tx = status_tx.clone();
        let cmd_protocol = protocol.clone();
        let cmd_url = server_url.clone();
        let cmd_task = tokio::spawn(async move {
            Self::command_loop(
                command_rx,
                client_id,
                cmd_state,
                cmd_llm,
                cmd_tx,
                cmd_protocol,
                cmd_url,
            )
            .await;
        });
        app_state.register_client_task(client_id, cmd_task).await;

        // Send connected event to LLM
        let connected_event = Event::new(
            &DOH_CLIENT_CONNECTED_EVENT,
            serde_json::json!({
                "server_url": server_url,
            }),
        );

        // Get instruction and memory for LLM call
        let instruction = app_state
            .get_instruction_for_client(client_id)
            .await
            .unwrap_or_default();
        let memory = app_state
            .get_memory_for_client(client_id)
            .await
            .unwrap_or_default();

        // Call LLM with connected event
        match call_llm_for_client(
            &llm_client,
            &app_state,
            client_id.to_string(),
            &instruction,
            &memory,
            Some(&connected_event),
            protocol.as_ref(),
            &status_tx,
        )
        .await
        {
            Ok(llm_result) => {
                debug!(
                    "DoH client {} received {} actions from LLM",
                    client_id,
                    llm_result.actions.len()
                );

                // Execute any immediate actions. Registered with AppState so
                // stop_client can abort this task — dropping a JoinHandle only
                // detaches it in Tokio.
                let task_handle = tokio::spawn(Self::execute_llm_actions(
                    client_id,
                    llm_result,
                    app_state.clone(),
                    llm_client.clone(),
                    status_tx.clone(),
                    protocol.clone(),
                    server_url.clone(),
                ));
                app_state.register_client_task(client_id, task_handle).await;
            }
            Err(e) => {
                error!("DoH client {} LLM call failed: {}", client_id, e);
            }
        }

        // Return dummy local address (DoH is over HTTPS, connectionless at app level)
        Ok("0.0.0.0:0".parse().unwrap())
    }

    /// Drain injected commands until the channel closes (client removed) or an
    /// injected `disconnect` ends the session.
    ///
    /// `command_support::handle_stream_client_command` cannot serve this client:
    /// there is no write half, and `query_dns` yields `ClientActionResult::Custom`.
    /// So the action goes through [`Self::apply_action`] — the same function the LLM
    /// path uses — and the outcome is recorded and replied the way the generic arm
    /// does it.
    #[allow(clippy::too_many_arguments)]
    async fn command_loop(
        mut command_rx: mpsc::Receiver<ClientCommand>,
        client_id: ClientId,
        app_state: Arc<AppState>,
        llm_client: OllamaClient,
        status_tx: mpsc::UnboundedSender<String>,
        protocol: Arc<DohClientProtocol>,
        server_url: String,
    ) {
        let mut removal_check = tokio::time::interval(REMOVAL_CHECK_INTERVAL);
        removal_check.tick().await; // the first tick completes immediately

        loop {
            tokio::select! {
                received = command_rx.recv() => {
                    let Some(command) = received else { break };
                    if Self::handle_command(
                        command,
                        client_id,
                        &app_state,
                        &llm_client,
                        &status_tx,
                        &protocol,
                        &server_url,
                    )
                    .await
                    {
                        break;
                    }
                }
                _ = removal_check.tick() => {
                    if app_state.get_client(client_id).await.is_none() {
                        info!("DoH client {} stopped", client_id);
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
    #[allow(clippy::too_many_arguments)]
    async fn handle_command(
        command: ClientCommand,
        client_id: ClientId,
        app_state: &Arc<AppState>,
        llm_client: &OllamaClient,
        status_tx: &mpsc::UnboundedSender<String>,
        protocol: &Arc<DohClientProtocol>,
        server_url: &str,
    ) -> bool {
        let action = command.action.clone();
        let outcome = match protocol.as_ref().execute_action(action.clone()) {
            Err(e) => Ok(ClientSendOutcome::Rejected {
                error: e.to_string(),
            }),
            Ok(action_result) => {
                match Self::apply_action(action_result, client_id, server_url, &app_state).await {
                    // Never `Sent`: reqwest owns the socket and reports no wire byte count
                    // for the query, so a number here would be invented. `Executed`
                    // carries the answer count and DNS rcode instead.
                    Ok(Applied::Queried { detail, event_data }) => {
                        // Deliver the response event from its own registered task: a
                        // dashboard client's manual rule can park that LLM call for
                        // minutes, and the command loop must stay responsive.
                        let notify = tokio::spawn(Self::notify_response(
                            client_id,
                            event_data,
                            app_state.clone(),
                            llm_client.clone(),
                            status_tx.clone(),
                            protocol.clone(),
                            server_url.to_string(),
                        ));
                        app_state.register_client_task(client_id, notify).await;
                        Ok(ClientSendOutcome::Executed { detail })
                    }
                    Ok(Applied::Disconnect) => Ok(ClientSendOutcome::Disconnected),
                    Ok(Applied::WaitForMore) => Ok(ClientSendOutcome::Executed {
                        detail: "wait_for_more".to_string(),
                    }),
                    Ok(Applied::Ignored(detail)) => Ok(ClientSendOutcome::Executed { detail }),
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
            error!("DoH client {} injected action failed: {}", client_id, e);
            let _ = status_tx.send(format!(
                "[WARN] Client {} injected action failed: {}",
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

    /// Execute actions returned by LLM
    async fn execute_llm_actions(
        client_id: ClientId,
        llm_result: ClientLlmResult,
        app_state: Arc<AppState>,
        llm_client: OllamaClient,
        status_tx: mpsc::UnboundedSender<String>,
        protocol: Arc<DohClientProtocol>,
        server_url: String,
    ) {
        // Update memory if provided
        if let Some(memory) = llm_result.memory_updates {
            app_state.set_memory_for_client(client_id, memory).await;
        }

        for action_value in llm_result.actions {
            match protocol.as_ref().execute_action(action_value.clone()) {
                Ok(action_result) => {
                    match Self::apply_action(action_result, client_id, &server_url, &app_state)
                        .await
                    {
                        Ok(Applied::Queried { detail, event_data }) => {
                            debug!("DoH client {}: {}", client_id, detail);
                            // Inline, not spawned: this is the model's own chain and
                            // the next round of actions continues from here.
                            Self::notify_response(
                                client_id,
                                event_data,
                                app_state.clone(),
                                llm_client.clone(),
                                status_tx.clone(),
                                protocol.clone(),
                                server_url.clone(),
                            )
                            .await;
                        }
                        Ok(Applied::Disconnect) => {
                            info!("DoH client {} disconnecting", client_id);
                            app_state.remove_client_handle(client_id).await;
                            app_state
                                .update_client_status(client_id, ClientStatus::Disconnected)
                                .await;
                            let _ = status_tx
                                .send(format!("[CLIENT] DoH client {} disconnected", client_id));
                            let _ = status_tx.send("__UPDATE_UI__".to_string());
                            break;
                        }
                        Ok(Applied::WaitForMore) => {
                            debug!("DoH client {} waiting for more queries", client_id);
                            break;
                        }
                        Ok(Applied::Ignored(detail)) => {
                            error!("DoH client {} {}", client_id, detail);
                        }
                        Err(e) => {
                            // `{:#}` rather than `{}`: reqwest's real cause (connection
                            // refused, TLS rejected, bad status) lives in the source chain,
                            // and `{}` prints only our own "DoH POST request failed"
                            // context -- which names the operation and says nothing about
                            // why it failed.
                            error!("DoH client {} query failed: {:#}", client_id, e);
                            let _ = status_tx.send(format!("[CLIENT] DoH query failed: {:#}", e));
                        }
                    }
                }
                Err(e) => {
                    error!("DoH client {} action execution failed: {}", client_id, e);
                }
            }
        }
    }

    /// Turn one executed action into a DNS-over-HTTPS query (or a session end).
    ///
    /// Shared by the LLM action path and the injected-command loop so the query
    /// encoding and the DoH HTTP call exist exactly once.
    /// Build an HTTPS client honouring this client's declared trust settings.
    ///
    /// `ca_cert_pem` adds one certificate to the system roots -- the right answer for a
    /// private CA or a known self-signed server. `insecure_skip_verify` accepts any
    /// certificate at all and is off unless explicitly asked for; it is named for what it
    /// does because a DoH connection made with it is unauthenticated, which defeats most
    /// of the point of doing DNS over HTTPS.
    async fn build_http_client(
        client_id: ClientId,
        server_url: &str,
        app_state: &Arc<AppState>,
    ) -> Result<reqwest::Client> {
        let (ca_pem, insecure) = app_state
            .with_client_mut(client_id, |c| {
                (
                    c.get_protocol_field("ca_cert_pem")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                    c.get_protocol_field("insecure_skip_verify")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false),
                )
            })
            .await
            .unwrap_or((None, false));

        // rustls explicitly, not reqwest's default TLS backend. RFC 8484 DoH runs over
        // HTTP/2, and the peer is reached only if ALPN offers `h2` -- NetGet's own DoH
        // server advertises `h2` alone and answers with HTTP/2 frames regardless, so a
        // client that negotiated no protocol tries to parse them as HTTP/1.1 and fails with
        // "invalid HTTP version parsed" before a single query gets through.
        // One HTTP client per distinct trust configuration, kept for the process.
        //
        // This was rebuilt for every query. Constructing a rustls client loads the
        // platform root store -- on macOS that means reading the keychain -- so every
        // single DNS query paid for a fresh TLS stack and a fresh handshake, and none of
        // the connection pooling reqwest provides was ever used. Under load it is
        // seconds per query.
        //
        // Keyed by host as well as by trust settings, because the resolver override below
        // is per-host: a client cached under one host and reused for another would carry
        // the wrong override.
        static CLIENTS: std::sync::OnceLock<
            std::sync::Mutex<
                std::collections::HashMap<(String, Option<String>, bool), reqwest::Client>,
            >,
        > = std::sync::OnceLock::new();
        let cache = CLIENTS.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()));
        let host = crate::llm::ollama_client::host_of(server_url).to_string();
        let key = (host.clone(), ca_pem.clone(), insecure);
        if let Ok(guard) = cache.lock() {
            if let Some(client) = guard.get(&key) {
                return Ok(client.clone());
            }
        }

        if insecure {
            warn!(
                "DoH client {} is skipping certificate verification (insecure_skip_verify); \
                 this connection is not authenticated",
                client_id
            );
        }

        // Built on a blocking thread, not here.
        //
        // `Client::builder().build()` sets up the rustls stack, which loads the platform
        // root store -- on macOS that reads the keychain. That is a synchronous,
        // syscall-heavy operation, and calling it from async context parks a tokio worker
        // thread for as long as it takes. Under load it took long enough to stall this
        // client's runtime entirely: the query logged "querying example.com" and then
        // nothing, no response and no timeout, because the request future had not been
        // created yet and there was no timeout to fire.
        let pem_for_build = ca_pem.clone();
        let host_for_build = host.clone();
        let client = tokio::task::spawn_blocking(move || {
            let mut builder = reqwest::Client::builder()
                .use_rustls_tls()
                // There was no timeout at all, so a DoH server that accepted the
                // connection and then said nothing hung the query forever with nothing in
                // the log. A DNS query that takes longer than this is useless anyway.
                .timeout(std::time::Duration::from_secs(10));

            // Never resolve a literal IP through the system resolver.
            //
            // `reqwest` hands the URL host to its resolver unconditionally and
            // `hyper-util`'s `GaiResolver` does not special-case a dotted quad, so
            // `https://127.0.0.1:8443/dns-query` performs a real `getaddrinfo("127.0.0.1")`.
            // On macOS that goes through libinfo to mDNSResponder — one system-wide daemon,
            // and a serialisation point — measured at 8.25 seconds with ~100 processes
            // asking at once. That is longer than the 10s budget above leaves for the rest
            // of the query, against a server that is up and idle.
            //
            // This is the same override `crate::llm::ollama_client::client_for_endpoint`
            // applies; it cannot be reused directly because this builder needs rustls, the
            // caller's trust settings and a timeout. `host_of` does the parsing, including
            // the trap it exists for: stripping only the scheme leaves `127.0.0.1:8443`,
            // which does not parse as an `IpAddr`, so the bypass silently would not engage.
            // A hostname is left alone — resolving it is the resolver's job.
            if let Ok(ip) = host_for_build.parse::<std::net::IpAddr>() {
                builder = builder.resolve(&host_for_build, std::net::SocketAddr::new(ip, 0));
            }

            if let Some(pem) = pem_for_build {
                let cert = reqwest::Certificate::from_pem(pem.as_bytes())
                    .context("ca_cert_pem is not a valid PEM certificate")?;
                builder = builder.add_root_certificate(cert);
            }
            if insecure {
                builder = builder
                    .danger_accept_invalid_certs(true)
                    // Do not load the platform root store when no certificate is going to
                    // be checked against it. On macOS that load reads the system keychain
                    // through Security.framework, which serialises across processes: with
                    // a hundred netget processes starting at once it dominates the time to
                    // build the client, and it buys exactly nothing here.
                    .tls_built_in_root_certs(false);
            }
            builder.build().context("Failed to build DoH HTTP client")
        })
        .await
        .context("DoH HTTP client build task panicked")??;
        if let Ok(mut guard) = cache.lock() {
            guard.insert(key, client.clone());
        }
        Ok(client)
    }

    async fn apply_action(
        action_result: ClientActionResult,
        client_id: ClientId,
        server_url: &str,
        app_state: &Arc<AppState>,
    ) -> Result<Applied> {
        match action_result {
            ClientActionResult::Custom { name, data } if name == "dns_query" => {
                let domain = data["domain"].as_str().unwrap_or("example.com").to_string();
                let record_type = data["record_type"].as_str().unwrap_or("A").to_string();
                let use_get = data["use_get"].as_bool().unwrap_or(false);

                info!(
                    "DoH client {} querying {} (type: {})",
                    client_id, domain, record_type
                );

                let event_data = Self::perform_query(
                    server_url,
                    &domain,
                    &record_type,
                    use_get,
                    client_id,
                    app_state,
                )
                .await?;

                let answer_count = event_data
                    .get("answers")
                    .and_then(|a| a.as_array())
                    .map(|a| a.len())
                    .unwrap_or(0);
                let status = event_data
                    .get("status")
                    .and_then(|s| s.as_str())
                    .unwrap_or("?");

                Ok(Applied::Queried {
                    detail: format!(
                        "query_dns {} {} -> {} answers ({})",
                        domain, record_type, answer_count, status
                    ),
                    event_data,
                })
            }
            ClientActionResult::Disconnect => Ok(Applied::Disconnect),
            ClientActionResult::WaitForMore => Ok(Applied::WaitForMore),
            ClientActionResult::NoAction => Ok(Applied::Ignored("no_action".to_string())),
            // Not swallowed: an action this client cannot carry out says so, rather
            // than looking identical to success.
            ClientActionResult::Custom { name, .. } => Ok(Applied::Ignored(format!(
                "custom result '{name}' is not handled by the DoH client"
            ))),
            ClientActionResult::SendData(_) => Ok(Applied::Ignored(
                "send_data has no meaning for a DoH client".to_string(),
            )),
            ClientActionResult::Multiple(_) => Ok(Applied::Ignored(
                "multiple results are not produced by the DoH client".to_string(),
            )),
        }
    }

    /// Run one DNS query over HTTPS and return the `doh_response_received` payload.
    ///
    /// No LLM involvement, so a caller can await this and know exactly what the
    /// resolver answered.
    pub async fn perform_query(
        server_url: &str,
        domain: &str,
        record_type: &str,
        use_get: bool,
        client_id: ClientId,
        app_state: &Arc<AppState>,
    ) -> Result<serde_json::Value> {
        // Parse domain name
        let name =
            Name::from_str(domain).with_context(|| format!("Invalid domain name: {}", domain))?;

        // Parse record type. An unknown type falls back to A rather than failing the
        // whole query, which is what the LLM path has always done.
        let rtype = match RecordType::from_str(record_type) {
            Ok(rt) => rt,
            Err(_) => {
                warn!(
                    "DoH: invalid record type {}, falling back to A",
                    record_type
                );
                RecordType::A
            }
        };

        // Build DNS query message
        let mut query_msg = Message::new();
        query_msg.set_id(rand::random());
        query_msg.set_recursion_desired(true);
        query_msg.add_query(Query::query(name, rtype));

        // Encode query to DNS wire format
        let query_bytes = query_msg.to_vec().context("Failed to encode DNS query")?;

        // Make HTTPS request to DoH server.
        //
        // Built per query from the client's stored trust settings rather than with
        // `Client::new()`. With the default system roots a DoH client cannot reach a
        // server presenting a private-CA or self-signed certificate -- including NetGet's
        // own DoH server, which is TLS-only and serves a self-signed cert, so the two
        // halves of this codebase could not talk to each other at all.
        let http_client = Self::build_http_client(client_id, server_url, app_state).await?;
        let response = if use_get {
            // GET method with base64url-encoded query
            use base64::Engine as _;
            let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&query_bytes);
            http_client
                .get(format!("{}?dns={}", server_url, encoded))
                .header("Accept", "application/dns-message")
                .send()
                .await
                .context("DoH GET request failed")?
        } else {
            // POST method with DNS query in body
            http_client
                .post(server_url)
                .header("Content-Type", "application/dns-message")
                .header("Accept", "application/dns-message")
                .body(query_bytes)
                .send()
                .await
                .context("DoH POST request failed")?
        };

        if !response.status().is_success() {
            return Err(anyhow::anyhow!(
                "DoH server answered with HTTP {}",
                response.status()
            ));
        }

        let response_bytes = response
            .bytes()
            .await
            .context("Failed to read DoH response body")?;

        let response_msg =
            Message::from_vec(&response_bytes).context("Failed to parse DNS response")?;
        trace!("DoH response: {:?}", response_msg);

        let answers: Vec<serde_json::Value> = response_msg
            .answers()
            .iter()
            .map(|record| {
                serde_json::json!({
                    "name": record.name().to_string(),
                    "type": record.record_type().to_string(),
                    "ttl": record.ttl(),
                    "data": record
                        .data()
                        .and_then(crate::utils::display::try_display)
                        .unwrap_or_default(),
                })
            })
            .collect();

        let status = format!("{:?}", response_msg.response_code());

        Ok(serde_json::json!({
            "query_id": response_msg.id(),
            "domain": domain,
            "query_type": record_type,
            "answers": answers,
            "status": status,
        }))
    }

    /// Hand a completed query to the LLM as a `doh_response_received` event, then run
    /// whatever it asks for next.
    async fn notify_response(
        client_id: ClientId,
        event_data: serde_json::Value,
        app_state: Arc<AppState>,
        llm_client: OllamaClient,
        status_tx: mpsc::UnboundedSender<String>,
        protocol: Arc<DohClientProtocol>,
        server_url: String,
    ) {
        let response_event = Event::new(&DOH_CLIENT_RESPONSE_RECEIVED_EVENT, event_data);

        let instruction = app_state
            .get_instruction_for_client(client_id)
            .await
            .unwrap_or_default();
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
            Some(&response_event),
            protocol.as_ref(),
            &status_tx,
        )
        .await
        {
            Ok(next_llm_result) => {
                // Boxed: execute_llm_actions calls back into this function, so the
                // two futures are mutually recursive and need an indirection.
                Box::pin(Self::execute_llm_actions(
                    client_id,
                    next_llm_result,
                    app_state.clone(),
                    llm_client.clone(),
                    status_tx.clone(),
                    protocol.clone(),
                    server_url,
                ))
                .await;
            }
            Err(e) => {
                error!(
                    "DoH client {} LLM call after response failed: {}",
                    client_id, e
                );
            }
        }
    }
}
