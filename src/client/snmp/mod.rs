//! SNMP client implementation
pub mod actions;

pub use actions::SnmpClientProtocol;

use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time::timeout;
use tracing::{debug, error, info, trace};

use crate::client::llm_budget::call_llm_for_client;
use crate::client::snmp::actions::{
    SNMP_CLIENT_CONNECTED_EVENT, SNMP_CLIENT_RESPONSE_RECEIVED_EVENT,
};
use crate::llm::actions::client_trait::Client;
use crate::llm::ollama_client::OllamaClient;
use crate::llm::ClientLlmResult;
use crate::protocol::Event;
use crate::state::app_state::AppState;
use crate::state::client_handles::{ClientCommand, ClientSendOutcome};
use crate::state::{AccessLogOwner, ClientId, ClientStatus};

// SNMP protocol support
use rasn::ber;
use rasn::types::{Integer, ObjectIdentifier};
use rasn_smi::v1::{ObjectSyntax as V1ObjectSyntax, SimpleSyntax as V1SimpleSyntax};
use rasn_smi::v2::{ObjectSyntax as V2ObjectSyntax, SimpleSyntax as V2SimpleSyntax};
use rasn_snmp::{v1, v2, v2c};
use serde_json::Value;

use crate::server::snmp::usm;

/// SNMP client configuration
#[derive(Clone)]
struct SnmpConfig {
    community: String,
    version: SnmpVersion,
    timeout_ms: u64,
    retries: u32,
    /// SNMPv3: the user and the engine it has discovered.
    usm: Option<Arc<usm::Manager>>,
    context_name: String,
}

impl std::fmt::Debug for SnmpConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SnmpConfig")
            .field("version", &self.version)
            .field("timeout_ms", &self.timeout_ms)
            .field("retries", &self.retries)
            .field("v3_user", &self.usm.as_ref().map(|m| m.user.name.clone()))
            .finish_non_exhaustive()
    }
}

impl Default for SnmpConfig {
    fn default() -> Self {
        Self {
            community: "public".to_string(),
            version: SnmpVersion::V2c,
            timeout_ms: 5000,
            retries: 3,
            usm: None,
            context_name: String::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SnmpVersion {
    V1,
    V2c,
    V3,
}

/// Parse startup parameters
fn parse_startup_params(params: Option<crate::protocol::StartupParams>) -> Result<SnmpConfig> {
    let mut config = SnmpConfig::default();

    if let Some(params) = params {
        if let Some(community) = params.get_optional_string("community")? {
            config.community = community;
        }
        if let Some(version) = params.get_optional_string("version")? {
            config.version = match version.to_lowercase().as_str() {
                "v1" | "1" => SnmpVersion::V1,
                "v2c" | "v2" | "2c" | "2" => SnmpVersion::V2c,
                "v3" | "3" => SnmpVersion::V3,
                other => anyhow::bail!("SNMP version {other:?} is not v1, v2c or v3"),
            };
        }
        if let Some(user) = params.get_optional_object("v3_user")? {
            config.usm = Some(Arc::new(usm::Manager::new(usm::User::from_json(
                &Value::Object(user.clone()),
            )?)));
        }
        if let Some(context) = params.get_optional_string("context_name")? {
            anyhow::ensure!(context.len() <= 32, "context_name is at most 32 bytes");
            config.context_name = context;
        }
        if let Some(timeout) = params.get_optional_i64("timeout_ms")? {
            config.timeout_ms =
                u64::try_from(timeout).context("SNMP timeout_ms must be nonnegative")?;
        }
        if let Some(retries) = params.get_optional_i64("retries")? {
            config.retries = u32::try_from(retries).context("SNMP retries must fit u32")?;
        }
    }

    match (config.version, config.usm.is_some()) {
        (SnmpVersion::V3, false) => anyhow::bail!("version v3 needs a v3_user"),
        (SnmpVersion::V1 | SnmpVersion::V2c, true) => {
            anyhow::bail!("v3_user is set but version is not v3")
        }
        _ => {}
    }
    Ok(config)
}

/// Helper function to parse OID string to ObjectIdentifier
fn parse_oid(oid_str: &str) -> ObjectIdentifier {
    let components: Vec<u32> = oid_str
        .split('.')
        .filter_map(|s| s.parse::<u32>().ok())
        .collect();

    if components.is_empty() {
        // Return a default OID if parsing fails
        ObjectIdentifier::new_unchecked(vec![1, 3, 6, 1, 2, 1, 1, 1, 0].into())
    } else {
        ObjectIdentifier::new_unchecked(components.into())
    }
}

/// SNMP client that connects to an SNMP agent
pub struct SnmpClient;

impl SnmpClient {
    /// Connect to an SNMP agent with integrated LLM actions
    pub async fn connect_with_llm_actions(
        remote_addr: String,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        client_id: ClientId,
        startup_params: Option<crate::protocol::StartupParams>,
    ) -> Result<SocketAddr> {
        // Parse configuration
        let config = parse_startup_params(startup_params)?;
        debug!("SNMP client config: {:?}", config);

        // Bind UDP socket to any local port
        let socket = UdpSocket::bind("0.0.0.0:0")
            .await
            .context("Failed to bind UDP socket")?;

        let local_addr = socket.local_addr()?;

        // Connect to remote agent (sets default destination for send/recv)
        socket.connect(&remote_addr).await.context(format!(
            "Failed to connect to SNMP agent at {}",
            remote_addr
        ))?;

        let remote_sock_addr: SocketAddr = remote_addr.parse().context("Invalid remote address")?;

        // SNMPv3: learn the agent's engine before anything else, so every request can be
        // authenticated against it. An agent that never answers discovery cannot be talked to.
        if let Some(manager) = &config.usm {
            Self::discover(&socket, manager, &config)
                .await
                .with_context(|| format!("SNMPv3 engine discovery with {remote_addr} failed"))?;
            info!(
                "SNMP client {} discovered engine {}",
                client_id,
                hex::encode(manager.engine_id().unwrap_or_default())
            );
        }

        info!(
            "SNMP client {} connected to {} (local: {})",
            client_id, remote_sock_addr, local_addr
        );

        // Update client state
        app_state
            .update_client_status(client_id, ClientStatus::Connected)
            .await;
        let _ = status_tx.send(format!("[CLIENT] SNMP client {} connected", client_id));
        let _ = status_tx.send("__UPDATE_UI__".to_string());

        let protocol = Arc::new(SnmpClientProtocol::new());
        let socket = Arc::new(socket);
        let config = Arc::new(config);

        // Command channel: lets the dashboard (and any programmatic caller) inject
        // actions into this client via AppState::send_to_client.
        //
        // Registered BEFORE the connected event is handled: a `manual` routing rule can
        // park that event at the dashboard for minutes, and until registration the UI
        // reports "no command channel" - reading as a protocol limitation when it is
        // only a queue.
        let command_rx =
            crate::client::command_support::register_command_channel(&app_state, client_id).await;

        // SNMP has no standing read loop - each request awaits its own reply - so the
        // commands are drained by a task of their own.
        let cmd_protocol = protocol.clone();
        let cmd_socket = socket.clone();
        let cmd_config = config.clone();
        let cmd_llm = llm_client.clone();
        let cmd_state = app_state.clone();
        let cmd_status = status_tx.clone();
        let cmd_task = tokio::spawn(async move {
            Self::command_loop(
                command_rx,
                cmd_protocol,
                cmd_socket,
                cmd_config,
                client_id,
                cmd_llm,
                cmd_state,
                cmd_status,
            )
            .await;
        });
        app_state.register_client_task(client_id, cmd_task).await;

        // Call LLM with connected event
        if let Some(instruction) = app_state.get_instruction_for_client(client_id).await {
            let event = Event::new(
                &SNMP_CLIENT_CONNECTED_EVENT,
                serde_json::json!({
                    "remote_addr": remote_sock_addr.to_string(),
                }),
            );

            let memory = app_state
                .get_memory_for_client(client_id)
                .await
                .unwrap_or_default();

            let llm_clone = llm_client.clone();
            let state_clone = app_state.clone();
            let status_clone = status_tx.clone();
            let protocol_clone = protocol.clone();
            let socket_clone = socket.clone();
            let config = config.clone();

            // Spawn initial LLM call
            // Registered with AppState so stop_client can abort this task —
            // dropping a JoinHandle only detaches it in Tokio.
            let task_registrar = app_state.clone();
            let task_handle = tokio::spawn(async move {
                match call_llm_for_client(
                    &llm_clone,
                    &state_clone,
                    client_id.to_string(),
                    &instruction,
                    &memory,
                    Some(&event),
                    protocol_clone.as_ref(),
                    &status_clone,
                )
                .await
                {
                    Ok(ClientLlmResult {
                        actions,
                        memory_updates,
                    }) => {
                        // Update memory
                        if let Some(mem) = memory_updates {
                            state_clone.set_memory_for_client(client_id, mem).await;
                        }

                        // Execute initial actions
                        Self::execute_actions(
                            actions,
                            &protocol_clone,
                            &socket_clone,
                            client_id,
                            &config,
                            &llm_clone,
                            &state_clone,
                            &status_clone,
                        )
                        .await;
                    }
                    Err(e) => {
                        error!(
                            "Initial LLM call failed for SNMP client {}: {}",
                            client_id, e
                        );
                    }
                }
            });
            task_registrar
                .register_client_task(client_id, task_handle)
                .await;
        }

        Ok(local_addr)
    }

    /// Execute SNMP actions from LLM
    async fn execute_actions(
        actions: Vec<Value>,
        protocol: &Arc<SnmpClientProtocol>,
        socket: &Arc<UdpSocket>,
        client_id: ClientId,
        config: &Arc<SnmpConfig>,
        llm_client: &OllamaClient,
        app_state: &Arc<AppState>,
        status_tx: &mpsc::UnboundedSender<String>,
    ) {
        use crate::llm::actions::client_trait::ClientActionResult;

        for action in actions {
            match protocol.execute_action(action) {
                Ok(ClientActionResult::Custom { name, data }) => {
                    match Self::build_request(&name, &data, config) {
                        Ok((request_bytes, request_type)) => {
                            if let Err(e) = Self::send_request_and_handle_response(
                                socket,
                                &request_bytes,
                                request_type,
                                config,
                                client_id,
                                llm_client,
                                app_state,
                                status_tx,
                                protocol,
                            )
                            .await
                            {
                                error!("Failed to send SNMP {}: {}", request_type, e);
                            }
                        }
                        Err(e) => {
                            debug!("SNMP client {} could not build request: {}", client_id, e);
                        }
                    }
                }
                Ok(ClientActionResult::Disconnect) => {
                    info!("SNMP client {} disconnecting", client_id);
                    app_state
                        .update_client_status(client_id, ClientStatus::Disconnected)
                        .await;
                    let _ = status_tx.send("__UPDATE_UI__".to_string());
                }
                Ok(ClientActionResult::WaitForMore) => {
                    // No action needed
                }
                Ok(_) => {}
                Err(e) => {
                    error!("Failed to execute SNMP action: {}", e);
                }
            }
        }
    }

    /// RFC 3414 §4: probe with an empty engine and learn it from the report.
    async fn discover(
        socket: &UdpSocket,
        manager: &usm::Manager,
        config: &SnmpConfig,
    ) -> Result<()> {
        let mut buffer = vec![0u8; 65535];
        for _ in 0..=config.retries {
            let (msg_id, probe) = manager.discovery()?;
            socket.send(&probe).await?;
            let deadline = tokio::time::Instant::now() + Duration::from_millis(config.timeout_ms);
            while let Ok(Ok(n)) = tokio::time::timeout_at(deadline, socket.recv(&mut buffer)).await
            {
                if crate::server::snmp::check_ber_structure(
                    &buffer[..n],
                    crate::server::snmp::MAX_BER_DEPTH,
                )
                .is_err()
                {
                    continue;
                }
                if manager.learn(&buffer[..n], msg_id).is_ok() {
                    return Ok(());
                }
            }
        }
        Err(anyhow::anyhow!(
            "no discovery report after {} tries",
            config.retries + 1
        ))
    }

    /// Wrap a v2c-encoded request's PDU in an SNMPv3 message for the configured user.
    fn to_v3(bytes: &[u8], config: &SnmpConfig) -> Result<Vec<u8>> {
        let manager = config.usm.as_ref().context("v3 without a user")?;
        let message: v2c::Message<v2::Pdus> =
            ber::decode(bytes).map_err(|e| anyhow::anyhow!("request PDU does not decode: {e}"))?;
        manager.wrap_request(message.data, config.context_name.as_bytes())
    }

    /// Encode the request datagram for one executed action.
    ///
    /// Pure - no I/O - so the LLM path and the command channel put byte-identical
    /// PDUs on the wire. Returns the bytes plus the PDU name used in the response
    /// event.
    fn build_request(
        name: &str,
        data: &Value,
        config: &SnmpConfig,
    ) -> Result<(Vec<u8>, &'static str)> {
        let (bytes, kind) = Self::build_community_request(name, data, config)?;
        if config.version == SnmpVersion::V3 {
            return Ok((Self::to_v3(&bytes, config)?, kind));
        }
        Ok((bytes, kind))
    }

    /// The v1/v2c datagram; for v3 the v2c one, whose PDU [`Self::to_v3`] re-wraps.
    fn build_community_request(
        name: &str,
        data: &Value,
        config: &SnmpConfig,
    ) -> Result<(Vec<u8>, &'static str)> {
        let oids: Vec<String> = data
            .get("oids")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        let request_id = rand::random::<i32>();

        match name {
            "snmp_get" => {
                let bytes = match config.version {
                    SnmpVersion::V1 => {
                        Self::build_v1_get_request(&oids, &config.community, request_id)?
                    }
                    SnmpVersion::V2c | SnmpVersion::V3 => {
                        Self::build_v2c_get_request(&oids, &config.community, request_id)?
                    }
                };
                Ok((bytes, "GetRequest"))
            }
            "snmp_getnext" => {
                let bytes = match config.version {
                    SnmpVersion::V1 => {
                        Self::build_v1_getnext_request(&oids, &config.community, request_id)?
                    }
                    SnmpVersion::V2c | SnmpVersion::V3 => {
                        Self::build_v2c_getnext_request(&oids, &config.community, request_id)?
                    }
                };
                Ok((bytes, "GetNextRequest"))
            }
            "snmp_getbulk" => {
                if matches!(config.version, SnmpVersion::V1) {
                    return Err(anyhow::anyhow!("GETBULK needs SNMPv2c or SNMPv3"));
                }
                let non_repeaters =
                    crate::client::wire_values::number::<u32>(&data, "non_repeaters", 0)?;
                let max_repetitions =
                    crate::client::wire_values::number::<u32>(&data, "max_repetitions", 10)?;
                let bytes = Self::build_v2c_getbulk_request(
                    &oids,
                    &config.community,
                    request_id,
                    non_repeaters,
                    max_repetitions,
                )?;
                Ok((bytes, "GetBulkRequest"))
            }
            "snmp_set" => {
                let variables = data
                    .get("variables")
                    .and_then(|v| v.as_array())
                    .context("Missing 'variables' array")?;
                let bytes = match config.version {
                    SnmpVersion::V1 => {
                        Self::build_v1_set_request(variables, &config.community, request_id)?
                    }
                    SnmpVersion::V2c | SnmpVersion::V3 => {
                        Self::build_v2c_set_request(variables, &config.community, request_id)?
                    }
                };
                Ok((bytes, "SetRequest"))
            }
            other => Err(anyhow::anyhow!(
                "custom result '{other}' is not an SNMP wire verb"
            )),
        }
    }

    /// Send request and handle response
    async fn send_request_and_handle_response(
        socket: &Arc<UdpSocket>,
        request_bytes: &[u8],
        request_type: &str,
        config: &Arc<SnmpConfig>,
        client_id: ClientId,
        llm_client: &OllamaClient,
        app_state: &Arc<AppState>,
        status_tx: &mpsc::UnboundedSender<String>,
        protocol: &Arc<SnmpClientProtocol>,
    ) -> Result<()> {
        socket.send(request_bytes).await?;
        Self::await_response(
            socket,
            request_bytes,
            request_type,
            config,
            client_id,
            llm_client,
            app_state,
            status_tx,
            protocol,
        )
        .await
    }

    /// Wait for the reply to a request already on the wire, resending it on timeout
    /// until `config.retries` is exhausted.
    ///
    /// Split out of [`Self::send_request_and_handle_response`] so the command channel
    /// can report `Sent { bytes_sent }` the moment the datagram leaves - an injected
    /// caller must not be made to wait out `timeout_ms * (retries + 1)` before it
    /// learns whether its request was sent.
    #[allow(clippy::too_many_arguments)]
    async fn await_response(
        socket: &Arc<UdpSocket>,
        request_bytes: &[u8],
        request_type: &str,
        config: &Arc<SnmpConfig>,
        client_id: ClientId,
        llm_client: &OllamaClient,
        app_state: &Arc<AppState>,
        status_tx: &mpsc::UnboundedSender<String>,
        protocol: &Arc<SnmpClientProtocol>,
    ) -> Result<()> {
        let timeout_duration = Duration::from_millis(config.timeout_ms);
        let mut retries = config.retries;

        loop {
            // Wait for response with timeout
            let mut buffer = vec![0u8; 65535];
            match timeout(timeout_duration, socket.recv(&mut buffer)).await {
                Ok(Ok(n)) => {
                    let response_data = &buffer[..n];
                    trace!("SNMP response (hex): {}", hex::encode(response_data));

                    // Parse response and call LLM
                    Self::handle_response(
                        response_data,
                        request_type,
                        client_id,
                        llm_client,
                        app_state,
                        status_tx,
                        protocol,
                        socket,
                        config,
                    )
                    .await?;

                    return Ok(());
                }
                Ok(Err(e)) => {
                    return Err(e.into());
                }
                Err(_) => {
                    // Timeout
                    if retries > 0 {
                        retries -= 1;
                        debug!(
                            "SNMP client {} request timeout, retrying ({} left)",
                            client_id, retries
                        );
                        socket.send(request_bytes).await?;
                        continue;
                    } else {
                        return Err(anyhow::anyhow!(
                            "SNMP request timeout after {} retries",
                            config.retries
                        ));
                    }
                }
            }
        }
    }

    /// Drain injected commands until the channel closes (the client was removed) or an
    /// injected `disconnect` ends the session.
    ///
    /// Bespoke rather than `command_support::handle_stream_client_command` because
    /// every SNMP verb yields `ClientActionResult::Custom` and the socket is a
    /// connected datagram socket, not a write half. The logging and reply are
    /// byte-for-byte what the generic helper does.
    ///
    /// The outcome is reported as soon as the request datagram is on the wire; the
    /// reply is then awaited in this same task, so the response event still reaches
    /// the LLM exactly as it does on the LLM path, and a second command simply queues
    /// behind the first (the channel is bounded, so a caller gets "client busy" rather
    /// than an unbounded backlog).
    #[allow(clippy::too_many_arguments)]
    async fn command_loop(
        mut command_rx: mpsc::Receiver<ClientCommand>,
        protocol: Arc<SnmpClientProtocol>,
        socket: Arc<UdpSocket>,
        config: Arc<SnmpConfig>,
        client_id: ClientId,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
    ) {
        use crate::llm::actions::client_trait::ClientActionResult;
        use crate::llm::actions::protocol_trait::Protocol;

        while let Some(command) = command_rx.recv().await {
            let action = command.action.clone();

            // Built here so the request bytes can be awaited on after the reply.
            let mut pending: Option<(Vec<u8>, &'static str)> = None;

            let outcome = match protocol.execute_action(action.clone()) {
                Err(e) => Ok(ClientSendOutcome::Rejected {
                    error: e.to_string(),
                }),
                Ok(ClientActionResult::Custom { name, data }) => {
                    match Self::build_request(&name, &data, &config) {
                        Err(e) => Ok(ClientSendOutcome::Rejected {
                            error: e.to_string(),
                        }),
                        Ok((request_bytes, request_type)) => {
                            match socket.send(&request_bytes).await {
                                Ok(bytes_sent) => {
                                    pending = Some((request_bytes, request_type));
                                    Ok(ClientSendOutcome::Sent { bytes_sent })
                                }
                                Err(e) => Err(anyhow::anyhow!("send failed: {e}")),
                            }
                        }
                    }
                }
                Ok(ClientActionResult::Disconnect) => Ok(ClientSendOutcome::Disconnected),
                Ok(ClientActionResult::WaitForMore) => Ok(ClientSendOutcome::Executed {
                    detail: "wait_for_more".to_string(),
                }),
                Ok(other) => Ok(ClientSendOutcome::Executed {
                    detail: format!("no wire effect: {other:?}"),
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
                error!("SNMP client {} injected action failed: {}", client_id, e);
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
                let _ = status_tx.send(format!(
                    "[CLIENT] SNMP client {} disconnected (injected action)",
                    client_id
                ));
                let _ = status_tx.send("__UPDATE_UI__".to_string());
                break;
            }

            if let Some((request_bytes, request_type)) = pending {
                if let Err(e) = Self::await_response(
                    &socket,
                    &request_bytes,
                    request_type,
                    &config,
                    client_id,
                    &llm_client,
                    &app_state,
                    &status_tx,
                    &protocol,
                )
                .await
                {
                    debug!(
                        "SNMP client {} got no usable reply to injected {}: {}",
                        client_id, request_type, e
                    );
                }
            }
        }

        // Every exit path lands here: drop the command handle so the dashboard stops
        // offering [ send ] on a dead client (a late send then fails fast).
        app_state.remove_client_handle(client_id).await;
        let _ = status_tx.send("__UPDATE_UI__".to_string());
    }

    /// Handle SNMP response
    async fn handle_response(
        response_data: &[u8],
        request_type: &str,
        client_id: ClientId,
        llm_client: &OllamaClient,
        app_state: &Arc<AppState>,
        status_tx: &mpsc::UnboundedSender<String>,
        protocol: &Arc<SnmpClientProtocol>,
        socket: &Arc<UdpSocket>,
        config: &Arc<SnmpConfig>,
    ) -> Result<()> {
        // The response side has the same fatal decoder as the agent side: `rasn`'s BER parser
        // recurses once per level of constructed nesting with no bound, and a stack overflow
        // is a `SIGABRT` that takes the whole NetGet process with it. A client is if anything
        // more exposed — the bytes come from whatever the operator pointed it at, and UDP means
        // an off-path attacker can beat the real agent to the reply. Screen before decoding.
        if let Err(reason) = crate::server::snmp::check_ber_structure(
            response_data,
            crate::server::snmp::MAX_BER_DEPTH,
        ) {
            return Err(anyhow::anyhow!(
                "Rejected malformed SNMP response ({} bytes): {}",
                response_data.len(),
                reason
            ));
        }

        // SNMPv3: nothing in the reply is believed until the USM has checked it.
        let mut usm_report: Option<Value> = None;
        let (variables, error_status) = if let Some(manager) = &config.usm {
            match manager.unwrap_reply(response_data)? {
                usm::Reply::Pdu(pdus) => Self::extract_v2c_response(&v2c::Message {
                    version: Integer::Primitive(1),
                    community: Vec::new().into(),
                    data: pdus,
                })?,
                usm::Reply::Report(kind, count) => {
                    usm_report = Some(serde_json::json!({"report": kind.name(), "count": count}));
                    (Vec::new(), 0)
                }
            }
        } else if let Ok(msg) = ber::decode::<v2c::Message<v2::Pdus>>(response_data) {
            Self::extract_v2c_response(&msg)?
        } else if let Ok(msg) = ber::decode::<v1::Message<v1::Pdus>>(response_data) {
            Self::extract_v1_response(&msg)?
        } else {
            return Err(anyhow::anyhow!("Failed to parse SNMP response"));
        };
        if let Some(report) = &usm_report {
            info!("SNMP client {} got a USM report: {}", client_id, report);
        }

        debug!(
            "SNMP client {} received response with {} variables, error_status={}",
            client_id,
            variables.len(),
            error_status
        );

        // Call LLM with response
        if let Some(instruction) = app_state.get_instruction_for_client(client_id).await {
            let mut data = serde_json::json!({
                "request_type": request_type,
                "variables": variables,
                "error_status": error_status,
            });
            if let Some(report) = usm_report {
                data["usm_report"] = report;
            }
            let event = Event::new(&SNMP_CLIENT_RESPONSE_RECEIVED_EVENT, data);

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

                    // Execute follow-up actions (boxed to avoid infinite recursion)
                    Box::pin(Self::execute_actions(
                        actions, protocol, socket, client_id, config, llm_client, app_state,
                        status_tx,
                    ))
                    .await;
                }
                Err(e) => {
                    error!("LLM error for SNMP client {}: {}", client_id, e);
                }
            }
        }

        Ok(())
    }

    /// Extract variables from v2c response
    fn extract_v2c_response(msg: &v2c::Message<v2::Pdus>) -> Result<(Vec<Value>, i32)> {
        let (var_binds, error_status) = match &msg.data {
            v2::Pdus::Response(resp) => (&resp.0.variable_bindings, resp.0.error_status as i32),
            _ => return Err(anyhow::anyhow!("Unexpected PDU type in response")),
        };

        let variables: Vec<Value> = var_binds
            .iter()
            .map(|vb| {
                serde_json::json!({
                    "oid": vb.name.to_string(),
                    "value": Self::format_v2_value(&vb.value),
                })
            })
            .collect();

        Ok((variables, error_status))
    }

    /// Extract variables from v1 response
    fn extract_v1_response(msg: &v1::Message<v1::Pdus>) -> Result<(Vec<Value>, i32)> {
        let (var_binds, error_status) = match &msg.data {
            v1::Pdus::GetResponse(resp) => {
                let err_status = match &resp.0.error_status {
                    Integer::Primitive(v) => *v as i32,
                    Integer::Variable(big) => big.to_string().parse().unwrap_or(0),
                };
                (&resp.0.variable_bindings, err_status)
            }
            _ => return Err(anyhow::anyhow!("Unexpected PDU type in response")),
        };

        let variables: Vec<Value> = var_binds
            .iter()
            .map(|vb| {
                serde_json::json!({
                    "oid": vb.name.to_string(),
                    "value": Self::format_v1_value(&vb.value),
                })
            })
            .collect();

        Ok((variables, error_status))
    }

    /// Format v2 value for JSON
    fn format_v2_value(value: &v2::VarBindValue) -> Value {
        use v2::VarBindValue;
        match value {
            VarBindValue::Unspecified => serde_json::json!(null),
            VarBindValue::NoSuchObject => serde_json::json!("(no such object)"),
            VarBindValue::NoSuchInstance => serde_json::json!("(no such instance)"),
            VarBindValue::EndOfMibView => serde_json::json!("(end of MIB view)"),
            VarBindValue::Value(obj_syntax) => Self::format_object_syntax_v2(obj_syntax),
        }
    }

    fn format_object_syntax_v2(syntax: &V2ObjectSyntax) -> Value {
        match syntax {
            V2ObjectSyntax::Simple(V2SimpleSyntax::Integer(n)) => match n {
                Integer::Primitive(val) => serde_json::json!(val),
                Integer::Variable(val) => serde_json::json!(val.to_string()),
            },
            V2ObjectSyntax::Simple(V2SimpleSyntax::String(s)) => {
                serde_json::json!(String::from_utf8_lossy(s))
            }
            V2ObjectSyntax::Simple(V2SimpleSyntax::ObjectId(_)) => serde_json::json!("(object-id)"),
            V2ObjectSyntax::ApplicationWide(_) => serde_json::json!("(application-wide)"),
        }
    }

    /// Format v1 value for JSON
    fn format_v1_value(value: &V1ObjectSyntax) -> Value {
        match value {
            V1ObjectSyntax::Simple(V1SimpleSyntax::Number(n)) => match n {
                Integer::Primitive(val) => serde_json::json!(val),
                Integer::Variable(val) => serde_json::json!(val.to_string()),
            },
            V1ObjectSyntax::Simple(V1SimpleSyntax::String(s)) => {
                serde_json::json!(String::from_utf8_lossy(s))
            }
            V1ObjectSyntax::Simple(V1SimpleSyntax::Object(_)) => serde_json::json!("(object-id)"),
            V1ObjectSyntax::Simple(V1SimpleSyntax::Empty) => serde_json::json!(null),
            V1ObjectSyntax::ApplicationWide(_) => serde_json::json!("(application-wide)"),
        }
    }

    // Request builders (simplified - using rasn-snmp encoding)

    fn build_v2c_get_request(oids: &[String], community: &str, request_id: i32) -> Result<Vec<u8>> {
        let var_binds: Vec<v2::VarBind> = oids
            .iter()
            .map(|oid| v2::VarBind {
                name: parse_oid(oid),
                value: v2::VarBindValue::Unspecified,
            })
            .collect();

        let pdu = v2::Pdus::GetRequest(v2::GetRequest(v2::Pdu {
            request_id,
            error_status: 0,
            error_index: 0,
            variable_bindings: var_binds,
        }));

        let message = v2c::Message {
            version: Integer::Primitive(1), // v2c uses version 1
            community: community.as_bytes().to_vec().into(),
            data: pdu,
        };

        ber::encode(&message)
            .map_err(|e| anyhow::anyhow!("Failed to encode SNMP v2c GET request: {}", e))
    }

    fn build_v2c_getnext_request(
        oids: &[String],
        community: &str,
        request_id: i32,
    ) -> Result<Vec<u8>> {
        let var_binds: Vec<v2::VarBind> = oids
            .iter()
            .map(|oid| v2::VarBind {
                name: parse_oid(oid),
                value: v2::VarBindValue::Unspecified,
            })
            .collect();

        let pdu = v2::Pdus::GetNextRequest(v2::GetNextRequest(v2::Pdu {
            request_id,
            error_status: 0,
            error_index: 0,
            variable_bindings: var_binds,
        }));

        let message = v2c::Message {
            version: Integer::Primitive(1),
            community: community.as_bytes().to_vec().into(),
            data: pdu,
        };

        ber::encode(&message)
            .map_err(|e| anyhow::anyhow!("Failed to encode SNMP v2c GETNEXT request: {}", e))
    }

    fn build_v2c_getbulk_request(
        oids: &[String],
        community: &str,
        request_id: i32,
        non_repeaters: u32,
        max_repetitions: u32,
    ) -> Result<Vec<u8>> {
        let var_binds: Vec<v2::VarBind> = oids
            .iter()
            .map(|oid| v2::VarBind {
                name: parse_oid(oid),
                value: v2::VarBindValue::Unspecified,
            })
            .collect();

        let pdu = v2::Pdus::GetBulkRequest(v2::GetBulkRequest(v2::BulkPdu {
            request_id,
            non_repeaters,
            max_repetitions,
            variable_bindings: var_binds,
        }));

        let message = v2c::Message {
            version: Integer::Primitive(1),
            community: community.as_bytes().to_vec().into(),
            data: pdu,
        };

        ber::encode(&message)
            .map_err(|e| anyhow::anyhow!("Failed to encode SNMP v2c GETBULK request: {}", e))
    }

    fn build_v2c_set_request(
        variables: &[Value],
        community: &str,
        request_id: i32,
    ) -> Result<Vec<u8>> {
        let var_binds: Vec<v2::VarBind> = variables
            .iter()
            .map(|var| {
                let oid = var
                    .get("oid")
                    .and_then(|v| v.as_str())
                    .unwrap_or("1.3.6.1.2.1.1.1.0");
                let value_type = var.get("type").and_then(|v| v.as_str()).unwrap_or("string");
                let value = var.get("value").unwrap_or(&serde_json::json!(null));

                let data = match value_type {
                    "integer" => {
                        let n = value.as_i64().unwrap_or(0);
                        v2::VarBindValue::Value(V2ObjectSyntax::Simple(V2SimpleSyntax::Integer(
                            Integer::Primitive(n as isize),
                        )))
                    }
                    "string" => {
                        let s = value.as_str().unwrap_or("");
                        v2::VarBindValue::Value(V2ObjectSyntax::Simple(V2SimpleSyntax::String(
                            s.as_bytes().to_vec().into(),
                        )))
                    }
                    _ => v2::VarBindValue::Unspecified,
                };

                v2::VarBind {
                    name: parse_oid(oid),
                    value: data,
                }
            })
            .collect();

        let pdu = v2::Pdus::SetRequest(v2::SetRequest(v2::Pdu {
            request_id,
            error_status: 0,
            error_index: 0,
            variable_bindings: var_binds,
        }));

        let message = v2c::Message {
            version: Integer::Primitive(1),
            community: community.as_bytes().to_vec().into(),
            data: pdu,
        };

        ber::encode(&message)
            .map_err(|e| anyhow::anyhow!("Failed to encode SNMP v2c SET request: {}", e))
    }

    fn build_v1_get_request(oids: &[String], community: &str, request_id: i32) -> Result<Vec<u8>> {
        let var_binds: Vec<v1::VarBind> = oids
            .iter()
            .map(|oid| v1::VarBind {
                name: parse_oid(oid),
                value: V1ObjectSyntax::Simple(V1SimpleSyntax::Empty),
            })
            .collect();

        let pdu = v1::Pdus::GetRequest(v1::GetRequest(v1::Pdu {
            request_id: Integer::Primitive(request_id as isize),
            error_status: Integer::Primitive(0),
            error_index: Integer::Primitive(0),
            variable_bindings: var_binds,
        }));

        let message = v1::Message {
            version: Integer::Primitive(0), // v1 uses version 0
            community: community.as_bytes().to_vec().into(),
            data: pdu,
        };

        ber::encode(&message)
            .map_err(|e| anyhow::anyhow!("Failed to encode SNMP v1 GET request: {}", e))
    }

    fn build_v1_getnext_request(
        oids: &[String],
        community: &str,
        request_id: i32,
    ) -> Result<Vec<u8>> {
        let var_binds: Vec<v1::VarBind> = oids
            .iter()
            .map(|oid| v1::VarBind {
                name: parse_oid(oid),
                value: V1ObjectSyntax::Simple(V1SimpleSyntax::Empty),
            })
            .collect();

        let pdu = v1::Pdus::GetNextRequest(v1::GetNextRequest(v1::Pdu {
            request_id: Integer::Primitive(request_id as isize),
            error_status: Integer::Primitive(0),
            error_index: Integer::Primitive(0),
            variable_bindings: var_binds,
        }));

        let message = v1::Message {
            version: Integer::Primitive(0),
            community: community.as_bytes().to_vec().into(),
            data: pdu,
        };

        ber::encode(&message)
            .map_err(|e| anyhow::anyhow!("Failed to encode SNMP v1 GETNEXT request: {}", e))
    }

    fn build_v1_set_request(
        variables: &[Value],
        community: &str,
        request_id: i32,
    ) -> Result<Vec<u8>> {
        let var_binds: Vec<v1::VarBind> = variables
            .iter()
            .map(|var| {
                let oid = var
                    .get("oid")
                    .and_then(|v| v.as_str())
                    .unwrap_or("1.3.6.1.2.1.1.1.0");
                let value_type = var.get("type").and_then(|v| v.as_str()).unwrap_or("string");
                let value = var.get("value").unwrap_or(&serde_json::json!(null));

                let value_obj = match value_type {
                    "integer" => {
                        let n = value.as_i64().unwrap_or(0);
                        V1ObjectSyntax::Simple(V1SimpleSyntax::Number(Integer::Primitive(
                            n as isize,
                        )))
                    }
                    "string" => {
                        let s = value.as_str().unwrap_or("");
                        V1ObjectSyntax::Simple(V1SimpleSyntax::String(s.as_bytes().to_vec().into()))
                    }
                    _ => V1ObjectSyntax::Simple(V1SimpleSyntax::Empty),
                };

                v1::VarBind {
                    name: parse_oid(oid),
                    value: value_obj,
                }
            })
            .collect();

        let pdu = v1::Pdus::SetRequest(v1::SetRequest(v1::Pdu {
            request_id: Integer::Primitive(request_id as isize),
            error_status: Integer::Primitive(0),
            error_index: Integer::Primitive(0),
            variable_bindings: var_binds,
        }));

        let message = v1::Message {
            version: Integer::Primitive(0),
            community: community.as_bytes().to_vec().into(),
            data: pdu,
        };

        ber::encode(&message)
            .map_err(|e| anyhow::anyhow!("Failed to encode SNMP v1 SET request: {}", e))
    }
}
