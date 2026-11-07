//! Syslog client implementation
pub mod actions;

pub use actions::SyslogClientProtocol;

use crate::logging::emit::Log;
use crate::protocol::StartupParams;
use anyhow::{anyhow, Context, Result};
use chrono::Utc;
use serde_json::Value;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{mpsc, Mutex};
use tracing::{error, info, trace};

use crate::client::llm_budget::call_llm_for_client;
use crate::llm::actions::client_trait::{Client, ClientActionResult};
use crate::llm::ollama_client::OllamaClient;
use crate::llm::ClientLlmResult;
use crate::protocol::Event;
use crate::state::app_state::AppState;
use crate::state::client_handles::{ClientCommand, ClientSendOutcome};
use crate::state::{AccessLogOwner, ClientId, ClientStatus};

use crate::client::syslog::actions::SYSLOG_CLIENT_CONNECTED_EVENT;

/// Syslog facilities (RFC 5424)
fn facility_to_number(facility: &str) -> Result<u8> {
    match facility.to_lowercase().as_str() {
        "kern" | "kernel" => Ok(0),
        "user" => Ok(1),
        "mail" => Ok(2),
        "daemon" => Ok(3),
        "auth" => Ok(4),
        "syslog" => Ok(5),
        "lpr" => Ok(6),
        "news" => Ok(7),
        "uucp" => Ok(8),
        "cron" => Ok(9),
        "authpriv" => Ok(10),
        "ftp" => Ok(11),
        "ntp" => Ok(12),
        "security" => Ok(13),
        "console" => Ok(14),
        "solaris-cron" => Ok(15),
        "local0" => Ok(16),
        "local1" => Ok(17),
        "local2" => Ok(18),
        "local3" => Ok(19),
        "local4" => Ok(20),
        "local5" => Ok(21),
        "local6" => Ok(22),
        "local7" => Ok(23),
        _ => Err(anyhow!("Unknown syslog facility: {}", facility)),
    }
}

/// Syslog severities (RFC 5424)
fn severity_to_number(severity: &str) -> Result<u8> {
    match severity.to_lowercase().as_str() {
        "emerg" | "emergency" | "panic" => Ok(0),
        "alert" => Ok(1),
        "crit" | "critical" => Ok(2),
        "err" | "error" => Ok(3),
        "warn" | "warning" => Ok(4),
        "notice" => Ok(5),
        "info" | "informational" => Ok(6),
        "debug" => Ok(7),
        _ => Err(anyhow!("Unknown syslog severity: {}", severity)),
    }
}

/// Format a syslog message according to RFC 5424
fn format_syslog_message(
    facility: &str,
    severity: &str,
    message: &str,
    hostname: &str,
    app_name: &str,
    proc_id: &str,
    msg_id: &str,
) -> Result<String> {
    let facility_num = facility_to_number(facility)?;
    let severity_num = severity_to_number(severity)?;
    let priority = (facility_num * 8) + severity_num;

    // RFC 5424 format:
    // <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
    let timestamp = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let structured_data = "-"; // No structured data for now

    let formatted = format!(
        "<{}>1 {} {} {} {} {} {} {}",
        priority, timestamp, hostname, app_name, proc_id, msg_id, structured_data, message
    );

    Ok(formatted)
}

/// Transport protocol for syslog
enum SyslogTransport {
    Tcp(Arc<Mutex<TcpStream>>),
    Udp(Arc<UdpSocket>, SocketAddr),
}

/// What applying one executed action did. Shared by the LLM path and the command
/// channel so an injected action reports the same truth the LLM path puts on the
/// wire.
enum Applied {
    /// Bytes really written (and flushed, on TCP) to the transport.
    Sent(usize),
    /// The action ran but wrote nothing.
    Executed(String),
    /// The session should end.
    Disconnect,
}

/// Syslog client that connects to a remote syslog server
pub struct SyslogClient;

impl SyslogClient {
    /// Resolve the collector's `host:port` for the UDP transport.
    ///
    /// A literal `IP:port` is used as given, with no name lookup. A hostname is resolved and
    /// its first IPv4 address is taken when it has one, otherwise its first address. UDP has
    /// no handshake that would reveal an unreachable address and move on to the next, and
    /// `localhost` commonly resolves to `::1` ahead of `127.0.0.1`, where a collector
    /// listening on IPv4 alone never receives the message. (The TCP transport resolves
    /// through `TcpStream::connect`, which tries each address in turn.)
    async fn resolve_udp_target(remote_addr: &str) -> Result<SocketAddr> {
        if let Ok(addr) = remote_addr.parse::<SocketAddr>() {
            return Ok(addr);
        }
        let candidates: Vec<SocketAddr> = tokio::net::lookup_host(remote_addr)
            .await
            .with_context(|| {
                format!(
                    "Could not resolve syslog address {remote_addr:?} (expected host:port, \
                     e.g. 127.0.0.1:514 or localhost:514)"
                )
            })?
            .collect();
        candidates
            .iter()
            .find(|addr| addr.is_ipv4())
            .or_else(|| candidates.first())
            .copied()
            .with_context(|| format!("Syslog address {remote_addr:?} resolved to no address"))
    }

    /// Connect to a syslog server with integrated LLM actions
    pub async fn connect_with_llm_actions(
        remote_addr: String,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        client_id: ClientId,
        startup_params: Option<StartupParams>,
    ) -> Result<SocketAddr> {
        // Parse protocol from startup params (default to UDP)
        let protocol = startup_params
            .as_ref()
            .map(|params| params.get_optional_string("protocol"))
            .transpose()?
            .flatten()
            .unwrap_or_else(|| "udp".to_string())
            .to_lowercase();

        let transport = match protocol.as_str() {
            "tcp" => {
                info!(
                    "Syslog client {} connecting via TCP to {}",
                    client_id, remote_addr
                );
                let stream = TcpStream::connect(&remote_addr).await.context(format!(
                    "Failed to connect to syslog server at {}",
                    remote_addr
                ))?;

                let local_addr = stream.local_addr()?;
                let remote_sock_addr = stream.peer_addr()?;

                info!(
                    "Syslog client {} connected via TCP to {} (local: {})",
                    client_id, remote_sock_addr, local_addr
                );

                SyslogTransport::Tcp(Arc::new(Mutex::new(stream)))
            }
            "udp" => {
                info!("Syslog client {} using UDP to {}", client_id, remote_addr);

                let remote_sock_addr = Self::resolve_udp_target(&remote_addr).await?;

                // Bind to local port (ephemeral)
                let local_bind = if remote_sock_addr.is_ipv6() {
                    "[::]:0"
                } else {
                    "0.0.0.0:0"
                };

                let socket = UdpSocket::bind(local_bind)
                    .await
                    .context("Failed to bind UDP socket")?;

                let local_addr = socket.local_addr()?;

                info!(
                    "Syslog client {} bound to UDP {} for remote {}",
                    client_id, local_addr, remote_sock_addr
                );

                SyslogTransport::Udp(Arc::new(socket), remote_sock_addr)
            }
            _ => {
                return Err(anyhow!(
                    "Invalid protocol: {}. Must be 'tcp' or 'udp'",
                    protocol
                ));
            }
        };

        let transport = Arc::new(transport);

        let local_addr = match transport.as_ref() {
            SyslogTransport::Tcp(stream) => stream.lock().await.local_addr()?,
            SyslogTransport::Udp(socket, _) => socket.local_addr()?,
        };

        // Update client state
        app_state
            .update_client_status(client_id, ClientStatus::Connected)
            .await;
        let _ = status_tx.send(format!(
            "[CLIENT] Syslog client {} connected via {}",
            client_id,
            protocol.to_uppercase()
        ));
        let _ = status_tx.send("__UPDATE_UI__".to_string());

        // Command channel: lets the dashboard (and any programmatic caller) inject
        // actions into this client via AppState::send_to_client. For syslog this is the
        // whole point of the client - "emit this line now" is a human action, and until
        // now nothing but the LLM could ask for it.
        //
        // Registered BEFORE the connected event is handled: a `manual` routing rule can
        // park that event at the dashboard for minutes, and until registration the UI
        // reports "no command channel" - reading as a protocol limitation when it is
        // only a queue.
        let command_rx =
            crate::client::command_support::register_command_channel(&app_state, client_id).await;

        // Syslog has no read loop at all (it is fire-and-forget in both transports), so
        // the commands are drained by a task of their own rather than a select! arm.
        let cmd_transport = transport.clone();
        let cmd_state = app_state.clone();
        let cmd_status = status_tx.clone();
        let cmd_task = tokio::spawn(async move {
            Self::command_loop(command_rx, cmd_transport, client_id, cmd_state, cmd_status).await;
        });
        app_state.register_client_task(client_id, cmd_task).await;

        // Call LLM with connected event
        if let Some(instruction) = app_state.get_instruction_for_client(client_id).await {
            let protocol_impl = Arc::new(SyslogClientProtocol::new());
            let event = Event::new(
                &SYSLOG_CLIENT_CONNECTED_EVENT,
                serde_json::json!({
                    "remote_addr": remote_addr,
                    "protocol": protocol,
                }),
            );

            match call_llm_for_client(
                &llm_client,
                &app_state,
                client_id.to_string(),
                &instruction,
                "",
                Some(&event),
                protocol_impl.as_ref(),
                &status_tx,
            )
            .await
            {
                Ok(ClientLlmResult {
                    actions,
                    memory_updates: _,
                }) => {
                    // Execute actions
                    for action in actions {
                        if let Err(e) = Self::execute_syslog_action(
                            action,
                            transport.as_ref(),
                            client_id,
                            &status_tx,
                            protocol_impl.as_ref(),
                        )
                        .await
                        {
                            error!("Error executing syslog action: {}", e);
                        }
                    }
                }
                Err(e) => {
                    error!("LLM error for syslog client {}: {}", client_id, e);
                }
            }
        }

        // Store transport for async actions
        // Note: In a full implementation, we'd store this in app_state for async action execution
        // For now, the client is fire-and-forget for UDP, or connection-based for TCP

        Ok(local_addr)
    }

    /// Execute a syslog action (LLM path: rejection and wire failure are both just
    /// logged by the caller).
    async fn execute_syslog_action(
        action: Value,
        transport: &SyslogTransport,
        client_id: ClientId,
        status_tx: &mpsc::UnboundedSender<String>,
        protocol: &dyn Client,
    ) -> Result<Applied> {
        let result = protocol.execute_action(action)?;
        Self::apply_action_result(result, transport, client_id, status_tx).await
    }

    /// Put one executed action on the wire. Shared by the connected-event path and
    /// injected commands, so the RFC 5424 framing exists exactly once and an injected
    /// message is byte-identical to an LLM-produced one.
    async fn apply_action_result(
        result: ClientActionResult,
        transport: &SyslogTransport,
        client_id: ClientId,
        status_tx: &mpsc::UnboundedSender<String>,
    ) -> Result<Applied> {
        match result {
            ClientActionResult::Custom { name, data } if name == "send_syslog_message" => {
                let facility = data["facility"].as_str().context("Missing facility")?;
                let severity = data["severity"].as_str().context("Missing severity")?;
                let message = data["message"].as_str().context("Missing message")?;
                let hostname = data["hostname"].as_str().unwrap_or("netget");
                let app_name = data["app_name"].as_str().unwrap_or("netget");
                let proc_id = data["proc_id"].as_str().unwrap_or("-");
                let msg_id = data["msg_id"].as_str().unwrap_or("-");

                let formatted_message = format_syslog_message(
                    facility, severity, message, hostname, app_name, proc_id, msg_id,
                )?;

                trace!("Syslog client {} sending: {}", client_id, formatted_message);

                // The byte count reported to an injected caller counts what actually
                // reached the transport, including the TCP framing newline.
                let bytes_sent = match transport {
                    SyslogTransport::Tcp(stream) => {
                        // TCP: message terminated with newline
                        let mut stream = stream.lock().await;
                        stream.write_all(formatted_message.as_bytes()).await?;
                        stream.write_all(b"\n").await?;
                        stream.flush().await?;
                        formatted_message.len() + 1
                    }
                    SyslogTransport::Udp(socket, remote_addr) => {
                        // UDP: send as datagram
                        socket
                            .send_to(formatted_message.as_bytes(), remote_addr)
                            .await?
                    }
                };

                info!(
                    "Syslog client {} sent message: facility={}, severity={}, msg={}",
                    client_id, facility, severity, message
                );
                let _ = status_tx.send(format!(
                    "[CLIENT] Syslog {} sent: [{}:{}] {}",
                    client_id, facility, severity, message
                ));

                Ok(Applied::Sent(bytes_sent))
            }
            ClientActionResult::Custom { name, .. } => Ok(Applied::Executed(format!(
                "custom result '{name}' is not a syslog wire verb"
            ))),
            ClientActionResult::Disconnect => {
                info!("Syslog client {} disconnecting", client_id);
                Ok(Applied::Disconnect)
            }
            ClientActionResult::WaitForMore => Ok(Applied::Executed("wait_for_more".to_string())),
            ClientActionResult::NoAction => Ok(Applied::Executed("no_action".to_string())),
            other => Ok(Applied::Executed(format!("no wire effect: {other:?}"))),
        }
    }

    /// Drain injected commands until the channel closes (the client was removed) or an
    /// injected `disconnect` ends the session.
    ///
    /// Bespoke rather than `command_support::handle_stream_client_command` because
    /// `send_syslog_message` yields `ClientActionResult::Custom` and the transport is
    /// either a datagram socket or a stream - there is no single write half. The
    /// logging and reply are byte-for-byte what the generic helper does.
    async fn command_loop(
        mut command_rx: mpsc::Receiver<ClientCommand>,
        transport: Arc<SyslogTransport>,
        client_id: ClientId,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
    ) {
        use crate::llm::actions::protocol_trait::Protocol;

        let protocol = SyslogClientProtocol::new();

        while let Some(command) = command_rx.recv().await {
            let action = command.action.clone();
            let outcome = match protocol.execute_action(action.clone()) {
                Err(e) => Ok(ClientSendOutcome::Rejected {
                    error: e.to_string(),
                }),
                Ok(result) => {
                    Self::apply_action_result(result, transport.as_ref(), client_id, &status_tx)
                        .await
                        .map(|applied| match applied {
                            Applied::Sent(bytes_sent) => ClientSendOutcome::Sent { bytes_sent },
                            Applied::Executed(detail) => ClientSendOutcome::Executed { detail },
                            Applied::Disconnect => ClientSendOutcome::Disconnected,
                        })
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
                    "Syslog client {} injected action failed: {}",
                    client_id, e
                ));
            }
            let _ = status_tx.send("__UPDATE_UI__".to_string());
            crate::client::command_support::reply(command, outcome);

            if disconnect {
                if let SyslogTransport::Tcp(stream) = transport.as_ref() {
                    // Half-close so the collector sees EOF rather than a dangling
                    // connection.
                    let _ = stream.lock().await.shutdown().await;
                }
                app_state
                    .update_client_status(client_id, ClientStatus::Disconnected)
                    .await;
                let _ = status_tx.send(format!(
                    "[CLIENT] Syslog client {} disconnected (injected action)",
                    client_id
                ));
                let _ = status_tx.send("__UPDATE_UI__".to_string());
                break;
            }
        }

        // Every exit path lands here: drop the command handle so the dashboard stops
        // offering [ send ] on a dead client (a late send then fails fast).
        app_state.remove_client_handle(client_id).await;
        let _ = status_tx.send("__UPDATE_UI__".to_string());
    }
}
