//! Syslog server implementation using syslog_loose library
pub mod actions;

use crate::server::connection::ConnectionId;
use anyhow::Result;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{debug, error};

use crate::llm::action_helper::call_llm;
use crate::llm::ollama_client::OllamaClient;
use crate::logging::emit::Log;
use crate::protocol::Event;
use crate::server::SyslogProtocol;
use crate::state::app_state::AppState;
use crate::{console_debug, console_error, console_info, console_trace};
use actions::SYSLOG_MESSAGE_EVENT;

/// Syslog server that forwards messages to LLM
pub struct SyslogServer;

impl SyslogServer {
    /// Spawn Syslog server with integrated LLM actions
    pub async fn spawn_with_llm_actions(
        listen_addr: SocketAddr,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        server_id: crate::state::ServerId,
    ) -> Result<SocketAddr> {
        let socket = Arc::new(UdpSocket::bind(listen_addr).await?);
        let local_addr = socket.local_addr()?;
        console_info!(status_tx, "Syslog server listening on {}", local_addr);

        let protocol = Arc::new(SyslogProtocol::new());

        let task_registrar = app_state.clone();
        let accept_handle = tokio::spawn(async move {
            let mut buffer = vec![0u8; 65535]; // Max UDP packet size

            loop {
                match socket.recv_from(&mut buffer).await {
                    Ok((n, peer_addr)) => {
                        let data = buffer[..n].to_vec();
                        let connection_id =
                            ConnectionId::new(app_state.get_next_unified_id().await);

                        // Add connection to ServerInstance (Syslog "connection" = recent peer)
                        use crate::state::server::{
                            ConnectionState as ServerConnectionState, ConnectionStatus,
                            ProtocolConnectionInfo,
                        };
                        let now = crate::utils::clock::Instant::now();
                        let conn_state = ServerConnectionState {
                            id: connection_id,
                            remote_addr: peer_addr,
                            local_addr,
                            bytes_sent: 0,
                            bytes_received: n as u64,
                            packets_sent: 0,
                            packets_received: 1,
                            last_activity: now,
                            status: ConnectionStatus::Active,
                            status_changed_at: now,
                            protocol_info: ProtocolConnectionInfo::empty(),
                        };
                        app_state
                            .add_connection_to_server(server_id, conn_state)
                            .await;
                        let _ = status_tx.send("__UPDATE_UI__".to_string());

                        // DEBUG: Log summary
                        console_debug!(status_tx, "Syslog received {} bytes from {}", n, peer_addr);

                        // TRACE: Log full payload
                        let message_str = String::from_utf8_lossy(&data);
                        console_trace!(status_tx, "Syslog message: {}", message_str);

                        // Parse the syslog message. syslog_loose is lenient: an unparseable
                        // datagram still yields a message with default facility/severity, so
                        // this does not drop traffic.
                        let parsed = Self::parse_syslog_message(&data);

                        let llm_clone = llm_client.clone();
                        let state_clone = app_state.clone();
                        let status_clone = status_tx.clone();
                        let protocol_clone = protocol.clone();

                        // Spawn task to handle message with LLM
                        // Tracked, not detached: stop_server must abort this task too.
                        let task_owner = app_state.clone();
                        task_owner.spawn_server_task(server_id, async move {
                            // Create syslog_message event
                            let event = Event::new(
                                &SYSLOG_MESSAGE_EVENT,
                                serde_json::json!({
                                    "facility": parsed.facility,
                                    "facility_code": parsed.facility_code,
                                    "severity": parsed.severity,
                                    "severity_code": parsed.severity_code,
                                    "priority": parsed.priority,
                                    "timestamp": parsed.timestamp,
                                    "hostname": parsed.hostname,
                                    "appname": parsed.appname,
                                    "procid": parsed.procid,
                                    "message": parsed.message,
                                    "source_ip": peer_addr.ip().to_string(),
                                    "raw_message": parsed.raw
                                }),
                            );

                            Log::to(&status_clone).debug(format!(
                                "Syslog calling LLM for message from {}", peer_addr
                            ));

                            // Call LLM
                            match call_llm(
                                &llm_clone,
                                &state_clone,
                                server_id,
                                None,
                                &event,
                                protocol_clone.as_ref(),
                            )
                            .await
                            {
                                Ok(execution_result) => {
                                    // Display messages from LLM
                                    for message in &execution_result.messages {
                                        Log::to(&status_clone).info(message);
                                    }

                                    // Syslog is one-way: nothing is ever written back to the
                                    // sender (RFC 5426 has no acknowledgement), so the only
                                    // record of what happened is the log. Keep the three
                                    // outcomes greppable and distinct: the model explicitly
                                    // dropped the message, the model answered nothing at all,
                                    // or it asked for real work.
                                    let decision = Self::decision_tag(&execution_result);
                                    debug!(
                                        "Syslog message from {} decision={} ({} protocol results, {} failed actions)",
                                        peer_addr,
                                        decision,
                                        execution_result.protocol_results.len(),
                                        execution_result.failures.len()
                                    );
                                    let _ = status_clone.send(format!(
                                        "[DEBUG] Syslog message from {} decision={} ({} protocol results)",
                                        peer_addr,
                                        decision,
                                        execution_result.protocol_results.len()
                                    ));
                                }
                                Err(e) => {
                                    // The peer is not told: syslog has no reply message, and
                                    // inventing one would be a protocol violation. The error
                                    // therefore goes to the log and the operator status stream
                                    // only — never to the wire — with the same category split
                                    // (`WireFailure`) the answering protocols put on the wire,
                                    // so an overload is distinguishable from a hard failure.
                                    let category = crate::utils::WireFailure::classify(&e);
                                    let category = if category.is_overloaded() {
                                        "overloaded"
                                    } else {
                                        "unavailable"
                                    };
                                    error!(
                                        "Syslog message from {} decision=fail_closed_llm_error category={} (dropped, no reply is possible on syslog): {}",
                                        peer_addr, category, e
                                    );
                                    let _ = status_clone.send(format!(
                                        "✗ Syslog message from {} decision=fail_closed_llm_error category={} (dropped): {}",
                                        peer_addr, category, e
                                    ));
                                }
                            }
                        }).await;
                    }
                    Err(e) => {
                        console_error!(status_tx, "Syslog receive error: {}", e);
                        break;
                    }
                }
            }
        });

        task_registrar
            .register_server_task(server_id, accept_handle)
            .await;

        Ok(local_addr)
    }

    /// Classify what the model actually decided about one datagram, for the log.
    ///
    /// Syslog cannot answer its sender, so "the model said drop it", "the model said
    /// nothing" and "the LLM call failed" are indistinguishable on the wire — all three
    /// are silence. They must not be indistinguishable in the log as well: the first is a
    /// decision, the other two are netget failing to make one. The error case is tagged at
    /// the call site (`decision=fail_closed_llm_error category=…`); this covers the
    /// successful-call cases.
    ///
    /// The tokens are stable so an operator can grep `decision=no_answer` /
    /// `decision=fail_closed_` for every message netget did not really handle.
    fn decision_tag(result: &crate::llm::ExecutionResult) -> &'static str {
        if result.raw_actions.is_empty() {
            // No actions at all: the model produced nothing usable. Dropping is what
            // syslog does anyway, but it was not a decision.
            return "no_answer";
        }
        let all_ignored = result.raw_actions.iter().all(|action| {
            action.get("type").and_then(|v| v.as_str()) == Some("ignore_syslog_message")
        });
        if all_ignored {
            "model_drop"
        } else {
            "model_handled"
        }
    }

    /// Parse a syslog datagram into the fields exposed to the LLM.
    ///
    /// `syslog_loose` is deliberately lenient and never fails: a datagram that matches
    /// neither RFC 3164 nor RFC 5424 comes back as a message with no priority, in which
    /// case we fall back to the RFC 5424 default priority 13 (user.notice).
    ///
    /// The facility/severity strings are the library's canonical short names
    /// (`kern`, `user`, … / `emerg`, `alert`, `crit`, `err`, `warning`, `notice`,
    /// `info`, `debug`), *not* the `{:?}` form (`LOG_KERN`, `SEV_ERR`), so that an
    /// event handler can compare them against the names used in the event docs.
    pub fn parse_syslog_message(data: &[u8]) -> ParsedSyslogInfo {
        use syslog_loose::{parse_message, ProcId, SyslogFacility, SyslogSeverity, Variant};

        // Convert bytes to string
        let message_str = String::from_utf8_lossy(data);

        // Parse using syslog_loose (handles both RFC 3164 and RFC 5424)
        let parsed = parse_message(&message_str, Variant::Either);

        // Facility/severity, with the RFC 5424 default (user.notice) when the datagram
        // carried no `<pri>` header.
        let facility = parsed.facility.unwrap_or(SyslogFacility::LOG_USER);
        let severity = parsed.severity.unwrap_or(SyslogSeverity::SEV_NOTICE);
        let facility_code = facility as u8;
        let severity_code = severity as u8;

        // Format timestamp
        let timestamp = match &parsed.timestamp {
            Some(ts) => ts.to_rfc3339(),
            None => "unknown".to_string(),
        };

        // Extract hostname
        let hostname = parsed
            .hostname
            .map(|s| s.to_string())
            .unwrap_or_else(|| "unknown".to_string());

        // Extract app name (tag for RFC 3164, APP-NAME for RFC 5424)
        let appname = match &parsed.appname {
            Some(name) => name.to_string(),
            None => "unknown".to_string(),
        };

        // Extract process ID if available
        let procid = match &parsed.procid {
            Some(ProcId::PID(pid)) => Some(format!("{}", pid)),
            Some(ProcId::Name(name)) => Some(name.to_string()),
            None => None,
        };

        ParsedSyslogInfo {
            facility: facility.as_str().to_string(),
            facility_code,
            severity: severity.as_str().to_string(),
            severity_code,
            priority: (facility_code as u16) * 8 + severity_code as u16,
            timestamp,
            hostname,
            appname,
            procid,
            message: parsed.msg.to_string(),
            raw: message_str.to_string(),
        }
    }
}

/// Parsed syslog message information
#[derive(Debug)]
pub struct ParsedSyslogInfo {
    /// Canonical facility name (`kern`, `user`, `auth`, `local0`, …)
    pub facility: String,
    /// Numeric facility, 0-23
    pub facility_code: u8,
    /// Canonical severity name (`emerg`, `alert`, `crit`, `err`, `warning`, `notice`, `info`, `debug`)
    pub severity: String,
    /// Numeric severity, 0 (most severe) - 7 (least severe)
    pub severity_code: u8,
    /// PRI value as it appears on the wire: facility * 8 + severity
    pub priority: u16,
    pub hostname: String,
    pub appname: String,
    pub procid: Option<String>,
    pub timestamp: String,
    /// Message text with the syslog header stripped
    pub message: String,
    /// The complete datagram as received, header included
    pub raw: String,
}
