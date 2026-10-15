//! BOOTP server implementation
pub mod actions;

use crate::server::connection::ConnectionId;
use anyhow::Result;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{error, info};

use crate::llm::action_helper::call_llm;
use crate::llm::ollama_client::OllamaClient;
use crate::logging::emit::Log;
use crate::protocol::Event;
use crate::server::BootpProtocol;
use crate::state::app_state::AppState;
use actions::BOOTP_REQUEST_EVENT;

use crate::{console_debug, console_trace};
use actions::BootpRequestContext;
use dhcproto::{v4, Decodable, Decoder};

/// Render a hardware address the way the `bootp_request` event reports it: lower-case hex
/// with no separators, e.g. `001122334455`.
///
/// The separator-free form is what `tests/server/bootp/e2e_test.rs` matches on, so it is
/// the contract. `send_bootp_reply`'s `client_mac` parameter accepts either this or the
/// colon-separated form when a handler supplies one explicitly.
pub fn format_mac(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

/// BOOTP server that forwards requests to LLM
pub struct BootpServer;

impl BootpServer {
    /// Spawn BOOTP server with integrated LLM actions
    pub async fn spawn_with_llm_actions(
        listen_addr: SocketAddr,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        server_id: crate::state::ServerId,
    ) -> Result<SocketAddr> {
        let socket = Arc::new(UdpSocket::bind(listen_addr).await?);
        let local_addr = socket.local_addr()?;
        info!("BOOTP server (action-based) listening on {}", local_addr);
        Log::new(Some(&status_tx)).info(format!("BOOTP server listening on {}", local_addr));

        let task_registrar = app_state.clone();
        let accept_handle = tokio::spawn(async move {
            let mut buffer = vec![0u8; 1500];

            loop {
                match socket.recv_from(&mut buffer).await {
                    Ok((n, peer_addr)) => {
                        let data = buffer[..n].to_vec();
                        let connection_id =
                            ConnectionId::new(app_state.get_next_unified_id().await);

                        // DEBUG: Log summary
                        console_debug!(status_tx, "BOOTP received {} bytes from {}", n, peer_addr);

                        // TRACE: Log full payload (always hex for BOOTP)
                        let hex_str = hex::encode(&data);
                        console_trace!(status_tx, "BOOTP data (hex): {}", hex_str);

                        let parsed_info = Self::parse_bootp_message(&data);


                        // Add connection to ServerInstance
                        use crate::state::server::{
                            ConnectionState as ServerConnectionState, ConnectionStatus,
                            ProtocolConnectionInfo,
                        };
                        let now = crate::utils::clock::Instant::now();

                        let _request_type = parsed_info
                            .as_ref()
                            .map(|(desc, _)| desc.clone())
                            .unwrap_or_else(|| "unknown".to_string());


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

                        let llm_clone = llm_client.clone();
                        let state_clone = app_state.clone();
                        let status_clone = status_tx.clone();
                        let socket_clone = socket.clone();

                        // Tracked, not detached: stop_server must abort this task too.
                        let task_owner = app_state.clone();
                        task_owner
                            .spawn_server_task(server_id, async move {
                                // One protocol instance per request. The instance carries the
                                // request context (xid, chaddr, giaddr) used to build the reply,
                                // so two clients whose LLM calls overlap can never read each
                                // other's transaction ID.
                                let protocol = BootpProtocol::new();

                                if let Some((_, Some(ctx))) = parsed_info.as_ref() {
                                    protocol.set_request_context(ctx.clone());
                                }

                                // Extract event data
                                let (op_code, client_mac, client_ip, xid, gateway_ip) =
                                    if let Some((_, Some(ctx))) = &parsed_info {
                                        (
                                            format!("{:?}", ctx.op),
                                            crate::server::bootp::format_mac(&ctx.chaddr),
                                            ctx.ciaddr.to_string(),
                                            Some(ctx.xid),
                                            ctx.giaddr.to_string(),
                                        )
                                    } else {
                                        (
                                            "unknown".to_string(),
                                            "unknown".to_string(),
                                            "0.0.0.0".to_string(),
                                            None,
                                            "0.0.0.0".to_string(),
                                        )
                                    };


                                let client_mac_for_log = client_mac.clone();

                                let event_data = serde_json::json!({
                                    "op_code": op_code,
                                    "client_mac": client_mac,
                                    "client_ip": client_ip,
                                    "xid": xid,
                                    "gateway_ip": gateway_ip
                                });

                                let event = Event::new(&BOOTP_REQUEST_EVENT, event_data);

                                Log::new(Some(&status_clone)).debug(format!(
                                    "BOOTP calling LLM for request from {}",
                                    peer_addr
                                ));

                                match call_llm(
                                    &llm_clone,
                                    &state_clone,
                                    server_id,
                                    None,
                                    &event,
                                    &protocol,
                                )
                                .await
                                {
                                    Ok(execution_result) => {
                                        let log = Log::new(Some(&status_clone));
                                        for message in &execution_result.messages {
                                            log.info(format!("{}", message));
                                        }

                                        log.debug(format!(
                                            "BOOTP got {} protocol results",
                                            execution_result.protocol_results.len()
                                        ));

                                        let mut declined = false;
                                        let mut replied = false;

                                        for protocol_result in execution_result.protocol_results {
                                            if let Some(output_data) =
                                                protocol_result.get_all_output().first()
                                            {
                                                replied = true;
                                                let _ = socket_clone
                                                    .send_to(output_data, peer_addr)
                                                    .await;

                                                // DEBUG: Log summary
                                                log.debug(format!(
                                                    "BOOTP sent {} bytes to {}",
                                                    output_data.len(),
                                                    peer_addr
                                                ));

                                                // TRACE: Log full payload
                                                let hex_str = hex::encode(output_data);
                                                log.trace(format!("BOOTP sent (hex): {}", hex_str));

                                                let _ = status_clone.send(format!(
                                                    "→ BOOTP response to {} ({} bytes)",
                                                    peer_addr,
                                                    output_data.len()
                                                ));
                                            } else {
                                                // `ignore_request` yields NoAction: the model
                                                // looked at the request and chose not to serve
                                                // this client. That is a real decision, not a
                                                // failure, and must not be confused with either
                                                // of the two below.
                                                declined = true;
                                                log.debug(
                                                    "BOOTP protocol result has no output data",
                                                );
                                            }
                                        }

                                        if !replied {
                                            let decision = if declined {
                                                "model_decline"
                                            } else {
                                                "no_answer"
                                            };
                                            Self::log_silence(
                                                &status_clone,
                                                peer_addr,
                                                &client_mac_for_log,
                                                decision,
                                            );
                                        }
                                    }
                                    Err(e) => {
                                        // The backend failed. BOOTP has no way to say so on the
                                        // wire (see `log_silence`), so the peer gets nothing and
                                        // the error goes to the log and the operator's status
                                        // stream only - never into a datagram.
                                        let decision = match crate::utils::WireFailure::classify(&e)
                                        {
                                            crate::utils::WireFailure::Overloaded => {
                                                "fail_closed_overloaded"
                                            }
                                            crate::utils::WireFailure::Unavailable => {
                                                "fail_closed_unavailable"
                                            }
                                        };
                                        error!(
                                            "BOOTP LLM call failed for {} (mac={}) decision={}: {}",
                                            peer_addr, client_mac_for_log, decision, e
                                        );
                                        let _ =
                                            status_clone.send(format!("✗ BOOTP LLM error: {}", e));
                                        Self::log_silence(
                                            &status_clone,
                                            peer_addr,
                                            &client_mac_for_log,
                                            decision,
                                        );
                                    }
                                }
                            })
                            .await;
                    }
                    Err(e) => {
                        error!("BOOTP receive error: {}", e);
                        let _ = status_tx.send(format!("✗ BOOTP receive error: {}", e));
                        break;
                    }
                }
            }
        });

        // Register the recv loop so stop_server can abort it and release the port.
        task_registrar
            .register_server_task(server_id, accept_handle)
            .await;

        Ok(local_addr)
    }

    /// Record, in one greppable shape, that this request goes unanswered - and why.
    ///
    /// **BOOTP has no failure message, and inventing one would be worse than silence.**
    /// RFC 951 defines exactly two operations, BOOTREQUEST and BOOTREPLY; there is no NAK
    /// (DHCPNAK belongs to DHCP's message-type option, which BOOTP does not have) and no
    /// status field anywhere in the 300-byte frame. The only thing this server could put on
    /// the wire on failure is a BOOTREPLY, and a BOOTREPLY is an *offer*: the client reads
    /// `yiaddr`, `siaddr` and `file` and boots from them. A reply carrying 0.0.0.0 would
    /// either be discarded as garbage or, on a lenient client, end the retransmit loop and
    /// strand a machine that would otherwise have been served by the next retry or by
    /// another BOOTP server on the segment.
    ///
    /// Silence is what the protocol already means by "not me": RFC 951 s7.1 has the client
    /// retransmit with backoff precisely so a busy or absent server costs nothing. So a
    /// transient backend failure resolves itself on the client's next attempt, which is the
    /// same outcome the `Overloaded` category asks for in protocols that can express it.
    ///
    /// The three cases are therefore distinguished only here, by `decision=`:
    /// `model_decline` (the model ran `ignore_request`), `no_answer` (the model produced
    /// nothing), and `fail_closed_overloaded` / `fail_closed_unavailable` (the LLM call
    /// itself errored, classified by [`crate::utils::WireFailure`]). Nothing derived from
    /// the error reaches the socket.
    fn log_silence(
        status_tx: &mpsc::UnboundedSender<String>,
        peer_addr: SocketAddr,
        client_mac: &str,
        decision: &'static str,
    ) {
        let line = format!(
            "BOOTP no reply to {} (mac={}) decision={} (RFC 951 has no failure reply; \
             client will retransmit)",
            peer_addr, client_mac, decision
        );
        tracing::warn!("{}", line);
        Log::new(Some(status_tx)).info(line);
    }

    fn parse_bootp_message(data: &[u8]) -> Option<(String, Option<BootpRequestContext>)> {
        match v4::Message::decode(&mut Decoder::new(data)) {
            Ok(msg) => {
                // `hlen` comes straight off the wire without validation, and
                // `Message::chaddr()` slices a fixed [u8; 16] with it - a datagram
                // declaring hlen > 16 panics inside dhcproto. This loop runs in the
                // socket task, so that panic would kill the server. Reject instead.
                if msg.hlen() as usize > 16 {
                    tracing::warn!(
                        "Dropping BOOTP datagram with invalid hlen {} (max 16)",
                        msg.hlen()
                    );
                    return None;
                }

                let op = msg.opcode();

                // Build human-readable description
                let mac_str = hex::encode(msg.chaddr());
                let description = format!(
                    "BOOTP {} from client MAC {} (transaction ID: 0x{:08x}, client IP: {})",
                    format!("{:?}", op),
                    mac_str,
                    msg.xid(),
                    msg.ciaddr()
                );

                // Create context for action execution
                let context = BootpRequestContext {
                    xid: msg.xid(),
                    chaddr: msg.chaddr().to_vec(),
                    op: op,
                    ciaddr: msg.ciaddr(),
                    giaddr: msg.giaddr(),
                    sname: msg
                        .sname()
                        .map(|s| String::from_utf8_lossy(s).trim_matches('\0').to_string())
                        .unwrap_or_default(),
                    file: msg
                        .fname()
                        .map(|f| String::from_utf8_lossy(f).trim_matches('\0').to_string())
                        .unwrap_or_default(),
                };

                Some((description, Some(context)))
            }
            Err(e) => {
                tracing::warn!("Failed to parse BOOTP message: {}", e);
                None
            }
        }
    }
}
