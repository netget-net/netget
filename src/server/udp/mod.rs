//! UDP server implementation for raw UDP stack
pub mod actions;

use crate::server::connection::ConnectionId;
use actions::UdpProtocol;
use anyhow::Result;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex};

use crate::llm::action_helper::call_llm;
use crate::llm::ollama_client::OllamaClient;
use crate::logging::emit::Log;
use crate::protocol::Event;
use crate::state::app_state::AppState;
use actions::UDP_DATAGRAM_RECEIVED_EVENT;

/// UDP server that manages UDP connections
pub struct UdpServer;

impl UdpServer {
    /// Spawn UDP server with action-based LLM handling
    pub async fn spawn_with_llm_actions(
        listen_addr: SocketAddr,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        server_id: crate::state::ServerId,
    ) -> Result<SocketAddr> {
        let socket = Arc::new(UdpSocket::bind(listen_addr).await?);
        let local_addr = socket.local_addr()?;
        Log::new(Some(&status_tx)).info(format!("UDP server listening on {}", local_addr));

        let tap = crate::capture::udp::UdpTap::server(&app_state, server_id, local_addr);
        let protocol = Arc::new(UdpProtocol::with_socket(socket.clone(), tap.clone()));

        let task_registrar = app_state.clone();
        let accept_handle = tokio::spawn(async move {
            let mut buffer = vec![0u8; 65535]; // Maximum UDP datagram size

            loop {
                match socket.recv_from(&mut buffer).await {
                    Ok((n, peer_addr)) => {
                        let data = buffer[..n].to_vec();
                        tap.inbound(peer_addr, &data);
                        let connection_id =
                            ConnectionId::new(app_state.get_next_unified_id().await);

                        // Add connection to ServerInstance (UDP "connection" = recent peer)
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

                        // Datagram summary + full payload are FileOnly: the
                        // udp_datagram_received event template surfaces the datagram to
                        // the TUI, so streaming the payload here too would duplicate it
                        // on the unbounded channel.
                        {
                            let log = Log::new(Some(&status_tx));
                            if data
                                .iter()
                                .all(|&b| b.is_ascii_graphic() || b.is_ascii_whitespace())
                            {
                                let data_str = String::from_utf8_lossy(&data);
                                let preview = if data_str.len() > 100 {
                                    format!("{}...", &data_str[..100])
                                } else {
                                    data_str.to_string()
                                };
                                log.debug(format!(
                                    "UDP received {} bytes from {}: {}",
                                    n, peer_addr, preview
                                ));
                                log.trace(format!("UDP data (text): {:?}", data_str));
                            } else {
                                log.debug(format!(
                                    "UDP received {} bytes from {} (binary data)",
                                    n, peer_addr
                                ));
                                log.trace(format!("UDP data (hex): {}", hex::encode(&data)));
                            }
                        }

                        let llm_clone = llm_client.clone();
                        let state_clone = app_state.clone();
                        let status_clone = status_tx.clone();
                        let socket_clone = socket.clone();
                        let reply_tap = tap.clone();
                        let protocol_clone = protocol.clone();

                        // Tracked, not detached: stop_server must abort this task too.
                        let task_owner = app_state.clone();
                        task_owner.spawn_server_task(server_id, async move {
                            let log = Log::new(Some(&status_clone));
                            // Render the payload the way the model will have to reply in.
                            //
                            // This used to be `format!("{:?}", data)` on a Vec<u8>, i.e. the
                            // model was shown `[72, 101, 108, 108, 111]` for "Hello" and had
                            // to reconstruct the text from decimal byte codes. Printable
                            // payloads are now shown as text and binary ones as hex, and
                            // data_encoding tells the model which it is looking at - and so
                            // which `encoding` to use in send_udp_response.
                            const PREVIEW_BYTES: usize = 200;
                            let shown = &data[..data.len().min(PREVIEW_BYTES)];
                            let printable = !shown.is_empty()
                                && shown
                                    .iter()
                                    .all(|&b| b.is_ascii_graphic() || b.is_ascii_whitespace());
                            let (data_encoding, mut data_preview) = if printable {
                                ("text", String::from_utf8_lossy(shown).into_owned())
                            } else {
                                ("hex", hex::encode(shown))
                            };
                            if data.len() > PREVIEW_BYTES {
                                data_preview.push_str("...");
                            }

                            let event = Event::new(
                                &UDP_DATAGRAM_RECEIVED_EVENT,
                                serde_json::json!({
                                    "peer_address": peer_addr.to_string(),
                                    "data_length": data.len(),
                                    "data_encoding": data_encoding,
                                    "data_preview": data_preview
                                }),
                            );

                            log.debug(format!("UDP calling LLM for datagram from {}", peer_addr));

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
                                    for message in &execution_result.messages {
                                        log.info(message);
                                    }

                                    log.debug(format!(
                                        "UDP got {} protocol results",
                                        execution_result.protocol_results.len()
                                    ));

                                    // Classify *before* `protocol_results` is consumed below.
                                    //
                                    // UDP puts nothing on the wire in three of the five
                                    // outcomes, so the log is the only place they can be told
                                    // apart: a model that answered `ignore_datagram`, a model
                                    // that answered nothing at all, and an action the executor
                                    // refused are all the same silence on the socket - and the
                                    // same silence a dead backend produces. Without a
                                    // `decision=` token an operator has no way to tell which
                                    // of the four they are looking at.
                                    let action_types: Vec<&str> = execution_result
                                        .raw_actions
                                        .iter()
                                        .filter_map(|a| a.get("type").and_then(|v| v.as_str()))
                                        .collect();
                                    let explicit_ignore = action_types.contains(&"ignore_datagram");
                                    let dispatched_elsewhere =
                                        action_types.contains(&"send_to_address");
                                    let failure_summary = execution_result
                                        .failures
                                        .iter()
                                        .map(|f| format!("{}: {}", f.action, f.error))
                                        .collect::<Vec<_>>()
                                        .join("; ");
                                    let mut sent = 0usize;
                                    let mut send_failed = false;

                                    for protocol_result in execution_result.protocol_results {
                                        if let Some(output_data) =
                                            protocol_result.get_all_output().first()
                                        {
                                            if let Err(e) =
                                                socket_clone.send_to(output_data, peer_addr).await
                                            {
                                                send_failed = true;
                                                log.error(format!(
                                                    "Failed to send UDP response: {}",
                                                    e
                                                ));
                                            } else {
                                                sent += 1;
                                                reply_tap.outbound(peer_addr, output_data);
                                                // Sent summary + payload are FileOnly; the
                                                // access line below carries the TUI.
                                                if output_data.iter().all(|&b| {
                                                    b.is_ascii_graphic() || b.is_ascii_whitespace()
                                                }) {
                                                    let data_str =
                                                        String::from_utf8_lossy(output_data);
                                                    let preview = if data_str.len() > 100 {
                                                        format!("{}...", &data_str[..100])
                                                    } else {
                                                        data_str.to_string()
                                                    };
                                                    log.debug(format!(
                                                        "UDP sent {} bytes to {}: {}",
                                                        output_data.len(),
                                                        peer_addr,
                                                        preview
                                                    ));
                                                    log.trace(format!(
                                                        "UDP sent (text): {:?}",
                                                        data_str
                                                    ));
                                                } else {
                                                    log.debug(format!(
                                                        "UDP sent {} bytes to {} (binary data)",
                                                        output_data.len(),
                                                        peer_addr
                                                    ));
                                                    log.trace(format!(
                                                        "UDP sent (hex): {}",
                                                        hex::encode(output_data)
                                                    ));
                                                }

                                                // Keep the pseudo-connection's counters live.
                                                // This server registered every datagram with
                                                // bytes_received set and then never touched
                                                // the row again, so the rail's ↑ column and
                                                // last_activity stayed at their initial values
                                                // for the whole life of the entry — the module
                                                // CLAUDE.md claimed "Response increments
                                                // packets_sent and bytes_sent" and nothing did.
                                                state_clone
                                                    .update_connection_stats(
                                                        server_id,
                                                        connection_id,
                                                        None,
                                                        Some(output_data.len() as u64),
                                                        None,
                                                        Some(1),
                                                    )
                                                    .await;

                                                log.info(format!(
                                                    "UDP response to {} ({} bytes)",
                                                    peer_addr,
                                                    output_data.len()
                                                ));
                                            }
                                        } else {
                                            log.debug("UDP protocol result has no output data");
                                        }
                                    }

                                    // One decision line per datagram, whatever happened.
                                    let subject = format!(
                                        "UDP datagram from {} ({})",
                                        peer_addr, connection_id
                                    );
                                    if sent > 0 {
                                        log.info(format!(
                                            "{} decision=model_answer ({} reply datagram(s))",
                                            subject, sent
                                        ));
                                    } else if send_failed {
                                        log.error(format!(
                                            "{} decision=protocol_error: the model answered but \
                                             the reply could not be put on the socket",
                                            subject
                                        ));
                                    } else if !failure_summary.is_empty() {
                                        log.error(format!(
                                            "{} decision=fail_closed_bad_action: nothing was sent \
                                             because the model's action(s) could not be executed \
                                             ({})",
                                            subject, failure_summary
                                        ));
                                    } else if explicit_ignore {
                                        log.info(format!(
                                            "{} decision=model_reject (ignore_datagram: the model \
                                             chose to send nothing)",
                                            subject
                                        ));
                                    } else if dispatched_elsewhere {
                                        log.info(format!(
                                            "{} decision=model_answer (send_to_address: the \
                                             datagram went to another address, nothing back to \
                                             this peer)",
                                            subject
                                        ));
                                    } else {
                                        log.warn(format!(
                                            "{} decision=model_silent: the model was asked and \
                                             returned no usable action, so nothing was sent - \
                                             bare UDP has no error form",
                                            subject
                                        ));
                                    }
                                }
                                Err(e) => {
                                    // Deliberately silent, and the one protocol in this group
                                    // where that is the right answer.
                                    //
                                    // Bare UDP (RFC 768) has no error frame, no transaction
                                    // identifier and no application semantics: this server does
                                    // not know what the datagram meant, so it has nothing to
                                    // say back that the peer could parse. Anything we invented
                                    // would be indistinguishable from a real reply in whatever
                                    // protocol the peer is actually speaking - a *worse*
                                    // failure than silence, because the peer would act on it.
                                    // Dropping the datagram is also normal, expected UDP
                                    // behaviour that every UDP client already handles.
                                    //
                                    // A protocol layered on UDP that *does* have an error form
                                    // must answer with it: see DNS (SERVFAIL), STUN (500
                                    // Binding Error Response) and NTP (Kiss-o'-Death) in this
                                    // same tree. So the silence is logged loudly here rather
                                    // than left to be inferred.
                                    // ERROR on both channels by design (see above and the
                                    // module CLAUDE.md): the silent drop must be explained.
                                    // tests/server/udp/llm_failure_test.rs asserts the phrase
                                    // "no reply possible: bare UDP has no error form" reaches
                                    // the status stream, so keep it here verbatim.
                                    //
                                    // The `decision=` token is what separates this silence from
                                    // the model's own `ignore_datagram` silence and from a
                                    // model that simply said nothing. On the wire all three are
                                    // identical, so the distinction can only live in the log.
                                    let decision = match crate::utils::wire_failure::WireFailure::classify(&e) {
                                        crate::utils::wire_failure::WireFailure::Overloaded => {
                                            "fail_closed_llm_overloaded"
                                        }
                                        crate::utils::wire_failure::WireFailure::Unavailable => {
                                            "fail_closed_llm_error"
                                        }
                                    };
                                    log.error(format!(
                                        "UDP LLM call failed for datagram from {} ({}) decision={}: {} - no reply possible: bare UDP has no error form",
                                        peer_addr, connection_id, decision, e
                                    ));
                                    if crate::llm::is_overload_error(&e) {
                                        log.warn(format!(
                                            "UDP datagram from {} dropped: LLM capacity exhausted",
                                            peer_addr
                                        ));
                                    }
                                }
                            }
                        }).await;
                    }
                    Err(e) => {
                        Log::new(Some(&status_tx)).error(format!("UDP receive error: {}", e));
                    }
                }
            }
        });

        task_registrar
            .register_server_task(server_id, accept_handle)
            .await;

        Ok(local_addr)
    }
}

/// Shared UDP socket for sending responses
pub type SharedUdpSocket = Arc<Mutex<Arc<UdpSocket>>>;

/// Map from connection ID to peer address for UDP responses
pub type UdpPeerMap = Arc<Mutex<HashMap<ConnectionId, SocketAddr>>>;
