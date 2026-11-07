//! NTP client implementation
pub mod actions;

pub use actions::NtpClientProtocol;

use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex};
use tracing::{error, info, trace};

use crate::client::llm_budget::call_llm_for_client;
use crate::client::ntp::actions::NTP_CLIENT_RESPONSE_RECEIVED_EVENT;
use crate::llm::actions::client_trait::{Client, ClientActionResult};
use crate::llm::ollama_client::OllamaClient;
use crate::llm::ClientLlmResult;
use crate::logging::emit::Log;
use crate::protocol::Event;
use crate::state::app_state::AppState;
use crate::state::client_handles::{ClientCommand, ClientSendOutcome};
use crate::state::{AccessLogOwner, ClientId, ClientStatus};

/// NTP client that queries NTP servers
pub struct NtpClient;

impl NtpClient {
    /// Connect to an NTP server with integrated LLM actions
    pub async fn connect_with_llm_actions(
        remote_addr: String,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        client_id: ClientId,
    ) -> Result<SocketAddr> {
        let remote_sock_addr = Self::resolve_server(&remote_addr).await?;

        // Bind an ephemeral local port in the family of the address we send to: an IPv4
        // socket cannot send to an IPv6 address, nor the other way round.
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
            "NTP client {} connected to {} (local: {})",
            client_id, remote_sock_addr, local_addr
        );

        // Update client state
        app_state
            .update_client_status(client_id, ClientStatus::Connected)
            .await;
        let _ = status_tx.send(format!("[CLIENT] NTP client {} connected", client_id));
        let _ = status_tx.send("__UPDATE_UI__".to_string());

        // Wrap socket in Arc for sharing
        let socket = Arc::new(socket);
        let socket_clone = socket.clone();

        // Only one query may own the socket's receive side at a time: the connect-time
        // query and any injected `query_time` would otherwise race for the same datagram
        // and one of them would parse the other's reply.
        let query_lock = Arc::new(Mutex::new(()));

        // Command channel for injected actions (the dashboard's [ send ]).
        //
        // Registered BEFORE the initial LLM call below, which a manual `*` routing rule can
        // park for minutes - [ send ] must work for the whole park.
        let command_rx =
            crate::client::command_support::register_command_channel(&app_state, client_id).await;

        let cmd_state = app_state.clone();
        let cmd_status_tx = status_tx.clone();
        let cmd_llm = llm_client.clone();
        let cmd_socket = socket.clone();
        let cmd_lock = query_lock.clone();
        let cmd_task = tokio::spawn(async move {
            Self::command_loop(
                command_rx,
                cmd_socket,
                remote_sock_addr,
                cmd_lock,
                client_id,
                cmd_llm,
                cmd_state,
                cmd_status_tx,
            )
            .await;
        });
        app_state.register_client_task(client_id, cmd_task).await;

        // Spawn task to handle LLM-directed queries
        // Registered with AppState so stop_client can abort this task —
        // dropping a JoinHandle only detaches it in Tokio.
        let task_registrar = app_state.clone();
        let query_lock_for_llm = query_lock.clone();
        let task_handle = tokio::spawn(async move {
            // Initial LLM call to get first action (usually query_time)
            if let Some(instruction) = app_state.get_instruction_for_client(client_id).await {
                let protocol = Arc::new(crate::client::ntp::actions::NtpClientProtocol::new());

                // Call LLM with connected event
                match call_llm_for_client(
                    &llm_client,
                    &app_state,
                    client_id.to_string(),
                    &instruction,
                    "", // No memory initially
                    // The connected event, not `None`.
                    //
                    // NTP_CLIENT_CONNECTED_EVENT was declared and nothing raised it, so
                    // this call arrived with no event attached: an `ntp_connected` handler
                    // the operator or the model wrote could never match, and
                    // `client_llm_action_set` could not union the event's own actions in.
                    Some(&Event::new(
                        &crate::client::ntp::actions::NTP_CLIENT_CONNECTED_EVENT,
                        serde_json::json!({ "remote_addr": remote_addr.clone() }),
                    )),
                    protocol.as_ref(),
                    &status_tx,
                )
                .await
                {
                    Ok(ClientLlmResult {
                        actions,
                        memory_updates: _,
                    }) => {
                        // Execute initial actions
                        for action in actions {
                            match protocol.as_ref().execute_action(action) {
                                Ok(ClientActionResult::Custom { name, data: _ })
                                    if name == "ntp_query" =>
                                {
                                    // Send the query, then read and report the reply. Same
                                    // two functions the injected-command path uses.
                                    match Self::send_query(&socket_clone, remote_sock_addr).await {
                                        Ok(sent) => {
                                            trace!(
                                                "NTP client {} sent {} byte query to {}",
                                                client_id,
                                                sent,
                                                remote_sock_addr
                                            );
                                            Self::await_and_report_response(
                                                &socket_clone,
                                                remote_sock_addr,
                                                &query_lock_for_llm,
                                                client_id,
                                                &llm_client,
                                                &app_state,
                                                &status_tx,
                                                &instruction,
                                                protocol.as_ref(),
                                            )
                                            .await;
                                        }
                                        Err(e) => {
                                            error!(
                                                "NTP client {} failed to send query: {}",
                                                client_id, e
                                            );
                                        }
                                    }
                                }
                                Ok(ClientActionResult::Disconnect) => {
                                    info!("NTP client {} disconnecting", client_id);
                                    app_state
                                        .update_client_status(client_id, ClientStatus::Disconnected)
                                        .await;
                                    let _ = status_tx.send("__UPDATE_UI__".to_string());
                                    break;
                                }
                                Ok(_) => {}
                                Err(e) => {
                                    error!("NTP client {} rejected action: {}", client_id, e);
                                }
                            }
                        }
                    }
                    Err(e) => {
                        error!("LLM error for NTP client {}: {}", client_id, e);
                    }
                }
            }

            // Mark as disconnected after query completes. The socket stays bound and the
            // command channel stays registered: an injected `query_time` can still run
            // another query, which is the multi-query path this client otherwise lacks.
            app_state
                .update_client_status(client_id, ClientStatus::Disconnected)
                .await;
            let _ = status_tx.send("__UPDATE_UI__".to_string());
        });
        task_registrar
            .register_client_task(client_id, task_handle)
            .await;

        Ok(local_addr)
    }

    /// Resolve the NTP server's `host:port`.
    ///
    /// A literal `IP:port` is used as given, with no name lookup. A hostname is resolved and
    /// its first IPv4 address is taken when it has one, otherwise its first address. UDP has
    /// no handshake that would reveal an unreachable address and move on to the next, and
    /// `localhost` commonly resolves to `::1` ahead of `127.0.0.1`, where a server listening
    /// on IPv4 alone never hears the query.
    async fn resolve_server(remote_addr: &str) -> Result<SocketAddr> {
        if let Ok(addr) = remote_addr.parse::<SocketAddr>() {
            return Ok(addr);
        }
        let candidates: Vec<SocketAddr> = tokio::net::lookup_host(remote_addr)
            .await
            .with_context(|| {
                format!(
                    "Could not resolve NTP server address {remote_addr:?} (expected host:port, \
                     e.g. 127.0.0.1:123 or ntp.example.org:123)"
                )
            })?
            .collect();
        candidates
            .iter()
            .find(|addr| addr.is_ipv4())
            .or_else(|| candidates.first())
            .copied()
            .with_context(|| format!("NTP server address {remote_addr:?} resolved to no address"))
    }

    /// Send one request and read its reply. Raises no event and calls no LLM.
    ///
    /// This is what a `query_time` the model asks for in answer to
    /// `ntp_response_received` runs through: reporting that reply as another event would
    /// let one query drive the model in an unbounded loop, and would make
    /// report -> query -> report a self-referential async chain rustc cannot prove `Send`.
    async fn query_once(socket: &Arc<UdpSocket>, remote: SocketAddr) -> Result<NtpTimestamps> {
        Self::send_query(socket, remote).await?;
        let mut buffer = vec![0u8; 48];
        let n = tokio::time::timeout(std::time::Duration::from_secs(5), socket.recv(&mut buffer))
            .await
            .map_err(|_| anyhow::anyhow!("timed out waiting for NTP reply"))??;
        Ok(Self::parse_ntp_response(&buffer[..n]))
    }

    /// Put one NTP request on the wire, returning the byte count `send_to` reported.
    async fn send_query(socket: &Arc<UdpSocket>, remote: SocketAddr) -> Result<usize> {
        let packet = Self::build_ntp_request();
        let sent = socket.send_to(&packet, remote).await?;
        Ok(sent)
    }

    /// Wait for the server's reply to a query we just sent, parse it, and hand it to the
    /// model as an `ntp_response_received` event.
    ///
    /// Holds `query_lock` across the receive so two concurrent queries cannot steal each
    /// other's datagram.
    #[allow(clippy::too_many_arguments)]
    async fn await_and_report_response(
        socket: &Arc<UdpSocket>,
        remote: SocketAddr,
        query_lock: &Arc<Mutex<()>>,
        client_id: ClientId,
        llm_client: &OllamaClient,
        app_state: &Arc<AppState>,
        status_tx: &mpsc::UnboundedSender<String>,
        instruction: &str,
        protocol: &dyn Client,
    ) {
        let mut buffer = vec![0u8; 48];
        let received = {
            let _guard = query_lock.lock().await;
            tokio::time::timeout(
                std::time::Duration::from_secs(5),
                socket.recv_from(&mut buffer),
            )
            .await
        };

        let n = match received {
            Ok(Ok((n, from_addr))) => {
                trace!(
                    "NTP client {} received {} bytes from {}",
                    client_id,
                    n,
                    from_addr
                );
                n
            }
            Ok(Err(e)) => {
                error!("NTP client {} recv error: {}", client_id, e);
                return;
            }
            Err(_) => {
                error!("NTP client {} timed out waiting for response", client_id);
                return;
            }
        };

        let timestamps = Self::parse_ntp_response(&buffer[..n]);

        let event = Event::new(
            &NTP_CLIENT_RESPONSE_RECEIVED_EVENT,
            serde_json::json!({
                "origin_timestamp": timestamps.origin_timestamp,
                "receive_timestamp": timestamps.receive_timestamp,
                "transmit_timestamp": timestamps.transmit_timestamp,
                "stratum": timestamps.stratum,
                "precision": timestamps.precision,
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
            instruction,
            &memory,
            Some(&event),
            protocol,
            status_tx,
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

                // Execute what the model asked for. These were discarded, so a model that
                // read a timestamp and wanted another sample was silently ignored.
                //
                // A `query_time` follow-up sends one more request and reads its reply
                // here, raising no further event. That bounds the loop -- otherwise each
                // reply would raise an event whose answer could ask for another query,
                // forever -- and keeps the type non-recursive, which is what
                // tokio::spawn's Send bound requires.
                use crate::llm::actions::client_trait::ClientActionResult;
                for action in actions {
                    match protocol.execute_action(action.clone()) {
                        Ok(ClientActionResult::Custom { name, .. }) if name == "query_time" => {
                            match Self::query_once(socket, remote).await {
                                Ok(t) => info!(
                                    "NTP client {} follow-up query_time: stratum {}",
                                    client_id, t.stratum
                                ),
                                Err(e) => error!(
                                    "NTP client {} follow-up query_time failed: {}",
                                    client_id, e
                                ),
                            }
                        }
                        Ok(_) => {}
                        Err(e) => error!(
                            "NTP client {} rejected its own follow-up action: {}",
                            client_id, e
                        ),
                    }
                }
            }
            Err(e) => {
                error!("LLM error for NTP client {}: {}", client_id, e);
            }
        }
    }

    /// Drain injected commands until the channel closes (the client was removed) or an
    /// injected `disconnect` ends the session.
    ///
    /// `query_time` reports `Sent { 48 }` the moment the request datagram is on the wire —
    /// the reply is then awaited and reported to the model *after* the caller has been
    /// answered, so a manual routing rule parked on `ntp_response_received` cannot hold the
    /// dashboard's [ send ] open for its whole timeout.
    #[allow(clippy::too_many_arguments)]
    async fn command_loop(
        mut command_rx: mpsc::Receiver<ClientCommand>,
        socket: Arc<UdpSocket>,
        remote: SocketAddr,
        query_lock: Arc<Mutex<()>>,
        client_id: ClientId,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
    ) {
        use crate::llm::actions::protocol_trait::Protocol;

        let protocol = NtpClientProtocol::new();

        while let Some(command) = command_rx.recv().await {
            let action = command.action.clone();

            // `query_time` is the only verb that puts bytes on the wire; the reply is
            // handled after the caller is answered, so `queried` carries that follow-up.
            let mut queried = false;
            let outcome = match protocol.execute_action(action.clone()) {
                Err(e) => Ok(ClientSendOutcome::Rejected {
                    error: e.to_string(),
                }),
                Ok(ClientActionResult::Custom { name, .. }) if name == "ntp_query" => {
                    match Self::send_query(&socket, remote).await {
                        Ok(bytes_sent) => {
                            queried = true;
                            Ok(ClientSendOutcome::Sent { bytes_sent })
                        }
                        Err(e) => Err(e),
                    }
                }
                Ok(ClientActionResult::Custom { name, .. }) => Ok(ClientSendOutcome::Executed {
                    detail: format!("custom result '{name}' is not an NTP client verb"),
                }),
                Ok(ClientActionResult::Disconnect) => Ok(ClientSendOutcome::Disconnected),
                Ok(ClientActionResult::WaitForMore) => Ok(ClientSendOutcome::Executed {
                    detail: "analyze_response is interpretation only; nothing written to the wire"
                        .to_string(),
                }),
                Ok(_) => Ok(ClientSendOutcome::Executed {
                    detail: "action produced no NTP request".to_string(),
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
                    "NTP client {} injected action failed: {}",
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
                    "[CLIENT] NTP client {} disconnected (injected action)",
                    client_id
                ));
                break;
            }

            if queried {
                if let Some(instruction) = app_state.get_instruction_for_client(client_id).await {
                    Self::await_and_report_response(
                        &socket,
                        remote,
                        &query_lock,
                        client_id,
                        &llm_client,
                        &app_state,
                        &status_tx,
                        &instruction,
                        &protocol,
                    )
                    .await;
                }
            }
        }

        app_state.remove_client_handle(client_id).await;
        let _ = status_tx.send("__UPDATE_UI__".to_string());
    }

    /// Build an NTP request packet (48 bytes)
    fn build_ntp_request() -> Vec<u8> {
        let mut packet = vec![0u8; 48];

        // Set LI = 0, VN = 3, Mode = 3 (client)
        packet[0] = 0x1b; // 00 011 011 = LI=0, VN=3, Mode=3

        // Set transmit timestamp to current time
        use crate::utils::clock::{SystemTime, UNIX_EPOCH};
        let unix_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Convert Unix timestamp to NTP timestamp (add NTP epoch offset)
        let ntp_timestamp = unix_time + 2_208_988_800;

        // Write transmit timestamp (bytes 40-47)
        let ntp_timestamp_bytes = ntp_timestamp.to_be_bytes();
        packet[40..44].copy_from_slice(&ntp_timestamp_bytes[4..8]);
        // Fraction field (bytes 44-47) left as 0

        packet
    }

    /// Parse NTP response packet
    fn parse_ntp_response(data: &[u8]) -> NtpTimestamps {
        if data.len() < 48 {
            return NtpTimestamps::default();
        }

        // Extract stratum (byte 1)
        let stratum = data[1];

        // Extract precision (byte 3)
        let precision = data[3] as i8;

        // Extract origin timestamp (bytes 24-31)
        let origin_seconds = u32::from_be_bytes([data[24], data[25], data[26], data[27]]) as u64;
        let _origin_fraction = u32::from_be_bytes([data[28], data[29], data[30], data[31]]) as u64;
        let origin_timestamp = if origin_seconds > 2_208_988_800 {
            origin_seconds - 2_208_988_800
        } else {
            origin_seconds
        };

        // Extract receive timestamp (bytes 32-39)
        let receive_seconds = u32::from_be_bytes([data[32], data[33], data[34], data[35]]) as u64;
        let _receive_fraction = u32::from_be_bytes([data[36], data[37], data[38], data[39]]) as u64;
        let receive_timestamp = if receive_seconds > 2_208_988_800 {
            receive_seconds - 2_208_988_800
        } else {
            receive_seconds
        };

        // Extract transmit timestamp (bytes 40-47)
        let transmit_seconds = u32::from_be_bytes([data[40], data[41], data[42], data[43]]) as u64;
        let _transmit_fraction =
            u32::from_be_bytes([data[44], data[45], data[46], data[47]]) as u64;
        let transmit_timestamp = if transmit_seconds > 2_208_988_800 {
            transmit_seconds - 2_208_988_800
        } else {
            transmit_seconds
        };

        NtpTimestamps {
            origin_timestamp,
            receive_timestamp,
            transmit_timestamp,
            stratum,
            precision,
        }
    }
}

#[derive(Debug, Default)]
struct NtpTimestamps {
    origin_timestamp: u64,
    receive_timestamp: u64,
    transmit_timestamp: u64,
    stratum: u8,
    precision: i8,
}
