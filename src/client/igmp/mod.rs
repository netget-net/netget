//! IGMP client implementation for multicast group management
pub mod actions;

pub use actions::IgmpClientProtocol;

use anyhow::{Context, Result};
use std::collections::HashSet;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex};
use tracing::{error, info, trace, warn};

use crate::client::igmp::actions::{IGMP_CLIENT_CONNECTED_EVENT, IGMP_CLIENT_DATA_RECEIVED_EVENT};
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

/// How much of a received datagram is hex-encoded into the `igmp_data_received` event.
///
/// A UDP datagram can be 64 KiB, which is 128 KiB of hex — enough to fill a model's whole
/// context with one multicast frame, and to do it again for every frame that arrives. The
/// event carries the true `data_length` and a `data_truncated` flag either way, so the model
/// is told what it is not being shown rather than quietly given a prefix.
const MAX_EVENT_PAYLOAD_BYTES: usize = 2048;

/// Hex for the event, plus whether it was cut short.
fn payload_hex(data: &[u8]) -> (String, bool) {
    if data.len() <= MAX_EVENT_PAYLOAD_BYTES {
        (hex::encode(data), false)
    } else {
        (hex::encode(&data[..MAX_EVENT_PAYLOAD_BYTES]), true)
    }
}

/// Per-client data for LLM handling.
///
/// There is deliberately no Idle/Processing/Accumulating state machine here. The one the other
/// protocols carry exists to stop two concurrent readers making concurrent LLM calls on one
/// connection; this client has a single receive task that awaits its LLM round-trip inline
/// before it calls `recv_from` again, so `Processing` could never be observed. The version that
/// had one queued nothing (the queue was only ever reachable from the unreachable arm) and
/// ended each pass by *clearing* the queue, so had it ever fired it would have silently dropped
/// the datagrams it collected. Datagrams that arrive during an LLM call wait in the kernel
/// socket buffer, which is where they belong.
struct IgmpClientData {
    memory: String,
    joined_groups: HashSet<Ipv4Addr>,
}

/// IGMP client for multicast group management
pub struct IgmpClient;

impl IgmpClient {
    /// Connect (bind) IGMP client with integrated LLM actions
    pub async fn connect_with_llm_actions(
        bind_addr: String,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        client_id: ClientId,
    ) -> Result<SocketAddr> {
        // Parse bind address - use 0.0.0.0:0 if not specified
        let socket_addr: SocketAddr = if bind_addr.is_empty() || bind_addr == "igmp" {
            "0.0.0.0:0".parse()?
        } else {
            bind_addr.parse().context("Invalid bind address")?
        };

        // Create UDP socket for multicast reception
        let socket = UdpSocket::bind(socket_addr)
            .await
            .context("Failed to bind UDP socket for IGMP client")?;

        let local_addr = socket.local_addr()?;

        info!("IGMP client {} bound to {}", client_id, local_addr);

        // Update client state
        app_state
            .update_client_status(client_id, ClientStatus::Connected)
            .await;
        let _ = status_tx.send(format!("[CLIENT] IGMP client {} ready", client_id));
        let _ = status_tx.send("__UPDATE_UI__".to_string());

        // Wrap socket in Arc for shared access
        let socket_arc = Arc::new(socket);

        // Initialize client data
        let client_data = Arc::new(Mutex::new(IgmpClientData {
            memory: String::new(),
            joined_groups: HashSet::new(),
        }));

        let protocol = Arc::new(IgmpClientProtocol::new());

        // Command channel for injected actions (the dashboard's [ send ]). Registered, and
        // drained by a live task, BEFORE the connected-event LLM call below: that call is
        // awaited inline here, so a manual `*` routing rule parks it - and the whole point
        // of the channel is that the operator can still reach the client while it waits.
        let command_rx =
            crate::client::command_support::register_command_channel(&app_state, client_id).await;
        // Filled in once the receive loop exists (it is spawned after the connected-event
        // call), so an injected `disconnect` can actually stop it and release the socket.
        let read_abort: Arc<std::sync::OnceLock<tokio::task::AbortHandle>> =
            Arc::new(std::sync::OnceLock::new());
        let cmd_task = tokio::spawn(Self::command_loop(
            command_rx,
            protocol.clone(),
            socket_arc.clone(),
            client_data.clone(),
            client_id,
            app_state.clone(),
            status_tx.clone(),
            read_abort.clone(),
        ));
        app_state.register_client_task(client_id, cmd_task).await;

        // Trigger initial connected event
        let client_instance = app_state.get_client(client_id).await;
        let instruction = client_instance
            .as_ref()
            .map(|c| c.instruction.clone())
            .unwrap_or_default();

        let connected_event = Event::new(
            &IGMP_CLIENT_CONNECTED_EVENT,
            serde_json::json!({
                "local_addr": local_addr.to_string(),
            }),
        );

        // Initial LLM call. Its actions used to be discarded (`let _ = ...`), so a model
        // that answered the connected event with a `join_multicast_group` was ignored;
        // they now go through the same `apply_action` the read loop and injected commands
        // use.
        match call_llm_for_client(
            &llm_client,
            &app_state,
            client_id.to_string(),
            &instruction,
            "",
            Some(&connected_event),
            protocol.as_ref(),
            &status_tx,
        )
        .await
        {
            Ok(result) => {
                for action in result.actions {
                    match protocol.as_ref().execute_action(action) {
                        Ok(action_result) => {
                            if let Err(e) = Self::apply_action(
                                client_id,
                                action_result,
                                &socket_arc,
                                &client_data,
                                &status_tx,
                            )
                            .await
                            {
                                error!(
                                    "IGMP client {} action failed after connect: {}",
                                    client_id, e
                                );
                                let _ = status_tx.send(format!(
                                    "[CLIENT] IGMP client {} action failed after connect: {}",
                                    client_id, e
                                ));
                            }
                        }
                        Err(e) => {
                            // On the status stream as well as in the log: this is where a
                            // model's malformed answer to `igmp_connected` lands, and until
                            // it was surfaced a client told to join a group could report a
                            // clean start having joined nothing.
                            warn!(
                                "IGMP client {} could not execute action after connect: {}",
                                client_id, e
                            );
                            let _ = status_tx.send(format!(
                                "[CLIENT] IGMP client {} rejected an action after connect: {}",
                                client_id, e
                            ));
                        }
                    }
                }
            }
            Err(e) => error!("LLM error on igmp_client_connected event: {}", e),
        }

        // An injected `disconnect` that arrived while the connected-event call was parked
        // has already dropped the command handle. Honour it rather than starting a receive
        // loop the operator just asked to stop.
        if !app_state.has_client_handle(client_id).await {
            return Ok(local_addr);
        }

        // Clone references for read loop
        let socket_clone = socket_arc.clone();
        let app_state_clone = app_state.clone();
        let status_tx_clone = status_tx.clone();
        let llm_client_clone = llm_client.clone();
        let client_data_clone = client_data.clone();
        let protocol = protocol.clone();

        // Spawn read loop for receiving multicast data
        // Registered with AppState so stop_client can abort this task —
        // dropping a JoinHandle only detaches it in Tokio.
        let task_registrar = app_state.clone();
        let task_handle = tokio::spawn(async move {
            let mut buffer = vec![0u8; 65536];
            // Lifecycle, at INFO: without it there is no way to tell "the datagram never
            // arrived" from "nothing was ever listening for it", and the two have very
            // different causes.
            info!("IGMP client {} receive loop listening", client_id);

            loop {
                match socket_clone.recv_from(&mut buffer).await {
                    Ok((n, peer_addr)) => {
                        let data = buffer[..n].to_vec();
                        trace!(
                            "IGMP client {} received {} bytes from {}",
                            client_id,
                            n,
                            peer_addr
                        );

                        // Ask the model what to do about this datagram and apply its answer.
                        // No state machine guards this: the same task does the `recv_from`
                        // and awaits the LLM call, so nothing else can be mid-call here
                        // (see `IgmpClientData`).
                        let Some(instruction) =
                            app_state_clone.get_instruction_for_client(client_id).await
                        else {
                            continue;
                        };

                        let memory = {
                            let data_lock = client_data_clone.lock().await;
                            data_lock.memory.clone()
                        };

                        let (data_hex, truncated) = payload_hex(&data);
                        let event = Event::new(
                            &IGMP_CLIENT_DATA_RECEIVED_EVENT,
                            serde_json::json!({
                                "data_hex": data_hex,
                                "data_length": n,
                                "data_truncated": truncated,
                                "source_addr": peer_addr.to_string(),
                            }),
                        );

                        match call_llm_for_client(
                            &llm_client_clone,
                            &app_state_clone,
                            client_id.to_string(),
                            &instruction,
                            &memory,
                            Some(&event),
                            protocol.as_ref(),
                            &status_tx_clone,
                        )
                        .await
                        {
                            Ok(ClientLlmResult {
                                actions,
                                memory_updates,
                            }) => {
                                if let Some(mem) = memory_updates {
                                    client_data_clone.lock().await.memory = mem;
                                }

                                for action in actions {
                                    match protocol.as_ref().execute_action(action) {
                                        Ok(result) => {
                                            match Self::apply_action(
                                                client_id,
                                                result,
                                                &socket_clone,
                                                &client_data_clone,
                                                &status_tx_clone,
                                            )
                                            .await
                                            {
                                                Ok(Applied::Disconnect) => {
                                                    info!(
                                                        "IGMP client {} disconnecting",
                                                        client_id
                                                    );
                                                    app_state_clone
                                                        .remove_client_handle(client_id)
                                                        .await;
                                                    app_state_clone
                                                        .update_client_status(
                                                            client_id,
                                                            ClientStatus::Disconnected,
                                                        )
                                                        .await;
                                                    let _ = status_tx_clone
                                                        .send("__UPDATE_UI__".to_string());
                                                    return;
                                                }
                                                Ok(_) => {}
                                                Err(e) => {
                                                    error!(
                                                        "IGMP client {} action failed: {}",
                                                        client_id, e
                                                    );
                                                    let _ = status_tx_clone.send(format!(
                                                        "[CLIENT] IGMP client {} action failed: {}",
                                                        client_id, e
                                                    ));
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            // Visible, not only in the log file: an action the
                                            // protocol cannot execute means the model's answer
                                            // never reached the wire, and nothing else says so.
                                            warn!(
                                                "Action execution error for IGMP client {}: {}",
                                                client_id, e
                                            );
                                            let _ = status_tx_clone.send(format!(
                                                "[CLIENT] IGMP client {} rejected an action: {}",
                                                client_id, e
                                            ));
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                error!("LLM error for IGMP client {}: {}", client_id, e);
                            }
                        }
                    }
                    Err(e) => {
                        error!("IGMP client {} read error: {}", client_id, e);
                        app_state_clone
                            .update_client_status(client_id, ClientStatus::Error(e.to_string()))
                            .await;
                        let _ = status_tx_clone
                            .send(format!("[CLIENT] IGMP client {} error: {}", client_id, e));
                        let _ = status_tx_clone.send("__UPDATE_UI__".to_string());
                        break;
                    }
                }
            }
            // Every exit path lands here: drop the command handle so the dashboard stops
            // offering [ send ] on a dead client, and a late send fails fast.
            app_state_clone.remove_client_handle(client_id).await;
            let _ = status_tx_clone.send("__UPDATE_UI__".to_string());
        });
        let _ = read_abort.set(task_handle.abort_handle());
        task_registrar
            .register_client_task(client_id, task_handle)
            .await;

        Ok(local_addr)
    }

    /// Drain injected commands until the channel closes (client removed) or an injected
    /// `disconnect` ends the session.
    ///
    /// The generic `command_support::handle_stream_client_command` cannot serve this client:
    /// every IGMP verb yields `ClientActionResult::Custom` and the transport is a datagram
    /// socket, not an `AsyncWrite`. The action goes through [`Self::apply_action`] - the same
    /// function the connected-event path and the receive loop use.
    #[allow(clippy::too_many_arguments)]
    async fn command_loop(
        mut command_rx: tokio::sync::mpsc::Receiver<ClientCommand>,
        protocol: Arc<IgmpClientProtocol>,
        socket: Arc<UdpSocket>,
        client_data: Arc<Mutex<IgmpClientData>>,
        client_id: ClientId,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        read_abort: Arc<std::sync::OnceLock<tokio::task::AbortHandle>>,
    ) {
        while let Some(command) = command_rx.recv().await {
            let action = command.action.clone();
            let outcome = match protocol.execute_action(action.clone()) {
                Err(e) => Ok(ClientSendOutcome::Rejected {
                    error: e.to_string(),
                }),
                Ok(result) => {
                    Self::apply_action(client_id, result, &socket, &client_data, &status_tx)
                        .await
                        .map(|applied| match applied {
                            Applied::Disconnect => ClientSendOutcome::Disconnected,
                            Applied::Sent(0) => ClientSendOutcome::Executed {
                                detail: "executed (no datagram sent)".to_string(),
                            },
                            Applied::Sent(bytes_sent) => ClientSendOutcome::Sent { bytes_sent },
                            Applied::Nothing(detail) => ClientSendOutcome::Executed { detail },
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
                    "IGMP client {} injected action failed: {}",
                    client_id, e
                ));
            }
            let _ = status_tx.send("__UPDATE_UI__".to_string());
            crate::client::command_support::reply(command, outcome);

            if disconnect {
                if let Some(abort) = read_abort.get() {
                    abort.abort();
                }
                app_state.remove_client_handle(client_id).await;
                app_state
                    .update_client_status(client_id, ClientStatus::Disconnected)
                    .await;
                let _ = status_tx.send("__UPDATE_UI__".to_string());
                break;
            }
        }
    }

    /// Apply one executed action. Shared by the connected-event path, the receive loop and
    /// injected commands so the multicast machinery exists exactly once.
    ///
    /// The group joins run on the client's **own** receive socket. They used to be applied
    /// to a throwaway `socket2::Socket` created inside the match and dropped at the end of
    /// it, so the membership died immediately and the socket the read loop was polling never
    /// joined anything - the client reported success and received no multicast.
    async fn apply_action(
        client_id: ClientId,
        result: ClientActionResult,
        socket: &UdpSocket,
        client_data: &Arc<Mutex<IgmpClientData>>,
        status_tx: &mpsc::UnboundedSender<String>,
    ) -> Result<Applied> {
        match result {
            ClientActionResult::Custom { name, data } if name == "join_multicast_group" => {
                let (mcast_ip, iface_ip) = Self::group_args(&data)?;
                if client_data.lock().await.joined_groups.contains(&mcast_ip) {
                    return Ok(Applied::Nothing(format!(
                        "already a member of {mcast_ip}; no IGMP report emitted"
                    )));
                }
                socket
                    .join_multicast_v4(mcast_ip, iface_ip)
                    .with_context(|| format!("failed to join multicast group {mcast_ip}"))?;
                client_data.lock().await.joined_groups.insert(mcast_ip);
                info!(
                    "IGMP client {} joined multicast group {}",
                    client_id, mcast_ip
                );
                let _ = status_tx.send(format!("[CLIENT] Joined multicast group {}", mcast_ip));
                Ok(Applied::Nothing(format!(
                    "joined {mcast_ip} on {iface_ip}; the kernel emits the IGMP membership report"
                )))
            }
            ClientActionResult::Custom { name, data } if name == "leave_multicast_group" => {
                let (mcast_ip, iface_ip) = Self::group_args(&data)?;
                socket
                    .leave_multicast_v4(mcast_ip, iface_ip)
                    .with_context(|| format!("failed to leave multicast group {mcast_ip}"))?;
                client_data.lock().await.joined_groups.remove(&mcast_ip);
                info!(
                    "IGMP client {} left multicast group {}",
                    client_id, mcast_ip
                );
                let _ = status_tx.send(format!("[CLIENT] Left multicast group {}", mcast_ip));
                Ok(Applied::Nothing(format!(
                    "left {mcast_ip} on {iface_ip}; the kernel emits the IGMP leave"
                )))
            }
            ClientActionResult::Custom { name, data } if name == "send_multicast" => {
                let mcast = data["multicast_addr"]
                    .as_str()
                    .context("send_multicast is missing 'multicast_addr'")?;
                let port = data["port"]
                    .as_u64()
                    .context("send_multicast is missing 'port'")?;
                let bytes = crate::client::wire_values::bytes(
                    data["data"]
                        .as_array()
                        .context("send_multicast is missing decoded 'data'")?,
                )?;
                let dest_addr: SocketAddr = format!("{}:{}", mcast, port)
                    .parse()
                    .with_context(|| format!("invalid multicast destination {mcast}:{port}"))?;
                let sent = socket.send_to(&bytes, dest_addr).await?;
                trace!(
                    "IGMP client {} sent {} bytes to {}",
                    client_id,
                    sent,
                    dest_addr
                );
                let _ = status_tx.send(format!(
                    "[CLIENT] Sent {} bytes to multicast {}",
                    sent, dest_addr
                ));
                Ok(Applied::Sent(sent))
            }
            ClientActionResult::Disconnect => Ok(Applied::Disconnect),
            ClientActionResult::WaitForMore => Ok(Applied::Nothing("wait_for_more".to_string())),
            ClientActionResult::Custom { name, .. } => Ok(Applied::Nothing(format!(
                "custom result '{name}' is not an IGMP verb; nothing sent"
            ))),
            other => Ok(Applied::Nothing(format!(
                "action result {other:?} produced no datagram"
            ))),
        }
    }

    /// Pull the multicast/interface address pair out of a join/leave action's data.
    fn group_args(data: &serde_json::Value) -> Result<(Ipv4Addr, Ipv4Addr)> {
        let mcast: Ipv4Addr = data["multicast_addr"]
            .as_str()
            .context("missing 'multicast_addr'")?
            .parse()
            .context("invalid multicast address")?;
        let iface: Ipv4Addr = data["interface_addr"]
            .as_str()
            .unwrap_or("0.0.0.0")
            .parse()
            .context("invalid interface address")?;
        Ok((mcast, iface))
    }
}

/// What [`IgmpClient::apply_action`] did with one action.
#[derive(Debug)]
enum Applied {
    /// Datagram bytes actually handed to `send_to` (0 when nothing was sent).
    Sent(usize),
    /// Ran, but produced no datagram of our own; the string says what happened.
    Nothing(String),
    /// The session should end.
    Disconnect,
}
