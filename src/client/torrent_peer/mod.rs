//! BitTorrent Peer Wire Protocol client implementation
pub mod actions;

pub use actions::TorrentPeerClientProtocol;

use anyhow::{bail, Context, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex};
use tracing::{error, info, trace};

use crate::client::llm_budget::call_llm_for_client;
use crate::client::torrent_peer::actions::{PEER_HANDSHAKE_EVENT, PEER_MESSAGE_EVENT};
use crate::llm::ollama_client::OllamaClient;
use crate::llm::ClientLlmResult;
use crate::logging::emit::Log;
use crate::protocol::Event;
use crate::state::app_state::AppState;
use crate::state::{ClientId, ClientStatus};

/// Maximum inbound peer message, including its message ID. Normal block messages
/// are much smaller; this also leaves room for large bitfields and extensions.
pub const MAX_PEER_MESSAGE_BYTES: usize = 8 * 1024 * 1024;

/// Read one length-prefixed peer message without trusting its allocation size.
/// An empty message is the protocol's keepalive. Do not cancel this read midway.
pub async fn read_peer_message<R: AsyncReadExt + Unpin>(reader: &mut R) -> Result<Vec<u8>> {
    read_peer_message_with_timeout(reader, crate::client::response_reader::RESPONSE_DEADLINE).await
}

pub async fn read_peer_message_with_timeout<R: AsyncReadExt + Unpin>(
    reader: &mut R,
    deadline: std::time::Duration,
) -> Result<Vec<u8>> {
    let first = reader.read_u8().await?;
    tokio::time::timeout(deadline, async {
        let mut length = [first, 0, 0, 0];
        reader.read_exact(&mut length[1..]).await?;
        let len = u32::from_be_bytes(length) as usize;
        if len > MAX_PEER_MESSAGE_BYTES {
            bail!("peer message length {len} exceeds the {MAX_PEER_MESSAGE_BYTES}-byte cap");
        }
        let mut message = vec![0; len];
        reader.read_exact(&mut message).await?;
        Ok(message)
    })
    .await
    .map_err(|_| anyhow::anyhow!("peer message deadline exceeded"))?
}

/// Peer wire message types
#[repr(u8)]
#[allow(dead_code)]
enum MessageType {
    Choke = 0,
    Unchoke = 1,
    Interested = 2,
    NotInterested = 3,
    Have = 4,
    Bitfield = 5,
    Request = 6,
    Piece = 7,
    Cancel = 8,
    Port = 9,
}

/// BitTorrent Peer Wire Protocol client
pub struct TorrentPeerClient;

impl TorrentPeerClient {
    /// Connect to a BitTorrent peer with integrated LLM actions
    pub async fn connect_with_llm_actions(
        remote_addr: String,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        client_id: ClientId,
    ) -> Result<SocketAddr> {
        // Connect to peer
        let stream = TcpStream::connect(&remote_addr)
            .await
            .context(format!("Failed to connect to peer at {}", remote_addr))?;

        let local_addr = stream.local_addr()?;
        let remote_sock_addr = stream.peer_addr()?;

        info!(
            "BitTorrent Peer client {} connected to {} (local: {})",
            client_id, remote_sock_addr, local_addr
        );

        // Update client state
        app_state
            .update_client_status(client_id, ClientStatus::Connected)
            .await;
        let _ = status_tx.send(format!(
            "[CLIENT] BitTorrent Peer client {} connected",
            client_id
        ));
        let _ = status_tx.send("__UPDATE_UI__".to_string());

        // Split stream
        let (mut read_half, write_half) = tokio::io::split(stream);
        let write_half_arc = Arc::new(Mutex::new(write_half));

        // Command channel for the dashboard's [ send_* ] / [ disconnect ] rows. Registered
        // BEFORE the connected-event LLM call (which a manual `*` rule can park for minutes),
        // so an injected send works for the whole park. The read loop uses `read_exact`,
        // which is NOT cancellation-safe, so the channel is drained by its own task sharing
        // the write half rather than by a `select!` arm.
        let command_rx =
            crate::client::command_support::register_command_channel(&app_state, client_id).await;
        let cmd_state = app_state.clone();
        let cmd_tx = status_tx.clone();
        let cmd_write = write_half_arc.clone();
        let cmd_protocol = Arc::new(TorrentPeerClientProtocol::new());
        let cmd_task = tokio::spawn(async move {
            Self::command_loop(
                command_rx,
                cmd_protocol,
                cmd_write,
                client_id,
                cmd_state,
                cmd_tx,
            )
            .await;
        });
        app_state.register_client_task(client_id, cmd_task).await;

        // Spawn read loop for peer messages
        let app_state_clone = app_state.clone();
        let status_tx_clone = status_tx.clone();
        let write_half_clone = write_half_arc.clone();
        let llm_client_clone = llm_client.clone();
        // Registered with AppState so stop_client can abort this task —
        // dropping a JoinHandle only detaches it in Tokio.
        let task_registrar = app_state.clone();
        let task_handle = tokio::spawn(async move {
            // First, wait for handshake
            let mut handshake_buf = vec![0u8; 68]; // 1 + 19 + 8 + 20 + 20
            let handshake_result = tokio::time::timeout(
                crate::client::response_reader::RESPONSE_DEADLINE,
                read_half.read_exact(&mut handshake_buf),
            )
            .await
            .unwrap_or_else(|_| {
                Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "peer handshake deadline exceeded",
                ))
            });
            match handshake_result {
                Ok(_) => {
                    trace!("Peer client {} received handshake", client_id);

                    // Parse handshake (simplified)
                    let pstrlen = handshake_buf[0];
                    if pstrlen == 19 && &handshake_buf[1..20] == b"BitTorrent protocol" {
                        let reserved = &handshake_buf[20..28];
                        let info_hash = &handshake_buf[28..48];
                        let peer_id = &handshake_buf[48..68];

                        trace!(
                            "Handshake: info_hash={:?}, peer_id={:?}",
                            hex::encode(info_hash),
                            hex::encode(peer_id)
                        );

                        // Call LLM with handshake event
                        if let Some(instruction) =
                            app_state_clone.get_instruction_for_client(client_id).await
                        {
                            let protocol = Arc::new(crate::client::torrent_peer::actions::TorrentPeerClientProtocol::new());
                            let event = Event::new(
                                &PEER_HANDSHAKE_EVENT,
                                serde_json::json!({
                                    "info_hash": hex::encode(info_hash),
                                    "peer_id": hex::encode(peer_id),
                                    "reserved": hex::encode(reserved),
                                }),
                            );

                            let memory = app_state_clone
                                .get_memory_for_client(client_id)
                                .await
                                .unwrap_or_default();

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
                                        app_state_clone.set_memory_for_client(client_id, mem).await;
                                    }

                                    for action in actions {
                                        if let Err(e) = Self::execute_peer_action(
                                            client_id,
                                            action,
                                            &write_half_clone,
                                            protocol.as_ref(),
                                        )
                                        .await
                                        {
                                            error!("Failed to execute peer action: {}", e);
                                        }
                                    }
                                }
                                Err(e) => {
                                    error!("LLM error for Peer client {}: {}", client_id, e);
                                }
                            }
                        }
                    }

                    // Now read peer wire messages. Refuse an oversized announcement
                    // before allocating or waiting for any of its body bytes.
                    loop {
                        match read_peer_message(&mut read_half).await {
                            Ok(msg_buf) => {
                                if msg_buf.is_empty() {
                                    trace!("Peer client {} received keep-alive", client_id);
                                    continue;
                                }
                                let msg_type = msg_buf[0];
                                let payload = &msg_buf[1..];

                                trace!(
                                    "Peer client {} received message type {}, len {}",
                                    client_id,
                                    msg_type,
                                    payload.len()
                                );

                                // Call LLM with message event
                                if let Some(instruction) =
                                    app_state_clone.get_instruction_for_client(client_id).await
                                {
                                    let protocol = Arc::new(crate::client::torrent_peer::actions::TorrentPeerClientProtocol::new());
                                    let event = Event::new(
                                        &PEER_MESSAGE_EVENT,
                                        serde_json::json!({
                                            "message_type": msg_type,
                                            "payload_len": payload.len(),
                                            "payload_hex": hex::encode(payload),
                                        }),
                                    );

                                    let memory = app_state_clone
                                        .get_memory_for_client(client_id)
                                        .await
                                        .unwrap_or_default();

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
                                                app_state_clone
                                                    .set_memory_for_client(client_id, mem)
                                                    .await;
                                            }

                                            for action in actions {
                                                if let Err(e) = Self::execute_peer_action(
                                                    client_id,
                                                    action,
                                                    &write_half_clone,
                                                    protocol.as_ref(),
                                                )
                                                .await
                                                {
                                                    error!("Failed to execute peer action: {}", e);
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            error!("LLM error: {}", e);
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                error!("Peer client {} message read error: {}", client_id, e);
                                break;
                            }
                        }
                    }
                }
                Err(e) => {
                    error!("Peer client {} handshake read error: {}", client_id, e);
                }
            }

            // Every read-loop exit (handshake error, message/length read error, EOF, an
            // injected or LLM disconnect) lands here: drop the command handle so the rail
            // stops offering [ send ] on a dead client and a late send fails fast.
            app_state_clone.remove_client_handle(client_id).await;
            app_state_clone
                .update_client_status(client_id, ClientStatus::Disconnected)
                .await;
            let _ = status_tx_clone.send(format!(
                "[CLIENT] BitTorrent Peer client {} disconnected",
                client_id
            ));
            let _ = status_tx_clone.send("__UPDATE_UI__".to_string());
        });
        task_registrar
            .register_client_task(client_id, task_handle)
            .await;

        // Call LLM with connected event
        if let Some(instruction) = app_state.get_instruction_for_client(client_id).await {
            let protocol =
                Arc::new(crate::client::torrent_peer::actions::TorrentPeerClientProtocol::new());
            let event = Event::new(
                &PEER_HANDSHAKE_EVENT,
                serde_json::json!({
                    "status": "connected",
                    "remote_addr": remote_sock_addr.to_string(),
                }),
            );

            let memory = app_state
                .get_memory_for_client(client_id)
                .await
                .unwrap_or_default();
            let write_half_clone = write_half_arc.clone();

            // Registered with AppState so stop_client can abort this task —
            // dropping a JoinHandle only detaches it in Tokio.
            let task_registrar = app_state.clone();
            let task_handle = tokio::spawn(async move {
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
                        if let Some(mem) = memory_updates {
                            app_state.set_memory_for_client(client_id, mem).await;
                        }

                        for action in actions {
                            if let Err(e) = Self::execute_peer_action(
                                client_id,
                                action,
                                &write_half_clone,
                                protocol.as_ref(),
                            )
                            .await
                            {
                                error!("Failed to execute peer action: {}", e);
                            }
                        }
                    }
                    Err(e) => {
                        error!("LLM error: {}", e);
                    }
                }
            });
            task_registrar
                .register_client_task(client_id, task_handle)
                .await;
        }

        Ok(local_addr)
    }

    /// Execute a peer action, putting its bytes on the wire. This is the single encoder for
    /// the peer-wire Custom results, shared by the LLM path and the injected command loop.
    async fn execute_peer_action(
        client_id: ClientId,
        action: serde_json::Value,
        write_half: &Arc<Mutex<tokio::io::WriteHalf<TcpStream>>>,
        protocol: &dyn crate::llm::actions::client_trait::Client,
    ) -> Result<PeerApplied> {
        use crate::llm::actions::client_trait::ClientActionResult;

        match protocol.execute_action(action)? {
            ClientActionResult::Custom { name, data } if name == "peer_handshake" => {
                let info_hash_hex = data
                    .get("info_hash")
                    .and_then(|v| v.as_str())
                    .context("Missing info_hash")?;
                let peer_id_hex = data
                    .get("peer_id")
                    .and_then(|v| v.as_str())
                    .context("Missing peer_id")?;

                let info_hash = hex::decode(info_hash_hex)?;
                let peer_id = hex::decode(peer_id_hex)?;

                // Build handshake
                let mut handshake = Vec::new();
                handshake.push(19); // pstrlen
                handshake.extend_from_slice(b"BitTorrent protocol"); // pstr
                handshake.extend_from_slice(&[0u8; 8]); // reserved
                handshake.extend_from_slice(&info_hash); // info_hash
                handshake.extend_from_slice(&peer_id); // peer_id

                write_half.lock().await.write_all(&handshake).await?;
                trace!("Peer client {} sent handshake", client_id);
                Ok(PeerApplied::Sent(handshake.len()))
            }
            ClientActionResult::Custom { name, data } if name == "peer_message" => {
                let msg_type = data
                    .get("message_type")
                    .and_then(|v| v.as_u64())
                    .context("Missing message_type")?;
                let msg_type = u8::try_from(msg_type).context("peer message_type exceeds u8")?;
                let payload_hex = data.get("payload").and_then(|v| v.as_str()).unwrap_or("");
                let payload = if !payload_hex.is_empty() {
                    hex::decode(payload_hex)?
                } else {
                    vec![]
                };

                // Build message
                if payload.len() >= MAX_PEER_MESSAGE_BYTES {
                    anyhow::bail!("peer message exceeds byte cap");
                }
                let msg_len =
                    u32::try_from(1 + payload.len()).context("peer message length exceeds u32")?;
                let mut message = Vec::new();
                message.extend_from_slice(&msg_len.to_be_bytes());
                message.push(msg_type);
                message.extend_from_slice(&payload);

                write_half.lock().await.write_all(&message).await?;
                trace!("Peer client {} sent message type {}", client_id, msg_type);
                Ok(PeerApplied::Sent(message.len()))
            }
            ClientActionResult::Disconnect => {
                info!("Peer client {} disconnecting", client_id);
                Ok(PeerApplied::Disconnect)
            }
            _ => Ok(PeerApplied::Nothing),
        }
    }

    /// Drain injected commands until the channel closes (client removed) or an injected
    /// `disconnect` ends the session.
    ///
    /// The generic `command_support::handle_stream_client_command` cannot run this client's
    /// vocabulary because the wire verbs yield `ClientActionResult::Custom`, so each action
    /// goes through [`Self::execute_peer_action`] - the same encoder the LLM path uses - and
    /// the outcome is recorded and replied exactly the way the generic arm does it.
    async fn command_loop(
        mut command_rx: tokio::sync::mpsc::Receiver<crate::state::client_handles::ClientCommand>,
        protocol: Arc<TorrentPeerClientProtocol>,
        write_half: Arc<Mutex<tokio::io::WriteHalf<TcpStream>>>,
        client_id: ClientId,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
    ) {
        use crate::llm::actions::protocol_trait::Protocol;
        use crate::state::client_handles::ClientSendOutcome;
        use crate::state::AccessLogOwner;

        while let Some(command) = command_rx.recv().await {
            let action = command.action.clone();
            let outcome: anyhow::Result<ClientSendOutcome> = match Self::execute_peer_action(
                client_id,
                action.clone(),
                &write_half,
                protocol.as_ref(),
            )
            .await
            {
                Err(e) => Ok(ClientSendOutcome::Rejected {
                    error: e.to_string(),
                }),
                Ok(PeerApplied::Disconnect) => Ok(ClientSendOutcome::Disconnected),
                Ok(PeerApplied::Sent(0)) | Ok(PeerApplied::Nothing) => {
                    Ok(ClientSendOutcome::Executed {
                        detail: "executed (nothing to write)".to_string(),
                    })
                }
                Ok(PeerApplied::Sent(bytes_sent)) => Ok(ClientSendOutcome::Sent { bytes_sent }),
            };

            let outcome_json = match &outcome {
                Ok(o) => serde_json::to_value(o).unwrap_or(serde_json::Value::Null),
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
                    "Peer client {} injected action failed: {}",
                    client_id, e
                ));
            }
            let _ = status_tx.send("__UPDATE_UI__".to_string());
            crate::client::command_support::reply(command, outcome);

            if disconnect {
                // BitTorrent has no graceful-close message; half-close so the peer reads EOF
                // and the read loop runs its normal disconnect path (which drops the handle).
                let _ = write_half.lock().await.shutdown().await;
                break;
            }
        }
    }
}

/// Result of putting one executed peer action on the wire.
enum PeerApplied {
    /// `n` bytes written to the peer.
    Sent(usize),
    /// The action requested disconnect (nothing written; the caller half-closes).
    Disconnect,
    /// Nothing to do (an action variant this client does not turn into wire bytes).
    Nothing,
}
