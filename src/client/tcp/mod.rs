//! TCP client implementation
pub mod actions;

pub use actions::TcpClientProtocol;

use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex};
use tracing::{error, info, trace};

use crate::client::llm_budget::call_llm_for_client;
use crate::client::tcp::actions::{TCP_CLIENT_CONNECTED_EVENT, TCP_CLIENT_DATA_RECEIVED_EVENT};
use crate::llm::ollama_client::OllamaClient;
use crate::llm::ClientLlmResult;
use crate::logging::patterns;
use crate::protocol::Event;
use crate::state::app_state::AppState;
use crate::state::{ClientId, ClientStatus};

/// Per-client data for LLM handling
struct ClientData {
    memory: String,
}

/// How many reads may wait while the model answers an earlier one. Each is at most one
/// 8 KiB read, so at most 256 KiB waits; past it the reader stops reading, the socket's
/// receive window fills, and the server is held back by TCP itself.
const READ_QUEUE_CHUNKS: usize = crate::protocol::metadata::MAX_BATCH_EVENTS;

/// What the reader task hands the answering loop.
enum Inbound {
    Data(Vec<u8>),
    Closed,
    Failed(String),
}

/// TCP client that connects to a remote TCP server
pub struct TcpClient;

impl TcpClient {
    /// Connect to a TCP server with integrated LLM actions
    pub async fn connect_with_llm_actions(
        remote_addr: String,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        client_id: ClientId,
    ) -> Result<SocketAddr> {
        // Resolve and connect
        let stream = TcpStream::connect(&remote_addr)
            .await
            .context(format!("Failed to connect to {}", remote_addr))?;

        let local_addr = stream.local_addr()?;
        let remote_sock_addr = stream.peer_addr()?;

        info!(
            "TCP client {} connected to {} (local: {})",
            client_id, remote_sock_addr, local_addr
        );

        // Update client state
        app_state
            .update_client_status(client_id, ClientStatus::Connected)
            .await;
        let _ = status_tx.send(format!("[CLIENT] TCP client {} connected", client_id));
        let _ = status_tx.send("__UPDATE_UI__".to_string());

        // Split stream
        let (mut read_half, write_half) = tokio::io::split(stream);
        let write_half_arc = Arc::new(Mutex::new(write_half));
        let write_half_for_connected = write_half_arc.clone();

        // Initialize client data
        let client_data = Arc::new(Mutex::new(ClientData {
            memory: String::new(),
        }));

        // Command channel: lets the dashboard (and any programmatic caller)
        // inject actions into this loop via AppState::send_to_client.
        //
        // Registered BEFORE the connected event is handled: a `manual` routing
        // rule can park that event at the dashboard for minutes, and until
        // registration the UI reports "no command channel" — reading as a
        // protocol limitation when it is only a queue. Registered here, a send
        // during the park waits in the channel instead of being refused.
        let mut command_rx =
            crate::client::command_support::register_command_channel(&app_state, client_id).await;

        // Call LLM with tcp_connected event
        if let Some(instruction) = app_state.get_instruction_for_client(client_id).await {
            let event = Event::new(
                &TCP_CLIENT_CONNECTED_EVENT,
                serde_json::json!({
                    "remote_addr": remote_sock_addr.to_string(),
                }),
            );

            match call_llm_for_client(
                &llm_client,
                &app_state,
                client_id.to_string(),
                &instruction,
                &client_data.lock().await.memory,
                Some(&event),
                &crate::client::tcp::actions::TcpClientProtocol,
                &status_tx,
            )
            .await
            {
                Ok(result) => {
                    // Update memory if provided
                    if let Some(new_memory) = result.memory_updates {
                        client_data.lock().await.memory = new_memory;
                    }

                    // Execute actions from LLM response using the proper execute_action method
                    use crate::llm::actions::client_trait::Client;
                    let protocol = crate::client::tcp::actions::TcpClientProtocol::new();
                    for action in result.actions {
                        match protocol.execute_action(action) {
                            Ok(
                                crate::llm::actions::client_trait::ClientActionResult::SendData(
                                    bytes,
                                ),
                            ) => {
                                let mut write_guard = write_half_for_connected.lock().await;
                                if let Err(e) = write_guard.write_all(&bytes).await {
                                    error!("Failed to send data after connect: {}", e);
                                } else if let Err(e) = write_guard.flush().await {
                                    error!("Failed to flush after connect: {}", e);
                                } else {
                                    info!("Sent {} {}", bytes.len(), patterns::TCP_CLIENT_SENT);
                                }
                            }
                            Ok(
                                crate::llm::actions::client_trait::ClientActionResult::Disconnect,
                            ) => {
                                info!("LLM requested disconnect after connect");
                                return Ok(local_addr);
                            }
                            Ok(
                                crate::llm::actions::client_trait::ClientActionResult::WaitForMore,
                            ) => {
                                // Just wait for data
                            }
                            Ok(_) => {
                                // Other action results
                            }
                            Err(e) => {
                                error!("Failed to execute action after connect: {}", e);
                            }
                        }
                    }
                }
                Err(e) => {
                    error!("LLM error on tcp_connected event: {}", e);
                }
            }
        }

        // The reader runs on its own task so that what the server sends while the model is
        // answering keeps its read boundaries in a bounded queue instead of merging in the
        // kernel buffer: with batching on everything waiting is answered together, with it
        // off one read per call. Registered, so stop_client aborts it with the loop.
        let (inbound_tx, mut inbound_rx) = mpsc::channel::<Inbound>(READ_QUEUE_CHUNKS);
        let reader = app_state
            .spawn_client_task(client_id, async move {
                let mut buffer = vec![0u8; 8192];
                loop {
                    let message = match read_half.read(&mut buffer).await {
                        Ok(0) => Inbound::Closed,
                        Ok(n) => Inbound::Data(buffer[..n].to_vec()),
                        Err(e) => Inbound::Failed(e.to_string()),
                    };
                    let last = !matches!(message, Inbound::Data(_));
                    if inbound_tx.send(message).await.is_err() || last {
                        break;
                    }
                }
            })
            .await;

        // Spawn the answering loop. The handle is registered with AppState so that
        // stop_client / remove_client can abort it — dropping a JoinHandle only
        // detaches the task, leaving the socket open and the LLM being called.
        let task_registrar = app_state.clone();
        let handle = tokio::spawn(async move {
            info!("TCP client {} read loop started", client_id);

            'read_loop: loop {
                let inbound = tokio::select! {
                    inbound = inbound_rx.recv() => inbound.unwrap_or(Inbound::Closed),
                    Some(cmd) = command_rx.recv() => {
                        let disconnect = crate::client::command_support::handle_stream_client_command(
                            &crate::client::tcp::actions::TcpClientProtocol,
                            &write_half_arc,
                            cmd,
                            client_id,
                            &app_state,
                            &status_tx,
                        )
                        .await;
                        if disconnect {
                            app_state
                                .update_client_status(client_id, ClientStatus::Disconnected)
                                .await;
                            let _ = status_tx.send(format!(
                                "[CLIENT] TCP client {} disconnected (injected action)",
                                client_id
                            ));
                            let _ = status_tx.send("__UPDATE_UI__".to_string());
                            break;
                        }
                        continue;
                    }
                };
                let mut data = match inbound {
                    Inbound::Data(data) => data,
                    Inbound::Closed => {
                        info!(
                            "TCP client {} {}",
                            client_id,
                            patterns::TCP_CLIENT_DISCONNECTED
                        );
                        app_state
                            .update_client_status(client_id, ClientStatus::Disconnected)
                            .await;
                        let _ = status_tx
                            .send(format!("[CLIENT] TCP client {} disconnected", client_id));
                        let _ = status_tx.send("__UPDATE_UI__".to_string());
                        break;
                    }
                    Inbound::Failed(e) => {
                        error!("TCP client {} read error: {}", client_id, e);
                        app_state
                            .update_client_status(client_id, ClientStatus::Error(e))
                            .await;
                        let _ = status_tx.send("__UPDATE_UI__".to_string());
                        break;
                    }
                };

                // With batching on, everything else already waiting — what the server sent
                // while the model answered the previous read — joins this payload, as the
                // tcp server does. An end of stream found while sweeping is handled after.
                let mut ended: Option<Inbound> = None;
                let batching = app_state
                    .client_conversation_settings(client_id)
                    .await
                    .is_some_and(|(_, batching)| batching);
                if batching {
                    while let Ok(more) = inbound_rx.try_recv() {
                        match more {
                            Inbound::Data(more) => data.extend_from_slice(&more),
                            other => {
                                ended = Some(other);
                                break;
                            }
                        }
                    }
                }

                info!(
                    "TCP client {} received {} {}",
                    client_id,
                    data.len(),
                    patterns::TCP_CLIENT_RECEIVED
                );
                trace!("TCP client {} received {} bytes", client_id, data.len());

                if let Some(instruction) = app_state.get_instruction_for_client(client_id).await {
                    let protocol = Arc::new(crate::client::tcp::actions::TcpClientProtocol::new());
                    // Text arrives as text, anything else as hex, and `encoding` says which,
                    // so the model can read a text protocol and echo either kind back with a
                    // matching `encoding` on send_tcp_data — the TCP server's contract.
                    let (data_str, data_encoding) = if data
                        .iter()
                        .all(|&b| b.is_ascii_graphic() || b.is_ascii_whitespace())
                    {
                        (String::from_utf8_lossy(&data).to_string(), "utf8")
                    } else {
                        (hex::encode(&data), "hex")
                    };
                    let event = Event::new(
                        &TCP_CLIENT_DATA_RECEIVED_EVENT,
                        serde_json::json!({
                            "data": data_str,
                            "encoding": data_encoding,
                            "data_length": data.len(),
                        }),
                    );

                    let memory = client_data.lock().await.memory.clone();
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
                                client_data.lock().await.memory = mem;
                            }
                            for action in actions {
                                use crate::llm::actions::client_trait::Client;
                                match protocol.as_ref().execute_action(action) {
                                    Ok(crate::llm::actions::client_trait::ClientActionResult::SendData(bytes)) => {
                                        let mut write_guard = write_half_arc.lock().await;
                                        if write_guard.write_all(&bytes).await.is_ok()
                                            && write_guard.flush().await.is_ok()
                                        {
                                            trace!("TCP client {} sent {} bytes", client_id, bytes.len());
                                        }
                                    }
                                    Ok(crate::llm::actions::client_trait::ClientActionResult::Disconnect) => {
                                        info!("TCP client {} disconnecting", client_id);
                                        app_state
                                            .update_client_status(client_id, ClientStatus::Disconnected)
                                            .await;
                                        let _ = status_tx.send(format!(
                                            "[CLIENT] TCP client {} disconnected",
                                            client_id
                                        ));
                                        let _ = status_tx.send("__UPDATE_UI__".to_string());
                                        break 'read_loop;
                                    }
                                    _ => {}
                                }
                            }
                        }
                        Err(e) => {
                            error!("LLM error for TCP client {}: {}", client_id, e);
                        }
                    }
                }

                match ended {
                    Some(Inbound::Closed) => {
                        info!(
                            "TCP client {} {}",
                            client_id,
                            patterns::TCP_CLIENT_DISCONNECTED
                        );
                        app_state
                            .update_client_status(client_id, ClientStatus::Disconnected)
                            .await;
                        let _ = status_tx
                            .send(format!("[CLIENT] TCP client {} disconnected", client_id));
                        let _ = status_tx.send("__UPDATE_UI__".to_string());
                        break;
                    }
                    Some(Inbound::Failed(e)) => {
                        error!("TCP client {} read error: {}", client_id, e);
                        app_state
                            .update_client_status(client_id, ClientStatus::Error(e))
                            .await;
                        let _ = status_tx.send("__UPDATE_UI__".to_string());
                        break;
                    }
                    _ => {}
                }
            }
            reader.abort();
            // The loop owns the only receiver; dropping the registered handle
            // makes later send_to_client calls fail fast instead of timing out.
            app_state.remove_client_handle(client_id).await;
        });
        task_registrar.register_client_task(client_id, handle).await;

        Ok(local_addr)
    }
}
