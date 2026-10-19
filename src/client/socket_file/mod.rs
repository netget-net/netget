//! Socket File client implementation
pub mod actions;

pub use actions::SocketFileClientProtocol;

use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::{mpsc, Mutex};
use tracing::{error, info, trace};

use crate::client::llm_budget::call_llm_for_client;
use crate::client::socket_file::actions::SOCKET_FILE_CLIENT_DATA_RECEIVED_EVENT;
use crate::llm::ollama_client::OllamaClient;
use crate::llm::ClientLlmResult;
use crate::protocol::Event;
use crate::state::app_state::AppState;
use crate::state::{ClientId, ClientStatus};

/// How many reads may wait while the model answers an earlier one. Each is at most one
/// 8 KiB read, so at most 256 KiB waits; past it the reader stops reading and the socket's
/// buffer holds the server back.
///
/// There used to be an `Idle`/`Processing`/`Accumulating` machine with a `queued_data` buffer
/// here, but the read loop awaited every model call inline, so nothing could arrive mid-call.
const READ_QUEUE_CHUNKS: usize = crate::protocol::metadata::MAX_BATCH_EVENTS;

/// What the reader task hands the answering loop.
enum Inbound {
    Data(Vec<u8>),
    Closed,
    Failed(String),
}

/// Socket File client that connects to a Unix domain socket
pub struct SocketFileClient;

impl SocketFileClient {
    /// Connect to a Unix domain socket with integrated LLM actions
    pub async fn connect_with_llm_actions(
        socket_path: String,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        client_id: ClientId,
    ) -> Result<SocketAddr> {
        // Connect to Unix domain socket
        let stream = UnixStream::connect(&socket_path)
            .await
            .context(format!("Failed to connect to Unix socket {}", socket_path))?;

        // Unix sockets don't have traditional socket addresses, so we create a dummy one
        // The socket path is stored in the client's remote_addr field in app_state
        let dummy_addr = SocketAddr::from(([127, 0, 0, 1], 0));

        info!(
            "Socket File client {} connected to {}",
            client_id, socket_path
        );

        // Update client state
        app_state
            .update_client_status(client_id, ClientStatus::Connected)
            .await;
        let _ = status_tx.send(format!(
            "[CLIENT] Socket File client {} connected to {}",
            client_id, socket_path
        ));
        let _ = status_tx.send("__UPDATE_UI__".to_string());

        // Split stream
        let (mut read_half, write_half) = stream.into_split();
        let write_half_arc = Arc::new(Mutex::new(write_half));

        // Spawn read loop
        // Registered with AppState so stop_client can abort this task —
        // dropping a JoinHandle only detaches it in Tokio.
        let task_registrar = app_state.clone();
        // Command channel: lets the dashboard inject actions into this loop
        // via AppState::send_to_client (see client/command_support.rs).
        let mut command_rx =
            crate::client::command_support::register_command_channel(&app_state, client_id).await;

        // Raise the connected event.
        //
        // SOCKET_FILE_CLIENT_CONNECTED_EVENT was declared and nothing raised it, so the
        // model was only ever consulted once the peer had already said something. A client
        // meant to speak first -- which this protocol's own example action
        // (`send_socket_file_data`) implies -- could never do so.
        //
        // From a registered task, not inline: a dashboard-created client defaults to a
        // `*` -> manual rule and awaiting a parked answer would block creation.
        let conn_state = app_state.clone();
        let conn_llm = llm_client.clone();
        let conn_status = status_tx.clone();
        let conn_write = write_half_arc.clone();
        let conn_path = socket_path.clone();
        let conn_task = tokio::spawn(async move {
            let Some(instruction) = conn_state.get_instruction_for_client(client_id).await else {
                return;
            };
            let protocol = crate::client::socket_file::actions::SocketFileClientProtocol::new();
            let event = Event::new(
                &crate::client::socket_file::actions::SOCKET_FILE_CLIENT_CONNECTED_EVENT,
                serde_json::json!({ "socket_path": conn_path }),
            );
            match call_llm_for_client(
                &conn_llm,
                &conn_state,
                client_id.to_string(),
                &instruction,
                "",
                Some(&event),
                &protocol,
                &conn_status,
            )
            .await
            {
                Ok(result) => {
                    if let Some(mem) = result.memory_updates {
                        conn_state.set_memory_for_client(client_id, mem).await;
                    }
                    use crate::llm::actions::client_trait::{Client, ClientActionResult};
                    for action in result.actions {
                        if let Ok(ClientActionResult::SendData(bytes)) =
                            protocol.execute_action(action)
                        {
                            let mut guard = conn_write.lock().await;
                            if let Err(e) = guard.write_all(&bytes).await {
                                error!(
                                    "Socket File client {} connect-time write failed: {}",
                                    client_id, e
                                );
                            }
                        }
                    }
                }
                Err(e) => error!(
                    "Socket File client {} LLM error on connected event: {}",
                    client_id, e
                ),
            }
        });
        app_state.register_client_task(client_id, conn_task).await;

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

        let task_handle = tokio::spawn(async move {
            'session: loop {
                let inbound = tokio::select! {
                    inbound = inbound_rx.recv() => inbound.unwrap_or(Inbound::Closed),
                    Some(cmd) = command_rx.recv() => {
                        let disconnect = crate::client::command_support::handle_stream_client_command(
                            &crate::client::socket_file::actions::SocketFileClientProtocol,
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
                                "[CLIENT] SocketFile client {} disconnected (injected action)",
                                client_id
                            ));
                            let _ = status_tx.send("__UPDATE_UI__".to_string());
                            break;
                        }
                        continue;
                    }
                };

                let mut ended: Option<Inbound> = None;
                let mut pending = match inbound {
                    Inbound::Data(data) => data,
                    other => {
                        ended = Some(other);
                        Vec::new()
                    }
                };

                // With batching on, everything else already waiting — what the server sent
                // while the model answered the previous read — joins this payload, as the
                // socket_file server and the tcp client do: a stream socket's read boundaries
                // mean nothing. An end of stream found while sweeping is handled after.
                if ended.is_none()
                    && app_state
                        .client_conversation_settings(client_id)
                        .await
                        .is_some_and(|(_, batching)| batching)
                {
                    while let Ok(more) = inbound_rx.try_recv() {
                        match more {
                            Inbound::Data(more) => pending.extend_from_slice(&more),
                            other => {
                                ended = Some(other);
                                break;
                            }
                        }
                    }
                }

                if !pending.is_empty() {
                    trace!(
                        "Socket File client {} received {} bytes",
                        client_id,
                        pending.len()
                    );
                    if let Some(instruction) = app_state.get_instruction_for_client(client_id).await
                    {
                        // The memory lives in AppState, where the connected-event task and
                        // `set_memory` write it.
                        let memory = app_state
                            .get_memory_for_client(client_id)
                            .await
                            .unwrap_or_default();

                        let protocol =
                            crate::client::socket_file::actions::SocketFileClientProtocol::new();
                        let (data_str, encoding) = if pending
                            .iter()
                            .all(|&b| b.is_ascii_graphic() || b.is_ascii_whitespace())
                        {
                            (String::from_utf8_lossy(&pending).to_string(), "utf8")
                        } else {
                            (hex::encode(&pending), "hex")
                        };
                        let event = Event::new(
                            &SOCKET_FILE_CLIENT_DATA_RECEIVED_EVENT,
                            serde_json::json!({
                                "data": data_str,
                                "encoding": encoding,
                                "data_length": pending.len(),
                            }),
                        );

                        match call_llm_for_client(
                            &llm_client,
                            &app_state,
                            client_id.to_string(),
                            &instruction,
                            &memory,
                            Some(&event),
                            &protocol,
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

                                use crate::llm::actions::client_trait::{
                                    Client, ClientActionResult,
                                };
                                for action in actions {
                                    match protocol.execute_action(action) {
                                        Ok(ClientActionResult::SendData(bytes)) => {
                                            let mut guard = write_half_arc.lock().await;
                                            match guard.write_all(&bytes).await {
                                                Ok(()) => trace!(
                                                    "Socket File client {} sent {} bytes",
                                                    client_id,
                                                    bytes.len()
                                                ),
                                                Err(e) => error!(
                                                    "Socket File client {} write failed: {}",
                                                    client_id, e
                                                ),
                                            }
                                        }
                                        Ok(ClientActionResult::Disconnect) => {
                                            // Actually hang up, not just stop reading actions.
                                            info!("Socket File client {} disconnecting", client_id);
                                            let _ = write_half_arc.lock().await.shutdown().await;
                                            app_state
                                                .update_client_status(
                                                    client_id,
                                                    ClientStatus::Disconnected,
                                                )
                                                .await;
                                            let _ = status_tx.send(format!(
                                                "[CLIENT] Socket File client {} disconnected (model)",
                                                client_id
                                            ));
                                            let _ = status_tx.send("__UPDATE_UI__".to_string());
                                            break 'session;
                                        }
                                        Ok(_) => {}
                                        Err(e) => error!(
                                            "Socket File client {} rejected an action: {}",
                                            client_id, e
                                        ),
                                    }
                                }
                            }
                            Err(e) => {
                                error!("LLM error for Socket File client {}: {}", client_id, e);
                            }
                        }
                    }
                }

                match ended {
                    Some(Inbound::Closed) => {
                        info!("Socket File client {} disconnected", client_id);
                        app_state
                            .update_client_status(client_id, ClientStatus::Disconnected)
                            .await;
                        let _ = status_tx.send(format!(
                            "[CLIENT] Socket File client {} disconnected",
                            client_id
                        ));
                        let _ = status_tx.send("__UPDATE_UI__".to_string());
                        break;
                    }
                    Some(Inbound::Failed(e)) => {
                        error!("Socket File client {} read error: {}", client_id, e);
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
        task_registrar
            .register_client_task(client_id, task_handle)
            .await;

        Ok(dummy_addr)
    }
}
