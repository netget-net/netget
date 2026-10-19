//! HTTP proxy client implementation
pub mod actions;

pub use actions::HttpProxyClientProtocol;

use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, error, info, trace};

use crate::client::http_proxy::actions::{
    HTTP_PROXY_CLIENT_CONNECTED_EVENT, HTTP_PROXY_RESPONSE_RECEIVED_EVENT,
    HTTP_PROXY_TUNNEL_ESTABLISHED_EVENT,
};
use crate::client::llm_budget::call_llm_for_client;
use crate::llm::actions::client_trait::{Client, ClientActionResult};
use crate::llm::ollama_client::OllamaClient;
use crate::llm::ClientLlmResult;
use crate::protocol::Event;
use crate::state::app_state::AppState;
use crate::state::client_handles::{ClientCommand, ClientSendOutcome};
use crate::state::{AccessLogOwner, ClientId, ClientStatus};

/// Per-client data for LLM handling
struct ClientData {
    memory: String,
    tunnel_established: bool,
}

/// HTTP proxy client that connects to a proxy server
pub struct HttpProxyClient;

impl HttpProxyClient {
    /// Connect to an HTTP proxy server with integrated LLM actions
    pub async fn connect_with_llm_actions(
        remote_addr: String,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        client_id: ClientId,
        startup_params: Option<crate::protocol::StartupParams>,
    ) -> Result<SocketAddr> {
        // `proxy_auth` and `default_target` were both declared and neither was read: a
        // proxy that requires authentication answered 407 to every CONNECT with nothing in
        // the parameter list to explain it, and `default_target` named a tunnel nothing
        // ever opened.
        //
        // `proxy_auth` is `username:password`, so it is resolved once here into the
        // `Proxy-Authorization: Basic ...` value every CONNECT now carries.
        let (proxy_auth, default_target) = match &startup_params {
            Some(params) => (
                params.get_optional_string("proxy_auth")?,
                params.get_optional_string("default_target")?,
            ),
            None => (None, None),
        };
        let proxy_authorization = proxy_auth.map(|credentials| {
            use base64::Engine;
            let encoded = base64::engine::general_purpose::STANDARD.encode(credentials.as_bytes());
            format!("Basic {encoded}")
        });

        // Connect to the proxy server
        let stream = TcpStream::connect(&remote_addr).await.context(format!(
            "Failed to connect to HTTP proxy at {}",
            remote_addr
        ))?;

        let local_addr = stream.local_addr()?;
        let remote_sock_addr = stream.peer_addr()?;

        info!(
            "HTTP proxy client {} connected to proxy {} (local: {})",
            client_id, remote_sock_addr, local_addr
        );

        // Stored so both the tunnel task and an injected `establish_tunnel` read the same
        // configuration rather than each carrying its own copy.
        app_state
            .with_client_mut(client_id, |client| {
                if let Some(value) = &proxy_authorization {
                    client.set_protocol_field(
                        "proxy_authorization".to_string(),
                        serde_json::json!(value),
                    );
                }
                if let Some(target) = &default_target {
                    client.set_protocol_field(
                        "default_target".to_string(),
                        serde_json::json!(target),
                    );
                }
            })
            .await;

        // Update client state
        app_state
            .update_client_status(client_id, ClientStatus::Connected)
            .await;
        let _ = status_tx.send(format!(
            "[CLIENT] HTTP proxy client {} connected to {}",
            client_id, remote_sock_addr
        ));
        let _ = status_tx.send("__UPDATE_UI__".to_string());

        // Split stream. Done before the connected-event LLM call so the write half can be
        // shared with the command task below while that call is (possibly) parked.
        let (read_half, write_half) = tokio::io::split(stream);
        let write_half_arc = Arc::new(Mutex::new(write_half));

        // Command channel for the dashboard's [ send_http_request ] / [ send_data ] /
        // [ establish_tunnel ] / [ disconnect ] rows. Registered BEFORE the connected call: a
        // manual handler can park that call for minutes, and an injected send must work for
        // the whole park. The read loop mixes `read_line` (CONNECT headers, not
        // cancellation-safe) and `read` (tunnel bytes), so the channel is drained by its own
        // task sharing the write half rather than by a `select!` arm.
        let mut command_rx =
            crate::client::command_support::register_command_channel(&app_state, client_id).await;
        let cmd_state = app_state.clone();
        let cmd_tx = status_tx.clone();
        let cmd_write = write_half_arc.clone();
        let cmd_task = tokio::spawn(async move {
            while let Some(cmd) = command_rx.recv().await {
                let disconnect =
                    handle_injected_command(&cmd_write, cmd, client_id, &cmd_state, &cmd_tx).await;
                if disconnect {
                    // Half-close: the proxy reads EOF and closes; the read loop then sees 0
                    // and runs its normal disconnect path (which drops the handle).
                    let _ = cmd_write.lock().await.shutdown().await;
                    break;
                }
            }
        });
        app_state.register_client_task(client_id, cmd_task).await;

        // Call LLM with connected event
        if let Some(instruction) = app_state.get_instruction_for_client(client_id).await {
            let protocol =
                Arc::new(crate::client::http_proxy::actions::HttpProxyClientProtocol::new());
            let event = Event::new(
                &HTTP_PROXY_CLIENT_CONNECTED_EVENT,
                serde_json::json!({
                    "proxy_addr": remote_sock_addr.to_string(),
                }),
            );

            match call_llm_for_client(
                &llm_client,
                &app_state,
                client_id.to_string(),
                &instruction,
                "",
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
                    // Store memory
                    if let Some(mem) = memory_updates {
                        app_state.set_memory_for_client(client_id, mem).await;
                    }

                    // Execute initial actions
                    for action in actions {
                        if let Ok(result) = protocol.as_ref().execute_action(action) {
                            match result {
                                ClientActionResult::Custom { name, data }
                                    if name == "establish_tunnel" =>
                                {
                                    // Handle tunnel establishment. A target the model did
                                    // not fully specify falls back to `default_target`,
                                    // which is what that parameter is for.
                                    let target = match (
                                        data.get("target_host").and_then(|v| v.as_str()),
                                        data.get("target_port").and_then(|v| v.as_u64()),
                                    ) {
                                        (Some(host), Some(port)) => Some(format!("{host}:{port}")),
                                        _ => default_target.clone(),
                                    };
                                    if let Some(target) = target {
                                        info!(
                                            "HTTP proxy client {} establishing tunnel to {}",
                                            client_id, target
                                        );
                                        // We'll establish the tunnel in the spawn task below
                                        app_state
                                            .with_client_mut(client_id, |client| {
                                                client.set_protocol_field(
                                                    "tunnel_target".to_string(),
                                                    serde_json::json!(target),
                                                );
                                            })
                                            .await;
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                }
                Err(e) => {
                    error!("LLM error for HTTP proxy client {}: {}", client_id, e);
                }
            }
        }

        // `default_target` means "open this tunnel", not "open it only if the model also
        // asks". If nothing selected a target above, it is the target.
        if let Some(target) = &default_target {
            app_state
                .with_client_mut(client_id, |client| {
                    if client.get_protocol_field("tunnel_target").is_none() {
                        client.set_protocol_field(
                            "tunnel_target".to_string(),
                            serde_json::json!(target),
                        );
                    }
                })
                .await;
        }

        // Initialize client data
        let client_data = Arc::new(Mutex::new(ClientData {
            memory: String::new(),
            tunnel_established: false,
        }));

        // Clone for spawn
        let app_state_clone = app_state.clone();
        let write_half_clone = write_half_arc.clone();
        let client_data_clone = client_data.clone();

        // Spawn task to handle tunnel establishment if needed
        // Registered with AppState so stop_client can abort this task —
        // dropping a JoinHandle only detaches it in Tokio.
        let task_registrar = app_state.clone();
        let task_handle = tokio::spawn(async move {
            // Check if we have a tunnel target to establish
            if let Some(tunnel_target) = app_state_clone
                .with_client_mut(client_id, |client| {
                    client
                        .get_protocol_field("tunnel_target")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string())
                })
                .await
                .flatten()
            {
                let parts: Vec<&str> = tunnel_target.split(':').collect();
                if parts.len() == 2 {
                    let target_host = parts[0];
                    let target_port = parts[1];

                    // Send CONNECT request
                    let connect_request =
                        connect_request(target_host, target_port, proxy_authorization.as_deref());

                    debug!(
                        "HTTP proxy client {} sending CONNECT request: {}",
                        client_id,
                        connect_request.trim()
                    );

                    if let Err(e) = write_half_clone
                        .lock()
                        .await
                        .write_all(connect_request.as_bytes())
                        .await
                    {
                        error!(
                            "HTTP proxy client {} failed to send CONNECT: {}",
                            client_id, e
                        );
                    }
                }
            }
        });
        task_registrar
            .register_client_task(client_id, task_handle)
            .await;

        // Spawn read loop
        let app_state_clone = app_state.clone();
        let status_tx_clone = status_tx.clone();
        let write_half_clone = write_half_arc.clone();

        // Registered with AppState so stop_client can abort this task —
        // dropping a JoinHandle only detaches it in Tokio.
        let task_registrar = app_state.clone();
        let task_handle = tokio::spawn(async move {
            let handle_state = app_state_clone.clone();
            // The loop body is an inner block so its `return`s all land on the handle removal
            // below: once the socket is dead the dashboard must stop offering [ send ].
            async move {
            let mut reader = BufReader::new(crate::client::response_reader::FrameReader::new(read_half));

            // First, check if we need to read CONNECT response
            if let Some(target) = app_state_clone
                .with_client_mut(client_id, |client| {
                    client
                        .get_protocol_field("tunnel_target")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string())
                })
                .await
                .flatten()
            {
                reader.get_mut().start_frame(crate::client::response_reader::RESPONSE_DEADLINE);
                // Read CONNECT response
                let mut status_line = String::new();
                match crate::client::response_reader::read_response_line(&mut reader, &mut status_line).await {
                    Ok(0) => {
                        error!(
                            "HTTP proxy client {} disconnected during CONNECT",
                            client_id
                        );
                        app_state_clone
                            .update_client_status(
                                client_id,
                                ClientStatus::Error("Proxy disconnected".to_string()),
                            )
                            .await;
                        return;
                    }
                    Ok(_) => {
                        debug!(
                            "HTTP proxy client {} received status: {}",
                            client_id,
                            status_line.trim()
                        );

                        // Parse status code
                        let parts: Vec<&str> = status_line.split_whitespace().collect();
                        let status_code = if parts.len() >= 2 {
                            parts[1].parse::<u16>().unwrap_or(0)
                        } else {
                            0
                        };

                        // Bound the aggregate head too: many short headers are otherwise
                        // just as unbounded as one line with no terminator.
                        let mut header_bytes = status_line.len();
                        loop {
                            let mut header_line = String::new();
                            match crate::client::response_reader::read_response_line(&mut reader, &mut header_line).await {
                                Ok(0) => {
                                    app_state_clone.update_client_status(client_id, ClientStatus::Error("Proxy closed before CONNECT headers completed".to_string())).await;
                                    return;
                                },
                                Ok(_) => {
                                    header_bytes += header_line.len();
                                    if header_bytes > crate::client::response_reader::MAX_RESPONSE_LINE_BYTES {
                                        app_state_clone.update_client_status(client_id, ClientStatus::Error("Proxy CONNECT response headers exceed the byte cap".to_string())).await;
                                        return;
                                    }
                                    if header_line.trim().is_empty() {
                                        break;
                                    }
                                }
                                Err(e) => {
                                    error!(
                                        "HTTP proxy client {} error reading headers: {}",
                                        client_id, e
                                    );
                                    app_state_clone.update_client_status(client_id, ClientStatus::Error(e.to_string())).await;
                                    return;
                                }
                            }
                        }

                        if status_code == 200 {
                            info!(
                                "HTTP proxy client {} tunnel established successfully",
                                client_id
                            );
                            client_data_clone.lock().await.tunnel_established = true;

                            // Call LLM with tunnel established event
                            if let Some(instruction) =
                                app_state_clone.get_instruction_for_client(client_id).await
                            {
                                let protocol = Arc::new(crate::client::http_proxy::actions::HttpProxyClientProtocol::new());

                                let parts: Vec<&str> = target.split(':').collect();
                                let (target_host, target_port) = if parts.len() == 2 {
                                    (parts[0].to_string(), parts[1].parse::<u16>().unwrap_or(0))
                                } else {
                                    (target.clone(), 0)
                                };

                                let event = Event::new(
                                    &HTTP_PROXY_TUNNEL_ESTABLISHED_EVENT,
                                    serde_json::json!({
                                        "target_host": target_host,
                                        "target_port": target_port,
                                        "status_code": status_code,
                                    }),
                                );

                                // Copy the memory out under its own guard first. Passing
                                // `&client_data_clone.lock().await.memory` into the call keeps
                                // that guard alive for the whole `match` -- a temporary in a
                                // match scrutinee lives until the match ends -- and the `Ok`
                                // arm locks the same mutex again to store the model's memory
                                // update. `tokio::sync::Mutex` is not reentrant, so the tunnel
                                // task deadlocks the moment the model returns memory.
                                let memory =
                                    { client_data_clone.lock().await.memory.clone() };
                                match call_llm_for_client(
                                    &llm_client,
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
                                        // Update memory
                                        if let Some(mem) = memory_updates {
                                            client_data_clone.lock().await.memory = mem;
                                        }

                                        // Execute actions
                                        for action in actions {
                                            if let Ok(result) =
                                                protocol.as_ref().execute_action(action)
                                            {
                                                match result {
                                                    ClientActionResult::SendData(bytes) => {
                                                        if write_half_clone
                                                            .lock()
                                                            .await
                                                            .write_all(&bytes)
                                                            .await
                                                            .is_ok()
                                                        {
                                                            trace!("HTTP proxy client {} sent {} bytes via tunnel", client_id, bytes.len());
                                                        }
                                                    }
                                                    ClientActionResult::Disconnect => {
                                                        info!(
                                                            "HTTP proxy client {} disconnecting",
                                                            client_id
                                                        );
                                                        return;
                                                    }
                                                    _ => {}
                                                }
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        error!(
                                            "LLM error for HTTP proxy client {}: {}",
                                            client_id, e
                                        );
                                    }
                                }
                            }
                        } else {
                            error!(
                                "HTTP proxy client {} tunnel failed with status {}",
                                client_id, status_code
                            );
                            app_state_clone
                                .update_client_status(
                                    client_id,
                                    ClientStatus::Error(format!("Tunnel failed: {}", status_code)),
                                )
                                .await;
                            return;
                        }
                    }
                    Err(e) => {
                        error!(
                            "HTTP proxy client {} error reading CONNECT response: {}",
                            client_id, e
                        );
                        app_state_clone
                            .update_client_status(client_id, ClientStatus::Error(e.to_string()))
                            .await;
                        return;
                    }
                }
            }

            // Now read data through the tunnel, on a registered task of its own: what the far
            // end sends while the model is answering keeps its read boundaries in a bounded
            // queue instead of merging in the kernel buffer, so batching on answers everything
            // waiting as one payload and batching off one read per call. The reader takes the
            // BufReader itself, so bytes it already buffered behind the CONNECT headers are
            // delivered first.
            reader.get_mut().end_frame();
            let mut inbound = crate::client::inbound_queue::InboundQueue::spawn(
                &app_state_clone,
                client_id,
                reader,
            )
            .await;
            use crate::client::inbound_queue::Inbound;
            loop {
                let (mut data, mut ended) = match inbound.recv().await {
                    Inbound::Data(data) => (data, None),
                    other => (Vec::new(), Some(other)),
                };
                if !data.is_empty() {
                    let batching = app_state_clone
                        .client_conversation_settings(client_id)
                        .await
                        .is_some_and(|(_, batching)| batching);
                    if batching {
                        ended = inbound.drain_into(&mut data);
                    }
                    trace!(
                        "HTTP proxy client {} received {} bytes via tunnel",
                        client_id,
                        data.len()
                    );
                    if answer_tunnel_data(
                        &llm_client,
                        &app_state_clone,
                        &status_tx_clone,
                        client_id,
                        &client_data_clone,
                        &write_half_clone,
                        &data,
                    )
                    .await
                    {
                        info!("HTTP proxy client {} disconnecting", client_id);
                        app_state_clone
                            .update_client_status(client_id, ClientStatus::Disconnected)
                            .await;
                        let _ = status_tx_clone.send(format!(
                            "[CLIENT] HTTP proxy client {} disconnected",
                            client_id
                        ));
                        let _ = status_tx_clone.send("__UPDATE_UI__".to_string());
                        break;
                    }
                }
                match ended {
                    Some(Inbound::Closed) => {
                        info!("HTTP proxy client {} disconnected", client_id);
                        app_state_clone
                            .update_client_status(client_id, ClientStatus::Disconnected)
                            .await;
                        let _ = status_tx_clone.send(format!(
                            "[CLIENT] HTTP proxy client {} disconnected",
                            client_id
                        ));
                        let _ = status_tx_clone.send("__UPDATE_UI__".to_string());
                        break;
                    }
                    Some(Inbound::Failed(e)) => {
                        error!("HTTP proxy client {} read error: {}", client_id, e);
                        app_state_clone
                            .update_client_status(client_id, ClientStatus::Error(e))
                            .await;
                        let _ = status_tx_clone.send("__UPDATE_UI__".to_string());
                        break;
                    }
                    _ => {}
                }
            }
            }
            .await;
            handle_state.remove_client_handle(client_id).await;
        });
        task_registrar
            .register_client_task(client_id, task_handle)
            .await;

        Ok(local_addr)
    }
}

/// Ask the model about one payload from the tunnel and carry out its answer. Returns `true`
/// when it asked to disconnect, which ends the tunnel rather than just this answer.
async fn answer_tunnel_data<W>(
    llm_client: &OllamaClient,
    app_state: &Arc<AppState>,
    status_tx: &mpsc::UnboundedSender<String>,
    client_id: ClientId,
    client_data: &Arc<Mutex<ClientData>>,
    write_half: &Arc<Mutex<W>>,
    data: &[u8],
) -> bool
where
    W: tokio::io::AsyncWrite + Unpin,
{
    let Some(instruction) = app_state.get_instruction_for_client(client_id).await else {
        return false;
    };
    let protocol = HttpProxyClientProtocol::new();
    let event = Event::new(
        &HTTP_PROXY_RESPONSE_RECEIVED_EVENT,
        serde_json::json!({
            "data_hex": hex::encode(data),
            "data_length": data.len(),
        }),
    );
    // Copied out under its own guard: the `Ok` arm locks the same mutex again.
    let memory = { client_data.lock().await.memory.clone() };
    match call_llm_for_client(
        llm_client,
        app_state,
        client_id.to_string(),
        &instruction,
        &memory,
        Some(&event),
        &protocol,
        status_tx,
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
                match protocol.execute_action(action) {
                    Ok(ClientActionResult::SendData(bytes)) => {
                        if write_half.lock().await.write_all(&bytes).await.is_ok() {
                            trace!("HTTP proxy client {} sent {} bytes", client_id, bytes.len());
                        }
                    }
                    Ok(ClientActionResult::Disconnect) => return true,
                    _ => {}
                }
            }
        }
        Err(e) => {
            error!("LLM error for HTTP proxy client {}: {}", client_id, e);
        }
    }
    false
}

/// The CONNECT request the client puts on the wire — the one encoder for both the LLM's
/// `establish_tunnel` (via the tunnel task) and a dashboard-injected one.
///
/// `proxy_authorization` is the already-encoded credential from the `proxy_auth` startup
/// parameter (`Basic <base64(user:pass)>`). RFC 7235 §4.4 puts it on the CONNECT itself,
/// which is the only request the proxy ever sees — everything after it is tunnel bytes.
fn connect_request(
    target_host: &str,
    target_port: &str,
    proxy_authorization: Option<&str>,
) -> String {
    let auth = match proxy_authorization {
        Some(value) => format!("Proxy-Authorization: {value}\r\n"),
        None => String::new(),
    };
    format!(
        "CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\n{}\r\n",
        target_host, target_port, target_host, target_port, auth
    )
}

/// Command-task arm. `send_http_request` / `send_data` / `disconnect` / `wait_for_more` are
/// `SendData`-shaped and go through the generic helper. `establish_tunnel` returns
/// `ClientActionResult::Custom`, which the generic arm cannot execute, so it is mapped here
/// through the same CONNECT encoder the tunnel task uses; the proxy's reply then reaches the
/// read loop as ordinary tunnel bytes (an `http_proxy_response_received` event).
async fn handle_injected_command<W>(
    write_half: &Arc<Mutex<W>>,
    command: ClientCommand,
    client_id: ClientId,
    state: &AppState,
    status_tx: &mpsc::UnboundedSender<String>,
) -> bool
where
    W: tokio::io::AsyncWrite + Unpin,
{
    let protocol = HttpProxyClientProtocol::new();
    if command.action.get("type").and_then(|v| v.as_str()) != Some("establish_tunnel") {
        return crate::client::command_support::handle_stream_client_command(
            &protocol, write_half, command, client_id, state, status_tx,
        )
        .await;
    }

    let action = command.action.clone();
    let outcome: anyhow::Result<ClientSendOutcome> = match protocol.execute_action(action.clone()) {
        Ok(ClientActionResult::Custom { data, .. }) => {
            // The same two startup parameters the LLM path honours: an injected CONNECT
            // that names no target uses `default_target`, and every injected CONNECT
            // carries the `proxy_auth` credential.
            let (default_target, proxy_authorization) = state
                .with_client_mut(client_id, |client| {
                    (
                        client
                            .get_protocol_field("default_target")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string()),
                        client
                            .get_protocol_field("proxy_authorization")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string()),
                    )
                })
                .await
                .unwrap_or((None, None));

            let (host, port) = match (
                data.get("target_host").and_then(|v| v.as_str()),
                data.get("target_port").and_then(|v| v.as_u64()),
            ) {
                (Some(host), Some(port)) => (host.to_string(), port.to_string()),
                _ => match default_target.as_deref().and_then(|t| t.rsplit_once(':')) {
                    Some((host, port)) => (host.to_string(), port.to_string()),
                    None => (String::new(), "0".to_string()),
                },
            };
            let bytes = connect_request(&host, &port, proxy_authorization.as_deref()).into_bytes();
            let mut guard = write_half.lock().await;
            match guard.write_all(&bytes).await {
                Ok(()) => match guard.flush().await {
                    Ok(()) => Ok(ClientSendOutcome::Sent {
                        bytes_sent: bytes.len(),
                    }),
                    Err(e) => Err(anyhow::anyhow!("flush failed: {e}")),
                },
                Err(e) => Err(anyhow::anyhow!("write failed: {e}")),
            }
        }
        Ok(_) => Ok(ClientSendOutcome::Executed {
            detail: "executed".to_string(),
        }),
        Err(e) => Ok(ClientSendOutcome::Rejected {
            error: e.to_string(),
        }),
    };

    // Same access-log shape as the generic arm, so the injection shows in the request pane.
    let outcome_json = match &outcome {
        Ok(outcome) => serde_json::to_value(outcome).unwrap_or(serde_json::Value::Null),
        Err(e) => serde_json::json!({"error": e.to_string()}),
    };
    state
        .record_access_log(
            AccessLogOwner::Client(client_id.as_u32()),
            crate::llm::actions::protocol_trait::Protocol::protocol_name(&protocol),
            None,
            "injected_action",
            action,
            vec![outcome_json],
        )
        .await;
    match &outcome {
        Ok(ClientSendOutcome::Sent { bytes_sent }) => info!(
            "HTTP proxy client {} sent injected CONNECT ({} bytes)",
            client_id, bytes_sent
        ),
        Ok(_) => {}
        Err(e) => {
            error!(
                "HTTP proxy client {} injected establish_tunnel failed: {}",
                client_id, e
            );
            let _ = status_tx.send(format!(
                "[WARN] Client {} injected action failed: {}",
                client_id, e
            ));
        }
    }
    let _ = status_tx.send("__UPDATE_UI__".to_string());
    crate::client::command_support::reply(command, outcome);
    false
}
