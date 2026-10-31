//! SSH Agent server implementation
//!
//! Platform: Unix/Linux/macOS (uses Unix domain sockets)
#![cfg(unix)]

pub mod actions;

use anyhow::{Context, Result};
use bytes::{BufMut, Bytes, BytesMut};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, error, info, trace};

use super::connection::ConnectionId;
use crate::llm::action_helper::call_llm;
use crate::llm::ollama_client::OllamaClient;
use crate::llm::ActionResult;
use crate::protocol::Event;
use crate::server::SshAgentProtocol;
use crate::state::app_state::AppState;
use actions::*;

/// SSH Agent message types (from SSH Agent Protocol specification)
const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
const SSH_AGENTC_SIGN_REQUEST: u8 = 13;
const SSH_AGENTC_ADD_IDENTITY: u8 = 17;
const SSH_AGENTC_REMOVE_IDENTITY: u8 = 18;
const SSH_AGENTC_REMOVE_ALL_IDENTITIES: u8 = 19;
const SSH_AGENTC_ADD_ID_CONSTRAINED: u8 = 25;
const SSH_AGENTC_LOCK: u8 = 22;
const SSH_AGENTC_UNLOCK: u8 = 23;

const SSH_AGENT_FAILURE: u8 = 5;
const SSH_AGENT_SUCCESS: u8 = 6;
const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
const SSH_AGENT_SIGN_RESPONSE: u8 = 14;

/// Largest agent message accepted, matching OpenSSH's own limit.
///
/// The length prefix is attacker-controlled, so without a cap a client could make the server
/// buffer arbitrary memory by announcing a huge message and never sending it.
pub const MAX_AGENT_MESSAGE_LEN: usize = 256 * 1024;

/// Pull one complete length-prefixed agent message off the front of `pending`.
///
/// The wire format is `uint32 length || byte type || payload`, and one TCP read is not one
/// message: a client may pipeline several requests into a single segment, or split one
/// request across segments. The previous reader treated every `read()` as exactly one message,
/// so pipelined requests after the first were discarded and split requests failed to parse.
///
/// Returns the frame including its 4-byte length prefix (which is what `parse_message` expects),
/// or `None` when more bytes are needed. `Err` means the stream is unusable and must be closed.
fn take_framed_message(pending: &mut Vec<u8>) -> Result<Option<Vec<u8>>> {
    if pending.len() < 4 {
        return Ok(None);
    }

    let length = u32::from_be_bytes([pending[0], pending[1], pending[2], pending[3]]) as usize;

    if length == 0 {
        anyhow::bail!("SSH Agent message declared zero length");
    }
    if length > MAX_AGENT_MESSAGE_LEN {
        anyhow::bail!(
            "SSH Agent message length {length} exceeds the {MAX_AGENT_MESSAGE_LEN} byte limit"
        );
    }
    if pending.len() < 4 + length {
        return Ok(None);
    }

    let frame = pending[..4 + length].to_vec();
    pending.drain(..4 + length);
    Ok(Some(frame))
}

/// How long a connected peer may send nothing at all before the server closes it.
///
/// The agent protocol is client-speaks-first — the server has nothing to say until asked — and
/// a real client (`ssh-add`, `ssh`) writes its first request the moment it connects. The peer
/// that does not is NetGet's own `ssh_agent` client: it connects inside `connect()`, writes
/// nothing, and waits for a model action or for a person to use `[ send message ]` —
/// **connected and silent**. So 300 seconds, the window a `manual` rule gives a human
/// (`src/state/intercepts.rs`), for `tcp`'s reason. Declared as the `first_byte_timeout_secs`
/// startup parameter; a stranger is still bounded, and capped at [`MAX_CONNECTIONS`].
const FIRST_BYTE_READ_TIMEOUT: Duration = Duration::from_secs(300);

/// How long an established session may be silent between requests.
///
/// OpenSSH's own agent sets no idle bound on a client connection, so there is no upstream
/// number to copy; `ssh` holds its agent connection for the authentication phase and closes it,
/// and a forwarded agent opens a fresh connection per request. Fifteen minutes, `tcp`'s number,
/// is far longer than any of those. The read is not polled while a request is being answered —
/// each one is handled inline, sequentially, before the loop reads again — so a model round-trip
/// or a `manual` rule parked for a human can never run against this clock. Declared as the
/// `idle_timeout_secs` startup parameter.
const IDLE_BETWEEN_REQUESTS_TIMEOUT: Duration = Duration::from_secs(900);

/// Concurrent connections this server admits.
///
/// [`crate::server::accept_bounded::DEFAULT_MAX_CONNECTIONS`]. Each connection may buffer up to
/// [`MAX_AGENT_MESSAGE_LEN`] of a partial message, so this is the multiplier that turns that
/// per-connection bound into a total one.
const MAX_CONNECTIONS: usize = crate::server::accept_bounded::DEFAULT_MAX_CONNECTIONS;

/// What a peer over [`MAX_CONNECTIONS`] is told before the socket closes: nothing.
///
/// The protocol's only negative is `SSH_AGENT_FAILURE`, which is an *answer* — written to a peer
/// that has asked nothing it would be read as the reply to whatever the client sends first. The
/// same reasoning keeps `raise_connection_opened` from writing one. A clean EOF, logged by
/// `accept_bounded_unix` with `decision=fail_closed_connection_cap`, is the honest refusal.
const CONNECTION_CAP_REFUSAL: &[u8] = b"";

/// Connection state for LLM processing
#[derive(Debug, Clone, PartialEq)]
enum ConnectionState {
    Idle,
    Processing,
    Accumulating,
}

/// Per-connection data for LLM handling
struct ConnectionData {
    state: ConnectionState,
    queued_data: Vec<u8>,
    memory: String,
    write_half: Arc<Mutex<tokio::io::WriteHalf<UnixStream>>>,
}

/// Unlinks the socket node this server bound when the accept loop ends — including when the
/// task is aborted by `stop_server`, because aborting drops the task future and this guard
/// with it.
///
/// Without it a stopped agent left its node on disk (`./netget-ssh-agent.sock` by default, in
/// whatever directory NetGet ran from), so `SSH_AUTH_SOCK` pointing at it got ECONNREFUSED —
/// "the agent is down" — rather than ENOENT. The node is always one this server created: the
/// bind is preceded by a guarded unlink that refuses anything that is not a socket.
struct SocketCleanup(PathBuf);

impl Drop for SocketCleanup {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// SSH Agent server that listens for incoming connections
pub struct SshAgentServer;

impl SshAgentServer {
    /// Spawn the SSH Agent server with integrated LLM actions
    pub async fn spawn_with_llm_actions(
        socket_path: PathBuf,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        server_id: crate::state::ServerId,
        first_byte_timeout_secs: Option<u64>,
        idle_timeout_secs: Option<u64>,
    ) -> Result<PathBuf> {
        let first_byte_timeout = first_byte_timeout_secs
            .map(Duration::from_secs)
            .unwrap_or(FIRST_BYTE_READ_TIMEOUT);
        let idle_timeout = idle_timeout_secs
            .map(Duration::from_secs)
            .unwrap_or(IDLE_BETWEEN_REQUESTS_TIMEOUT);

        // Remove a stale socket left behind by a previous run, so bind() does not fail with
        // EADDRINUSE. Only ever unlink an actual socket: `socket_path` comes from a startup
        // parameter, i.e. ultimately from model output, and blindly removing whatever is at
        // that path would let a bad value delete a regular file.
        if let Ok(metadata) = std::fs::symlink_metadata(&socket_path) {
            use std::os::unix::fs::FileTypeExt;
            if !metadata.file_type().is_socket() {
                anyhow::bail!(
                    "Refusing to start SSH Agent: {:?} already exists and is not a Unix socket. \
                     Choose a different socket_path.",
                    socket_path
                );
            }
            std::fs::remove_file(&socket_path).with_context(|| {
                format!("Failed to remove existing socket file: {:?}", socket_path)
            })?;
        }

        // Create and bind Unix domain socket server
        let listener = tokio::net::UnixListener::bind(&socket_path)
            .with_context(|| format!("Failed to bind to socket path: {:?}", socket_path))?;

        info!("SSH Agent server listening on {:?}", socket_path);
        let _ = status_tx.send(format!("SSH Agent server listening on {:?}", socket_path));

        let connections = Arc::new(Mutex::new(HashMap::new()));
        let protocol = Arc::new(SshAgentProtocol::new());

        let socket_path_clone = socket_path.clone();

        // Spawn accept loop
        let task_registrar = app_state.clone();
        let cleanup = SocketCleanup(socket_path.clone());
        let limiter = crate::server::accept_bounded::ConnectionLimiter::new(MAX_CONNECTIONS);
        let accept_handle = tokio::spawn(async move {
            // Moved in so it drops (and unlinks) when the loop ends or the task is aborted.
            let _cleanup = cleanup;
            loop {
                match crate::server::accept_bounded::accept_bounded_unix(
                    &listener,
                    &limiter,
                    CONNECTION_CAP_REFUSAL,
                    "SSH Agent",
                    Some(&status_tx),
                )
                .await
                {
                    Ok((stream, permit)) => {
                        let connection_id =
                            ConnectionId::new(app_state.get_next_unified_id().await);
                        info!("Accepted SSH Agent connection {}", connection_id);
                        let _ = status_tx
                            .send(format!("✓ SSH Agent connection {} opened", connection_id));

                        // Split stream
                        let (read_half, write_half) = tokio::io::split(stream);
                        let write_half_arc = Arc::new(Mutex::new(write_half));

                        // Add connection to ServerInstance
                        use crate::state::server::{
                            ConnectionState as ServerConnectionState, ConnectionStatus,
                            ProtocolConnectionInfo,
                        };
                        let now = crate::utils::clock::Instant::now();
                        let dummy_addr = "127.0.0.1:0".parse().unwrap();
                        let conn_state = ServerConnectionState {
                            id: connection_id,
                            remote_addr: dummy_addr,
                            local_addr: dummy_addr,
                            bytes_sent: 0,
                            bytes_received: 0,
                            packets_sent: 0,
                            packets_received: 0,
                            last_activity: now,
                            status: ConnectionStatus::Active,
                            status_changed_at: now,
                            protocol_info: ProtocolConnectionInfo::new(serde_json::json!({
                                "state": "Idle",
                                "socket_path": socket_path_clone.to_string_lossy()
                            })),
                        };
                        app_state
                            .add_connection_to_server(server_id, conn_state)
                            .await;
                        let _ = status_tx.send("__UPDATE_UI__".to_string());

                        // Register the connection HERE, before either task is spawned.
                        //
                        // This used to be the first thing the connection-opened task did,
                        // racing the reader task spawned immediately after it, and
                        // handle_data_with_actions returns silently when the connection is
                        // not in the map. For an agent that is worse than a dropped byte:
                        // the frame has already been taken off the read buffer, the protocol
                        // is a strict request/response sequence with no retry, so the client
                        // (`ssh-add -l`) blocks forever on a reply that was never generated.
                        // 7 of 64 clients that wrote immediately after connect hung this way.
                        connections.lock().await.insert(
                            connection_id,
                            ConnectionData {
                                state: ConnectionState::Idle,
                                queued_data: Vec::new(),
                                memory: String::new(),
                                write_half: write_half_arc.clone(),
                            },
                        );

                        // Raise the connection-opened event.
                        let llm_client_clone = llm_client.clone();
                        let app_state_clone = app_state.clone();
                        let status_tx_clone = status_tx.clone();
                        let connections_clone = connections.clone();
                        let protocol_clone = protocol.clone();
                        // Tracked, not detached: stop_server must abort this task too.
                        let task_owner = app_state.clone();
                        task_owner
                            .spawn_server_task(server_id, async move {
                                Self::raise_connection_opened(
                                    connection_id,
                                    server_id,
                                    llm_client_clone,
                                    app_state_clone,
                                    status_tx_clone,
                                    connections_clone,
                                    protocol_clone,
                                )
                                .await;
                            })
                            .await;

                        // Spawn reader task
                        let llm_client_clone = llm_client.clone();
                        let app_state_clone = app_state.clone();
                        let status_tx_clone = status_tx.clone();
                        let connections_clone = connections.clone();
                        let protocol_clone = protocol.clone();
                        // Tracked, not detached: stop_server must abort this task too.
                        let task_owner = app_state.clone();
                        task_owner.spawn_server_task(server_id, async move {
                            // Held for the life of the connection, so the cap counts live
                            // connections rather than accepts.
                            let _permit = permit;
                            let mut buffer = vec![0u8; 8192];
                            let mut read_half = read_half;
                            // Bytes received but not yet forming a complete message.
                            let mut pending: Vec<u8> = Vec::new();
                            let mut seen_bytes = false;

                            loop {
                                let bound = if seen_bytes {
                                    idle_timeout
                                } else {
                                    first_byte_timeout
                                };
                                // The deadline wraps this read and nothing else: every request
                                // is answered inline below, so the clock is not running while
                                // the model — or a human — composes the reply.
                                let read = match tokio::time::timeout(
                                    bound,
                                    read_half.read(&mut buffer),
                                )
                                .await
                                {
                                    Ok(read) => read,
                                    Err(_) => {
                                        connections_clone.lock().await.remove(&connection_id);
                                        app_state_clone
                                            .close_connection_on_server(server_id, connection_id)
                                            .await;
                                        let _ = status_tx_clone.send(format!(
                                            "SSH Agent connection {} sent nothing for {}s; \
                                             closing idle connection",
                                            connection_id,
                                            bound.as_secs()
                                        ));
                                        let _ = status_tx_clone.send("__UPDATE_UI__".to_string());
                                        break;
                                    }
                                };
                                match read {
                                    Ok(0) => {
                                        // Connection closed
                                        connections_clone.lock().await.remove(&connection_id);
                                        app_state_clone
                                            .close_connection_on_server(server_id, connection_id)
                                            .await;
                                        let _ = status_tx_clone.send(format!(
                                            "✗ SSH Agent connection {} closed",
                                            connection_id
                                        ));
                                        let _ = status_tx_clone.send("__UPDATE_UI__".to_string());
                                        break;
                                    }
                                    Ok(n) => {
                                        seen_bytes = true;
                                        trace!(
                                            "SSH Agent received {} bytes on connection {}",
                                            n,
                                            connection_id
                                        );
                                        pending.extend_from_slice(&buffer[..n]);

                                        // Drain every complete message this read produced.
                                        // Handled sequentially and inline: spawning a task per
                                        // read let concurrent requests race for the connection
                                        // lock and be answered out of order, which the agent
                                        // protocol - a strict request/response sequence on one
                                        // socket - cannot tolerate.
                                        let mut fatal = false;
                                        loop {
                                            match take_framed_message(&mut pending) {
                                                Ok(Some(frame)) => {
                                                    Self::handle_data_with_actions(
                                                        connection_id,
                                                        server_id,
                                                        Bytes::from(frame),
                                                        llm_client_clone.clone(),
                                                        app_state_clone.clone(),
                                                        status_tx_clone.clone(),
                                                        connections_clone.clone(),
                                                        protocol_clone.clone(),
                                                    )
                                                    .await;
                                                }
                                                Ok(None) => break,
                                                Err(e) => {
                                                    error!(
                                                        "Malformed framing on SSH Agent connection {}: {}",
                                                        connection_id, e
                                                    );
                                                    let _ = status_tx_clone.send(format!(
                                                        "[ERROR] SSH Agent framing error on connection {}: {}",
                                                        connection_id, e
                                                    ));
                                                    fatal = true;
                                                    break;
                                                }
                                            }
                                        }

                                        if fatal {
                                            connections_clone.lock().await.remove(&connection_id);
                                            app_state_clone
                                                .close_connection_on_server(
                                                    server_id,
                                                    connection_id,
                                                )
                                                .await;
                                            let _ =
                                                status_tx_clone.send("__UPDATE_UI__".to_string());
                                            break;
                                        }
                                    }
                                    Err(e) => {
                                        error!(
                                            "Read error on SSH Agent connection {}: {}",
                                            connection_id, e
                                        );
                                        connections_clone.lock().await.remove(&connection_id);
                                        break;
                                    }
                                }
                            }
                        }).await;
                    }
                    Err(e) => {
                        // A listener error (EMFILE, the socket torn down) recurs immediately,
                        // so continuing would spin a hot loop flooding the status channel.
                        error!("SSH Agent accept failed, listener stopped: {}", e);
                        let _ = status_tx.send(format!(
                            "[ERROR] SSH Agent accept failed, listener stopped: {}",
                            e
                        ));
                        break;
                    }
                }
            }
        });

        task_registrar
            .register_server_task(server_id, accept_handle)
            .await;

        Ok(socket_path)
    }

    /// Raise `ssh_agent_connection_opened` for a new connection.
    ///
    /// The connection is already registered by the accept loop by the time this runs.
    async fn raise_connection_opened(
        connection_id: ConnectionId,
        server_id: crate::state::ServerId,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        connections: Arc<Mutex<HashMap<ConnectionId, ConnectionData>>>,
        protocol: Arc<SshAgentProtocol>,
    ) {
        // Call LLM with connection opened event
        let event = Event::new(
            &SSH_AGENT_CONNECTION_OPENED_EVENT,
            serde_json::json!({
                "connection_id": connection_id.to_string(),
            }),
        );

        match call_llm(
            &llm_client,
            &app_state,
            server_id,
            Some(connection_id),
            &event,
            protocol.as_ref(),
        )
        .await
        {
            Ok(execution_result) => {
                // Display messages
                for msg in execution_result.messages {
                    let _ = status_tx.send(msg);
                }

                // Execute protocol actions. There is no pending agent request at this
                // point - the client has connected but asked nothing - so the fail-closed
                // rule below does not apply here: writing an unsolicited SSH_AGENT_FAILURE
                // would answer a request that was never made.
                for action in execution_result.protocol_results {
                    if let Err(e) = Self::execute_action_result(
                        action,
                        connection_id,
                        server_id,
                        &connections,
                        &app_state,
                        &status_tx,
                    )
                    .await
                    {
                        error!("Failed to execute action: {}", e);
                    }
                }
            }
            Err(e) => {
                error!("LLM error on connection opened: {}", e);
            }
        }
    }

    /// Handle incoming data with LLM actions
    async fn handle_data_with_actions(
        connection_id: ConnectionId,
        server_id: crate::state::ServerId,
        data: Bytes,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        connections: Arc<Mutex<HashMap<ConnectionId, ConnectionData>>>,
        protocol: Arc<SshAgentProtocol>,
    ) {
        // Check connection state
        let mut conns = connections.lock().await;
        let conn_data = match conns.get_mut(&connection_id) {
            Some(cd) => cd,
            None => return,
        };

        match conn_data.state {
            ConnectionState::Idle => {
                // Process immediately
                conn_data.state = ConnectionState::Processing;
                let current_memory = conn_data.memory.clone();
                drop(conns);

                // Parse and handle message
                Box::pin(Self::process_message_with_llm(
                    connection_id,
                    server_id,
                    data.to_vec(),
                    llm_client,
                    app_state,
                    status_tx,
                    connections.clone(),
                    protocol,
                    current_memory,
                ))
                .await;
            }
            ConnectionState::Processing => {
                // Queue data
                conn_data.queued_data.extend_from_slice(&data);
                conn_data.state = ConnectionState::Accumulating;
                debug!(
                    "SSH Agent: Queuing {} bytes (total queued: {})",
                    data.len(),
                    conn_data.queued_data.len()
                );
            }
            ConnectionState::Accumulating => {
                // Continue queuing
                conn_data.queued_data.extend_from_slice(&data);
                debug!(
                    "SSH Agent: Queuing {} bytes (total queued: {})",
                    data.len(),
                    conn_data.queued_data.len()
                );
            }
        }
    }

    /// Process SSH Agent message and call LLM
    async fn process_message_with_llm(
        connection_id: ConnectionId,
        server_id: crate::state::ServerId,
        data: Vec<u8>,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        connections: Arc<Mutex<HashMap<ConnectionId, ConnectionData>>>,
        protocol: Arc<SshAgentProtocol>,
        _current_memory: String,
    ) {
        // Parse SSH Agent message
        let event = match Self::parse_message(&data) {
            Ok(Some(event)) => event,
            Ok(None) => {
                // Unknown or unsupported message type - send failure
                Self::send_failure(connection_id, &connections).await;
                Self::check_queued_data(
                    connection_id,
                    server_id,
                    llm_client,
                    app_state,
                    status_tx,
                    connections,
                    protocol,
                )
                .await;
                return;
            }
            Err(e) => {
                error!("Failed to parse SSH Agent message: {}", e);
                Self::send_failure(connection_id, &connections).await;
                Self::check_queued_data(
                    connection_id,
                    server_id,
                    llm_client,
                    app_state,
                    status_tx,
                    connections,
                    protocol,
                )
                .await;
                return;
            }
        };

        // Call LLM
        match call_llm(
            &llm_client,
            &app_state,
            server_id,
            Some(connection_id),
            &event,
            protocol.as_ref(),
        )
        .await
        {
            Ok(execution_result) => {
                // Send messages to TUI
                for msg in execution_result.messages {
                    let _ = status_tx.send(msg);
                }

                // Execute actions, tracking whether the request ends up answered.
                let mut answered = false;
                let mut execution_failed = false;
                for action in execution_result.protocol_results {
                    match Self::execute_action_result(
                        action,
                        connection_id,
                        server_id,
                        &connections,
                        &app_state,
                        &status_tx,
                    )
                    .await
                    {
                        Ok(true) => answered = true,
                        Ok(false) => {}
                        Err(e) => {
                            error!("Failed to execute action: {}", e);
                            execution_failed = true;
                        }
                    }
                }

                // FAIL CLOSED. An SSH agent request is a question the client blocks on; if
                // the model answered with nothing usable, saying nothing leaves `ssh` or
                // `ssh-add` waiting on a read that will never complete, which the user reads
                // as a hung agent rather than as a refusal. SSH_AGENT_FAILURE is the
                // protocol's only way to say no, so it is what silence has to become.
                //
                // The decision token keeps the three cases apart the way `src/server/radius/`
                // does. `send_failure` from the model is decision=model_reject and is logged
                // by nothing here; these two are the server's own decision and must never be
                // mistaken for it.
                if !answered {
                    let decision = if execution_failed {
                        "fail_closed_action_error"
                    } else {
                        "fail_closed_no_action"
                    };
                    let message = format!(
                        "SSH Agent request on connection {}: decision={} (denied because no \
                         usable answer was produced)",
                        connection_id, decision
                    );
                    error!("{}", message);
                    let _ = status_tx.send(message);
                    Self::send_failure(connection_id, &connections).await;
                }
            }
            Err(e) => {
                // The backend is unreachable. An unanswerable request is refused, never left
                // to hang, and the error itself stays in the log - the agent wire format has
                // no field that could carry it to the peer anyway.
                let category = crate::utils::WireFailure::classify(&e);
                error!(
                    "SSH Agent request on connection {}: decision=fail_closed_llm_error \
                     category={:?}: {}",
                    connection_id, category, e
                );
                let _ = status_tx.send(format!(
                    "SSH Agent request on connection {}: decision=fail_closed_llm_error \
                     category={:?}",
                    connection_id, category
                ));
                Self::send_failure(connection_id, &connections).await;
            }
        }

        // Check for queued data
        Self::check_queued_data(
            connection_id,
            server_id,
            llm_client,
            app_state,
            status_tx,
            connections,
            protocol,
        )
        .await;
    }

    /// Parse SSH Agent protocol message
    fn parse_message(data: &[u8]) -> Result<Option<Event>> {
        if data.len() < 5 {
            return Ok(None);
        }

        // SSH Agent wire format: [uint32: length][byte: type][data...]
        // Skip the 4-byte length prefix
        let _length = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let msg_type = data[4];
        let mut cursor = &data[5..];

        debug!(
            "SSH Agent: parsing message type {} from {} bytes",
            msg_type,
            data.len()
        );

        match msg_type {
            SSH_AGENTC_REQUEST_IDENTITIES => Ok(Some(Event::new(
                &SSH_AGENT_REQUEST_IDENTITIES_EVENT,
                serde_json::json!({}),
            ))),
            SSH_AGENTC_SIGN_REQUEST => {
                // Parse: string public_key_blob, string data, uint32 flags
                let public_key_blob = Self::read_string(&mut cursor)?;
                let data_to_sign = Self::read_string(&mut cursor)?;
                let flags = Self::read_uint32(&mut cursor)?;

                Ok(Some(Event::new(
                    &SSH_AGENT_SIGN_REQUEST_EVENT,
                    serde_json::json!({
                        "key_type": Self::key_type_of(public_key_blob),
                        "public_key_blob_hex": hex::encode(public_key_blob),
                        "data_hex": hex::encode(data_to_sign),
                        "flags": flags,
                    }),
                )))
            }
            SSH_AGENTC_ADD_IDENTITY | SSH_AGENTC_ADD_ID_CONSTRAINED => {
                // Parse: string key_type, (key-specific data), string comment
                let key_type = Self::read_string(&mut cursor)?;
                let key_type_str = String::from_utf8_lossy(key_type);

                // For simplicity, we'll just extract key type and skip to comment
                // In a full implementation, we'd parse the key-specific data
                let public_key_blob = Self::read_string(&mut cursor)?;
                let _private_key_blob = Self::read_string(&mut cursor)?; // Skip private key
                let comment = Self::read_string(&mut cursor)?;

                Ok(Some(Event::new(
                    &SSH_AGENT_ADD_IDENTITY_EVENT,
                    serde_json::json!({
                        "key_type": key_type_str,
                        "public_key_blob_hex": hex::encode(public_key_blob),
                        "comment": String::from_utf8_lossy(comment),
                        "constrained": msg_type == SSH_AGENTC_ADD_ID_CONSTRAINED,
                    }),
                )))
            }
            SSH_AGENTC_REMOVE_IDENTITY => {
                let public_key_blob = Self::read_string(&mut cursor)?;

                Ok(Some(Event::new(
                    &SSH_AGENT_REMOVE_IDENTITY_EVENT,
                    serde_json::json!({
                        "public_key_blob_hex": hex::encode(public_key_blob),
                    }),
                )))
            }
            SSH_AGENTC_REMOVE_ALL_IDENTITIES => Ok(Some(Event::new(
                &SSH_AGENT_REMOVE_ALL_IDENTITIES_EVENT,
                serde_json::json!({}),
            ))),
            // Both carry a single `string passphrase`. It was previously parsed away and the
            // event delivered empty, so a handler could not tell a correct unlock passphrase
            // from a wrong one - the whole point of the operation.
            SSH_AGENTC_LOCK => {
                let passphrase = Self::read_string(&mut cursor)?;
                Ok(Some(Event::new(
                    &SSH_AGENT_LOCK_EVENT,
                    serde_json::json!({
                        "passphrase": String::from_utf8_lossy(passphrase),
                    }),
                )))
            }
            SSH_AGENTC_UNLOCK => {
                let passphrase = Self::read_string(&mut cursor)?;
                Ok(Some(Event::new(
                    &SSH_AGENT_UNLOCK_EVENT,
                    serde_json::json!({
                        "passphrase": String::from_utf8_lossy(passphrase),
                    }),
                )))
            }
            _ => {
                debug!("Unknown SSH Agent message type: {}", msg_type);
                Ok(None)
            }
        }
    }

    /// Extract the algorithm name from an SSH public key blob.
    ///
    /// Every blob starts with its algorithm as a length-prefixed string ("ssh-ed25519",
    /// "ssh-rsa", ...). Surfacing it saves a handler from having to decode hex just to work
    /// out which key a sign request refers to. Returns "" for a blob it cannot read.
    fn key_type_of(blob: &[u8]) -> String {
        let mut cursor = blob;
        match Self::read_string(&mut cursor) {
            Ok(name) => String::from_utf8_lossy(name).to_string(),
            Err(_) => String::new(),
        }
    }

    /// Read SSH wire format string (uint32 length + bytes)
    fn read_string<'a>(cursor: &mut &'a [u8]) -> Result<&'a [u8]> {
        if cursor.len() < 4 {
            anyhow::bail!("Not enough data to read string length");
        }
        let len = u32::from_be_bytes([cursor[0], cursor[1], cursor[2], cursor[3]]) as usize;
        *cursor = &cursor[4..];

        if cursor.len() < len {
            anyhow::bail!("Not enough data to read string of length {}", len);
        }
        let result = &cursor[..len];
        *cursor = &cursor[len..];
        Ok(result)
    }

    /// Read SSH wire format uint32
    fn read_uint32(cursor: &mut &[u8]) -> Result<u32> {
        if cursor.len() < 4 {
            anyhow::bail!("Not enough data to read uint32");
        }
        let result = u32::from_be_bytes([cursor[0], cursor[1], cursor[2], cursor[3]]);
        *cursor = &cursor[4..];
        Ok(result)
    }

    /// Execute one action the model produced.
    ///
    /// Returns `true` when the pending agent request has been *answered* - a reply written to
    /// the socket, or the connection torn down. The caller uses that to enforce the
    /// fail-closed rule: an agent request that draws no answer at all leaves `ssh`/`ssh-add`
    /// blocked on a read that never completes, which is indistinguishable from a hung agent.
    async fn execute_action_result(
        action: ActionResult,
        connection_id: ConnectionId,
        server_id: crate::state::ServerId,
        connections: &Arc<Mutex<HashMap<ConnectionId, ConnectionData>>>,
        app_state: &Arc<AppState>,
        status_tx: &mpsc::UnboundedSender<String>,
    ) -> Result<bool> {
        match action {
            ActionResult::Custom { name, data } => match name.as_str() {
                "send_identities_list" => {
                    let identities = data["identities"]
                        .as_array()
                        .context("Missing 'identities' field")?;
                    Self::send_identities_list(connection_id, identities, connections).await;
                    Ok(true)
                }
                "send_sign_response" => {
                    let signature_hex = data["signature_hex"]
                        .as_str()
                        .context("Missing 'signature_hex' field")?;
                    Self::send_sign_response(connection_id, signature_hex, connections).await;
                    Ok(true)
                }
                "send_success" => {
                    Self::send_success(connection_id, connections).await;
                    Ok(true)
                }
                "send_failure" => {
                    Self::send_failure(connection_id, connections).await;
                    Ok(true)
                }
                other => {
                    debug!("Unknown custom action: {}", other);
                    Ok(false)
                }
            },
            ActionResult::CloseConnection => {
                connections.lock().await.remove(&connection_id);
                app_state
                    .close_connection_on_server(server_id, connection_id)
                    .await;
                let _ = status_tx.send(format!("✗ SSH Agent connection {} closed", connection_id));
                let _ = status_tx.send("__UPDATE_UI__".to_string());
                Ok(true)
            }
            // WaitForMore is a deliberate "say nothing yet": the model wants the rest of a
            // pipelined request before answering. It is the one non-answer that must NOT be
            // turned into a failure.
            ActionResult::WaitForMore => Ok(true),
            _ => Ok(false),
        }
    }

    /// Send SSH_AGENT_IDENTITIES_ANSWER
    async fn send_identities_list(
        connection_id: ConnectionId,
        identities: &Vec<serde_json::Value>,
        connections: &Arc<Mutex<HashMap<ConnectionId, ConnectionData>>>,
    ) {
        // Decode every key blob before committing to a reply. Previously an unparseable hex
        // string became an empty blob via unwrap_or_default(), so the client silently received
        // an identity with a zero-length key instead of an error it could act on.
        let mut decoded: Vec<(Vec<u8>, &str)> = Vec::with_capacity(identities.len());
        for identity in identities {
            let key_blob_hex = identity["public_key_blob_hex"].as_str().unwrap_or("");
            let comment = identity["comment"].as_str().unwrap_or("");

            match hex::decode(key_blob_hex) {
                Ok(blob) if !blob.is_empty() => decoded.push((blob, comment)),
                Ok(_) => {
                    error!(
                        "SSH Agent: identity {:?} has an empty public_key_blob_hex; failing the request",
                        comment
                    );
                    Self::send_failure(connection_id, connections).await;
                    return;
                }
                Err(e) => {
                    error!(
                        "SSH Agent: identity {:?} has invalid hex in public_key_blob_hex: {}",
                        comment, e
                    );
                    Self::send_failure(connection_id, connections).await;
                    return;
                }
            }
        }

        let mut response = BytesMut::new();
        response.put_u8(SSH_AGENT_IDENTITIES_ANSWER);
        response.put_u32(decoded.len() as u32);

        for (key_blob, comment) in &decoded {
            // Write key blob (string)
            response.put_u32(key_blob.len() as u32);
            response.put_slice(key_blob);

            // Write comment (string)
            response.put_u32(comment.len() as u32);
            response.put_slice(comment.as_bytes());
        }

        Self::send_response(connection_id, response.freeze(), connections).await;
    }

    /// Send SSH_AGENT_SIGN_RESPONSE
    async fn send_sign_response(
        connection_id: ConnectionId,
        signature_hex: &str,
        connections: &Arc<Mutex<HashMap<ConnectionId, ConnectionData>>>,
    ) {
        // A malformed signature used to be sent as a zero-length blob, which the client reads
        // as a valid-but-empty signature and then fails to verify with no useful diagnostic.
        let signature_blob = match hex::decode(signature_hex) {
            Ok(blob) if !blob.is_empty() => blob,
            Ok(_) => {
                error!("SSH Agent: signature_hex decoded to zero bytes; failing the sign request");
                Self::send_failure(connection_id, connections).await;
                return;
            }
            Err(e) => {
                error!("SSH Agent: invalid hex in signature_hex: {}", e);
                Self::send_failure(connection_id, connections).await;
                return;
            }
        };

        let mut response = BytesMut::new();
        response.put_u8(SSH_AGENT_SIGN_RESPONSE);
        response.put_u32(signature_blob.len() as u32);
        response.put_slice(&signature_blob);

        Self::send_response(connection_id, response.freeze(), connections).await;
    }

    /// Send SSH_AGENT_SUCCESS
    async fn send_success(
        connection_id: ConnectionId,
        connections: &Arc<Mutex<HashMap<ConnectionId, ConnectionData>>>,
    ) {
        let mut response = BytesMut::new();
        response.put_u8(SSH_AGENT_SUCCESS);
        Self::send_response(connection_id, response.freeze(), connections).await;
    }

    /// Send SSH_AGENT_FAILURE
    async fn send_failure(
        connection_id: ConnectionId,
        connections: &Arc<Mutex<HashMap<ConnectionId, ConnectionData>>>,
    ) {
        let mut response = BytesMut::new();
        response.put_u8(SSH_AGENT_FAILURE);
        Self::send_response(connection_id, response.freeze(), connections).await;
    }

    /// Send response with SSH wire format (length prefix + data)
    async fn send_response(
        connection_id: ConnectionId,
        data: Bytes,
        connections: &Arc<Mutex<HashMap<ConnectionId, ConnectionData>>>,
    ) {
        let conns = connections.lock().await;
        if let Some(conn_data) = conns.get(&connection_id) {
            // Prepend length
            let mut message = BytesMut::new();
            message.put_u32(data.len() as u32);
            message.put_slice(&data);

            // Wait for the write half rather than try_lock: a failed try_lock silently
            // dropped the response, leaving the client blocked forever on a reply that was
            // never sent.
            let mut write_half = conn_data.write_half.lock().await;
            if let Err(e) = write_half.write_all(&message).await {
                error!("Failed to write SSH Agent response: {}", e);
            }
        } else {
            debug!(
                "SSH Agent: dropping response for closed connection {}",
                connection_id
            );
        }
    }

    /// Check for queued data and process if present
    async fn check_queued_data(
        connection_id: ConnectionId,
        server_id: crate::state::ServerId,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        connections: Arc<Mutex<HashMap<ConnectionId, ConnectionData>>>,
        protocol: Arc<SshAgentProtocol>,
    ) {
        let mut conns = connections.lock().await;
        if let Some(conn_data) = conns.get_mut(&connection_id) {
            if conn_data.state == ConnectionState::Accumulating {
                let queued = std::mem::take(&mut conn_data.queued_data);
                conn_data.state = ConnectionState::Processing;
                let current_memory = conn_data.memory.clone();
                drop(conns);

                Box::pin(Self::process_message_with_llm(
                    connection_id,
                    server_id,
                    queued,
                    llm_client,
                    app_state,
                    status_tx,
                    connections,
                    protocol,
                    current_memory,
                ))
                .await;
            } else {
                conn_data.state = ConnectionState::Idle;
            }
        }
    }
}
