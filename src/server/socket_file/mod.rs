//! Unix domain socket server implementation
//!
//! Platform: Unix/Linux only (uses Unix domain sockets)
#![cfg(unix)]

pub mod actions;

use anyhow::{Context, Result};
use bytes::Bytes;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, info};

use super::connection::ConnectionId;
use crate::llm::action_helper::call_llm;
use crate::llm::ollama_client::OllamaClient;
use crate::llm::ActionResult;
use crate::logging::emit::Log;
use crate::protocol::Event;
use crate::server::read_queue::{Admitted, Held, ReadQueue};
use crate::server::SocketFileProtocol;
use crate::state::app_state::AppState;
use actions::{SOCKET_FILE_CONNECTION_OPENED_EVENT, SOCKET_FILE_DATA_RECEIVED_EVENT};

/// How long a connected peer may send nothing at all before the server closes it.
///
/// 300 seconds, the window a `manual` rule gives a human to answer one event
/// (`src/state/intercepts.rs`), for the reason `tcp` gives for the same number: this is the
/// generic byte stream over a filesystem socket, and the peer it most often has is NetGet's own
/// `socket_file` client, which connects inside `connect()`, writes nothing, and waits for a
/// person to use `[ send message ]` — **connected and silent**. A shorter bound drops that peer
/// while the operator is still looking at it. A stranger is still bounded, and still capped at
/// [`MAX_CONNECTIONS`]; the node is owner-only (0600), so the stranger is a local process of the
/// same user. Declared as the `first_byte_timeout_secs` startup parameter.
///
/// A `send_first` server is not the exception it looks like: the banner task holds the
/// connection's [`ConnectionActivity`](crate::server::accept_bounded::ConnectionActivity) busy
/// for the whole of its model round-trip, so the clock does not run while the peer is waiting
/// to be spoken to.
const FIRST_BYTE_READ_TIMEOUT: Duration = Duration::from_secs(300);

/// How long an established session may be silent between messages.
///
/// Fifteen minutes, `tcp`'s number: three times the window a `manual` rule gives a human, so a
/// session whose last exchange was composed by hand still has minutes of think-time left. A
/// message still being answered is never silence — the reader consults `ConnectionActivity`.
/// Declared as the `idle_timeout_secs` startup parameter.
const IDLE_BETWEEN_MESSAGES_TIMEOUT: Duration = Duration::from_secs(900);

/// Most bytes that may pile up in one connection's queue while its LLM call is in flight, and
/// the most `wait_for_more` may accumulate.
///
/// Every byte the peer sends during a call is queued, so without a ceiling a peer streaming for
/// the length of one call decides how much memory its connection costs. 8 MiB, the same as
/// `tcp`, is far more than any exchange this server is for; reaching it means the peer is not
/// waiting for answers, so the connection is closed (`decision=queue_overflow`) rather than the
/// queue trimmed, which would hand the model a truncated message it could not know was
/// truncated.
pub const MAX_QUEUED_BYTES: usize = 8 * 1024 * 1024;

/// Concurrent connections this server admits.
///
/// [`crate::server::accept_bounded::DEFAULT_MAX_CONNECTIONS`]. Each connection may queue bytes
/// while its LLM call is in flight, so this is the multiplier that turns the per-connection cost
/// into a total one.
const MAX_CONNECTIONS: usize = crate::server::accept_bounded::DEFAULT_MAX_CONNECTIONS;

/// What a peer over [`MAX_CONNECTIONS`] is told before the socket closes: nothing.
///
/// A raw byte stream has no vocabulary — anything written would be read as payload — so the
/// refusal is a clean EOF, logged by `accept_bounded_unix` with
/// `decision=fail_closed_connection_cap`. Same reasoning as `tcp`.
const CONNECTION_CAP_REFUSAL: &[u8] = b"";

/// Read from `reader` with a deadline that a connection doing work can never trip.
///
/// Returns `None` when the peer has genuinely been silent for `bound`, and the read's own
/// result otherwise. The read loop hands each message to a spawned task and goes straight back
/// to `read()`, so the deadline and an answer in progress are live at the same moment;
/// consulting [`ConnectionActivity::idle_for`](crate::server::accept_bounded::ConnectionActivity::idle_for)
/// — which reports a connection with work in flight as not idle — keeps the deadline from
/// closing the connection it is in the middle of answering. The same helper as `tcp`'s.
async fn read_bounded<R>(
    reader: &mut R,
    buffer: &mut [u8],
    activity: &crate::server::accept_bounded::ConnectionActivity,
    bound: Duration,
) -> Option<std::io::Result<usize>>
where
    R: tokio::io::AsyncRead + Unpin,
{
    loop {
        match tokio::time::timeout(bound, reader.read(buffer)).await {
            Ok(result) => return Some(result),
            Err(_) => match activity.idle_for() {
                // Work in flight: the peer is waiting on us, not the other way round.
                None => continue,
                // Something crossed the connection inside the window; wait again from there.
                Some(idle) if idle < bound => continue,
                Some(_) => return None,
            },
        }
    }
}

/// Per-connection data for LLM handling
struct ConnectionData {
    /// The Idle → Processing → Accumulating machine and the reads waiting behind the answer in
    /// flight. Every decision on it is made under the connection map's lock; see
    /// [`crate::server::read_queue`]. A byte stream has no message boundaries, so with batching
    /// on everything that arrived during a call is the next call's payload; off, each read is
    /// answered on its own, in order — the `tcp` shape.
    reads: ReadQueue,
    write_half: Arc<Mutex<tokio::io::WriteHalf<UnixStream>>>,
}

/// Describe a file type for the "refusing to unlink" error message.
fn describe_file_type(ft: &std::fs::FileType) -> &'static str {
    use std::os::unix::fs::FileTypeExt;
    if ft.is_dir() {
        "directory"
    } else if ft.is_symlink() {
        "symlink"
    } else if ft.is_fifo() {
        "FIFO"
    } else if ft.is_char_device() {
        "character device"
    } else if ft.is_block_device() {
        "block device"
    } else {
        "regular file"
    }
}

/// Removes the socket node this server bound, when the accept loop ends — including when the
/// task is aborted by `stop_server`, because aborting drops the task future and with it this
/// guard.
///
/// Without it a stopped server left its socket node on disk advertising a service nothing was
/// listening on: `connect(2)` gets ECONNREFUSED rather than ENOENT, which reads as "the service
/// is down" instead of "there is no service". `named_pipe` and `pty` both clean up after
/// themselves; this one did not. The node is always one we created — the bind is preceded by a
/// guarded unlink of any stale socket at the same path.
struct SocketCleanup(PathBuf);

impl Drop for SocketCleanup {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Unix domain socket server that listens for incoming connections
pub struct SocketFileServer;

impl SocketFileServer {
    /// Spawn the socket file server with integrated LLM actions
    #[allow(clippy::too_many_arguments)]
    pub async fn spawn_with_llm_actions(
        socket_path: PathBuf,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        send_first: bool,
        server_id: crate::state::ServerId,
        first_byte_timeout_secs: Option<u64>,
        idle_timeout_secs: Option<u64>,
    ) -> Result<PathBuf> {
        let first_byte_timeout = first_byte_timeout_secs
            .map(Duration::from_secs)
            .unwrap_or(FIRST_BYTE_READ_TIMEOUT);
        let idle_timeout = idle_timeout_secs
            .map(Duration::from_secs)
            .unwrap_or(IDLE_BETWEEN_MESSAGES_TIMEOUT);
        // Remove a stale socket file, but ONLY if the path really is a socket.
        //
        // `socket_path` comes from the LLM or an MCP caller, so an unconditional
        // `remove_file` here is an arbitrary-file delete: "./netget.sock" typo'd as
        // "./netget.rs", or a deliberately chosen "~/.ssh/id_ed25519", would be unlinked
        // before the bind. `symlink_metadata` deliberately does not follow symlinks, so a
        // symlink pointing at a regular file is refused rather than followed and deleted.
        match std::fs::symlink_metadata(&socket_path) {
            Ok(meta) => {
                use std::os::unix::fs::FileTypeExt;
                if !meta.file_type().is_socket() {
                    anyhow::bail!(
                        "Refusing to remove {:?}: it exists but is not a Unix domain socket \
                         (it is a {}). Delete it yourself if that is really what you want, or \
                         pass a different socket_path.",
                        socket_path,
                        describe_file_type(&meta.file_type())
                    );
                }
                std::fs::remove_file(&socket_path).with_context(|| {
                    format!("Failed to remove existing socket file: {:?}", socket_path)
                })?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // Nothing there - normal case.
            }
            Err(e) => {
                return Err(e).with_context(|| format!("Failed to stat {:?}", socket_path));
            }
        }

        // Create and bind Unix domain socket server
        let listener = tokio::net::UnixListener::bind(&socket_path)
            .with_context(|| format!("Failed to bind to socket path: {:?}", socket_path))?;

        // Owner-only (0600). `bind` creates the node with 0777 & ~umask, which on a default
        // umask of 022 is `srwxr-xr-x`: on both Linux and macOS the kernel checks write
        // permission on the socket node at connect(2), so every local user could speak to a
        // server the model was told to run for one process. The model or an MCP caller chooses
        // `socket_path`, and a predictable path under a world-writable directory is the classic
        // local-escalation shape, so the default has to be closed. There is a brief window
        // between bind and chmod; closing it entirely means a private directory, which is the
        // caller's choice of path, not ours.
        std::fs::set_permissions(
            &socket_path,
            <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o600),
        )
        .with_context(|| {
            format!(
                "Failed to restrict permissions on socket file {:?} to owner-only",
                socket_path
            )
        })?;

        Log::new(Some(&status_tx))
            .info(format!("Socket file server listening on {:?}", socket_path));

        let connections = Arc::new(Mutex::new(HashMap::new()));
        let protocol = Arc::new(SocketFileProtocol::new());

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
                    "Socket file",
                    Some(&status_tx),
                )
                .await
                {
                    Ok((stream, permit)) => {
                        let connection_id =
                            ConnectionId::new(app_state.get_next_unified_id().await);
                        info!("Accepted socket file connection {}", connection_id);

                        // Split stream
                        let (read_half, write_half) = tokio::io::split(stream);
                        let write_half_arc = Arc::new(Mutex::new(write_half));

                        // Whether this connection is doing work the peer is waiting on. The
                        // read deadline consults it, so an LLM round-trip or a `manual` rule
                        // parked for a human is never mistaken for an idle peer.
                        let activity =
                            Arc::new(crate::server::accept_bounded::ConnectionActivity::new());

                        // Add connection to ServerInstance
                        use crate::state::server::{
                            ConnectionState as ServerConnectionState, ConnectionStatus,
                            ProtocolConnectionInfo,
                        };
                        let now = crate::utils::clock::Instant::now();
                        // Use a dummy SocketAddr since Unix sockets don't have IP addresses
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
                        // This used to be the first thing the banner task did, racing the
                        // reader task: a read is dropped when the connection is not in the
                        // map, so a client that wrote immediately
                        // after connecting (`printf ping | nc -U ...`) had its first payload
                        // dropped with no response and no log line. Inserting synchronously
                        // in the accept loop closes the window.
                        //
                        // A `send_first` server registers it `Processing`: the banner is being
                        // composed, and anything the peer sends meanwhile queues behind it
                        // rather than being answered first. The banner task hands the queue
                        // over when the banner is out. Without `send_first` it starts `Idle`.
                        connections.lock().await.insert(
                            connection_id,
                            ConnectionData {
                                reads: if send_first {
                                    ReadQueue::answering()
                                } else {
                                    ReadQueue::idle()
                                },
                                write_half: write_half_arc.clone(),
                            },
                        );

                        // Send the greeting banner, if this server was asked for one.
                        if send_first {
                            let llm_client_clone = llm_client.clone();
                            let app_state_clone = app_state.clone();
                            let status_tx_clone = status_tx.clone();
                            let connections_clone = connections.clone();
                            let write_half_for_conn = write_half_arc.clone();
                            let protocol_clone = protocol.clone();
                            // The peer is waiting to be greeted, so the first-byte deadline
                            // must not run while the banner is being composed.
                            let banner_busy = activity.busy();
                            // Tracked, not detached: stop_server must abort this task too.
                            let task_owner = app_state.clone();
                            task_owner
                                .spawn_server_task(server_id, async move {
                                    let _banner_busy = banner_busy;
                                    Self::send_banner(
                                        connection_id,
                                        server_id,
                                        llm_client_clone,
                                        app_state_clone,
                                        status_tx_clone,
                                        connections_clone,
                                        write_half_for_conn,
                                        protocol_clone,
                                    )
                                    .await;
                                })
                                .await;
                        }

                        // Spawn reader task
                        let llm_client_clone = llm_client.clone();
                        let app_state_clone = app_state.clone();
                        let status_tx_clone = status_tx.clone();
                        let connections_clone = connections.clone();
                        let protocol_clone = protocol.clone();
                        let activity_clone = activity.clone();
                        // Tracked, not detached: stop_server must abort this task too.
                        let task_owner = app_state.clone();
                        task_owner
                            .spawn_server_task(server_id, async move {
                                // Held for the life of the connection, so the cap counts live
                                // connections rather than accepts.
                                let _permit = permit;
                                let mut buffer = vec![0u8; 8192];
                                let mut read_half = read_half;
                                let mut seen_bytes = false;

                                loop {
                                    let bound = if seen_bytes {
                                        idle_timeout
                                    } else {
                                        first_byte_timeout
                                    };
                                    // The deadline wraps this read and nothing else.
                                    let read = match read_bounded(
                                        &mut read_half,
                                        &mut buffer,
                                        &activity_clone,
                                        bound,
                                    )
                                    .await
                                    {
                                        Some(result) => result,
                                        None => {
                                            connections_clone.lock().await.remove(&connection_id);
                                            app_state_clone
                                                .close_connection_on_server(
                                                    server_id,
                                                    connection_id,
                                                )
                                                .await;
                                            Log::new(Some(&status_tx_clone)).info(format!(
                                                "Socket file connection {connection_id} sent \
                                                 nothing for {}s; closing idle connection",
                                                bound.as_secs()
                                            ));
                                            let _ =
                                                status_tx_clone.send("__UPDATE_UI__".to_string());
                                            break;
                                        }
                                    };
                                    match read {
                                        Ok(0) => {
                                            // Connection closed
                                            connections_clone.lock().await.remove(&connection_id);
                                            app_state_clone
                                                .close_connection_on_server(
                                                    server_id,
                                                    connection_id,
                                                )
                                                .await;
                                            Log::new(Some(&status_tx_clone)).info(format!(
                                                "Socket file connection {connection_id} closed"
                                            ));
                                            let _ =
                                                status_tx_clone.send("__UPDATE_UI__".to_string());
                                            break;
                                        }
                                        Ok(n) => {
                                            seen_bytes = true;
                                            activity_clone.touch();
                                            let data = Bytes::copy_from_slice(&buffer[..n]);

                                            // Data summary + full payload are FileOnly: the
                                            // socket_file_data_received event template renders the
                                            // equivalent lines to the TUI, so streaming the payload
                                            // here too would duplicate it and load the unbounded
                                            // status channel.
                                            let log = Log::new(Some(&status_tx_clone));
                                            if data.iter().all(|&b| {
                                                b.is_ascii_graphic() || b.is_ascii_whitespace()
                                            }) {
                                                let data_str = String::from_utf8_lossy(&data);
                                                let preview =
                                                    crate::utils::truncate_for_log(&data_str, 100);
                                                log.debug(format!(
                                                    "Socket file received {} bytes on {}: {}",
                                                    n, connection_id, preview
                                                ));
                                                log.trace(format!(
                                                    "Socket file data (text): {:?}",
                                                    data_str
                                                ));
                                            } else {
                                                log.debug(format!(
                                                "Socket file received {} bytes on {} (binary data)",
                                                n, connection_id
                                            ));
                                                log.trace(format!(
                                                    "Socket file data (hex): {}",
                                                    hex::encode(&data)
                                                ));
                                            }

                                            // Into the connection's state machine here, in the
                                            // order the reads arrived: either it starts an
                                            // answer, or it waits behind the one in flight.
                                            // Deciding that in a task spawned per read let two
                                            // tasks race for it — a later read could start its
                                            // answer first, or two reads could both find the
                                            // connection Idle and be answered at once — and
                                            // either way replies went out in the wrong order.
                                            let batching = app_state_clone
                                                .server_conversation_settings(server_id)
                                                .await
                                                .is_some_and(|(_, batching)| batching);
                                            let start = Self::admit_read(
                                                connection_id,
                                                server_id,
                                                &data,
                                                batching,
                                                &app_state_clone,
                                                &status_tx_clone,
                                                &connections_clone,
                                            )
                                            .await;

                                            // Feeds the dashboard rail's counters and refreshes
                                            // `last_activity`; this protocol never called it, so a
                                            // live connection read 0B/0B in the tree forever.
                                            // Counted once the read is in the state machine, so a
                                            // count that includes it means it is queued or being
                                            // answered.
                                            app_state_clone
                                                .update_connection_stats(
                                                    server_id,
                                                    connection_id,
                                                    Some(n as u64),
                                                    None,
                                                    Some(1),
                                                    None,
                                                )
                                                .await;

                                            let Some(payload) = start else {
                                                continue;
                                            };

                                            // The answer runs in its own task so the loop can
                                            // go back to reading: what arrives meanwhile is
                                            // queued behind it by `admit_read`.
                                            let llm_clone = llm_client_clone.clone();
                                            let state_clone = app_state_clone.clone();
                                            let status_clone = status_tx_clone.clone();
                                            let conns_clone = connections_clone.clone();
                                            let protocol_clone = protocol_clone.clone();
                                            // Busy for the whole of the answer — the LLM call,
                                            // a script, or a `manual` rule parked for a human —
                                            // so the read deadline cannot close the connection
                                            // this is an answer for.
                                            let busy = activity_clone.busy();
                                            // Tracked, not detached: stop_server must abort this task too.
                                            let task_owner = app_state_clone.clone();
                                            task_owner
                                                .spawn_server_task(server_id, async move {
                                                    let _busy = busy;
                                                    Self::answer(
                                                        connection_id,
                                                        server_id,
                                                        payload,
                                                        batching,
                                                        llm_clone,
                                                        state_clone,
                                                        status_clone,
                                                        conns_clone,
                                                        protocol_clone,
                                                    )
                                                    .await;
                                                })
                                                .await;
                                        }
                                        Err(e) => {
                                            Log::new(Some(&status_tx_clone)).error(format!(
                                                "Read error on socket file connection {}: {}",
                                                connection_id, e
                                            ));
                                            connections_clone.lock().await.remove(&connection_id);
                                            break;
                                        }
                                    }
                                }
                            })
                            .await;
                    }
                    Err(e) => {
                        Log::new(Some(&status_tx))
                            .error(format!("Accept error on socket file: {}", e));
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

    /// Send the greeting banner for a new connection (`send_first` servers only), then answer
    /// whatever the peer sent while it was being composed.
    ///
    /// The connection is already registered by the accept loop by the time this runs, in
    /// `Processing`, so reads queue behind the banner rather than being answered ahead of it.
    #[allow(clippy::too_many_arguments)]
    async fn send_banner(
        connection_id: ConnectionId,
        server_id: crate::state::ServerId,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        connections: Arc<Mutex<HashMap<ConnectionId, ConnectionData>>>,
        write_half: Arc<Mutex<tokio::io::WriteHalf<UnixStream>>>,
        protocol: Arc<SocketFileProtocol>,
    ) {
        {
            let log = Log::new(Some(&status_tx));
            // Create connection opened event
            let event = Event::new(&SOCKET_FILE_CONNECTION_OPENED_EVENT, serde_json::json!({}));

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
                    debug!("LLM socket file banner response received");

                    // Display messages
                    for msg in execution_result.messages {
                        let _ = status_tx.send(msg);
                    }

                    // Handle protocol results (send banner)
                    let mut wrote_banner = false;
                    for protocol_result in execution_result.protocol_results {
                        match protocol_result {
                            ActionResult::Output(output_data) => {
                                let mut write = write_half.lock().await;
                                if let Err(e) = write.write_all(&output_data).await {
                                    log.error(format!("Failed to send socket file banner: {}", e));
                                } else {
                                    app_state
                                        .update_connection_stats(
                                            server_id,
                                            connection_id,
                                            None,
                                            Some(output_data.len() as u64),
                                            None,
                                            Some(1),
                                        )
                                        .await;
                                    // Sent-data summary + payload are FileOnly: the
                                    // send_socket_data action template already reports the
                                    // send to the TUI.
                                    if output_data
                                        .iter()
                                        .all(|&b| b.is_ascii_graphic() || b.is_ascii_whitespace())
                                    {
                                        let data_str = String::from_utf8_lossy(&output_data);
                                        let preview =
                                            crate::utils::truncate_for_log(&data_str, 100);
                                        log.debug(format!(
                                            "Socket file sent {} bytes to {}: {}",
                                            output_data.len(),
                                            connection_id,
                                            preview
                                        ));
                                        log.trace(format!(
                                            "Socket file sent (text): {:?}",
                                            data_str
                                        ));
                                    } else {
                                        log.debug(format!(
                                            "Socket file sent {} bytes to {} (binary data)",
                                            output_data.len(),
                                            connection_id
                                        ));
                                        log.trace(format!(
                                            "Socket file sent (hex): {}",
                                            hex::encode(&output_data)
                                        ));
                                    }
                                    log.debug(format!(
                                        "Sent banner to socket file connection {connection_id}"
                                    ));
                                    wrote_banner = true;
                                }
                            }
                            ActionResult::CloseConnection => {
                                connections.lock().await.remove(&connection_id);
                                log.info(format!(
                                    "Closed socket file connection {connection_id} after banner: decision=model_close"
                                ));
                            }
                            _ => {}
                        }
                    }

                    // Greeting with nothing is a legitimate answer, not a failure —
                    // keep it distinguishable in the log from the two below.
                    if !wrote_banner {
                        log.debug(format!(
                            "No banner bytes for socket file connection {connection_id}: decision=model_no_actions"
                        ));
                    }
                }
                Err(e) => {
                    let failure = crate::utils::WireFailure::classify(&e);
                    let class = if failure.is_overloaded() {
                        "overloaded"
                    } else {
                        "unavailable"
                    };
                    // The full error goes to the log and the status stream, where an
                    // operator looks. Nothing derived from it reaches the peer.
                    log.warn(format!(
                        "Socket file banner failed for {connection_id}: decision=fail_closed_llm_error class={class} error={e}"
                    ));

                    // A send_first server owes this peer a greeting and now has none.
                    // A raw byte stream has no error frame, so the only honest signal is
                    // FIN: half-close so the peer's next read returns EOF immediately
                    // instead of blocking until its own timeout. Same shape as `tcp`.
                    {
                        let mut write = write_half.lock().await;
                        let _ = write.shutdown().await;
                    }
                    connections.lock().await.remove(&connection_id);
                    app_state
                        .close_connection_on_server(server_id, connection_id)
                        .await;
                    log.info(format!(
                        "Closed socket file connection {connection_id} after banner LLM error"
                    ));
                }
            }
        }

        // Hand over whatever the peer sent while the banner was being composed. The connection
        // was registered `Processing` for exactly this: those reads queued behind the banner
        // instead of starting an answer that could reach the peer ahead of it. Taken and left
        // `Processing` under one lock, or the reader could find the connection `Idle` in
        // between and start an answer for a later read ahead of these. A connection the banner
        // closed is gone from the map, and nothing is answered.
        let batching = app_state
            .server_conversation_settings(server_id)
            .await
            .is_some_and(|(_, batching)| batching);
        let queued = {
            let mut conns = connections.lock().await;
            let Some(conn) = conns.get_mut(&connection_id) else {
                return;
            };
            conn.reads.next_or_idle(batching)
        };
        if let Some(queued) = queued {
            Self::answer(
                connection_id,
                server_id,
                Bytes::from(queued),
                batching,
                llm_client,
                app_state,
                status_tx,
                connections,
                protocol,
            )
            .await;
        }
    }

    /// Close a connection whose queue passed [`MAX_QUEUED_BYTES`]: shut the write half so the
    /// peer reads EOF now instead of waiting on an answer that is never coming.
    #[allow(clippy::too_many_arguments)]
    async fn close_for_queue_overflow(
        connection_id: ConnectionId,
        server_id: crate::state::ServerId,
        queued_len: usize,
        when: &str,
        write_half: &Arc<Mutex<tokio::io::WriteHalf<UnixStream>>>,
        connections: &Arc<Mutex<HashMap<ConnectionId, ConnectionData>>>,
        app_state: &Arc<AppState>,
        status_tx: &mpsc::UnboundedSender<String>,
    ) {
        Log::new(Some(status_tx)).warn(format!(
            "Socket file connection {connection_id} queued {queued_len} bytes {when} (limit \
             {MAX_QUEUED_BYTES}); closing: decision=queue_overflow"
        ));
        {
            let mut write = write_half.lock().await;
            let _ = write.shutdown().await;
        }
        connections.lock().await.remove(&connection_id);
        app_state
            .close_connection_on_server(server_id, connection_id)
            .await;
        let _ = status_tx.send("__UPDATE_UI__".to_string());
    }

    /// Take one read into the connection's state machine, in the order the reader got it.
    ///
    /// Returns the payload of the answer this read starts, or `None` when it waits behind the
    /// answer already in flight (or the connection has gone, or was closed for queueing too
    /// much). Called by the reader itself, never from a spawned task: the decision has to be
    /// made in arrival order and under one lock. When each read's task made it, two reads could
    /// both find the connection `Idle` and be answered concurrently, and a later read's task
    /// could run first — its reply then went out ahead of the earlier one's.
    async fn admit_read(
        connection_id: ConnectionId,
        server_id: crate::state::ServerId,
        data: &[u8],
        batching: bool,
        app_state: &Arc<AppState>,
        status_tx: &mpsc::UnboundedSender<String>,
        connections: &Arc<Mutex<HashMap<ConnectionId, ConnectionData>>>,
    ) -> Option<Bytes> {
        let (queued_len, write_half) = {
            let mut conns = connections.lock().await;
            let Some(conn) = conns.get_mut(&connection_id) else {
                // Never silent. A miss here means the connection was torn down after the read
                // (peer reset, or close_this_connection on the answering task) - legitimate,
                // but indistinguishable from a registration race, which is exactly what made
                // the bitcoin accept-order bug so hard to find: the read loop logged "received
                // N bytes" and then nothing at all.
                debug!(
                    "socket-file connection {} is no longer registered; dropping {} received bytes",
                    connection_id,
                    data.len()
                );
                return None;
            };
            match conn.reads.admit(data, batching) {
                Admitted::Start(payload) => return Some(Bytes::from(payload)),
                // An answer is in flight: queued behind it — up to MAX_QUEUED_BYTES.
                Admitted::Queued(queued_len) => (queued_len, conn.write_half.clone()),
            }
        };
        if queued_len > MAX_QUEUED_BYTES {
            Self::close_for_queue_overflow(
                connection_id,
                server_id,
                queued_len,
                "while awaiting a response",
                &write_half,
                connections,
                app_state,
                status_tx,
            )
            .await;
            return None;
        }
        Log::new(Some(status_tx)).debug(format!(
            "Queued {} bytes for socket file connection {} ({} queued)",
            data.len(),
            connection_id,
            queued_len
        ));
        None
    }

    /// Answer `payload` on a connection [`Self::admit_read`] has moved to `Processing`, then
    /// everything queued behind it, oldest first, until the queue is empty.
    ///
    /// One of these runs per connection at a time: only the move into `Processing` starts one,
    /// and it leaves `Processing` only when it ends.
    #[allow(clippy::too_many_arguments)]
    async fn answer(
        connection_id: ConnectionId,
        server_id: crate::state::ServerId,
        payload: Bytes,
        batching: bool,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        connections: Arc<Mutex<HashMap<ConnectionId, ConnectionData>>>,
        protocol: Arc<SocketFileProtocol>,
    ) {
        let log = Log::new(Some(&status_tx));
        let mut all_data = payload;

        loop {
            // Get write_half for context
            let write_half = {
                let conns = connections.lock().await;
                conns.get(&connection_id).map(|c| c.write_half.clone())
            };

            let Some(write_half) = write_half else {
                debug!(
                    "socket-file connection {} went away before its response could be written",
                    connection_id
                );
                return;
            };

            // Format data for event parameter. Printable ASCII is passed through as text,
            // anything else is hex-encoded. `encoding` tells the LLM which one it got, so it
            // can echo the payload back with a matching `encoding` on send_socket_data.
            let (data_str, data_encoding) = if all_data
                .iter()
                .all(|&b| b.is_ascii_graphic() || b.is_ascii_whitespace())
            {
                (String::from_utf8_lossy(&all_data).to_string(), "utf8")
            } else {
                (hex::encode(&all_data), "hex")
            };

            // Create data received event
            let event = Event::new(
                &SOCKET_FILE_DATA_RECEIVED_EVENT,
                serde_json::json!({
                    "data": data_str,
                    "encoding": data_encoding
                }),
            );

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
                    debug!("LLM socket file response received");

                    // Display messages
                    for msg in execution_result.messages {
                        let _ = status_tx.send(msg);
                    }

                    // Handle protocol results
                    let mut should_close = false;
                    let mut should_wait = false;
                    let mut wrote_output = false;

                    for protocol_result in execution_result.protocol_results {
                        match protocol_result {
                            ActionResult::Output(output_data) => {
                                let mut write = write_half.lock().await;
                                if let Err(e) = write.write_all(&output_data).await {
                                    log.error(format!(
                                        "Failed to send socket file response: {}",
                                        e
                                    ));
                                } else {
                                    app_state
                                        .update_connection_stats(
                                            server_id,
                                            connection_id,
                                            None,
                                            Some(output_data.len() as u64),
                                            None,
                                            Some(1),
                                        )
                                        .await;
                                    // Sent-data summary + payload are FileOnly: the
                                    // send_socket_data action template already reports the
                                    // send to the TUI.
                                    if output_data
                                        .iter()
                                        .all(|&b| b.is_ascii_graphic() || b.is_ascii_whitespace())
                                    {
                                        let data_str = String::from_utf8_lossy(&output_data);
                                        let preview =
                                            crate::utils::truncate_for_log(&data_str, 100);
                                        log.debug(format!(
                                            "Socket file sent {} bytes to {}: {}",
                                            output_data.len(),
                                            connection_id,
                                            preview
                                        ));
                                        log.trace(format!(
                                            "Socket file sent (text): {:?}",
                                            data_str
                                        ));
                                    } else {
                                        log.debug(format!(
                                            "Socket file sent {} bytes to {} (binary data)",
                                            output_data.len(),
                                            connection_id
                                        ));
                                        log.trace(format!(
                                            "Socket file sent (hex): {}",
                                            hex::encode(&output_data)
                                        ));
                                    }
                                    log.debug(format!(
                                        "Sent {} bytes to socket file connection {}",
                                        output_data.len(),
                                        connection_id
                                    ));
                                    wrote_output = true;
                                }
                            }
                            ActionResult::CloseConnection => {
                                should_close = true;
                            }
                            ActionResult::WaitForMore => {
                                should_wait = true;
                            }
                            _ => {}
                        }
                    }

                    // Handle wait_for_more.
                    //
                    // The fragment the model was just shown goes back to the *head* of the
                    // queue, ahead of anything that arrived during the call, as one payload:
                    // `wait_for_more` means "these bytes are an incomplete message", so they
                    // must be shown again with whatever completes them. The same as `tcp`.
                    if should_wait {
                        // Bytes that arrived while the model was thinking *are* the "more" it
                        // asked for, and parking them would wait for a read that may never come.
                        // So `hold_for_more` hands the joined payload straight back, still
                        // `Processing`, in the same step that would otherwise have parked it.
                        let held = {
                            let mut conns = connections.lock().await;
                            let Some(conn) = conns.get_mut(&connection_id) else {
                                return;
                            };
                            conn.reads.hold_for_more(&all_data)
                        };
                        let queued_len = held.len();

                        // Same bound as the Processing queue: a model that answers
                        // `wait_for_more` to everything must not be a way to grow memory
                        // without limit either.
                        if queued_len > MAX_QUEUED_BYTES {
                            Self::close_for_queue_overflow(
                                connection_id,
                                server_id,
                                queued_len,
                                "across wait_for_more",
                                &write_half,
                                &connections,
                                &app_state,
                                &status_tx,
                            )
                            .await;
                            return;
                        }

                        if let Held::Resume(joined) = held {
                            log.debug(format!(
                                "wait_for_more on socket file connection {connection_id}: {} \
                                 bytes already waiting, continuing",
                                joined.len()
                            ));
                            all_data = Bytes::from(joined);
                            continue;
                        }

                        log.debug(format!(
                            "Waiting for more data from socket file connection {connection_id} \
                             ({queued_len} bytes held)"
                        ));
                        return;
                    }

                    // Handle close_connection
                    if should_close {
                        connections.lock().await.remove(&connection_id);
                        // The model answered by hanging up — distinct in the log from
                        // "answered nothing" and from an LLM failure.
                        log.info(format!(
                            "Closed socket file connection {connection_id}: decision=model_close"
                        ));
                        return;
                    }

                    // The model answered, but with no bytes and no lifecycle action. On a
                    // raw byte stream that is a legitimate answer ("say nothing, keep
                    // listening"), so the connection stays open — but it must not be
                    // confused with the backend having failed.
                    if !wrote_output {
                        log.debug(format!(
                            "No response bytes for socket file connection {connection_id}: decision=model_no_actions"
                        ));
                    }

                    // Take the queue's next payload, or go Idle when it is empty — under one
                    // lock. Checked and set separately, a read queued in between (the
                    // connection still `Processing`) was stranded by the move to `Idle` until
                    // the peer happened to send something else.
                    //
                    // Taken, not peeked: leaving it in place re-sent the SAME bytes to the
                    // model on every pass and never emptied the queue — one response per
                    // iteration, forever, for a single line of input.
                    let queued = {
                        let mut conns = connections.lock().await;
                        let Some(conn) = conns.get_mut(&connection_id) else {
                            return;
                        };
                        conn.reads.next_or_idle(batching)
                    };
                    let Some(queued) = queued else {
                        return;
                    };
                    all_data = Bytes::from(queued);
                }
                Err(e) => {
                    let failure = crate::utils::WireFailure::classify(&e);
                    let class = if failure.is_overloaded() {
                        "overloaded"
                    } else {
                        "unavailable"
                    };
                    // Full error to the log/status stream only — never to the peer.
                    log.warn(format!(
                        "LLM error for socket file data on {connection_id}: decision=fail_closed_llm_error class={class} error={e}"
                    ));
                    if failure.is_overloaded() {
                        log.warn(format!(
                            "Socket file connection {connection_id} closed: LLM capacity exhausted"
                        ));
                    }

                    // Say *something* on the wire. A raw byte stream has no error frame,
                    // so the only honest signal is FIN: half-close the connection so the
                    // peer's next read returns EOF immediately. This path used to reset
                    // to Idle and write nothing, leaving the peer blocked until its own
                    // timeout with no indication anything had gone wrong.
                    {
                        let mut write = write_half.lock().await;
                        let _ = write.shutdown().await;
                    }
                    connections.lock().await.remove(&connection_id);
                    app_state
                        .close_connection_on_server(server_id, connection_id)
                        .await;
                    log.info(format!(
                        "Closed socket file connection {connection_id} after LLM error"
                    ));
                    return;
                }
            }
        }
    }
}
