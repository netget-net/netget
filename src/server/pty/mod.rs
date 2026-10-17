//! Pseudo-terminal (PTY) server implementation.
//!
//! Platform: Unix/Linux/macOS only. The server allocates a PTY with `openpty`, holds the master,
//! and role-plays a program with a terminal: it reads what a terminal program types on the slave
//! (`pty_input_received`), and the model decides the bytes that appear on the terminal
//! (`write_pty_output`). A real client is any terminal program that opens the slave device.
#![cfg(unix)]

pub mod actions;

use anyhow::{Context, Result};
use std::ffi::OsStr;
use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::{FromRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc;
use tracing::{error, info};

use crate::llm::action_helper::call_llm_batch;
use crate::llm::ollama_client::OllamaClient;
use crate::llm::ActionResult;
use crate::logging::emit::Log;
use crate::protocol::Event;
use crate::server::pty::actions::{PtyProtocol, PTY_INPUT_RECEIVED_EVENT, PTY_OPENED_EVENT};
use crate::state::app_state::AppState;
use crate::utils::WireFailure;

/// Removes the slave symlink this server created when the read task ends — including on abort by
/// `stop_server`, because aborting drops the task future and with it this guard.
struct LinkCleanup(Option<PathBuf>);

impl Drop for LinkCleanup {
    fn drop(&mut self) {
        if let Some(p) = &self.0 {
            let _ = std::fs::remove_file(p);
        }
    }
}

/// Resolve the filesystem path of the slave PTY device from its fd, portably (Linux and macOS).
fn slave_device_path(slave_fd: RawFd) -> Result<PathBuf> {
    let mut buf = vec![0u8; 256];
    // ttyname_r returns 0 on success, or an errno value.
    let rc = unsafe { libc::ttyname_r(slave_fd, buf.as_mut_ptr() as *mut libc::c_char, buf.len()) };
    if rc != 0 {
        return Err(std::io::Error::from_raw_os_error(rc))
            .context("ttyname_r failed to resolve slave PTY device path");
    }
    let cstr = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr() as *const libc::c_char) };
    Ok(PathBuf::from(OsStr::from_bytes(cstr.to_bytes())))
}

/// Point `link` at `target` as a symlink, refusing to clobber a non-symlink.
///
/// `link_path` comes from the model or an MCP caller, so a pre-existing symlink is replaced but a
/// regular file/dir at that path is refused rather than deleted — the same guard shape as
/// `socket_file`'s stale-socket handling.
fn ensure_symlink(link: &Path, target: &Path) -> Result<()> {
    match std::fs::symlink_metadata(link) {
        Ok(meta) => {
            if meta.file_type().is_symlink() {
                std::fs::remove_file(link)
                    .with_context(|| format!("Failed to replace existing symlink {:?}", link))?;
            } else {
                anyhow::bail!(
                    "Refusing to use link_path {:?}: it exists and is not a symlink. Delete it \
                     yourself or pass a different link_path.",
                    link
                );
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).with_context(|| format!("Failed to stat {:?}", link)),
    }
    std::os::unix::fs::symlink(target, link)
        .with_context(|| format!("Failed to symlink {:?} -> {:?}", link, target))
}

/// Put the slave PTY into raw mode: no echo and no canonical line buffering, so the model owns the
/// exact byte stream in both directions (nothing echoes back to the master, and bytes flow without
/// waiting for a newline). Uses libc directly (nix is a dev-only dependency here).
fn set_slave_raw(slave_fd: RawFd) -> Result<()> {
    unsafe {
        let mut termios: libc::termios = std::mem::zeroed();
        if libc::tcgetattr(slave_fd, &mut termios) != 0 {
            return Err(std::io::Error::last_os_error()).context("tcgetattr on slave PTY failed");
        }
        libc::cfmakeraw(&mut termios);
        if libc::tcsetattr(slave_fd, libc::TCSANOW, &termios) != 0 {
            return Err(std::io::Error::last_os_error()).context("tcsetattr on slave PTY failed");
        }
    }
    Ok(())
}

/// Set O_NONBLOCK on `fd` so it can be driven by tokio's `AsyncFd`.
fn set_nonblocking(fd: RawFd) -> Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error()).context("fcntl F_GETFL on PTY master failed");
    }
    let rc = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    if rc < 0 {
        return Err(std::io::Error::last_os_error()).context("fcntl F_SETFL on PTY master failed");
    }
    Ok(())
}

/// How many reads from the PTY master may wait while the model answers an earlier one.
///
/// Each is at most one 8 KiB read, so the queue holds at most 256 KiB; past it the reader stops
/// reading and the terminal's input queue holds the writer back. It equals the batch cap, so
/// one batching call can take everything that is waiting.
const READ_QUEUE_CHUNKS: usize = crate::protocol::metadata::MAX_BATCH_EVENTS;

/// Register this server's session as the one connection it has, so the core keeps the
/// per-connection history the protocol declares (`AppState::record_access_log` records only for
/// a connection the server holds) and the dashboard shows a peer row for it.
///
/// There is no IP address on either side, so both addresses are the `127.0.0.1:0` placeholder
/// `socket_file` uses; `protocol_info` names the endpoint instead.
async fn register_session(
    app_state: &AppState,
    server_id: crate::state::ServerId,
    info: serde_json::Value,
) -> crate::server::connection::ConnectionId {
    use crate::state::server::{ConnectionState, ConnectionStatus, ProtocolConnectionInfo};
    let id = crate::server::connection::ConnectionId::new(app_state.get_next_unified_id().await);
    let now = crate::utils::clock::Instant::now();
    let addr: std::net::SocketAddr = ([127, 0, 0, 1], 0).into();
    app_state
        .add_connection_to_server(
            server_id,
            ConnectionState {
                id,
                remote_addr: addr,
                local_addr: addr,
                bytes_sent: 0,
                bytes_received: 0,
                packets_sent: 0,
                packets_received: 0,
                last_activity: now,
                status: ConnectionStatus::Active,
                status_changed_at: now,
                protocol_info: ProtocolConnectionInfo::new(info),
            },
        )
        .await;
    id
}

/// Pseudo-terminal server.
pub struct PtyServer;

impl PtyServer {
    /// Allocate the PTY, wire up the master, and spawn the read/dispatch loop.
    ///
    /// Awaits readiness (PTY allocated, slave configured, symlink created, master registered) and
    /// returns `Err` on any failure, so `server_startup` records `ServerStatus::Error`.
    pub async fn spawn_with_llm_actions(
        link_path: Option<PathBuf>,
        send_first: bool,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        server_id: crate::state::ServerId,
    ) -> Result<()> {
        // Allocate the PTY with libc::openpty (nix is a dev-only dependency in this crate).
        let (master_raw, slave_raw) = unsafe {
            let mut master: libc::c_int = -1;
            let mut slave: libc::c_int = -1;
            if libc::openpty(
                &mut master,
                &mut slave,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            ) != 0
            {
                return Err(std::io::Error::last_os_error()).context("openpty failed");
            }
            (master, slave)
        };
        // Own both descriptors before any fallible setup. In particular, refusing an
        // existing regular file at link_path must not leak the already-open master.
        let master_file = unsafe { File::from_raw_fd(master_raw) };
        // Own the slave fd so it is closed on drop; holding it open keeps the master from
        // returning EIO when a terminal client detaches.
        let slave_fd = unsafe { OwnedFd::from_raw_fd(slave_raw) };

        set_slave_raw(slave_raw)?;

        let slave_path = slave_device_path(slave_raw)?;
        info!("PTY allocated, slave device {:?}", slave_path);

        if let Some(link) = &link_path {
            ensure_symlink(link, &slave_path)?;
            info!("PTY slave symlinked at {:?}", link);
        }
        let cleanup = LinkCleanup(link_path.clone());

        // Master fd: make nonblocking and hand to a std File / AsyncFd.
        set_nonblocking(master_raw)?;
        let async_master = AsyncFd::new(master_file)
            .context("Failed to register PTY master with the async runtime")?;

        Log::new(Some(&status_tx)).info(format!(
            "PTY server ready, slave device {}",
            slave_path.to_string_lossy()
        ));

        let protocol = Arc::new(PtyProtocol::new());
        let task_registrar = app_state.clone();

        // One session for the server's lifetime. The server holds the slave open itself (so the
        // master never sees EIO), which also means it cannot tell one terminal program attaching
        // from the next: there is no per-client event to key a finer session on.
        let connection_id = register_session(
            &app_state,
            server_id,
            serde_json::json!({ "slave_path": slave_path.to_string_lossy() }),
        )
        .await;
        let _ = status_tx.send("__UPDATE_UI__".to_string());
        // Shared by the reader (reads) and the dispatcher (writes the model's output).
        let async_master = Arc::new(async_master);

        // The reader runs on its own so that input typed while the model is answering is read
        // as it arrives — each read keeping its own boundary — rather than piling up in the
        // PTY's buffer until the call returns. The bounded channel is the backpressure: once
        // it holds `READ_QUEUE_CHUNKS` chunks the reader stops reading and the terminal's own
        // input queue holds the rest, which is what a busy program does to a typist.
        let (chunk_tx, mut chunk_rx) = mpsc::channel::<Vec<u8>>(READ_QUEUE_CHUNKS);
        let reader_master = Arc::clone(&async_master);
        let reader = app_state
            .spawn_server_task(server_id, async move {
                let mut buffer = vec![0u8; 8192];
                loop {
                    let mut guard = match reader_master.readable().await {
                        Ok(g) => g,
                        Err(e) => {
                            error!("PTY master readable() error: {}", e);
                            break;
                        }
                    };

                    let read_result = guard.try_io(|inner| inner.get_ref().read(&mut buffer));

                    let n = match read_result {
                        Ok(Ok(0)) => {
                            // With the slave fd held open this should not occur.
                            // `clear_ready()` is what makes `continue` safe: `try_io` only drops
                            // the cached readiness when the closure reports WouldBlock, so
                            // continuing on any *other* outcome leaves readiness set,
                            // `readable()` returns instantly and the loop pins a core. Clearing
                            // it means the next pass really waits on the fd.
                            guard.clear_ready();
                            continue;
                        }
                        Ok(Ok(n)) => n,
                        Ok(Err(e)) => {
                            // EIO here means no slave is currently attached; treat other errors
                            // as fatal.
                            if e.raw_os_error() == Some(libc::EIO) {
                                guard.clear_ready();
                                continue;
                            }
                            error!("PTY master read error: {}", e);
                            break;
                        }
                        Err(_would_block) => continue,
                    };
                    if chunk_tx.send(buffer[..n].to_vec()).await.is_err() {
                        break;
                    }
                }
            })
            .await;

        let handle = tokio::spawn(async move {
            // Keep the slave fd open for the whole session: it prevents the master from returning
            // EIO when a terminal client detaches, so clients can come and go without ending the
            // server. Moved in here so it drops on abort. The cleanup guard unlinks the symlink.
            let _slave_fd = slave_fd;
            let _cleanup = cleanup;

            // send_first: give the model a chance to print a banner/prompt on connect.
            if send_first {
                let event = Event::new(
                    &PTY_OPENED_EVENT,
                    serde_json::json!({ "slave_path": slave_path.to_string_lossy() }),
                );
                Self::dispatch(
                    std::slice::from_ref(&event),
                    connection_id,
                    &async_master,
                    &llm_client,
                    &app_state,
                    server_id,
                    protocol.as_ref(),
                    &status_tx,
                )
                .await;
            }

            while let Some(first) = chunk_rx.recv().await {
                // With batching on, every read that arrived while the model was answering the
                // previous one is answered in one call; with it off, one read per call.
                let batching = app_state
                    .server_conversation_settings(server_id)
                    .await
                    .is_some_and(|(_, batching)| batching);
                let mut chunks = vec![first];
                while batching && chunks.len() < crate::protocol::metadata::MAX_BATCH_EVENTS {
                    match chunk_rx.try_recv() {
                        Ok(chunk) => chunks.push(chunk),
                        Err(_) => break,
                    }
                }

                let mut events = Vec::with_capacity(chunks.len());
                for data in &chunks {
                    let (data_str, encoding) = if data
                        .iter()
                        .all(|&b| b.is_ascii_graphic() || b.is_ascii_whitespace())
                    {
                        (String::from_utf8_lossy(data).to_string(), "utf8")
                    } else {
                        (hex::encode(data), "hex")
                    };

                    Log::new(Some(&status_tx)).debug(format!(
                        "PTY received {} bytes of input ({})",
                        data.len(),
                        encoding
                    ));

                    app_state
                        .update_connection_stats(
                            server_id,
                            connection_id,
                            Some(data.len() as u64),
                            None,
                            Some(1),
                            None,
                        )
                        .await;

                    events.push(Event::new(
                        &PTY_INPUT_RECEIVED_EVENT,
                        serde_json::json!({ "data": data_str, "encoding": encoding }),
                    ));
                }
                Self::dispatch(
                    &events,
                    connection_id,
                    &async_master,
                    &llm_client,
                    &app_state,
                    server_id,
                    protocol.as_ref(),
                    &status_tx,
                )
                .await;
            }
            reader.abort();
            // The reader has ended, so the session has: its history goes with it. (On
            // stop_server the whole server, history included, is removed instead.)
            app_state
                .remove_connection_from_server(server_id, connection_id)
                .await;
            let _ = status_tx.send("__UPDATE_UI__".to_string());
        });

        task_registrar.register_server_task(server_id, handle).await;
        Ok(())
    }

    /// Run one LLM round-trip for `events` (one, or a batch that arrived during the previous
    /// call) and write any produced output onto the PTY master.
    #[allow(clippy::too_many_arguments)]
    async fn dispatch(
        events: &[Event],
        connection_id: crate::server::connection::ConnectionId,
        async_master: &AsyncFd<File>,
        llm_client: &OllamaClient,
        app_state: &Arc<AppState>,
        server_id: crate::state::ServerId,
        protocol: &PtyProtocol,
        status_tx: &mpsc::UnboundedSender<String>,
    ) {
        // The newest event names the batch in the log; it is the trigger the model answers.
        let Some(event) = events.last() else {
            return;
        };
        match call_llm_batch(
            llm_client,
            app_state,
            server_id,
            Some(connection_id),
            events,
            protocol,
        )
        .await
        {
            Ok(result) => {
                for msg in result.messages {
                    let _ = status_tx.send(msg);
                }
                let mut wrote = 0usize;
                for pr in result.protocol_results {
                    if let ActionResult::Output(bytes) = pr {
                        wrote += 1;
                        Self::write_master(async_master, &bytes, status_tx).await;
                        app_state
                            .update_connection_stats(
                                server_id,
                                connection_id,
                                None,
                                Some(bytes.len() as u64),
                                None,
                                Some(1),
                            )
                            .await;
                    }
                    // CloseConnection / WaitForMore are meaningless for a PTY and are ignored.
                }
                // "The model deliberately printed nothing" is a legitimate answer on a terminal —
                // a program need not emit a byte for every keystroke — so nothing is written here.
                // It is logged with its own tag so it stays distinguishable from an LLM failure.
                if wrote == 0 {
                    info!(
                        "PTY {} decision=model_no_output",
                        event.event_type.id.as_str()
                    );
                }
            }
            Err(e) => {
                // The backend failed. The terminal gets a *category* only; the error itself goes
                // to the log and the status stream, never onto the wire (see utils/wire_failure).
                let failure = WireFailure::classify(&e);
                let decision = if failure.is_overloaded() {
                    "fail_closed_overloaded"
                } else {
                    "fail_closed_llm_error"
                };
                error!(
                    "PTY {} decision={} error={}",
                    event.event_type.id.as_str(),
                    decision,
                    e
                );
                Log::new(Some(status_tx))
                    .error(format!("PTY LLM error (decision={decision}): {e}"));
                // CRLF on both sides: cfmakeraw clears ONLCR, so a bare LF would staircase on a
                // real terminal, and the leading CRLF keeps the notice off whatever half-typed
                // line the user is looking at.
                let notice = format!("\r\n[{}]\r\n", failure.prefixed_text());
                Self::write_master(async_master, notice.as_bytes(), status_tx).await;
            }
        }
    }

    /// Write `bytes` to the PTY master (they appear to the terminal program reading the slave).
    async fn write_master(
        async_master: &AsyncFd<File>,
        bytes: &[u8],
        status_tx: &mpsc::UnboundedSender<String>,
    ) {
        let mut written = 0;
        while written < bytes.len() {
            let mut guard = match async_master.writable().await {
                Ok(g) => g,
                Err(e) => {
                    Log::new(Some(status_tx)).error(format!("PTY write error: {e}"));
                    return;
                }
            };
            match guard.try_io(|inner| inner.get_ref().write(&bytes[written..])) {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => written += n,
                Ok(Err(e)) => {
                    Log::new(Some(status_tx)).error(format!("PTY write error: {e}"));
                    return;
                }
                Err(_would_block) => continue,
            }
        }
        // FileOnly: the write_pty_output action's own log_template already reports
        // "-> PTY {data_len}B" to the TUI at INFO.
        Log::new(Some(status_tx)).debug(format!("PTY wrote {} bytes to terminal", written));
    }
}
