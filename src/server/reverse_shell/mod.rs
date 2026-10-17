//! Reverse-shell listener server.
//!
//! A raw-TCP listener that **emulates** the operator side of a reverse shell for authorized
//! security testing, CTF and lab use. An operator connects back to this listener with a plain
//! TCP client (`nc`, `socat`, `ncat`), and the LLM role-plays the shell on the far end: it
//! decides the banner, each command's output and the prompt.
//!
//! Safety: NetGet does **not** execute the operator's commands on this host. Every byte the
//! operator sees is fictional output supplied by the model — the same premise as every other
//! NetGet protocol (impersonating a service without being one). Real command execution is only
//! reachable through the separate, opt-in, unsandboxed scripting layer documented in the
//! top-level `CLAUDE.md`; this protocol never touches it. See `src/server/reverse_shell/CLAUDE.md`.
//!
//! Wire model: there is no framing. The listener reads raw bytes, buffers them into
//! newline-terminated lines, and raises one `reverse_shell_command` event per line. One
//! connection is handled strictly sequentially — the model call for one line finishes before the
//! next line is read — so there is never a concurrent LLM call on a single connection, and input
//! that arrives mid-call sits in the socket buffer until the call returns.

pub mod actions;

use crate::llm::action_helper::call_llm_batch;
use crate::llm::actions::protocol_trait::ActionResult;
use crate::llm::ollama_client::OllamaClient;
use crate::protocol::Event;
use crate::server::connection::ConnectionId;
use crate::state::app_state::AppState;
use crate::state::server::{ConnectionState, ConnectionStatus, ProtocolConnectionInfo};
use crate::{console_debug, console_info, console_warn};
use actions::{
    ReverseShellProtocol, REVERSE_SHELL_COMMAND_EVENT, REVERSE_SHELL_SESSION_OPENED_EVENT,
};
use anyhow::Result;
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, error, info, warn};

/// Largest single line accepted from the operator, in bytes.
///
/// The line accumulator grows until a newline arrives; without a cap a peer that never sends one
/// could grow it without bound. A command line far longer than this is not a real shell command.
pub const MAX_LINE_LEN: usize = 64 * 1024;

/// Reverse-shell listener.
/// How long to wait for the first command from an operator who has only connected.
///
/// Two minutes rather than a machine protocol's thirty seconds, because the peer here is a
/// person at `nc`: the session opens with a model-written banner and prompt, and they read it
/// before typing. The banner sits outside this deadline by construction — it is generated and
/// written before the read loop starts — so this bound measures only the time from a prompt
/// being on their screen to the first key.
const FIRST_COMMAND_READ_TIMEOUT: Duration = Duration::from_secs(120);

/// How long to wait for a *further* command once one has been answered.
///
/// Fifteen minutes. A shell's own idle convention is `TMOUT`, which hardening baselines set to
/// 900 seconds, so this is the number an operator already expects a shell session to be
/// reclaimed at — and long enough that reading a long listing, or stepping away mid-engagement,
/// does not cost the session.
///
/// The LLM round-trip and a `manual` rule parking a command for a human
/// (`src/state/intercepts.rs`, 300s by default) both happen after a line has already been read,
/// so neither can be timed out from under itself.
const IDLE_BETWEEN_COMMANDS_TIMEOUT: Duration = Duration::from_secs(900);

/// Concurrent connections this listener admits.
///
/// [`crate::server::accept_bounded::DEFAULT_MAX_CONNECTIONS`]. A reverse-shell listener in real
/// use holds one or two sessions, so the generous shared default is far above anything
/// legitimate while still bounding a peer that simply opens sockets.
const MAX_CONNECTIONS: usize = crate::server::accept_bounded::DEFAULT_MAX_CONNECTIONS;

/// What a peer over [`MAX_CONNECTIONS`] is told before the socket closes.
///
/// There is no framing to refuse in — this is a raw byte stream — but there *is* a terminal on
/// the other end, so a plain line is read by the one audience that exists. It is deliberately
/// netget's own voice rather than a shell-looking error: the emulated shell never got as far as
/// existing, and a fabricated shell message would be a positive assertion about a session that
/// was declined. Fixed text, so there is no placeholder an internal error could reach.
const CONNECTION_CAP_REFUSAL: &[u8] = b"\r\n[netget] too many connections\r\n";

pub struct ReverseShellServer;

impl ReverseShellServer {
    /// Bind the listener and spawn the accept loop.
    ///
    /// Awaits the bind so a failure (address in use, permission) is returned as `Err` and the
    /// server is marked `Error` rather than lying about being `Running`. The accept-loop
    /// `JoinHandle` is registered so `stop_server` releases the socket.
    pub async fn spawn_with_llm_actions(
        listen_addr: SocketAddr,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        server_id: crate::state::ServerId,
    ) -> Result<SocketAddr> {
        let listener =
            crate::server::socket_helpers::create_reusable_tcp_listener(listen_addr).await?;
        let local_addr = listener.local_addr()?;

        // Keep the address last on the line: the E2E harness parses the port from after "on ".
        console_info!(
            status_tx,
            "Reverse-shell listener (emulation) listening on {}",
            local_addr
        );

        let task_registrar = app_state.clone();
        let limiter = crate::server::accept_bounded::ConnectionLimiter::new(MAX_CONNECTIONS);
        let accept_handle = tokio::spawn(async move {
            loop {
                match crate::server::accept_bounded::accept_bounded(
                    &listener,
                    &limiter,
                    CONNECTION_CAP_REFUSAL,
                    "Reverse-shell",
                    Some(&status_tx),
                )
                .await
                {
                    Ok((stream, remote_addr, permit)) => {
                        let connection_id =
                            ConnectionId::new(app_state.get_next_unified_id().await);
                        let local_addr_conn = stream.local_addr().unwrap_or(local_addr);

                        info!("Reverse-shell operator connected from {}", remote_addr);
                        let _ = status_tx.send(format!(
                            "[INFO] Reverse-shell operator connected from {}",
                            remote_addr
                        ));

                        let llm_clone = llm_client.clone();
                        let state_clone = app_state.clone();
                        let status_clone = status_tx.clone();
                        // Tracked, not detached: stop_server must abort this task too.
                        let task_owner = app_state.clone();
                        task_owner
                            .spawn_server_task(server_id, async move {
                                // Held for the life of the connection: releasing it here would
                                // cap the accept rate rather than the number of live
                                // connections.
                                let _permit = permit;
                                if let Err(e) = Self::handle_connection(
                                    stream,
                                    connection_id,
                                    remote_addr,
                                    local_addr_conn,
                                    server_id,
                                    state_clone,
                                    status_clone,
                                    llm_clone,
                                )
                                .await
                                {
                                    error!("Reverse-shell connection error: {}", e);
                                }
                            })
                            .await;
                    }
                    Err(e) => {
                        // Break rather than spin: a persistent accept error (EMFILE, socket
                        // closed under us) would otherwise loop at full CPU.
                        error!("Reverse-shell accept failed: {}", e);
                        let _ = status_tx
                            .send(format!("✗ Reverse-shell accept failed, stopping: {}", e));
                        break;
                    }
                }
            }
        });

        task_registrar
            .register_server_task(server_id, accept_handle)
            .await;

        Ok(local_addr)
    }

    /// Handle one operator connection: session-open event, then a line loop.
    #[allow(clippy::too_many_arguments)]
    async fn handle_connection(
        stream: TcpStream,
        connection_id: ConnectionId,
        remote_addr: SocketAddr,
        local_addr: SocketAddr,
        server_id: crate::state::ServerId,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        llm_client: OllamaClient,
    ) -> Result<()> {
        let (mut read_half, write_half) = tokio::io::split(stream);
        let write_half = Arc::new(Mutex::new(write_half));

        let now = crate::utils::clock::Instant::now();
        let conn_state = ConnectionState {
            id: connection_id,
            remote_addr,
            local_addr,
            bytes_sent: 0,
            bytes_received: 0,
            packets_sent: 0,
            packets_received: 0,
            last_activity: now,
            status: ConnectionStatus::Active,
            status_changed_at: now,
            protocol_info: ProtocolConnectionInfo::empty(),
        };
        app_state
            .add_connection_to_server(server_id, conn_state)
            .await;
        let _ = status_tx.send("__UPDATE_UI__".to_string());

        // Register a peer handle so the dashboard can [ message this peer ] /
        // [ disconnect this peer ] this live connection. The command task shares the same
        // Arc<Mutex<WriteHalf>> the reader writes through, so injected output is serialized
        // against the model's. Every wire verb (send_shell_output/prompt, end_shell_session)
        // returns Output/CloseConnection, so the generic peer task covers the whole vocabulary.
        let protocol: Arc<ReverseShellProtocol> = Arc::new(ReverseShellProtocol::new());
        let peer_rx = crate::server::peer_support::register_peer_channel(
            &app_state,
            server_id,
            connection_id.as_u32(),
        )
        .await;
        crate::server::peer_support::spawn_peer_command_task(
            peer_rx,
            protocol.clone(),
            app_state.clone(),
            server_id,
            connection_id.as_u32(),
            write_half.clone(),
            status_tx.clone(),
        );

        let mut conn = ShellConnection {
            connection_id,
            server_id,
            app_state: app_state.clone(),
            llm_client,
            protocol: ReverseShellProtocol::new(),
            status_tx: status_tx.clone(),
            write_half,
        };

        let result = conn.run(&mut read_half).await;

        // Remove the peer handle on every exit path (EOF, read error, oversize line,
        // end_shell_session, no-answer fail-closed) — this single cleanup runs after run()
        // returns however it returned, so the rail never keeps offering a dead peer.
        app_state
            .remove_peer_handle(server_id, connection_id.as_u32())
            .await;
        app_state
            .remove_connection_from_server(server_id, connection_id)
            .await;
        let _ = status_tx.send("__UPDATE_UI__".to_string());

        result
    }
}

/// Per-connection state and behaviour for one operator session.
struct ShellConnection {
    connection_id: ConnectionId,
    server_id: crate::state::ServerId,
    app_state: Arc<AppState>,
    llm_client: OllamaClient,
    protocol: ReverseShellProtocol,
    status_tx: mpsc::UnboundedSender<String>,
    write_half: Arc<Mutex<tokio::io::WriteHalf<TcpStream>>>,
}

/// Why a session is being failed closed, kept distinct from a deliberate model decision.
///
/// The two variants exist so the log can tell an operator which happened. Collapsing them —
/// which this protocol used to do behind a single `no_answer` flag — makes a backend outage
/// indistinguishable from a model that answered with an unusable action list, and those want
/// completely different responses from whoever is watching.
#[derive(Clone, Copy, Debug)]
enum FailClosed {
    /// The LLM call itself returned `Err`. Carries only the *category* of the failure — the
    /// error text is logged, never carried towards the wire (`crate::utils::wire_failure`).
    LlmError(crate::utils::WireFailure),
    /// The call succeeded but produced nothing usable: an empty action list, or a batch where
    /// every action failed. The backend is up; the answer was not usable.
    NoUsableAnswer,
}

impl FailClosed {
    /// The peer-visible category. `&'static str` by construction, so nothing derived from an
    /// error can reach the socket.
    fn wire_text(self) -> &'static str {
        match self {
            Self::LlmError(failure) => failure.text(),
            // The backend answered; it is this request that could not be served.
            Self::NoUsableAnswer => crate::utils::WireFailure::Unavailable.text(),
        }
    }

    /// The `decision=` tag written to the log and the status stream. Three cases stay
    /// distinguishable there: `model_end_session` (a deliberate close), `fail_closed_no_answer`
    /// (the model said nothing usable) and `fail_closed_llm_error` (the call errored), the last
    /// split further by overload so a capacity problem is not read as a permanent fault.
    fn decision_tag(self) -> &'static str {
        match self {
            Self::LlmError(crate::utils::WireFailure::Overloaded) => {
                "fail_closed_llm_error_overloaded"
            }
            Self::LlmError(crate::utils::WireFailure::Unavailable) => {
                "fail_closed_llm_error_unavailable"
            }
            Self::NoUsableAnswer => "fail_closed_no_answer",
        }
    }
}

/// What the model decided in answer to one event.
#[derive(Default)]
struct Outcome {
    /// Bytes to write to the operator, in order.
    output: Vec<u8>,
    /// The session should close after writing `output`.
    close: bool,
    /// Set when nothing usable came back, with the reason kept separate from a model decision.
    fail_closed: Option<FailClosed>,
}

impl ShellConnection {
    /// The session: greet on open, then one event per operator command line.
    async fn run(&mut self, read_half: &mut tokio::io::ReadHalf<TcpStream>) -> Result<()> {
        // Session-opened event.
        let open_event = Event::new(&REVERSE_SHELL_SESSION_OPENED_EVENT, serde_json::json!({}));
        let outcome = self.consult(std::slice::from_ref(&open_event)).await;
        if self.apply(outcome).await? {
            return Ok(());
        }

        let mut buffer = vec![0u8; 8192];
        // The partial line still being typed, and complete command lines not yet answered.
        let mut line: Vec<u8> = Vec::new();
        let mut commands: VecDeque<String> = VecDeque::new();
        let mut first_command = true;
        // Set when the stream has ended (EOF, read error) or a line outgrew `MAX_LINE_LEN`:
        // the commands already complete are still answered, in order, before the session ends.
        let mut ended = false;
        let mut too_long = false;

        loop {
            if commands.is_empty() {
                if too_long {
                    console_warn!(
                        self.status_tx,
                        "Reverse-shell line from {} exceeded {} bytes, closing",
                        self.connection_id,
                        MAX_LINE_LEN
                    );
                    self.shutdown().await;
                    return Ok(());
                }
                if ended {
                    break;
                }
                // The deadline wraps this read and nothing else. Everything that can
                // legitimately take minutes — the LLM round-trip, and a `manual` rule parking
                // the command for a human to answer — happens below, after bytes have already
                // been read.
                let read_timeout = if first_command {
                    FIRST_COMMAND_READ_TIMEOUT
                } else {
                    IDLE_BETWEEN_COMMANDS_TIMEOUT
                };
                let read =
                    match tokio::time::timeout(read_timeout, read_half.read(&mut buffer)).await {
                        Ok(read) => read,
                        Err(_) => {
                            info!(
                                "Reverse-shell operator {} sent nothing for {}s; closing idle \
                                 session",
                                self.connection_id,
                                read_timeout.as_secs()
                            );
                            break;
                        }
                    };
                match self.received(read).await {
                    Some(n) => {
                        too_long = !split_commands(&buffer[..n], &mut line, &mut commands);
                    }
                    None => ended = true,
                }
                continue;
            }

            // With batching on, everything else the operator already sent — typed while the
            // model was answering the previous command, or pasted as several lines — is
            // answered in the same call. Read without waiting, so batching never delays a
            // reply.
            let batching = self
                .app_state
                .server_conversation_settings(self.server_id)
                .await
                .is_some_and(|(_, batching)| batching);
            let max = crate::protocol::metadata::MAX_BATCH_EVENTS;
            while batching && !ended && !too_long && commands.len() < max {
                // A zero deadline polls the read once: whatever the kernel already holds.
                let Ok(read) =
                    tokio::time::timeout(Duration::ZERO, read_half.read(&mut buffer)).await
                else {
                    break;
                };
                match self.received(read).await {
                    Some(n) => {
                        too_long = !split_commands(&buffer[..n], &mut line, &mut commands);
                    }
                    None => ended = true,
                }
            }
            let take = if batching { commands.len().min(max) } else { 1 };

            let mut events = Vec::with_capacity(take);
            for command in commands.drain(..take) {
                console_debug!(
                    self.status_tx,
                    "Reverse-shell command from {}: {:?}",
                    self.connection_id,
                    command
                );
                let empty = command.trim().is_empty();
                events.push(Event::new(
                    &REVERSE_SHELL_COMMAND_EVENT,
                    serde_json::json!({
                        "command": command,
                        "first_command": first_command,
                        "empty": empty,
                    }),
                ));
                first_command = false;
            }

            let outcome = self.consult(&events).await;
            if self.apply(outcome).await? {
                return Ok(());
            }
        }

        Ok(())
    }

    /// Account for one read: `Some(n)` for `n` bytes, `None` once the stream has ended.
    async fn received(&self, read: std::io::Result<usize>) -> Option<usize> {
        match read {
            Ok(0) => {
                debug!("Reverse-shell operator {} disconnected", self.connection_id);
                None
            }
            Ok(n) => {
                // Refresh byte/packet counters and last_activity so the rail's ↓ moves and
                // connection-scoped task prompts see a fresh timestamp.
                self.app_state
                    .update_connection_stats(
                        self.server_id,
                        self.connection_id,
                        Some(n as u64),
                        None,
                        Some(1),
                        None,
                    )
                    .await;
                Some(n)
            }
            Err(e) => {
                error!("Reverse-shell read error on {}: {}", self.connection_id, e);
                None
            }
        }
    }

    /// Ask the event handlers (script → static → LLM) what to do.
    ///
    /// Never returns an error: a failure has to fail *closed* on the caller side, so the reason
    /// is carried back in `Outcome::no_answer` and the caller closes the socket. Silence is never
    /// treated as approval — there is nothing to approve here, but the same discipline keeps the
    /// "no answer" path distinct from a deliberate "no output" (`no_shell_output`).
    async fn consult(&self, events: &[Event]) -> Outcome {
        let mut outcome = Outcome::default();
        // The newest event is the batch's trigger; it is the one a failure is logged under.
        let Some(event) = events.last() else {
            return outcome;
        };

        let execution = match call_llm_batch(
            &self.llm_client,
            &self.app_state,
            self.server_id,
            Some(self.connection_id),
            events,
            &self.protocol,
        )
        .await
        {
            Ok(execution) => execution,
            Err(e) => {
                // The full error goes to the log and the status stream, where an operator
                // looks. Only its category is allowed anywhere near the socket.
                let failure = crate::utils::WireFailure::classify(&e);
                error!(
                    "Reverse-shell event {} decision={} error={}",
                    event.event_type.id,
                    FailClosed::LlmError(failure).decision_tag(),
                    e
                );
                let _ = self.status_tx.send(format!(
                    "[ERROR] Reverse-shell {} decision={}: {}",
                    event.event_type.id,
                    FailClosed::LlmError(failure).decision_tag(),
                    e
                ));
                outcome.fail_closed = Some(FailClosed::LlmError(failure));
                return outcome;
            }
        };

        for message in execution.messages {
            let _ = self.status_tx.send(message);
        }

        let mut saw_result = false;
        for result in execution.protocol_results {
            match result {
                ActionResult::Output(data) => {
                    saw_result = true;
                    outcome.output.extend_from_slice(&data);
                }
                ActionResult::CloseConnection => {
                    saw_result = true;
                    outcome.close = true;
                }
                // no_shell_output: a deliberate decision to print nothing. Structurally distinct
                // from a missing answer — the session stays open and no placeholder is invented.
                ActionResult::WaitForMore | ActionResult::NoAction => {
                    saw_result = true;
                }
                other => {
                    warn!(
                        "Reverse-shell ignoring unexpected action result: {:?}",
                        other
                    );
                }
            }
        }

        if !saw_result {
            warn!(
                "Reverse-shell event {} decision={} (model returned no usable action)",
                event.event_type.id,
                FailClosed::NoUsableAnswer.decision_tag()
            );
            outcome.fail_closed = Some(FailClosed::NoUsableAnswer);
        }

        outcome
    }

    /// Write the decided output, then close if asked or if no usable answer came back.
    ///
    /// Returns true when the connection has been closed and the caller must stop.
    ///
    /// Fail-closed: a missing answer (LLM error, empty/failed action list) shuts the socket down
    /// with a FIN rather than falling through to any permissive default — there is no fabricated
    /// output and no fake prompt, so an LLM outage is visible to the operator as a dropped
    /// session, not as a silently-working shell.
    async fn apply(&mut self, outcome: Outcome) -> Result<bool> {
        if !outcome.output.is_empty() {
            let mut writer = self.write_half.lock().await;
            writer.write_all(&outcome.output).await?;
            writer.flush().await?;
            drop(writer);
            self.app_state
                .update_connection_stats(
                    self.server_id,
                    self.connection_id,
                    None,
                    Some(outcome.output.len() as u64),
                    None,
                    Some(1),
                )
                .await;
            console_debug!(
                self.status_tx,
                "Reverse-shell sent {} bytes to {}",
                outcome.output.len(),
                self.connection_id
            );
        }

        if let Some(reason) = outcome.fail_closed {
            let _ = self.status_tx.send(format!(
                "✗ Reverse-shell closing {} decision={}",
                self.connection_id,
                reason.decision_tag()
            ));
            self.write_failure_notice(reason).await;
            self.shutdown().await;
            return Ok(true);
        }

        if outcome.close {
            let _ = self.status_tx.send(format!(
                "✗ Reverse-shell session {} decision=model_end_session",
                self.connection_id
            ));
            self.shutdown().await;
            return Ok(true);
        }

        Ok(false)
    }

    /// Tell the operator, on its own line, that the server could not answer — then the caller
    /// half-closes.
    ///
    /// A bare FIN is honest but ambiguous: on a reverse-shell transcript it looks exactly like
    /// the implant on the far end dying, which sends the operator hunting the wrong problem.
    /// One line naming the *category* removes that ambiguity while inventing no shell output.
    ///
    /// The text is `WireFailure`'s `&'static str` and nothing else. The error itself has
    /// already been logged; interpolating it here is the defect this whole path exists to
    /// avoid (see `crate::utils::wire_failure`). The two categories carry different words —
    /// "retry later" for a saturated backend, "could not be processed" otherwise — so an
    /// operator (or a script watching the transcript) can tell a transient outage from a
    /// permanent one even though a raw shell stream has no status code.
    ///
    /// CRLF and a leading newline so the notice cannot be mistaken for the output of whatever
    /// the operator last typed, and so a cooked-mode client does not stair-step it.
    async fn write_failure_notice(&self, reason: FailClosed) {
        let notice = format!("\r\n[netget] {}\r\n", reason.wire_text());
        let mut writer = self.write_half.lock().await;
        if writer.write_all(notice.as_bytes()).await.is_ok() {
            let _ = writer.flush().await;
            drop(writer);
            self.app_state
                .update_connection_stats(
                    self.server_id,
                    self.connection_id,
                    None,
                    Some(notice.len() as u64),
                    None,
                    Some(1),
                )
                .await;
        }
    }

    /// Half-close the write direction so the operator's next read returns EOF.
    async fn shutdown(&self) {
        let mut writer = self.write_half.lock().await;
        let _ = writer.shutdown().await;
    }
}

/// Append `bytes` to the command line being typed, moving each completed line onto `commands`
/// with its newline (and a CR before it) stripped, so CRLF and LF clients look identical to
/// the model. Returns `false` once the line being typed outgrows [`MAX_LINE_LEN`].
fn split_commands(bytes: &[u8], line: &mut Vec<u8>, commands: &mut VecDeque<String>) -> bool {
    for &byte in bytes {
        if byte == b'\n' {
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            commands.push_back(String::from_utf8_lossy(line).to_string());
            line.clear();
        } else {
            line.push(byte);
            if line.len() > MAX_LINE_LEN {
                return false;
            }
        }
    }
    true
}
