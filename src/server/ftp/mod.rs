//! FTP server implementation
//!
//! File Transfer Protocol (RFC 959) server with LLM-controlled responses.
//! Supports basic FTP commands: USER, PASS, SYST, PWD, CWD, LIST, RETR, STOR, QUIT, etc.

pub mod actions;

use anyhow::Result;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::sync::Mutex;

use crate::llm::action_helper::{call_llm, call_llm_batch};
use crate::llm::ollama_client::OllamaClient;
use crate::llm::ActionResult;
use crate::logging::emit::Log;
use crate::protocol::Event;
use crate::server::ftp::actions::FtpProtocol;
use crate::state::app_state::AppState;
use actions::FTP_COMMAND_EVENT;

/// FTP server that provides LLM-controlled file transfer operations
pub struct FtpServer;

impl FtpServer {
    /// Spawn FTP server with integrated LLM actions
    #[allow(clippy::too_many_arguments)]
    pub async fn spawn_with_llm_actions(
        listen_addr: SocketAddr,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        server_id: crate::state::ServerId,
        first_byte_timeout_secs: Option<u64>,
        idle_timeout_secs: Option<u64>,
    ) -> Result<SocketAddr> {
        // Both bounds are tunable because their right value is a property of who is on the
        // other end, which only the operator knows. The defaults serve NetGet's own FTP client
        // waiting on a human; a listener exposed to strangers wants the first one much lower.
        let deadlines = ReadDeadlines::resolve(first_byte_timeout_secs, idle_timeout_secs);
        let listener =
            crate::server::socket_helpers::create_reusable_tcp_listener(listen_addr).await?;
        let local_addr = listener.local_addr()?;

        Log::new(Some(&status_tx)).info(format!("FTP server listening on {}", local_addr));

        let protocol = Arc::new(FtpProtocol::new());

        let task_registrar = app_state.clone();
        let limiter = crate::server::accept_bounded::ConnectionLimiter::new(MAX_CONNECTIONS);
        let accept_handle = tokio::spawn(async move {
            loop {
                match crate::server::accept_bounded::accept_bounded(
                    &listener,
                    &limiter,
                    CONNECTION_CAP_REFUSAL,
                    "FTP",
                    Some(&status_tx),
                )
                .await
                {
                    Ok((stream, remote_addr, permit)) => {
                        let connection_id = crate::server::connection::ConnectionId::new(
                            app_state.get_next_unified_id().await,
                        );
                        Log::new(Some(&status_tx)).info(format!(
                            "FTP connection {} from {}",
                            connection_id, remote_addr
                        ));

                        let llm_clone = llm_client.clone();
                        let state_clone = app_state.clone();
                        let status_clone = status_tx.clone();
                        let protocol_clone = protocol.clone();
                        let local_addr_conn = stream.local_addr().unwrap_or(local_addr);

                        // Tracked, not detached: stop_server must abort this task too.
                        let task_owner = app_state.clone();
                        task_owner
                            .spawn_server_task(server_id, async move {
                                // Held for the life of the connection: releasing it here would
                                // cap the accept rate rather than the number of live
                                // connections.
                                let _permit = permit;
                                // Register the connection so it shows up in the TUI and in
                                // list_connections, and so stop_server accounts for it.
                                use crate::state::server::{
                                    ConnectionState as ServerConnectionState, ConnectionStatus,
                                    ProtocolConnectionInfo,
                                };
                                let now = crate::utils::clock::Instant::now();
                                let conn_state = ServerConnectionState {
                                    id: connection_id,
                                    remote_addr,
                                    local_addr: local_addr_conn,
                                    bytes_sent: 0,
                                    bytes_received: 0,
                                    packets_sent: 0,
                                    packets_received: 0,
                                    last_activity: now,
                                    status: ConnectionStatus::Active,
                                    status_changed_at: now,
                                    protocol_info: ProtocolConnectionInfo::empty(),
                                };
                                state_clone
                                    .add_connection_to_server(server_id, conn_state)
                                    .await;
                                let _ = status_clone.send("__UPDATE_UI__".to_string());

                                if let Err(e) = FtpSession::handle_session(
                                    stream,
                                    connection_id,
                                    server_id,
                                    llm_clone,
                                    state_clone.clone(),
                                    status_clone.clone(),
                                    protocol_clone,
                                    deadlines,
                                )
                                .await
                                {
                                    Log::new(Some(&status_clone))
                                        .error(format!("FTP session error: {}", e));
                                }

                                state_clone
                                    .close_connection_on_server(server_id, connection_id)
                                    .await;
                                let _ = status_clone.send("__UPDATE_UI__".to_string());
                            })
                            .await;
                    }
                    Err(e) => {
                        Log::new(Some(&status_tx))
                            .error(format!("Failed to accept FTP connection: {}", e));
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
}

/// How long to wait for the first command after the `220` greeting has been sent.
///
/// **This was 60 seconds, and "FTP is server-speaks-first" was the wrong reason for it.** The
/// argument read: every real client — `ftp(1)`, `lftp`, curl, a browser — answers the greeting
/// with `USER` from inside its own connect path, with no human in the loop yet, so a minute is
/// far more than that needs. Every word of that is true and none of it is about the peer this
/// server most often has. The greeting is *ours*; sending it says nothing about whether the
/// other end will answer it.
///
/// The question a first-byte bound actually has to answer is whether NetGet's own client of
/// this protocol can be connected and silent. FTP's can, and is, by default:
/// `src/client/ftp/mod.rs` opens the socket, splits it, registers the command channel, raises
/// `ftp_connected`, and then reads the `220` in its read loop. It writes nothing of its own —
/// every byte it puts on the wire comes from an action, and a client created from the
/// dashboard's `[ + ftp client ]` is routed `ftp_connected` → static-with-no-actions and then
/// `*` → manual (`src/tui/modal/form.rs`). So it connects, is answered with nothing, reads our
/// greeting, parks that too, and waits for a person to type into `[ send message ]`. At 60
/// seconds this server hung up on the operator's own client while they were still looking at
/// it.
///
/// 300 seconds is the window a `manual` rule gives a human to answer one event
/// (`src/state/intercepts.rs`), which is the number this product already uses for how long
/// someone might take.
///
/// What it costs: a stranger holding a socket, a task, an `AppState` row and one of
/// [`MAX_CONNECTIONS`] slots while saying nothing now gets 300 seconds rather than 60. That is
/// a fivefold rise in how long one idle slot is held, not a removal of the bound — the cap
/// still holds and a peer over it is still answered [`CONNECTION_CAP_REFUSAL`]. A listener
/// genuinely exposed to strangers should set `first_byte_timeout_secs` low; 60 is the old
/// value and remains a sound choice for one.
///
/// The greeting itself is generated and written before the command loop begins, so the model's
/// time over it, and a `manual` rule parking it for a human, are outside this deadline by
/// construction — as is every later LLM round-trip, which happens after a line has been read.
const FIRST_COMMAND_READ_TIMEOUT: Duration = Duration::from_secs(300);

/// The two read deadlines for one connection, resolved from the server's startup parameters.
///
/// Carried as one value so threading them from `spawn_with_llm_actions` down to the command
/// loop costs one argument rather than two at each hop.
#[derive(Clone, Copy)]
struct ReadDeadlines {
    /// [`FIRST_COMMAND_READ_TIMEOUT`], or this server's `first_byte_timeout_secs`.
    first_byte: Duration,
    /// [`IDLE_BETWEEN_COMMANDS_TIMEOUT`], or this server's `idle_timeout_secs`.
    idle: Duration,
}

impl ReadDeadlines {
    fn resolve(first_byte_secs: Option<u64>, idle_secs: Option<u64>) -> Self {
        Self {
            first_byte: first_byte_secs
                .map(Duration::from_secs)
                .unwrap_or(FIRST_COMMAND_READ_TIMEOUT),
            idle: idle_secs
                .map(Duration::from_secs)
                .unwrap_or(IDLE_BETWEEN_COMMANDS_TIMEOUT),
        }
    }
}

/// How long to wait for a *further* command once one has been answered.
///
/// Five minutes, which is vsftpd's `idle_session_timeout` default — the idle bound on the FTP
/// control connection that every client in use is already built to tolerate, and which
/// ProFTPD's `TimeoutIdle` only doubles. It has to be on a human timescale rather than a
/// machine one: `ftp(1)` prompts the person at it for the password after `USER`, and again for
/// each command of an interactive session, so the silence between two commands here is someone
/// typing.
///
/// The LLM round-trip and a `manual` rule parking a command for a human
/// (`src/state/intercepts.rs`, 300s by default) both happen after a line has already been read,
/// so neither can be timed out from under itself.
///
/// Overridable per server with `idle_timeout_secs`, for the same reason the first bound is:
/// the right value is a property of who is on the other end, and only the operator knows that.
const IDLE_BETWEEN_COMMANDS_TIMEOUT: Duration = Duration::from_secs(300);

/// Concurrent control connections this server admits.
///
/// [`crate::server::accept_bounded::DEFAULT_MAX_CONNECTIONS`]. Each connection may buffer up to
/// [`MAX_COMMAND_LINE`], so this is the multiplier that turns that per-connection bound into a
/// total one.
const MAX_CONNECTIONS: usize = crate::server::accept_bounded::DEFAULT_MAX_CONNECTIONS;

/// What a peer over [`MAX_CONNECTIONS`] is told before the socket closes.
///
/// `421 Service not available, closing control connection` is RFC 959's own reply for exactly
/// this — the server declining to open a session — and it is what real FTP servers send when
/// they are at their client limit. A `4xx` is a transient negative reply, so a client retries
/// later rather than recording a permanent failure. Fixed text, so there is no placeholder an
/// internal error could reach.
const CONNECTION_CAP_REFUSAL: &[u8] = b"421 Too many connections, closing control connection\r\n";

/// Largest control line the server will accumulate before giving up on the peer.
///
/// RFC 959 commands are short — the longest standard one is a `STOR` with a path — and
/// 8 KiB is far above anything a real client sends. The cap exists because
/// [`tokio::io::AsyncBufReadExt::read_line`] grows its buffer until it finds a newline: a
/// peer that opens a connection and streams bytes with no `\n` makes the server allocate
/// without bound, which is a one-connection out-of-memory.
pub const MAX_COMMAND_LINE: usize = 8192;

/// The result of trying to read one control line.
enum CommandLine {
    /// A complete line. The trailing CRLF is still attached; the caller trims it.
    Line(String),
    /// The peer closed the control connection.
    Eof,
    /// The peer sent `MAX_COMMAND_LINE` bytes with no newline in them.
    TooLong,
}

/// Read a single CRLF-terminated FTP command, refusing to buffer more than `max_len` bytes.
///
/// Returns the line and the number of bytes consumed from the socket, so the caller can
/// account for them in the connection stats exactly as `read_line` allowed.
async fn read_command_line<R>(
    reader: &mut tokio::io::BufReader<R>,
    max_len: usize,
) -> std::io::Result<(CommandLine, usize)>
where
    R: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncBufReadExt;

    let mut buf: Vec<u8> = Vec::new();
    loop {
        // `fill_buf` borrows the reader, so decide what to take and drop the borrow before
        // calling `consume`.
        let (newline_at, available_len) = {
            let available = reader.fill_buf().await?;
            (available.iter().position(|&b| b == b'\n'), available.len())
        };

        if available_len == 0 {
            // EOF. A trailing fragment with no newline is not a command; the peer hung up
            // mid-line, which is the same as hanging up.
            return Ok((CommandLine::Eof, buf.len()));
        }

        let take = match newline_at {
            Some(idx) => idx + 1,
            None => available_len,
        };

        if buf.len() + take > max_len {
            // Consume what we looked at so the reader is not left mid-buffer, then give up:
            // the caller closes the connection, so there is nothing to resynchronise with.
            reader.consume(take);
            return Ok((CommandLine::TooLong, buf.len() + take));
        }

        {
            let available = reader.fill_buf().await?;
            buf.extend_from_slice(&available[..take]);
        }
        reader.consume(take);

        if newline_at.is_some() {
            let consumed = buf.len();
            // `from_utf8_lossy` rather than a hard error: a stray non-UTF-8 byte in a
            // command is the peer's problem to be answered with 500, not a reason to drop
            // the connection without a reply.
            return Ok((
                CommandLine::Line(String::from_utf8_lossy(&buf).into_owned()),
                consumed,
            ));
        }
    }
}

/// The RFC 959 reply code at the head of a control-connection write, when there is one.
///
/// For the log only. FTP has a rich enough vocabulary that the *code* is the outcome, so the
/// `decision=` line names what the peer actually received — which is how an operator sees
/// that a PASS was answered 530 and not 230.
fn reply_code_of(data: &[u8]) -> Option<u16> {
    let head = data.get(..3)?;
    if head.iter().all(u8::is_ascii_digit) {
        std::str::from_utf8(head).ok()?.parse().ok()
    } else {
        None
    }
}

/// Tracks the one-reply-per-command rule across an answer's `Output`s.
///
/// RFC 959 gives each command exactly one completion reply (2xx-5xx), optionally preceded by
/// preliminary 1xx replies. The real-model eval saw llama3.1:8b answer a connection with five
/// `220`s: the client took the first as the greeting and the next four as the answers to the
/// commands it sent afterwards, so `USER anonymous` read `220 FTP Server Ready` and no login
/// ever happened (`ftp/anonymous-login` 0/5). Everything after the first completion reply is
/// dropped and counted, and the caller logs `decision=duplicate_response_dropped`.
#[derive(Default)]
struct OneReply {
    completed: bool,
    dropped: usize,
}

impl OneReply {
    /// Whether `data` may go on the wire.
    fn admit(&mut self, data: &[u8]) -> bool {
        if self.completed {
            self.dropped += 1;
            return false;
        }
        // A non-numeric write (the model's free text) is not a reply code; let it through and
        // leave the rule to the numbered replies around it.
        if reply_code_of(data).is_some_and(|code| code >= 200) {
            self.completed = true;
        }
        true
    }

    fn log_drops(&self, log: &Log, connection_id: impl std::fmt::Display, what: &str) {
        if self.dropped > 0 {
            log.warn(format!(
                "FTP {what} on connection {connection_id} decision=duplicate_response_dropped: \
                 {} further reply(ies) after the completion reply were not sent",
                self.dropped
            ));
        }
    }
}

/// How a single `ftp_command` event ended, as a stable `decision=` token plus the detail the
/// log line carries.
///
/// Computed **before** `protocol_results` is consumed, because the command loop moves them
/// into a `for` and the `CloseConnection` arm returns straight out of it.
///
/// The three non-answer outcomes are the point. A model that refuses (`close_connection`), a
/// model that answered with nothing, and a model whose action the executor refused all leave
/// the *same* thing on the wire today — nothing at all — so the log is the only place they
/// can be told apart, and only the first of the three is a decision anybody made.
fn classify_ftp_outcome(result: &crate::llm::ExecutionResult) -> (&'static str, String) {
    let codes: Vec<String> = result
        .protocol_results
        .iter()
        .flat_map(|r| r.get_all_output())
        .map(|d| match reply_code_of(&d) {
            Some(code) => code.to_string(),
            None => "non-numeric".to_string(),
        })
        .collect();

    if !codes.is_empty() {
        return ("model_answer", format!("reply {}", codes.join(",")));
    }

    // Only a top-level `CloseConnection` is honoured by the command loop, so only a top-level
    // one is reported here.
    if result
        .protocol_results
        .iter()
        .any(|r| matches!(r, ActionResult::CloseConnection))
    {
        return (
            "model_reject",
            "close_connection: control connection closed with no reply".to_string(),
        );
    }

    // `wait_for_more` also writes nothing, but it is a decision the model made and declared,
    // not an absence of one. Folding it into `model_silent` would be the exact conflation this
    // tagging exists to prevent.
    if result
        .protocol_results
        .iter()
        .any(|r| matches!(r, ActionResult::WaitForMore))
    {
        return (
            "model_wait_for_more",
            "wait_for_more: no reply until the client sends another line".to_string(),
        );
    }

    if !result.failures.is_empty() {
        let detail = result
            .failures
            .iter()
            .map(|f| format!("{}: {}", f.action, f.error))
            .collect::<Vec<_>>()
            .join("; ");
        return ("fail_closed_bad_action", detail);
    }

    (
        "model_silent",
        "no usable action; nothing was written and the client is left waiting".to_string(),
    )
}

/// The `ftp_command` event for one command line.
fn command_event(command: &str) -> Event {
    Event::new(&FTP_COMMAND_EVENT, {
        let mut data = serde_json::json!({ "command": command });
        if let Some(hint) = actions::answer_with_for_command(command) {
            data["answer_with"] = serde_json::json!(hint);
        }
        data
    })
}

/// Complete command lines already here - buffered, or readable without waiting - up to `max`,
/// each with the bytes it consumed.
///
/// What a batch collects after the first command: everything a pipelining client sent while
/// the model was answering. `fill_buf` returns what is buffered without reading, polls the
/// socket only when the buffer is empty, and is cancel-safe, so the zero deadline never waits
/// and never loses a byte. It stops at a partial line or one over [`MAX_COMMAND_LINE`], leaving
/// either for [`read_command_line`] to read and report.
async fn lines_already_here<R>(
    reader: &mut tokio::io::BufReader<R>,
    max: usize,
) -> Vec<(String, usize)>
where
    R: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncBufReadExt;
    let mut lines = Vec::new();
    while lines.len() < max {
        let line = match tokio::time::timeout(Duration::ZERO, reader.fill_buf()).await {
            Ok(Ok(buf)) => match buf.iter().position(|&b| b == b'\n') {
                Some(idx) if idx < MAX_COMMAND_LINE => {
                    String::from_utf8_lossy(&buf[..=idx]).into_owned()
                }
                _ => break,
            },
            _ => break,
        };
        let consumed = line.len();
        reader.consume(consumed);
        lines.push((line, consumed));
    }
    lines
}

struct FtpSession;

impl FtpSession {
    /// Handle an FTP session
    ///
    /// Owns the split socket. The write half lives in an `Arc<Mutex<_>>` shared with the
    /// peer command task, so the dashboard's "message this peer" / "disconnect this peer"
    /// write through the same half the session does. The peer handle is registered here
    /// (the accept loop has already added the connection) and removed on every exit —
    /// EOF, 421, `close_connection` and errors all funnel through the single return below.
    #[allow(clippy::too_many_arguments)]
    async fn handle_session(
        stream: tokio::net::TcpStream,
        connection_id: crate::server::connection::ConnectionId,
        server_id: crate::state::ServerId,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        protocol: Arc<FtpProtocol>,
        deadlines: ReadDeadlines,
    ) -> Result<()> {
        let (read_half, write_half) = tokio::io::split(stream);
        let write_half = Arc::new(Mutex::new(write_half));

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

        let result = async {
            Self::send_greeting(
                &write_half,
                connection_id,
                server_id,
                &llm_client,
                &app_state,
                &status_tx,
                &protocol,
            )
            .await?;

            Self::handle_session_commands(
                read_half,
                &write_half,
                connection_id,
                server_id,
                llm_client,
                &app_state,
                &status_tx,
                protocol,
                deadlines,
            )
            .await
        }
        .await;

        app_state
            .remove_peer_handle(server_id, connection_id.as_u32())
            .await;
        result
    }

    /// Lock the shared write half, write + flush, and account for the bytes. The guard is
    /// dropped before returning so no `.await` on the LLM ever holds it.
    async fn write_out<W>(
        write_half: &Arc<Mutex<W>>,
        data: &[u8],
        app_state: &AppState,
        server_id: crate::state::ServerId,
        connection_id: crate::server::connection::ConnectionId,
    ) -> std::io::Result<()>
    where
        W: tokio::io::AsyncWrite + Unpin,
    {
        use tokio::io::AsyncWriteExt;
        {
            let mut write = write_half.lock().await;
            write.write_all(data).await?;
            write.flush().await?;
        }
        app_state
            .update_connection_stats(
                server_id,
                connection_id,
                None,
                Some(data.len() as u64),
                None,
                Some(1),
            )
            .await;
        Ok(())
    }

    /// Send FTP greeting (220 response)
    async fn send_greeting<W>(
        write_half: &Arc<Mutex<W>>,
        connection_id: crate::server::connection::ConnectionId,
        server_id: crate::state::ServerId,
        llm_client: &OllamaClient,
        app_state: &Arc<AppState>,
        status_tx: &mpsc::UnboundedSender<String>,
        protocol: &Arc<FtpProtocol>,
    ) -> Result<()>
    where
        W: tokio::io::AsyncWrite + Unpin,
    {
        // The client will not speak until it has seen a 2xx greeting, so this event is the
        // handler's only chance to produce one. `CONNECTION_ESTABLISHED` is a sentinel, not a
        // command the client sent - see FTP_COMMAND_EVENT.
        let greeting_event = Event::new(
            &FTP_COMMAND_EVENT,
            serde_json::json!({
                "command": "CONNECTION_ESTABLISHED",
                "answer_with": actions::answer_with_for_command("CONNECTION_ESTABLISHED"),
            }),
        );

        match call_llm(
            llm_client,
            app_state,
            server_id,
            Some(connection_id),
            &greeting_event,
            protocol.as_ref(),
        )
        .await
        {
            Ok(execution_result) => {
                let (decision, detail) = classify_ftp_outcome(&execution_result);
                let log = Log::new(Some(status_tx));
                match decision {
                    "model_answer" => log.info(format!(
                        "FTP greeting on connection {connection_id} decision=model_answer \
                         ({detail})"
                    )),
                    "model_reject" => log.info(format!(
                        "FTP greeting on connection {connection_id} decision=model_reject \
                         ({detail})"
                    )),
                    "model_wait_for_more" => log.info(format!(
                        "FTP greeting on connection {connection_id} \
                         decision=model_wait_for_more ({detail})"
                    )),
                    "fail_closed_bad_action" => log.error(format!(
                        "FTP greeting on connection {connection_id} \
                         decision=fail_closed_bad_action ({detail}); the client is waiting for a \
                         220 that will never arrive"
                    )),
                    _ => log.warn(format!(
                        "FTP greeting on connection {connection_id} decision=model_silent \
                         ({detail}); an FTP client may send no command until it has read a \
                         greeting"
                    )),
                }

                let mut one_reply = OneReply::default();
                for protocol_result in execution_result.protocol_results {
                    if let ActionResult::Output(data) = protocol_result {
                        if !one_reply.admit(&data) {
                            continue;
                        }
                        Self::write_out(write_half, &data, app_state, server_id, connection_id)
                            .await?;
                    }
                }
                one_reply.log_drops(&log, connection_id, "greeting");
            }
            Err(e) => {
                // Logging it was an improvement on silence for *us*; the client still sat
                // waiting for a greeting that never came, because an FTP client may not send
                // a command until it has read one. RFC 959 defines 421 as the greeting a
                // server sends when it is declining the session, and it closes afterwards -
                // which is the same shape SMTP uses, for the same reason.
                let failure = crate::utils::WireFailure::classify(&e);
                let notice = failure.prefixed_text();
                let decision = if failure.is_overloaded() {
                    "fail_closed_llm_overloaded"
                } else {
                    "fail_closed_llm_error"
                };
                Log::new(Some(status_tx)).error(format!(
                    "FTP greeting on connection {connection_id} decision={decision}, refused \
                     with 421 ({notice}): {e}"
                ));
                let reply =
                    format!("421 Service not available, closing control connection ({notice})\r\n");
                let _ = Self::write_out(
                    write_half,
                    reply.as_bytes(),
                    app_state,
                    server_id,
                    connection_id,
                )
                .await;
                // 421 means the control connection is closing, so the session must not
                // continue into the command loop. The caller propagates this with `?`, which
                // ends the connection task and drops the socket.
                return Err(anyhow::anyhow!("FTP greeting refused with 421: {e}"));
            }
        }

        Ok(())
    }

    /// Write the answer to a batch of command lines, one completion reply per command.
    ///
    /// RFC 959 owes each command exactly one completion reply (2xx-5xx), and a client matches
    /// replies to commands by position alone. So a batch is written only when the handler gave
    /// exactly one completion reply per command, in the order the commands arrived (1xx
    /// replies and non-numeric text pass through, as `OneReply` lets them); a handler that
    /// says nothing at all leaves every command unanswered, as it would one; and a handler that
    /// closes the connection may stop early. Any other count cannot be matched to commands,
    /// so nothing of it is written: the connection is refused with `421` and closed, logged
    /// `decision=fail_closed_batch_mismatch`, rather than risk a client reading one command's
    /// reply as another's. This is why batching is off by default here.
    ///
    /// Returns `Ok(false)` when the connection is to close.
    #[allow(clippy::too_many_arguments)]
    async fn write_batch_answer<W>(
        execution_result: crate::llm::ExecutionResult,
        commands: &[String],
        write_half: &Arc<Mutex<W>>,
        app_state: &AppState,
        server_id: crate::state::ServerId,
        connection_id: crate::server::connection::ConnectionId,
        log: &Log<'_>,
    ) -> std::io::Result<bool>
    where
        W: tokio::io::AsyncWrite + Unpin,
    {
        let completions = execution_result
            .protocol_results
            .iter()
            .filter_map(|r| match r {
                ActionResult::Output(data) => reply_code_of(data),
                _ => None,
            })
            .filter(|code| *code >= 200)
            .count();
        let closes = execution_result
            .protocol_results
            .iter()
            .any(|r| matches!(r, ActionResult::CloseConnection));
        let (decision, detail) = classify_ftp_outcome(&execution_result);
        let n = commands.len();

        if completions == 0 && !closes {
            // Nothing answered any of them: the same outcome a single command gets.
            let line = format!(
                "FTP {commands:?} on connection {connection_id} decision={decision} ({detail})"
            );
            match decision {
                "model_wait_for_more" => log.info(line),
                "fail_closed_bad_action" => log.error(line),
                _ => log.warn(line),
            }
            return Ok(true);
        }
        if completions > n || (completions < n && !closes) {
            log.error(format!(
                "FTP {commands:?} on connection {connection_id} \
                 decision=fail_closed_batch_mismatch: {completions} completion reply(ies) for \
                 {n} commands ({detail}); none written, refused with 421"
            ));
            let reply = "421 Service not available, closing control connection \
                         (replies could not be matched to commands)\r\n";
            let _ = Self::write_out(
                write_half,
                reply.as_bytes(),
                app_state,
                server_id,
                connection_id,
            )
            .await;
            return Ok(false);
        }

        log.info(format!(
            "FTP {commands:?} on connection {connection_id} decision={decision} ({detail})"
        ));
        for protocol_result in execution_result.protocol_results {
            match protocol_result {
                ActionResult::Output(data) => {
                    Self::write_out(write_half, &data, app_state, server_id, connection_id).await?;
                    log.debug(format!(
                        "FTP sent: {}",
                        String::from_utf8_lossy(&data).trim()
                    ));
                }
                ActionResult::CloseConnection => return Ok(false),
                _ => {}
            }
        }
        Ok(true)
    }

    /// Handle FTP session commands
    #[allow(clippy::too_many_arguments)]
    async fn handle_session_commands<R, W>(
        read_half: R,
        write_half: &Arc<Mutex<W>>,
        connection_id: crate::server::connection::ConnectionId,
        server_id: crate::state::ServerId,
        llm_client: OllamaClient,
        app_state: &Arc<AppState>,
        status_tx: &mpsc::UnboundedSender<String>,
        protocol: Arc<FtpProtocol>,
        deadlines: ReadDeadlines,
    ) -> Result<()>
    where
        R: tokio::io::AsyncRead + Unpin,
        W: tokio::io::AsyncWrite + Unpin,
    {
        use tokio::io::BufReader;

        let mut reader = BufReader::new(read_half);
        let log = Log::new(Some(status_tx));

        let mut answered_one = false;
        loop {
            // The deadline wraps this read and nothing else. Everything that can legitimately
            // take minutes — the LLM round-trip, and a `manual` rule parking the command for a
            // human to answer — happens below, after a line has already been read.
            let read_timeout = if answered_one {
                deadlines.idle
            } else {
                deadlines.first_byte
            };
            let (outcome, n) = match tokio::time::timeout(
                read_timeout,
                read_command_line(&mut reader, MAX_COMMAND_LINE),
            )
            .await
            {
                Ok(result) => result?,
                Err(_) => {
                    log.info(format!(
                        "FTP connection {connection_id} sent nothing for {}s; closing idle \
                         control connection",
                        read_timeout.as_secs()
                    ));
                    return Ok(());
                }
            };
            answered_one = true;
            let line = match outcome {
                CommandLine::Eof => break,
                CommandLine::TooLong => {
                    // A control line this long is not an FTP command. RFC 959 has no
                    // "line too long" code, but 500 is the syntax-error reply and the
                    // connection is closed so the peer cannot keep feeding the buffer.
                    log.warn(format!(
                        "FTP command line from connection {connection_id} \
                         decision=refused_line_too_long: exceeded {MAX_COMMAND_LINE} bytes \
                         without a newline; answered 500 and closing"
                    ));
                    let _ = Self::write_out(
                        write_half,
                        b"500 Command line too long\r\n",
                        app_state,
                        server_id,
                        connection_id,
                    )
                    .await;
                    return Ok(());
                }
                CommandLine::Line(line) => line,
            };
            app_state
                .update_connection_stats(
                    server_id,
                    connection_id,
                    Some(n as u64),
                    None,
                    Some(1),
                    None,
                )
                .await;

            let command = line.trim();
            // FileOnly: the ftp_command event template surfaces the command on the TUI.
            log.debug(format!("FTP received: {}", command));

            // With batching on (off by default - see `write_batch_answer`), every further
            // command line already here is answered in the same call.
            let batching = app_state
                .server_conversation_settings(server_id)
                .await
                .is_some_and(|(_, batching)| batching);
            let mut commands = vec![command.to_string()];
            if batching {
                for (more, consumed) in
                    lines_already_here(&mut reader, crate::protocol::metadata::MAX_BATCH_EVENTS - 1)
                        .await
                {
                    app_state
                        .update_connection_stats(
                            server_id,
                            connection_id,
                            Some(consumed as u64),
                            None,
                            Some(1),
                            None,
                        )
                        .await;
                    log.debug(format!("FTP received: {}", more.trim()));
                    commands.push(more.trim().to_string());
                }
            }
            let events: Vec<Event> = commands.iter().map(|c| command_event(c)).collect();

            // Get handler/LLM response
            match call_llm_batch(
                &llm_client,
                app_state,
                server_id,
                Some(connection_id),
                &events,
                protocol.as_ref(),
            )
            .await
            {
                Ok(execution_result) if commands.len() > 1 => {
                    if !Self::write_batch_answer(
                        execution_result,
                        &commands,
                        write_half,
                        app_state,
                        server_id,
                        connection_id,
                        &log,
                    )
                    .await?
                    {
                        return Ok(());
                    }
                }
                Ok(execution_result) => {
                    let (decision, detail) = classify_ftp_outcome(&execution_result);
                    match decision {
                        "model_answer" => log.info(format!(
                            "FTP {command:?} on connection {connection_id} \
                             decision=model_answer ({detail})"
                        )),
                        "model_reject" => log.info(format!(
                            "FTP {command:?} on connection {connection_id} \
                             decision=model_reject ({detail})"
                        )),
                        "model_wait_for_more" => log.info(format!(
                            "FTP {command:?} on connection {connection_id} \
                             decision=model_wait_for_more ({detail})"
                        )),
                        "fail_closed_bad_action" => log.error(format!(
                            "FTP {command:?} on connection {connection_id} \
                             decision=fail_closed_bad_action ({detail}); nothing was written and \
                             the client is left waiting"
                        )),
                        _ => log.warn(format!(
                            "FTP {command:?} on connection {connection_id} \
                             decision=model_silent ({detail})"
                        )),
                    }

                    let mut one_reply = OneReply::default();
                    for protocol_result in execution_result.protocol_results {
                        match protocol_result {
                            ActionResult::Output(data) => {
                                if !one_reply.admit(&data) {
                                    continue;
                                }
                                Self::write_out(
                                    write_half,
                                    &data,
                                    app_state,
                                    server_id,
                                    connection_id,
                                )
                                .await?;

                                let response = String::from_utf8_lossy(&data);
                                log.debug(format!("FTP sent: {}", response.trim()));
                            }
                            ActionResult::CloseConnection => {
                                one_reply.log_drops(&log, connection_id, "reply");
                                return Ok(());
                            }
                            _ => {}
                        }
                    }
                    one_reply.log_drops(&log, connection_id, "reply");
                }
                Err(e) => {
                    // Do not leave the client hanging with no diagnostic: RFC 959 421 tells it
                    // the service is unavailable and the control connection is closing.
                    //
                    // The peer gets the `WireFailure` *category* — the same one the greeting
                    // path uses — never the error text. `prefixed_text()` returns
                    // `&'static str`, so nothing derived from `e` can reach the wire; `e`
                    // itself goes to the log, which is where an operator looks.
                    let failure = crate::utils::WireFailure::classify(&e);
                    let notice = failure.prefixed_text();
                    let decision = if failure.is_overloaded() {
                        "fail_closed_llm_overloaded"
                    } else {
                        "fail_closed_llm_error"
                    };
                    log.error(format!(
                        "FTP {command:?} on connection {connection_id} decision={decision}, \
                         refused with 421 ({notice}): {e}"
                    ));
                    let reply = format!(
                        "421 Service not available, closing control connection ({notice})\r\n"
                    );
                    let _ = Self::write_out(
                        write_half,
                        reply.as_bytes(),
                        app_state,
                        server_id,
                        connection_id,
                    )
                    .await;
                    return Ok(());
                }
            }
        }

        Ok(())
    }
}

// Stub types needed for non-feature compilation
