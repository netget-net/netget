//! FTP server implementation
//!
//! File Transfer Protocol (RFC 959, RFC 2428) server with LLM-controlled responses.
//!
//! The handler answers every command on the control connection and supplies every listing and
//! file. The server owns the mechanics: the data-connection setup verbs (`PASV`, `EPSV`,
//! `PORT`, `EPRT`), `TYPE`/`MODE`/`STRU` and `REST` are answered here (`data.rs`), as are
//! `ABOR` and FTPS's `AUTH TLS`/`PBSZ`/`PROT` (`tls.rs`), and a transfer's `150` ... `226`
//! sequence is written around the handler's payload.

pub mod actions;
pub mod control;
pub mod data;
pub mod tls;

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
use control::{CommandLine, ControlReader};
use tls::{ControlWriter, MaybeTls};

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
        data_limits: data::DataLimits,
        tls_config: Arc<rustls::ServerConfig>,
    ) -> Result<SocketAddr> {
        // Both bounds are tunable because their right value is a property of who is on the
        // other end, which only the operator knows. The defaults serve NetGet's own FTP client
        // waiting on a human; a listener exposed to strangers wants the first one much lower.
        let deadlines = ReadDeadlines::resolve(first_byte_timeout_secs, idle_timeout_secs);
        let config = SessionConfig {
            deadlines,
            data: data_limits,
            // Passive listeners bind the host the server was configured with, never wider.
            bind_ip: listen_addr.ip(),
            tls: tokio_rustls::TlsAcceptor::from(tls_config),
        };
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
                        let config = config.clone();
                        receive_urgent_inline(&stream);

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
                                    config,
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

/// Everything one session needs from the server's configuration.
#[derive(Clone)]
struct SessionConfig {
    deadlines: ReadDeadlines,
    data: data::DataLimits,
    /// The configured bind host, where passive listeners are opened.
    bind_ip: std::net::IpAddr,
    /// FTPS: the control connection after `AUTH TLS`, data connections after `PROT P`.
    tls: tokio_rustls::TlsAcceptor,
}

/// Read TCP urgent data in line with the rest of the control connection.
///
/// A client may send `ABOR` as urgent data (RFC 959 §4.1.3's Synch; python's `ftplib` marks the
/// whole line `MSG_OOB`, which makes its last byte, the `\n`, the urgent one). Without
/// `SO_OOBINLINE` the kernel takes that byte out of the stream, the server reads `ABOR\r` with
/// no end of line, and the abort is never seen. vsftpd sets the same option for the same reason.
#[cfg(not(target_arch = "wasm32"))]
fn receive_urgent_inline(stream: &tokio::net::TcpStream) {
    if let Err(e) = socket2::SockRef::from(stream).set_out_of_band_inline(true) {
        tracing::warn!("FTP control connection: SO_OOBINLINE could not be set: {e}");
    }
}

/// The browser build's virtual loopback has no urgent data to receive.
#[cfg(target_arch = "wasm32")]
fn receive_urgent_inline(_stream: &tokio::net::TcpStream) {}

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

/// What a greeting the handler did not answer is replaced with before the connection closes.
///
/// 421 is the greeting RFC 959 gives a server declining the session. Fixed text, so nothing a
/// handler or an error produced can reach the wire.
const GREETING_UNANSWERED: &[u8] =
    b"421 Service not available, closing control connection (netget: no greeting was produced)\r\n";

/// What a command the handler did not answer — no usable action, or an action the executor
/// refused — is answered with.
///
/// `451 Requested action aborted: local error in processing` is RFC 959's transient failure
/// for an action the server could not carry out. A client reads it as a failed command and
/// goes on; silence would leave it waiting for a reply until its own timeout.
const COMMAND_UNANSWERED: &[u8] = b"451 Requested action aborted: local error in processing\r\n";

/// Largest control line the server will accumulate before giving up on the peer.
///
/// RFC 959 commands are short — the longest standard one is a `STOR` with a path — and
/// 8 KiB is far above anything a real client sends. The cap exists because
/// [`tokio::io::AsyncBufReadExt::read_line`] grows its buffer until it finds a newline: a
/// peer that opens a connection and streams bytes with no `\n` makes the server allocate
/// without bound, which is a one-connection out-of-memory.
pub const MAX_COMMAND_LINE: usize = 8192;

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

    // A listing or file outside a transfer has no data connection to go to.
    if result
        .protocol_results
        .iter()
        .any(|r| actions::transfer_bytes(r).is_some())
    {
        return (
            "fail_closed_bad_action",
            "send_ftp_list/send_ftp_data answer only LIST, NLST, MLSD and RETR; this command \
             has no data connection"
                .to_string(),
        );
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
        config: SessionConfig,
    ) -> Result<()> {
        let ends = data::ControlEnds {
            bind_ip: config.bind_ip,
            local: stream.local_addr()?,
            peer: stream.peer_addr()?,
        };
        let (read_half, write_half) = tokio::io::split(MaybeTls::Plain(stream));
        let write_half = Arc::new(Mutex::new(ControlWriter(Some(write_half))));

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
                ControlReader::new(read_half),
                &write_half,
                connection_id,
                server_id,
                llm_client,
                &app_state,
                &status_tx,
                protocol,
                config,
                ends,
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
                         decision=fail_closed_bad_action ({detail}); refused with 421 and closed"
                    )),
                    _ => log.warn(format!(
                        "FTP greeting on connection {connection_id} decision=model_silent \
                         ({detail}); an FTP client may send no command until it has read a \
                         greeting, so it is refused with 421 and closed"
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

                // A client sends nothing until it has read a greeting, so a greeting the
                // handler did not produce would hang it until its own timeout. A silent or
                // refused answer is declined the way a failed one is: 421, then close.
                // `wait_for_more` is excluded: there is no line to wait for, but it is the
                // handler's declared choice, and the first-command deadline still bounds it.
                if !one_reply.completed
                    && matches!(decision, "model_silent" | "fail_closed_bad_action")
                {
                    let _ = Self::write_out(
                        write_half,
                        GREETING_UNANSWERED,
                        app_state,
                        server_id,
                        connection_id,
                    )
                    .await;
                    return Err(anyhow::anyhow!(
                        "FTP greeting had no reply ({decision}); refused with 421"
                    ));
                }
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
            // Nothing answered any of them: the same outcome a single command gets, once per
            // command, so the client's replies still line up with what it sent.
            let line = format!(
                "FTP {commands:?} on connection {connection_id} decision={decision} ({detail})"
            );
            match decision {
                "model_wait_for_more" => {
                    log.info(line);
                    return Ok(true);
                }
                "fail_closed_bad_action" => log.error(format!("{line}; each answered 451")),
                _ => log.warn(format!("{line}; each answered 451")),
            }
            for _ in commands {
                Self::write_out(
                    write_half,
                    COMMAND_UNANSWERED,
                    app_state,
                    server_id,
                    connection_id,
                )
                .await?;
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
    async fn handle_session_commands(
        mut reader: ControlReader,
        write_half: &Arc<Mutex<ControlWriter>>,
        connection_id: crate::server::connection::ConnectionId,
        server_id: crate::state::ServerId,
        llm_client: OllamaClient,
        app_state: &Arc<AppState>,
        status_tx: &mpsc::UnboundedSender<String>,
        protocol: Arc<FtpProtocol>,
        config: SessionConfig,
        ends: data::ControlEnds,
    ) -> Result<()> {
        let deadlines = config.deadlines;
        let log = Log::new(Some(status_tx));
        let mut data_state = data::DataState::default();

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
                reader.read_line(MAX_COMMAND_LINE),
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

            let verb = data::Verb::of(command);
            if verb.is_setup() {
                // Data-connection setup and representation type: answered here, because each
                // reply names a socket only the server can open or changes how it frames bytes.
                let answer = data::answer_setup(verb, command, &mut data_state, &ends).await;
                log.info(format!(
                    "FTP {command:?} on connection {connection_id} decision={} ({})",
                    answer.decision,
                    answer.reply.trim_end()
                ));
                Self::write_out(
                    write_half,
                    answer.reply.as_bytes(),
                    app_state,
                    server_id,
                    connection_id,
                )
                .await?;
                continue;
            }
            if verb == data::Verb::Abor {
                // An ABOR read here has no transfer to abort: one in progress is watched for
                // ABOR by `watch`, which answers it there. RFC 959 §4.1.3: close any data
                // connection, and reply that there was nothing to abort.
                data_state.channel = None;
                data_state.restart = None;
                log.info(format!(
                    "FTP {command:?} on connection {connection_id} decision=server_answer \
                     (225, no transfer in progress)"
                ));
                Self::write_out(
                    write_half,
                    b"225 No transfer to abort\r\n",
                    app_state,
                    server_id,
                    connection_id,
                )
                .await?;
                continue;
            }
            if verb == data::Verb::Auth {
                let keep_going = Self::answer_auth(
                    command,
                    &mut reader,
                    write_half,
                    &mut data_state,
                    &config,
                    app_state,
                    server_id,
                    connection_id,
                    &log,
                )
                .await?;
                if !keep_going {
                    return Ok(());
                }
                continue;
            }
            if verb.is_transfer() {
                let keep_going = Transfer {
                    verb,
                    command,
                    write_half,
                    connection_id,
                    server_id,
                    llm_client: &llm_client,
                    app_state,
                    protocol: &protocol,
                    log: &log,
                    ends: &ends,
                    limits: &config.data,
                    tls: &config.tls,
                }
                .run(&mut data_state, &mut reader)
                .await?;
                if !keep_going {
                    return Ok(());
                }
                continue;
            }

            // With batching on (off by default - see `write_batch_answer`), every further
            // command line already here is answered in the same call.
            let batching = app_state
                .server_conversation_settings(server_id)
                .await
                .is_some_and(|(_, batching)| batching);
            let mut commands = vec![command.to_string()];
            if batching {
                for (more, consumed) in reader
                    .lines_already_here(
                        crate::protocol::metadata::MAX_BATCH_EVENTS - 1,
                        MAX_COMMAND_LINE,
                        // A setup or transfer command is answered on its own path, so a batch
                        // ends before it and leaves it to be read next.
                        |line| data::Verb::of(line) == data::Verb::Other,
                    )
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
                             decision=fail_closed_bad_action ({detail}); answered 451"
                        )),
                        _ => log.warn(format!(
                            "FTP {command:?} on connection {connection_id} \
                             decision=model_silent ({detail}); answered 451"
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
                    if !one_reply.completed
                        && matches!(decision, "model_silent" | "fail_closed_bad_action")
                    {
                        Self::write_out(
                            write_half,
                            COMMAND_UNANSWERED,
                            app_state,
                            server_id,
                            connection_id,
                        )
                        .await?;
                    }
                }
                Err(e) => {
                    Self::refuse_backend_failure(
                        &e,
                        command,
                        write_half,
                        app_state,
                        server_id,
                        connection_id,
                        &log,
                    )
                    .await;
                    return Ok(());
                }
            }
        }

        Ok(())
    }

    /// `AUTH TLS` (RFC 4217 §4): answer `234`, then turn the control connection into TLS in
    /// place. `Ok(false)` when the connection is to close: the handshake failed or the client
    /// did not start one within `idle_timeout_secs`, and there is no clear text left to reply in.
    #[allow(clippy::too_many_arguments)]
    async fn answer_auth(
        command: &str,
        reader: &mut ControlReader,
        write_half: &Arc<Mutex<ControlWriter>>,
        data_state: &mut data::DataState,
        config: &SessionConfig,
        app_state: &AppState,
        server_id: crate::state::ServerId,
        connection_id: crate::server::connection::ConnectionId,
        log: &Log<'_>,
    ) -> Result<bool> {
        let refuse = |decision: &str, reply: &'static [u8]| {
            log.info(format!(
                "FTP {command:?} on connection {connection_id} decision={decision} ({})",
                String::from_utf8_lossy(reply).trim_end()
            ));
            reply
        };
        // RFC 2228's mechanism names: AUTH TLS (RFC 4217), and AUTH SSL / TLS-C, which
        // clients still send and every FTPS server treats as the same thing. curl tries SSL
        // first.
        let mechanism = argument_of(command).to_ascii_uppercase();
        let reply = if !matches!(mechanism.as_str(), "TLS" | "SSL" | "TLS-C") {
            Some(refuse(
                "refused_unsupported",
                b"504 AUTH mechanism not supported; use AUTH TLS\r\n",
            ))
        } else if data_state.control_tls {
            Some(refuse(
                "refused_sequence",
                b"503 The control connection is already TLS\r\n",
            ))
        } else if reader.has_pending() {
            // The client must wait for the 234 before its ClientHello; bytes already here
            // would be read as clear text inside what it thinks is a TLS session.
            Some(refuse(
                "refused_sequence",
                b"503 Nothing may follow AUTH before its reply\r\n",
            ))
        } else {
            None
        };
        if let Some(reply) = reply {
            Self::write_out(write_half, reply, app_state, server_id, connection_id).await?;
            return Ok(true);
        }

        Self::write_out(
            write_half,
            b"234 AUTH TLS successful; start the TLS handshake\r\n",
            app_state,
            server_id,
            connection_id,
        )
        .await?;

        // The writer stays locked for the handshake, so the dashboard's peer task cannot write
        // clear text into the middle of it.
        let mut writer = write_half.lock().await;
        let (Some(write), Some(read)) = (writer.0.take(), reader.take_half()) else {
            return Err(anyhow::anyhow!(
                "FTP connection {connection_id}: control halves missing at AUTH TLS"
            ));
        };
        let MaybeTls::Plain(tcp) = read.unsplit(write) else {
            return Err(anyhow::anyhow!(
                "FTP connection {connection_id}: AUTH TLS on a connection that is already TLS"
            ));
        };
        // The handshake is the client's next move after a reply, so the between-commands
        // bound is the one that applies to a client that never makes it.
        let idle = config.deadlines.idle;
        match tokio::time::timeout(idle, config.tls.accept(tcp)).await {
            Ok(Ok(stream)) => {
                let (read, write) = tokio::io::split(MaybeTls::Tls(Box::new(stream)));
                writer.0 = Some(write);
                reader.put_half(read);
                // RFC 4217 §9: protection is negotiated afresh on the protected connection.
                data_state.control_tls = true;
                data_state.pbsz = false;
                data_state.protect = false;
                log.info(format!(
                    "FTP {command:?} on connection {connection_id} decision=tls_established \
                     (234, the control connection is TLS)"
                ));
                Ok(true)
            }
            Ok(Err(e)) => {
                log.warn(format!(
                    "FTP {command:?} on connection {connection_id} \
                     decision=refused_tls_handshake ({e}); closing"
                ));
                Ok(false)
            }
            Err(_) => {
                log.warn(format!(
                    "FTP {command:?} on connection {connection_id} \
                     decision=refused_tls_handshake (no handshake within {}s of the 234); \
                     closing",
                    idle.as_secs()
                ));
                Ok(false)
            }
        }
    }

    /// Answer a command whose handler call failed: `421`, and the caller closes.
    ///
    /// RFC 959's 421 tells the client the service is unavailable and the control connection is
    /// closing, rather than leaving it hanging with no diagnostic. The peer gets the
    /// `WireFailure` *category*, never the error text: `prefixed_text()` returns
    /// `&'static str`, so nothing derived from `e` can reach the wire; `e` itself goes to the
    /// log, which is where an operator looks.
    #[allow(clippy::too_many_arguments)]
    async fn refuse_backend_failure<W>(
        e: &anyhow::Error,
        command: &str,
        write_half: &Arc<Mutex<W>>,
        app_state: &AppState,
        server_id: crate::state::ServerId,
        connection_id: crate::server::connection::ConnectionId,
        log: &Log<'_>,
    ) where
        W: tokio::io::AsyncWrite + Unpin,
    {
        let failure = crate::utils::WireFailure::classify(e);
        let notice = failure.prefixed_text();
        let decision = if failure.is_overloaded() {
            "fail_closed_llm_overloaded"
        } else {
            "fail_closed_llm_error"
        };
        log.error(format!(
            "FTP {command:?} on connection {connection_id} decision={decision}, refused with \
             421 ({notice}): {e}"
        ));
        let reply = format!("421 Service not available, closing control connection ({notice})\r\n");
        let _ = Self::write_out(
            write_half,
            reply.as_bytes(),
            app_state,
            server_id,
            connection_id,
        )
        .await;
    }
}

/// One transfer command (`LIST`, `NLST`, `MLSD`, `RETR`, `STOR`, `APPE`, `STOU`) and everything
/// it needs from the session.
///
/// RFC 959 §5.4 fixes the reply sequences: a download is refused with `450`/`550` *before* any
/// `150`, and once `150` is written its completion is `226`, `425` (no data connection), `426`
/// (the data connection broke, or `ABOR`) or `451`. So the handler is asked first, and only an
/// answer that carries a payload opens the data connection. An upload has to be read before
/// there is anything to ask about, so its `150` comes first and the handler's reply is the
/// completion.
struct Transfer<'a, W> {
    verb: data::Verb,
    command: &'a str,
    write_half: &'a Arc<Mutex<W>>,
    connection_id: crate::server::connection::ConnectionId,
    server_id: crate::state::ServerId,
    llm_client: &'a OllamaClient,
    app_state: &'a Arc<AppState>,
    protocol: &'a Arc<FtpProtocol>,
    log: &'a Log<'a>,
    ends: &'a data::ControlEnds,
    limits: &'a data::DataLimits,
    tls: &'a tokio_rustls::TlsAcceptor,
}

/// Why the data phase of a transfer did not complete.
enum DataFailure {
    /// The data connection did not open (or its TLS handshake did not complete): `425`.
    Open(String),
    /// It opened and then stalled or broke: `426`.
    Broken(String),
    /// More than `max_upload_bytes` arrived: `552`.
    TooLarge,
}

/// How a data phase raced against the control connection ended.
enum Watched<T> {
    Done(T),
    /// The client sent `ABOR`; the value is the bytes its line took.
    Aborted(usize),
    /// The control connection closed or failed mid-transfer.
    ControlLost,
}

/// Run `work` (the data phase of a transfer) while reading the control connection for `ABOR`.
///
/// RFC 959 §4.1.3: `ABOR` during a transfer stops it, and the server answers the transfer
/// command `426` and then `ABOR` itself `226`. Dropping `work` closes the data connection, which
/// is the abort. Any other command that arrives meanwhile is put back to be answered once the
/// transfer ends, and the control connection is not read again until then: commands are
/// answered in order, and a client that pipelines one behind a transfer can wait for it.
async fn watch<T>(
    control: &mut ControlReader,
    work: impl std::future::Future<Output = T>,
) -> Watched<T> {
    tokio::pin!(work);
    let mut watching = true;
    loop {
        tokio::select! {
            out = &mut work => return Watched::Done(out),
            line = control.read_line(MAX_COMMAND_LINE), if watching => match line {
                Ok((CommandLine::Line(line), n)) => {
                    if data::Verb::of(&line) == data::Verb::Abor {
                        return Watched::Aborted(n);
                    }
                    control.unread(&line);
                    watching = false;
                }
                _ => return Watched::ControlLost,
            },
        }
    }
}

impl<W> Transfer<'_, W>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    async fn reply(&self, bytes: &[u8]) -> std::io::Result<()> {
        FtpSession::write_out(
            self.write_half,
            bytes,
            self.app_state,
            self.server_id,
            self.connection_id,
        )
        .await
    }

    /// Count data-connection bytes on the control connection's row, so the dashboard's
    /// counters show the transfer.
    async fn count_data(&self, received: u64, sent: u64) {
        self.app_state
            .update_connection_stats(
                self.server_id,
                self.connection_id,
                (received > 0).then_some(received),
                (sent > 0).then_some(sent),
                None,
                None,
            )
            .await;
    }

    fn line(&self, decision: &str, detail: impl std::fmt::Display) -> String {
        format!(
            "FTP {:?} on connection {} decision={decision} ({detail})",
            self.command, self.connection_id
        )
    }

    /// Run the transfer. `Ok(false)` when the control connection is to close.
    async fn run(self, state: &mut data::DataState, control: &mut ControlReader) -> Result<bool> {
        // The marker belongs to the transfer command right after REST, whichever it is.
        let restart = state.restart.take();
        // One prepared channel, one transfer, whatever the outcome.
        let Some(channel) = state.channel.take() else {
            self.log.info(self.line(
                "refused_no_data_connection",
                "no PASV, EPSV, PORT or EPRT before it; answered 425",
            ));
            self.reply(b"425 Use PASV, EPSV, PORT or EPRT first\r\n")
                .await?;
            return Ok(true);
        };
        let restart = match restart {
            Some(offset) if self.verb.restarts() => Some(offset),
            Some(offset) => {
                self.log.debug(self.line(
                    "restart_ignored",
                    format!("REST {offset} applies to RETR and STOR only"),
                ));
                None
            }
            None => None,
        };
        let job = Job {
            channel,
            transfer_type: state.transfer_type,
            tls: state.protect.then_some(self.tls),
            restart,
        };
        if self.verb.is_upload() {
            self.upload(job, control).await
        } else {
            self.download(job, control).await
        }
    }

    fn event(&self, transfer_type: data::TransferType, restart: Option<u64>) -> Event {
        let mut event = command_event(self.command);
        event.data["transfer_type"] = serde_json::json!(transfer_type.event_name());
        if let Some(offset) = restart {
            event.data["restart_offset"] = serde_json::json!(offset);
        }
        event
    }

    /// `ABOR` arrived mid-transfer: the data connection is already closed (its future was
    /// dropped), so answer the transfer `426` and the `ABOR` `226`, in that order.
    async fn aborted(&self, abor_bytes: usize) -> std::io::Result<()> {
        self.app_state
            .update_connection_stats(
                self.server_id,
                self.connection_id,
                Some(abor_bytes as u64),
                None,
                Some(1),
                None,
            )
            .await;
        self.log.info(self.line(
            "transfer_aborted_by_client",
            "ABOR during the transfer; data connection closed, answered 426 then 226",
        ));
        self.reply(b"426 Connection closed; transfer aborted\r\n")
            .await?;
        self.reply(b"226 Abort successful\r\n").await
    }

    async fn data_failed(&self, failure: DataFailure) -> std::io::Result<()> {
        match failure {
            DataFailure::Open(why) => {
                self.log
                    .warn(self.line("refused_data_connection", format!("{why}; answered 425")));
                self.reply(b"425 Can't open data connection\r\n").await
            }
            DataFailure::Broken(why) => {
                self.log
                    .warn(self.line("transfer_aborted", format!("{why}; answered 426")));
                self.reply(b"426 Connection closed; transfer aborted\r\n")
                    .await
            }
            DataFailure::TooLarge => {
                self.log.warn(self.line(
                    "refused_upload_too_large",
                    format!(
                        "more than {} bytes; answered 552 without asking the handler",
                        self.limits.max_upload
                    ),
                ));
                self.reply(b"552 Requested file action aborted: exceeded storage allocation\r\n")
                    .await
            }
        }
    }

    async fn download(self, job: Job<'_>, control: &mut ControlReader) -> Result<bool> {
        let event = self.event(job.transfer_type, job.restart);
        let result = match call_llm(
            self.llm_client,
            self.app_state,
            self.server_id,
            Some(self.connection_id),
            &event,
            self.protocol.as_ref(),
        )
        .await
        {
            Ok(result) => result,
            Err(e) => {
                FtpSession::refuse_backend_failure(
                    &e,
                    self.command,
                    self.write_half,
                    self.app_state,
                    self.server_id,
                    self.connection_id,
                    self.log,
                )
                .await;
                return Ok(false);
            }
        };

        let (decision, detail) = classify_ftp_outcome(&result);
        let mut payload: Option<Vec<u8>> = None;
        let mut replies: Vec<Vec<u8>> = Vec::new();
        let mut closes = false;
        for r in &result.protocol_results {
            if let Some(bytes) = actions::transfer_bytes(r) {
                payload.get_or_insert_with(Vec::new).extend(bytes);
                continue;
            }
            match r {
                ActionResult::Output(d) => replies.push(d.clone()),
                ActionResult::CloseConnection => closes = true,
                _ => {}
            }
        }

        let Some(payload) = payload else {
            // No listing or file: the handler refused, or did not answer.
            if let Some(refusal) = replies
                .iter()
                .find(|d| reply_code_of(d).is_some_and(|c| c >= 400))
            {
                self.log.info(self.line(
                    "model_answer",
                    format!("reply {}", reply_code_of(refusal).unwrap_or(0)),
                ));
                self.reply(refusal).await?;
            } else if closes {
                self.log.info(self.line("model_reject", detail));
                return Ok(false);
            } else {
                // A 1xx or 2xx with no payload would claim a transfer that has nothing to
                // send; silence would leave the client waiting. Either way the honest answer
                // is that the action could not be carried out.
                let decision = if decision == "model_answer" {
                    "fail_closed_no_payload"
                } else {
                    decision
                };
                self.log
                    .warn(self.line(decision, format!("{detail}; answered 451")));
                self.reply(COMMAND_UNANSWERED).await?;
            }
            return Ok(!closes);
        };

        // REST: the handler gave the whole file and the transfer starts `offset` bytes in. An
        // offset past the end names no byte to start from, so it is refused before any 150.
        let payload = match job.restart {
            Some(offset) if offset > payload.len() as u64 => {
                self.log.info(self.line(
                    "refused_restart_offset",
                    format!(
                        "REST {offset} is past the end of the {}-byte file; answered 554",
                        payload.len()
                    ),
                ));
                let reply = format!(
                    "554 Restart offset {offset} is past the end of the file ({} bytes)\r\n",
                    payload.len()
                );
                self.reply(reply.as_bytes()).await?;
                return Ok(!closes);
            }
            Some(offset) => payload[offset as usize..].to_vec(),
            None => payload,
        };

        // The handler may name its own completion text; anything else it wrote around the
        // payload would break the sequence the server is writing, and is dropped.
        let completion = replies
            .iter()
            .find(|d| matches!(reply_code_of(d), Some(226 | 250)))
            .cloned();
        let dropped = replies.len() - usize::from(completion.is_some());
        if dropped > 0 {
            self.log.warn(self.line(
                "transfer_reply_dropped",
                format!("{dropped} reply(ies) beside the payload were not sent"),
            ));
        }
        let wire = if job.transfer_type == data::TransferType::Ascii && !self.verb.is_listing() {
            data::to_network_ascii(&payload)
        } else {
            payload
        };

        let what = if self.verb.is_listing() {
            "directory listing".to_string()
        } else {
            format!("{} ({} bytes)", argument_of(self.command), wire.len())
        };
        self.reply(data::opening_reply(job.transfer_type, &what).as_bytes())
            .await?;

        let (ends, limits) = (self.ends, self.limits);
        let work = async {
            let mut stream = data::open(job.channel, ends, limits, job.tls)
                .await
                .map_err(DataFailure::Open)?;
            data::send_all(&mut stream, &wire, limits.idle)
                .await
                .map_err(DataFailure::Broken)
        };
        match watch(control, work).await {
            Watched::Done(Ok(())) => {
                self.count_data(0, wire.len() as u64).await;
                self.log.info(self.line(
                    "model_answer",
                    format!("{} bytes on the data connection, then 226", wire.len()),
                ));
                let completion =
                    completion.unwrap_or_else(|| b"226 Transfer complete\r\n".to_vec());
                self.reply(&completion).await?;
            }
            Watched::Done(Err(failure)) => self.data_failed(failure).await?,
            Watched::Aborted(n) => self.aborted(n).await?,
            Watched::ControlLost => return Ok(false),
        }
        Ok(!closes)
    }

    async fn upload(self, job: Job<'_>, control: &mut ControlReader) -> Result<bool> {
        // STOU (RFC 959 §4.1.3): the server names the file, and RFC 1123 §4.1.2.9 has the name
        // in the 150 as "FILE: <name>". There is no directory to check it against, so it is
        // random enough never to repeat.
        let unique_name =
            (self.verb == data::Verb::Stou).then(|| format!("ftp-{:016x}", rand::random::<u64>()));
        let opening = match &unique_name {
            Some(name) => format!("150 FILE: {name}\r\n"),
            None => data::opening_reply(job.transfer_type, &argument_of(self.command)),
        };
        self.reply(opening.as_bytes()).await?;

        let limits = self.limits;
        let ends = self.ends;
        let (channel, tls) = (job.channel, job.tls);
        let work = async {
            let mut stream = data::open(channel, ends, limits, tls)
                .await
                .map_err(DataFailure::Open)?;
            let raw = match data::receive_all(&mut stream, limits).await {
                data::Upload::Complete(raw) => raw,
                data::Upload::TooLarge => return Err(DataFailure::TooLarge),
                data::Upload::Idle => {
                    return Err(DataFailure::Broken(format!(
                        "the peer sent nothing for {}s",
                        limits.idle.as_secs()
                    )))
                }
                data::Upload::Failed(why) => return Err(DataFailure::Broken(why)),
            };
            // Answer the client's close in kind: on a TLS data connection this is the
            // close_notify a client that shuts TLS down properly (python's `unwrap()`) waits for.
            let _ =
                tokio::time::timeout(limits.idle, tokio::io::AsyncWriteExt::shutdown(&mut stream))
                    .await;
            Ok(raw)
        };
        let raw = match watch(control, work).await {
            Watched::Done(Ok(raw)) => raw,
            Watched::Done(Err(failure)) => {
                self.data_failed(failure).await?;
                return Ok(true);
            }
            Watched::Aborted(n) => {
                self.aborted(n).await?;
                return Ok(true);
            }
            Watched::ControlLost => return Ok(false),
        };
        self.count_data(raw.len() as u64, 0).await;

        let content = if job.transfer_type == data::TransferType::Ascii {
            data::from_network_ascii(&raw)
        } else {
            raw
        };
        let mut event = self.event(job.transfer_type, job.restart);
        event.data["upload_bytes"] = serde_json::json!(content.len());
        if let Some(name) = &unique_name {
            event.data["unique_name"] = serde_json::json!(name);
        }
        match String::from_utf8(content) {
            Ok(text) => {
                event.data["upload_is_text"] = serde_json::json!(true);
                event.data["upload_text"] = serde_json::json!(text);
            }
            Err(not_text) => {
                event.data["upload_is_text"] = serde_json::json!(false);
                let bytes = not_text.into_bytes();
                // A model can read binary only as hex; past the bound the size alone has to do.
                if bytes.len() <= self.limits.max_hex_upload {
                    event.data["upload_hex"] = serde_json::json!(hex::encode(&bytes));
                } else {
                    self.log.info(self.line(
                        "upload_hex_omitted",
                        format!(
                            "{} binary bytes is over max_hex_upload_bytes ({}); the handler \
                             gets the size alone",
                            bytes.len(),
                            self.limits.max_hex_upload
                        ),
                    ));
                }
            }
        }

        let result = match call_llm(
            self.llm_client,
            self.app_state,
            self.server_id,
            Some(self.connection_id),
            &event,
            self.protocol.as_ref(),
        )
        .await
        {
            Ok(result) => result,
            Err(e) => {
                FtpSession::refuse_backend_failure(
                    &e,
                    self.command,
                    self.write_half,
                    self.app_state,
                    self.server_id,
                    self.connection_id,
                    self.log,
                )
                .await;
                return Ok(false);
            }
        };

        let (decision, detail) = classify_ftp_outcome(&result);
        // After 150 only a completion reply belongs on the wire: the first one the handler
        // gave, or 451 when it gave none.
        let completion = result.protocol_results.iter().find_map(|r| match r {
            ActionResult::Output(d) if reply_code_of(d).is_some_and(|c| c >= 200) => Some(d),
            _ => None,
        });
        let closes = result
            .protocol_results
            .iter()
            .any(|r| matches!(r, ActionResult::CloseConnection));
        match completion {
            Some(reply) => {
                self.log.info(self.line(
                    "model_answer",
                    format!("reply {}", reply_code_of(reply).unwrap_or(0)),
                ));
                self.reply(reply).await?;
            }
            None if closes => {
                self.log.info(self.line("model_reject", detail));
                return Ok(false);
            }
            None => {
                let decision = if decision == "model_answer" {
                    "fail_closed_no_completion"
                } else {
                    decision
                };
                self.log
                    .warn(self.line(decision, format!("{detail}; answered 451")));
                self.reply(COMMAND_UNANSWERED).await?;
            }
        }
        Ok(!closes)
    }
}

/// What one transfer was set up with before it started.
struct Job<'a> {
    channel: data::DataChannel,
    transfer_type: data::TransferType,
    /// `Some` after `PROT P`: the data connection is TLS.
    tls: Option<&'a tokio_rustls::TlsAcceptor>,
    /// The `REST` offset, for `RETR` and `STOR`.
    restart: Option<u64>,
}

/// The argument of a command line, for a `150` reply's text, with any control character
/// removed so it cannot end the reply early.
fn argument_of(command: &str) -> String {
    let command = command.trim();
    let arg = match command.find(char::is_whitespace) {
        Some(i) => command[i..].trim(),
        None => "",
    };
    crate::utils::sanitize::strip_controls(arg)
}
