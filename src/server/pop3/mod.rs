//! POP3 server implementation
pub mod actions;

use anyhow::Result;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, error, info};

use crate::console_debug;
use crate::llm::action_helper::call_llm;
use crate::llm::ollama_client::OllamaClient;
use crate::llm::ActionResult;
use crate::protocol::Event;
use crate::server::Pop3Protocol;
use crate::state::app_state::AppState;
use actions::POP3_COMMAND_EVENT;
use tokio_rustls::TlsAcceptor;

/// Largest single command line the server will buffer before refusing the peer.
///
/// RFC 2449 §4 fixes the POP3 command line at **255 octets** including the CRLF, and RFC 1939
/// keeps every keyword to three or four characters. 1 KiB is four times the spec's own ceiling,
/// so nothing a conforming client sends is refused, and the margin covers a long `USER` or an
/// `APOP` digest without inviting anything larger.
///
/// The cap exists because `AsyncBufReadExt::read_line` grows its `String` until it finds a
/// `\n` and bounds nothing: an unauthenticated peer that connects and streams bytes with no
/// newline made the server allocate without limit, which is a one-connection out-of-memory.
/// The refusal happens here, before the `pop3_command_received` event is built, so an
/// oversized line never reaches a prompt.
pub const MAX_COMMAND_BYTES: usize = 1024;

/// How long to wait for the first command after the greeting has been sent.
///
/// **This was 60 seconds — Dovecot's `login_timeout` — and "POP3 is server-speaks-first" was
/// the wrong reason for it.** The argument read: the peer gets a `+OK` greeting and every real
/// client answers it with `CAPA`, `USER` or `AUTH` from inside its own connect path, and
/// Dovecot bounds exactly this pre-authentication phase at a minute. True of every third-party
/// client, and irrelevant to the peer this server most often has: the greeting is *ours*, and
/// sending it says nothing about whether the other end will answer it.
///
/// The question a first-byte bound actually has to answer is whether NetGet's own client of
/// this protocol can be connected and silent. POP3's can, and is, by default:
/// `src/client/pop3/mod.rs` opens the socket, registers its command channel, and then reads
/// the `+OK` greeting in its read loop. It writes nothing of its own — every byte it puts on
/// the wire comes from an action — and a client created from the dashboard's
/// `[ + pop3 client ]` is routed `pop3_connected` → static-with-no-actions and then `*` →
/// manual (`src/tui/modal/form.rs`). So it connects, reads our greeting, parks it for a
/// person, and waits for someone to type into `[ send message ]`. At 60 seconds this server
/// hung up on the operator's own client while they were still looking at it.
///
/// Dovecot's number is not wrong for Dovecot — it has no client that parks on a human. 300
/// seconds is the window a `manual` rule gives a human to answer one event
/// (`src/state/intercepts.rs`), which is the number this product already uses for how long
/// someone might take.
///
/// What it costs: a stranger holding a socket, a task, an `AppState` row and one of
/// [`MAX_CONNECTIONS`] slots while saying nothing now gets 300 seconds rather than 60 — a
/// fivefold rise in how long one idle slot is held, not a removal of the bound. The cap still
/// holds and a peer over it is still answered [`CONNECTION_CAP_REFUSAL`]. A listener exposed
/// to strangers should set `first_byte_timeout_secs` back to 60, which is Dovecot's own
/// number and a sound choice for one.
///
/// The greeting itself sits outside this deadline by construction: it is generated and written
/// before the command loop begins, so however long the model — or a `manual` rule parking it
/// for a human — takes over it, the clock below has not started.
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
/// Ten minutes, which is not a taste: RFC 1939 §3 says a POP3 server's inactivity autologout
/// timer "MUST be of at least 10 minutes' duration". This is that timer, at its minimum. The
/// shorter bound above does not contradict it — what the RFC protects is a *session*, whose
/// deletions are only committed at `QUIT`, and a peer that has issued no command has no session
/// to lose.
///
/// The LLM round-trip and a `manual` rule parking a command for a human
/// (`src/state/intercepts.rs`, 300s by default) both happen after a line has already been read,
/// so neither can be timed out from under itself.
///
/// Overridable per server with `idle_timeout_secs` — but note that RFC 1939's floor means
/// lowering it below 600 puts this server outside the specification, which the parameter's own
/// description says.
const IDLE_BETWEEN_COMMANDS_TIMEOUT: Duration = Duration::from_secs(600);

/// Concurrent connections this server admits.
///
/// [`crate::server::accept_bounded::DEFAULT_MAX_CONNECTIONS`]. Each connection may buffer up to
/// [`MAX_COMMAND_BYTES`], so this is the multiplier that turns that per-connection bound into a
/// total one.
const MAX_CONNECTIONS: usize = crate::server::accept_bounded::DEFAULT_MAX_CONNECTIONS;

/// What a peer over [`MAX_CONNECTIONS`] is told before the socket closes.
///
/// `-ERR` in place of the greeting is how POP3 refuses a connection it will not serve, and
/// RFC 3206's `[SYS/TEMP]` response code says precisely what a connection cap means: a
/// temporary condition, retry later. A client that understands it backs off instead of
/// recording a permanent fault; one that does not still reads a well-formed `-ERR`. This file
/// already uses the `[SYS/PERM]` half of the same pair for an over-long command line.
const CONNECTION_CAP_REFUSAL: &[u8] = b"-ERR [SYS/TEMP] too many connections\r\n";

/// POP3 server that forwards mail retrieval to LLM
/// NetGet's answer to `CAPA` (RFC 2449).
///
/// Answered here rather than by the model because it has one correct form: the commands this
/// server has actions for (`USER`/`PASS`, `TOP`, `UIDL`) and the extended response codes its own
/// failure replies carry (`RESP-CODES` - `[SYS/TEMP]`, `[SYS/PERM]`). It is multi-line, and no
/// model action renders a multi-line `+OK` block other than the message and listing actions, so
/// a model asked for it answered a single `+OK` and left the client waiting for a `.` that never
/// came. Nothing else is advertised: no STLS, no SASL, no PIPELINING, no APOP.
pub const CAPA_REPLY: &[u8] =
    b"+OK Capability list follows\r\nUSER\r\nTOP\r\nUIDL\r\nRESP-CODES\r\n.\r\n";

/// The actions whose reply wins when a batch answers one POP3 command with several: the one
/// the command's `answer_with` names when only one fits. The real-model eval found the model
/// answering `STAT` with a bare `+OK` *and then* the `STAT` line; the second is the answer.
/// See `ExecutionResult::chosen_reply`.
pub fn pop3_preferred_actions(command: &str) -> &'static [&'static str] {
    if command == "CONNECTION_ESTABLISHED" {
        return &["send_pop3_greeting"];
    }
    let mut words = command.split_whitespace();
    let verb = words.next().unwrap_or("").to_ascii_uppercase();
    let has_arg = words.next().is_some();
    match (verb.as_str(), has_arg) {
        ("STAT", _) => &["send_pop3_stat"],
        ("LIST", false) => &["send_pop3_list"],
        ("UIDL", false) => &["send_pop3_uidl"],
        ("RETR", _) => &["send_pop3_retr", "send_pop3_err"],
        ("TOP", _) => &["send_pop3_top", "send_pop3_err"],
        _ => &[],
    }
}

/// A `RETR`/`TOP` answered as a `+OK` status line and the message as raw text, framed by NetGet.
///
/// The real-model eval found llama3.1:8b answering `RETR` with `send_pop3_ok` followed by
/// `send_pop3_message` carrying the message itself - the right content, split the way the wire
/// shows it, with no terminating `.`, so the client waited for one until its timeout. That is a
/// multi-line answer with its mechanics missing, and the mechanics are NetGet's to write: the
/// status line, the byte-stuffed body and the `.` line, exactly as `send_pop3_retr` renders
/// them. Returns `None` - leaving the batch alone - unless the command is `RETR`/`TOP`, the
/// batch has no `send_pop3_retr`/`send_pop3_top`/`send_pop3_err` of its own, and a
/// `send_pop3_message` in it is not itself a status line.
pub fn assemble_multiline_answer(
    command: &str,
    result: &crate::llm::actions::executor::ExecutionResult,
) -> Option<Vec<u8>> {
    if command != "RETR" && command != "TOP" {
        return None;
    }
    let names = &result.protocol_result_actions;
    if names.iter().any(|n| {
        matches!(
            n.as_str(),
            "send_pop3_retr" | "send_pop3_top" | "send_pop3_err"
        )
    }) {
        return None;
    }
    let body = names
        .iter()
        .zip(&result.protocol_results)
        .find_map(|(name, r)| {
            if name != "send_pop3_message" {
                return None;
            }
            let text = String::from_utf8_lossy(r.get_all_output().first()?).into_owned();
            (!text.starts_with("+OK") && !text.starts_with("-ERR")).then_some(text)
        })?;
    // A terminator the model wrote itself is not message text.
    let body = body.replace("\r\n", "\n");
    let body = body
        .trim_end_matches('\n')
        .strip_suffix("\n.")
        .unwrap_or(body.trim_end_matches('\n'));
    let framed = actions::format_pop3_multiline_body(body);
    Some(format!("+OK {} octets\r\n{}.\r\n", framed.len(), framed).into_bytes())
}

/// The event data for one POP3 command line: the line itself, plus what NetGet can tell from
/// it.
///
/// `answer_with` names the action this particular command takes. The real-model eval found a
/// small model answering `RETR` with a bare `send_pop3_ok` - a single `+OK` line, after which
/// the client waits for the message body and its terminating `.` until its own timeout. A
/// per-request hint is followed far better than the general action list. `message_number`
/// (and `lines`, for `TOP`) are the command's arguments as numbers.
pub fn pop3_command_event_data(command: &str) -> serde_json::Value {
    let mut data = serde_json::json!({ "command": command });
    if command == "CONNECTION_ESTABLISHED" {
        data["answer_with"] = "send_pop3_greeting".into();
        return data;
    }
    let mut words = command.split_whitespace();
    let verb = words.next().unwrap_or("").to_ascii_uppercase();
    let n: Option<u64> = words.next().and_then(|w| w.parse().ok());
    let lines: Option<u64> = words.next().and_then(|w| w.parse().ok());
    if let Some(n) = n {
        data["message_number"] = n.into();
    }
    let answer = match (verb.as_str(), n) {
        ("USER", _) => "send_pop3_ok to accept the user name (the password follows), or \
                        send_pop3_err to refuse it"
            .to_string(),
        ("PASS", _) => {
            "send_pop3_ok to log in, or send_pop3_err to refuse the password".to_string()
        }
        ("STAT", _) => "send_pop3_stat with message_count and total_size (octets) for the whole \
                        mailbox"
            .to_string(),
        ("LIST", None) => "send_pop3_list with the id and size of every message".to_string(),
        ("LIST", Some(n)) => format!(
            "send_pop3_ok with message \"{n} <size in octets>\" for message {n}, or \
             send_pop3_err if there is no message {n}"
        ),
        ("UIDL", None) => "send_pop3_uidl with the id and unique id of every message".to_string(),
        ("UIDL", Some(n)) => format!(
            "send_pop3_ok with message \"{n} <unique id>\" for message {n}, or send_pop3_err \
             if there is no message {n}"
        ),
        ("RETR", Some(n)) => format!(
            "send_pop3_retr with the whole of message {n}: its from, to, subject and body \
             (NetGet writes the header lines, the octet count and the terminating '.'); \
             send_pop3_err if there is no message {n}. Never a bare send_pop3_ok: the client \
             waits for the message itself"
        ),
        ("TOP", Some(n)) => {
            if let Some(lines) = lines {
                data["lines"] = lines.into();
            }
            format!(
                "send_pop3_top with message {n}'s headers and the first {} body lines; \
                 send_pop3_err if there is no message {n}",
                lines.map_or_else(|| "requested".to_string(), |l| l.to_string())
            )
        }
        ("DELE", Some(n)) => format!(
            "send_pop3_ok to mark message {n} deleted, or send_pop3_err if there is no message {n}"
        ),
        ("NOOP", _) | ("RSET", _) => "send_pop3_ok".to_string(),
        ("QUIT", _) => "send_pop3_ok, then close_connection".to_string(),
        _ => return data,
    };
    data["answer_with"] = answer.into();
    data
}

pub struct Pop3Server;

impl Pop3Server {
    /// Spawn POP3 server with integrated LLM actions
    ///
    /// If tls_config is Some, the server will use implicit TLS (POP3S)
    /// If tls_config is None, the server will use plain text (POP3)
    #[allow(clippy::too_many_arguments)]
    pub async fn spawn_with_llm_actions(
        listen_addr: SocketAddr,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        server_id: crate::state::ServerId,
        tls_config: Option<Arc<rustls::ServerConfig>>,
        first_byte_timeout_secs: Option<u64>,
        idle_timeout_secs: Option<u64>,
    ) -> Result<SocketAddr> {
        // Both bounds are tunable because their right value is a property of who is on the
        // other end, which only the operator knows. The defaults serve NetGet's own POP3
        // client waiting on a human; a listener exposed to strangers wants the first one much
        // lower.
        let deadlines = ReadDeadlines::resolve(first_byte_timeout_secs, idle_timeout_secs);
        let listener =
            crate::server::socket_helpers::create_reusable_tcp_listener(listen_addr).await?;
        let local_addr = listener.local_addr()?;

        if tls_config.is_some() {
            info!(
                "POP3S server (TLS, action-based) listening on {}",
                local_addr
            );
        } else {
            info!(
                "POP3 server (plain, action-based) listening on {}",
                local_addr
            );
        }

        let protocol = Arc::new(Pop3Protocol::new());
        let tls_acceptor = tls_config.map(TlsAcceptor::from);

        let task_registrar = app_state.clone();
        let limiter = crate::server::accept_bounded::ConnectionLimiter::new(MAX_CONNECTIONS);
        let accept_handle = tokio::spawn(async move {
            loop {
                match crate::server::accept_bounded::accept_bounded(
                    &listener,
                    &limiter,
                    CONNECTION_CAP_REFUSAL,
                    "POP3",
                    Some(&status_tx),
                )
                .await
                {
                    Ok((stream, remote_addr, permit)) => {
                        let connection_id = crate::server::connection::ConnectionId::new(
                            app_state.get_next_unified_id().await,
                        );
                        // Captured before a TLS handshake could consume the TcpStream.
                        let local_addr_conn = stream.local_addr().unwrap_or(local_addr);
                        console_debug!(
                            status_tx,
                            "POP3 connection {} from {}",
                            connection_id,
                            remote_addr
                        );

                        let llm_clone = llm_client.clone();
                        let state_clone = app_state.clone();
                        let status_clone = status_tx.clone();
                        let protocol_clone = protocol.clone();
                        let tls_acceptor_clone = tls_acceptor.clone();

                        // Tracked, not detached: stop_server must abort this task too.
                        let task_owner = app_state.clone();
                        task_owner
                            .spawn_server_task(server_id, async move {
                                // Held for the life of the connection: releasing it here would
                                // cap the accept rate rather than the number of live
                                // connections.
                                let _permit = permit;
                                // Optionally perform TLS handshake
                                if let Some(ref acceptor) = tls_acceptor_clone {
                                    match acceptor.accept(stream).await {
                                        Ok(tls_stream) => {
                                            debug!(
                                                "TLS handshake completed for connection {}",
                                                connection_id
                                            );
                                            let _ = status_clone.send(format!(
                                                "[DEBUG] TLS handshake completed for connection {}",
                                                connection_id
                                            ));
                                            if let Err(e) = Pop3Session::handle_session(
                                                tls_stream,
                                                connection_id,
                                                remote_addr,
                                                local_addr_conn,
                                                server_id,
                                                llm_clone,
                                                state_clone,
                                                status_clone,
                                                protocol_clone,
                                                deadlines,
                                            )
                                            .await
                                            {
                                                error!(
                                                    "POP3S session error for connection {}: {}",
                                                    connection_id, e
                                                );
                                            }
                                        }
                                        Err(e) => {
                                            error!(
                                                "TLS handshake failed for connection {}: {}",
                                                connection_id, e
                                            );
                                        }
                                    }
                                } else {
                                    // Plain text POP3
                                    if let Err(e) = Pop3Session::handle_session(
                                        stream,
                                        connection_id,
                                        remote_addr,
                                        local_addr_conn,
                                        server_id,
                                        llm_clone,
                                        state_clone,
                                        status_clone,
                                        protocol_clone,
                                        deadlines,
                                    )
                                    .await
                                    {
                                        error!(
                                            "POP3 session error for connection {}: {}",
                                            connection_id, e
                                        );
                                    }
                                }
                            })
                            .await;
                    }
                    Err(e) => {
                        // Do not continue: an accept() error here is persistent (the listener
                        // is gone, or the process is out of descriptors), and looping on it
                        // spins a core at 100% while the server still reports Running.
                        error!("Failed to accept POP3 connection, stopping listener: {}", e);
                        let _ = status_tx.send(format!(
                            "[ERROR] POP3 listener stopped, failed to accept connection: {}",
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

        Ok(local_addr)
    }
}

struct Pop3Session;

impl Pop3Session {
    /// Drive one POP3 session to completion.
    ///
    /// Generic over the transport so the plain TCP and POP3S (implicit TLS) paths share a
    /// single implementation - they were previously duplicated verbatim, which is how the
    /// two drifted.
    #[allow(clippy::too_many_arguments)]
    async fn handle_session<S>(
        stream: S,
        connection_id: crate::server::connection::ConnectionId,
        remote_addr: SocketAddr,
        local_addr: SocketAddr,
        server_id: crate::state::ServerId,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        protocol: Arc<Pop3Protocol>,
        deadlines: ReadDeadlines,
    ) -> Result<()>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        use crate::state::server::{ConnectionState, ConnectionStatus, ProtocolConnectionInfo};

        let (read_half, write_half) = tokio::io::split(stream);
        let reader = tokio::io::BufReader::new(read_half);
        let write_half = Arc::new(tokio::sync::Mutex::new(write_half));

        // Track the connection so the dashboard lists it with live counters.
        let now = crate::utils::clock::Instant::now();
        app_state
            .add_connection_to_server(
                server_id,
                ConnectionState {
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
                },
            )
            .await;
        let _ = status_tx.send("__UPDATE_UI__".to_string());

        // Peer messaging: the dashboard's "message this peer" / "disconnect this peer" inject
        // actions into THIS connection through the same executor the LLM path uses. Registered
        // before the greeting, because a manual `*` rule can park that greeting for minutes and
        // the operator must be able to reach the connection while it waits.
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

        let result = Self::run_session(
            reader,
            &write_half,
            connection_id,
            server_id,
            &llm_client,
            &app_state,
            &status_tx,
            &protocol,
            deadlines,
        )
        .await;

        // Every exit path - EOF, read error, close_connection, refused greeting - lands here.
        app_state
            .remove_peer_handle(server_id, connection_id.as_u32())
            .await;
        app_state
            .close_connection_on_server(server_id, connection_id)
            .await;
        let _ = status_tx.send("__UPDATE_UI__".to_string());
        result
    }

    #[allow(clippy::too_many_arguments)]
    async fn run_session<R, W>(
        mut reader: tokio::io::BufReader<R>,
        write_half: &Arc<tokio::sync::Mutex<W>>,
        connection_id: crate::server::connection::ConnectionId,
        server_id: crate::state::ServerId,
        llm_client: &OllamaClient,
        app_state: &Arc<AppState>,
        status_tx: &mpsc::UnboundedSender<String>,
        protocol: &Arc<Pop3Protocol>,
        deadlines: ReadDeadlines,
    ) -> Result<()>
    where
        R: tokio::io::AsyncRead + Unpin,
        W: tokio::io::AsyncWrite + Unpin,
    {
        use tokio::io::AsyncWriteExt;

        // Send initial greeting
        let mut greeting_data = pop3_command_event_data("CONNECTION_ESTABLISHED");
        greeting_data["connection_id"] = connection_id.to_string().into();
        let greeting_event = Event::new(&POP3_COMMAND_EVENT, greeting_data);

        match Self::process_command(
            &greeting_event,
            llm_client,
            app_state,
            status_tx,
            protocol,
            server_id,
            connection_id,
            write_half,
        )
        .await
        {
            Ok(SessionControl::Close) => return Ok(()),
            Ok(SessionControl::Continue) => {}
            Err(e) => {
                // A POP3 client waits for a banner before saying anything, so dropping the
                // socket here left it blocked until its own timeout. RFC 1939 allows the
                // greeting to be `-ERR`, and RFC 2449 gives the reason a machine-readable code.
                let token = if crate::utils::WireFailure::classify(&e).is_overloaded() {
                    "fail_closed_llm_overloaded"
                } else {
                    "fail_closed_llm_error"
                };
                error!(
                    "POP3 greeting on connection {} decision={}: {}",
                    connection_id, token, e
                );
                let _ = status_tx.send(format!(
                    "[ERROR] POP3 greeting on connection {} decision={}",
                    connection_id, token
                ));
                let reply = pop3_failure_reply(&e);
                let _ = status_tx.send(format!(
                    "[ERROR] POP3 connection {} refused: {}",
                    connection_id,
                    reply.trim_end()
                ));
                let mut writer = write_half.lock().await;
                let _ = writer.write_all(reply.as_bytes()).await;
                let _ = writer.flush().await;
                drop(writer);
                app_state
                    .update_connection_stats(
                        server_id,
                        connection_id,
                        None,
                        Some(reply.len() as u64),
                        None,
                        Some(1),
                    )
                    .await;
                return Ok(());
            }
        }

        // Main command loop
        let mut answered_one = false;
        loop {
            // Bounded: `read_line` would grow its `String` until it found a `\n`, so a peer
            // that connects and never sends one was a one-connection OOM before any model
            // call. `line.clear()` bounded accumulation *across* commands and nothing within
            // one.
            // The deadline wraps this read and nothing else. Everything that can legitimately
            // take minutes — the LLM round-trip, and a `manual` rule parking the command for a
            // human to answer — happens below, after a line has already been read.
            let read_timeout = if answered_one {
                deadlines.idle
            } else {
                deadlines.first_byte
            };
            let framed = tokio::time::timeout(
                read_timeout,
                crate::utils::line_reader::read_bounded_line(&mut reader, MAX_COMMAND_BYTES),
            )
            .await;
            let (read, n) = match framed {
                Err(_) => {
                    info!(
                        "POP3 connection {} sent nothing for {}s; closing idle connection",
                        connection_id,
                        read_timeout.as_secs()
                    );
                    break;
                }
                Ok(Ok(v)) => v,
                Ok(Err(e)) => {
                    debug!("POP3 read error on connection {}: {}", connection_id, e);
                    break;
                }
            };
            answered_one = true;
            let line = match read {
                crate::utils::line_reader::BoundedLine::Line(line) => line,
                crate::utils::line_reader::BoundedLine::Eof => {
                    debug!("POP3 connection {} closed by client", connection_id);
                    break;
                }
                crate::utils::line_reader::BoundedLine::TooLong => {
                    // No resynchronisation point: the peer is mid-line, so the next byte is
                    // not the start of a command. Refuse in POP3's own vocabulary and close.
                    // `[SYS/PERM]` rather than `[SYS/TEMP]` — retrying an oversized line
                    // unchanged will fail again.
                    let reply = format!(
                        "-ERR [SYS/PERM] command line exceeds {MAX_COMMAND_BYTES} bytes\r\n"
                    );
                    error!(
                        "POP3 connection {} sent a command line over {} bytes with no newline; \
                         decision=fail_closed_oversized_command",
                        connection_id, MAX_COMMAND_BYTES
                    );
                    let _ = status_tx.send(format!(
                        "[ERROR] POP3 connection {} refused: {}",
                        connection_id,
                        reply.trim_end()
                    ));
                    {
                        let mut writer = write_half.lock().await;
                        let _ = writer.write_all(reply.as_bytes()).await;
                        let _ = writer.flush().await;
                    }
                    app_state
                        .update_connection_stats(
                            server_id,
                            connection_id,
                            Some(n as u64),
                            Some(reply.len() as u64),
                            None,
                            Some(1),
                        )
                        .await;
                    break;
                }
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
            let command = line.trim().to_string();
            if command.is_empty() {
                continue;
            }
            // The verb alone, for log lines. Kept separately so nothing downstream
            // has to re-derive it from a `command` the event may have consumed.
            let verb = command
                .split_whitespace()
                .next()
                .unwrap_or("?")
                .to_uppercase();

            console_debug!(
                status_tx,
                "POP3 connection {} received: {}",
                connection_id,
                command
            );

            if verb == "CAPA" {
                info!(
                    "POP3 CAPA on connection {} decision=netget_answer: answered by NetGet",
                    connection_id
                );
                let _ = status_tx.send(format!(
                    "[INFO] POP3 CAPA on connection {} decision=netget_answer",
                    connection_id
                ));
                {
                    let mut writer = write_half.lock().await;
                    writer.write_all(CAPA_REPLY).await?;
                    writer.flush().await?;
                }
                app_state
                    .update_connection_stats(
                        server_id,
                        connection_id,
                        None,
                        Some(CAPA_REPLY.len() as u64),
                        None,
                        Some(1),
                    )
                    .await;
                continue;
            }

            let mut event_data = pop3_command_event_data(&command);
            event_data["connection_id"] = connection_id.to_string().into();
            let event = Event::new(&POP3_COMMAND_EVENT, event_data);

            match Self::process_command(
                &event,
                llm_client,
                app_state,
                status_tx,
                protocol,
                server_id,
                connection_id,
                write_half,
            )
            .await
            {
                Ok(SessionControl::Continue) => {}
                Ok(SessionControl::Close) => {
                    debug!("POP3 connection {} closed by server", connection_id);
                    break;
                }
                Err(e) => {
                    // Answer before hanging up. Silence here is indistinguishable from
                    // a hung server, and for USER/PASS it is worse than that: the
                    // client cannot tell a refused login from a lost connection.
                    // `-ERR` is a refusal on every command POP3 has, so this fails
                    // closed by construction - there is no `+OK` on this path.
                    // `-ERR`, always. A backend outage and a model that denied the
                    // login are indistinguishable on this wire, so the token is
                    // what keeps them apart in the log.
                    let token = if crate::utils::WireFailure::classify(&e).is_overloaded() {
                        "fail_closed_llm_overloaded"
                    } else {
                        "fail_closed_llm_error"
                    };
                    error!(
                        "POP3 {} on connection {} decision={}: {}",
                        verb, connection_id, token, e
                    );
                    let _ = status_tx.send(format!(
                        "[ERROR] POP3 {} on connection {} decision={}",
                        verb, connection_id, token
                    ));
                    let reply = pop3_failure_reply(&e);
                    let _ = status_tx.send(format!(
                        "[ERROR] POP3 connection {} replying: {}",
                        connection_id,
                        reply.trim_end()
                    ));
                    let mut writer = write_half.lock().await;
                    let _ = writer.write_all(reply.as_bytes()).await;
                    let _ = writer.flush().await;
                    drop(writer);
                    app_state
                        .update_connection_stats(
                            server_id,
                            connection_id,
                            None,
                            Some(reply.len() as u64),
                            None,
                            Some(1),
                        )
                        .await;
                    break;
                }
            }
        }

        Ok(())
    }

    async fn process_command<W>(
        event: &Event,
        llm_client: &OllamaClient,
        app_state: &Arc<AppState>,
        status_tx: &mpsc::UnboundedSender<String>,
        protocol: &Arc<Pop3Protocol>,
        server_id: crate::state::ServerId,
        connection_id: crate::server::connection::ConnectionId,
        write_half: &Arc<tokio::sync::Mutex<W>>,
    ) -> Result<SessionControl>
    where
        W: tokio::io::AsyncWrite + Unpin,
    {
        use tokio::io::AsyncWriteExt;

        // The command this answer belongs to, for the decision line. Without it a
        // `decision=` tag has no subject, and "which command was refused" is the only
        // question worth asking of a POP3 log.
        let command = event
            .data
            .get("command")
            .and_then(|v| v.as_str())
            .unwrap_or("?")
            .split_whitespace()
            .next()
            .unwrap_or("?")
            .to_uppercase();

        // Call LLM for action.
        //
        // The `?` hands an LLM failure back to `run_session`, which answers `-ERR` and
        // logs `decision=fail_closed_llm_*`. **Nothing on that path can produce `+OK`**:
        // the only `+OK` in this protocol comes from an action the model named, and
        // `pop3_failure_reply` is `-ERR` in every branch. That is what stops a backend
        // outage from becoming a granted mailbox — the OAuth2 failure mode.
        let llm_result = call_llm(
            llm_client,
            app_state,
            server_id,
            Some(connection_id),
            event,
            protocol.as_ref(),
        )
        .await?;
        let failures = llm_result.failures.len();
        let mut llm_result = llm_result;
        if let Some(assembled) = assemble_multiline_answer(&command, &llm_result) {
            info!(
                "POP3 {} on connection {} decision=multiline_assembled: a +OK status line and \
                 the message as raw text, framed by NetGet",
                command, connection_id
            );
            let _ = status_tx.send(format!(
                "[INFO] POP3 {} on connection {} decision=multiline_assembled",
                command, connection_id
            ));
            llm_result.protocol_results = vec![ActionResult::Output(assembled)];
            llm_result.protocol_result_actions = vec!["send_pop3_retr".to_string()];
        }
        let chosen = llm_result.chosen_reply(pop3_preferred_actions(
            event
                .data
                .get("command")
                .and_then(|v| v.as_str())
                .unwrap_or(""),
        ));

        // Execute actions. `close_connection` must still flush everything queued before it -
        // the QUIT reply is normally `send_pop3_ok` followed by `close_connection` in the same
        // batch - so record the intent and act on it once the batch is drained.
        let mut control = SessionControl::Continue;
        // What the model actually put on the wire. POP3 says yes and no with the same
        // action mechanism, so the leading token of the first reply is the only honest
        // way to tell an approval from a refusal — and they must never be conflated.
        let mut first_reply: Option<String> = None;
        let mut asked_to_close = false;
        let mut dropped_replies = 0usize;

        for (index, action) in llm_result.protocol_results.into_iter().enumerate() {
            match action {
                // One command, one reply. POP3 has no pipelining here, so a second reply is
                // read as the answer to the client's *next* command, and every reply after it
                // is one step late - a RETR then reads the previous command's `+OK` as its
                // status line and waits for a body that is never coming. Only the chosen one -
                // the action `answer_with` names, else the first - is written.
                ActionResult::Output(_) if Some(index) != chosen => dropped_replies += 1,
                ActionResult::Output(data) => {
                    first_reply =
                        Some(String::from_utf8_lossy(&data[..data.len().min(8)]).to_string());
                    let mut writer = write_half.lock().await;
                    writer.write_all(&data).await?;
                    writer.flush().await?;
                    drop(writer);
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

                    console_debug!(
                        status_tx,
                        "POP3 connection {} sent {} bytes",
                        connection_id,
                        data.len()
                    );
                }
                ActionResult::CloseConnection => {
                    control = SessionControl::Close;
                    asked_to_close = true;
                }
                ActionResult::WaitForMore => {
                    // Do nothing, wait for next command
                }
                _ => {
                    // Not an action that produces POP3 output (memory updates, logging, ...)
                }
            }
        }

        if dropped_replies > 0 {
            tracing::warn!(
                "POP3 {} on connection {} decision=duplicate_response_dropped: {} extra \
                 repl{} not sent; one command gets one reply",
                command,
                connection_id,
                dropped_replies,
                if dropped_replies == 1 { "y" } else { "ies" }
            );
            let _ = status_tx.send(format!(
                "[WARN] POP3 {} on connection {} decision=duplicate_response_dropped ({})",
                command, connection_id, dropped_replies
            ));
        }

        // One decision line per command, so `grep decision=` separates a granted request
        // from a refused one from a request nobody answered.
        let decision = match first_reply.as_deref() {
            Some(reply) if reply.starts_with("-ERR") => "model_reject",
            Some(_) => "model_answer",
            // A `close_connection` with no reply is the model hanging up rather than
            // answering — a deliberate refusal, not a failure.
            None if asked_to_close => "model_reject",
            None if failures == 0 => "model_silent",
            None => "fail_closed_bad_action",
        };
        let summary = format!(
            "POP3 {} on connection {} decision={} ({} failed action(s))",
            command, connection_id, decision, failures
        );
        match decision {
            // Nothing was written and nothing asked to close: the client is still waiting
            // for a reply it will never get. No `+OK` was produced, so no mailbox was
            // opened — but the peer is owed an answer it did not receive.
            "model_silent" => {
                tracing::warn!("{}", summary);
                let _ = status_tx.send(format!("[WARN] {}", summary));
            }
            "fail_closed_bad_action" => {
                error!("{}", summary);
                let _ = status_tx.send(format!("[ERROR] {}", summary));
            }
            _ => {
                info!("{}", summary);
                let _ = status_tx.send(format!("[INFO] {}", summary));
            }
        }

        Ok(control)
    }
}

/// The `-ERR` line to write when the LLM backend fails, RFC 2449 extended response code
/// included so the client can tell "come back later" from "this is broken".
///
/// `[SYS/TEMP]` is the retryable one and is reserved for capacity exhaustion - the same split
/// HTTP makes between 503 and 500. Everything else gets `[SYS/PERM]`, which does not invite an
/// immediate retry loop against a backend that is down.
///
/// Every branch is `-ERR`. POP3 has no response that both refuses and looks like success, so
/// there is no way for this path to authenticate anybody or hand out a message.
fn pop3_failure_reply(err: &anyhow::Error) -> String {
    // The text is a category, never the error itself (`crate::utils::wire_failure`). The reply
    // is one line, so a newline in an error would have forged a second response, and a leading
    // `.` would have terminated a multiline block.
    let failure = crate::utils::WireFailure::classify(err);
    let text = failure.prefixed_text();
    if failure.is_overloaded() {
        format!("-ERR [SYS/TEMP] {text}\r\n")
    } else {
        format!("-ERR [SYS/PERM] {text}\r\n")
    }
}

/// Whether the command loop should keep reading or shut the connection down.
///
/// `process_command` used to signal a close by returning `Ok(())` early, which is
/// indistinguishable from "command handled" - so `close_connection` never actually closed
/// anything and a client that sent QUIT was left holding an open socket.
#[derive(Clone, Copy, PartialEq, Eq)]
enum SessionControl {
    Continue,
    Close,
}
