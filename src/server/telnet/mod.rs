//! Telnet server implementation
pub mod actions;

use crate::server::connection::ConnectionId;
use anyhow::Result;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

use crate::llm::action_helper::call_llm;
use crate::llm::actions::protocol_trait::ActionResult;
use crate::llm::ollama_client::OllamaClient;
use crate::logging::emit::Log;
use crate::protocol::Event;
use crate::server::TelnetProtocol;
use crate::state::app_state::AppState;
use actions::{TELNET_CONNECTION_OPENED_EVENT, TELNET_MESSAGE_RECEIVED_EVENT};

/// Truncate `text` to at most `max` bytes without splitting a UTF-8 character.
///
/// Slicing `&text[..max]` directly panics when the boundary lands inside a multi-byte
/// character, and both the received line and the handler's response are attacker- or
/// model-controlled, so that panic is reachable from the network.
fn preview(text: &str, max: usize) -> String {
    if text.len() <= max {
        return text.to_string();
    }
    let mut end = max;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &text[..end])
}

/// A telnet line longer than this is not a line anyone typed.
///
/// `BufReader::read_line` grows its `String` until a newline arrives, so before this cap
/// existed an unauthenticated peer could hold the connection open and stream gigabytes with
/// no `\n` among them, and the server buffered every byte. Nothing authenticates before this
/// loop, and telnet is the protocol an operator is most likely to point at a real device.
pub const MAX_LINE_BYTES: usize = 8192;

/// How long to wait for the first line from a peer that has only connected.
///
/// **This was 120 seconds, and the argument for it was right about the peer and wrong about
/// the number.** It read: two minutes rather than the thirty seconds a machine protocol gets,
/// because the other end of a telnet session is usually a *person* — they connect, read
/// whatever banner `send_first` produced, and then start typing. That reasoning already knew
/// this bound waits on a human. It just picked a figure this product contradicts elsewhere.
///
/// NetGet's own telnet client is the strongest case of it. `src/client/telnet/mod.rs` opens
/// the socket, registers its command channel, raises `telnet_connected` and then reads: it
/// writes nothing of its own, every byte comes from an action, and a client created from the
/// dashboard's `[ + telnet client ]` is routed `telnet_connected` →
/// static-with-no-actions and then `*` → manual (`src/tui/modal/form.rs`). So it connects,
/// is answered with nothing, and waits for a person at `[ send message ]`. That person is
/// given **300** seconds to answer one event (`src/state/intercepts.rs`); at 120 the server
/// hung up on them less than halfway through their own window. Telnet was also the only one of
/// the five protocols raised in the first pass of this sweep that had no startup parameter to
/// raise it with, so an operator could not even work around it.
///
/// 300 seconds is that window, and it is the number this product already uses for how long
/// someone might take.
///
/// What it costs: a stranger holding a socket, a task, an `AppState` row and one of
/// [`MAX_CONNECTIONS`] slots while saying nothing now gets 300 seconds rather than 120 — two
/// and a half times longer for one idle slot, not a removal of the bound. The cap still holds
/// and a peer over it is still answered [`CONNECTION_CAP_REFUSAL`]. A listener genuinely
/// exposed to strangers should set `first_byte_timeout_secs` low; 120 is the old value and
/// remains a sound choice for one.
///
/// The banner itself sits outside the deadline by construction — it is generated and written
/// before this loop starts, so however long the model takes, the clock below has not started.
const FIRST_LINE_READ_TIMEOUT: Duration = Duration::from_secs(300);

/// The two read deadlines for one connection, resolved from the server's startup parameters.
///
/// Carried as one value so threading them from `spawn_with_llm_actions` into the connection
/// task costs one argument rather than two.
#[derive(Clone, Copy)]
struct ReadDeadlines {
    /// [`FIRST_LINE_READ_TIMEOUT`], or this server's `first_byte_timeout_secs`.
    first_byte: Duration,
    /// [`IDLE_BETWEEN_LINES_TIMEOUT`], or this server's `idle_timeout_secs`.
    idle: Duration,
}

impl ReadDeadlines {
    fn resolve(first_byte_secs: Option<u64>, idle_secs: Option<u64>) -> Self {
        Self {
            first_byte: first_byte_secs
                .map(Duration::from_secs)
                .unwrap_or(FIRST_LINE_READ_TIMEOUT),
            idle: idle_secs
                .map(Duration::from_secs)
                .unwrap_or(IDLE_BETWEEN_LINES_TIMEOUT),
        }
    }
}

/// How long to wait for a *further* line once the peer has sent one.
///
/// Ten minutes, which is Cisco IOS's `exec-timeout 10 0` default for vty lines — the canonical
/// idle bound for exactly the kind of device an operator points this server at, and therefore
/// the number every telnet user already expects. A session here is long-lived by nature: a
/// person thinks, reads output, and types again, and cutting that off at a machine protocol's
/// timescale would break the protocol's own use. Everything that can legitimately take minutes
/// — the LLM round-trip, and a `manual` rule parking a line for a human to answer
/// (`src/state/intercepts.rs`, 300s by default) — happens after a read has already returned, so
/// a slow answer can never be timed out from under itself.
///
/// Overridable per server with `idle_timeout_secs`, for the same reason the first bound is:
/// the right value is a property of who is on the other end, and only the operator knows that.
const IDLE_BETWEEN_LINES_TIMEOUT: Duration = Duration::from_secs(600);

/// Concurrent connections this server admits.
///
/// [`crate::server::accept_bounded::DEFAULT_MAX_CONNECTIONS`]. Each connection may buffer up to
/// [`MAX_LINE_BYTES`], so this is the multiplier that turns that per-connection bound into a
/// total one.
const MAX_CONNECTIONS: usize = crate::server::accept_bounded::DEFAULT_MAX_CONNECTIONS;

/// What a peer over [`MAX_CONNECTIONS`] is told before the socket closes.
///
/// Telnet has no error frame — it is a byte stream with a human on the other end — so the
/// protocol-appropriate refusal is the same plain notice line this file already writes when a
/// line runs past [`MAX_LINE_BYTES`]: fixed text, on its own line, with nothing interpolated
/// into it. A terminal prints it; no client can mistake it for a prompt or a login success.
const CONNECTION_CAP_REFUSAL: &[u8] = b"\r\n[netget] too many connections\r\n";

mod iac {
    pub const IAC: u8 = 255;
    pub const SE: u8 = 240;
    pub const SB: u8 = 250;
    pub const WILL: u8 = 251;
    pub const DONT: u8 = 254;
}

/// Where the IAC state machine is between reads.
///
/// The whole machine is this one enum plus a buffer capped at [`MAX_LINE_BYTES`], which is
/// what makes "can option negotiation be driven into unbounded state?" answerable: it cannot.
/// A subnegotiation that never sends `IAC SE` discards bytes as they arrive rather than
/// accumulating them, and no arm can panic.
#[derive(Clone, Copy, PartialEq, Eq)]
enum IacState {
    /// Ordinary data.
    Data,
    /// `IAC` seen; the next byte is the command.
    Command,
    /// `IAC WILL/WONT/DO/DONT` seen; the next byte is the option, and is consumed.
    Option,
    /// Inside `IAC SB …`; everything is consumed until `IAC SE`.
    Subnegotiation,
    /// `IAC` inside a subnegotiation: `SE` ends it, `IAC` is an escaped 0xFF.
    SubnegotiationIac,
}

/// What one attempt to read a line produced.
enum LineRead {
    /// A line with its terminator stripped, and the wire bytes it consumed.
    Line(Vec<u8>, usize),
    /// The peer hung up with nothing pending.
    Eof,
    /// [`MAX_LINE_BYTES`] of data arrived with no newline in it.
    TooLong,
    /// Nothing arrived within the caller's deadline.
    TimedOut,
    /// The socket errored.
    Failed(std::io::Error),
}

/// Reads `\n`-terminated lines with IAC sequences removed and a hard size cap.
///
/// Two defects this replaced, both reachable from any peer:
///
/// * **Unbounded buffering.** See [`MAX_LINE_BYTES`].
/// * **A real `telnet(1)` client was dropped on its first line.** `read_line` validates UTF-8
///   across the whole line and returns `InvalidData` when that fails. A real client opens by
///   sending `IAC DO/WILL …` negotiation, whose bytes are not valid UTF-8, so the first line
///   the user typed arrived with that junk in front of it, failed to decode, and the read loop
///   treated the error as a reason to close. `actions.rs` told the model those bytes "arrive
///   as part of the first message", which was never what happened — the connection died
///   instead. Sequences are now removed from the stream and what is left is decoded lossily,
///   so the client survives and the model sees what was typed.
///
/// Stripping has to happen on the byte stream *before* lines are split out, not on a line
/// already cut at a newline: an option byte can itself be `0x0A` (`IAC DO NAOCRD` is
/// `FF FD 0A`), and a sequence may straddle two reads.
///
/// Negotiation is still **not answered**: options are recognised only well enough to be
/// skipped, so a real client gets no reply to its offers and stays in its default line mode,
/// which is the mode this server can serve.
struct TelnetLineReader<R> {
    reader: R,
    /// Data bytes received and not yet returned as a line.
    pending: Vec<u8>,
    chunk: Vec<u8>,
    state: IacState,
}

impl<R: tokio::io::AsyncRead + Unpin> TelnetLineReader<R> {
    fn new(reader: R) -> Self {
        Self {
            reader,
            pending: Vec::new(),
            chunk: vec![0u8; 4096],
            state: IacState::Data,
        }
    }

    /// Feed raw bytes through the IAC machine, appending only data bytes to `pending`.
    fn absorb(&mut self, raw: &[u8]) {
        for &byte in raw {
            self.state = match self.state {
                IacState::Data => {
                    if byte == iac::IAC {
                        IacState::Command
                    } else {
                        self.pending.push(byte);
                        IacState::Data
                    }
                }
                IacState::Command => match byte {
                    // `IAC IAC` is a literal 0xFF in the data stream.
                    iac::IAC => {
                        self.pending.push(iac::IAC);
                        IacState::Data
                    }
                    iac::SB => IacState::Subnegotiation,
                    iac::WILL..=iac::DONT => IacState::Option,
                    // Every other command (NOP, DM, BRK, AYT, GA …) is two bytes in total.
                    _ => IacState::Data,
                },
                IacState::Option => IacState::Data,
                IacState::Subnegotiation => {
                    if byte == iac::IAC {
                        IacState::SubnegotiationIac
                    } else {
                        IacState::Subnegotiation
                    }
                }
                IacState::SubnegotiationIac => match byte {
                    iac::SE => IacState::Data,
                    // Anything else, including an escaped 0xFF, is still payload we discard.
                    _ => IacState::Subnegotiation,
                },
            };
        }
    }

    /// The `bound` limits the wait for *more bytes*, not the whole line: a peer that is still
    /// typing keeps the connection alive, which is what a person on a slow link needs.
    async fn next_line(&mut self, bound: Duration) -> LineRead {
        use tokio::io::AsyncReadExt;
        loop {
            if let Some(idx) = self.pending.iter().position(|b| *b == b'\n') {
                let mut line: Vec<u8> = self.pending.drain(..=idx).collect();
                let consumed = line.len();
                line.pop();
                if line.last() == Some(&b'\r') {
                    line.pop();
                }
                return LineRead::Line(line, consumed);
            }
            if self.pending.len() > MAX_LINE_BYTES {
                return LineRead::TooLong;
            }

            let read = match tokio::time::timeout(bound, self.reader.read(&mut self.chunk)).await {
                Err(_) => return LineRead::TimedOut,
                Ok(read) => read,
            };
            let n = match read {
                Ok(0) => {
                    if self.pending.is_empty() {
                        return LineRead::Eof;
                    }
                    // A final line with no terminator: answer it rather than discarding what
                    // the peer said on its way out.
                    let mut line = std::mem::take(&mut self.pending);
                    let consumed = line.len();
                    if line.last() == Some(&b'\r') {
                        line.pop();
                    }
                    return LineRead::Line(line, consumed);
                }
                Ok(n) => n,
                Err(e) => return LineRead::Failed(e),
            };
            let raw = self.chunk[..n].to_vec();
            self.absorb(&raw);
        }
    }
}

/// Telnet server that forwards messages to LLM
pub struct TelnetServer;

impl TelnetServer {
    /// Spawn Telnet server with integrated LLM actions
    #[allow(clippy::too_many_arguments)]
    pub async fn spawn_with_llm_actions(
        listen_addr: SocketAddr,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        server_id: crate::state::ServerId,
        send_first: bool,
        first_byte_timeout_secs: Option<u64>,
        idle_timeout_secs: Option<u64>,
    ) -> Result<SocketAddr> {
        // Both bounds are tunable because their right value is a property of who is on the
        // other end, which only the operator knows. The defaults serve a person at a keyboard
        // — including NetGet's own telnet client parked at the dashboard waiting for one; a
        // listener exposed to strangers wants the first one much lower.
        let deadlines = ReadDeadlines::resolve(first_byte_timeout_secs, idle_timeout_secs);
        let listener =
            crate::server::socket_helpers::create_reusable_tcp_listener(listen_addr).await?;
        let local_addr = listener.local_addr()?;
        Log::new(Some(&status_tx)).info(format!("Telnet server listening on {}", local_addr));

        let protocol = Arc::new(TelnetProtocol::new());

        let task_registrar = app_state.clone();
        let limiter = crate::server::accept_bounded::ConnectionLimiter::new(MAX_CONNECTIONS);
        let accept_handle = tokio::spawn(async move {
            loop {
                match crate::server::accept_bounded::accept_bounded(
                    &listener,
                    &limiter,
                    CONNECTION_CAP_REFUSAL,
                    "Telnet",
                    Some(&status_tx),
                )
                .await
                {
                    Ok((stream, remote_addr, permit)) => {
                        let connection_id =
                            ConnectionId::new(app_state.get_next_unified_id().await);
                        let local_addr_conn = stream.local_addr().unwrap_or(local_addr);
                        let llm_clone = llm_client.clone();
                        let state_clone = app_state.clone();
                        let status_clone = status_tx.clone();
                        let protocol_clone = protocol.clone();

                        // Tracked, not detached: stop_server must abort this task too.
                        let task_owner = app_state.clone();
                        task_owner.spawn_server_task(server_id, async move {
                            // Held for the life of the connection: releasing it here would cap
                            // the accept rate rather than the number of live connections.
                            let _permit = permit;
                            let (read_half, write_half) = tokio::io::split(stream);
                            let write_half_arc = Arc::new(tokio::sync::Mutex::new(write_half));

                            // Add connection to ServerInstance
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
                            let log = Log::new(Some(&status_clone));

                            // Peer messaging: the dashboard's "message this peer" and
                            // "disconnect" inject actions into THIS connection through
                            // the same executor the handlers use. The handle is removed
                            // on every exit path below; the command task ends with it.
                            let peer_rx = crate::server::peer_support::register_peer_channel(
                                &state_clone,
                                server_id,
                                connection_id.as_u32(),
                            )
                            .await;
                            crate::server::peer_support::spawn_peer_command_task(
                                peer_rx,
                                protocol_clone.clone(),
                                state_clone.clone(),
                                server_id,
                                connection_id.as_u32(),
                                write_half_arc.clone(),
                                status_clone.clone(),
                            );

                            // Raise telnet_connection_opened for EVERY connection, before the
                            // first line is read, so the handler can greet before the client
                            // says anything. It used to be raised only with send_first, which a
                            // server started from a one-line instruction cannot set - so
                            // "greet everyone who connects" was unservable, and the real-model
                            // eval scored every banner case 0. With nothing to say, the model
                            // answers with no actions; a dashboard-created instance routes the
                            // event to a zero-action static rule and pays nothing.
                            //
                            // The line reader starts only after this returns, so the first read
                            // is always held until the connect event is answered. send_first
                            // now says the peer is OWED a greeting: silence is then a warning,
                            // and a backend failure prints the failure notice.
                            {
                                let event = Event::new(
                                    &TELNET_CONNECTION_OPENED_EVENT,
                                    crate::protocol::event_type::connect_event_data(),
                                );
                                match call_llm(
                                    &llm_clone,
                                    &state_clone,
                                    server_id,
                                    Some(connection_id),
                                    &event,
                                    protocol_clone.as_ref(),
                                )
                                .await
                                {
                                    Ok(execution_result) => {
                                        let mut greeted = 0usize;
                                        for protocol_result in execution_result.protocol_results {
                                            if let ActionResult::Output(data) = protocol_result {
                                                greeted += 1;
                                                use tokio::io::AsyncWriteExt;
                                                let mut write = write_half_arc.lock().await;
                                                let _ = write.write_all(&data).await;
                                                let _ = write.flush().await;
                                                drop(write);
                                                state_clone
                                                    .update_connection_stats(
                                                        server_id,
                                                        connection_id,
                                                        None,
                                                        Some(data.len() as u64),
                                                        None,
                                                        Some(1),
                                                    )
                                                    .await;
                                                log.debug(format!(
                                                    "Telnet sent greeting ({} bytes) on connection {}",
                                                    data.len(),
                                                    connection_id
                                                ));
                                            }
                                        }
                                        if greeted > 0 {
                                            log.info(format!(
                                                "Telnet greeting for {} (connection {}) \
                                                 decision=model_answer ({} write(s))",
                                                remote_addr, connection_id, greeted
                                            ));
                                        } else if !send_first {
                                            // Nothing to say on connect is the ordinary answer
                                            // for a server that waits for the client.
                                            log.debug(format!(
                                                "Telnet connect for {} (connection {}) \
                                                 decision=model_no_actions",
                                                remote_addr, connection_id
                                            ));
                                        } else {
                                            // `send_first` was asked for and nothing came back,
                                            // so the peer stares at a blank screen with no
                                            // notice. Distinct from the backend failing below.
                                            log.warn(format!(
                                                "Telnet greeting for {} (connection {}) \
                                                 decision=model_silent: send_first was requested \
                                                 but the model produced no banner",
                                                remote_addr, connection_id
                                            ));
                                        }
                                    }
                                    Err(e) if !send_first => {
                                        // Nobody asked this server to speak first, so the peer
                                        // has been failed by nothing yet: its first line gets
                                        // the per-line path's answer, or that path's notice if
                                        // the backend is still down.
                                        log.warn(format!(
                                            "Telnet connect event for {} (connection {}) \
                                             decision=connect_event_failed: {}",
                                            remote_addr, connection_id, e
                                        ));
                                    }
                                    Err(e) => {
                                        // The client asked for a banner and is sitting at a
                                        // blank screen. Telnet has no error frame - it is a
                                        // byte stream with a human on the other end - so the
                                        // protocol-appropriate answer is a plain notice line.
                                        //
                                        // Tagged like the per-line path: the notice is a
                                        // category, not the banner that was asked for.
                                        let decision = match crate::utils::WireFailure::classify(&e)
                                        {
                                            crate::utils::WireFailure::Overloaded => {
                                                "fail_closed_llm_overloaded"
                                            }
                                            crate::utils::WireFailure::Unavailable => {
                                                "fail_closed_llm_error"
                                            }
                                        };
                                        log.error(format!(
                                            "Telnet greeting for {} (connection {}) decision={}: {}",
                                            remote_addr, connection_id, decision, e
                                        ));
                                        let notice = telnet_failure_notice(&e);
                                        use tokio::io::AsyncWriteExt;
                                        let mut write = write_half_arc.lock().await;
                                        let _ = write.write_all(notice.as_bytes()).await;
                                        let _ = write.flush().await;
                                    }
                                }
                            }

                            // Bounded, IAC-stripping line reading. Option negotiation is still
                            // not *answered* — sequences are recognised only well enough to be
                            // removed, so a real telnet client survives instead of being
                            // dropped when its negotiation fails to decode as UTF-8.
                            let mut reader = TelnetLineReader::new(read_half);
                            let mut close_requested = false;
                            let mut answered_one = false;

                            loop {
                                // The deadline wraps the read and nothing else: the LLM call
                                // and a `manual` park both happen further down this loop, after
                                // a line has already been read.
                                let read_timeout = if answered_one {
                                    deadlines.idle
                                } else {
                                    deadlines.first_byte
                                };
                                let (line_bytes, n) = match reader.next_line(read_timeout).await {
                                    LineRead::Line(bytes, n) => (bytes, n),
                                    LineRead::Eof => break,
                                    LineRead::TimedOut => {
                                        log.info(format!(
                                            "Telnet client {} (connection {}) sent nothing for \
                                             {}s; closing idle connection",
                                            remote_addr,
                                            connection_id,
                                            read_timeout.as_secs()
                                        ));
                                        break;
                                    }
                                    LineRead::TooLong => {
                                        // No error frame exists in telnet, so say it in words
                                        // on their own line and hang up. A category, never an
                                        // error string: see `telnet_failure_notice`.
                                        // The protocol refused this, not the model: no LLM call
                                        // was made and none will be. Its own token, so it is
                                        // never confused with a backend failure.
                                        log.warn(format!(
                                            "Telnet line from {} (connection {}) \
                                             decision=refused_line_too_long: more than {} bytes \
                                             with no newline; closing",
                                            remote_addr, connection_id, MAX_LINE_BYTES
                                        ));
                                        use tokio::io::AsyncWriteExt;
                                        let mut write = write_half_arc.lock().await;
                                        let _ = write
                                            .write_all(b"\r\n[netget] line too long\r\n")
                                            .await;
                                        let _ = write.flush().await;
                                        let _ = write.shutdown().await;
                                        break;
                                    }
                                    LineRead::Failed(e) => {
                                        log.debug(format!(
                                            "Telnet read error on connection {}: {}",
                                            connection_id, e
                                        ));
                                        break;
                                    }
                                };
                                // Decoded lossily: after IAC stripping whatever is left is
                                // what the peer typed, and a stray non-UTF-8 byte must not
                                // cost them the connection.
                                let line = String::from_utf8_lossy(&line_bytes).into_owned();
                                answered_one = true;

                                // Counters and last_activity: the rail shows ↓/↑ per peer,
                                // and until this was added every telnet peer read 0/0.
                                state_clone
                                    .update_connection_stats(
                                        server_id,
                                        connection_id,
                                        Some(n as u64),
                                        None,
                                        Some(1),
                                        None,
                                    )
                                    .await;

                                // Summary + full payload are FileOnly: the
                                // telnet_message_received event template renders the
                                // equivalent line to the TUI, so streaming it here too
                                // would duplicate it and load the unbounded status channel.
                                let line_preview = preview(&line, 100);
                                log.debug(format!(
                                    "Telnet received {} bytes on connection {}: {}",
                                    n,
                                    connection_id,
                                    line_preview.trim()
                                ));
                                log.trace(format!("Telnet data (text): {:?}", line.trim()));

                                let event = Event::new(
                                    &TELNET_MESSAGE_RECEIVED_EVENT,
                                    serde_json::json!({
                                        "message": line.trim()
                                    }),
                                );

                                log.debug(format!(
                                    "Telnet calling LLM for connection {}",
                                    connection_id
                                ));

                                match call_llm(
                                    &llm_clone,
                                    &state_clone,
                                    server_id,
                                    Some(connection_id),
                                    &event,
                                    protocol_clone.as_ref(),
                                )
                                .await
                                {
                                    Ok(execution_result) => {
                                        for message in &execution_result.messages {
                                            log.info(message);
                                        }

                                        log.debug(format!(
                                            "Telnet got {} protocol results",
                                            execution_result.protocol_results.len()
                                        ));

                                        // Classify *before* `protocol_results` is consumed.
                                        //
                                        // Three of these outcomes write nothing to the socket
                                        // and leave the session open, so from the peer's seat
                                        // they are identical: a deliberate `wait_for_more`, a
                                        // model that returned no usable action at all, and an
                                        // action the executor refused. Only the log can tell
                                        // them apart, and only if it carries a token.
                                        let waited = execution_result
                                            .protocol_results
                                            .iter()
                                            .any(|r| matches!(r, ActionResult::WaitForMore));
                                        let failure_summary = execution_result
                                            .failures
                                            .iter()
                                            .map(|f| format!("{}: {}", f.action, f.error))
                                            .collect::<Vec<_>>()
                                            .join("; ");
                                        let mut wrote = 0usize;
                                        let mut closed = false;

                                        for protocol_result in execution_result.protocol_results {
                                            match protocol_result {
                                                ActionResult::Output(data) => {
                                                    wrote += 1;
                                                    let mut write = write_half_arc.lock().await;

                                                    // Write the action's bytes verbatim. Going
                                                    // via String::from_utf8_lossy would replace
                                                    // any non-UTF-8 byte with U+FFFD before it
                                                    // reached the wire.
                                                    use tokio::io::AsyncWriteExt;
                                                    let _ = write.write_all(&data).await;
                                                    let _ = write.flush().await;
                                                    drop(write);
                                                    state_clone
                                                        .update_connection_stats(
                                                            server_id,
                                                            connection_id,
                                                            None,
                                                            Some(data.len() as u64),
                                                            None,
                                                            Some(1),
                                                        )
                                                        .await;

                                                    let response = String::from_utf8_lossy(&data);

                                                    // Summary + full payload FileOnly: the
                                                    // send_telnet_* action template already
                                                    // reports the send to the TUI.
                                                    let response_preview = preview(&response, 100);
                                                    log.debug(format!(
                                                        "Telnet sent {} bytes on connection {}: {}",
                                                        data.len(),
                                                        connection_id,
                                                        response_preview.trim()
                                                    ));
                                                    log.trace(format!(
                                                        "Telnet sent (text): {:?}",
                                                        response.trim()
                                                    ));
                                                }
                                                // Only flags the intent: `break` here would
                                                // leave the read loop running and the socket
                                                // open, so close_connection did nothing.
                                                ActionResult::CloseConnection => {
                                                    close_requested = true;
                                                    closed = true;
                                                }
                                                _ => {}
                                            }
                                        }

                                        // One decision line per line of input, whatever happened.
                                        let subject = format!(
                                            "Telnet line from {} (connection {})",
                                            remote_addr, connection_id
                                        );
                                        if wrote > 0 {
                                            log.info(format!(
                                                "{} decision=model_answer ({} write(s){})",
                                                subject,
                                                wrote,
                                                if closed { ", then close" } else { "" }
                                            ));
                                        } else if closed {
                                            log.info(format!(
                                                "{} decision=model_reject (close_connection with \
                                                 no reply: the model hung up rather than answer)",
                                                subject
                                            ));
                                        } else if !failure_summary.is_empty() {
                                            log.error(format!(
                                                "{} decision=fail_closed_bad_action: nothing was \
                                                 written because the model's action(s) could not \
                                                 be executed ({})",
                                                subject, failure_summary
                                            ));
                                        } else if waited {
                                            log.info(format!(
                                                "{} decision=model_wait_for_more (deliberately \
                                                 nothing yet; the session stays open)",
                                                subject
                                            ));
                                        } else {
                                            // Not a fail-closed: the peer gets no notice and the
                                            // session stays open, so a human sits at a terminal
                                            // that looks hung. It is the model's silence rather
                                            // than the backend's, which is exactly why the two
                                            // need different tokens.
                                            log.warn(format!(
                                                "{} decision=model_silent: the model was asked and \
                                                 returned no usable action, so nothing was written \
                                                 and the peer sees an idle session",
                                                subject
                                            ));
                                        }
                                    }
                                    Err(e) => {
                                        // Same reasoning as the greeting: a Telnet client that
                                        // sent a line and gets nothing back cannot tell a
                                        // broken server from a slow one. A notice is not a
                                        // prompt and not a shell result, so nothing downstream
                                        // can read it as the command having run.
                                        //
                                        // ERROR with a `decision=fail_closed_*` token: the notice
                                        // on the wire is a category, not an answer, so this turn
                                        // produced nothing the peer asked for. The token is what
                                        // separates a dead backend from the model's own silence
                                        // and from its `close_connection` — all three leave the
                                        // request unanswered.
                                        let decision = match crate::utils::WireFailure::classify(&e)
                                        {
                                            crate::utils::WireFailure::Overloaded => {
                                                "fail_closed_llm_overloaded"
                                            }
                                            crate::utils::WireFailure::Unavailable => {
                                                "fail_closed_llm_error"
                                            }
                                        };
                                        log.error(format!(
                                            "Telnet line from {} (connection {}) decision={}: {}",
                                            remote_addr, connection_id, decision, e
                                        ));
                                        let notice = telnet_failure_notice(&e);
                                        use tokio::io::AsyncWriteExt;
                                        let mut write = write_half_arc.lock().await;
                                        let _ = write.write_all(notice.as_bytes()).await;
                                        let _ = write.flush().await;
                                    }
                                }

                                if close_requested {
                                    log.info(format!(
                                        "Telnet connection {} closed by handler",
                                        connection_id
                                    ));
                                    use tokio::io::AsyncWriteExt;
                                    let mut write = write_half_arc.lock().await;
                                    let _ = write.shutdown().await;
                                    break;
                                }
                            }

                            // Connection closed - mark as closed
                            state_clone
                                .remove_peer_handle(server_id, connection_id.as_u32())
                                .await;
                            state_clone
                                .close_connection_on_server(server_id, connection_id)
                                .await;
                            let _ = status_clone.send("__UPDATE_UI__".to_string());
                        }).await;
                    }
                    Err(e) => {
                        Log::new(Some(&status_tx))
                            .error(format!("Failed to accept Telnet connection: {}", e));
                        break;
                    }
                }
            }
        });

        // Register the accept loop so stop_server can abort it and release the port.
        task_registrar
            .register_server_task(server_id, accept_handle)
            .await;

        Ok(local_addr)
    }
}


/// The line to print when the LLM backend fails.
///
/// Telnet is an unstructured byte stream: there is no status code to send and no framing a
/// client could key off, so the only useful thing to do is tell whoever is on the other end,
/// in words, that the server could not answer - and to say so on its own line so it cannot be
/// mistaken for the output of whatever they typed.
///
/// The text is a category, never the error: see `crate::utils::wire_failure`. This is the
/// path that put netget's own retry message on a stranger's terminal.
///
/// CRLF because a raw Telnet client is usually in a mode where a bare LF does not return the
/// carriage, which would leave the message stair-stepping across the terminal.
fn telnet_failure_notice(err: &anyhow::Error) -> String {
    format!(
        "\r\n[netget] {}\r\n",
        crate::utils::WireFailure::classify(err).text()
    )
}
