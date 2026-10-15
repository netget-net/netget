//! SMTP server implementation
pub mod actions;

use anyhow::Result;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{error, warn};

use crate::console_debug;
#[cfg(not(target_arch = "wasm32"))]
use crate::llm::action_helper::call_llm;
#[cfg(not(target_arch = "wasm32"))]
use crate::llm::ollama_client::OllamaClient;
#[cfg(not(target_arch = "wasm32"))]
use crate::llm::ActionResult;
#[cfg(not(target_arch = "wasm32"))]
use crate::logging::emit::Log;
#[cfg(not(target_arch = "wasm32"))]
use crate::protocol::Event;
#[cfg(not(target_arch = "wasm32"))]
use crate::server::SmtpProtocol;
#[cfg(not(target_arch = "wasm32"))]
use crate::state::app_state::AppState;
#[cfg(not(target_arch = "wasm32"))]
use actions::SMTP_COMMAND_EVENT;
#[cfg(not(target_arch = "wasm32"))]
use tokio_rustls::TlsAcceptor;

/// The longest single line this server will buffer, in bytes.
///
/// RFC 5321 §4.5.3.1 sets the minimum a server must accept at 512 octets for a command and
/// 1000 for a `DATA` text line, and invites larger. 64 KiB is far above anything legitimate
/// and far below what it costs us to refuse.
///
/// The cap is the point. `BufReader::read_line` grows its `String` until it finds a `\n`, so
/// a peer that connects and streams bytes without ever sending one allocates until the
/// process dies — one unauthenticated socket, no credentials, no protocol state.
#[cfg(not(target_arch = "wasm32"))]
pub const MAX_LINE_BYTES: usize = 64 * 1024;

/// How long a session waits for the next line before it gives up on the peer.
///
/// RFC 5321 §4.5.3.2 sets the server-side "command" timeout at 5 minutes. Without one, a peer
/// that connects and then says nothing holds a connection task, a socket and its slot in the
/// connection map for as long as the process runs.
#[cfg(not(target_arch = "wasm32"))]
const READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

/// Concurrent connections this server admits before it starts refusing.
///
/// [`crate::server::accept_bounded::DEFAULT_MAX_CONNECTIONS`]. This is the bound
/// [`READ_TIMEOUT`] needs to be worth anything: RFC 5321 §4.5.3.2 makes the per-command wait
/// five minutes, so one stranger legitimately holds a socket for five minutes and an uncapped
/// accept loop turns that into as many five-minute holds as it can open. A mail server is the
/// canonical target for this, which is why every real MTA ships a connection limit of its own
/// (Postfix's `smtpd_client_connection_count_limit` defaults to 50 *per client*); 256 total is
/// generous against a real sending host and finite against an attacker.
#[cfg(not(target_arch = "wasm32"))]
const MAX_CONNECTIONS: usize = crate::server::accept_bounded::DEFAULT_MAX_CONNECTIONS;

/// What a peer over [`MAX_CONNECTIONS`] is told before the socket closes, on a **plain**
/// listener.
///
/// SMTP is server-speaks-first, so a refusal has a natural place: the greeting. RFC 5321 §3.1
/// and §4.3.2 let the server open with something other than 220, and 421 — "Service not
/// available, closing transmission channel" — is precisely this case; Postfix answers its own
/// connection-count limit with a 421 greeting, so every MTA in the world already handles it and
/// backs off rather than recording a permanent failure. The enhanced code matches the
/// `421 4.3.2` this server already sends when its model backend is saturated.
#[cfg(not(target_arch = "wasm32"))]
const CONNECTION_CAP_REFUSAL: &[u8] = b"421 4.3.2 Too many connections, try again later\r\n";

/// What a peer over [`MAX_CONNECTIONS`] gets on an **implicit-TLS (SMTPS)** listener: nothing,
/// and then a close.
///
/// A peer on port 465 is mid-`ClientHello` and expects TLS records; plaintext ASCII arriving
/// there is not a 421 it will ever read, it is a record with content type 0x34 and a nonsense
/// version, and every TLS stack aborts the handshake with a decode error. That is a worse
/// answer than silence — the client records a broken server rather than a busy one. The
/// correct refusal would be a TLS `alert(internal_error)`, which cannot be formed without
/// first completing the handshake we are declining to spend a slot on, so the honest answer is
/// an empty write and a clean close, logged as `decision=fail_closed_connection_cap`.
#[cfg(not(target_arch = "wasm32"))]
const CONNECTION_CAP_REFUSAL_TLS: &[u8] = b"";

/// The outcome of one bounded read.
#[cfg(not(target_arch = "wasm32"))]
enum LineRead {
    Line(String),
    /// The peer closed, or sent a partial line and then closed.
    Eof,
    /// `MAX_LINE_BYTES` went by without a `\n`.
    TooLong,
    /// `READ_TIMEOUT` went by without a byte.
    Timeout,
}

/// Read one `\n`-terminated line, bounded in both length and time.
///
/// Two deliberate differences from `BufReader::read_line`:
///
/// * It stops at `MAX_LINE_BYTES` instead of growing without bound.
/// * It decodes lossily instead of failing on invalid UTF-8. `read_line` returns
///   `ErrorKind::InvalidData` for any non-UTF-8 byte and the session died on it — while the
///   EHLO reply advertises `8BITMIME`, so the server would be promising a capability its own
///   read path could not survive. One Latin-1 byte in a message body was
///   enough. These bytes only ever become the model's event payload and a log line; nothing
///   here is re-emitted on the wire, so a lossy decode loses nothing a peer can observe.
///
/// A partial line at EOF is reported as `Eof`, not as a line: half a command is not a command.
#[cfg(not(target_arch = "wasm32"))]
async fn read_line_bounded<R>(reader: &mut tokio::io::BufReader<R>) -> Result<LineRead>
where
    R: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncBufReadExt;

    let mut buf: Vec<u8> = Vec::new();
    loop {
        let chunk = match tokio::time::timeout(READ_TIMEOUT, reader.fill_buf()).await {
            Err(_elapsed) => return Ok(LineRead::Timeout),
            Ok(result) => result?,
        };
        if chunk.is_empty() {
            return Ok(LineRead::Eof);
        }
        match chunk.iter().position(|&b| b == b'\n') {
            Some(idx) => {
                if buf.len() + idx + 1 > MAX_LINE_BYTES {
                    return Ok(LineRead::TooLong);
                }
                buf.extend_from_slice(&chunk[..=idx]);
                reader.consume(idx + 1);
                return Ok(LineRead::Line(String::from_utf8_lossy(&buf).into_owned()));
            }
            None => {
                let taken = chunk.len();
                if buf.len() + taken > MAX_LINE_BYTES {
                    return Ok(LineRead::TooLong);
                }
                buf.extend_from_slice(chunk);
                reader.consume(taken);
            }
        }
    }
}

/// The extensions NetGet's own EHLO reply advertises.
///
/// Only what this server actually does. `8BITMIME` because the reader is 8-bit clean
/// ([`read_line_bounded`] decodes lossily rather than failing). Nothing else: there is no
/// STARTTLS, no AUTH, no PIPELINING, and no SIZE is enforced, and advertising any of them makes
/// a real MTA try it and fail.
pub const EHLO_EXTENSIONS: &[&str] = &["8BITMIME"];

/// NetGet's answer to `EHLO`/`HELO`, or `None` for any other line.
///
/// Answered here rather than by the model because the reply has exactly one correct form - the
/// greeting's hostname and [`EHLO_EXTENSIONS`], which are facts about this implementation, not
/// decisions. Asked, a small model answered EHLO with the 220 greeting action (so the client
/// read a greeting as its EHLO reply and every later reply one step late), or advertised
/// STARTTLS copied from an example, which this server cannot do.
pub fn ehlo_reply(command: &str, hostname: &str) -> Option<Vec<u8>> {
    let mut parts = command.trim().splitn(2, char::is_whitespace);
    let verb = parts.next()?.to_ascii_uppercase();
    if verb != "EHLO" && verb != "HELO" {
        return None;
    }
    let client = parts.next().map(str::trim).unwrap_or("");
    if client.is_empty() {
        // RFC 5321 4.1.1.1: the domain argument is required.
        return Some(format!("501 5.5.4 Syntax: {verb} hostname\r\n").into_bytes());
    }
    let mut reply = String::new();
    if verb == "HELO" {
        reply.push_str(&format!("250 {hostname} greets {client}\r\n"));
    } else {
        reply.push_str(&format!("250-{hostname} greets {client}\r\n"));
        for (i, ext) in EHLO_EXTENSIONS.iter().enumerate() {
            let sep = if i + 1 == EHLO_EXTENSIONS.len() {
                ' '
            } else {
                '-'
            };
            reply.push_str(&format!("250{sep}{ext}\r\n"));
        }
    }
    Some(reply.into_bytes())
}

/// The hostname a 220 greeting announced (`220 <host> ...`), for the EHLO reply to repeat.
pub fn greeting_hostname(greeting: &[u8]) -> Option<String> {
    let line = String::from_utf8_lossy(greeting);
    let mut fields = line.split_whitespace();
    if fields.next()? != "220" {
        return None;
    }
    fields
        .next()
        .filter(|h| h.bytes().all(|b| b.is_ascii_graphic()))
        .map(str::to_string)
}

/// The actions whose reply wins when a batch answers one SMTP line with several: the one the
/// line's `answer_with` names when only one fits. See `ExecutionResult::chosen_reply`.
pub fn smtp_preferred_actions(command: &str, in_data: bool) -> &'static [&'static str] {
    const ACCEPT_OR_REFUSE: &[&str] = &["send_smtp_ok", "send_smtp_error"];
    if in_data {
        return if command == "." {
            ACCEPT_OR_REFUSE
        } else {
            &[]
        };
    }
    if command == "CONNECTION_ESTABLISHED" {
        return &["send_smtp_greeting"];
    }
    let upper = command.to_ascii_uppercase();
    if upper.starts_with("MAIL FROM:") || upper.starts_with("RCPT TO:") {
        return ACCEPT_OR_REFUSE;
    }
    match upper.split_whitespace().next().unwrap_or("") {
        "DATA" => &["send_smtp_start_data"],
        "QUIT" => &["send_smtp_quit"],
        "RSET" | "NOOP" => &["send_smtp_ok"],
        _ => &[],
    }
}

/// The event data for one SMTP line: the line itself, plus what NetGet can tell from it.
///
/// `answer_with` names the action (and reply code) this particular line takes. A small model
/// reused one action for a whole session - the 220 greeting for EHLO and MAIL, a 250 for a
/// recipient the instruction said to refuse - and it follows a per-request hint far better
/// than a general description. For `MAIL FROM`/`RCPT TO` the address and its domain are
/// split out, because an instruction like "refuse any other domain" is a decision about the
/// domain. `in_data` is whether a 354 has gone out and the terminating `.` has not arrived:
/// then the line is message text, whatever it looks like.
pub fn smtp_command_event_data(command: &str, in_data: bool) -> serde_json::Value {
    let mut data = serde_json::json!({ "command": command });
    if in_data {
        data["answer_with"] = if command == "." {
            "send_smtp_ok (250) to accept the message, or send_smtp_error to refuse it".into()
        } else {
            "wait_for_more: a line of the message body gets no reply".into()
        };
        return data;
    }
    if command == "CONNECTION_ESTABLISHED" {
        data["answer_with"] = "send_smtp_greeting, with the banner your instruction gives (if \
                               any) as message; close_connection to refuse the connection"
            .into();
        return data;
    }
    let upper = command.to_ascii_uppercase();
    let address = |prefix: &str| -> Option<String> {
        let rest = command.get(prefix.len()..)?.trim();
        let inner = rest
            .strip_prefix('<')
            .and_then(|r| r.split_once('>').map(|(a, _)| a))
            .unwrap_or_else(|| rest.split_whitespace().next().unwrap_or(""));
        Some(inner.to_string())
    };
    let (answer, addr) = if upper.starts_with("MAIL FROM:") {
        (
            "send_smtp_ok (250) to accept this sender, or send_smtp_error with code 550 to \
             refuse it. The recipient is decided later, at RCPT TO",
            address("MAIL FROM:"),
        )
    } else if upper.starts_with("RCPT TO:") {
        (
            "send_smtp_ok (250) to accept mail for this recipient, or send_smtp_error with \
             code 550 to refuse it; decide from the recipient's domain",
            address("RCPT TO:"),
        )
    } else {
        let answer = match upper.split_whitespace().next().unwrap_or("") {
            "DATA" => "send_smtp_start_data (354); the message then arrives one line per event",
            "QUIT" => "send_smtp_quit (221), then close_connection",
            "RSET" | "NOOP" => "send_smtp_ok (250)",
            _ => return data,
        };
        (answer, None)
    };
    data["answer_with"] = answer.into();
    if let Some(addr) = addr {
        if let Some((_, domain)) = addr.rsplit_once('@') {
            data["domain"] = domain.to_ascii_lowercase().into();
        }
        data["address"] = addr.into();
    }
    data
}

/// SMTP server that forwards mail to LLM
pub struct SmtpServer;

#[cfg(not(target_arch = "wasm32"))]
impl SmtpServer {
    /// Spawn SMTP server with integrated LLM actions
    ///
    /// If tls_config is Some, the server will use implicit TLS (SMTPS)
    /// If tls_config is None, the server will use plain text (SMTP)
    pub async fn spawn_with_llm_actions(
        listen_addr: SocketAddr,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        server_id: crate::state::ServerId,
        tls_config: Option<Arc<rustls::ServerConfig>>,
    ) -> Result<SocketAddr> {
        let listener =
            crate::server::socket_helpers::create_reusable_tcp_listener(listen_addr).await?;
        let local_addr = listener.local_addr()?;

        if tls_config.is_some() {
            Log::new(Some(&status_tx)).info(format!(
                "SMTPS server (TLS, action-based) listening on {}",
                local_addr
            ));
        } else {
            Log::new(Some(&status_tx)).info(format!(
                "SMTP server (plain, action-based) listening on {}",
                local_addr
            ));
        }

        let protocol = Arc::new(SmtpProtocol::new());
        let tls_acceptor = tls_config.map(TlsAcceptor::from);

        let task_registrar = app_state.clone();
        let limiter = crate::server::accept_bounded::ConnectionLimiter::new(MAX_CONNECTIONS);
        // Which refusal this listener can honestly send depends on what the peer is speaking,
        // and on this listener that is decided once, at bind time.
        let cap_refusal: &'static [u8] = if tls_acceptor.is_some() {
            CONNECTION_CAP_REFUSAL_TLS
        } else {
            CONNECTION_CAP_REFUSAL
        };
        let accept_handle = tokio::spawn(async move {
            loop {
                match crate::server::accept_bounded::accept_bounded(
                    &listener,
                    &limiter,
                    cap_refusal,
                    "SMTP",
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
                            "SMTP connection {} from {}",
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
                                // Released when this task ends, and this task is the whole of
                                // the connection — the TLS handshake and the session both run
                                // inside it and SMTP spawns nothing else per peer — so
                                // `MAX_CONNECTIONS` caps live connections, not accepts.
                                let _permit = permit;
                                // Optionally perform TLS handshake
                                if let Some(ref acceptor) = tls_acceptor_clone {
                                    match acceptor.accept(stream).await {
                                        Ok(tls_stream) => {
                                            Log::new(Some(&status_clone)).debug(format!(
                                                "TLS handshake completed for connection {}",
                                                connection_id
                                            ));
                                            if let Err(e) = SmtpSession::handle_session(
                                                tls_stream,
                                                connection_id,
                                                remote_addr,
                                                local_addr_conn,
                                                server_id,
                                                llm_clone,
                                                state_clone,
                                                status_clone.clone(),
                                                protocol_clone,
                                            )
                                            .await
                                            {
                                                Log::new(Some(&status_clone))
                                                    .error(format!("SMTP session error: {}", e));
                                            }
                                        }
                                        Err(e) => {
                                            Log::new(Some(&status_clone)).error(format!(
                                                "TLS handshake failed for connection {}: {}",
                                                connection_id, e
                                            ));
                                        }
                                    }
                                } else {
                                    if let Err(e) = SmtpSession::handle_session(
                                        stream,
                                        connection_id,
                                        remote_addr,
                                        local_addr_conn,
                                        server_id,
                                        llm_clone,
                                        state_clone,
                                        status_clone.clone(),
                                        protocol_clone,
                                    )
                                    .await
                                    {
                                        Log::new(Some(&status_clone))
                                            .error(format!("SMTP session error: {}", e));
                                    }
                                };
                            })
                            .await;
                    }
                    Err(e) => {
                        error!("Failed to accept SMTP connection: {}", e);
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

#[cfg(not(target_arch = "wasm32"))]
struct SmtpSession;

#[cfg(not(target_arch = "wasm32"))]
impl SmtpSession {
    /// Handle one SMTP session, plain or SMTPS.
    ///
    /// Generic over the transport: the plain and TLS paths were previously two verbatim
    /// copies of the same greeting-then-command-loop code.
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
        protocol: Arc<SmtpProtocol>,
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
        protocol: &Arc<SmtpProtocol>,
    ) -> Result<()>
    where
        R: tokio::io::AsyncRead + Unpin,
        W: tokio::io::AsyncWrite + Unpin,
    {
        use tokio::io::AsyncWriteExt;

        // Send initial greeting. `None` means the model refused the connection; close
        // without entering the command loop. Otherwise it is the hostname the greeting
        // announced, which NetGet's own EHLO reply repeats.
        let Some(hostname) = Self::send_greeting(
            write_half,
            connection_id,
            server_id,
            llm_client,
            app_state,
            status_tx,
            protocol,
        )
        .await?
        else {
            return Ok(());
        };

        // Between a 354 and the terminating ".", every line is message text: it is never
        // a command, whatever it looks like, and it gets no reply of its own.
        let mut in_data = false;

        loop {
            let line = match read_line_bounded(&mut reader).await? {
                LineRead::Line(line) => line,
                LineRead::Eof => break,
                LineRead::TooLong => {
                    // RFC 5321 §4.5.3.1 sets the line limits; 500 5.5.2 is the reply for
                    // breaking them. Close afterwards: we stopped reading mid-line, so the
                    // rest of that line would be parsed as fresh commands.
                    warn!(
                        "SMTP connection {} sent a line over {} bytes with no newline; closing",
                        connection_id, MAX_LINE_BYTES
                    );
                    Self::write_counted(
                        write_half,
                        b"500 5.5.2 Line too long\r\n",
                        connection_id,
                        server_id,
                        app_state,
                        status_tx,
                    )
                    .await?;
                    break;
                }
                LineRead::Timeout => {
                    // RFC 5321 §4.5.3.2: the server-side command timeout. 421 is the code for
                    // "service closing transmission channel", which is exactly what happens.
                    warn!(
                        "SMTP connection {} idle for {}s; closing",
                        connection_id,
                        READ_TIMEOUT.as_secs()
                    );
                    Self::write_counted(
                        write_half,
                        b"421 4.4.2 Timeout waiting for command\r\n",
                        connection_id,
                        server_id,
                        app_state,
                        status_tx,
                    )
                    .await?;
                    break;
                }
            };
            let n = line.len();
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
            console_debug!(status_tx, "SMTP received: {}", command);

            if !in_data {
                if let Some(reply) = ehlo_reply(command, &hostname) {
                    Log::new(Some(status_tx)).info(format!(
                        "SMTP connection {} decision=netget_answer: {} answered by NetGet \
                         (extensions: {})",
                        connection_id,
                        crate::utils::truncate_for_log(command, 80),
                        EHLO_EXTENSIONS.join(" ")
                    ));
                    Self::write_reply(
                        write_half,
                        &reply,
                        connection_id,
                        server_id,
                        app_state,
                        status_tx,
                    )
                    .await?;
                    continue;
                }
            }

            let event = Event::new(
                &SMTP_COMMAND_EVENT,
                smtp_command_event_data(command, in_data),
            );
            let preferred = smtp_preferred_actions(command, in_data);
            // The terminating "." ends the message whatever the answer to it is.
            let ends_message = in_data && command == ".";
            if ends_message {
                in_data = false;
            }

            match call_llm(
                llm_client,
                app_state,
                server_id,
                Some(connection_id),
                &event,
                protocol.as_ref(),
            )
            .await
            {
                Ok(execution_result) => {
                    let mut should_close = false;
                    let mut wrote_reply = false;
                    let mut silence_is_deliberate = false;
                    let mut dropped_replies = 0usize;

                    let chosen = execution_result.chosen_reply(preferred);
                    for (index, protocol_result) in
                        execution_result.protocol_results.into_iter().enumerate()
                    {
                        match protocol_result {
                            // One command, one reply. SMTP has no pipelining here, so a second
                            // reply is read by the client as the answer to its *next* command,
                            // and every reply after that is off by one for the rest of the
                            // session. Only the chosen one - the action `answer_with` names,
                            // else the first - is written.
                            ActionResult::Output(_) if Some(index) != chosen => {
                                dropped_replies += 1
                            }
                            ActionResult::Output(data) => {
                                wrote_reply = true;
                                if !ends_message && data.starts_with(b"354") {
                                    in_data = true;
                                }
                                Self::write_reply(
                                    write_half,
                                    &data,
                                    connection_id,
                                    server_id,
                                    app_state,
                                    status_tx,
                                )
                                .await?;
                            }
                            // Do not return here: the QUIT reply is normally a 221 followed by
                            // close_connection in the same batch, and returning early would
                            // drop the 221 when the ordering came back reversed.
                            ActionResult::CloseConnection => should_close = true,
                            // `wait_for_more` is the model saying "send nothing and read the
                            // next line" - correct and required during DATA, where SMTP
                            // expects no per-line reply. It is the one answer that makes
                            // silence right, which is exactly why it has to be told apart
                            // from an empty answer below.
                            ActionResult::WaitForMore => silence_is_deliberate = true,
                            _ => {}
                        }
                    }

                    if dropped_replies > 0 {
                        Log::new(Some(status_tx)).warn(format!(
                            "SMTP connection {} decision=duplicate_response_dropped: {} extra \
                             repl{} to {:?} not sent; one command gets one reply",
                            connection_id,
                            dropped_replies,
                            if dropped_replies == 1 { "y" } else { "ies" },
                            crate::utils::truncate_for_log(command, 80)
                        ));
                    }

                    if should_close {
                        return Ok(());
                    }

                    // A model that answered with nothing at all used to leave the peer
                    // blocked until its own timeout - the same defect the `Err` arm's 451
                    // exists to remove, reached through the success path instead. SMTP is not
                    // one of the deliberately-silent protocols: every command owes a reply,
                    // and `wait_for_more` is already the way to decline one. So an empty
                    // answer is a failure and gets the same 451, and the log says which of
                    // the two it was.
                    if !wrote_reply && !silence_is_deliberate {
                        Log::new(Some(status_tx)).error(format!(
                            "SMTP connection {} decision=model_silent for {:?}: the model \
                             produced no reply; answering 451",
                            connection_id,
                            crate::utils::truncate_for_log(command, 200)
                        ));
                        Self::write_counted(
                            write_half,
                            b"451 4.3.0 Temporary local error, try again later\r\n",
                            connection_id,
                            server_id,
                            app_state,
                            status_tx,
                        )
                        .await?;
                    }
                }
                Err(e) => {
                    // Answer 451 rather than writing nothing. SMTP has a whole 4xx class
                    // meaning "temporary, retry later" (RFC 5321 §4.2.1), which is exactly
                    // what an unavailable backend is, and a client that gets one requeues the
                    // message instead of blocking until its own timeout and then bouncing it.
                    //
                    // It also fails closed: a 4xx is never mistaken for acceptance, so an
                    // outage cannot silently look like a delivered message.
                    Log::new(Some(status_tx)).error(format!(
                        "SMTP connection {} got no response for {:?}: {:#}",
                        connection_id, command, e
                    ));

                    // 4.3.2 is "system not accepting network messages" (RFC 3463), which is
                    // the truthful enhanced code for capacity exhaustion; 4.3.0 covers the
                    // rest.
                    let reply: &[u8] = if crate::llm::is_overload_error(&e) {
                        warn!(
                            "SMTP 451 on connection {}: LLM capacity exhausted",
                            connection_id
                        );
                        b"451 4.3.2 Backend at capacity, try again later\r\n"
                    } else {
                        b"451 4.3.0 Temporary local error, try again later\r\n"
                    };
                    let mut writer = write_half.lock().await;
                    writer.write_all(reply).await?;
                    writer.flush().await?;
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
                    console_debug!(
                        status_tx,
                        "SMTP sent: {}",
                        String::from_utf8_lossy(reply).trim()
                    );
                }
            }
        }

        Ok(())
    }

    /// Write a fixed reply and account for it, dropping the writer guard before returning.
    ///
    /// The byte slice is `&'static [u8]` on purpose: everything this is used for is a protocol
    /// constant, and a `&[u8]` parameter would be one `format!` away from putting an internal
    /// error string on a stranger's terminal — the defect `crate::utils::wire_failure` exists
    /// to prevent.
    async fn write_counted<W>(
        write_half: &Arc<tokio::sync::Mutex<W>>,
        reply: &'static [u8],
        connection_id: crate::server::connection::ConnectionId,
        server_id: crate::state::ServerId,
        app_state: &Arc<AppState>,
        status_tx: &mpsc::UnboundedSender<String>,
    ) -> Result<()>
    where
        W: tokio::io::AsyncWrite + Unpin,
    {
        use tokio::io::AsyncWriteExt;

        {
            let mut writer = write_half.lock().await;
            writer.write_all(reply).await?;
            writer.flush().await?;
        }
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
        console_debug!(
            status_tx,
            "SMTP sent: {}",
            String::from_utf8_lossy(reply).trim()
        );
        Ok(())
    }

    /// Write one reply built at runtime (a model's answer, NetGet's EHLO reply) and account
    /// for it.
    async fn write_reply<W>(
        write_half: &Arc<tokio::sync::Mutex<W>>,
        reply: &[u8],
        connection_id: crate::server::connection::ConnectionId,
        server_id: crate::state::ServerId,
        app_state: &Arc<AppState>,
        status_tx: &mpsc::UnboundedSender<String>,
    ) -> Result<()>
    where
        W: tokio::io::AsyncWrite + Unpin,
    {
        use tokio::io::AsyncWriteExt;

        {
            let mut writer = write_half.lock().await;
            writer.write_all(reply).await?;
            writer.flush().await?;
        }
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
        console_debug!(
            status_tx,
            "SMTP sent: {}",
            String::from_utf8_lossy(reply).trim()
        );
        Ok(())
    }

    /// Send the greeting.
    ///
    /// Returns `Ok(None)` when the model answered the greeting event with `close_connection`
    /// — a deliberate refusal, which is a different thing from a backend failure and must not
    /// be reported as one. `Err` is reserved for the backend actually failing, and carries the
    /// 421 that has already been written. Otherwise `Ok(Some(hostname))`: the host the banner
    /// announced, or `localhost` when it named none.
    async fn send_greeting<W>(
        write_half: &Arc<tokio::sync::Mutex<W>>,
        connection_id: crate::server::connection::ConnectionId,
        server_id: crate::state::ServerId,
        llm_client: &OllamaClient,
        app_state: &Arc<AppState>,
        status_tx: &mpsc::UnboundedSender<String>,
        protocol: &Arc<SmtpProtocol>,
    ) -> Result<Option<String>>
    where
        W: tokio::io::AsyncWrite + Unpin,
    {
        use tokio::io::AsyncWriteExt;

        let greeting_event = Event::new(
            &SMTP_COMMAND_EVENT,
            smtp_command_event_data("CONNECTION_ESTABLISHED", false),
        );
        let mut hostname = None;

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
                let mut refused = false;
                let mut dropped_replies = 0usize;
                let chosen = execution_result
                    .chosen_reply(smtp_preferred_actions("CONNECTION_ESTABLISHED", false));
                for (index, protocol_result) in
                    execution_result.protocol_results.into_iter().enumerate()
                {
                    match protocol_result {
                        // One banner. A second 220 would be read as the reply to the client's
                        // first command, leaving every reply after it one step late.
                        ActionResult::Output(_) if Some(index) != chosen => dropped_replies += 1,
                        ActionResult::Output(data) => {
                            hostname = greeting_hostname(&data);
                            Self::write_reply(
                                write_half,
                                &data,
                                connection_id,
                                server_id,
                                app_state,
                                status_tx,
                            )
                            .await?;
                        }
                        // `close_connection` is advertised on `smtp_command`, and the greeting
                        // *is* an `smtp_command` event, so refusing the connection is an answer
                        // the model is explicitly offered. This arm used to be an
                        // `if let ActionResult::Output(..)`, which dropped the refusal on the
                        // floor and carried on into the command loop on a connection the model
                        // had declined - a denial that did not deny.
                        ActionResult::CloseConnection => refused = true,
                        _ => {}
                    }
                }
                if dropped_replies > 0 {
                    Log::new(Some(status_tx)).warn(format!(
                        "SMTP connection {} decision=duplicate_response_dropped: {} extra \
                         greeting repl{} not sent",
                        connection_id,
                        dropped_replies,
                        if dropped_replies == 1 { "y" } else { "ies" }
                    ));
                }
                if refused {
                    Log::new(Some(status_tx)).info(format!(
                        "SMTP connection {} decision=model_reject: the model refused the \
                         connection at the greeting",
                        connection_id
                    ));
                    return Ok(None);
                }
            }
            Err(e) => {
                // No banner means no session. RFC 5321 §3.1 gives a server exactly this way
                // to decline one: a 421 greeting, after which the connection closes. Writing
                // nothing (the previous behaviour) left the peer waiting for a 220 until its
                // own timeout, with no way to tell an overloaded server from a black hole.
                Log::new(Some(status_tx)).error(format!(
                    "SMTP greeting for connection {} failed: {:#}",
                    connection_id, e
                ));

                let reply: &[u8] = if crate::llm::is_overload_error(&e) {
                    warn!(
                        "SMTP 421 on connection {}: LLM capacity exhausted",
                        connection_id
                    );
                    b"421 4.3.2 Service not available, backend at capacity\r\n"
                } else {
                    b"421 4.3.0 Service not available, closing transmission channel\r\n"
                };
                let mut writer = write_half.lock().await;
                writer.write_all(reply).await?;
                writer.flush().await?;
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
                let _ = status_tx.send(format!(
                    "→ SMTP {} to connection {}",
                    String::from_utf8_lossy(reply).trim(),
                    connection_id
                ));

                // Propagate so handle_session stops before the command loop: after a 421 the
                // only thing the server may do is close.
                anyhow::bail!("SMTP greeting unavailable: {e:#}");
            }
        }

        Ok(Some(hostname.unwrap_or_else(|| "localhost".to_string())))
    }
}

#[cfg(target_arch = "wasm32")]
impl SmtpServer {
    pub async fn spawn_with_llm_actions(
        _listen_addr: SocketAddr,
        _llm_client: OllamaClient,
        _app_state: Arc<AppState>,
        _status_tx: mpsc::UnboundedSender<String>,
        _server_id: crate::state::ServerId,
        _tls_config: Option<Arc<rustls::ServerConfig>>,
    ) -> Result<SocketAddr> {
        anyhow::bail!("SMTP feature not enabled")
    }
}
