//! NNTP server implementation
pub mod actions;
pub mod extensions;

use crate::server::connection::ConnectionId;
use anyhow::Result;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncWriteExt, BufReader};
use tokio::sync::mpsc;

use crate::llm::action_helper::call_llm;
use crate::llm::actions::protocol_trait::ActionResult;
use crate::llm::ollama_client::OllamaClient;
use crate::logging::emit::Log;
use crate::protocol::Event;
use crate::server::NntpProtocol;
use crate::state::app_state::AppState;
use actions::NNTP_COMMAND_RECEIVED_EVENT;

/// Largest single command line the server will buffer before refusing the peer.
///
/// RFC 3977 §3.1 fixes the NNTP command line at **512 octets** including the CRLF. 4 KiB is
/// eight times that, which leaves room for the long arguments `NEWNEWS` and a wildmat
/// `LIST ACTIVE` can carry while staying far below anything worth buffering.
///
/// The cap exists because `AsyncBufReadExt::read_line` grows its `String` until it finds a
/// `\n` and bounds nothing: an unauthenticated peer that connects and streams bytes with no
/// newline made the server allocate without limit. The refusal happens here, before the
/// `nntp_command_received` event is built, so an oversized line never reaches a prompt.
pub const MAX_COMMAND_BYTES: usize = 4096;

/// How long to wait for the first command after the greeting has been sent.
///
/// **This was 60 seconds, and "NNTP is server-speaks-first" was the wrong reason for it.** The
/// argument read: the peer is answered with a `200`/`201` greeting and every reader — `nntp`,
/// `slrn`, `tin`, a mail client's news backend — replies inside its own connect path with
/// `CAPABILITIES` or `MODE READER`, so a minute is far longer than that takes. True of every
/// third-party reader, and irrelevant to the peer this server most often has: the greeting is
/// *ours*, and sending it says nothing about whether the other end will answer it.
///
/// The question a first-byte bound actually has to answer is whether NetGet's own client of
/// this protocol can be connected and silent. NNTP's can, and is, by default:
/// `src/client/nntp/mod.rs` opens the socket, registers its command channel, and then reads
/// the welcome line in its read loop. It writes nothing of its own — every byte it puts on the
/// wire comes from an action — and a client created from the dashboard's `[ + nntp client ]`
/// is routed `nntp_connected` → static-with-no-actions and then `*` → manual
/// (`src/tui/modal/form.rs`). So it connects, reads our greeting, parks it for a person, and
/// waits for someone to type into `[ send message ]`. At 60 seconds this server hung up on the
/// operator's own client while they were still looking at it.
///
/// 300 seconds is the window a `manual` rule gives a human to answer one event
/// (`src/state/intercepts.rs`), which is the number this product already uses for how long
/// someone might take.
///
/// What it costs: a stranger holding a socket, a task, an `AppState` row and one of
/// [`MAX_CONNECTIONS`] slots while saying nothing now gets 300 seconds rather than 60 — a
/// fivefold rise in how long one idle slot is held, not a removal of the bound. The cap still
/// holds and a peer over it is still answered [`CONNECTION_CAP_REFUSAL`]. A listener exposed
/// to strangers should set `first_byte_timeout_secs` low; 60 is the old value and remains a
/// sound choice for one.
///
/// The greeting itself sits outside this deadline by construction: it is generated and written
/// before this loop begins, so however long the model or a `manual` rule takes over it, the
/// clock has not started.
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
/// Ten minutes. A newsreader is idle for exactly as long as the person at it takes to read an
/// article, so the bound has to be on a human timescale rather than a machine one — which is
/// why news server operators configure their client timeout in minutes. It is safe to make it
/// this generous because NNTP here holds nothing on the client's behalf that a reconnect cannot
/// rebuild: the model answers every command afresh, so a reclaimed idle connection costs a
/// reader one transparent reconnect.
///
/// The LLM round-trip and a `manual` rule parking a command for a human
/// (`src/state/intercepts.rs`, 300s by default) both happen after a line has already been read,
/// so neither can be timed out from under itself.
///
/// Overridable per server with `idle_timeout_secs`, for the same reason the first bound is:
/// the right value is a property of who is on the other end, and only the operator knows that.
const IDLE_BETWEEN_COMMANDS_TIMEOUT: Duration = Duration::from_secs(600);

/// Concurrent connections this server admits.
///
/// [`crate::server::accept_bounded::DEFAULT_MAX_CONNECTIONS`]. Each connection may buffer up to
/// [`MAX_COMMAND_BYTES`], so this is the multiplier that turns that per-connection bound into a
/// total one.
const MAX_CONNECTIONS: usize = crate::server::accept_bounded::DEFAULT_MAX_CONNECTIONS;

/// What a peer over [`MAX_CONNECTIONS`] is told before the socket closes.
///
/// `400` is NNTP's "service temporarily unavailable, the connection is closing" response, and
/// RFC 3977 lets a server send it at any point — including in place of a greeting, which is
/// exactly where a refused peer is. A client reads it as *retry later* rather than as a
/// permanent refusal, which is what a connection cap means. Fixed text, so there is no
/// placeholder an internal error could reach.
const CONNECTION_CAP_REFUSAL: &[u8] = b"400 too many connections\r\n";

/// NNTP server that forwards commands to LLM
pub struct NntpServer;

impl NntpServer {
    /// Spawn NNTP server with integrated LLM actions
    #[allow(clippy::too_many_arguments)]
    pub async fn spawn_with_llm_actions(
        listen_addr: SocketAddr,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        server_id: crate::state::ServerId,
        first_byte_timeout_secs: Option<u64>,
        idle_timeout_secs: Option<u64>,
        tls: Option<tokio_rustls::TlsAcceptor>,
        require_auth: bool,
    ) -> Result<SocketAddr> {
        // Both bounds are tunable because their right value is a property of who is on the
        // other end, which only the operator knows. The defaults serve NetGet's own NNTP
        // client waiting on a human; a listener exposed to strangers wants the first one much
        // lower.
        let deadlines = ReadDeadlines::resolve(first_byte_timeout_secs, idle_timeout_secs);
        let listener =
            crate::server::socket_helpers::create_reusable_tcp_listener(listen_addr).await?;
        let local_addr = listener.local_addr()?;
        Log::new(Some(&status_tx)).info(format!("NNTP server listening on {}", local_addr));

        let protocol = Arc::new(NntpProtocol::new());

        let task_registrar = app_state.clone();
        let limiter = crate::server::accept_bounded::ConnectionLimiter::new(MAX_CONNECTIONS);
        let accept_handle = tokio::spawn(async move {
            loop {
                match crate::server::accept_bounded::accept_bounded(
                    &listener,
                    &limiter,
                    CONNECTION_CAP_REFUSAL,
                    "NNTP",
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
                        let tls = tls.clone();

                        // Tracked, not detached: stop_server must abort this task too.
                        let task_owner = app_state.clone();
                        task_owner
                            .spawn_server_task(server_id, async move {
                                // Held for the life of the connection: releasing it here would
                                // cap the accept rate rather than the number of live
                                // connections.
                                let _permit = permit;
                                let secure = tls.is_some();
                                let stream: crate::server::p2p_support::Stream =
                                    if let Some(tls) = tls {
                                        let Ok(Ok(stream)) = tokio::time::timeout(
                                            Duration::from_secs(10),
                                            tls.accept(stream),
                                        )
                                        .await
                                        else {
                                            return;
                                        };
                                        Box::new(stream)
                                    } else {
                                        Box::new(stream)
                                    };
                                Self::handle_connection(
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
                                    secure,
                                    require_auth,
                                )
                                .await;
                            })
                            .await;
                    }
                    Err(e) => {
                        Log::new(Some(&status_tx))
                            .error(format!("Failed to accept NNTP connection: {}", e));
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

    /// Track one connection, register its peer handle, run the session, and clean up on
    /// every exit path.
    #[allow(clippy::too_many_arguments)]
    async fn handle_connection(
        stream: crate::server::p2p_support::Stream,
        connection_id: ConnectionId,
        remote_addr: SocketAddr,
        local_addr: SocketAddr,
        server_id: crate::state::ServerId,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        protocol: Arc<NntpProtocol>,
        deadlines: ReadDeadlines,
        secure: bool,
        require_auth: bool,
    ) {
        use crate::state::server::{
            ConnectionState as ServerConnectionState, ConnectionStatus, ProtocolConnectionInfo,
        };

        let (read_half, write_half) = tokio::io::split(stream);
        let write_half_arc = Arc::new(tokio::sync::Mutex::new(write_half));

        // Add connection to ServerInstance
        let now = crate::utils::clock::Instant::now();
        let conn_state = ServerConnectionState {
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
            write_half_arc.clone(),
            status_tx.clone(),
        );

        Self::run_session(
            BufReader::new(read_half),
            &write_half_arc,
            connection_id,
            server_id,
            &llm_client,
            &app_state,
            &status_tx,
            &protocol,
            deadlines,
            secure,
            require_auth,
        )
        .await;

        // Every exit path - EOF, read error, close_connection, refused greeting - lands here.
        app_state
            .remove_peer_handle(server_id, connection_id.as_u32())
            .await;
        app_state
            .remove_connection_from_server(server_id, connection_id)
            .await;
        let _ = status_tx.send("__UPDATE_UI__".to_string());
    }

    /// Write one buffer to the peer and count it.
    async fn write_counted<W>(
        write_half: &Arc<tokio::sync::Mutex<W>>,
        app_state: &AppState,
        server_id: crate::state::ServerId,
        connection_id: ConnectionId,
        data: &[u8],
        shutdown: bool,
    ) where
        W: tokio::io::AsyncWrite + Unpin,
    {
        {
            let mut write = write_half.lock().await;
            let _ = write.write_all(data).await;
            let _ = write.flush().await;
            if shutdown {
                let _ = write.shutdown().await;
            }
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
    }

    /// Answer pipelined commands with one model call, one response per command, in order.
    /// Returns whether the session should end.
    ///
    /// The answer is used only when it holds exactly one response per command. Anything else
    /// — one short, one extra — and every command is answered `403` instead, the same reply a
    /// single command gets when its answer is unusable: the client stays in step and is handed
    /// no article and no group it did not ask about. A backend failure answers each the way a
    /// single command's failure is answered (`403`, or `400` and close when overloaded).
    #[allow(clippy::too_many_arguments)]
    async fn answer_batch<W>(
        commands: &[String],
        write_half_arc: &Arc<tokio::sync::Mutex<W>>,
        connection_id: ConnectionId,
        server_id: crate::state::ServerId,
        llm_client: &OllamaClient,
        app_state: &Arc<AppState>,
        protocol: &Arc<NntpProtocol>,
        log: &Log<'_>,
    ) -> bool
    where
        W: tokio::io::AsyncWrite + Unpin,
    {
        let total = commands.len();
        let events: Vec<Event> = commands
            .iter()
            .enumerate()
            .map(|(i, command)| {
                let mut data = nntp_command_event_data(command);
                crate::server::command_batch::mark_pipelined(&mut data, i + 1, total);
                Event::new(&NNTP_COMMAND_RECEIVED_EVENT, data)
            })
            .collect();
        let (replies, close) = match crate::llm::action_helper::call_llm_batch(
            llm_client,
            app_state,
            server_id,
            Some(connection_id),
            &events,
            protocol.as_ref(),
        )
        .await
        {
            Ok(result) => {
                let answer = crate::server::command_batch::BatchReplies::from_result(&result);
                if answer.replies.len() == total {
                    log.info(format!(
                        "NNTP connection {} decision=model_answer: {} pipelined commands, one \
                         response each",
                        connection_id, total
                    ));
                    (answer.replies, answer.close)
                } else {
                    let reply = nntp_command_failure_line_static();
                    log.warn(format!(
                        "NNTP connection {} decision=fail_closed_batch_mismatch: {} responses \
                         for {} pipelined commands; replying {} to each",
                        connection_id,
                        answer.replies.len(),
                        total,
                        reply.trim_end()
                    ));
                    (vec![reply.into_bytes(); total], answer.close)
                }
            }
            Err(e) => {
                let (reply, close) = nntp_command_failure_line(&e);
                log.warn(format!(
                    "NNTP LLM error on connection {} for {} pipelined commands \
                     (decision=fail_closed_llm_error, replying: {}): {}",
                    connection_id,
                    total,
                    reply.trim_end(),
                    e
                ));
                (vec![reply.into_bytes(); total], close)
            }
        };
        let last = replies.len().saturating_sub(1);
        for (i, data) in replies.iter().enumerate() {
            Self::write_counted(
                write_half_arc,
                app_state,
                server_id,
                connection_id,
                data,
                close && i == last,
            )
            .await;
        }
        close
    }

    #[allow(clippy::too_many_arguments)]
    async fn run_session<R, W>(
        mut reader: BufReader<R>,
        write_half_arc: &Arc<tokio::sync::Mutex<W>>,
        connection_id: ConnectionId,
        server_id: crate::state::ServerId,
        llm_client: &OllamaClient,
        app_state: &Arc<AppState>,
        status_tx: &mpsc::UnboundedSender<String>,
        protocol: &Arc<NntpProtocol>,
        deadlines: ReadDeadlines,
        secure: bool,
        require_auth: bool,
    ) where
        R: tokio::io::AsyncRead + Unpin,
        W: tokio::io::AsyncWrite + Unpin,
    {
        let log = Log::new(Some(status_tx));

        // Send initial greeting
        log.debug(format!(
            "NNTP sending greeting to connection {}",
            connection_id
        ));

        let greeting_event = Event::new(
            &NNTP_COMMAND_RECEIVED_EVENT,
            nntp_command_event_data("GREETING"),
        );
        // The greeting's status code (200 or 201), which MODE READER reports again. Every
        // path that does not set it returns before the command loop.
        let greeting_code: Option<String>;
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
                for message in &execution_result.messages {
                    log.info(message);
                }

                let plan = SessionWrite::collect(&execution_result, &[]);
                plan.log_dropped(&log, connection_id, "GREETING");
                greeting_code = plan
                    .outputs
                    .first()
                    .and_then(|data| data.get(..3))
                    .map(|code| String::from_utf8_lossy(code).to_string());

                for data in &plan.outputs {
                    Self::write_counted(
                        write_half_arc,
                        app_state,
                        server_id,
                        connection_id,
                        data,
                        false,
                    )
                    .await;

                    // Sent summary + payload are FileOnly.
                    let response = String::from_utf8_lossy(data);
                    let preview = crate::utils::truncate_for_log(&response, 100);
                    log.debug(format!(
                        "NNTP sent {} bytes on connection {} (decision={}): {}",
                        data.len(),
                        connection_id,
                        nntp_model_decision(data),
                        preview.trim()
                    ));
                    log.trace(format!("NNTP sent (text): {:?}", response.trim()));
                }

                // A greeting is mandatory: RFC 3977 5.1 has the server speak
                // first, and a client reads that line before it sends
                // anything. So an answer with no greeting in it is not
                // "say nothing", it is a session that can never start - the
                // client blocks forever on a line that is not coming. The
                // Err branch below already answers 400; this covers the
                // model (or a static/manual handler) returning zero actions,
                // or actions that all failed to execute, which reaches here
                // as Ok with nothing to write. An explicit wait_for_more or
                // close_connection is a deliberate choice and is left alone.
                if plan.wrote_nothing() && !plan.silence_is_deliberate {
                    let decision = if execution_result.failures.is_empty() {
                        "fail_closed_no_actions"
                    } else {
                        "fail_closed_action_error"
                    };
                    let line = nntp_greeting_failure_line_static();
                    log.warn(format!(
                        "NNTP greeting produced no response on connection {} \
                         (decision={}, refused: {}): {}",
                        connection_id,
                        decision,
                        line.trim_end(),
                        nntp_failure_detail(&execution_result)
                    ));
                    Self::write_counted(
                        write_half_arc,
                        app_state,
                        server_id,
                        connection_id,
                        line.as_bytes(),
                        true,
                    )
                    .await;
                    return;
                }

                if plan.close {
                    return;
                }
            }
            Err(e) => {
                // RFC 3977 5.1: the initial greeting may be `400 service
                // temporarily unavailable`, after which the server closes.
                // Writing nothing left the client blocked reading a
                // greeting line that was never coming.
                let line = nntp_greeting_failure_line(&e);
                log.warn(format!(
                    "NNTP greeting LLM error on connection {} \
                     (decision=fail_closed_llm_error, refused: {}): {}",
                    connection_id,
                    line.trim_end(),
                    e
                ));
                Self::write_counted(
                    write_half_arc,
                    app_state,
                    server_id,
                    connection_id,
                    line.as_bytes(),
                    true,
                )
                .await;
                return;
            }
        }

        // Read commands from client.
        //
        // Bounded: `read_line` would grow its `String` until it found a `\n`, so a peer that
        // connects and never sends one was a one-connection OOM before any model call.
        let mut extensions = extensions::State {
            secure,
            require_auth,
            authenticated: !require_auth,
            posting_allowed: greeting_code.as_deref() == Some("200"),
            ..Default::default()
        };
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
            let framed = tokio::time::timeout(
                read_timeout,
                crate::utils::line_reader::read_bounded_line(&mut reader, MAX_COMMAND_BYTES),
            )
            .await;
            let (read, n) = match framed {
                Err(_) => {
                    log.info(format!(
                        "NNTP connection {} sent nothing for {}s; closing idle connection",
                        connection_id,
                        read_timeout.as_secs()
                    ));
                    break;
                }
                Ok(Ok(v)) => v,
                Ok(Err(_)) => break,
            };
            answered_one = true;
            let line = match read {
                crate::utils::line_reader::BoundedLine::Line(line) => line,
                crate::utils::line_reader::BoundedLine::Eof => break,
                crate::utils::line_reader::BoundedLine::TooLong => {
                    // RFC 3977 §3.1 caps the command line at 512 octets, and 501 is the
                    // syntax-error response. There is no resynchronisation point — the peer
                    // is mid-line — so answer and close.
                    log.error(format!(
                        "NNTP connection {} sent a command line over {} bytes with no newline; \
                         decision=fail_closed_oversized_command",
                        connection_id, MAX_COMMAND_BYTES
                    ));
                    Self::write_counted(
                        write_half_arc,
                        app_state,
                        server_id,
                        connection_id,
                        b"501 command line too long\r\n",
                        true,
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

            // Summary + payload FileOnly: the nntp_command_received
            // event template surfaces the command to the TUI.
            let safe_line = if line.to_ascii_uppercase().starts_with("AUTHINFO PASS ") {
                "AUTHINFO PASS [redacted]"
            } else {
                &line
            };
            let preview = crate::utils::truncate_for_log(safe_line, 100);
            log.debug(format!(
                "NNTP received {} bytes on connection {}: {}",
                n,
                connection_id,
                preview.trim()
            ));
            log.trace(format!("NNTP data (text): {:?}", safe_line.trim()));

            let extension_ctx = extensions::ContextRefs {
                llm: llm_client,
                state: app_state,
                server: server_id,
                peer: connection_id,
                protocol: protocol.as_ref(),
            };
            match extensions::handle(
                &mut reader,
                write_half_arc,
                line.trim_end_matches(['\r', '\n']),
                &mut extensions,
                &extension_ctx,
            )
            .await
            {
                Ok(true) => continue,
                Ok(false) => {}
                Err(e) => {
                    log.warn(format!("NNTP extension ended: {e}"));
                    break;
                }
            }
            if line.trim().eq_ignore_ascii_case("CAPABILITIES") {
                let mut reply = String::from_utf8_lossy(CAPABILITIES_REPLY).to_string();
                if !extensions.posting_allowed {
                    reply = reply.replace("POST\r\n", "");
                }
                if secure {
                    reply = reply.replace(".\r\n", "AUTHINFO USER\r\n.\r\n");
                }
                Self::write_counted(
                    write_half_arc,
                    app_state,
                    server_id,
                    connection_id,
                    reply.as_bytes(),
                    false,
                )
                .await;
                continue;
            }
            if let Some(reply) = netget_answer(line.trim(), greeting_code.as_deref()) {
                log.info(format!(
                    "NNTP {} on connection {} decision=netget_answer: answered by NetGet",
                    crate::utils::truncate_for_log(line.trim(), 60),
                    connection_id
                ));
                Self::write_counted(
                    write_half_arc,
                    app_state,
                    server_id,
                    connection_id,
                    reply,
                    false,
                )
                .await;
                continue;
            }

            // Pipelined commands already waiting behind this one are answered with it in one
            // model call when the instance batches; see `nntp_batch_role`. A session that
            // must still authenticate batches nothing: its commands are refused one by one.
            let authenticated = !extensions.require_auth || extensions.authenticated;
            if let (true, Some(ends)) = (authenticated, nntp_batch_role(line.trim())) {
                let mut commands = vec![line.trim().to_string()];
                if !ends
                    && crate::server::command_batch::one_model_call_answers(
                        app_state,
                        server_id,
                        &[NNTP_COMMAND_RECEIVED_EVENT.id.as_str()],
                    )
                    .await
                {
                    use tokio::io::AsyncBufReadExt;
                    while commands.len() < crate::protocol::metadata::MAX_BATCH_EVENTS {
                        let Some((next, len)) = crate::server::command_batch::peek_ready_line(
                            &mut reader,
                            MAX_COMMAND_BYTES,
                        )
                        .await
                        else {
                            break;
                        };
                        let next = next.trim().to_string();
                        let Some(ends) = nntp_batch_role(&next) else {
                            break;
                        };
                        reader.consume(len);
                        app_state
                            .update_connection_stats(
                                server_id,
                                connection_id,
                                Some(len as u64),
                                None,
                                Some(1),
                                None,
                            )
                            .await;
                        commands.push(next);
                        if ends {
                            break;
                        }
                    }
                }
                if commands.len() > 1 {
                    if Self::answer_batch(
                        &commands,
                        write_half_arc,
                        connection_id,
                        server_id,
                        llm_client,
                        app_state,
                        protocol,
                        &log,
                    )
                    .await
                    {
                        break;
                    }
                    continue;
                }
            }

            let event = Event::new(
                &NNTP_COMMAND_RECEIVED_EVENT,
                nntp_command_event_data(line.trim()),
            );

            log.debug(format!("NNTP calling LLM for connection {}", connection_id));

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
                    for message in &execution_result.messages {
                        log.info(message);
                    }

                    log.debug(format!(
                        "NNTP got {} protocol results",
                        execution_result.protocol_results.len()
                    ));

                    let plan = SessionWrite::collect(
                        &execution_result,
                        nntp_preferred_actions(line.trim()),
                    );
                    plan.log_dropped(&log, connection_id, line.trim());

                    // NNTP is one response line per command, so writing
                    // nothing desynchronises the client for the rest of the
                    // session - it waits forever for a line that will never
                    // come, and if it ever gives up and sends another
                    // command it reads the next reply as the answer to this
                    // one. Two Ok cases land here with nothing to write and
                    // both get 403: actions that failed to execute (a
                    // missing required field, say) and an answer with no
                    // actions in it at all - an empty model reply, a manual
                    // "answer with nothing", a zero-action static handler.
                    // The empty case is the worse of the two, not the
                    // exempt one. A deliberate wait_for_more or
                    // close_connection is left alone.
                    if plan.wrote_nothing() && !plan.silence_is_deliberate {
                        let decision = if execution_result.failures.is_empty() {
                            "fail_closed_no_actions"
                        } else {
                            "fail_closed_action_error"
                        };
                        // The peer gets a category; the detail goes to the
                        // log. Action names and executor error strings are
                        // netget's internals and are not the peer's to read.
                        let reply = nntp_command_failure_line_static();
                        log.warn(format!(
                            "NNTP produced no response on connection {} \
                             (decision={}, replying: {}): {}",
                            connection_id,
                            decision,
                            reply.trim_end(),
                            nntp_failure_detail(&execution_result)
                        ));
                        Self::write_counted(
                            write_half_arc,
                            app_state,
                            server_id,
                            connection_id,
                            reply.as_bytes(),
                            false,
                        )
                        .await;
                    }

                    for data in &plan.outputs {
                        Self::write_counted(
                            write_half_arc,
                            app_state,
                            server_id,
                            connection_id,
                            data,
                            false,
                        )
                        .await;

                        // Sent summary + payload are FileOnly.
                        let response = String::from_utf8_lossy(data);
                        let preview = crate::utils::truncate_for_log(&response, 100);
                        log.debug(format!(
                            "NNTP sent {} bytes on connection {} (decision={}): {}",
                            data.len(),
                            connection_id,
                            nntp_model_decision(data),
                            preview.trim()
                        ));
                        log.trace(format!("NNTP sent (text): {:?}", response.trim()));
                    }

                    if plan.close {
                        break;
                    }
                }
                Err(e) => {
                    // NNTP is strictly one response line per command, so
                    // silence desynchronises the client for the rest of
                    // the session. 403 is RFC 3977's "internal fault or
                    // problem preventing action being taken" and is a
                    // refusal on every command NNTP has, AUTHINFO
                    // included - there is no way for this path to
                    // authenticate anyone or hand back an article.
                    let (reply, close) = nntp_command_failure_line(&e);
                    log.warn(format!(
                        "NNTP LLM error on connection {} \
                         (decision=fail_closed_llm_error, replying: {}): {}",
                        connection_id,
                        reply.trim_end(),
                        e
                    ));
                    Self::write_counted(
                        write_half_arc,
                        app_state,
                        server_id,
                        connection_id,
                        reply.as_bytes(),
                        close,
                    )
                    .await;
                    if close {
                        break;
                    }
                }
            }
        }

        log.info(format!("NNTP connection {} closed", connection_id));
    }
}

/// NetGet's answer to `CAPABILITIES` (RFC 3977 5.2).
///
/// Answered here rather than by the model because it has one correct form: what this server
/// has actions for - reading (`READER`: GROUP, ARTICLE/HEAD/BODY), `LIST ACTIVE`
/// (`send_nntp_list` renders the active format) and `OVER` (`send_nntp_overview`). No `POST`,
/// no `IHAVE`, no `AUTHINFO`: none is implemented. Asked, a small model answered CAPABILITIES
/// with the 200 greeting, and nntplib - which sends CAPABILITIES from its constructor - raised
/// before the command under test was ever sent.
pub const CAPABILITIES_REPLY: &[u8] =
    b"101 Capability list:\r\nVERSION 2\r\nREADER\r\nLIST ACTIVE\r\nOVER\r\nPOST\r\nIHAVE\r\nSTREAMING\r\n.\r\n";

/// NetGet's answer to `MODE READER` (RFC 3977 5.3): the greeting's own status again, which is
/// what the command reports. `201` (posting prohibited) unless the greeting said `200`.
pub fn mode_reader_reply(greeting_code: Option<&str>) -> &'static [u8] {
    if greeting_code == Some("200") {
        b"200 Reader mode, posting allowed\r\n"
    } else {
        b"201 Reader mode, posting prohibited\r\n"
    }
}

/// Which of the connection-mechanics commands NetGet answers itself, if `command` is one.
pub fn netget_answer(command: &str, greeting_code: Option<&str>) -> Option<&'static [u8]> {
    let upper = command.trim().to_ascii_uppercase();
    let mut words = upper.split_whitespace();
    match (words.next(), words.next(), words.next()) {
        (Some("CAPABILITIES"), _, None) => Some(CAPABILITIES_REPLY),
        (Some("MODE"), Some("READER"), None) => Some(mode_reader_reply(greeting_code)),
        _ => None,
    }
}

/// Whether an NNTP command may be answered as part of a batch, and whether it ends one.
///
/// RFC 3977 §3.5 lets a client pipeline any command. `None` for those this server answers
/// on its own: `CAPABILITIES` and `MODE` (NetGet answers them), `AUTHINFO` (credentials, and
/// it changes what later commands are allowed), `POST`/`IHAVE`/`TAKETHIS`/`CHECK` (an article
/// transfer the server reads itself), `STARTTLS`, and anything unknown. `Some(true)` for
/// `QUIT`; `Some(false)` for the reading commands, which carry nothing beyond their own line.
pub fn nntp_batch_role(command: &str) -> Option<bool> {
    match command
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_ascii_uppercase()
        .as_str()
    {
        "GROUP" | "LISTGROUP" | "LIST" | "ARTICLE" | "HEAD" | "BODY" | "STAT" | "NEXT" | "LAST"
        | "OVER" | "XOVER" | "HDR" | "XHDR" | "NEWGROUPS" | "NEWNEWS" | "DATE" | "HELP" => {
            Some(false)
        }
        "QUIT" => Some(true),
        _ => None,
    }
}

/// The actions whose reply wins when a batch answers one NNTP command with several: the one
/// the command's `answer_with` names when only one fits. See `ExecutionResult::chosen_reply`.
pub fn nntp_preferred_actions(command: &str) -> &'static [&'static str] {
    let mut words = command.split_whitespace();
    let verb = words.next().unwrap_or("").to_ascii_uppercase();
    let arg = words.next().map(str::to_ascii_uppercase);
    match (verb.as_str(), arg.as_deref()) {
        ("GROUP", _) => &["send_nntp_group"],
        ("LIST", None) | ("LIST", Some("ACTIVE")) => &["send_nntp_list"],
        ("ARTICLE" | "HEAD" | "BODY", _) => &["send_nntp_article"],
        ("OVER" | "XOVER", _) => &["send_nntp_overview"],
        _ => &[],
    }
}

/// The event data for one NNTP line: the line itself, plus what NetGet can tell from it.
///
/// `answer_with` names the action and reply code this particular command takes. The
/// real-model eval found a small model answering CAPABILITIES with the 200 greeting and an
/// unknown group with `501` (syntax error) where RFC 3977 says `411`; a per-request hint is
/// followed far better than the general description. `group` and `article` are the command's
/// arguments, split out.
pub fn nntp_command_event_data(command: &str) -> serde_json::Value {
    let mut data = serde_json::json!({ "command": command });
    if command == "GREETING" {
        data["answer_with"] = "send_nntp_response with code 200 (posting allowed) or 201 \
                               (posting prohibited) and the server's banner as text"
            .into();
        return data;
    }
    let mut words = command.split_whitespace();
    let verb = words.next().unwrap_or("").to_ascii_uppercase();
    let arg = words.next();
    let answer = match (verb.as_str(), arg) {
        ("GROUP", Some(group)) => {
            data["group"] = group.into();
            format!(
                "send_nntp_group with name {group} and its count, low and high article numbers \
                 if the group {group} exists; if it does not, send_nntp_response with code 411 \
                 and text \"No such newsgroup\""
            )
        }
        ("LIST", None) => "send_nntp_list with every group the server carries (name, high, \
                           low, status \"y\")"
            .to_string(),
        ("LIST", Some(kind)) if kind.eq_ignore_ascii_case("ACTIVE") => {
            "send_nntp_list with every group the server carries (name, high, low, status \"y\")"
                .to_string()
        }
        ("ARTICLE" | "HEAD" | "BODY", article) => {
            if let Some(article) = article {
                data["article"] = article.into();
            }
            let code = match verb.as_str() {
                "ARTICLE" => 220,
                "HEAD" => 221,
                _ => 222,
            };
            format!(
                "send_nntp_article with code {code}; send_nntp_response with code 423 if there \
                 is no such article in the group, 430 if there is no article with that \
                 message-id, or 412 if no group has been selected"
            )
        }
        ("OVER" | "XOVER", _) => "send_nntp_overview with one entry per article in the range; \
                                   send_nntp_response with code 412 if no group has been selected"
            .to_string(),
        ("QUIT", _) => "send_nntp_response with code 205, then close_connection".to_string(),
        _ => return data,
    };
    data["answer_with"] = answer.into();
    data
}

/// What a batch of action results means for the wire.
///
/// Collected up front so the "nothing to say" case can be recognised *before* anything is
/// written, and so a nested `Multiple` still counts as a response — matching on the top-level
/// variants alone would read `Multiple(vec![Output(..)])` as silence and answer 403 over a
/// perfectly good reply.
#[derive(Default)]
struct SessionWrite {
    /// The one reply to put on the wire: the one produced by the action `answer_with` names,
    /// else the first the batch produced (`ExecutionResult::chosen_reply`). NNTP has no
    /// pipelining here, so a second reply is read as the answer to the client's *next*
    /// command and every reply after it is one step late.
    outputs: Vec<Vec<u8>>,
    /// Replies the batch carried past the first, which are not written.
    dropped: usize,
    /// The session should end after those bytes.
    close: bool,
    /// The answer contained an explicit `wait_for_more` or `close_connection`, so writing
    /// nothing is a choice rather than a hole.
    silence_is_deliberate: bool,
}

impl SessionWrite {
    fn collect(
        result: &crate::llm::actions::executor::ExecutionResult,
        preferred: &[&str],
    ) -> Self {
        let chosen = result.chosen_reply(preferred);
        let mut plan = Self::default();
        for (index, action_result) in result.protocol_results.iter().enumerate() {
            plan.absorb(std::slice::from_ref(action_result), Some(index) == chosen);
        }
        plan
    }

    fn absorb(&mut self, results: &[ActionResult], is_the_reply: bool) {
        for result in results {
            match result {
                ActionResult::Output(_) if !is_the_reply || !self.outputs.is_empty() => {
                    self.dropped += 1
                }
                ActionResult::Output(data) => self.outputs.push(data.clone()),
                ActionResult::CloseConnection => {
                    self.close = true;
                    self.silence_is_deliberate = true;
                }
                ActionResult::WaitForMore => self.silence_is_deliberate = true,
                ActionResult::Multiple(inner) => self.absorb(inner, is_the_reply),
                _ => {}
            }
        }
    }

    fn wrote_nothing(&self) -> bool {
        self.outputs.is_empty()
    }

    fn log_dropped(&self, log: &Log, connection_id: ConnectionId, command: &str) {
        if self.dropped > 0 {
            log.warn(format!(
                "NNTP {} on connection {} decision=duplicate_response_dropped: {} extra \
                 repl{} not sent; one command gets one reply",
                crate::utils::truncate_for_log(command, 60),
                connection_id,
                self.dropped,
                if self.dropped == 1 { "y" } else { "ies" }
            ));
        }
    }
}

/// Log tag for a response the model itself produced: a 4xx/5xx status line is the model
/// refusing, anything else is the model answering. Keeping the two apart in the log is what
/// makes a real denial distinguishable from netget's own fail-closed replies, which are
/// tagged `decision=fail_closed_*`.
fn nntp_model_decision(data: &[u8]) -> &'static str {
    match data.first() {
        Some(b'4') | Some(b'5') => "model_reject",
        _ => "model_answer",
    }
}

/// Everything about a failed answer that belongs in the log and nowhere else.
fn nntp_failure_detail(result: &crate::llm::actions::executor::ExecutionResult) -> String {
    if result.failures.is_empty() {
        "the answer contained no actions".to_string()
    } else {
        result
            .failures
            .iter()
            .map(|f| format!("{}: {}", f.action, f.error))
            .collect::<Vec<_>>()
            .join("; ")
    }
}

/// The greeting to write when the answer contains no greeting at all.
///
/// There is no error to classify here — nothing failed, the answer was simply empty — so this
/// is the flat `Unavailable` category. 400 is the same legal failure greeting the LLM-error
/// path uses, and the server closes after it.
fn nntp_greeting_failure_line_static() -> String {
    format!(
        "400 {}\r\n",
        crate::utils::WireFailure::Unavailable.prefixed_text()
    )
}

/// The command reply to write when the answer contains nothing to send.
///
/// 403 leaves the session usable, which is right for a per-command hole. The free text is a
/// fixed category: action names and executor error strings name netget's internals and never
/// reach the peer.
fn nntp_command_failure_line_static() -> String {
    format!(
        "403 {}\r\n",
        crate::utils::WireFailure::Unavailable.prefixed_text()
    )
}

/// The greeting to write when the LLM backend cannot produce one.
///
/// RFC 3977 5.1 defines exactly two failure greetings: 400 (temporarily unavailable) and 502
/// (permanently unavailable). Neither can be mistaken for the 200/201 that means "ready", so
/// a client can never read this as a usable session.
fn nntp_greeting_failure_line(err: &anyhow::Error) -> String {
    // The free text is a category, never the error itself (`crate::utils::wire_failure`),
    // which also makes it impossible for a newline in an error to forge a second response
    // line and desynchronise the session.
    format!(
        "400 {}\r\n",
        crate::utils::WireFailure::classify(err).prefixed_text()
    )
}

/// The response line for a command the LLM backend failed to answer, and whether to close.
///
/// 403 is RFC 3977's generic "internal fault or problem preventing action being taken" and
/// leaves the session usable, which is what a one-off failure deserves. Capacity exhaustion
/// gets 400 instead - "service discontinued", which per RFC 3977 3.1 the server follows by
/// closing the connection - because telling a client to come back later is more useful than
/// letting it hammer a backend that is already saturated.
fn nntp_command_failure_line(err: &anyhow::Error) -> (String, bool) {
    let failure = crate::utils::WireFailure::classify(err);
    let text = failure.prefixed_text();
    if failure.is_overloaded() {
        (format!("400 {text}\r\n"), true)
    } else {
        (format!("403 {text}\r\n"), false)
    }
}
