//! IRC server implementation
pub mod actions;
pub(crate) mod wire;

use crate::server::connection::ConnectionId;
use anyhow::Result;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::mpsc;
use tracing::{debug, error, info, trace};

use crate::llm::action_helper::call_llm_batch;
use crate::llm::actions::protocol_trait::ActionResult;
use crate::llm::ollama_client::OllamaClient;
use crate::protocol::Event;
use crate::server::irc::wire::{read_irc_line, IrcLine, MAX_IRC_READ_LINE};
use crate::server::IrcProtocol;
use crate::state::app_state::AppState;
use actions::IRC_MESSAGE_RECEIVED_EVENT;

/// How long to wait for the first message from a peer that has only connected.
///
/// IRC is client-speaks-first and the first thing a client sends is its registration — `NICK`
/// and `USER`, or `CAP LS` before them — inside its own dial path. Every real ircd bounds
/// exactly this: InspIRCd's connect timeout and charybdis/ratbox's registration timeout both
/// default to 30 seconds, so a minute is twice the strictest thing a real client is already
/// built to satisfy, and a peer that has not registered has authenticated nothing.
const FIRST_MESSAGE_READ_TIMEOUT: Duration = Duration::from_secs(60);

/// How long to wait for a *further* message once the peer has sent one.
///
/// Half an hour, because IRC is long-lived by nature: a registered client may sit in a channel
/// for a whole working day without typing, and closing that is breaking the protocol's own use
/// rather than defending it. The number is still an order of magnitude more generous than any
/// ircd's own liveness bound — InspIRCd and UnrealIRCd ping an idle client every 120 seconds
/// and drop it after roughly twice that — so nothing a real client does comes near it, while an
/// unauthenticated socket still cannot be held forever.
///
/// The LLM round-trip and a `manual` rule parking a message for a human
/// (`src/state/intercepts.rs`, 300s by default) both happen after a line has already been read,
/// so they sit outside this deadline by construction.
const IDLE_BETWEEN_MESSAGES_TIMEOUT: Duration = Duration::from_secs(1800);

/// Concurrent connections this server admits.
///
/// [`crate::server::accept_bounded::DEFAULT_MAX_CONNECTIONS`]. Each connection may buffer up to
/// [`MAX_IRC_READ_LINE`], so this is the multiplier that turns that per-connection bound into a
/// total one.
const MAX_CONNECTIONS: usize = crate::server::accept_bounded::DEFAULT_MAX_CONNECTIONS;

/// What a peer over [`MAX_CONNECTIONS`] is told before the socket closes.
///
/// `ERROR :Closing Link:` is IRC's own way of ending a link before registration, and it is
/// verbatim what a real ircd sends when it is at its connection limit. This file already uses
/// the same form for an over-long line. Fixed text, so there is no placeholder an internal
/// error could reach.
const CONNECTION_CAP_REFUSAL: &[u8] = b"ERROR :Closing Link: too many connections\r\n";

/// IRC server that forwards messages to LLM
pub struct IrcServer;

impl IrcServer {
    /// Spawn IRC server with integrated LLM actions
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
        info!("IRC server (action-based) listening on {}", local_addr);
        let _ = status_tx.send(format!("IRC server listening on {}", local_addr));

        let protocol = Arc::new(IrcProtocol::new());

        let task_registrar = app_state.clone();
        let limiter = crate::server::accept_bounded::ConnectionLimiter::new(MAX_CONNECTIONS);
        let accept_handle = tokio::spawn(async move {
            loop {
                match crate::server::accept_bounded::accept_bounded(
                    &listener,
                    &limiter,
                    CONNECTION_CAP_REFUSAL,
                    "IRC",
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

                            // Peer messaging: the dashboard's "message this peer" /
                            // "disconnect this peer" inject actions into THIS connection
                            // through the same executor the LLM path uses. Registered
                            // before the first read, so a manual `*` rule parking the
                            // registration exchange still leaves the operator able to
                            // reach the connection.
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

                            let mut reader = BufReader::new(read_half);
                            let mut answered_one = false;

                            loop {
                                // The deadline wraps this read and nothing else: the model
                                // round-trip below, and a `manual` rule parking a message for
                                // a human, happen only after a line has been read.
                                let read_timeout = if answered_one {
                                    IDLE_BETWEEN_MESSAGES_TIMEOUT
                                } else {
                                    FIRST_MESSAGE_READ_TIMEOUT
                                };
                                // Bounded: `read_line` grows its buffer until it finds a
                                // newline, so an unauthenticated peer that connects and
                                // streams bytes with no `\n` was a one-connection OOM. IRC
                                // messages are 512 bytes by RFC 1459 and 8704 with IRCv3
                                // tags, so nothing real is refused by the ceiling.
                                let framed = tokio::time::timeout(
                                    read_timeout,
                                    read_irc_line(&mut reader, MAX_IRC_READ_LINE),
                                )
                                .await;
                                let (read, n) = match framed {
                                    Err(_) => {
                                        info!(
                                            "IRC connection {} from {} sent nothing for {}s; \
                                             closing idle connection",
                                            connection_id,
                                            remote_addr,
                                            read_timeout.as_secs()
                                        );
                                        break;
                                    }
                                    Ok(Ok(v)) => v,
                                    Ok(Err(e)) => {
                                        debug!(
                                            "IRC read error on connection {}: {}",
                                            connection_id, e
                                        );
                                        break;
                                    }
                                };
                                answered_one = true;
                                let line = match read {
                                    IrcLine::Line(line) => line,
                                    IrcLine::Eof => break,
                                    IrcLine::TooLong => {
                                        // No resynchronisation point: the peer is mid-line
                                        // and its prefix is gone. ERROR + close is IRC's own
                                        // way of ending a link, and it names the limit so a
                                        // real client's operator can see what happened.
                                        // Refused by the protocol before any model call, so
                                        // it is neither the model's answer nor a backend
                                        // failure and carries its own token.
                                        error!(
                                            "IRC connection {} sent {} bytes with no newline \
                                             (limit {}), closing decision=refused_body_too_large",
                                            connection_id, n, MAX_IRC_READ_LINE
                                        );
                                        let _ = status_clone.send(format!(
                                            "[ERROR] IRC connection {} exceeded {} bytes with no \
                                             newline decision=refused_body_too_large",
                                            connection_id, MAX_IRC_READ_LINE
                                        ));
                                        let reply = format!(
                                            "ERROR :Closing link: message exceeds {MAX_IRC_READ_LINE} bytes\r\n"
                                        );
                                        let mut write = write_half_arc.lock().await;
                                        let _ = write.write_all(reply.as_bytes()).await;
                                        let _ = write.flush().await;
                                        let _ = write.shutdown().await;
                                        break;
                                    }
                                };
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

                                // DEBUG: Log summary with text preview.
                                // `truncate_for_log` cuts on a char boundary. Slicing with
                                // `&line[..100]` panicked here on any IRC line longer than 100
                                // bytes whose 100th byte fell inside a multi-byte character -
                                // i.e. on ordinary non-ASCII chat text - and a panic in this
                                // task is silent while the server still reads as Running.
                                let preview = crate::utils::truncate_for_log(&line, 100);
                                debug!(
                                    "IRC received {} bytes on connection {}: {}",
                                    n,
                                    connection_id,
                                    preview.trim()
                                );
                                let _ = status_clone.send(format!(
                                    "[DEBUG] IRC received {} bytes on connection {}: {}",
                                    n,
                                    connection_id,
                                    preview.trim()
                                ));

                                // TRACE: Log full text payload
                                trace!("IRC data (text): {:?}", line.trim());
                                let _ = status_clone
                                    .send(format!("[TRACE] IRC data (text): {:?}", line.trim()));

                                // With batching on, every other complete line the peer has
                                // already sent — typically what it sent while the model was
                                // answering the previous one, or a NICK and USER written
                                // together — is answered in the same call. Read without
                                // waiting, so batching never delays a reply.
                                let batching = state_clone
                                    .server_conversation_settings(server_id)
                                    .await
                                    .is_some_and(|(_, batching)| batching);
                                let mut lines = vec![line];
                                if batching {
                                    for (more, consumed) in lines_already_here(
                                        &mut reader,
                                        crate::protocol::metadata::MAX_BATCH_EVENTS - 1,
                                    )
                                    .await
                                    {
                                        state_clone
                                            .update_connection_stats(
                                                server_id,
                                                connection_id,
                                                Some(consumed as u64),
                                                None,
                                                Some(1),
                                                None,
                                            )
                                            .await;
                                        trace!("IRC data (text, batched): {:?}", more.trim());
                                        lines.push(more);
                                    }
                                }
                                let events: Vec<Event> = lines
                                    .iter()
                                    .map(|l| {
                                        Event::new(
                                            &IRC_MESSAGE_RECEIVED_EVENT,
                                            serde_json::json!({ "message": l.trim() }),
                                        )
                                    })
                                    .collect();
                                // The newest line is the batch's trigger, and the one the
                                // decision line and a failure numeric name.
                                let line = lines.pop().unwrap_or_default();

                                debug!(
                                    "IRC calling LLM for connection {} ({} line(s))",
                                    connection_id,
                                    events.len()
                                );
                                let _ = status_clone.send(format!(
                                    "[DEBUG] IRC calling LLM for connection {} ({} line(s))",
                                    connection_id,
                                    events.len()
                                ));

                                match call_llm_batch(
                                    &llm_clone,
                                    &state_clone,
                                    server_id,
                                    Some(connection_id),
                                    &events,
                                    protocol_clone.as_ref(),
                                )
                                .await
                                {
                                    Ok(execution_result) => {
                                        for message in &execution_result.messages {
                                            info!("{}", message);
                                            let _ =
                                                status_clone.send(format!("[INFO] {}", message));
                                        }

                                        debug!(
                                            "IRC got {} protocol results",
                                            execution_result.protocol_results.len()
                                        );
                                        let _ = status_clone.send(format!(
                                            "[DEBUG] IRC got {} protocol results",
                                            execution_result.protocol_results.len()
                                        ));

                                        // Which terminal outcome this answer was. Computed
                                        // here rather than inferred from the log later,
                                        // because "the model sent a numeric", "the model
                                        // asked to hang up" and "the model said nothing" are
                                        // three different things that all end with the server
                                        // going back to reading.
                                        let mut wrote_output = false;
                                        let mut asked_to_close = false;
                                        let failures = execution_result.failures.len();
                                        for protocol_result in execution_result.protocol_results {
                                            match protocol_result {
                                                ActionResult::Output(data) => {
                                                    wrote_output = true;
                                                    let response = String::from_utf8_lossy(&data);
                                                    let formatted = if response.ends_with("\r\n") {
                                                        response.to_string()
                                                    } else if response.ends_with('\n') {
                                                        format!("{response}\r")
                                                    } else {
                                                        format!("{response}\r\n")
                                                    };
                                                    {
                                                        let mut write = write_half_arc.lock().await;
                                                        let _ = write
                                                            .write_all(formatted.as_bytes())
                                                            .await;
                                                        let _ = write.flush().await;
                                                    }
                                                    state_clone
                                                        .update_connection_stats(
                                                            server_id,
                                                            connection_id,
                                                            None,
                                                            Some(formatted.len() as u64),
                                                            None,
                                                            Some(1),
                                                        )
                                                        .await;

                                                    // Same char-boundary hazard as the inbound
                                                    // preview above, but on model output.
                                                    let preview = crate::utils::truncate_for_log(
                                                        &formatted, 100,
                                                    );
                                                    debug!(
                                                        "IRC sent {} bytes on connection {}: {}",
                                                        formatted.len(),
                                                        connection_id,
                                                        preview.trim()
                                                    );
                                                    let _ = status_clone.send(format!("[DEBUG] IRC sent {} bytes on connection {}: {}", formatted.len(), connection_id, preview.trim()));

                                                    // TRACE: Log full text payload
                                                    trace!(
                                                        "IRC sent (text): {:?}",
                                                        formatted.trim()
                                                    );
                                                    let _ = status_clone.send(format!(
                                                        "[TRACE] IRC sent (text): {:?}",
                                                        formatted.trim()
                                                    ));
                                                }
                                                ActionResult::CloseConnection => {
                                                    asked_to_close = true;
                                                    break;
                                                }
                                                _ => {}
                                            }
                                        }

                                        // One decision line per request. `model_reject` is the
                                        // model choosing to end the link rather than answer;
                                        // `model_silent` is an answer with nothing usable in
                                        // it; `fail_closed_bad_action` is an answer the
                                        // executor refused. All three leave the peer with no
                                        // reply, so the log is the only place they differ.
                                        let decision = if wrote_output {
                                            "model_answer"
                                        } else if asked_to_close {
                                            "model_reject"
                                        } else if failures == 0 {
                                            "model_silent"
                                        } else {
                                            "fail_closed_bad_action"
                                        };
                                        let summary = format!(
                                            "IRC {} on connection {} from {} decision={} ({} failed action(s))",
                                            irc_command_token(&line),
                                            connection_id,
                                            remote_addr,
                                            decision,
                                            failures
                                        );
                                        if decision == "fail_closed_bad_action" {
                                            error!("{}", summary);
                                            let _ =
                                                status_clone.send(format!("[ERROR] {}", summary));
                                        } else if decision == "model_silent" {
                                            tracing::warn!("{}", summary);
                                            let _ =
                                                status_clone.send(format!("[WARN] {}", summary));
                                        } else {
                                            info!("{}", summary);
                                            let _ =
                                                status_clone.send(format!("[INFO] {}", summary));
                                        }

                                        // Actually end the link the model asked to end.
                                        //
                                        // The `break` that sets `asked_to_close` leaves the
                                        // `for` over `protocol_results` — it stops executing
                                        // further actions, which is right — but it does not
                                        // leave the read loop, so for a long time
                                        // `close_connection` logged a hang-up and then went
                                        // back to reading the next line. This break is the one
                                        // that closes, and it is placed after the decision
                                        // line so a refusal is still logged before the link
                                        // goes.
                                        if asked_to_close {
                                            break;
                                        }
                                    }
                                    Err(e) => {
                                        // Silence here is worse than it looks: a client that
                                        // has sent NICK/USER blocks until it gives up, because
                                        // registration only completes on numeric 001. 400
                                        // (ERR_UNKNOWNERROR) is the numeric reserved for
                                        // exactly this - a command the server understood and
                                        // could not carry out - and it can never be mistaken
                                        // for a registration, a JOIN or a PRIVMSG.
                                        // Saturation keeps the link (the client may retry);
                                        // anything else closes it. Both look like a 400 to the
                                        // client, so the token carries the distinction, and
                                        // the error goes only here — never into the numeric's
                                        // trailing parameter, which a real IRC client prints
                                        // verbatim to a human.
                                        let token = if crate::utils::WireFailure::classify(&e)
                                            .is_overloaded()
                                        {
                                            "fail_closed_llm_overloaded"
                                        } else {
                                            "fail_closed_llm_error"
                                        };
                                        let command = irc_command_token(&line);
                                        error!(
                                            "IRC {} on connection {} from {} decision={}: {}",
                                            command, connection_id, remote_addr, token, e
                                        );
                                        let _ = status_clone.send(format!(
                                            "[ERROR] IRC {} on connection {} from {} decision={}",
                                            command, connection_id, remote_addr, token
                                        ));
                                        let (reply, close) = irc_failure_reply(&command, &e);
                                        let _ = status_clone.send(format!(
                                            "[ERROR] IRC connection {} replying: {}",
                                            connection_id,
                                            reply.trim_end()
                                        ));
                                        {
                                            let mut write = write_half_arc.lock().await;
                                            let _ = write.write_all(reply.as_bytes()).await;
                                            let _ = write.flush().await;
                                            if close {
                                                let _ = write.shutdown().await;
                                            }
                                        }
                                        state_clone
                                            .update_connection_stats(
                                                server_id,
                                                connection_id,
                                                None,
                                                Some(reply.len() as u64),
                                                None,
                                                Some(1),
                                            )
                                            .await;
                                        if close {
                                            break;
                                        }
                                    }
                                }
                            }

                            // Connection closed - every exit path (EOF, read error,
                            // close_connection, backend-unavailable ERROR) lands here.
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
                        error!("Failed to accept IRC connection: {}", e);
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

/// Complete lines that are already here — buffered, or readable without waiting — up to `max`.
///
/// What batching collects after the first line. It never waits: a zero deadline polls
/// `fill_buf` once, and `fill_buf` consumes nothing, so giving up on it loses no bytes. It
/// stops at a partial line, an over-long one or the end of the stream and leaves each for the
/// next bounded `read_irc_line` to report, so every existing bound still applies.
async fn lines_already_here<R>(reader: &mut BufReader<R>, max: usize) -> Vec<(String, usize)>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut lines = Vec::new();
    while lines.len() < max {
        if reader.buffer().is_empty() {
            match tokio::time::timeout(Duration::ZERO, reader.fill_buf()).await {
                Ok(Ok(available)) if !available.is_empty() => {}
                _ => break,
            }
        }
        match reader.buffer().iter().position(|b| *b == b'\n') {
            Some(idx) if idx < MAX_IRC_READ_LINE => {}
            _ => break,
        }
        // A newline is buffered, so this returns without touching the socket.
        match read_irc_line(reader, MAX_IRC_READ_LINE).await {
            Ok((IrcLine::Line(line), consumed)) => lines.push((line, consumed)),
            _ => break,
        }
    }
    lines
}

/// The command token of an IRC message, uppercased, for echoing back in a numeric.
///
/// Handles the optional `:prefix` clients are allowed to send, and falls back to `*` for a
/// line with nothing usable in it - a numeric with a missing parameter is worse than a vague
/// one, because it changes the arity the client parses.
fn irc_command_token(line: &str) -> String {
    let trimmed = line.trim();
    let without_prefix = if let Some(rest) = trimmed.strip_prefix(':') {
        rest.split_once(' ').map(|(_, r)| r).unwrap_or("")
    } else {
        trimmed
    };
    let token: String = without_prefix
        .split_whitespace()
        .next()
        .unwrap_or("*")
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect();
    if token.is_empty() {
        "*".to_string()
    } else {
        token.to_uppercase()
    }
}

/// What to send an IRC client when the LLM backend fails, and whether to close the link.
///
/// Numeric 400 (`ERR_UNKNOWNERROR`) is the code reserved for "an error the server has no more
/// specific numeric for", carrying the offending command as a parameter. It is not 421
/// (`ERR_UNKNOWNCOMMAND`), which would tell the client the command does not exist and stop it
/// ever retrying, and it is not any of the registration numerics, so a client waiting on 001
/// cannot mistake it for a completed registration.
///
/// A capacity failure is transient, so the link survives and the client may try again. Any
/// other failure means the server cannot answer anything at all, and IRC's honest way to say
/// that is `ERROR` followed by closing the link - which is also what unblocks a client that is
/// mid-registration instead of leaving it on a socket that will never speak again.
fn irc_failure_reply(command: &str, err: &anyhow::Error) -> (String, bool) {
    // The text is a category, never the error itself (`crate::utils::wire_failure`). A numeric
    // is one CRLF-terminated line whose trailing parameter runs to end of line, so an embedded
    // newline in an error would have forged a second message.
    let failure = crate::utils::WireFailure::classify(err);
    let text = failure.prefixed_text();
    if failure.is_overloaded() {
        (format!(":netget 400 * {command} :{text}\r\n"), false)
    } else {
        (
            format!(
                ":netget 400 * {command} :{text}\r\nERROR :Closing link: netget backend unavailable\r\n"
            ),
            true,
        )
    }
}
