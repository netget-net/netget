//! STOMP 1.2 server implementation.
//!
//! # Where the work is divided
//!
//! Everything mechanical is done here in Rust and never asked of the model: frame boundaries,
//! header escaping, the `content-length`/NUL body rule, the `receipt` handshake, heart-beat
//! negotiation, and refusing a frame that violates the spec. The model decides *content* —
//! admit this CONNECT or not, what a MESSAGE carries, whether to refuse.
//!
//! That split is why `receipt` is handled generically: it is a property of the frame, not of
//! what the frame means, and asking a model to remember it on every reply is asking it to get
//! it wrong eventually. A client frame carrying `receipt` gets a `RECEIPT` back once the frame
//! has been processed — after the model's own output, as the spec requires.
//!
//! # No per-connection state machine, deliberately
//!
//! `src/server/tcp/mod.rs` carries an Idle/Processing/Accumulating machine because raw TCP has
//! no frame boundaries: the reader task cannot know whether the bytes it just read complete a
//! request, so a second read arriving mid-LLM-call has to be queued. STOMP *does* have frame
//! boundaries, so this connection reads, parses out whole frames, and handles them one at a
//! time in the same task. Bytes arriving during an LLM call sit in the socket buffer — TCP's
//! own backpressure — and are read on the next pass. There is no window in which two LLM calls
//! could run for one connection, so there is no state to track.
//!
//! # Failure behaviour
//!
//! STOMP has an `ERROR` frame, so this server is never silent on failure. The peer is told a
//! *category* (`crate::utils::WireFailure`) and the connection is closed, as the spec requires
//! after an ERROR. The error itself goes to the log and the status stream only — never onto
//! the wire.
//!
//! `stomp_connect` is the one event where "the model said nothing" is not an acceptable
//! answer: STOMP defines exactly two replies to CONNECT, and a client that receives neither
//! blocks forever. So a connect event that produces no bytes is answered with an ERROR and
//! closed, logged as `decision=fail_closed_no_answer`. For every other event silence is a real
//! answer — a broker that accepts a SEND and says nothing is behaving normally.

pub mod actions;
pub mod frame;

use crate::llm::action_helper::call_llm;
use crate::llm::actions::protocol_trait::ActionResult;
use crate::llm::ollama_client::OllamaClient;
use crate::logging::emit::Log;
use crate::protocol::Event;
use crate::server::connection::ConnectionId;
use crate::state::app_state::AppState;
use actions::{
    StompProtocol, STOMP_ACK_EVENT, STOMP_CONNECT_EVENT, STOMP_DISCONNECT_EVENT, STOMP_NACK_EVENT,
    STOMP_SEND_EVENT, STOMP_SUBSCRIBE_EVENT, STOMP_UNSUBSCRIBE_EVENT, STOMP_VERSION,
};
use anyhow::Result;
use frame::{error_frame, receipt_frame, ParseOutcome, StompFrame};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, Mutex};

/// How long to wait for a peer's `CONNECT` after it opens the socket.
///
/// STOMP is client-speaks-first and the spec makes `CONNECT`/`STOMP` the *only* legal first
/// frame, so a peer that has connected and sent nothing has begun no session at all — which is
/// the state an unauthenticated flood lives in. The deadline wraps the `read()` and nothing
/// else, so a model round-trip, or a `manual` rule parking the CONNECT for a human, sits outside
/// it by construction.
const FIRST_FRAME_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// How long a connected peer may send nothing further.
///
/// **This is the one bound here that can close a well-behaved client, and the reason is worth
/// stating rather than hiding.** A STOMP subscriber sends `SUBSCRIBE` once and then only
/// receives, and this server negotiates heart-beating **off unconditionally**
/// (`actions::STOMP_HEARTBEAT` is `"0,0"`, because there is no heart-beat timer here and
/// promising one would be a lie), so there is no keepalive interval to sit above and no traffic
/// from an idle subscriber at all. Some finite bound is still required — a socket, a task and an
/// `AppState` row per silent peer, pre-authentication, is the denial of service this exists to
/// close.
///
/// Thirty minutes is chosen against what a real broker does: ActiveMQ and RabbitMQ negotiate
/// heart-beats in the 10–60 second range and cut a peer at twice the negotiated interval, so
/// this is between thirty and a hundred and eighty times more patient than either. A client that
/// wants to stay silent longer has a cheap way to say so: a bare EOL is a STOMP heart-beat, the
/// parser drains it as one, and it counts as inbound activity here.
const IDLE_BETWEEN_FRAMES_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1800);

/// Concurrent connections this server admits.
///
/// Each admitted connection holds a task, a frame buffer and an `AppState` row before any
/// `CONNECT` is decided, so the cap is what turns those per-connection bounds into total ones.
const MAX_CONNECTIONS: usize = crate::server::accept_bounded::DEFAULT_MAX_CONNECTIONS;

/// The `message` header of the `ERROR` frame a peer over [`MAX_CONNECTIONS`] is sent.
///
/// STOMP has an `ERROR` frame and the spec has the server close after one, which is exactly the
/// shape of a refusal — so the peer is told, in the protocol's own vocabulary, rather than
/// dropped. The frame is built through `frame::error_frame` rather than written as a byte
/// literal so that the escaping and the `content-length`/NUL rules stay the encoder's job.
const CONNECTION_CAP_REFUSAL_MESSAGE: &str = "too many connections";

/// The body of that `ERROR` frame. A fixed string: nothing derived from an internal error may
/// reach the wire (`crate::utils::wire_failure`), and there is nothing internal here anyway —
/// the server is simply full.
const CONNECTION_CAP_REFUSAL_BODY: &str =
    "The server has reached its connection limit. Retry later.";

pub struct StompServer;

impl StompServer {
    /// Bind and start accepting STOMP connections.
    ///
    /// Returns `Err` if the socket cannot be bound, so `server_startup` records
    /// `ServerStatus::Error` rather than a server that claims to be up and is not.
    pub async fn spawn_with_llm_actions(
        listen_addr: SocketAddr,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        server_id: crate::state::ServerId,
    ) -> Result<SocketAddr> {
        let listener = crate::server::socket_helpers::create_reusable_tcp_listener(listen_addr)
            .await
            .map_err(|e| anyhow::anyhow!("STOMP could not bind {listen_addr}: {e}"))?;
        let local_addr = listener.local_addr()?;

        Log::new(Some(&status_tx)).info(format!("STOMP server listening on {}", local_addr));

        let protocol = Arc::new(StompProtocol::new());
        let task_registrar = app_state.clone();

        let limiter = crate::server::accept_bounded::ConnectionLimiter::new(MAX_CONNECTIONS);
        // Encoded once rather than per refusal: the bytes never change, and going through the
        // protocol's own encoder keeps header escaping and the NUL terminator its job.
        let cap_refusal = error_frame(CONNECTION_CAP_REFUSAL_MESSAGE, CONNECTION_CAP_REFUSAL_BODY);

        let accept_handle = tokio::spawn(async move {
            loop {
                match crate::server::accept_bounded::accept_bounded(
                    &listener,
                    &limiter,
                    &cap_refusal,
                    "STOMP",
                    Some(&status_tx),
                )
                .await
                {
                    Ok((socket, peer_addr, permit)) => {
                        let connection_id =
                            ConnectionId::new(app_state.get_next_unified_id().await);
                        let local_addr_conn = socket.local_addr().unwrap_or(local_addr);

                        use crate::state::server::{
                            ConnectionState as ServerConnectionState, ConnectionStatus,
                            ProtocolConnectionInfo,
                        };
                        let now = crate::utils::clock::Instant::now();
                        app_state
                            .add_connection_to_server(
                                server_id,
                                ServerConnectionState {
                                    id: connection_id,
                                    remote_addr: peer_addr,
                                    local_addr: local_addr_conn,
                                    bytes_sent: 0,
                                    bytes_received: 0,
                                    packets_sent: 0,
                                    packets_received: 0,
                                    last_activity: now,
                                    status: ConnectionStatus::Active,
                                    status_changed_at: now,
                                    protocol_info: ProtocolConnectionInfo::new(
                                        serde_json::json!({"session": "pre-connect"}),
                                    ),
                                },
                            )
                            .await;
                        let _ = status_tx.send("__UPDATE_UI__".to_string());

                        Log::new(Some(&status_tx))
                            .info(format!("STOMP client connected from {}", peer_addr));

                        let llm_clone = llm_client.clone();
                        let state_clone = app_state.clone();
                        let status_clone = status_tx.clone();
                        let protocol_clone = protocol.clone();

                        // Every task this protocol spawns is registered, not just the accept
                        // loop: aborting a parent does not abort what it spawned, so an
                        // unregistered connection task keeps its socket alive after
                        // stop_server has released the listener.
                        let conn_handle = tokio::spawn(async move {
                            // Held for the life of the connection: dropping it early releases
                            // the slot while the peer is still here, which silently un-caps
                            // the server.
                            let _permit = permit;
                            handle_stomp_connection(
                                socket,
                                peer_addr,
                                llm_clone,
                                state_clone,
                                status_clone,
                                server_id,
                                protocol_clone,
                                connection_id,
                            )
                            .await
                        });
                        app_state.register_server_task(server_id, conn_handle).await;
                    }
                    Err(e) => {
                        Log::new(Some(&status_tx)).error(format!("STOMP accept error: {}", e));
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

/// Write bytes to the peer and count them.
///
/// The write guard is dropped before the stats update, so nothing awaits an `AppState` lock
/// while holding the socket.
async fn write_counted<W>(
    write_half: &Arc<Mutex<W>>,
    data: &[u8],
    app_state: &AppState,
    server_id: crate::state::ServerId,
    connection_id: ConnectionId,
) -> std::io::Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    {
        let mut writer = write_half.lock().await;
        writer.write_all(data).await?;
        writer.flush().await?;
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

#[allow(clippy::too_many_arguments)]
async fn handle_stomp_connection(
    socket: tokio::net::TcpStream,
    peer_addr: SocketAddr,
    llm_client: OllamaClient,
    app_state: Arc<AppState>,
    status_tx: mpsc::UnboundedSender<String>,
    server_id: crate::state::ServerId,
    protocol: Arc<StompProtocol>,
    connection_id: ConnectionId,
) {
    let (reader, write_half) = tokio::io::split(socket);
    let write_half = Arc::new(Mutex::new(write_half));

    // Registered before the first read: a STOMP server says nothing until the client sends
    // CONNECT, and a manual `*` routing rule can park that frame for minutes, so the operator
    // has to be able to reach the connection while it waits.
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

    run_stomp_session(
        reader,
        &write_half,
        peer_addr,
        &llm_client,
        &app_state,
        &status_tx,
        server_id,
        &protocol,
        connection_id,
    )
    .await;

    // Every exit path lands here. Dropping the peer handle ends the peer command task, which
    // releases its clone of the write half; the explicit shutdown makes the FIN immediate.
    app_state
        .remove_peer_handle(server_id, connection_id.as_u32())
        .await;
    let _ = write_half.lock().await.shutdown().await;

    use crate::state::server::ConnectionStatus;
    app_state
        .update_connection_status(server_id, connection_id, ConnectionStatus::Closed)
        .await;
    let _ = status_tx.send("__UPDATE_UI__".to_string());
}

/// What to do after a frame has been handled.
enum Flow {
    /// Keep reading frames on this connection.
    Continue,
    /// Stop: the session is over (DISCONNECT, ERROR, or the model hung up).
    Close,
}

#[allow(clippy::too_many_arguments)]
async fn run_stomp_session<R, W>(
    mut reader: R,
    write_half: &Arc<Mutex<W>>,
    peer_addr: SocketAddr,
    llm_client: &OllamaClient,
    app_state: &Arc<AppState>,
    status_tx: &mpsc::UnboundedSender<String>,
    server_id: crate::state::ServerId,
    protocol: &Arc<StompProtocol>,
    connection_id: ConnectionId,
) where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let log = Log::new(Some(status_tx));
    let mut pending: Vec<u8> = Vec::new();
    let mut read_buf = vec![0u8; 8192];
    let mut connected = false;

    loop {
        // Drain every complete frame already buffered before asking the socket for more.
        loop {
            match frame::parse_frame(&pending) {
                Ok(ParseOutcome::Incomplete) => break,
                Ok(ParseOutcome::Heartbeat { consumed }) => {
                    // A bare EOL is a STOMP heart-beat, and clients also append trailing
                    // newlines after a frame's NUL. Neither is a frame.
                    log.trace(format!(
                        "STOMP drained {consumed} inter-frame EOL byte(s) from {peer_addr}"
                    ));
                    pending.drain(..consumed);
                }
                Ok(ParseOutcome::Frame { frame, consumed }) => {
                    pending.drain(..consumed);
                    // With batching on, the frames that are already here behind this one -
                    // typically what the client sent while the model answered the last - are
                    // answered in the same call.
                    let first = if connected {
                        batchable_event(&frame)
                    } else {
                        None
                    };
                    let batching = match &first {
                        Some(_) => app_state
                            .server_conversation_settings(server_id)
                            .await
                            .is_some_and(|(_, batching)| batching),
                        None => false,
                    };
                    let more = if batching {
                        frames_already_here(
                            &mut pending,
                            &mut reader,
                            &mut read_buf,
                            app_state,
                            server_id,
                            connection_id,
                        )
                        .await
                    } else {
                        Vec::new()
                    };
                    let flow = match first {
                        Some(event) if !more.is_empty() => {
                            let receipt = frame.header("receipt").map(str::to_string);
                            let mut frames = Vec::with_capacity(1 + more.len());
                            frames.push((event, receipt));
                            frames.extend(more);
                            handle_batch(
                                frames,
                                &mut connected,
                                write_half,
                                peer_addr,
                                llm_client,
                                app_state,
                                status_tx,
                                server_id,
                                protocol,
                                connection_id,
                            )
                            .await
                        }
                        _ => {
                            handle_frame(
                                frame,
                                &mut connected,
                                write_half,
                                peer_addr,
                                llm_client,
                                app_state,
                                status_tx,
                                server_id,
                                protocol,
                                connection_id,
                            )
                            .await
                        }
                    };
                    if matches!(flow, Flow::Close) {
                        return;
                    }
                }
                Err(e) => {
                    // Framing is lost; STOMP has no way to resynchronise. The peer is told
                    // what it did wrong - this is its own malformed input, not anything
                    // internal to netget - and the connection closes as the spec requires
                    // after an ERROR.
                    log.warn(format!("STOMP framing error from {peer_addr}: {e}"));
                    let _ = write_counted(
                        write_half,
                        &error_frame("malformed frame", &e.to_string()),
                        app_state,
                        server_id,
                        connection_id,
                    )
                    .await;
                    return;
                }
            }
        }

        // The deadline wraps this read and nothing else. `handle_frame` above is awaited in the
        // same task, so while the model is answering — or a `manual` rule is parked for a
        // human — nothing is being read and no clock is running: what this measures is the
        // peer's own silence, which is what it should measure.
        //
        // Which bound applies is the protocol's own distinction: `connected` is set by the
        // CONNECT/STOMP frame the spec requires first, so "has begun no session" and "is
        // mid-session" are exactly the two states.
        let read_deadline = if connected {
            IDLE_BETWEEN_FRAMES_TIMEOUT
        } else {
            FIRST_FRAME_READ_TIMEOUT
        };
        let read_result =
            match tokio::time::timeout(read_deadline, reader.read(&mut read_buf)).await {
                Ok(v) => v,
                Err(_) => {
                    log.info(format!(
                        "STOMP client {} sent nothing for {}s; closing \
                     decision=fail_closed_idle_timeout",
                        peer_addr,
                        read_deadline.as_secs()
                    ));
                    // ERROR then close, as the spec requires after an ERROR. A fixed string: the
                    // peer is being told the server's own policy, not anything internal.
                    let _ = write_counted(
                        write_half,
                        &error_frame("idle timeout", "No frame received within the idle timeout."),
                        app_state,
                        server_id,
                        connection_id,
                    )
                    .await;
                    return;
                }
            };

        match read_result {
            Ok(0) => {
                log.info(format!("STOMP client {} disconnected", peer_addr));
                return;
            }
            Ok(n) => {
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
                log.debug(format!("STOMP received {} bytes from {}", n, peer_addr));
                pending.extend_from_slice(&read_buf[..n]);
            }
            Err(e) => {
                log.error(format!("STOMP read error from {}: {}", peer_addr, e));
                return;
            }
        }
    }
}

/// The batchable frames already here behind the one being handled, each with its `receipt`, up
/// to [`crate::protocol::metadata::MAX_BATCH_EVENTS`] in all.
///
/// Takes complete frames out of `pending`, reading the socket only for what is readable
/// without waiting. It stops at the first frame [`batchable_event`] does not build - the
/// handshake, `DISCONNECT`, a transaction frame, a malformed frame - and leaves it in `pending`,
/// so that frame is handled alone, after the batch, in the order it arrived.
async fn frames_already_here<R>(
    pending: &mut Vec<u8>,
    reader: &mut R,
    read_buf: &mut [u8],
    app_state: &AppState,
    server_id: crate::state::ServerId,
    connection_id: ConnectionId,
) -> Vec<(Event, Option<String>)>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut frames = Vec::new();
    while frames.len() + 1 < crate::protocol::metadata::MAX_BATCH_EVENTS {
        match frame::parse_frame(pending) {
            Ok(ParseOutcome::Heartbeat { consumed }) => {
                pending.drain(..consumed);
            }
            Ok(ParseOutcome::Frame { frame, consumed }) => {
                let Some(event) = batchable_event(&frame) else {
                    break;
                };
                pending.drain(..consumed);
                frames.push((event, frame.header("receipt").map(str::to_string)));
            }
            Ok(ParseOutcome::Incomplete) => {
                // A zero deadline polls the read once: whatever the kernel already holds,
                // nothing that would mean waiting. `read` is cancel-safe, so a timeout loses
                // no bytes.
                match tokio::time::timeout(std::time::Duration::ZERO, reader.read(read_buf)).await {
                    Ok(Ok(n)) if n > 0 => {
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
                        pending.extend_from_slice(&read_buf[..n]);
                    }
                    _ => break,
                }
            }
            // Left for the session loop, which reports it.
            Err(_) => break,
        }
    }
    frames
}

/// Refuse a frame the peer got wrong, and end the session.
///
/// `message` and `body` describe the *peer's* mistake — a missing header, an unknown command —
/// so they are safe to send. Nothing derived from an internal error is ever routed through
/// here; that path is `WireFailure` in [`handle_frame`].
async fn refuse_frame<W>(
    write_half: &Arc<Mutex<W>>,
    app_state: &AppState,
    server_id: crate::state::ServerId,
    connection_id: ConnectionId,
    message: &str,
    body: &str,
) -> Flow
where
    W: tokio::io::AsyncWrite + Unpin,
{
    let _ = write_counted(
        write_half,
        &error_frame(message, body),
        app_state,
        server_id,
        connection_id,
    )
    .await;
    Flow::Close
}

/// Handle one complete frame.
#[allow(clippy::too_many_arguments)]
async fn handle_frame<W>(
    frame: StompFrame,
    connected: &mut bool,
    write_half: &Arc<Mutex<W>>,
    peer_addr: SocketAddr,
    llm_client: &OllamaClient,
    app_state: &Arc<AppState>,
    status_tx: &mpsc::UnboundedSender<String>,
    server_id: crate::state::ServerId,
    protocol: &Arc<StompProtocol>,
    connection_id: ConnectionId,
) -> Flow
where
    W: tokio::io::AsyncWrite + Unpin,
{
    let log = Log::new(Some(status_tx));
    let command = frame.command.clone();
    log.debug(format!("STOMP {} frame from {}", command, peer_addr));

    // Nothing but a handshake is legal before one has happened.
    if !*connected && !matches!(command.as_str(), "CONNECT" | "STOMP") {
        log.warn(format!(
            "STOMP {command} from {peer_addr} before CONNECT: decision=protocol_error"
        ));
        return refuse_frame(
            write_half,
            app_state,
            server_id,
            connection_id,
            "expected CONNECT",
            &format!("The first frame of a STOMP session must be CONNECT or STOMP, not {command}."),
        )
        .await;
    }

    let receipt_id = frame.header("receipt").map(str::to_string);

    // Build the event, or refuse the frame outright. Every refusal here is a spec violation by
    // the peer, decided deterministically - the model is never asked to police framing.
    let event = if let Some(event) = batchable_event(&frame) {
        event
    } else {
        match command.as_str() {
            "CONNECT" | "STOMP" => {
                let accept_version = frame.header("accept-version").unwrap_or("");
                if !accept_version.split(',').any(|v| v.trim() == STOMP_VERSION) {
                    log.warn(format!(
                        "STOMP CONNECT from {peer_addr} wants accept-version={accept_version:?}: \
                     decision=version_refused"
                    ));
                    // The spec asks the ERROR to name the versions the server does support.
                    let body = format!(
                        "This server implements STOMP {STOMP_VERSION} only. Send \
                     accept-version:{STOMP_VERSION}."
                    );
                    let refusal = StompFrame::new(
                        "ERROR",
                        vec![
                            ("version".to_string(), STOMP_VERSION.to_string()),
                            ("message".to_string(), "unsupported version".to_string()),
                            ("content-type".to_string(), "text/plain".to_string()),
                        ],
                        body.into_bytes(),
                    )
                    .encode();
                    let _ =
                        write_counted(write_half, &refusal, app_state, server_id, connection_id)
                            .await;
                    return Flow::Close;
                }
                Event::new(
                    &STOMP_CONNECT_EVENT,
                    serde_json::json!({
                        "accept_version": accept_version,
                        "host": frame.header("host").unwrap_or(""),
                        "login": frame.header("login").unwrap_or(""),
                        "passcode": frame.header("passcode").unwrap_or(""),
                        "heart_beat": frame.header("heart-beat").unwrap_or("0,0"),
                    }),
                )
            }
            // The five commands `batchable_event` builds reach here only when a header they need
            // is missing.
            "SEND" => {
                return refuse_frame(
                    write_half,
                    app_state,
                    server_id,
                    connection_id,
                    "missing destination",
                    "A SEND frame must carry a destination header.",
                )
                .await;
            }
            "SUBSCRIBE" => {
                return refuse_frame(
                    write_half,
                    app_state,
                    server_id,
                    connection_id,
                    "missing subscription headers",
                    "A SUBSCRIBE frame must carry both destination and id headers.",
                )
                .await;
            }
            "UNSUBSCRIBE" => {
                return refuse_frame(
                    write_half,
                    app_state,
                    server_id,
                    connection_id,
                    "missing id",
                    "An UNSUBSCRIBE frame must carry an id header.",
                )
                .await;
            }
            "ACK" | "NACK" => {
                return refuse_frame(
                    write_half,
                    app_state,
                    server_id,
                    connection_id,
                    "missing id",
                    &format!("A {command} frame must carry an id header."),
                )
                .await;
            }
            "DISCONNECT" => Event::new(
                &STOMP_DISCONNECT_EVENT,
                serde_json::json!({ "receipt": receipt_id.clone().unwrap_or_default() }),
            ),
            // Transactions are acknowledged and otherwise ignored. Holding a SEND until COMMIT
            // would mean queueing messages inside the protocol, which is storage - see the
            // "protocols must not implement storage" rule. The transaction header still reaches
            // the model on the SEND event, so a handler can implement whatever it likes.
            "BEGIN" | "COMMIT" | "ABORT" => {
                log.info(format!(
                "STOMP {command} from {peer_addr} acknowledged; transactions are not implemented"
            ));
                if let Some(id) = &receipt_id {
                    if write_counted(
                        write_half,
                        &receipt_frame(id),
                        app_state,
                        server_id,
                        connection_id,
                    )
                    .await
                    .is_err()
                    {
                        return Flow::Close;
                    }
                }
                return Flow::Continue;
            }
            other => {
                log.warn(format!(
                    "STOMP unknown command {other:?} from {peer_addr}: decision=protocol_error"
                ));
                return refuse_frame(
                    write_half,
                    app_state,
                    server_id,
                    connection_id,
                    "unknown command",
                    &format!("{other} is not a STOMP 1.2 client command."),
                )
                .await;
            }
        }
    };

    let is_connect = matches!(command.as_str(), "CONNECT" | "STOMP");
    let is_disconnect = command == "DISCONNECT";

    let execution = call_llm(
        llm_client,
        app_state,
        server_id,
        Some(connection_id),
        &event,
        protocol.as_ref(),
    )
    .await;
    deliver_answer(
        execution,
        &command,
        &[receipt_id],
        is_connect,
        is_disconnect,
        connected,
        write_half,
        peer_addr,
        app_state,
        status_tx,
        server_id,
        connection_id,
    )
    .await
}

/// The event for a frame that the model answers and that can share a batch: `SEND`,
/// `SUBSCRIBE`, `UNSUBSCRIBE`, `ACK` and `NACK` carrying the headers the spec requires.
///
/// `None` for everything else - the handshake, `DISCONNECT`, the transaction frames Rust
/// acknowledges itself, and a frame missing a required header, which [`handle_frame`] refuses.
/// A batch stops at the first such frame, so it is handled alone and in order.
fn batchable_event(frame: &StompFrame) -> Option<Event> {
    match frame.command.as_str() {
        "SEND" => {
            let destination = frame.header("destination")?;
            let (body, body_encoding) = body_for_event(&frame.body);
            Some(Event::new(
                &STOMP_SEND_EVENT,
                serde_json::json!({
                    "destination": destination,
                    "body": body,
                    "body_encoding": body_encoding,
                    "headers": frame.headers_except(&["destination", "content-length"]),
                }),
            ))
        }
        "SUBSCRIBE" => {
            let destination = frame.header("destination")?;
            let id = frame.header("id")?;
            Some(Event::new(
                &STOMP_SUBSCRIBE_EVENT,
                serde_json::json!({
                    "destination": destination,
                    "id": id,
                    "ack_mode": frame.header("ack").unwrap_or("auto"),
                }),
            ))
        }
        "UNSUBSCRIBE" => {
            let id = frame.header("id")?;
            Some(Event::new(
                &STOMP_UNSUBSCRIBE_EVENT,
                serde_json::json!({ "id": id }),
            ))
        }
        "ACK" | "NACK" => {
            let id = frame.header("id")?;
            let event_type = if frame.command == "ACK" {
                &*STOMP_ACK_EVENT
            } else {
                &*STOMP_NACK_EVENT
            };
            Some(Event::new(event_type, serde_json::json!({ "id": id })))
        }
        _ => None,
    }
}

/// Answer several frames that were already waiting in one model call.
///
/// Every frame here came from [`batchable_event`], so none is a handshake or a `DISCONNECT`,
/// and each one's `receipt` is still owed by Rust: any the model's own output did not carry is
/// written after that output, in arrival order - the rule a single frame follows.
#[allow(clippy::too_many_arguments)]
async fn handle_batch<W>(
    frames: Vec<(Event, Option<String>)>,
    connected: &mut bool,
    write_half: &Arc<Mutex<W>>,
    peer_addr: SocketAddr,
    llm_client: &OllamaClient,
    app_state: &Arc<AppState>,
    status_tx: &mpsc::UnboundedSender<String>,
    server_id: crate::state::ServerId,
    protocol: &Arc<StompProtocol>,
    connection_id: ConnectionId,
) -> Flow
where
    W: tokio::io::AsyncWrite + Unpin,
{
    let (events, receipts): (Vec<Event>, Vec<Option<String>>) = frames.into_iter().unzip();
    Log::new(Some(status_tx)).debug(format!(
        "STOMP answering {} frames from {peer_addr} together",
        events.len()
    ));
    let execution = crate::llm::action_helper::call_llm_batch(
        llm_client,
        app_state,
        server_id,
        Some(connection_id),
        &events,
        protocol.as_ref(),
    )
    .await;
    let command = format!("batch of {}", events.len());
    deliver_answer(
        execution,
        &command,
        &receipts,
        false,
        false,
        connected,
        write_half,
        peer_addr,
        app_state,
        status_tx,
        server_id,
        connection_id,
    )
    .await
}

/// Put a handler's answer on the wire, then every receipt it did not carry itself.
///
/// `receipts` holds one entry per frame answered, in arrival order: one for a single frame,
/// several for a batch.
#[allow(clippy::too_many_arguments)]
async fn deliver_answer<W>(
    execution: Result<crate::llm::ExecutionResult>,
    command: &str,
    receipts: &[Option<String>],
    is_connect: bool,
    is_disconnect: bool,
    connected: &mut bool,
    write_half: &Arc<Mutex<W>>,
    peer_addr: SocketAddr,
    app_state: &Arc<AppState>,
    status_tx: &mpsc::UnboundedSender<String>,
    server_id: crate::state::ServerId,
    connection_id: ConnectionId,
) -> Flow
where
    W: tokio::io::AsyncWrite + Unpin,
{
    let log = Log::new(Some(status_tx));
    let execution = match execution {
        Ok(result) => result,
        Err(e) => {
            // The peer gets a category; the log gets the error. Never the other way round.
            let failure = crate::utils::WireFailure::classify(&e);
            let class = if failure.is_overloaded() {
                "overloaded"
            } else {
                "unavailable"
            };
            log.warn(format!(
                "STOMP {command} on {connection_id} could not be answered: \
                 decision=fail_closed_llm_error class={class} error={e}"
            ));
            let _ = write_counted(
                write_half,
                &error_frame(failure.text(), failure.prefixed_text()),
                app_state,
                server_id,
                connection_id,
            )
            .await;
            return Flow::Close;
        }
    };

    for message in &execution.messages {
        log.info(message);
    }

    let mut wrote_output = false;
    let mut wrote_receipt = vec![false; receipts.len()];
    let mut wrote_error = false;
    let mut model_closed = false;

    for result in execution.protocol_results {
        match result {
            ActionResult::Output(bytes) => {
                if write_counted(write_half, &bytes, app_state, server_id, connection_id)
                    .await
                    .is_err()
                {
                    return Flow::Close;
                }
                wrote_output = true;
                // Only a RECEIPT carrying the id the client actually asked for cancels the
                // automatic one. Matching on the command alone meant *any* RECEIPT suppressed
                // it, so a handler answering `UNSUBSCRIBE id:s0 receipt:r-9` with a receipt
                // for some other id sent that one and the client's `r-9` never arrived - and
                // a spec-compliant client blocks on it forever, with no read timeout to reap
                // the connection. The declared examples for stomp_unsubscribe, stomp_ack and
                // stomp_nack used to be exactly that mistake, so this was reachable by
                // following the documentation.
                for (wrote, receipt_id) in wrote_receipt.iter_mut().zip(receipts) {
                    *wrote |= receipt_id
                        .as_deref()
                        .is_some_and(|id| is_receipt_for(&bytes, id));
                }
                wrote_error |= bytes.starts_with(b"ERROR\n");
                log.debug(format!("STOMP sent {} bytes to {}", bytes.len(), peer_addr));
                log.trace(format!(
                    "STOMP sent: {}",
                    String::from_utf8_lossy(&bytes).replace('\0', "\\0")
                ));
            }
            ActionResult::CloseConnection => model_closed = true,
            _ => {}
        }
    }

    if is_connect {
        if wrote_error {
            log.info(format!(
                "STOMP CONNECT from {peer_addr} refused: decision=model_reject"
            ));
            return Flow::Close;
        }
        if !wrote_output {
            // STOMP defines exactly two answers to CONNECT. A client that gets neither blocks
            // forever, so silence cannot be passed through as "say nothing" the way it can on
            // a SEND.
            log.warn(format!(
                "STOMP CONNECT from {peer_addr} produced no frame ({} failed action(s)): \
                 decision=fail_closed_no_answer",
                execution.failures.len()
            ));
            let _ = write_counted(
                write_half,
                &error_frame(
                    "connection refused",
                    "The server did not accept this connection.",
                ),
                app_state,
                server_id,
                connection_id,
            )
            .await;
            return Flow::Close;
        }
        *connected = true;
        log.info(format!("STOMP session opened for {peer_addr}"));
    } else if wrote_error {
        // The spec requires the connection to close after an ERROR, whoever produced it.
        log.info(format!(
            "STOMP closing {connection_id} after ERROR: decision=model_reject"
        ));
        return Flow::Close;
    }

    // The receipt is sent after the frame has been processed, which is what the spec says and
    // is also the only order that lets a handler answer before the acknowledgement. CONNECT is
    // exempt: CONNECTED is its acknowledgement and a receipt on it is not defined.
    for (receipt_id, wrote) in receipts.iter().zip(&wrote_receipt) {
        let owes_receipt = receipt_id.is_some() && !is_connect && !wrote;
        if let (true, Some(id)) = (owes_receipt, receipt_id) {
            if write_counted(
                write_half,
                &receipt_frame(id),
                app_state,
                server_id,
                connection_id,
            )
            .await
            .is_err()
            {
                return Flow::Close;
            }
        }
    }

    if model_closed {
        log.info(format!(
            "STOMP closing {connection_id}: decision=model_close"
        ));
        return Flow::Close;
    }
    if is_disconnect {
        log.info(format!("STOMP session closed by {peer_addr}"));
        return Flow::Close;
    }
    if !wrote_output {
        log.debug(format!(
            "STOMP {command} on {connection_id} answered with no frame: \
             decision=model_no_actions"
        ));
    }
    Flow::Continue
}

/// Whether `bytes` is a `RECEIPT` frame acknowledging `receipt_id`.
///
/// The comparison is against the bytes `receipt_frame` itself would produce, so the escaping
/// rules cannot drift between the two: whatever `RECEIPT` this server builds for an id, a
/// model-authored one for the same id is byte-identical.
fn is_receipt_for(bytes: &[u8], receipt_id: &str) -> bool {
    bytes.starts_with(b"RECEIPT\n") && bytes == frame::receipt_frame(receipt_id)
}

/// Render a received body for an event as text plus an explicit encoding.
///
/// Printable bodies go through as text so a model can read them; anything else is hex, and the
/// `body_encoding` field says which. There is no sniffing on the way back out — the model
/// passes the same pair to `send_stomp_message`, which is what makes an echo exact.
fn body_for_event(body: &[u8]) -> (String, &'static str) {
    if body
        .iter()
        .all(|b| b.is_ascii_graphic() || b.is_ascii_whitespace())
    {
        (String::from_utf8_lossy(body).to_string(), "utf8")
    } else {
        (hex::encode(body), "hex")
    }
}
