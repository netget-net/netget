//! TCP server implementation
pub mod actions;

use anyhow::{Context, Result};
use bytes::Bytes;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, info};

use super::connection::ConnectionId;
use crate::llm::action_helper::call_llm;
use crate::llm::ollama_client::OllamaClient;
use crate::llm::ActionResult;
use crate::logging::emit::Log;
use crate::protocol::Event;
use crate::server::TcpProtocol;
use crate::state::app_state::AppState;
use actions::{TCP_CONNECTION_OPENED_EVENT, TCP_DATA_RECEIVED_EVENT};

/// Most bytes that may pile up in one connection's `queued_data` while its LLM call is in
/// flight.
///
/// An LLM call takes seconds, and every byte the peer sends during it is appended to
/// `queued_data` with nothing to stop it: a peer that streams for the length of one call can
/// push NetGet's memory as fast as its link allows, pre-authentication, on the protocol every
/// other protocol copies. 8 MiB is far more than any request/response exchange this server is
/// for, and reaching it means the peer is not waiting for answers at all — so the connection is
/// closed rather than the queue trimmed, which would hand the model a truncated message it had
/// no way to know was truncated.
pub const MAX_QUEUED_BYTES: usize = 8 * 1024 * 1024;

/// How long to wait for the first byte from a peer that has only connected.
///
/// Generic TCP is client-speaks-first: `send_first` is opt-in and off by default, so a peer
/// that has connected and sent nothing has made no claim on this server at all. Thirty seconds
/// is far longer than any real client needs to put its first request on the wire once its
/// `connect()` has returned, and short enough that an unauthenticated socket, task and
/// `AppState` entry cannot be held for free.
///
/// The connect event is not an exception either: the task answering `tcp_connection_opened`
/// holds [`ConnectionActivity::busy`] for the whole of its LLM round-trip, so the clock does
/// not run while a peer is legitimately waiting to be spoken to.
///
/// **This was 30 seconds and that broke a real flow.** The argument for 30 was that generic TCP
/// is client-speaks-first, so a silent peer has made no claim — true of a stranger, and false of
/// the peer this server most often has. The dashboard offers `[ + tcp client ]` under a server's
/// peers and `[ send message ]` beneath it: that client connects, says nothing, and waits for a
/// person to type. Thirty seconds is less than a person takes, so the peer was dropped while the
/// operator was still looking at it. `tests/mcp_stdio_test.rs::client_tools_manage_a_real_connection`
/// is the same shape and failed deterministically — it takes ~38s to drive the MCP surface, and
/// the client it had just created was gone before it asked for its status.
///
/// 300 seconds is the window a `manual` rule gives a human to answer one event
/// (`src/state/intercepts.rs`), which is the number this product already uses for "how long
/// someone might take". The stranger it was protecting against is still bounded, and still
/// capped at [`MAX_CONNECTIONS`]; what changed is which of the two cases the default serves.
/// A listener genuinely exposed to strangers should set `first_byte_timeout_secs` low.
const FIRST_BYTE_READ_TIMEOUT: Duration = Duration::from_secs(300);

/// How long to wait for further bytes once the peer has sent something.
///
/// Longer than the first bound by a wide margin, because the two are different claims: "has
/// said nothing at all" is a peer that may not be a client, while "has gone quiet mid-session"
/// is a client between requests, and this is the generic byte-stream protocol every kind of
/// session is built on top of. Fifteen minutes is three times the default a `manual` rule gives
/// a human to answer one event (`src/state/intercepts.rs`, 300s), so even a session whose last
/// exchange was composed by hand at the dashboard has minutes of ordinary think-time left
/// afterwards before the connection is reclaimed.
const IDLE_BETWEEN_MESSAGES_TIMEOUT: Duration = Duration::from_secs(900);

/// Concurrent connections this server admits.
///
/// [`crate::server::accept_bounded::DEFAULT_MAX_CONNECTIONS`]. Each connection may queue up to
/// [`MAX_QUEUED_BYTES`] while its LLM call is in flight, so this is the multiplier that turns
/// that per-connection bound into a total one.
const MAX_CONNECTIONS: usize = crate::server::accept_bounded::DEFAULT_MAX_CONNECTIONS;

/// What a peer over [`MAX_CONNECTIONS`] is told before the socket closes: nothing.
///
/// Generic TCP has no vocabulary — there is no framing, no status code and no error message
/// this server could write that a peer would not read as *payload*, and a fabricated payload is
/// worse than silence for the same reason twenty protocols here stay silent on an LLM failure.
/// The refusal is still recorded: `accept_bounded` logs it at WARN with
/// `decision=fail_closed_connection_cap`, and the peer sees a clean EOF rather than a reset.
const CONNECTION_CAP_REFUSAL: &[u8] = b"";

/// Read from `reader` with a deadline that a connection doing work can never trip.
///
/// Returns `None` when the peer has genuinely been silent for `bound`, and the read's own
/// result otherwise. TCP needs this rather than a bare `tokio::time::timeout` because its read
/// loop is the one thing here that does *not* stop while a request is answered: each message is
/// handed to a spawned task and the loop goes straight back to `read()`, so at any moment the
/// connection may be parked on an LLM round-trip, or on a `manual` rule waiting for a human,
/// with nothing arriving on the socket. Consulting [`ConnectionActivity::idle_for`] — which
/// reports a connection with work in flight as not idle at all — is what keeps the deadline
/// from closing the connection it is in the middle of answering.
async fn read_bounded<R>(
    reader: &mut R,
    buffer: &mut [u8],
    activity: &crate::server::accept_bounded::ConnectionActivity,
    bound: Duration,
) -> Option<std::io::Result<usize>>
where
    R: tokio::io::AsyncRead + Unpin,
{
    loop {
        match tokio::time::timeout(bound, reader.read(buffer)).await {
            Ok(result) => return Some(result),
            Err(_) => match activity.idle_for() {
                // Work in flight: the peer is waiting on us, not the other way round.
                None => continue,
                // Something crossed the connection inside the window; wait again from there.
                Some(idle) if idle < bound => continue,
                Some(_) => return None,
            },
        }
    }
}

/// Connection state for LLM processing
#[derive(Debug, Clone, PartialEq)]
enum ConnectionState {
    Idle,
    Processing,
    Accumulating,
}

/// Per-connection data for LLM handling
struct ConnectionData {
    state: ConnectionState,
    queued_data: Vec<u8>,
    /// Where each read that was queued ended, oldest first, summing to `queued_data.len()`.
    /// With batching off the next call answers one read rather than the whole queue.
    queued_chunks: std::collections::VecDeque<usize>,
    memory: String,
    write_half: Arc<Mutex<tokio::io::WriteHalf<TcpStream>>>,
}

impl ConnectionData {
    /// Queue a read that arrived while the model was answering.
    fn queue(&mut self, data: &[u8]) {
        if !data.is_empty() {
            self.queued_data.extend_from_slice(data);
            self.queued_chunks.push_back(data.len());
        }
    }

    /// What the next call answers: the whole queue when batching, else the oldest read.
    ///
    /// A byte stream has no message boundaries, so "batching" here is what TCP always did —
    /// everything that arrived during a call is the next call's payload. With it off, each
    /// read the socket delivered is answered on its own, in order.
    fn take_next(&mut self, batching: bool) -> Vec<u8> {
        if batching || self.queued_chunks.len() <= 1 {
            self.queued_chunks.clear();
            return std::mem::take(&mut self.queued_data);
        }
        let n = self
            .queued_chunks
            .pop_front()
            .unwrap_or(self.queued_data.len())
            .min(self.queued_data.len());
        self.queued_data.drain(..n).collect()
    }

    /// Replace the queue with one payload that must stay whole — what `wait_for_more` holds.
    fn hold_as_one(&mut self, data: Vec<u8>) {
        self.queued_chunks.clear();
        if !data.is_empty() {
            self.queued_chunks.push_back(data.len());
        }
        self.queued_data = data;
    }
}

/// TCP server that listens for incoming connections
pub struct TcpServer;

impl TcpServer {
    /// Spawn the TCP server with integrated LLM actions
    pub async fn spawn_with_llm_actions(
        listen_addr: SocketAddr,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        send_first: bool,
        server_id: crate::state::ServerId,
        first_byte_timeout_secs: Option<u64>,
        idle_timeout_secs: Option<u64>,
    ) -> Result<SocketAddr> {
        let first_byte_timeout = first_byte_timeout_secs
            .map(Duration::from_secs)
            .unwrap_or(FIRST_BYTE_READ_TIMEOUT);
        let idle_timeout = idle_timeout_secs
            .map(Duration::from_secs)
            .unwrap_or(IDLE_BETWEEN_MESSAGES_TIMEOUT);
        // Create and bind TCP server
        let listener =
            crate::server::socket_helpers::create_reusable_tcp_listener(listen_addr).await?;
        let local_addr = listener.local_addr()?;
        Log::new(Some(&status_tx)).info(format!("TCP server listening on {}", local_addr));

        let connections = Arc::new(Mutex::new(HashMap::new()));
        let protocol = Arc::new(TcpProtocol::new());

        // Spawn accept loop
        let task_registrar = app_state.clone();
        let limiter = crate::server::accept_bounded::ConnectionLimiter::new(MAX_CONNECTIONS);
        let accept_handle = tokio::spawn(async move {
            loop {
                match crate::server::accept_bounded::accept_bounded(
                    &listener,
                    &limiter,
                    CONNECTION_CAP_REFUSAL,
                    "TCP",
                    Some(&status_tx),
                )
                .await
                {
                    Ok((stream, remote_addr, permit)) => {
                        let connection_id =
                            ConnectionId::new(app_state.get_next_unified_id().await);
                        let local_addr_conn = stream.local_addr().unwrap_or(local_addr);
                        info!("Accepted connection {} from {}", connection_id, remote_addr);

                        // Split stream
                        let (read_half, write_half) = tokio::io::split(stream);
                        let write_half_arc = Arc::new(Mutex::new(write_half));

                        // Whether this connection is doing work the peer is waiting on. The
                        // read deadline below consults it, so an LLM round-trip or a `manual`
                        // rule parked for a human can never be mistaken for an idle peer.
                        let activity =
                            Arc::new(crate::server::accept_bounded::ConnectionActivity::new());

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
                            protocol_info: ProtocolConnectionInfo::new(serde_json::json!({
                                "state": "Idle"
                            })),
                        };
                        app_state
                            .add_connection_to_server(server_id, conn_state)
                            .await;
                        let _ = status_tx.send("__UPDATE_UI__".to_string());

                        // Register the connection HERE, before either task is spawned.
                        //
                        // This used to be the first thing the banner task did, racing the
                        // reader task spawned immediately after it:
                        // handle_data_with_actions returns silently when the connection is
                        // not in the map, so a client that wrote before the server accepted
                        // (the normal case - connect() returns as soon as the kernel
                        // completes the handshake) lost that payload with no response, no
                        // error and no log line. Inserting synchronously in the accept loop
                        // closes the window: the reader task does not exist yet.
                        //
                        // A `send_first` server starts it in `Processing`: `tcp_connection_opened`
                        // is being answered, and anything the peer sends meanwhile queues behind
                        // it rather than raising a second, concurrent model call on the same
                        // connection. The connect task moves it to `Idle` and hands over the
                        // queue. Without `send_first` no connect event is raised, so it starts
                        // `Idle`.
                        connections.lock().await.insert(
                            connection_id,
                            ConnectionData {
                                state: if send_first {
                                    ConnectionState::Processing
                                } else {
                                    ConnectionState::Idle
                                },
                                queued_data: Vec::new(),
                                queued_chunks: Default::default(),
                                memory: String::new(),
                                write_half: write_half_arc.clone(),
                            },
                        );

                        // Peer messaging: the dashboard can inject an action into
                        // THIS connection (send_tcp_data through the same
                        // executor the model's actions use). The task ends when
                        // the handle is dropped — by the close paths below or by
                        // server teardown.
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

                        // Raise `tcp_connection_opened` only for a `send_first` server, where the
                        // peer is owed a greeting and nothing is read until it is on the wire.
                        //
                        // Raising it for every connection was measured and rejected: generic TCP
                        // is client-speaks-first, so a model-driven server paid one extra model
                        // call per connection to learn there was nothing to say, and the real-model
                        // eval showed the cost in behaviour as well as time - told to upper-case
                        // the client's text, llama3.1:8b answered the empty connect event with a
                        // greeting and the client's real answer arrived seconds later. A greeting
                        // is what `send_first` is for, and its description says so.
                        let (opened_tx, opened_rx) = tokio::sync::oneshot::channel::<()>();
                        // Dropped by the reader task on every exit path (EOF, error, deadline,
                        // abort), which tells the connect task its peer is gone.
                        let (reader_alive_tx, reader_alive_rx) =
                            tokio::sync::oneshot::channel::<()>();
                        if send_first {
                            let llm_client_clone = llm_client.clone();
                            let app_state_clone = app_state.clone();
                            let status_tx_clone = status_tx.clone();
                            let connections_clone = connections.clone();
                            let write_half_for_conn = write_half_arc.clone();
                            let protocol_clone = protocol.clone();
                            // The peer may be waiting to be greeted, so the first-byte deadline
                            // must not run while the model is answering the connect event.
                            let opened_busy = activity.busy();
                            // Tracked, not detached: it holds the write half and makes an LLM
                            // call, so a detached one keeps talking to a peer after the
                            // operator stopped the server.
                            let state_for_spawn = app_state.clone();
                            state_for_spawn
                                .spawn_server_task(server_id, async move {
                                    let _opened_busy = opened_busy;
                                    Self::handle_connection_opened(
                                        connection_id,
                                        server_id,
                                        send_first,
                                        opened_tx,
                                        reader_alive_rx,
                                        llm_client_clone,
                                        app_state_clone,
                                        status_tx_clone,
                                        connections_clone,
                                        write_half_for_conn,
                                        protocol_clone,
                                    )
                                    .await;
                                })
                                .await;
                        } else {
                            drop(opened_tx);
                            drop(reader_alive_rx);
                        }

                        // Spawn reader task
                        let llm_client_clone = llm_client.clone();
                        let app_state_clone = app_state.clone();
                        let status_tx_clone = status_tx.clone();
                        let connections_clone = connections.clone();
                        let protocol_clone = protocol.clone();
                        let activity_clone = activity.clone();
                        // The per-connection reader is registered with the server, so
                        // `stop_server` aborts it along with the accept loop. Registering
                        // prunes finished handles, so one entry per live connection is the
                        // steady state however many connections have come and gone.
                        //
                        // Without this, stopping released the listening socket and left every
                        // in-flight connection running: still reading, still answering, still
                        // spending LLM budget on a server the operator had stopped.
                        let state_for_reader = app_state.clone();
                        state_for_reader
                            .spawn_server_task(server_id, async move {
                                // Held for the life of the connection: releasing it here
                                // would cap the accept rate rather than the number of live
                                // connections.
                                let _permit = permit;
                                let _reader_alive = reader_alive_tx;
                                let mut buffer = vec![0u8; 8192];
                                let mut read_half = read_half;
                                let mut seen_bytes = false;

                                // `send_first`: nothing is read until the connect event has
                                // been answered, so the greeting is on the wire before the
                                // peer's first bytes are even looked at. Without it the read
                                // proceeds and anything that arrives queues behind the
                                // connect event instead (the connection starts `Processing`).
                                if send_first {
                                    let _ = opened_rx.await;
                                } else {
                                    drop(opened_rx);
                                }

                                loop {
                                    let bound = if seen_bytes {
                                        idle_timeout
                                    } else {
                                        first_byte_timeout
                                    };
                                    // The deadline wraps this read and nothing else.
                                    let read = match read_bounded(
                                        &mut read_half,
                                        &mut buffer,
                                        &activity_clone,
                                        bound,
                                    )
                                    .await
                                    {
                                        Some(result) => result,
                                        None => {
                                            connections_clone.lock().await.remove(&connection_id);
                                            app_state_clone
                                                .remove_peer_handle(
                                                    server_id,
                                                    connection_id.as_u32(),
                                                )
                                                .await;
                                            app_state_clone
                                                .close_connection_on_server(
                                                    server_id,
                                                    connection_id,
                                                )
                                                .await;
                                            Log::new(Some(&status_tx_clone)).info(format!(
                                                "Connection {connection_id} sent nothing for \
                                                 {}s; closing idle connection",
                                                bound.as_secs()
                                            ));
                                            let _ =
                                                status_tx_clone.send("__UPDATE_UI__".to_string());
                                            break;
                                        }
                                    };
                                    match read {
                                        Ok(0) => {
                                            // Connection closed
                                            connections_clone.lock().await.remove(&connection_id);
                                            app_state_clone
                                                .remove_peer_handle(
                                                    server_id,
                                                    connection_id.as_u32(),
                                                )
                                                .await;
                                            app_state_clone
                                                .close_connection_on_server(
                                                    server_id,
                                                    connection_id,
                                                )
                                                .await;
                                            Log::new(Some(&status_tx_clone))
                                                .info(format!("Connection {connection_id} closed"));
                                            let _ =
                                                status_tx_clone.send("__UPDATE_UI__".to_string());
                                            break;
                                        }
                                        Ok(n) => {
                                            seen_bytes = true;
                                            activity_clone.touch();
                                            let data = Bytes::copy_from_slice(&buffer[..n]);

                                            // Data summary + full payload. These are FileOnly:
                                            // the tcp_data_received event template renders the
                                            // equivalent lines to the TUI (see actions.rs), so
                                            // streaming the payload here too would duplicate it
                                            // and load the unbounded status channel.
                                            let log = Log::new(Some(&status_tx_clone));
                                            if data.iter().all(|&b| {
                                                b.is_ascii_graphic() || b.is_ascii_whitespace()
                                            }) {
                                                let data_str = String::from_utf8_lossy(&data);
                                                let preview = if data_str.len() > 100 {
                                                    format!("{}...", &data_str[..100])
                                                } else {
                                                    data_str.to_string()
                                                };
                                                log.debug(format!(
                                                    "TCP received {} bytes on {}: {}",
                                                    n, connection_id, preview
                                                ));
                                                log.trace(format!(
                                                    "TCP data (text): {:?}",
                                                    data_str
                                                ));
                                            } else {
                                                log.debug(format!(
                                                    "TCP received {} bytes on {} (binary data)",
                                                    n, connection_id
                                                ));
                                                log.trace(format!(
                                                    "TCP data (hex): {}",
                                                    hex::encode(&data)
                                                ));
                                            }

                                            // Keep the connection's counters live: the
                                            // dashboard and /status read these, and TCP
                                            // was the one server never updating them.
                                            app_state_clone
                                                .update_connection_stats(
                                                    server_id,
                                                    connection_id,
                                                    Some(n as u64),
                                                    None,
                                                    Some(1),
                                                    None,
                                                )
                                                .await;

                                            // Handle data in separate task
                                            let llm_clone = llm_client_clone.clone();
                                            let state_clone = app_state_clone.clone();
                                            let status_clone = status_tx_clone.clone();
                                            let conns_clone = connections_clone.clone();
                                            let protocol_clone = protocol_clone.clone();
                                            // The per-request handler makes the LLM call and
                                            // writes the reply, so it is the task that must not
                                            // outlive a stop.
                                            let state_for_data = app_state_clone.clone();
                                            // Busy for the whole of the answer — the LLM call,
                                            // a script, or a `manual` rule parked for a human —
                                            // so the read deadline above cannot close the
                                            // connection this is an answer for.
                                            let busy = activity_clone.busy();
                                            state_for_data
                                                .spawn_server_task(server_id, async move {
                                                    let _busy = busy;
                                                    Self::handle_data_with_actions(
                                                        connection_id,
                                                        server_id,
                                                        data,
                                                        llm_clone,
                                                        state_clone,
                                                        status_clone,
                                                        conns_clone,
                                                        protocol_clone,
                                                    )
                                                    .await;
                                                })
                                                .await;
                                        }
                                        Err(e) => {
                                            Log::new(Some(&status_tx_clone)).error(format!(
                                                "Read error on {}: {}",
                                                connection_id, e
                                            ));
                                            connections_clone.lock().await.remove(&connection_id);
                                            app_state_clone
                                                .remove_peer_handle(
                                                    server_id,
                                                    connection_id.as_u32(),
                                                )
                                                .await;
                                            break;
                                        }
                                    }
                                }
                            })
                            .await;
                    }
                    Err(e) => {
                        Log::new(Some(&status_tx)).error(format!("Accept error: {}", e));
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

    /// Answer `tcp_connection_opened` for a new connection, then release whatever the peer
    /// sent while it was being answered.
    ///
    /// The accept loop calls this only for a `send_first` server, whose peer is owed a greeting:
    /// no bytes is `decision=model_silent` (a warning), and a backend failure half-closes the
    /// connection, because the peer is waiting for something that is not coming. The branch for
    /// a server without `send_first` (no bytes is `decision=model_no_actions`, a failure is
    /// logged `decision=connect_event_failed`) is kept so the function stays correct if it is
    /// ever called for one.
    ///
    /// `opened` is signalled once the answer is on the wire; a `send_first` reader waits for it.
    /// `reader_alive` resolves when the reader task ends, and abandons the call: a peer that
    /// has already gone is not greeted.
    /// The connection is registered as `Processing` by the accept loop, so data that arrives
    /// meanwhile is queued; this moves it to `Idle` and processes that queue.
    #[allow(clippy::too_many_arguments)]
    async fn handle_connection_opened(
        connection_id: ConnectionId,
        server_id: crate::state::ServerId,
        send_first: bool,
        opened: tokio::sync::oneshot::Sender<()>,
        reader_alive: tokio::sync::oneshot::Receiver<()>,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        connections: Arc<Mutex<HashMap<ConnectionId, ConnectionData>>>,
        write_half: Arc<Mutex<tokio::io::WriteHalf<TcpStream>>>,
        protocol: Arc<TcpProtocol>,
    ) {
        let log = Log::new(Some(&status_tx));
        let event = Event::new(
            &TCP_CONNECTION_OPENED_EVENT,
            crate::protocol::event_type::connect_event_data(),
        );

        // A peer that connects and leaves before the connect event is answered has nobody
        // left to greet. The call is abandoned rather than finished, so a port scan against a
        // `send_first` server does not cost one model call per probe, each running on after its
        // socket was gone.
        let answer = tokio::select! {
            answer = call_llm(
                &llm_client,
                &app_state,
                server_id,
                Some(connection_id),
                &event,
                protocol.as_ref(),
            ) => answer,
            _ = reader_alive => {
                log.debug(format!(
                    "Connection {connection_id} closed before its connect event was answered: \
                     decision=peer_left_before_answer"
                ));
                return;
            }
        };

        match answer {
            Ok(execution_result) => {
                debug!("LLM TCP connect-event response received");
                for msg in execution_result.messages {
                    let _ = status_tx.send(msg);
                }

                let mut wrote = false;
                let mut close = false;
                for protocol_result in execution_result.protocol_results {
                    match protocol_result {
                        ActionResult::Output(output_data) => {
                            let mut write = write_half.lock().await;
                            if let Err(e) = write.write_all(&output_data).await {
                                log.error(format!("Failed to send greeting: {}", e));
                            } else if let Err(e) = write.flush().await {
                                log.error(format!("Failed to flush greeting: {}", e));
                            } else {
                                drop(write);
                                // Sent-data summary + payload are FileOnly: the send_tcp_data
                                // action template already reports the send to the TUI.
                                if output_data
                                    .iter()
                                    .all(|&b| b.is_ascii_graphic() || b.is_ascii_whitespace())
                                {
                                    let data_str = String::from_utf8_lossy(&output_data);
                                    log.debug(format!(
                                        "TCP sent {} bytes to {}: {}",
                                        output_data.len(),
                                        connection_id,
                                        crate::utils::truncate_for_log(&data_str, 100)
                                    ));
                                    log.trace(format!("TCP sent (text): {:?}", data_str));
                                } else {
                                    log.debug(format!(
                                        "TCP sent {} bytes to {} (binary data)",
                                        output_data.len(),
                                        connection_id
                                    ));
                                    log.trace(format!(
                                        "TCP sent (hex): {}",
                                        hex::encode(&output_data)
                                    ));
                                }
                                app_state
                                    .update_connection_stats(
                                        server_id,
                                        connection_id,
                                        None,
                                        Some(output_data.len() as u64),
                                        None,
                                        Some(1),
                                    )
                                    .await;
                                wrote = true;
                            }
                        }
                        ActionResult::CloseConnection => close = true,
                        _ => {}
                    }
                }

                if close {
                    {
                        let mut write = write_half.lock().await;
                        let _ = write.shutdown().await;
                    }
                    connections.lock().await.remove(&connection_id);
                    app_state
                        .close_connection_on_server(server_id, connection_id)
                        .await;
                    log.info(format!(
                        "Closed connection {connection_id} on connect: decision=model_close"
                    ));
                    let _ = opened.send(());
                    return;
                }

                if wrote {
                    log.debug(format!(
                        "Greeted {connection_id} on connect: decision=model_answer"
                    ));
                } else if send_first {
                    // Asked to speak first and said nothing: the peer sits at a blank
                    // connection. A real answer, but not the one send_first promised.
                    log.warn(format!(
                        "No greeting for {connection_id}: decision=model_silent (send_first \
                         was requested but the model produced no bytes)"
                    ));
                } else {
                    log.debug(format!(
                        "No greeting for {connection_id}: decision=model_no_actions"
                    ));
                }
            }
            Err(e) => {
                let failure = crate::utils::WireFailure::classify(&e);
                let class = if failure.is_overloaded() {
                    "overloaded"
                } else {
                    "unavailable"
                };
                if send_first {
                    // The full error goes to the log and the status stream, where an
                    // operator looks. Nothing derived from it reaches the peer.
                    log.warn(format!(
                        "TCP greeting failed for {connection_id}: decision=fail_closed_llm_error \
                         class={class} error={e}"
                    ));
                    // A send_first server owes this peer a greeting and now has none. Raw
                    // TCP has no error frame, so the only honest signal is FIN: half-close
                    // so the peer's next read returns EOF immediately instead of blocking
                    // until its own timeout. Same shape as the data path.
                    {
                        let mut write = write_half.lock().await;
                        let _ = write.shutdown().await;
                    }
                    connections.lock().await.remove(&connection_id);
                    app_state
                        .close_connection_on_server(server_id, connection_id)
                        .await;
                    log.info(format!(
                        "Closed connection {connection_id} after greeting LLM error"
                    ));
                    let _ = opened.send(());
                    return;
                }
                // Nobody asked this server to speak first, so the peer has been failed by
                // nothing yet: its own request will get the data path's answer (and the data
                // path's fail-closed, if the backend is still down).
                log.warn(format!(
                    "TCP connect event for {connection_id} failed: \
                     decision=connect_event_failed class={class} error={e}"
                ));
            }
        }

        let _ = opened.send(());

        // Hand over whatever arrived while the connect event was being answered.
        let queued = {
            let mut conns = connections.lock().await;
            let Some(conn) = conns.get_mut(&connection_id) else {
                return;
            };
            conn.state = ConnectionState::Idle;
            !conn.queued_data.is_empty()
        };
        if queued {
            Self::handle_data_with_actions(
                connection_id,
                server_id,
                Bytes::new(),
                llm_client,
                app_state,
                status_tx,
                connections,
                protocol,
            )
            .await;
        }
    }

    /// Handle data received on a connection with LLM actions
    #[allow(clippy::too_many_arguments)]
    async fn handle_data_with_actions(
        connection_id: ConnectionId,
        server_id: crate::state::ServerId,
        data: Bytes,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        connections: Arc<Mutex<HashMap<ConnectionId, ConnectionData>>>,
        protocol: Arc<TcpProtocol>,
    ) {
        let batching = app_state
            .server_conversation_settings(server_id)
            .await
            .is_some_and(|(_, batching)| batching);

        // Check connection state
        let current_state = {
            let conns = connections.lock().await;
            if let Some(conn_data) = conns.get(&connection_id) {
                conn_data.state.clone()
            } else {
                // Never silent. A miss here means the connection was torn down between the
                // read and this lookup (peer reset, or close_this_connection on another
                // task) - legitimate, but indistinguishable from a registration race, which
                // is exactly what made the bitcoin accept-order bug so hard to find: the
                // read loop logged "received N bytes" and then nothing at all.
                debug!(
                    "TCP connection {} is no longer registered; dropping {} received bytes",
                    connection_id,
                    data.len()
                );
                return;
            }
        };

        // If processing, queue the data — up to MAX_QUEUED_BYTES.
        if current_state == ConnectionState::Processing {
            let (queued_len, write_half) = {
                let mut conns = connections.lock().await;
                let Some(conn) = conns.get_mut(&connection_id) else {
                    return; // Connection closed while we were waiting for the lock
                };
                conn.queue(&data);
                (conn.queued_data.len(), conn.write_half.clone())
            };

            let log = Log::new(Some(&status_tx));
            if queued_len > MAX_QUEUED_BYTES {
                log.warn(format!(
                    "Connection {connection_id} queued {queued_len} bytes while awaiting a \
                     response (limit {MAX_QUEUED_BYTES}); closing: decision=queue_overflow"
                ));
                // Same signal as every other server-side close on raw TCP: FIN, so the peer
                // reads EOF now instead of blocking on an answer that is never coming.
                {
                    let mut write = write_half.lock().await;
                    let _ = write.shutdown().await;
                }
                connections.lock().await.remove(&connection_id);
                app_state
                    .close_connection_on_server(server_id, connection_id)
                    .await;
                let _ = status_tx.send("__UPDATE_UI__".to_string());
                return;
            }

            log.debug(format!(
                "Queued {} bytes for {} ({} queued)",
                data.len(),
                connection_id,
                queued_len
            ));
            return;
        }

        // Merge any queued data with new data.
        //
        // The lock was released after the state check above, so the reader task may have
        // removed this connection in the meantime - a client that writes and immediately
        // closes does exactly that. Unwrapping here panicked the task on that race (15 of 64
        // such clients in a burst), and a panicked socket task is silent while the server
        // still reports Running.
        let mut all_data = {
            let mut conns = connections.lock().await;
            let Some(conn_data) = conns.get_mut(&connection_id) else {
                return; // Connection closed while we were waiting for the lock
            };
            conn_data.state = ConnectionState::Processing;
            // Bytes held for `wait_for_more` are one message with whatever completes it, so
            // they are always taken whole; otherwise batching decides.
            let take_all = batching || current_state == ConnectionState::Accumulating;
            conn_data.queue(&data);
            Bytes::from(conn_data.take_next(take_all))
        };

        loop {
            // Get memory
            let memory = {
                let conns = connections.lock().await;
                conns
                    .get(&connection_id)
                    .map(|c| c.memory.clone())
                    .unwrap_or_default()
            };

            // Get write_half for context
            let write_half = {
                let conns = connections.lock().await;
                conns.get(&connection_id).map(|c| c.write_half.clone())
            };

            let Some(write_half) = write_half else {
                debug!(
                    "TCP connection {} went away before its response could be written",
                    connection_id
                );
                return;
            };

            // Format data for event parameter. Printable ASCII is passed through as text,
            // anything else is hex-encoded. `encoding` tells the LLM which one it got, so it
            // can echo the payload back with a matching `encoding` on send_tcp_data.
            let (data_str, data_encoding) = if all_data
                .iter()
                .all(|&b| b.is_ascii_graphic() || b.is_ascii_whitespace())
            {
                (String::from_utf8_lossy(&all_data).to_string(), "utf8")
            } else {
                (hex::encode(&all_data), "hex")
            };

            // Create data received event
            let event = Event::new(
                &TCP_DATA_RECEIVED_EVENT,
                serde_json::json!({
                    "data": data_str,
                    "encoding": data_encoding
                }),
            );

            // Call LLM
            match call_llm(
                &llm_client,
                &app_state,
                server_id,
                Some(connection_id),
                &event,
                protocol.as_ref(),
            )
            .await
            {
                Ok(execution_result) => {
                    let log = Log::new(Some(&status_tx));
                    debug!("LLM TCP response received");

                    // Update memory
                    connections
                        .lock()
                        .await
                        .entry(connection_id)
                        .and_modify(|conn| conn.memory = memory.clone());

                    // Display messages
                    for msg in execution_result.messages {
                        let _ = status_tx.send(msg);
                    }

                    // Handle protocol results
                    let mut should_close = false;
                    let mut should_wait = false;
                    let mut wrote_output = false;

                    for protocol_result in execution_result.protocol_results {
                        match protocol_result {
                            ActionResult::Output(output_data) => {
                                let mut write = write_half.lock().await;
                                if let Err(e) = write.write_all(&output_data).await {
                                    log.error(format!("Failed to send response: {}", e));
                                } else if let Err(e) = write.flush().await {
                                    log.error(format!("Failed to flush response: {}", e));
                                } else {
                                    // Sent-data summary + payload are FileOnly: the
                                    // send_tcp_data action template already reports the
                                    // send to the TUI (see actions.rs).
                                    if output_data
                                        .iter()
                                        .all(|&b| b.is_ascii_graphic() || b.is_ascii_whitespace())
                                    {
                                        let data_str = String::from_utf8_lossy(&output_data);
                                        let preview = if data_str.len() > 100 {
                                            format!("{}...", &data_str[..100])
                                        } else {
                                            data_str.to_string()
                                        };
                                        log.debug(format!(
                                            "TCP sent {} bytes to {}: {}",
                                            output_data.len(),
                                            connection_id,
                                            preview
                                        ));
                                        log.trace(format!("TCP sent (text): {:?}", data_str));
                                    } else {
                                        log.debug(format!(
                                            "TCP sent {} bytes to {} (binary data)",
                                            output_data.len(),
                                            connection_id
                                        ));
                                        log.trace(format!(
                                            "TCP sent (hex): {}",
                                            hex::encode(&output_data)
                                        ));
                                    }
                                    log.debug(format!(
                                        "Sent {} bytes to {}",
                                        output_data.len(),
                                        connection_id
                                    ));
                                    app_state
                                        .update_connection_stats(
                                            server_id,
                                            connection_id,
                                            None,
                                            Some(output_data.len() as u64),
                                            None,
                                            Some(1),
                                        )
                                        .await;
                                    wrote_output = true;
                                }
                            }
                            ActionResult::CloseConnection => {
                                should_close = true;
                            }
                            ActionResult::WaitForMore => {
                                should_wait = true;
                            }
                            _ => {}
                        }
                    }

                    // Handle wait_for_more.
                    //
                    // The fragment the model was just shown goes back to the *head* of the
                    // queue, ahead of anything that arrived during the call. `wait_for_more`
                    // means "these bytes are an incomplete message"; dropping them was the one
                    // thing that could not be right, because the model would never be shown the
                    // front of the message again and could only reassemble it by having copied
                    // it into memory first. Now the accumulation the action's name promises
                    // actually happens.
                    if should_wait {
                        let (queued_len, arrived_during_call, write_half_for_close) = {
                            let mut conns = connections.lock().await;
                            let Some(conn) = conns.get_mut(&connection_id) else {
                                return;
                            };
                            let arrived_during_call = !conn.queued_data.is_empty();
                            let mut merged = all_data.to_vec();
                            merged.append(&mut conn.queued_data);
                            conn.hold_as_one(merged);
                            conn.state = ConnectionState::Accumulating;
                            (
                                conn.queued_data.len(),
                                arrived_during_call,
                                conn.write_half.clone(),
                            )
                        };

                        // Same bound as the Processing queue: a model that answers
                        // `wait_for_more` to everything must not be a way to grow memory
                        // without limit either.
                        if queued_len > MAX_QUEUED_BYTES {
                            log.warn(format!(
                                "Connection {connection_id} accumulated {queued_len} bytes across \
                                 wait_for_more (limit {MAX_QUEUED_BYTES}); closing: \
                                 decision=queue_overflow"
                            ));
                            {
                                let mut write = write_half_for_close.lock().await;
                                let _ = write.shutdown().await;
                            }
                            connections.lock().await.remove(&connection_id);
                            app_state
                                .close_connection_on_server(server_id, connection_id)
                                .await;
                            let _ = status_tx.send("__UPDATE_UI__".to_string());
                            return;
                        }

                        // If bytes arrived while the model was thinking, they *are* the "more"
                        // it asked for. Returning here would park them until the next read,
                        // which may never come — the peer has sent its whole message and is
                        // waiting for us. Go round again with the joined payload instead.
                        if arrived_during_call {
                            let joined = {
                                let mut conns = connections.lock().await;
                                let Some(conn) = conns.get_mut(&connection_id) else {
                                    return;
                                };
                                conn.state = ConnectionState::Processing;
                                conn.take_next(true)
                            };
                            log.debug(format!(
                                "wait_for_more on {connection_id}: {} bytes already waiting, \
                                 continuing",
                                joined.len()
                            ));
                            all_data = Bytes::from(joined);
                            continue;
                        }

                        log.debug(format!(
                            "Waiting for more data from {connection_id} ({queued_len} bytes held)"
                        ));
                        return;
                    }

                    // Handle close_connection
                    if should_close {
                        connections.lock().await.remove(&connection_id);
                        // The model answered by hanging up — distinct in the log from
                        // "answered nothing" and from an LLM failure.
                        log.info(format!(
                            "Closed connection {connection_id}: decision=model_close"
                        ));
                        return;
                    }

                    // The model answered, but with no bytes and no lifecycle action.
                    // On raw TCP that is a legitimate answer ("say nothing, keep
                    // listening"), so the connection stays open — but it must not be
                    // confused with the backend having failed.
                    if !wrote_output {
                        log.debug(format!(
                            "No response bytes for {connection_id}: decision=model_no_actions"
                        ));
                    }

                    // Check for queued data
                    let has_queued = {
                        let conns = connections.lock().await;
                        conns
                            .get(&connection_id)
                            .map(|c| !c.queued_data.is_empty())
                            .unwrap_or(false)
                    };

                    if has_queued {
                        // Take the queue and make it the next iteration's payload.
                        // Leaving it in place re-sent the SAME bytes to the model on
                        // every pass and never emptied the queue: one response per
                        // iteration, forever, for a single line of input.
                        let queued = {
                            let mut conns = connections.lock().await;
                            match conns.get_mut(&connection_id) {
                                Some(conn) => conn.take_next(batching),
                                None => return,
                            }
                        };
                        if queued.is_empty() {
                            connections
                                .lock()
                                .await
                                .entry(connection_id)
                                .and_modify(|conn| conn.state = ConnectionState::Idle);
                            return;
                        }
                        all_data = Bytes::from(queued);
                    } else {
                        // Go to Idle state
                        connections
                            .lock()
                            .await
                            .entry(connection_id)
                            .and_modify(|conn| conn.state = ConnectionState::Idle);
                        return;
                    }
                }
                Err(e) => {
                    let log = Log::new(Some(&status_tx));
                    let failure = crate::utils::WireFailure::classify(&e);
                    let class = if failure.is_overloaded() {
                        "overloaded"
                    } else {
                        "unavailable"
                    };
                    // Full error to the log/status stream only — never to the peer.
                    log.warn(format!(
                        "LLM error for TCP data on {connection_id}: decision=fail_closed_llm_error class={class} error={e}"
                    ));

                    // Say *something* on the wire. Raw TCP has no error frame, so
                    // the only honest signal is FIN: half-close the connection so
                    // the peer's next read returns EOF immediately.
                    //
                    // This path used to reset the state to Idle and write
                    // nothing, which left the peer blocked until its own timeout
                    // with no indication anything had gone wrong — the visible
                    // half of the concurrency-drop bug, and the same shape as the
                    // "reset to Idle and write nothing" pattern noted in
                    // CLAUDE.md's known systemic issues.
                    if failure.is_overloaded() {
                        log.warn(format!(
                            "TCP connection {} closed: LLM capacity exhausted",
                            connection_id
                        ));
                    }
                    {
                        let mut write = write_half.lock().await;
                        let _ = write.shutdown().await;
                    }
                    connections.lock().await.remove(&connection_id);
                    app_state
                        .close_connection_on_server(server_id, connection_id)
                        .await;
                    log.info(format!("Closed connection {connection_id} after LLM error"));
                    return;
                }
            }
        }
    }
}

/// Send data on a TCP connection
pub async fn send_data(stream: &mut TcpStream, data: &[u8]) -> Result<()> {
    stream
        .write_all(data)
        .await
        .context("Failed to write data")?;
    stream.flush().await.context("Failed to flush stream")?;
    Ok(())
}
