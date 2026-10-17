//! TLS server implementation
//!
//! Provides a generic TLS transport layer that allows the LLM to implement
//! custom application protocols on top of encrypted connections.

pub mod actions;

use anyhow::{Context, Result};
use bytes::Bytes;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info};

use super::connection::ConnectionId;
use crate::llm::action_helper::call_llm;
use crate::llm::ollama_client::OllamaClient;
use crate::llm::ActionResult;
use crate::logging::emit::Log;
use crate::protocol::Event;
use crate::server::TlsProtocol;
use crate::state::app_state::AppState;
use crate::utils::WireFailure;
use actions::{TLS_CONNECTION_OPENED_EVENT, TLS_DATA_RECEIVED_EVENT};

/// How long a peer has to complete the TLS handshake.
///
/// **One constant used to govern this wait and the wait for the first application record**, on
/// the reasoning that from the peer's side they are one condition: it holds a socket and has
/// produced nothing usable. They are not one condition, because they face different peers.
/// This one faces a peer that has opened a TCP socket and not yet sent a ClientHello; the
/// other faces a peer that has *completed* a handshake. A single number cannot be right for
/// both, and the number that was right here was wrong there.
///
/// Nothing on this side of the split has changed. `acceptor.accept()` was once unbounded, so a
/// peer that connected and never sent a ClientHello held a task and a rustls state machine for
/// as long as it liked — cheaper for an attacker than a completed connection. Every real
/// client sends ClientHello immediately and finishes in one round-trip, and NetGet's own TLS
/// client is no exception: `src/client/tls/mod.rs` runs `TlsConnector::connect` inside its own
/// `connect()`, before any model turn or keystroke, so a minute is far beyond what any peer
/// worth waiting for needs, even on a bad link. Nothing in this phase involves the model, so
/// the deadline may cover the whole of it.
///
/// Overridable per server with `handshake_timeout_secs`.
const HANDSHAKE_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// How long a handshaked peer has to send its first *application* record.
///
/// **This was [`HANDSHAKE_READ_TIMEOUT`]'s 60 seconds, and the peer it faces is a different
/// one.** The handshake is done here: the peer has proved it speaks TLS and has paid for a
/// rustls state machine of its own. What it has not done is say anything on top — and TLS is a
/// carrier, so whether it *should* have by now is a property of the application riding on it,
/// which this server does not know.
///
/// What it does know is who is usually there. `src/client/tls/mod.rs` completes the handshake
/// inside `connect()` and then writes **no application bytes at all** unprompted: every byte
/// comes from an action, and a client created from the dashboard's `[ + tls client ]` is
/// routed `tls_client_connected` → static-with-no-actions and then `*` → manual
/// (`src/tui/modal/form.rs`). So it connects, handshakes, is answered with nothing, and waits
/// for a person to type into `[ send message ]`. At 60 seconds this server hung up on the
/// operator's own client while they were still looking at it — and, unlike the handshake
/// phase, there was nothing the peer could have done about it.
///
/// 300 seconds is the window a `manual` rule gives a human to answer one event
/// (`src/state/intercepts.rs`), which is the number this product already uses for how long
/// someone might take, and it is also this server's own [`IDLE_AFTER_DATA_TIMEOUT`] — so a
/// hand-driven session is now bounded the same way before its first record as after it.
///
/// What it costs: a peer that completed a handshake and then said nothing holds a socket, a
/// task, an `AppState` row and one of [`MAX_CONNECTIONS`] slots for 300 seconds rather than
/// 60 — a fivefold rise in how long one such slot is held, not a removal of the bound, and a
/// peer over the cap is still answered [`CONNECTION_CAP_REFUSAL`]. Note that it is also
/// strictly more expensive for the attacker than the handshake phase, which is untouched: to
/// reach this bound at all it must complete a real TLS handshake. A listener exposed to
/// strangers should set `first_byte_timeout_secs` low; 60 is the old value and remains a sound
/// choice for one.
const FIRST_RECORD_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

/// The three read deadlines for one listener, resolved from its startup parameters.
///
/// Carried as one value so threading them from `spawn_with_llm_actions` into the connection
/// task costs one argument rather than three.
#[derive(Clone, Copy)]
struct ReadDeadlines {
    /// [`HANDSHAKE_READ_TIMEOUT`], or this server's `handshake_timeout_secs`.
    handshake: std::time::Duration,
    /// [`FIRST_RECORD_READ_TIMEOUT`], or this server's `first_byte_timeout_secs`.
    first_byte: std::time::Duration,
    /// [`IDLE_AFTER_DATA_TIMEOUT`], or this server's `idle_timeout_secs`.
    idle: std::time::Duration,
}

impl ReadDeadlines {
    fn resolve(
        handshake_secs: Option<u64>,
        first_byte_secs: Option<u64>,
        idle_secs: Option<u64>,
    ) -> Self {
        Self {
            handshake: handshake_secs
                .map(std::time::Duration::from_secs)
                .unwrap_or(HANDSHAKE_READ_TIMEOUT),
            first_byte: first_byte_secs
                .map(std::time::Duration::from_secs)
                .unwrap_or(FIRST_RECORD_READ_TIMEOUT),
            idle: idle_secs
                .map(std::time::Duration::from_secs)
                .unwrap_or(IDLE_AFTER_DATA_TIMEOUT),
        }
    }
}

/// How long to wait for a *further* record once the peer has sent application data.
///
/// TLS is a carrier, not an application: whatever rides on it decides what "idle" means, and
/// this server cannot know. Five minutes is therefore chosen to sit well above any
/// request/response turnaround an operator would run over it and well below an unbounded hold.
/// Because the clock counts only *silence* — see the `activity` check at the read site — a peer
/// waiting on a slow answer of ours is never counted against it.
///
/// Overridable per server with `idle_timeout_secs`, for the same reason the two before it are:
/// the right value is a property of whatever rides on this carrier, and only the operator
/// knows that.
const IDLE_AFTER_DATA_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

/// Concurrent connections this server admits.
const MAX_CONNECTIONS: usize = crate::server::accept_bounded::DEFAULT_MAX_CONNECTIONS;

/// Most application data this server will hold for one connection while an answer is in flight.
///
/// `ConnectionData::queued_data` exists because a peer may keep writing while the model is
/// being asked what to say — the Idle → Processing → Accumulating machine every protocol here
/// hand-rolls. It had no ceiling, so the peer decided how much memory one connection cost, and
/// it decided it *while the answer it is waiting for has not arrived*: the window is a whole
/// LLM round-trip, or, where a `manual` rule parks the record for a human
/// (`src/state/intercepts.rs`), **300 seconds by default**, times
/// [`MAX_CONNECTIONS`]. Neither authentication nor a model call stands in front of it: the
/// first record a stranger sends opens the window.
///
/// 1 MiB is 64 maximum-size TLS records (RFC 8446 caps a plaintext record at 2^14 bytes), and
/// the number is taken from the protocol's own framing rather than from a guess about the
/// application: the queue holds what arrived *while one answer was being composed*, and sixty
/// four full records is already far more than any request a model is going to be asked to read.
/// Past that the peer is not waiting for an answer, it is filling memory.
pub const MAX_QUEUED_BYTES: usize = 1024 * 1024;

/// How many further octets are read and **discarded** after the queue cap is exceeded, so the
/// peer can finish writing and then read the alert.
///
/// A peer refused here is by definition mid-stream. Closing a socket with unread data in the
/// receive queue sends `RST`, which discards the bytes already written along with it — so the
/// close_notify record below would never arrive and the peer would see a bare connection reset
/// instead. This is nginx's `lingering_close`; nothing is buffered, the octets are counted and
/// dropped, and a peer that keeps writing past either bound gets the abrupt close it earned.
const LINGER_DRAIN_BYTES: usize = 8 * 1024 * 1024;

/// Wall-clock bound on that drain, so a peer trickling one octet at a time cannot hold the
/// connection open by staying under [`LINGER_DRAIN_BYTES`].
const LINGER_DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// What a peer over [`MAX_CONNECTIONS`] is told before the socket closes.
///
/// A plaintext fatal alert record: content type 21 (alert), legacy record version 0x0303,
/// length 2, level `fatal`(2), description `internal_error`(80). TLS defines no "server busy"
/// alert — RFC 8446's closest is `internal_error`, which is what a server sends when it cannot
/// proceed for reasons unrelated to the peer — so that is the honest choice. A client reports
/// "received fatal alert: internal_error" instead of a bare connection reset, which is the
/// difference between an operator having a reason and guessing at one.
const CONNECTION_CAP_REFUSAL: &[u8] = &[0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x50];

/// The `decision=` token for an LLM call that returned `Err`.
///
/// TLS has exactly one failure shape on the wire - a close_notify alert - so an overloaded
/// backend and a broken one cannot be told apart by the peer. They are told apart in the log
/// instead: the token is stable, so `grep 'decision=fail_closed_'` finds every connection that
/// was hung up on because nothing usable was produced, and the `_overloaded` suffix marks the
/// transient half. The error itself is logged, never written to the socket.
fn llm_error_decision(err: &anyhow::Error) -> &'static str {
    match WireFailure::classify(err) {
        WireFailure::Overloaded => "fail_closed_llm_error_overloaded",
        WireFailure::Unavailable => "fail_closed_llm_error_unavailable",
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
    write_half: Arc<Mutex<tokio::io::WriteHalf<tokio_rustls::server::TlsStream<TcpStream>>>>,
}

impl ConnectionData {
    /// Queue a read that arrived while the model was answering. The caller has already
    /// checked [`MAX_QUEUED_BYTES`].
    fn queue(&mut self, data: &[u8]) {
        if !data.is_empty() {
            self.queued_data.extend_from_slice(data);
            self.queued_chunks.push_back(data.len());
        }
    }

    /// What the next call answers: the whole queue when batching, else the oldest read.
    ///
    /// The decrypted stream has no message boundaries, so batching is what TLS always did —
    /// everything that arrived during a call is the next call's payload. With it off, each
    /// read the socket delivered (in practice one TLS record each) is answered on its own, in
    /// order. The same shape as `tcp`.
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

/// TLS server that listens for incoming connections
pub struct TlsServer;

impl TlsServer {
    /// Spawn the TLS server with integrated LLM actions
    #[allow(clippy::too_many_arguments)]
    pub async fn spawn_with_llm_actions(
        listen_addr: SocketAddr,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        send_first: bool,
        server_id: crate::state::ServerId,
        tls_config: Option<Arc<rustls::ServerConfig>>,
        handshake_timeout_secs: Option<u64>,
        first_byte_timeout_secs: Option<u64>,
        idle_timeout_secs: Option<u64>,
    ) -> Result<SocketAddr> {
        // All three bounds are tunable because their right value is a property of who is on
        // the other end and what rides on this carrier, which only the operator knows. The
        // first-record default serves NetGet's own TLS client waiting on a human; a listener
        // exposed to strangers wants it much lower.
        let deadlines = ReadDeadlines::resolve(
            handshake_timeout_secs,
            first_byte_timeout_secs,
            idle_timeout_secs,
        );
        // Create TLS configuration (use provided or generate default)
        let tls_config = if let Some(config) = tls_config {
            config
        } else {
            crate::server::tls_cert_manager::generate_default_tls_config()
                .context("Failed to generate TLS configuration")?
        };

        // Create and bind TCP listener
        let listener = TcpListener::bind(listen_addr)
            .await
            .context("Failed to bind TLS TCP listener")?;
        let local_addr = listener.local_addr()?;
        Log::new(Some(&status_tx)).info(format!(
            "TLS server (action-based) listening on {}",
            local_addr
        ));

        let connections = Arc::new(Mutex::new(HashMap::new()));
        let protocol = Arc::new(TlsProtocol::new());
        let acceptor = TlsAcceptor::from(tls_config);

        // Spawn accept loop
        let task_registrar = app_state.clone();
        let limiter = crate::server::accept_bounded::ConnectionLimiter::new(MAX_CONNECTIONS);
        let accept_handle = tokio::spawn(async move {
            loop {
                match crate::server::accept_bounded::accept_bounded(
                    &listener,
                    &limiter,
                    CONNECTION_CAP_REFUSAL,
                    "TLS",
                    Some(&status_tx),
                )
                .await
                {
                    Ok((stream, remote_addr, permit)) => {
                        let connection_id =
                            ConnectionId::new(app_state.get_next_unified_id().await);
                        let local_addr_conn = stream.local_addr().unwrap_or(local_addr);
                        debug!("TLS TCP connection from {}", remote_addr);

                        let acceptor = acceptor.clone();
                        let llm_client_clone = llm_client.clone();
                        let app_state_clone = app_state.clone();
                        let status_tx_clone = status_tx.clone();
                        let connections_clone = connections.clone();
                        let protocol_clone = protocol.clone();

                        // Tracked, not detached: stop_server must abort this task too.
                        let task_owner = app_state.clone();
                        task_owner
                            .spawn_server_task(server_id, async move {
                                // Held for the life of the connection, so the cap counts live
                                // peers rather than accepts.
                                let _permit = permit;

                                // Perform TLS handshake, bounded. This awaits the peer's
                                // ClientHello and the rest of its side of the handshake; nothing in
                                // it involves the model, so the deadline may cover the whole of it.
                                let handshake = tokio::time::timeout(
                                    deadlines.handshake,
                                    acceptor.accept(stream),
                                );
                                let tls_stream = match handshake.await {
                                    Err(_) => {
                                        Log::new(Some(&status_tx_clone)).warn(format!(
                                            "TLS handshake with {} produced nothing within {}s; \
                                         closing",
                                            remote_addr,
                                            deadlines.handshake.as_secs()
                                        ));
                                        return;
                                    }
                                    Ok(Ok(stream)) => stream,
                                    Ok(Err(e)) => {
                                        // Handshake failure ends this connection but is a
                                        // client-side condition, not a server error: WARN.
                                        Log::new(Some(&status_tx_clone)).warn(format!(
                                            "TLS handshake failed with {}: {}",
                                            remote_addr, e
                                        ));
                                        return;
                                    }
                                };

                                Log::new(Some(&status_tx_clone))
                                    .debug(format!("TLS handshake complete with {}", remote_addr));

                                info!(
                                    "Accepted TLS connection {} from {}",
                                    connection_id, remote_addr
                                );

                                // Split stream
                                let (read_half, write_half) = tokio::io::split(tls_stream);
                                let write_half_arc = Arc::new(Mutex::new(write_half));

                                // TLS is the one server here whose read loop runs *concurrently*
                                // with the answer: `handle_data_with_actions` is spawned and the
                                // loop goes straight back to reading. So a peer whose record is
                                // parked for a human, or is waiting on the model, sits inside the
                                // read deadline while that happens — and closing it there would be
                                // exactly the live-transfer eviction this project learned about
                                // from TFTP. This tracks work in flight so the read site can tell
                                // "the peer is silent" from "the peer is waiting for us".
                                let activity = Arc::new(
                                    crate::server::accept_bounded::ConnectionActivity::new(),
                                );

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
                                        "state": "Idle",
                                        "tls_handshake": "complete"
                                    })),
                                };
                                app_state_clone
                                    .add_connection_to_server(server_id, conn_state)
                                    .await;
                                let _ = status_tx_clone.send("__UPDATE_UI__".to_string());

                                // Register the connection HERE, before either task is spawned.
                                //
                                // This used to be the first thing the banner task did, racing the
                                // reader task spawned immediately after it, and
                                // handle_data_with_actions returns silently when the connection
                                // is not in the map. TLS loses that race almost every time: the
                                // handshake reads from the socket, so application data sent right
                                // behind the client's Finished is already buffered inside rustls
                                // and the reader's first read() returns it without ever waiting on
                                // the I/O driver. 15 of 16 clients that wrote at handshake
                                // completion had their request dropped with no response and no log
                                // line.
                                // A `send_first` server registers it `Processing`:
                                // `tls_connection_opened` is being answered, and application data
                                // that arrives meanwhile queues behind it instead of raising a
                                // concurrent model call. Without `send_first` no connect event is
                                // raised, so it starts `Idle`.
                                connections_clone.lock().await.insert(
                                    connection_id,
                                    ConnectionData {
                                        state: if send_first {
                                            ConnectionState::Processing
                                        } else {
                                            ConnectionState::Idle
                                        },
                                        queued_data: Vec::new(),
                                        queued_chunks: Default::default(),
                                        write_half: write_half_arc.clone(),
                                    },
                                );

                                // Peer messaging: the dashboard's "message this peer" /
                                // "disconnect this peer" inject actions into THIS connection
                                // through the same executor the LLM path uses, and the bytes
                                // go out over the same `Arc<Mutex<WriteHalf<TlsStream>>>` the
                                // session writes through - so an injected `send_tls_data` is
                                // encrypted by rustls exactly like a modelled one.
                                //
                                // Registered here, before the banner task and before the
                                // reader, for the same reason the connection map entry is:
                                // a `manual` rule can park the very first record for a human
                                // (300s by default), and that is precisely the window in
                                // which an operator needs to reach the peer. Registering it
                                // from inside the reader would lose the same race the
                                // comment above describes.
                                let peer_rx = crate::server::peer_support::register_peer_channel(
                                    &app_state_clone,
                                    server_id,
                                    connection_id.as_u32(),
                                )
                                .await;
                                crate::server::peer_support::spawn_peer_command_task(
                                    peer_rx,
                                    protocol_clone.clone(),
                                    app_state_clone.clone(),
                                    server_id,
                                    connection_id.as_u32(),
                                    write_half_arc.clone(),
                                    status_tx_clone.clone(),
                                );

                                // `tls_connection_opened` is raised only for a `send_first`
                                // server, as `tcp_connection_opened` is: the peer is owed a
                                // greeting and nothing is read until the event is answered. A
                                // server that speaks second pays no model call per connection.
                                // See `handle_connection_opened`.
                                let (opened_tx, opened_rx) = tokio::sync::oneshot::channel::<()>();
                                // Dropped by the reader on every exit path, which tells the
                                // connect task its peer is gone.
                                let (reader_alive_tx, reader_alive_rx) =
                                    tokio::sync::oneshot::channel::<()>();
                                if send_first {
                                    let llm_client_for_conn = llm_client_clone.clone();
                                    let app_state_for_conn = app_state_clone.clone();
                                    let status_tx_for_conn = status_tx_clone.clone();
                                    let connections_for_conn = connections_clone.clone();
                                    let write_half_for_conn = write_half_arc.clone();
                                    let protocol_for_conn = protocol_clone.clone();
                                    let opened_busy = activity.busy();
                                    // Tracked, not detached: stop_server must abort this task too.
                                    let task_owner = app_state_clone.clone();
                                    task_owner
                                        .spawn_server_task(server_id, async move {
                                            let _opened_busy = opened_busy;
                                            Self::handle_connection_opened(
                                                connection_id,
                                                server_id,
                                                send_first,
                                                opened_tx,
                                                reader_alive_rx,
                                                llm_client_for_conn,
                                                app_state_for_conn,
                                                status_tx_for_conn,
                                                connections_for_conn,
                                                write_half_for_conn,
                                                protocol_for_conn,
                                            )
                                            .await;
                                        })
                                        .await;
                                } else {
                                    drop(opened_tx);
                                    drop(reader_alive_rx);
                                }

                                // Spawn reader task
                                let llm_client_for_read = llm_client_clone.clone();
                                let app_state_for_read = app_state_clone.clone();
                                let status_tx_for_read = status_tx_clone.clone();
                                let connections_for_read = connections_clone.clone();
                                let protocol_for_read = protocol_clone.clone();
                                let activity_for_read = Arc::clone(&activity);
                                // The reader decides the queue cap, so it needs the write half
                                // to say so: the refusal is a TLS record, and rustls will only
                                // produce one through this stream.
                                let write_half_for_read = write_half_arc.clone();
                                // Tracked, not detached: stop_server must abort this task too.
                                let task_owner = app_state_clone.clone();
                                task_owner
                                    .spawn_server_task(server_id, async move {
                                        let _reader_alive = reader_alive_tx;
                                        let mut buffer = vec![0u8; 8192];
                                        let mut read_half = read_half;
                                        let mut seen_data = false;

                                        // `send_first`: nothing is read until the connect event
                                        // has been answered. Otherwise reads proceed and queue
                                        // behind it (the connection starts `Processing`).
                                        if send_first {
                                            let _ = opened_rx.await;
                                        } else {
                                            drop(opened_rx);
                                        }

                                        loop {
                                            let read_timeout = if seen_data {
                                                deadlines.idle
                                            } else {
                                                deadlines.first_byte
                                            };
                                            // Re-arm rather than close whenever the deadline expires
                                            // while an answer is still being produced: a peer waiting
                                            // on us is not idle.
                                            let read = loop {
                                                match tokio::time::timeout(
                                                    read_timeout,
                                                    read_half.read(&mut buffer),
                                                )
                                                .await
                                                {
                                                    Ok(read) => break Some(read),
                                                    Err(_) => {
                                                        if activity_for_read.idle_for().is_none() {
                                                            continue;
                                                        }
                                                        Log::new(Some(&status_tx_for_read)).info(
                                                            format!(
                                                    "TLS connection {connection_id} sent nothing \
                                                     for {}s; closing idle connection",
                                                    read_timeout.as_secs()
                                                ),
                                                        );
                                                        break None;
                                                    }
                                                }
                                            };
                                            let Some(read) = read else {
                                                connections_for_read
                                                    .lock()
                                                    .await
                                                    .remove(&connection_id);
                                                app_state_for_read
                                                    .close_connection_on_server(
                                                        server_id,
                                                        connection_id,
                                                    )
                                                    .await;
                                                let _ = status_tx_for_read
                                                    .send("__UPDATE_UI__".to_string());
                                                break;
                                            };
                                            match read {
                                                Ok(0) => {
                                                    // Connection closed
                                                    connections_for_read
                                                        .lock()
                                                        .await
                                                        .remove(&connection_id);
                                                    app_state_for_read
                                                        .close_connection_on_server(
                                                            server_id,
                                                            connection_id,
                                                        )
                                                        .await;
                                                    Log::new(Some(&status_tx_for_read)).info(
                                                        format!(
                                                            "TLS connection {connection_id} closed"
                                                        ),
                                                    );
                                                    let _ = status_tx_for_read
                                                        .send("__UPDATE_UI__".to_string());
                                                    break;
                                                }
                                                Ok(n) => {
                                                    seen_data = true;

                                                    // Bound the queue **before** these bytes are
                                                    // handed to anything that would keep them.
                                                    // The size compared is the one the peer has
                                                    // already committed to — what is queued plus
                                                    // what this read delivered — not what is left
                                                    // over after some part of it has been
                                                    // subtracted, which is the NATS `HPUB`
                                                    // mistake the project CLAUDE.md records.
                                                    let queued_state = {
                                                        let conns =
                                                            connections_for_read.lock().await;
                                                        conns.get(&connection_id).map(|c| {
                                                            (c.state.clone(), c.queued_data.len())
                                                        })
                                                    };
                                                    if let Some((
                                                        ConnectionState::Processing,
                                                        queued,
                                                    )) = queued_state
                                                    {
                                                        if queued.saturating_add(n)
                                                            > MAX_QUEUED_BYTES
                                                        {
                                                            Self::refuse_queued_data_overflow(
                                                                connection_id,
                                                                server_id,
                                                                queued.saturating_add(n),
                                                                &mut read_half,
                                                                &write_half_for_read,
                                                                &connections_for_read,
                                                                &app_state_for_read,
                                                                &status_tx_for_read,
                                                            )
                                                            .await;
                                                            break;
                                                        }
                                                    }

                                                    let data = Bytes::copy_from_slice(&buffer[..n]);

                                                    // Keep the rail's down/up counters and
                                                    // `last_activity` moving. Nothing else updates
                                                    // them for TLS, so every connection was drawn
                                                    // with 0B in both directions however much it
                                                    // carried.
                                                    app_state_for_read
                                                        .update_connection_stats(
                                                            server_id,
                                                            connection_id,
                                                            Some(n as u64),
                                                            None,
                                                            Some(1),
                                                            None,
                                                        )
                                                        .await;

                                                    // Data summary + full payload are FileOnly: the
                                                    // tls_data_received event template renders the
                                                    // equivalent lines to the TUI, so streaming the
                                                    // payload here too would duplicate it and load the
                                                    // unbounded status channel.
                                                    let log = Log::new(Some(&status_tx_for_read));
                                                    if data.iter().all(|&b| {
                                                        b.is_ascii_graphic()
                                                            || b.is_ascii_whitespace()
                                                    }) {
                                                        let data_str =
                                                            String::from_utf8_lossy(&data);
                                                        let preview = if data_str.len() > 100 {
                                                            format!("{}...", &data_str[..100])
                                                        } else {
                                                            data_str.to_string()
                                                        };
                                                        log.debug(format!(
                                                            "TLS received {} bytes on {}: {}",
                                                            n, connection_id, preview
                                                        ));
                                                        log.trace(format!(
                                                            "TLS data (text): {:?}",
                                                            data_str
                                                        ));
                                                    } else {
                                                        log.debug(format!(
                                                    "TLS received {} bytes on {} (binary data)",
                                                    n, connection_id
                                                ));
                                                        log.trace(format!(
                                                            "TLS data (hex): {}",
                                                            hex::encode(&data)
                                                        ));
                                                    }

                                                    // Handle data in separate task
                                                    let llm_clone = llm_client_for_read.clone();
                                                    let state_clone = app_state_for_read.clone();
                                                    let status_clone = status_tx_for_read.clone();
                                                    let conns_clone = connections_for_read.clone();
                                                    let protocol_clone = protocol_for_read.clone();
                                                    // Marked busy *before* the task is spawned, so
                                                    // there is no window in which the read deadline
                                                    // could see the connection as idle while an answer
                                                    // is on its way.
                                                    activity_for_read.begin_work();
                                                    let activity_for_handler =
                                                        Arc::clone(&activity_for_read);
                                                    // Tracked, not detached: stop_server must abort this task too.
                                                    let task_owner = app_state_for_read.clone();
                                                    task_owner
                                                        .spawn_server_task(server_id, async move {
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
                                                            activity_for_handler.end_work();
                                                        })
                                                        .await;
                                                }
                                                Err(e) => {
                                                    Log::new(Some(&status_tx_for_read)).error(
                                                        format!(
                                                            "Read error on {}: {}",
                                                            connection_id, e
                                                        ),
                                                    );
                                                    connections_for_read
                                                        .lock()
                                                        .await
                                                        .remove(&connection_id);
                                                    // Close it in AppState as well. Dropping only the
                                                    // map entry left the connection drawn as Active
                                                    // for the life of the server, and every later
                                                    // stat update targeted a peer that was gone.
                                                    app_state_for_read
                                                        .close_connection_on_server(
                                                            server_id,
                                                            connection_id,
                                                        )
                                                        .await;
                                                    let _ = status_tx_for_read
                                                        .send("__UPDATE_UI__".to_string());
                                                    break;
                                                }
                                            }
                                        }

                                        // Every exit from the read loop — EOF, the idle
                                        // deadline, a read error — lands here, so the handle
                                        // goes away with the connection rather than leaving
                                        // the rail offering a dead peer. The peer-command
                                        // task ends when the handle is dropped, releasing its
                                        // clone of the write half. Idempotent with
                                        // `peer_support`'s own close path, which runs when an
                                        // injected `close_connection` half-closes from
                                        // outside this task.
                                        app_state_for_read
                                            .remove_peer_handle(server_id, connection_id.as_u32())
                                            .await;
                                    })
                                    .await;
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

    /// Answer `tls_connection_opened` for a new connection, then release whatever the peer
    /// sent while it was being answered. The TLS twin of `tcp`'s function of the same name,
    /// called only for a `send_first` server, whose peer is owed a greeting: no bytes is WARN
    /// `decision=model_silent`, and a backend failure closes with close_notify
    /// (`decision=fail_closed_llm_error_*`). The branch for a server without `send_first` is
    /// kept so the function stays correct if it is ever called for one.
    ///
    /// `opened` is signalled once the answer is on the wire; a `send_first` reader waits for
    /// it. `reader_alive` resolves when the reader ends, which abandons the call.
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
        write_half: Arc<Mutex<tokio::io::WriteHalf<tokio_rustls::server::TlsStream<TcpStream>>>>,
        protocol: Arc<TlsProtocol>,
    ) {
        let log = Log::new(Some(&status_tx));
        let event = Event::new(
            &TLS_CONNECTION_OPENED_EVENT,
            crate::protocol::event_type::connect_event_data(),
        );

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
                    "TLS connection {connection_id} closed before its connect event was \
                     answered: decision=peer_left_before_answer"
                ));
                return;
            }
        };

        match answer {
            Ok(execution_result) => {
                debug!("LLM TLS connect-event response received");
                for msg in execution_result.messages {
                    let _ = status_tx.send(msg);
                }

                let mut wrote = false;
                for protocol_result in execution_result.protocol_results {
                    match protocol_result {
                        ActionResult::Output(output_data) => {
                            let mut write = write_half.lock().await;
                            if let Err(e) = write.write_all(&output_data).await {
                                log.error(format!("Failed to send greeting: {}", e));
                            } else {
                                drop(write);
                                log.debug(format!(
                                    "TLS sent {} bytes to {}",
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
                                wrote = true;
                            }
                        }
                        ActionResult::CloseConnection => {
                            connections.lock().await.remove(&connection_id);
                            if let Err(e) = write_half.lock().await.shutdown().await {
                                debug!("TLS shutdown on {} returned: {}", connection_id, e);
                            }
                            log.info(format!(
                                "Closed TLS connection {connection_id} on connect: \
                                 decision=model_close"
                            ));
                            let _ = opened.send(());
                            return;
                        }
                        _ => {}
                    }
                }

                if wrote {
                    log.debug(format!(
                        "TLS connection {connection_id} greeted: decision=model_answer"
                    ));
                } else if send_first {
                    log.warn(format!(
                        "TLS connection {connection_id} decision=model_silent: send_first was \
                         requested but the model produced no greeting"
                    ));
                } else {
                    log.debug(format!(
                        "TLS connection {connection_id} connect: decision=model_no_actions"
                    ));
                }
            }
            Err(e) if send_first => {
                // A `send_first` server owes the peer a greeting; without one the peer waits
                // for a banner that will never come. Close with a close_notify alert so it
                // reads EOF instead. The full error goes to the log only.
                let decision = llm_error_decision(&e);
                error!(
                    "TLS connection {} decision={}: LLM call failed generating greeting: {:#}",
                    connection_id, decision, e
                );
                log.warn(format!(
                    "TLS connection {connection_id} decision={decision}: no greeting \
                     generated, closing with close_notify"
                ));
                {
                    let mut write = write_half.lock().await;
                    if let Err(shutdown_err) = write.shutdown().await {
                        debug!(
                            "TLS shutdown on {} returned: {}",
                            connection_id, shutdown_err
                        );
                    }
                }
                connections.lock().await.remove(&connection_id);
                app_state
                    .remove_peer_handle(server_id, connection_id.as_u32())
                    .await;
                app_state
                    .close_connection_on_server(server_id, connection_id)
                    .await;
                let _ = opened.send(());
                return;
            }
            Err(e) => {
                // Nobody asked this server to speak first, so the peer has been failed by
                // nothing yet; its own data gets the data path's answer.
                log.warn(format!(
                    "TLS connect event for {connection_id} failed: \
                     decision=connect_event_failed error={e}"
                ));
            }
        }

        let _ = opened.send(());

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

    /// Refuse a connection whose queued application data has passed [`MAX_QUEUED_BYTES`].
    ///
    /// **The alert is `close_notify`, and it is not the alert this deserves.** TLS has a
    /// description for exactly this condition — `record_overflow(22)` — and rustls 0.23 cannot
    /// send it: `CommonState::send_fatal_alert` is `pub(crate)`, and the only alert the public
    /// API will emit is `send_close_notify`, which is what `poll_shutdown` on a
    /// `tokio_rustls` stream calls. Writing the seven raw bytes of a `record_overflow` alert to
    /// the TCP socket underneath is not an alternative: after the handshake every record is
    /// encrypted, so a plaintext one is a protocol violation the peer must reject, and it would
    /// arrive as garbage rather than as a reason. (The connection **cap** refusal higher up in
    /// this file *is* a raw plaintext alert, and legitimately so — it is written before any
    /// handshake has happened, when nothing is encrypted yet.)
    ///
    /// So the distinction the wire cannot carry is carried by the log, which is the rule the
    /// project CLAUDE.md states for every deliberately-silent protocol: `decision=` names what
    /// happened, and `grep decision=fail_closed` finds it.
    #[allow(clippy::too_many_arguments)]
    async fn refuse_queued_data_overflow<R>(
        connection_id: ConnectionId,
        server_id: crate::state::ServerId,
        would_be: usize,
        read_half: &mut R,
        write_half: &Arc<Mutex<tokio::io::WriteHalf<tokio_rustls::server::TlsStream<TcpStream>>>>,
        connections: &Arc<Mutex<HashMap<ConnectionId, ConnectionData>>>,
        app_state: &Arc<AppState>,
        status_tx: &mpsc::UnboundedSender<String>,
    ) where
        R: tokio::io::AsyncRead + Unpin,
    {
        Log::new(Some(status_tx)).warn(format!(
            "TLS connection {connection_id} decision=fail_closed_queued_data_overflow: peer \
             queued {would_be} bytes while an answer was in flight, limit is {MAX_QUEUED_BYTES}; \
             closing with close_notify (TLS record_overflow is not reachable through rustls)"
        ));

        {
            let mut write = write_half.lock().await;
            if let Err(e) = write.shutdown().await {
                debug!(
                    "TLS shutdown on {} after overflow returned: {}",
                    connection_id, e
                );
            }
        }

        // Drain before the socket is dropped, or the close is an RST and the alert just
        // written is discarded with it.
        let mut drained = 0usize;
        let mut scratch = vec![0u8; 64 * 1024];
        let _ = tokio::time::timeout(LINGER_DRAIN_TIMEOUT, async {
            while drained < LINGER_DRAIN_BYTES {
                match read_half.read(&mut scratch).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => drained = drained.saturating_add(n),
                }
            }
        })
        .await;
        debug!("TLS {connection_id}: drained {drained} bytes after refusing the queue");

        connections.lock().await.remove(&connection_id);
        app_state
            .remove_peer_handle(server_id, connection_id.as_u32())
            .await;
        app_state
            .close_connection_on_server(server_id, connection_id)
            .await;
        let _ = status_tx.send("__UPDATE_UI__".to_string());
    }

    /// Handle data received on a connection with LLM actions
    async fn handle_data_with_actions(
        connection_id: ConnectionId,
        server_id: crate::state::ServerId,
        data: Bytes,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        connections: Arc<Mutex<HashMap<ConnectionId, ConnectionData>>>,
        protocol: Arc<TlsProtocol>,
    ) {
        // Read per event: batching is hot-changeable.
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
                    "TLS connection {} is no longer registered; dropping {} received bytes",
                    connection_id,
                    data.len()
                );
                return;
            }
        };

        // If processing, queue the data — up to the cap, and never past it.
        //
        // The reader loop refuses and tears the connection down before it ever hands over data
        // that would cross [`MAX_QUEUED_BYTES`], so this is the second half of the same bound
        // rather than a different one: the reader's check reads the queue length a moment
        // before this runs, and with a handler task in between the two there is a window in
        // which another read could arrive. Refusing to extend here is what makes the `Vec`
        // itself unable to exceed the cap, whatever that window does.
        if current_state == ConnectionState::Processing {
            let mut refused = None;
            connections
                .lock()
                .await
                .entry(connection_id)
                .and_modify(|conn| {
                    let would_be = conn.queued_data.len().saturating_add(data.len());
                    if would_be > MAX_QUEUED_BYTES {
                        refused = Some(would_be);
                    } else {
                        conn.queue(&data);
                    }
                });
            match refused {
                Some(would_be) => Log::new(Some(&status_tx)).warn(format!(
                    "TLS connection {connection_id} decision=fail_closed_queued_data_overflow: \
                     dropped {} bytes that would have taken the queue to {would_be}, limit is \
                     {MAX_QUEUED_BYTES}",
                    data.len()
                )),
                None => Log::new(Some(&status_tx)).debug(format!(
                    "Queued {} bytes for {}",
                    data.len(),
                    connection_id
                )),
            }
            return;
        }

        // Merge any queued data with new data.
        //
        // The lock was released after the state check above, so the reader task
        // may have removed this connection in the meantime (client disconnected).
        // Unwrapping here panicked the task on that race, and a panicked task
        // leaves the server reporting Running.
        let mut all_data = {
            let mut conns = connections.lock().await;
            let Some(conn_data) = conns.get_mut(&connection_id) else {
                return; // Connection closed while we were waiting for the lock
            };
            // Bytes held for `wait_for_more` are one message with whatever completes it, so
            // they are always taken whole; otherwise batching decides.
            let take_all = batching || current_state == ConnectionState::Accumulating;
            conn_data.state = ConnectionState::Processing;
            conn_data.queue(&data);
            Bytes::from(conn_data.take_next(take_all))
        };

        loop {
            // Get write_half for context
            let write_half = {
                let conns = connections.lock().await;
                conns.get(&connection_id).map(|c| c.write_half.clone())
            };

            let Some(write_half) = write_half else {
                debug!(
                    "TLS connection {} went away before its response could be written",
                    connection_id
                );
                return;
            };

            // Format data for event parameter. The encoding is reported
            // alongside so the model can echo binary back through
            // send_tls_data with encoding="hex" instead of sending the ASCII
            // hex digits.
            let printable = all_data
                .iter()
                .all(|&b| b.is_ascii_graphic() || b.is_ascii_whitespace());
            let (data_str, encoding) = if printable {
                (String::from_utf8_lossy(&all_data).to_string(), "utf8")
            } else {
                (hex::encode(&all_data), "hex")
            };

            // Create data received event
            let event = Event::new(
                &TLS_DATA_RECEIVED_EVENT,
                serde_json::json!({
                    "data": data_str,
                    "encoding": encoding
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
                    debug!("LLM TLS response received");

                    // Display messages
                    for msg in execution_result.messages {
                        let _ = status_tx.send(msg);
                    }

                    // Handle protocol results
                    let mut should_close = false;
                    let mut should_wait = false;
                    let mut acted = false;

                    for protocol_result in execution_result.protocol_results {
                        match protocol_result {
                            ActionResult::Output(output_data) => {
                                acted = true;
                                let mut write = write_half.lock().await;
                                let log = Log::new(Some(&status_tx));
                                if let Err(e) = write.write_all(&output_data).await {
                                    log.error(format!("Failed to send response: {}", e));
                                } else {
                                    // Sent-data summary + payload are FileOnly: the
                                    // send_tls_data action template already reports the send
                                    // to the TUI.
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
                                            "TLS sent {} bytes to {}: {}",
                                            output_data.len(),
                                            connection_id,
                                            preview
                                        ));
                                        log.trace(format!("TLS sent (text): {:?}", data_str));
                                    } else {
                                        log.debug(format!(
                                            "TLS sent {} bytes to {} (binary data)",
                                            output_data.len(),
                                            connection_id
                                        ));
                                        log.trace(format!(
                                            "TLS sent (hex): {}",
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
                                }
                            }
                            ActionResult::CloseConnection => {
                                acted = true;
                                should_close = true;
                            }
                            ActionResult::WaitForMore => {
                                acted = true;
                                should_wait = true;
                            }
                            _ => {}
                        }
                    }

                    // An answer that carries no output, no close and no wait leaves the
                    // peer holding an unanswered request. That is a legitimate "say nothing"
                    // for a transport with no reply obligation, so the connection stays open -
                    // but it is logged distinctly from a backend failure, which hangs up.
                    if !acted {
                        Log::new(Some(&status_tx)).warn(format!(
                            "TLS connection {connection_id} decision=model_no_action: model \
                             produced no usable action, nothing sent"
                        ));
                    }

                    // Handle wait_for_more.
                    //
                    // The fragment the model was just shown goes back to the *head* of the
                    // queue, ahead of anything that arrived during the call, as one payload.
                    // `wait_for_more` means "these bytes are an incomplete message"; dropping
                    // them meant the model never saw the front of the message again. The same
                    // repair as `tcp`.
                    if should_wait {
                        let (queued_len, arrived_during_call) = {
                            let mut conns = connections.lock().await;
                            let Some(conn) = conns.get_mut(&connection_id) else {
                                return;
                            };
                            let arrived_during_call = !conn.queued_data.is_empty();
                            let mut merged = all_data.to_vec();
                            merged.append(&mut conn.queued_data);
                            conn.hold_as_one(merged);
                            conn.state = ConnectionState::Accumulating;
                            (conn.queued_data.len(), arrived_during_call)
                        };

                        // Same bound as the Processing queue: a model that answers
                        // `wait_for_more` to everything must not be a way to grow memory
                        // without limit either.
                        if queued_len > MAX_QUEUED_BYTES {
                            Log::new(Some(&status_tx)).warn(format!(
                                "TLS connection {connection_id} \
                                 decision=fail_closed_queued_data_overflow: accumulated \
                                 {queued_len} bytes across wait_for_more, limit is \
                                 {MAX_QUEUED_BYTES}"
                            ));
                            connections.lock().await.remove(&connection_id);
                            if let Err(e) = write_half.lock().await.shutdown().await {
                                debug!("TLS shutdown on {} returned: {}", connection_id, e);
                            }
                            app_state
                                .close_connection_on_server(server_id, connection_id)
                                .await;
                            let _ = status_tx.send("__UPDATE_UI__".to_string());
                            return;
                        }

                        // Bytes that arrived while the model was thinking *are* the "more" it
                        // asked for. Returning here would park them until the next read, which
                        // may never come — the peer has sent its whole message and is waiting.
                        if arrived_during_call {
                            let joined = {
                                let mut conns = connections.lock().await;
                                let Some(conn) = conns.get_mut(&connection_id) else {
                                    return;
                                };
                                conn.state = ConnectionState::Processing;
                                conn.take_next(true)
                            };
                            Log::new(Some(&status_tx)).debug(format!(
                                "wait_for_more on {connection_id}: {} bytes already waiting, \
                                 continuing",
                                joined.len()
                            ));
                            all_data = Bytes::from(joined);
                            continue;
                        }

                        Log::new(Some(&status_tx)).debug(format!(
                            "Waiting for more data from {connection_id} ({queued_len} bytes held)"
                        ));
                        return;
                    }

                    // Handle close_connection.
                    //
                    // Dropping the map entry alone left the socket open forever
                    // (the reader task kept blocking on read and the client never
                    // saw a close), so close_this_connection did not close
                    // anything. Shut the TLS write half down to send close_notify
                    // and let the peer's read return EOF.
                    if should_close {
                        connections.lock().await.remove(&connection_id);
                        if let Err(e) = write_half.lock().await.shutdown().await {
                            debug!("TLS shutdown on {} returned: {}", connection_id, e);
                        }
                        Log::new(Some(&status_tx))
                            .info(format!("Closed TLS connection {connection_id}"));
                        return;
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
                    // The full error goes to the log and the status stream; the peer gets a
                    // close_notify alert carrying nothing about why.
                    let decision = llm_error_decision(&e);
                    error!(
                        "TLS connection {} decision={}: LLM call failed for received data: {:#}",
                        connection_id, decision, e
                    );
                    Log::new(Some(&status_tx)).warn(format!(
                        "TLS connection {connection_id} decision={decision}: no response \
                         generated, closing with close_notify"
                    ));

                    // Say something on the wire instead of resetting to Idle in silence.
                    //
                    // TLS carries no application-level error - the application protocol here
                    // is whatever the handler invents, so there is no reply we could phrase in
                    // it. What TLS does have is the alert protocol, and `shutdown()` emits a
                    // real close_notify alert record (not just a FIN), which every TLS client
                    // surfaces as a clean end of stream immediately rather than blocking until
                    // its own timeout.
                    //
                    // A *fatal* `internal_error` alert would be more precise, but rustls 0.23
                    // keeps `CommonState::send_fatal_alert` `pub(crate)`; close_notify is the
                    // strongest in-spec signal reachable through its public API. Forging a
                    // plaintext alert record onto the TCP socket underneath would violate
                    // TLS 1.3 record protection, so it is not done.
                    {
                        let mut write = write_half.lock().await;
                        if let Err(shutdown_err) = write.shutdown().await {
                            debug!(
                                "TLS shutdown on {} returned: {}",
                                connection_id, shutdown_err
                            );
                        }
                    }
                    connections.lock().await.remove(&connection_id);
                    // The reader task is still parked in `read()` and will only notice once
                    // the peer closes its own side, so retire the peer handle here rather
                    // than leaving the rail offering a connection this task has already
                    // ended. Idempotent with the reader's own removal.
                    app_state
                        .remove_peer_handle(server_id, connection_id.as_u32())
                        .await;
                    app_state
                        .close_connection_on_server(server_id, connection_id)
                        .await;
                    Log::new(Some(&status_tx)).info(format!(
                        "Closed TLS connection {connection_id} after LLM error"
                    ));
                    return;
                }
            }
        }
    }
}
