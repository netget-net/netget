//! Redis server implementation with RESP protocol
pub mod actions;
pub mod cluster;
pub mod pubsub;
pub mod resp3;
pub mod resp_value;

use crate::llm::action_helper::call_llm;
use crate::llm::actions::protocol_trait::ActionResult;
use crate::llm::ollama_client::OllamaClient;
use crate::logging::emit::Log;
use crate::protocol::Event;
use crate::server::connection::ConnectionId;
use crate::state::app_state::AppState;
use crate::utils::redis_keys::{key_hash_slot, slot_keys};
use crate::utils::resp::{scan_resp2_frame, RespLength, RespLimits, RespScan};
use actions::{
    encode_error, encode_integer, RedisProtocol, ACCEPT_SUBSCRIPTION, DELIVER_MESSAGE,
    REDIS_COMMAND_EVENT, REDIS_PUBLISH_EVENT, REDIS_SUBSCRIBE_EVENT,
};
use anyhow::Result;
use pubsub::{Kind, Outbox, OutboxReceiver, PubSubHub};
use redis_protocol::resp2::decode::decode;
use redis_protocol::resp2::types::OwnedFrame as Frame;
use resp_value::Resp;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tracing::{debug, error, trace, warn};

/// Maximum bytes we will buffer for a single, still-incomplete RESP frame.
///
/// `decode()` returns `Ok(None)` while a frame is incomplete, so without this cap a client
/// that announces a huge bulk string (`$2000000000\r\n`) and then stalls would make the
/// connection buffer grow without bound. Real Redis caps a bulk string at 512 MB; 64 MB is
/// far more than any LLM-authored command needs.
pub const MAX_PENDING_FRAME_BYTES: usize = 64 * 1024 * 1024;

/// What a frame may declare before `decode` is allowed to see it: [`crate::utils::resp`]'s
/// depth and element bounds, and a bulk string no longer than the buffer that must hold it —
/// a `$N` past [`MAX_PENDING_FRAME_BYTES`] can never complete, so it is refused on its header
/// line instead of after the peer has filled 64 MiB.
const RESP_LIMITS: RespLimits = RespLimits::with_max_bulk_len(MAX_PENDING_FRAME_BYTES);

/// How long to wait for the first byte of the first command from a peer that has only
/// connected.
///
/// **This was 30 seconds, and the argument for 30 was about the wrong peer.** It read: every
/// real RESP client speaks immediately — `redis-cli` sends `COMMAND DOCS`, `redis-rs` sends
/// `PING` or the `HELLO`/`AUTH` it was configured with — so a peer that has connected and said
/// nothing has made no claim on the server. That is true of every *third-party* client and
/// false of the one this server most often has.
///
/// NetGet's own Redis client (`src/client/redis/mod.rs`) is a bare `TcpStream::connect` and
/// nothing else: it puts no byte on the wire until an action says to. The dashboard offers
/// `[ + redis client ]` under a server's peers, and a client created there is routed
/// `<proto>_connected` → static-with-no-actions and then `*` → manual
/// (`src/tui/modal/form.rs`), so it connects, is answered with nothing, and waits for a person
/// to type into `[ send message ]`. The same is true from this side: `run` registers a peer
/// channel before the first read precisely so `[ message ]` reaches a peer that has not spoken
/// yet. With a 30-second bound the server dropped that peer while the operator was still
/// looking at it — the same defect `src/server/tcp/mod.rs` had, found there by
/// `tests/mcp_stdio_test.rs::client_tools_manage_a_real_connection` reporting `Disconnected`.
///
/// 300 seconds is the window a `manual` rule gives a human to answer one event
/// (`src/state/intercepts.rs`), which is the number this product already uses for how long
/// someone might take, and it is also this server's own
/// [`IDLE_BETWEEN_COMMANDS_TIMEOUT`] — so a hand-driven session is now bounded the same way
/// before its first command as after it.
///
/// What it costs: a stranger holding a socket, a task and an `AppState` row while saying
/// nothing now gets 300 seconds rather than 30. That is still bounded, still capped at
/// [`MAX_CONNECTIONS`], and still answered above that cap with real Redis's own
/// `-ERR max number of clients reached`; the change is a tenfold rise in how long one idle
/// slot is held, not a removal of the bound. A listener genuinely exposed to strangers should
/// set `first_byte_timeout_secs` low — 30 is the old value and remains a sound choice for one.
const FIRST_COMMAND_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

/// How long to wait for a *further* command once one has been answered.
///
/// Much longer than the first wait, and deliberately so: real Redis ships `timeout 0` — it
/// never closes an idle client — and every pooling client in the ecosystem (`redis-rs`'s
/// `ConnectionManager`, `deadpool-redis`, an interactive `redis-cli`) depends on holding an
/// established connection unused between bursts. Closing those at 30s would break correct
/// clients to fix a problem they are not causing. Five minutes still bounds the hold, and a
/// client that reconnects after it reconnects transparently.
///
/// Overridable per server with `idle_timeout_secs`, for the same reason the first bound is:
/// the right value is a property of who is on the other end, and only the operator knows that.
const IDLE_BETWEEN_COMMANDS_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

/// Concurrent connections this server admits.
///
/// [`accept_bounded::DEFAULT_MAX_CONNECTIONS`]; nothing about RESP makes a connection more or
/// less expensive than the default assumes.
const MAX_CONNECTIONS: usize = crate::server::accept_bounded::DEFAULT_MAX_CONNECTIONS;

/// What a peer over [`MAX_CONNECTIONS`] is told before the socket closes.
///
/// Byte-for-byte what real Redis sends in the same situation, so every RESP client already
/// knows it: `redis-rs` surfaces it as `ResponseError`, `redis-cli` prints it. A simple error
/// can never be mistaken for data, which is what makes it safe to send unprompted — the peer
/// has not spoken yet, so this arrives before its first command rather than as a reply to one.
const CONNECTION_CAP_REFUSAL: &[u8] = b"-ERR max number of clients reached\r\n";

/// What one server's connections share: the pub/sub registry, and — in cluster mode — the
/// topology. Registered with [`AppState::register_server_handle`] so the model's async actions
/// (`redis_publish_message`, `redis_cluster_set_slot`) reach the running server.
pub struct RedisShared {
    pub hub: PubSubHub,
    pub cluster: Option<std::sync::Mutex<cluster::ClusterState>>,
}

impl RedisShared {
    fn cluster(&self) -> Option<std::sync::MutexGuard<'_, cluster::ClusterState>> {
        self.cluster
            .as_ref()
            .map(|c| c.lock().unwrap_or_else(|p| p.into_inner()))
    }
}

/// The per-server knobs `spawn` reads from the startup parameters.
#[derive(Debug, Default, Clone)]
pub struct RedisServerOptions {
    pub first_byte_timeout_secs: Option<u64>,
    pub idle_timeout_secs: Option<u64>,
    /// The `cluster_nodes` topology; `Some` puts the server in cluster mode.
    pub cluster_nodes: Option<serde_json::Value>,
}

/// Redis server implementation
pub struct RedisServer {
    llm_client: OllamaClient,
    app_state: Arc<AppState>,
    #[allow(dead_code)]
    status_tx: mpsc::UnboundedSender<String>,
    server_id: Option<crate::state::ServerId>,
}

impl RedisServer {
    /// Create a new Redis server
    pub fn new(
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        server_id: Option<crate::state::ServerId>,
    ) -> Self {
        Self {
            llm_client,
            app_state,
            status_tx,
            server_id,
        }
    }

    /// Spawn Redis server with LLM integration
    pub async fn spawn_with_llm_actions(
        listen_addr: SocketAddr,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        _send_first: bool,
        server_id: crate::state::ServerId,
        options: RedisServerOptions,
    ) -> Result<SocketAddr> {
        // Both bounds are tunable because their right value is a property of who is on the
        // other end, which only the operator knows. The defaults serve NetGet's own client
        // waiting on a human; a listener exposed to strangers wants the first one much lower.
        let first_byte_timeout = options
            .first_byte_timeout_secs
            .map(std::time::Duration::from_secs)
            .unwrap_or(FIRST_COMMAND_READ_TIMEOUT);
        let idle_timeout = options
            .idle_timeout_secs
            .map(std::time::Duration::from_secs)
            .unwrap_or(IDLE_BETWEEN_COMMANDS_TIMEOUT);
        let listener = TcpListener::bind(listen_addr).await?;
        let actual_addr = listener.local_addr()?;

        // The topology is validated against the address actually bound (a `myself` node
        // without a port is this listener), and a bad one refuses to start rather than serving
        // a cluster nobody can navigate.
        let cluster = options
            .cluster_nodes
            .as_ref()
            .map(|nodes| cluster::ClusterState::from_param(nodes, actual_addr))
            .transpose()
            .map_err(|e| anyhow::anyhow!("invalid cluster_nodes: {e:#}"))?;
        let shared = Arc::new(RedisShared {
            hub: PubSubHub::default(),
            cluster: cluster.map(std::sync::Mutex::new),
        });
        app_state
            .register_server_handle(server_id, shared.clone())
            .await;

        let log = Log::new(Some(&status_tx));
        match shared.cluster() {
            Some(c) => log.info(format!(
                "Redis server listening on {} (cluster mode: {} of {} nodes)",
                actual_addr,
                c.me().addr(),
                c.nodes.len()
            )),
            None => log.info(format!("Redis server listening on {}", actual_addr)),
        }

        let server = Arc::new(RedisServer::new(
            llm_client,
            app_state.clone(),
            status_tx.clone(),
            Some(server_id),
        ));

        let status_tx_clone = status_tx.clone();
        let task_registrar = app_state.clone();

        // Spawn the accept loop
        let limiter = crate::server::accept_bounded::ConnectionLimiter::new(MAX_CONNECTIONS);
        let accept_handle = tokio::spawn(async move {
            loop {
                match crate::server::accept_bounded::accept_bounded(
                    &listener,
                    &limiter,
                    CONNECTION_CAP_REFUSAL,
                    "Redis",
                    Some(&status_tx),
                )
                .await
                {
                    Ok((stream, addr, permit)) => {
                        Log::new(Some(&status_tx)).info(format!("Redis connection from {}", addr));

                        let connection_id =
                            ConnectionId::new(app_state.get_next_unified_id().await);
                        let local_addr_conn = stream.local_addr().unwrap_or(actual_addr);

                        // Track the connection
                        if let Some(server_id) = server.server_id {
                            use crate::state::server::{
                                ConnectionState as ServerConnectionState, ConnectionStatus,
                                ProtocolConnectionInfo,
                            };
                            let now = crate::utils::clock::Instant::now();
                            let conn_state = ServerConnectionState {
                                id: connection_id,
                                remote_addr: addr,
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
                            server
                                .app_state
                                .add_connection_to_server(server_id, conn_state)
                                .await;
                        }

                        let handler = RedisHandler {
                            connection_id,
                            llm_client: server.llm_client.clone(),
                            app_state: server.app_state.clone(),
                            status_tx: status_tx.clone(),
                            server_id: server.server_id,
                            first_byte_timeout,
                            idle_timeout,
                            shared: shared.clone(),
                        };

                        let conn_handle = tokio::spawn(async move {
                            // The permit is released when this task ends, which is what makes
                            // `MAX_CONNECTIONS` a cap on live connections rather than on the
                            // accept rate.
                            let _permit = permit;
                            if let Err(e) = handler.handle_connection(stream).await {
                                error!("Redis connection error: {:?}", e);
                            }
                        });

                        // Register the per-connection task too, not just the accept loop:
                        // aborting the accept loop releases the port but leaves every
                        // in-flight session running, so `stop_server` did not actually stop
                        // the server. `register_server_task` prunes finished handles on each
                        // call, so this cannot grow without bound.
                        if let Some(server_id) = server.server_id {
                            server
                                .app_state
                                .register_server_task(server_id, conn_handle)
                                .await;
                        }
                    }
                    Err(e) => {
                        Log::new(Some(&status_tx)).error(format!("Redis accept error: {}", e));
                    }
                }
            }
        });

        // Register the accept loop so stop_server can abort it and release the port.
        task_registrar
            .register_server_task(server_id, accept_handle)
            .await;

        let _ = status_tx_clone.send("__UPDATE_UI__".to_string());
        Ok(actual_addr)
    }
}

/// Redis connection handler
struct RedisHandler {
    connection_id: ConnectionId,
    llm_client: OllamaClient,
    app_state: Arc<AppState>,
    status_tx: mpsc::UnboundedSender<String>,
    server_id: Option<crate::state::ServerId>,
    /// [`FIRST_COMMAND_READ_TIMEOUT`], or the value of this server's `first_byte_timeout_secs`.
    first_byte_timeout: std::time::Duration,
    /// [`IDLE_BETWEEN_COMMANDS_TIMEOUT`], or the value of this server's `idle_timeout_secs`.
    idle_timeout: std::time::Duration,
    shared: Arc<RedisShared>,
}

/// Aborts the connection's writer task however the read loop ends. The writer may be parked in
/// a write to a peer that stopped reading — the slow-consumer case — and only an abort ends
/// that.
struct AbortWriter(tokio::task::AbortHandle);

impl Drop for AbortWriter {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// What the model answered, folded out of its action results.
#[derive(Default)]
struct ModelAnswer {
    /// RESP bytes the reply verbs produced, or the fail-closed error.
    output: Vec<u8>,
    close: bool,
    /// `redis_accept_subscription`.
    accept: bool,
    /// `redis_deliver_message`.
    deliver: bool,
    /// The model call itself failed; `output` holds the error.
    failed: bool,
}

/// Everything the per-command handling needs from the connection.
struct Conn<'a> {
    protocol: Arc<RedisProtocol>,
    outbox: Outbox,
    write_half: Arc<tokio::sync::Mutex<tokio::io::WriteHalf<TcpStream>>>,
    log: Log<'a>,
    /// The one-shot `ASKING` flag of cluster mode.
    asking: bool,
}

/// What to do after one command.
enum Flow {
    Continue,
    Close,
}

/// Commands a RESP2 connection may send while it holds a subscription (Redis's own list).
const SUBSCRIBED_MODE_COMMANDS: &[&str] = &[
    "SUBSCRIBE",
    "PSUBSCRIBE",
    "SSUBSCRIBE",
    "UNSUBSCRIBE",
    "PUNSUBSCRIBE",
    "SUNSUBSCRIBE",
    "PING",
    "QUIT",
    "RESET",
];

fn wrong_arity(name: &str) -> String {
    format!(
        "ERR wrong number of arguments for '{}' command",
        name.to_ascii_lowercase()
    )
}

impl RedisHandler {
    /// Run the connection, then always mark it closed in `AppState`.
    ///
    /// Without this the connection stays `Active` forever in the server's connection map,
    /// which is what `src/server/redis/CLAUDE.md` already claimed happened but did not.
    async fn handle_connection(self, stream: TcpStream) -> Result<()> {
        let server_id = self.server_id;
        let connection_id = self.connection_id;
        let app_state = self.app_state.clone();
        let status_tx = self.status_tx.clone();
        let shared = self.shared.clone();

        let result = self.run(stream).await;

        // A subscription is a fact about this socket; it goes with it.
        shared.hub.remove_connection(connection_id.as_u32());

        // Every exit path - EOF, read error, decode error, close_this_connection, frame
        // cap, slow consumer - lands here, so the dashboard's peer rows go away with the
        // connection.
        if let Some(server_id) = server_id {
            app_state
                .remove_peer_handle(server_id, connection_id.as_u32())
                .await;
            app_state
                .close_connection_on_server(server_id, connection_id)
                .await;
            let _ = status_tx.send("__UPDATE_UI__".to_string());
        }

        result
    }

    /// Write one fixed RESP error, then half-close: the refusal for a frame this server will
    /// not decode. The text is a constant chosen by the caller, never anything derived from
    /// the peer's bytes or an internal error.
    async fn refuse(&self, conn: &Conn<'_>, message: &str) {
        let _ = conn.outbox.send_reply(encode_error(message)).await;
        let _ = conn.write_half.lock().await.shutdown().await;
    }

    /// Write one reply. It goes through the connection's outbox so it keeps its place among
    /// delivered pub/sub messages, and this waits until it is on the socket.
    async fn write_reply(&self, conn: &Conn<'_>, reply: Vec<u8>) -> Result<()> {
        conn.outbox.send_reply(reply).await?;
        Ok(())
    }

    /// The single writer of this connection: replies and delivered messages, in queue order.
    async fn writer_task(
        mut out: OutboxReceiver,
        outbox: Outbox,
        write_half: Arc<tokio::sync::Mutex<tokio::io::WriteHalf<TcpStream>>>,
        app_state: Arc<AppState>,
        server_id: Option<crate::state::ServerId>,
        connection_id: ConnectionId,
    ) {
        while let Some(frame) = out.rx.recv().await {
            let len = frame.bytes.len();
            let result = if len == 0 {
                // A barrier: the read loop waits on it to know that everything queued before
                // it (subscription confirmations) has been written.
                Ok(())
            } else {
                let mut writer = write_half.lock().await;
                match writer.write_all(&frame.bytes).await {
                    Ok(()) => writer.flush().await,
                    Err(e) => Err(e),
                }
            };
            if frame.counted {
                out.queued.fetch_sub(len, Ordering::AcqRel);
            }
            let failed = result.is_err();
            if !failed && len > 0 {
                if let Some(server_id) = server_id {
                    app_state
                        .update_connection_stats(
                            server_id,
                            connection_id,
                            None,
                            Some(len as u64),
                            None,
                            Some(1),
                        )
                        .await;
                }
            }
            if let Some(ack) = frame.ack {
                let _ = ack.send(result);
            }
            if failed {
                outbox.mark_killed();
                break;
            }
        }
    }

    async fn run(self, stream: TcpStream) -> Result<()> {
        // Copied out before `self` is partially moved into the tasks below.
        let first_byte_timeout = self.first_byte_timeout;
        let idle_timeout = self.idle_timeout;
        let protocol = Arc::new(RedisProtocol::for_connection(
            self.connection_id,
            self.app_state.clone(),
            self.status_tx.clone(),
            self.shared.clone(),
        ));

        // The write half is shared with the peer command task below, so the dashboard can
        // write into this connection while the read loop is parked in `read()`.
        let (mut read_half, write_half) = tokio::io::split(stream);
        let write_half = Arc::new(tokio::sync::Mutex::new(write_half));

        // Peer messaging: "message this peer" / "disconnect this peer" inject actions into
        // THIS connection through the same executor the LLM path uses. Registered before the
        // first read, so a manual `*` rule parking the first command still leaves the
        // operator able to reach the connection. Every reply verb returns
        // `ActionResult::Output` with the RESP bytes pre-encoded (see actions.rs), so the
        // generic peer task writes injected replies to the wire; `close_connection`
        // half-closes.
        if let Some(server_id) = self.server_id {
            let peer_rx = crate::server::peer_support::register_peer_channel(
                &self.app_state,
                server_id,
                self.connection_id.as_u32(),
            )
            .await;
            crate::server::peer_support::spawn_peer_command_task(
                peer_rx,
                protocol.clone(),
                self.app_state.clone(),
                server_id,
                self.connection_id.as_u32(),
                write_half.clone(),
                self.status_tx.clone(),
            );
            let _ = self.status_tx.send("__UPDATE_UI__".to_string());
        }

        // One writer owns the socket, so a reply and a delivered message never interleave
        // mid-frame and a subscription's confirmation is written before its first message.
        let (outbox, outbox_rx) = Outbox::new();
        let writer = tokio::spawn(Self::writer_task(
            outbox_rx,
            outbox.clone(),
            write_half.clone(),
            self.app_state.clone(),
            self.server_id,
            self.connection_id,
        ));
        let _writer_guard = AbortWriter(writer.abort_handle());
        if let Some(server_id) = self.server_id {
            self.app_state.register_server_task(server_id, writer).await;
        }

        let mut conn = Conn {
            protocol,
            outbox,
            write_half,
            log: Log::new(Some(&self.status_tx)),
            asking: false,
        };

        let mut buffer = Vec::new();
        let mut answered_one = false;

        loop {
            // Read data from the stream.
            //
            // The deadline wraps the `read()` alone and nothing else in this loop. That is the
            // whole design: an LLM round-trip, and a `manual` rule parking a command for a
            // human (`src/state/intercepts.rs`, 300s by default), both happen *below*, after
            // the read has already returned — so neither can be timed out from under itself.
            // What is bounded is only the time a peer may hold this connection while sending
            // nothing, which is the resource an idle attacker is actually consuming.
            let read_timeout = if answered_one {
                idle_timeout
            } else {
                first_byte_timeout
            };
            let mut chunk = vec![0u8; 4096];
            let read = tokio::select! {
                read = tokio::time::timeout(read_timeout, read_half.read(&mut chunk)) => read,
                // A slow consumer the hub disconnected, or a write that failed.
                _ = conn.outbox.closing() => {
                    conn.log.warn(format!(
                        "Redis connection {} closed: it stopped reading while {} bytes of \
                         pub/sub messages were queued for it",
                        self.connection_id,
                        conn.outbox.queued_bytes()
                    ));
                    return Ok(());
                }
            };
            let read = match read {
                Ok(read) => read,
                Err(_) => {
                    conn.log.info(format!(
                        "Redis client {} sent nothing for {}s; closing idle connection",
                        self.connection_id,
                        read_timeout.as_secs()
                    ));
                    return Ok(());
                }
            };
            let n = match read {
                Ok(0) => {
                    debug!("Redis client disconnected");
                    return Ok(());
                }
                Ok(n) => n,
                Err(e) => {
                    error!("Redis read error: {}", e);
                    return Err(e.into());
                }
            };

            buffer.extend_from_slice(&chunk[..n]);

            if let Some(server_id) = self.server_id {
                self.app_state
                    .update_connection_stats(
                        server_id,
                        self.connection_id,
                        Some(n as u64),
                        None,
                        Some(1),
                        None,
                    )
                    .await;
            }

            if buffer.len() > MAX_PENDING_FRAME_BYTES {
                conn.log.error(format!(
                    "Redis client {} exceeded the {} byte frame buffer limit without completing a frame; closing",
                    self.connection_id, MAX_PENDING_FRAME_BYTES
                ));
                self.refuse(&conn, "ERR Protocol error: invalid multibulk length")
                    .await;
                return Ok(());
            }

            // Try to decode RESP frames
            let mut offset = 0;
            while offset < buffer.len() {
                // The frame's shape is walked iteratively before `decode` sees it, because
                // `decode` recurses once per nested array with no limit and a stack overflow
                // aborts the whole process (`src/utils/resp.rs`). Only a frame the scan has
                // seen end is decoded.
                match scan_resp2_frame(&buffer[offset..], &RESP_LIMITS) {
                    RespScan::Complete { .. } => {}
                    RespScan::Incomplete => break,
                    RespScan::TooDeep { limit } => {
                        conn.log.warn(format!(
                            "Redis connection {} decision=fail_closed_resp_too_deep: frame nests \
                             arrays deeper than {} levels; refusing and closing",
                            self.connection_id, limit
                        ));
                        self.refuse(&conn, "ERR Protocol error: nesting too deep")
                            .await;
                        return Ok(());
                    }
                    RespScan::TooLong(kind) => {
                        let (what, reply) = match kind {
                            RespLength::Aggregate => (
                                "array length",
                                "ERR Protocol error: invalid multibulk length",
                            ),
                            RespLength::Bulk => {
                                ("bulk length", "ERR Protocol error: invalid bulk length")
                            }
                        };
                        conn.log.warn(format!(
                            "Redis connection {} decision=fail_closed_resp_too_long: declared {} \
                             exceeds the frame limit; refusing and closing",
                            self.connection_id, what
                        ));
                        self.refuse(&conn, reply).await;
                        return Ok(());
                    }
                    RespScan::Malformed => {
                        // `decode` would reject the same byte; closed without a reply, as an
                        // undecodable frame always is.
                        error!(
                            "Redis connection {} sent a frame that is not RESP2; closing",
                            self.connection_id
                        );
                        return Err(anyhow::anyhow!("undecodable RESP frame"));
                    }
                }
                match decode(&buffer[offset..]) {
                    Ok(Some((frame, consumed))) => {
                        // From here on the peer is an established client, so the longer idle
                        // bound applies to every later read.
                        answered_one = true;
                        trace!("Redis frame: {:?}", frame);
                        offset += consumed;
                        match self.handle_frame(&mut conn, &frame).await? {
                            Flow::Continue => {}
                            Flow::Close => return Ok(()),
                        }
                    }
                    Ok(None) => {
                        // Need more data
                        break;
                    }
                    Err(e) => {
                        // Invalid frame
                        error!("Redis decode error: {:?}", e);
                        return Err(e.into());
                    }
                }
            }

            // Remove processed bytes from buffer
            buffer.drain(..offset);
        }
    }

    /// One decoded command, from routing to the reply.
    ///
    /// The order is Redis's own (`processCommand`): a cluster redirection first, then the
    /// subscribed-mode restriction, then the commands this server answers itself — protocol
    /// negotiation, connection state, pub/sub mechanics, cluster introspection — and
    /// everything else to the model.
    async fn handle_frame(&self, conn: &mut Conn<'_>, frame: &Frame) -> Result<Flow> {
        let args = frame_args(frame);
        let name = args
            .first()
            .map(|a| String::from_utf8_lossy(a).to_ascii_uppercase())
            .unwrap_or_default();
        let conn_key = self.connection_id.as_u32();
        let proto = conn.protocol.protocol_version();
        // `ASKING` holds for exactly the next command.
        let asking = std::mem::take(&mut conn.asking);

        // Cluster redirection, before anything else looks at the command.
        // The topology lock is a std mutex and is released before anything is awaited.
        let route = self.shared.cluster().map(|cluster| {
            let slots: Vec<u16> = slot_keys(&args).iter().map(|k| key_hash_slot(k)).collect();
            cluster.route(&slots, asking)
        });
        if let Some(route) = route {
            if let Some(error) = route.error() {
                debug!(
                    "Redis connection {} decision=cluster_redirect command={} {}",
                    self.connection_id, name, error
                );
                self.write_reply(conn, encode_error(&error)).await?;
                return Ok(Flow::Continue);
            }
        }

        // RESP2 subscribed mode: only the pub/sub family, PING, QUIT and RESET.
        if proto == 2
            && self.shared.hub.subscription_count(conn_key) > 0
            && !SUBSCRIBED_MODE_COMMANDS.contains(&name.as_str())
        {
            self.write_reply(
                conn,
                encode_error(&format!(
                    "ERR Can't execute '{}': only (P|S)SUBSCRIBE / (P|S)UNSUBSCRIBE / PING / QUIT / RESET are allowed in this context",
                    name.to_ascii_lowercase()
                )),
            )
            .await?;
            return Ok(Flow::Continue);
        }

        let command_str = frame_to_command_string(frame);
        // Truncated for the log and the status channel only - the event below still carries
        // the whole command, because that is what the model has to answer. A single 64 MB bulk
        // string would otherwise be copied verbatim into the *unbounded* status channel on
        // every frame.
        let command_for_log = crate::utils::truncate_for_log(&command_str, 512);
        conn.log
            .debug(format!("Redis command: {}", command_for_log));
        let subscribed_resp2 = proto == 2 && self.shared.hub.subscription_count(conn_key) > 0;

        match name.as_str() {
            "HELLO" => {
                return self
                    .hello(conn, frame, &command_str, &command_for_log)
                    .await
            }
            "RESET" => {
                // Connection state back to a fresh connection's: no subscriptions (dropped
                // without confirmations, as Redis does), RESP2, no ASKING.
                self.shared.hub.remove_connection(conn_key);
                conn.protocol.set_protocol_version(2);
                self.write_reply(conn, b"+RESET\r\n".to_vec()).await?;
                return Ok(Flow::Continue);
            }
            "PING" if subscribed_resp2 => {
                if args.len() > 2 {
                    self.write_reply(conn, encode_error(&wrong_arity("ping")))
                        .await?;
                } else {
                    let payload = args.get(1).cloned().unwrap_or_default();
                    let reply = Resp::Array(vec![Resp::bulk("pong"), Resp::Bulk(payload)]);
                    self.write_reply(conn, reply.encode(2)).await?;
                }
                return Ok(Flow::Continue);
            }
            "QUIT" if subscribed_resp2 => {
                self.write_reply(conn, b"+OK\r\n".to_vec()).await?;
                let _ = conn.write_half.lock().await.shutdown().await;
                return Ok(Flow::Close);
            }
            "SUBSCRIBE" | "PSUBSCRIBE" | "SSUBSCRIBE" => {
                let kind = match name.as_str() {
                    "SUBSCRIBE" => Kind::Channel,
                    "PSUBSCRIBE" => Kind::Pattern,
                    _ => Kind::Shard,
                };
                return self
                    .subscribe(conn, kind, &name, &args, &command_for_log)
                    .await;
            }
            "UNSUBSCRIBE" | "PUNSUBSCRIBE" | "SUNSUBSCRIBE" => {
                let kind = match name.as_str() {
                    "UNSUBSCRIBE" => Kind::Channel,
                    "PUNSUBSCRIBE" => Kind::Pattern,
                    _ => Kind::Shard,
                };
                self.shared
                    .hub
                    .unsubscribe(conn_key, &conn.outbox, proto, kind, &args[1..]);
                // A barrier: wait until the confirmations are on the socket.
                self.write_reply(conn, Vec::new()).await?;
                return Ok(Flow::Continue);
            }
            "PUBLISH" | "SPUBLISH" => {
                return self.publish(conn, &name, &args, &command_for_log).await;
            }
            "PUBSUB" => {
                let reply = self.pubsub_command(&args, proto);
                self.write_reply(conn, reply).await?;
                return Ok(Flow::Continue);
            }
            _ => {}
        }

        // Cluster-mode commands this server answers from its topology.
        if self.shared.cluster.is_some() {
            if let Some(reply) = self.cluster_command(conn, &name, &args, proto) {
                self.write_reply(conn, reply).await?;
                return Ok(Flow::Continue);
            }
        }

        let event = Event::new(
            &REDIS_COMMAND_EVENT,
            command_event_data(&command_str, &args, proto),
        );
        let answer = self.ask_model(conn, &event, &command_for_log).await;
        if answer.accept || answer.deliver {
            warn!(
                "Redis connection {}: redis_accept_subscription / redis_deliver_message only \
                 answer redis_subscribe / redis_publish events; ignored for '{}'",
                self.connection_id, command_for_log
            );
        }
        let mut response = answer.output;
        if response.is_empty() && !answer.close {
            // Redis is strictly request/response: a command with no reply hangs the client
            // until its own timeout. `decision=` tags mirror `src/server/radius/`: on the wire
            // a refusal, an outage and a model that answered with nothing usable all look like
            // "-ERR something", so only the log can tell them apart.
            warn!(
                "Redis connection {} decision=fail_closed_no_action command='{}': \
                 no response action produced, replying with an error",
                self.connection_id, command_for_log
            );
            response = encode_error("ERR no response produced for this command");
        }
        if !response.is_empty() {
            self.write_reply(conn, response).await?;
        }
        if answer.close {
            // The peer command task holds a clone of the write half until its channel
            // closes; half-close now so the client sees EOF at once.
            let _ = conn.write_half.lock().await.shutdown().await;
            return Ok(Flow::Close);
        }
        Ok(Flow::Continue)
    }

    /// Ask the model about one event and fold its answer. A failed call is answered here, fail
    /// closed: `-LOADING` when the backend is saturated, `-ERR` otherwise, never a fabricated
    /// success.
    async fn ask_model(
        &self,
        conn: &Conn<'_>,
        event: &Event,
        command_for_log: &str,
    ) -> ModelAnswer {
        let server_id = self
            .server_id
            .unwrap_or_else(|| crate::state::ServerId::new(0));
        let llm_result = call_llm(
            &self.llm_client,
            &self.app_state,
            server_id,
            Some(self.connection_id),
            event,
            conn.protocol.as_ref(),
        )
        .await;

        let mut answer = ModelAnswer::default();
        match llm_result {
            Ok(execution_result) => {
                // The actions arrive already RESP-encoded as `ActionResult::Output` — the
                // encoding lives once, in `actions.rs::execute_action`, shared with peer
                // injection.
                let mut stack: Vec<ActionResult> = execution_result.protocol_results;
                stack.reverse();
                while let Some(result) = stack.pop() {
                    match result {
                        ActionResult::Output(bytes) => answer.output.extend_from_slice(&bytes),
                        ActionResult::Multiple(items) => {
                            for inner in items.into_iter().rev() {
                                stack.push(inner);
                            }
                        }
                        ActionResult::CloseConnection => {
                            debug!("Redis closing connection");
                            answer.close = true;
                        }
                        ActionResult::Custom { name, .. } if name == ACCEPT_SUBSCRIPTION => {
                            answer.accept = true;
                        }
                        ActionResult::Custom { name, .. } if name == DELIVER_MESSAGE => {
                            answer.deliver = true;
                        }
                        ActionResult::Custom { name, .. } => {
                            // No other Redis action returns Custom; one reappearing would
                            // silently write nothing, so make that loud.
                            warn!(
                                "Redis: action result '{}' is Custom, not Output; client will receive nothing for it",
                                name
                            );
                        }
                        _ => {
                            // Other action results are informational
                        }
                    }
                }
            }
            Err(e) => {
                // A RESP error is the only thing a client can do anything with here, and
                // `redis-rs`, `jedis` and `redis-py` all surface it as an exception rather
                // than a value - so it cannot be mistaken for a reply to the command.
                //
                // `-LOADING` when the backend is merely saturated: clients already know that
                // prefix means "not ready yet, retry", and several retry it automatically.
                // Anything else is `-ERR`.
                let overloaded = crate::llm::is_overload_error(&e);
                let message = redis_error_message(&e, overloaded);
                let decision = if overloaded {
                    "fail_closed_llm_overloaded"
                } else {
                    "fail_closed_llm_error"
                };
                conn.log.warn(format!(
                    "Redis connection {} decision={} command='{}' replying -{}: {}",
                    self.connection_id, decision, command_for_log, message, e
                ));
                answer.output = encode_error(&message);
                answer.failed = true;
            }
        }
        answer
    }

    /// HELLO is protocol negotiation and is answered here. With AUTH it also carries
    /// credentials, which only the handler can judge, so it goes to the model like AUTH does
    /// and the switch waits on its answer: anything but an error accepts.
    async fn hello(
        &self,
        conn: &mut Conn<'_>,
        frame: &Frame,
        command_str: &str,
        command_for_log: &str,
    ) -> Result<Flow> {
        let args = hello_args(frame).unwrap_or_default();
        let mode = if self.shared.cluster.is_some() {
            "cluster"
        } else {
            "standalone"
        };
        let id = u64::from(self.connection_id.as_u32());
        let hello = match resp3::parse_hello(&args) {
            Err(message) => {
                self.write_reply(conn, encode_error(&message)).await?;
                return Ok(Flow::Continue);
            }
            Ok(hello) => hello,
        };
        let target = hello.protover.unwrap_or(conn.protocol.protocol_version());
        if hello.auth.is_none() {
            conn.protocol.set_protocol_version(target);
            conn.log.info(format!(
                "Redis connection {} speaks RESP{} (HELLO)",
                self.connection_id, target
            ));
            self.write_reply(conn, resp3::hello_reply(target, id, mode))
                .await?;
            return Ok(Flow::Continue);
        }
        let event = Event::new(
            &REDIS_COMMAND_EVENT,
            command_event_data(
                command_str,
                &frame_args(frame),
                conn.protocol.protocol_version(),
            ),
        );
        let answer = self.ask_model(conn, &event, command_for_log).await;
        let response = if answer.output.starts_with(b"-") {
            conn.log.info(format!(
                "Redis connection {} decision=model_reject: HELLO with AUTH refused; staying on \
                 RESP{}",
                self.connection_id,
                conn.protocol.protocol_version()
            ));
            answer.output
        } else if answer.output.is_empty() && !answer.close {
            warn!(
                "Redis connection {} decision=fail_closed_no_action command='{}': no answer to \
                 HELLO with AUTH; refusing",
                self.connection_id, command_for_log
            );
            encode_error("ERR no response produced for this command")
        } else {
            conn.protocol.set_protocol_version(target);
            resp3::hello_reply(target, id, mode)
        };
        self.write_reply(conn, response).await?;
        if answer.close {
            let _ = conn.write_half.lock().await.shutdown().await;
            return Ok(Flow::Close);
        }
        Ok(Flow::Continue)
    }

    /// SUBSCRIBE, PSUBSCRIBE, SSUBSCRIBE: bounds in Rust, then the model decides whether the
    /// subscription is allowed, then Rust registers it and confirms each channel.
    async fn subscribe(
        &self,
        conn: &mut Conn<'_>,
        kind: Kind,
        name: &str,
        args: &[Vec<u8>],
        command_for_log: &str,
    ) -> Result<Flow> {
        let conn_key = self.connection_id.as_u32();
        if args.len() < 2 {
            self.write_reply(conn, encode_error(&wrong_arity(name)))
                .await?;
            return Ok(Flow::Continue);
        }
        let names = &args[1..];
        // A request that can never be honoured costs no model call.
        if let Err(message) = self.shared.hub.check_subscribe(conn_key, kind, names) {
            conn.log.warn(format!(
                "Redis connection {} decision=fail_closed_subscription_bound: {}",
                self.connection_id, message
            ));
            self.write_reply(conn, encode_error(&message)).await?;
            return Ok(Flow::Continue);
        }
        let event = Event::new(
            &REDIS_SUBSCRIBE_EVENT,
            serde_json::json!({
                "command": name,
                "channels": names.iter().map(|n| String::from_utf8_lossy(n).to_string()).collect::<Vec<_>>(),
                "subscriptions": self.shared.hub.subscription_count(conn_key),
                "protocol": conn.protocol.protocol_version(),
            }),
        );
        let answer = self.ask_model(conn, &event, command_for_log).await;
        if answer.accept && !answer.failed {
            if !answer.output.is_empty() {
                warn!(
                    "Redis connection {}: the subscription was accepted, so the reply verbs \
                     sent alongside redis_accept_subscription are dropped (the confirmations \
                     are the reply)",
                    self.connection_id
                );
            }
            match self.shared.hub.subscribe(
                conn_key,
                &conn.outbox,
                &conn.protocol.protover_cell(),
                kind,
                names,
            ) {
                Ok(()) => {
                    debug!(
                        "Redis connection {} decision=model_accept command='{}'",
                        self.connection_id, command_for_log
                    );
                    // A barrier: the confirmations are on the socket before the next command.
                    self.write_reply(conn, Vec::new()).await?;
                }
                Err(message) => {
                    conn.log.warn(format!(
                        "Redis connection {} decision=fail_closed_subscription_bound: {}",
                        self.connection_id, message
                    ));
                    self.write_reply(conn, encode_error(&message)).await?;
                }
            }
        } else if !answer.output.is_empty() {
            if !answer.failed {
                debug!(
                    "Redis connection {} decision=model_reject command='{}': not subscribed",
                    self.connection_id, command_for_log
                );
            }
            self.write_reply(conn, answer.output).await?;
        } else if !answer.close {
            warn!(
                "Redis connection {} decision=fail_closed_no_action command='{}': no decision \
                 on the subscription; refusing it",
                self.connection_id, command_for_log
            );
            self.write_reply(
                conn,
                encode_error("ERR no response produced for this command"),
            )
            .await?;
        }
        if answer.close {
            let _ = conn.write_half.lock().await.shutdown().await;
            return Ok(Flow::Close);
        }
        Ok(Flow::Continue)
    }

    /// PUBLISH, SPUBLISH: the bound in Rust, then the model decides whether the message is
    /// delivered and what the publisher is told.
    async fn publish(
        &self,
        conn: &mut Conn<'_>,
        name: &str,
        args: &[Vec<u8>],
        command_for_log: &str,
    ) -> Result<Flow> {
        if args.len() != 3 {
            self.write_reply(conn, encode_error(&wrong_arity(name)))
                .await?;
            return Ok(Flow::Continue);
        }
        let shard = name == "SPUBLISH";
        let (channel, message) = (&args[1], &args[2]);
        let kind = if shard { Kind::Shard } else { Kind::Channel };
        if let Err(error) =
            pubsub::check_name(kind, channel).and_then(|()| pubsub::check_message(message))
        {
            conn.log.warn(format!(
                "Redis connection {} decision=fail_closed_message_bound: {}",
                self.connection_id, error
            ));
            self.write_reply(conn, encode_error(&error)).await?;
            return Ok(Flow::Continue);
        }
        let event = Event::new(
            &REDIS_PUBLISH_EVENT,
            serde_json::json!({
                "command": name,
                "channel": String::from_utf8_lossy(channel),
                "message": String::from_utf8_lossy(message),
                "receivers": self.shared.hub.receivers(channel, shard),
                "protocol": conn.protocol.protocol_version(),
            }),
        );
        let answer = self.ask_model(conn, &event, command_for_log).await;
        if answer.deliver && !answer.failed {
            if !answer.output.is_empty() {
                warn!(
                    "Redis connection {}: the message was delivered, so the reply verbs sent \
                     alongside redis_deliver_message are dropped (the receiver count is the \
                     reply)",
                    self.connection_id
                );
            }
            let receivers = self.shared.hub.publish(channel, message, shard);
            debug!(
                "Redis connection {} decision=model_deliver command='{}' receivers={}",
                self.connection_id, command_for_log, receivers
            );
            self.write_reply(conn, encode_integer(receivers as i64))
                .await?;
        } else if !answer.output.is_empty() {
            if !answer.failed {
                debug!(
                    "Redis connection {} decision=model_withhold command='{}': answered without \
                     delivering",
                    self.connection_id, command_for_log
                );
            }
            self.write_reply(conn, answer.output).await?;
        } else if !answer.close {
            warn!(
                "Redis connection {} decision=fail_closed_no_action command='{}': no decision \
                 on the message; nothing delivered",
                self.connection_id, command_for_log
            );
            self.write_reply(
                conn,
                encode_error("ERR no response produced for this command"),
            )
            .await?;
        }
        if answer.close {
            let _ = conn.write_half.lock().await.shutdown().await;
            return Ok(Flow::Close);
        }
        Ok(Flow::Continue)
    }

    /// `PUBSUB CHANNELS | NUMSUB | NUMPAT | SHARDCHANNELS | SHARDNUMSUB`, from the hub.
    fn pubsub_command(&self, args: &[Vec<u8>], proto: u8) -> Vec<u8> {
        let sub = args
            .get(1)
            .map(|a| String::from_utf8_lossy(a).to_ascii_uppercase())
            .unwrap_or_default();
        let hub = &self.shared.hub;
        let channels = |shard: bool| -> Vec<u8> {
            if args.len() > 3 {
                return encode_error(&wrong_arity(&format!("pubsub|{}", sub.to_lowercase())));
            }
            let pattern = args.get(2).map(|p| p.as_slice());
            if let Some(p) = pattern {
                if let Err(e) = pubsub::check_name(Kind::Pattern, p) {
                    return encode_error(&e);
                }
            }
            Resp::Array(
                hub.active_channels(shard, pattern)
                    .into_iter()
                    .map(Resp::Bulk)
                    .collect(),
            )
            .encode(proto)
        };
        let numsub = |shard: bool| -> Vec<u8> {
            Resp::Map(
                hub.numsub(shard, &args[2..])
                    .into_iter()
                    .map(|(c, n)| (Resp::Bulk(c), Resp::Int(n as i64)))
                    .collect(),
            )
            .encode(proto)
        };
        match sub.as_str() {
            "CHANNELS" => channels(false),
            "SHARDCHANNELS" => channels(true),
            "NUMSUB" => numsub(false),
            "SHARDNUMSUB" => numsub(true),
            "NUMPAT" if args.len() == 2 => encode_integer(hub.numpat() as i64),
            "NUMPAT" => encode_error(&wrong_arity("pubsub|numpat")),
            "" => encode_error(&wrong_arity("pubsub")),
            other => encode_error(&format!(
                "ERR unknown subcommand '{}'. Try PUBSUB HELP.",
                crate::utils::truncate_for_log(&other.to_lowercase(), 64)
            )),
        }
    }

    /// The cluster commands answered from the topology. `None` sends the command on to the
    /// model (`CLUSTER SETSLOT`, `COUNTKEYSINSLOT`, `GETKEYSINSLOT` and the rest need policy
    /// or a keyspace this server does not have).
    fn cluster_command(
        &self,
        conn: &mut Conn<'_>,
        name: &str,
        args: &[Vec<u8>],
        proto: u8,
    ) -> Option<Vec<u8>> {
        match name {
            "ASKING" => {
                conn.asking = true;
                return Some(b"+OK\r\n".to_vec());
            }
            "READONLY" | "READWRITE" => return Some(b"+OK\r\n".to_vec()),
            "CLUSTER" => {}
            _ => return None,
        }
        let sub = args
            .get(1)
            .map(|a| String::from_utf8_lossy(a).to_ascii_uppercase())
            .unwrap_or_default();
        let cluster = self.shared.cluster()?;
        let reply = match (sub.as_str(), args.len()) {
            ("SLOTS", 2) => cluster.slots_reply().encode(proto),
            ("SHARDS", 2) => cluster.shards_reply().encode(proto),
            ("NODES", 2) => cluster.nodes_reply().encode(proto),
            ("INFO", 2) => cluster.info_reply().encode(proto),
            ("MYID", 2) => Resp::bulk(&cluster.me().id).encode(proto),
            ("KEYSLOT", 3) => encode_integer(i64::from(key_hash_slot(&args[2]))),
            ("SLOTS" | "SHARDS" | "NODES" | "INFO" | "MYID" | "KEYSLOT", _) => encode_error(
                &wrong_arity(&format!("cluster|{}", sub.to_ascii_lowercase())),
            ),
            _ => return None,
        };
        Some(reply)
    }
}

/// Every argument of a command frame as raw bytes (the command name first).
fn frame_args(frame: &Frame) -> Vec<Vec<u8>> {
    match frame {
        Frame::Array(parts) => parts
            .iter()
            .map(|f| match f {
                Frame::BulkString(b) | Frame::SimpleString(b) => b.clone(),
                Frame::Integer(i) => i.to_string().into_bytes(),
                other => format!("{other:?}").into_bytes(),
            })
            .collect(),
        other => vec![format!("{other:?}").into_bytes()],
    }
}

/// The data of a `redis_command` event.
///
/// `command` is the space-joined line, kept for display, log templates and simple matching,
/// but it cannot carry argument boundaries: `SET k "a b c"` and `SET k a b c` join to the
/// same string. `args` is the command exactly as the client framed it, one string per
/// argument, the command name first.
///
/// A RESP bulk string is binary-safe and an argument need not be UTF-8, while a JSON string
/// must be text. An argument that is valid UTF-8 is given as that text; one that is not is
/// given as lowercase hex (two digits per byte) and its index is listed in `hex_args`. The
/// encoding is stated rather than left to be guessed, the same rule as TCP's `encoding`
/// field: `"cafe"` is both valid text and valid hex, and only the index list says which one
/// a given argument is.
fn command_event_data(command: &str, args: &[Vec<u8>], protocol: u8) -> serde_json::Value {
    let mut hex_args = Vec::new();
    let args: Vec<String> = args
        .iter()
        .enumerate()
        .map(|(i, arg)| match std::str::from_utf8(arg) {
            Ok(text) => text.to_string(),
            Err(_) => {
                hex_args.push(i);
                hex::encode(arg)
            }
        })
        .collect();
    serde_json::json!({
        "command": command,
        "args": args,
        "hex_args": hex_args,
        "protocol": protocol,
    })
}

/// The arguments of a `HELLO` command, or `None` for any other command.
fn hello_args(frame: &Frame) -> Option<Vec<String>> {
    let Frame::Array(parts) = frame else {
        return None;
    };
    let text = |f: &Frame| match f {
        Frame::BulkString(b) | Frame::SimpleString(b) => String::from_utf8_lossy(b).to_string(),
        Frame::Integer(i) => i.to_string(),
        other => format!("{other:?}"),
    };
    let first = parts.first().map(text)?;
    first
        .eq_ignore_ascii_case("HELLO")
        .then(|| parts[1..].iter().map(text).collect())
}

/// Convert RESP frame to command string for display
fn frame_to_command_string(frame: &Frame) -> String {
    match frame {
        Frame::Array(frames) => {
            let parts: Vec<String> = frames
                .iter()
                .map(|f| match f {
                    Frame::BulkString(bytes) => String::from_utf8_lossy(bytes).to_string(),
                    Frame::SimpleString(bytes) => String::from_utf8_lossy(bytes).to_string(),
                    Frame::Integer(i) => i.to_string(),
                    _ => format!("{:?}", f),
                })
                .collect();
            parts.join(" ")
        }
        _ => format!("{:?}", frame),
    }
}

/// The RESP simple-error payload to send when the LLM backend fails.
///
/// The text is a category, never the error itself (`crate::utils::wire_failure`). That also
/// settles a framing hazard: a RESP simple error is CRLF-terminated with no length prefix, so
/// a newline anywhere in the text ends the frame early and the remainder is parsed as the
/// *next* reply - and backend error strings are routinely multi-line (a timeout with a URL, a
/// serde error with a snippet), so it would have desynchronised the connection for good.
fn redis_error_message(err: &anyhow::Error, overloaded: bool) -> String {
    let text = crate::utils::WireFailure::classify(err).prefixed_text();
    if overloaded {
        format!("LOADING {text}")
    } else {
        format!("ERR {text}")
    }
}
