//! AMQP 0-9-1 broker with LLM-controlled responses.
//!
//! The wire format is implemented directly in [`codec`]. The `amqp` feature carries
//! `lapin`, but `lapin` is an AMQP *client* library — it could never have implemented a
//! broker — so it is used only by `src/client/amqp` and by the E2E tests, which drive this
//! server with a real client.
//!
//! What the LLM (or a script / static handler) decides:
//! - whether a connection is accepted once the handshake finishes (`amqp_connection_open`)
//! - what `Queue.Declare` reports back (`amqp_queue_declare`)
//! - whether a consumer is registered (`amqp_basic_consume`)
//! - **what a consumer receives** — every `Basic.Deliver` comes from an action
//! - what happens to a published message (`amqp_basic_publish`)
//!
//! What the broker answers by itself, because there is no semantics to decide:
//! protocol header exchange, `Connection.Start`/`Tune` negotiation, `Channel.Open`,
//! `Channel.Close`, `Exchange.Declare`, `Queue.Bind`, `Basic.Qos`, `Basic.Cancel`,
//! `Connection.Close` initiated by the client, and heartbeats.
//!
//! **No storage.** There is no queue, no exchange table, no binding table and no message
//! store. The only cross-request state is a directory of *live consumers* — a socket
//! sender plus the channel number a delivery must be written on — which exists so that a
//! `Basic.Deliver` produced on one connection can reach the consumer on another. Nothing
//! survives a disconnect.

pub mod actions;
pub mod codec;

use crate::llm::action_helper::call_llm_batch;
use crate::llm::actions::protocol_trait::ActionResult;
use crate::llm::ollama_client::OllamaClient;
use crate::logging::emit::Log;
use crate::protocol::Event;
use crate::server::connection::ConnectionId;
use crate::state::app_state::AppState;
use crate::state::server::{ConnectionState, ConnectionStatus, ProtocolConnectionInfo};
use actions::{
    AmqpProtocol, RESP_CHANNEL_CLOSE, RESP_CONNECTION_CLOSE, RESP_CONNECTION_OPEN_OK,
    RESP_CONSUME_OK, RESP_QUEUE_DECLARE_OK,
};
use anyhow::{anyhow, Result};
use codec::*;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tracing::{debug, trace};

/// Largest total frame size this broker offers in `Connection.Tune`, in bytes.
/// RabbitMQ's default is the same value.
const DEFAULT_FRAME_MAX: u32 = 131_072;
/// AMQP 0-9-1 section 4.2.3 sets 4096 as the smallest legal frame-max.
const MIN_FRAME_MAX: u32 = 4_096;
/// Hard ceiling on the `frame_max` startup parameter and on anything a client may
/// negotiate upward, so one peer cannot make the broker allocate arbitrarily per frame.
const MAX_FRAME_MAX: u32 = 1_048_576;
/// Highest channel number offered in `Connection.Tune`.
const CHANNEL_MAX: u16 = 2_047;
/// Heartbeat interval offered in `Connection.Tune`, in seconds. 0 disables heartbeats.
const DEFAULT_HEARTBEAT: u16 = 60;
/// Largest message body accepted from a publisher. The content header carries a 64-bit
/// `body-size`; trusting it would let one client announce an 18 EiB message.
pub const MAX_BODY_SIZE: u64 = 8 * 1024 * 1024;
/// Largest number of channels one connection may hold open at once.
const MAX_OPEN_CHANNELS: usize = 256;
/// How much of a declared `body-size` is reserved up front.
///
/// `MAX_BODY_SIZE` bounds one channel, but a connection may open `MAX_OPEN_CHANNELS` of
/// them and a content header costs a few dozen bytes. Reserving the full declared size meant
/// ~256 small frames - a few KB on the wire, and no body bytes at all - bought an immediate
/// 2 GiB allocation held until the connection dropped. `Vec` grows geometrically as the body
/// frames actually arrive, so a real publisher pays at most one extra reallocation and an
/// attacker pays for every byte it claims.
const BODY_RESERVE_CHUNK: u64 = 64 * 1024;
/// How long a peer may take to send the 8-byte protocol header.
///
/// This read happens before anything is negotiated, so nothing else bounds it. A peer that
/// opened a socket and said nothing held the connection's four tasks and its `AppState` row
/// for as long as it liked.
const HANDSHAKE_TIMEOUT_SECS: u64 = 30;
/// Read deadline applied when heartbeating is off.
///
/// `Session::heartbeat` is zero until the client's `Tune-Ok`, and AMQP lets a client answer
/// `Tune-Ok` with zero to switch heartbeating off entirely - so "no heartbeat, no deadline"
/// left the whole handshake untimed *and* handed an uncooperative peer a permanently untimed
/// session. Deliberately long, because an idle consumer with heartbeats off is a real
/// configuration; finite, which is the point.
const IDLE_READ_TIMEOUT_SECS: u64 = 600;
/// How many `accept()` failures in a row before the listener is treated as dead.
const MAX_CONSECUTIVE_ACCEPT_ERRORS: u32 = 64;

/// Concurrent connections this broker admits before it starts refusing.
///
/// [`crate::server::accept_bounded::DEFAULT_MAX_CONNECTIONS`]. [`HANDSHAKE_TIMEOUT_SECS`] and
/// [`IDLE_READ_TIMEOUT_SECS`] bound how long *one* peer holds a slot; only a cap bounds how
/// many of them there can be at once, and the idle bound is ten minutes, so a peer connecting
/// once a second pins six hundred sockets before the first is even eligible to close.
///
/// An AMQP connection is worth more than most in this tree, which argues for the cap rather
/// than for a larger number: each one is four tasks, and each may open
/// [`MAX_OPEN_CHANNELS`] channels that each buffer toward [`MAX_BODY_SIZE`], so the
/// per-connection cost is already a product this cap has to multiply. It is also a long-lived
/// *session* rather than a request — a consumer holds its connection for the life of the
/// application, and AMQP clients are built around exactly one per process — so the broker's
/// live-connection count tracks its client count, not its message rate, and 256 clients is a
/// plausible deployment well inside the default. A deployment that wants a tighter total
/// should tighten `frame_max` or [`MAX_BODY_SIZE`], which are the halves of the product that
/// describe the memory.
const MAX_CONNECTIONS: usize = crate::server::accept_bounded::DEFAULT_MAX_CONNECTIONS;

/// AMQP reply code 320, `CONNECTION_FORCED` (0-9-1 section 4.2.7).
///
/// The spec glosses it as the server closing the connection for a reason of its own, and — the
/// part that decides it here — "the client may retry at some later date", which is the
/// back-off this refusal wants. 506 `RESOURCE_ERROR` is the near miss: its wording about
/// resources fits better, but it is a 5xx *hard* error, which tells a client the operation
/// itself was wrong and should not simply be repeated. A full broker is a transient
/// condition, so the code that says "come back" is the honest one.
const REPLY_CONNECTION_FORCED: u16 = 320;

/// The `reply_text` in [`CONNECTION_CAP_REFUSAL`].
const CONNECTION_CAP_REPLY_TEXT: &str = "connection limit reached, try again later";

/// What a peer over [`MAX_CONNECTIONS`] is told before the socket closes: a connection-level
/// `Connection.Close` on channel 0 carrying [`REPLY_CONNECTION_FORCED`].
///
/// **The argument is that AMQP explicitly provides for a Close that answers nothing.** The
/// method's `class-id`/`method-id` fields name the method that provoked it, and 0-9-1 section
/// 1.4.2.9 says they are *zero* when the close was not provoked by one — which is exactly this
/// case, and exactly what a peer over the cap needs, because it has not sent a method. That is
/// what separates this from `ipp`'s `server-error-busy` and MongoDB's OP_MSG, both rejected in
/// this same sweep: those carry a request identifier that a refused peer has never supplied,
/// so the reply cannot be matched and is read as a protocol violation. Nothing here is
/// fabricated.
///
/// The frame is written before the peer's 8-byte protocol header has arrived, which is the one
/// thing worth checking rather than assuming. It is safe: TCP is full-duplex, so the client
/// writes its header and then reads, and 0-9-1 allows `Connection.Close` at any point after
/// the connection exists — it is how every broker refuses an authentication failure or a
/// missing vhost mid-handshake, so no client can treat an early Close as a surprise. Answering
/// with the protocol header instead (section 4.2.2's "I do not speak your version") was the
/// alternative and would have been a lie: this broker speaks 0-9-1, it is simply full, and a
/// client told its version is wrong retries nothing.
static CONNECTION_CAP_REFUSAL: std::sync::LazyLock<Vec<u8>> = std::sync::LazyLock::new(|| {
    let mut args = Encoder::new();
    args.u16(REPLY_CONNECTION_FORCED);
    args.reply_text(CONNECTION_CAP_REPLY_TEXT);
    // class-id and method-id: zero, "not in reply to any method" (0-9-1 section 1.4.2.9).
    args.u16(0);
    args.u16(0);
    method_frame(0, CLASS_CONNECTION, CONNECTION_CLOSE, &args.into_vec())
});

/// AMQP reply code 505, `UNEXPECTED_FRAME` (0-9-1 section 4.2.7): the peer sent a frame this
/// broker could not decode or did not expect where it arrived.
const REPLY_UNEXPECTED_FRAME: u16 = 505;

/// The `reply_text` that accompanies [`REPLY_UNEXPECTED_FRAME`], fixed rather than built from
/// the decoder's own error.
///
/// The peer gets a category; the log gets the error. This used to be
/// `format!("UNEXPECTED_FRAME - {}", e)`, which put netget's internal decoder diagnostics on a
/// stranger's wire — `"AMQP payload truncated: 24 bytes wanted at offset 6, only 2 available"`
/// tells an unauthenticated peer our buffer offsets, and `anyhow` context chains reach further
/// than that. It is the same leak class `crate::utils::WireFailure` exists for on the LLM-error
/// path; `WireFailure` itself does not apply here because this is a *decode* failure and
/// neither of its two categories (`Overloaded`, `Unavailable`) describes it — but the rule is
/// the one `WireFailure` encodes, so the text is a `&'static str` for the same reason its
/// `text()` is: a helper that can return a `String` is one `format!` away from leaking again.
const UNEXPECTED_FRAME_REPLY_TEXT: &str =
    "UNEXPECTED_FRAME - frame could not be decoded or was not expected here";

/// AMQP 0-9-1 broker.
pub struct AmqpServer;

impl AmqpServer {
    /// Spawn the broker. Bind failure is propagated so the server is never reported
    /// `Running` on a port it does not hold.
    pub async fn spawn_with_llm_actions(
        listen_addr: SocketAddr,
        llm_client: OllamaClient,
        state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        server_id: crate::state::ServerId,
        startup_params: Option<crate::protocol::StartupParams>,
    ) -> Result<SocketAddr> {
        let (frame_max, heartbeat) = match startup_params.as_ref() {
            Some(params) => {
                let frame_max = match params.get_optional_u64("frame_max") {
                    Ok(Some(v)) => {
                        (v.min(u32::MAX as u64) as u32).clamp(MIN_FRAME_MAX, MAX_FRAME_MAX)
                    }
                    Ok(None) => DEFAULT_FRAME_MAX,
                    Err(e) => return Err(anyhow!("AMQP startup parameter error: {}", e)),
                };
                let heartbeat = match params.get_optional_u64("heartbeat_secs") {
                    Ok(Some(v)) => v.min(u16::MAX as u64) as u16,
                    Ok(None) => DEFAULT_HEARTBEAT,
                    Err(e) => return Err(anyhow!("AMQP startup parameter error: {}", e)),
                };
                (frame_max, heartbeat)
            }
            None => (DEFAULT_FRAME_MAX, DEFAULT_HEARTBEAT),
        };

        let listener = TcpListener::bind(listen_addr).await?;
        let local_addr = listener.local_addr()?;

        Log::new(Some(&status_tx)).info(format!(
            "AMQP broker listening on {} (frame_max={}, heartbeat={}s)",
            local_addr, frame_max, heartbeat
        ));

        let accept_state = state.clone();
        let accept_status_tx = status_tx.clone();

        let accept_handle = tokio::spawn(async move {
            // ECONNABORTED (a peer hanging up between SYN and accept) and EMFILE/ENFILE
            // (descriptor exhaustion) are transient. Breaking on one stopped the listener for
            // good and released the port while AppState went on reporting the server Running
            // - a server that lies about being up, reached from the other direction.
            let mut consecutive_accept_errors = 0u32;
            let limiter = crate::server::accept_bounded::ConnectionLimiter::new(MAX_CONNECTIONS);
            loop {
                match crate::server::accept_bounded::accept_bounded(
                    &listener,
                    &limiter,
                    &CONNECTION_CAP_REFUSAL,
                    "AMQP",
                    Some(&accept_status_tx),
                )
                .await
                {
                    Ok((socket, peer_addr, permit)) => {
                        consecutive_accept_errors = 0;
                        Log::new(Some(&accept_status_tx))
                            .debug(format!("AMQP connection from {}", peer_addr));

                        let llm_client = llm_client.clone();
                        let app_state = accept_state.clone();
                        let status_tx = accept_status_tx.clone();

                        // Tracked, not detached: stop_server must abort this task too.
                        let task_owner = app_state.clone();
                        task_owner
                            .spawn_server_task(server_id, async move {
                                // Released when this task ends, and this task is the whole of
                                // the connection even though `handle_connection` spawns a
                                // writer: every exit path there drops `out_tx` and then
                                // `.await`s the writer task, so no task outlives this future
                                // and `MAX_CONNECTIONS` caps live connections rather than
                                // accepts.
                                let _permit = permit;
                                if let Err(e) = handle_connection(
                                    socket, peer_addr, local_addr, llm_client, app_state,
                                    status_tx, server_id, frame_max, heartbeat,
                                )
                                .await
                                {
                                    debug!("AMQP connection {} ended: {}", peer_addr, e);
                                }
                            })
                            .await;
                    }
                    Err(e) => {
                        consecutive_accept_errors += 1;
                        if consecutive_accept_errors >= MAX_CONSECUTIVE_ACCEPT_ERRORS {
                            Log::new(Some(&accept_status_tx)).error(format!(
                                "AMQP accept failed {} times in a row ({}); listener stopping",
                                consecutive_accept_errors, e
                            ));
                            break;
                        }
                        Log::new(Some(&accept_status_tx))
                            .warn(format!("AMQP accept error: {} - retrying", e));
                        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    }
                }
            }
        });

        // Register the accept loop so stop_server can abort it and release the port.
        state.register_server_task(server_id, accept_handle).await;
        let _ = status_tx.send("__UPDATE_UI__".to_string());
        Ok(local_addr)
    }
}

// ============================================================================
// Per-connection state
// ============================================================================

/// A `Basic.Publish` whose content header and body frames have not all arrived yet.
struct PendingPublish {
    exchange: String,
    routing_key: String,
    mandatory: bool,
    immediate: bool,
    properties: BasicProperties,
    body_size: u64,
    body: Vec<u8>,
    header_seen: bool,
}

#[derive(Default)]
struct ChannelState {
    pending: Option<PendingPublish>,
}

/// Where the connection is in the AMQP handshake.
#[derive(PartialEq, Clone, Copy, Debug)]
enum Phase {
    AwaitStartOk,
    AwaitTuneOk,
    AwaitOpen,
    Open,
}

/// What the frame dispatcher wants the read loop to do next.
enum Next {
    Continue,
    Close,
}

#[allow(clippy::too_many_arguments)]
async fn handle_connection(
    socket: TcpStream,
    peer_addr: SocketAddr,
    local_addr: SocketAddr,
    llm_client: OllamaClient,
    app_state: Arc<AppState>,
    status_tx: mpsc::UnboundedSender<String>,
    server_id: crate::state::ServerId,
    offered_frame_max: u32,
    offered_heartbeat: u16,
) -> Result<()> {
    let connection_id = ConnectionId::new(app_state.get_next_unified_id().await);
    let (mut read_half, write_half) = tokio::io::split(socket);
    // Shared with the dashboard's peer command task: every AMQP action writes its frames
    // through `out_tx` (below), so the only thing the peer task ever does to the write half
    // directly is `shutdown()` it for `close_connection`.
    let write_half = Arc::new(tokio::sync::Mutex::new(write_half));

    // Every write for this connection funnels through one channel, so a frame produced by
    // the read loop can never interleave with one produced by an action running for a
    // different connection (a cross-connection Basic.Deliver, for instance). The writer
    // task is also the one place every outbound byte passes, so it owns the sent counters.
    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let writer_status_tx = status_tx.clone();
    let writer_write_half = write_half.clone();
    let writer_state = app_state.clone();
    let writer_handle = tokio::spawn(async move {
        while let Some(bytes) = out_rx.recv().await {
            let written = {
                let mut w = writer_write_half.lock().await;
                w.write_all(&bytes).await
            };
            if let Err(e) = written {
                Log::new(Some(&writer_status_tx)).debug(format!("AMQP write failed: {}", e));
                break;
            }
            writer_state
                .update_connection_stats(
                    server_id,
                    connection_id,
                    None,
                    Some(bytes.len() as u64),
                    None,
                    Some(1),
                )
                .await;
        }
        let _ = writer_write_half.lock().await.flush().await;
    });

    let now = crate::utils::clock::Instant::now();
    let conn_state = ConnectionState {
        id: connection_id,
        remote_addr: peer_addr,
        local_addr,
        bytes_sent: 0,
        bytes_received: 0,
        packets_sent: 0,
        packets_received: 0,
        last_activity: now,
        status: ConnectionStatus::Active,
        status_changed_at: now,
        protocol_info: ProtocolConnectionInfo::new(json!({
            "virtual_host": Value::Null,
            "username": Value::Null,
        })),
    };
    app_state
        .add_connection_to_server(server_id, conn_state)
        .await;
    let _ = status_tx.send("__UPDATE_UI__".to_string());

    Log::new(Some(&status_tx)).info(format!(
        "AMQP connection {} from {}",
        connection_id, peer_addr
    ));

    let mut session = Session {
        ready_publishes: Vec::new(),
        server_id,
        connection_id,
        peer_addr,
        out_tx: out_tx.clone(),
        status_tx: status_tx.clone(),
        app_state: app_state.clone(),
        llm_client,
        protocol: Arc::new(AmqpProtocol::for_connection(
            server_id,
            connection_id,
            out_tx.clone(),
            status_tx.clone(),
            offered_frame_max,
        )),
        channels: HashMap::new(),
        frame_max: offered_frame_max,
        heartbeat: 0,
        mechanism: String::new(),
        locale: String::new(),
        username: None,
        has_password: false,
        client_properties: json!({}),
        virtual_host: String::new(),
    };

    // Peer messaging: the dashboard's "message this peer" / "disconnect this peer" inject
    // actions into THIS connection through the same executor the handler chain uses.
    // Registered before the first read, so the operator can reach the connection even
    // while a manual rule parks its connection.open.
    let peer_rx = crate::server::peer_support::register_peer_channel(
        &app_state,
        server_id,
        connection_id.as_u32(),
    )
    .await;
    crate::server::peer_support::spawn_peer_command_task(
        peer_rx,
        session.protocol.clone(),
        app_state.clone(),
        server_id,
        connection_id.as_u32(),
        write_half.clone(),
        status_tx.clone(),
    );

    // Buffered so a batch can see which frames are already here without waiting for more
    // (`Session::collect_publishes`). The buffer bounds nothing: `read_frame` still checks each
    // declared size before allocating, and a frame larger than the buffer is read past it.
    let mut reader = tokio::io::BufReader::with_capacity(READ_BUFFER_BYTES, &mut read_half);
    let result = session
        .run(&mut reader, offered_frame_max, offered_heartbeat)
        .await;

    if let Err(e) = &result {
        Log::new(Some(&status_tx)).debug(format!("AMQP connection {} error: {}", connection_id, e));
    }

    // Every exit path - EOF, heartbeat timeout, protocol error, Connection.Close either
    // way, handler refusal - lands here. The peer handle must go before the writer is
    // awaited: the peer task holds an `AmqpProtocol` (and with it an `out_tx` clone) and
    // only drops it once its command channel closes.
    actions::unregister_consumers_for_connection(server_id, connection_id);
    app_state
        .remove_peer_handle(server_id, connection_id.as_u32())
        .await;
    drop(out_tx);
    drop(session);
    let _ = writer_handle.await;
    app_state
        .update_connection_status(server_id, connection_id, ConnectionStatus::Closed)
        .await;
    let _ = status_tx.send("__UPDATE_UI__".to_string());
    Log::new(Some(&status_tx)).info(format!("AMQP connection {} closed", connection_id));

    result
}

struct Session {
    /// Publishes completed and not yet handed to the handler, with their channel: a batch
    /// being collected (`collect_publishes`). Empty whenever the instance is not batching.
    ready_publishes: Vec<(u16, Event)>,
    server_id: crate::state::ServerId,
    connection_id: ConnectionId,
    peer_addr: SocketAddr,
    out_tx: mpsc::UnboundedSender<Vec<u8>>,
    status_tx: mpsc::UnboundedSender<String>,
    app_state: Arc<AppState>,
    llm_client: OllamaClient,
    protocol: Arc<AmqpProtocol>,
    channels: HashMap<u16, ChannelState>,
    frame_max: u32,
    heartbeat: u16,
    mechanism: String,
    locale: String,
    username: Option<String>,
    has_password: bool,
    client_properties: Value,
    virtual_host: String,
}

impl Session {
    async fn run<R: AsyncBufRead + Unpin>(
        &mut self,
        reader: &mut R,
        offered_frame_max: u32,
        offered_heartbeat: u16,
    ) -> Result<()> {
        // --- protocol header -------------------------------------------------
        // Bounded: see HANDSHAKE_TIMEOUT_SECS. Nothing has been negotiated yet, so this read
        // had no deadline of any kind.
        let mut header = [0u8; 8];
        match tokio::time::timeout(
            std::time::Duration::from_secs(HANDSHAKE_TIMEOUT_SECS),
            reader.read_exact(&mut header),
        )
        .await
        {
            Ok(result) => result
                .map_err(|e| anyhow!("no AMQP protocol header from {}: {}", self.peer_addr, e))?,
            Err(_) => {
                return Err(anyhow!(
                    "no AMQP protocol header from {} within {}s",
                    self.peer_addr,
                    HANDSHAKE_TIMEOUT_SECS
                ))
            }
        };
        self.count_received(header.len()).await;

        if header != PROTOCOL_HEADER_091 {
            // Section 4.2.2: answer an unsupported version with the header the broker
            // does speak, then close. Anything not starting with "AMQP" is not a client.
            Log::new(Some(&self.status_tx)).warn(format!(
                "AMQP client {} sent an unsupported protocol header {:?}; replying with 0-9-1 \
                 and closing",
                self.peer_addr, header
            ));
            let _ = self.out_tx.send(PROTOCOL_HEADER_091.to_vec());
            return Ok(());
        }

        // --- Connection.Start ------------------------------------------------
        self.send_method(
            0,
            CLASS_CONNECTION,
            CONNECTION_START,
            connection_start_args()?,
        );

        let mut phase = Phase::AwaitStartOk;
        // Until Tune-Ok the negotiated size is the one we offered.
        let mut max_payload = offered_frame_max as usize - FRAME_OVERHEAD;

        loop {
            let frame = match self.read_next_frame(reader, max_payload).await? {
                Some(frame) => frame,
                None => return Ok(()), // peer closed
            };

            let mut dispatched = self.dispatch(frame, &mut phase, offered_heartbeat).await;
            // A publish completed with batching on: take every further publish on the same
            // channel that is already here, then answer them all in one call.
            if matches!(dispatched, Ok(Next::Continue)) && !self.ready_publishes.is_empty() {
                let collected = self
                    .collect_publishes(reader, max_payload, &mut phase, offered_heartbeat)
                    .await;
                let answered = self.flush_publishes().await;
                dispatched = match (collected, answered) {
                    // The publishes before a bad frame were valid and are answered first, as
                    // they would have been one at a time; then the bad frame is reported.
                    (Err(e), Next::Continue) => Err(e),
                    (Ok(Next::Close), _) | (_, Next::Close) => Ok(Next::Close),
                    (Ok(Next::Continue), Next::Continue) => Ok(Next::Continue),
                };
            }

            let next = match dispatched {
                Ok(next) => next,
                Err(e) => {
                    // A framing or decoding error desynchronises the stream; the spec's
                    // remedy is a connection exception.
                    //
                    // The error goes in the log line below and nowhere else. What the peer
                    // gets is the fixed category — see `UNEXPECTED_FRAME_REPLY_TEXT`.
                    Log::new(Some(&self.status_tx)).warn(format!(
                        "AMQP protocol error from {}: decision=fail_closed_decode_error: {}",
                        self.peer_addr, e
                    ));
                    self.send_connection_close(
                        REPLY_UNEXPECTED_FRAME,
                        UNEXPECTED_FRAME_REPLY_TEXT,
                        0,
                        0,
                    );
                    return Ok(());
                }
            };

            if phase == Phase::Open || phase == Phase::AwaitOpen {
                max_payload = (self.frame_max as usize).saturating_sub(FRAME_OVERHEAD);
            }

            if matches!(next, Next::Close) {
                return Ok(());
            }
        }
    }

    /// After a publish completed with batching on, take the frames already here that belong
    /// to further publishes on the same channel, dispatching each so complete publishes join
    /// `ready_publishes`, up to [`crate::protocol::metadata::MAX_BATCH_EVENTS`].
    ///
    /// Only a frame that is wholly in the read buffer is taken, so nothing here waits on the
    /// peer. It stops at the first frame that is anything other than a `Basic.Publish`, its
    /// content header or a body frame on that channel, or a heartbeat - every synchronous
    /// method owes its own reply, and frames for other channels keep their order - and leaves
    /// that frame for the session loop. A publish whose content is still arriving simply stays
    /// pending on its channel, as it would have without batching.
    ///
    /// `Ok(Next::Close)` if a dispatched frame ended the connection; `Err` for a frame that
    /// broke the protocol, after which the session loop closes.
    async fn collect_publishes<R: AsyncBufRead + Unpin>(
        &mut self,
        reader: &mut R,
        max_payload: usize,
        phase: &mut Phase,
        offered_heartbeat: u16,
    ) -> Result<Next> {
        let Some(&(channel, _)) = self.ready_publishes.first() else {
            return Ok(Next::Continue);
        };
        while self.ready_publishes.len() < crate::protocol::metadata::MAX_BATCH_EVENTS {
            // `fill_buf` returns what is buffered without reading, and polls the socket once
            // only when the buffer is empty; the zero deadline means that poll never waits.
            // It is cancel-safe, so a timeout loses nothing.
            let belongs =
                match tokio::time::timeout(std::time::Duration::ZERO, reader.fill_buf()).await {
                    Ok(Ok(buf)) => frame_belongs_to_publish_batch(buf, channel, max_payload),
                    _ => false,
                };
            if !belongs {
                break;
            }
            let frame = match read_frame(reader, max_payload).await? {
                Some(frame) => frame,
                None => break,
            };
            self.count_received(FRAME_OVERHEAD + frame.payload.len())
                .await;
            if let Next::Close = self.dispatch(frame, phase, offered_heartbeat).await? {
                return Ok(Next::Close);
            }
        }
        Ok(Next::Continue)
    }

    /// Hand every collected publish to the handler in one batch.
    async fn flush_publishes(&mut self) -> Next {
        let ready = std::mem::take(&mut self.ready_publishes);
        let Some(&(channel, _)) = ready.first() else {
            return Next::Continue;
        };
        let events: Vec<Event> = ready.into_iter().map(|(_, event)| event).collect();
        if events.len() > 1 {
            Log::new(Some(&self.status_tx)).debug(format!(
                "AMQP answering {} publishes on channel {} together",
                events.len(),
                channel
            ));
        }
        match self.run_handler(&events, channel, None, None).await {
            HandlerOutcome::Closed => Next::Close,
            HandlerOutcome::Wrote(mask) if mask & RESP_CONNECTION_CLOSE != 0 => Next::Close,
            _ => Next::Continue,
        }
    }

    /// Read one frame, enforcing the negotiated heartbeat as a read deadline.
    async fn read_next_frame<R: AsyncRead + Unpin>(
        &self,
        reader: &mut R,
        max_payload: usize,
    ) -> Result<Option<Frame>> {
        // Section 4.2.7: a peer that sends nothing for two heartbeat intervals is dead. Where
        // the peer switched heartbeating off, IDLE_READ_TIMEOUT_SECS applies instead - there
        // is always a deadline, because there was previously none at all before Tune-Ok and
        // none ever for a peer that answered zero.
        let deadline = if self.heartbeat == 0 {
            std::time::Duration::from_secs(IDLE_READ_TIMEOUT_SECS)
        } else {
            std::time::Duration::from_secs(self.heartbeat as u64 * 2)
        };
        let result = match tokio::time::timeout(deadline, read_frame(reader, max_payload)).await {
            Ok(result) => result,
            Err(_) => {
                Log::new(Some(&self.status_tx)).warn(format!(
                    "AMQP client {} sent nothing for {}s ({}); closing",
                    self.peer_addr,
                    deadline.as_secs(),
                    if self.heartbeat == 0 {
                        "heartbeating is off, so the idle timeout applies"
                    } else {
                        "two heartbeat intervals"
                    }
                ));
                Ok(None)
            }
        };
        if let Ok(Some(frame)) = &result {
            // 7-byte frame header + payload + the 0xCE end marker.
            self.count_received(FRAME_OVERHEAD + frame.payload.len())
                .await;
        }
        result
    }

    /// Live inbound counters for the dashboard (and `last_activity` for connection-scoped
    /// tasks). Outbound bytes are counted by the writer task, which sees every frame.
    async fn count_received(&self, bytes: usize) {
        self.app_state
            .update_connection_stats(
                self.server_id,
                self.connection_id,
                Some(bytes as u64),
                None,
                Some(1),
                None,
            )
            .await;
    }

    async fn dispatch(
        &mut self,
        frame: Frame,
        phase: &mut Phase,
        offered_heartbeat: u16,
    ) -> Result<Next> {
        match frame.frame_type {
            FRAME_HEARTBEAT => {
                trace!("AMQP heartbeat from {}", self.peer_addr);
                Ok(Next::Continue)
            }
            FRAME_HEADER => self.on_content_header(frame).await,
            FRAME_BODY => self.on_content_body(frame).await,
            FRAME_METHOD => self.on_method(frame, phase, offered_heartbeat).await,
            other => Err(anyhow!("unknown frame type {}", other)),
        }
    }

    async fn on_method(
        &mut self,
        frame: Frame,
        phase: &mut Phase,
        offered_heartbeat: u16,
    ) -> Result<Next> {
        let mut d = Decoder::new(&frame.payload);
        let class_id = d.u16()?;
        let method_id = d.u16()?;
        let channel = frame.channel;

        trace!(
            "AMQP <- {} on channel {} from {}",
            method_name(class_id, method_id),
            channel,
            self.peer_addr
        );

        // The handshake is a strict sequence; anything out of order is a protocol error.
        match *phase {
            Phase::AwaitStartOk => {
                if (class_id, method_id) != (CLASS_CONNECTION, CONNECTION_START_OK) {
                    return Err(anyhow!(
                        "expected connection.start-ok, got {}",
                        method_name(class_id, method_id)
                    ));
                }
                self.client_properties = d.field_table()?;
                self.mechanism = d.short_string()?;
                let response = d.long_string()?;
                self.locale = d.short_string()?;
                let (username, has_password) = parse_plain_response(&response);
                self.username = username;
                self.has_password = has_password;

                Log::new(Some(&self.status_tx)).debug(format!(
                    "AMQP start-ok from {} (mechanism={}, user={})",
                    self.peer_addr,
                    self.mechanism,
                    self.username.as_deref().unwrap_or("-")
                ));

                let mut args = Encoder::new();
                args.u16(CHANNEL_MAX);
                args.u32(self.frame_max);
                args.u16(offered_heartbeat);
                self.send_method(0, CLASS_CONNECTION, CONNECTION_TUNE, args.into_vec());
                *phase = Phase::AwaitTuneOk;
                Ok(Next::Continue)
            }

            Phase::AwaitTuneOk => {
                if (class_id, method_id) != (CLASS_CONNECTION, CONNECTION_TUNE_OK) {
                    return Err(anyhow!(
                        "expected connection.tune-ok, got {}",
                        method_name(class_id, method_id)
                    ));
                }
                let _channel_max = d.u16()?;
                let client_frame_max = d.u32()?;
                let client_heartbeat = d.u16()?;

                // A client may only lower frame-max; 0 means "take the server's value".
                self.frame_max = if client_frame_max == 0 {
                    self.frame_max
                } else {
                    client_frame_max.clamp(MIN_FRAME_MAX, self.frame_max)
                };
                self.heartbeat = client_heartbeat;
                self.protocol.set_frame_max(self.frame_max);

                if self.heartbeat > 0 {
                    spawn_heartbeat(
                        self.out_tx.clone(),
                        self.heartbeat,
                        self.app_state.clone(),
                        self.server_id,
                    )
                    .await;
                }
                Log::new(Some(&self.status_tx)).debug(format!(
                    "AMQP tuned for {}: frame_max={} heartbeat={}s",
                    self.peer_addr, self.frame_max, self.heartbeat
                ));
                *phase = Phase::AwaitOpen;
                Ok(Next::Continue)
            }

            Phase::AwaitOpen => {
                if (class_id, method_id) != (CLASS_CONNECTION, CONNECTION_OPEN) {
                    return Err(anyhow!(
                        "expected connection.open, got {}",
                        method_name(class_id, method_id)
                    ));
                }
                self.virtual_host = d.short_string()?;
                let _reserved = d.short_string()?;
                let _bits = d.bits(1)?;
                self.on_connection_open(phase).await
            }

            Phase::Open => self.on_open_method(class_id, method_id, channel, d).await,
        }
    }

    /// The handshake is finished and the client asked to open a virtual host. This is the
    /// connection's one authentication/authorisation decision.
    async fn on_connection_open(&mut self, phase: &mut Phase) -> Result<Next> {
        Log::new(Some(&self.status_tx)).info(format!(
            "AMQP connection.open from {} vhost='{}' user='{}'",
            self.peer_addr,
            self.virtual_host,
            self.username.as_deref().unwrap_or("-")
        ));

        let event = Event::new(
            &actions::AMQP_CONNECTION_OPEN_EVENT,
            json!({
                "virtual_host": self.virtual_host,
                "username": self.username,
                "has_password": self.has_password,
                "mechanism": self.mechanism,
                "locale": self.locale,
                "client_properties": self.client_properties,
                "peer_address": self.peer_addr.to_string(),
                "frame_max": self.frame_max,
                "heartbeat_secs": self.heartbeat,
            }),
        );

        let outcome = self
            .run_handler(std::slice::from_ref(&event), 0, None, None)
            .await;
        match outcome {
            HandlerOutcome::Closed => Ok(Next::Close),
            HandlerOutcome::Wrote(mask) if mask & RESP_CONNECTION_CLOSE != 0 => {
                // The model refused. Its Connection.Close is already queued.
                Log::new(Some(&self.status_tx)).info(format!(
                    "AMQP connection from {} refused by handler",
                    self.peer_addr
                ));
                Ok(Next::Close)
            }
            HandlerOutcome::Wrote(mask) if mask & RESP_CONNECTION_OPEN_OK != 0 => {
                *phase = Phase::Open;
                self.app_state
                    .with_server_mut(self.server_id, |server| {
                        if let Some(conn) = server.connections.get_mut(&self.connection_id) {
                            conn.protocol_info = ProtocolConnectionInfo::new(json!({
                                "virtual_host": self.virtual_host,
                                "username": self.username,
                            }));
                        }
                    })
                    .await;
                let _ = self.status_tx.send("__UPDATE_UI__".to_string());
                Ok(Next::Continue)
            }
            _ => {
                // Silence is refusal. An LLM outage, a script that answered nothing or a
                // handler that produced an unrelated action must not open a broker to a
                // client — and the refusal a handler asks for explicitly stays
                // distinguishable from this one by its reply code and text.
                Log::new(Some(&self.status_tx)).warn(format!(
                    "AMQP handler made no decision for {}: decision=fail_closed_no_answer; \
                     refusing with 403. Answer amqp_connection_open with \
                     amqp_connection_open_ok to accept clients.",
                    self.peer_addr
                ));
                self.send_connection_close(
                    REPLY_ACCESS_REFUSED,
                    "ACCESS_REFUSED - the broker's handler made no decision about this connection",
                    CLASS_CONNECTION,
                    CONNECTION_OPEN,
                );
                Ok(Next::Close)
            }
        }
    }

    async fn on_open_method(
        &mut self,
        class_id: u16,
        method_id: u16,
        channel: u16,
        mut d: Decoder<'_>,
    ) -> Result<Next> {
        match (class_id, method_id) {
            // ---- connection -------------------------------------------------
            (CLASS_CONNECTION, CONNECTION_CLOSE) => {
                let reply_code = d.u16()?;
                let reply_text = d.short_string()?;
                Log::new(Some(&self.status_tx)).info(format!(
                    "AMQP client {} closing: {} {}",
                    self.peer_addr, reply_code, reply_text
                ));
                self.send_method(0, CLASS_CONNECTION, CONNECTION_CLOSE_OK, Vec::new());
                Ok(Next::Close)
            }
            (CLASS_CONNECTION, CONNECTION_CLOSE_OK) => Ok(Next::Close),

            // ---- channel ----------------------------------------------------
            (CLASS_CHANNEL, CHANNEL_OPEN) => {
                if channel == 0 {
                    return Err(anyhow!("channel.open on channel 0"));
                }
                if self.channels.len() >= MAX_OPEN_CHANNELS && !self.channels.contains_key(&channel)
                {
                    self.send_connection_close(
                        REPLY_ACCESS_REFUSED,
                        "ACCESS_REFUSED - too many open channels",
                        CLASS_CHANNEL,
                        CHANNEL_OPEN,
                    );
                    return Ok(Next::Close);
                }
                self.channels.insert(channel, ChannelState::default());
                let mut args = Encoder::new();
                args.long_string(b"");
                self.send_method(channel, CLASS_CHANNEL, CHANNEL_OPEN_OK, args.into_vec());
                Log::new(Some(&self.status_tx)).debug(format!("AMQP channel {} opened", channel));
                Ok(Next::Continue)
            }
            (CLASS_CHANNEL, CHANNEL_CLOSE) => {
                let reply_code = d.u16()?;
                let reply_text = d.short_string()?;
                Log::new(Some(&self.status_tx)).debug(format!(
                    "AMQP channel {} closed by client: {} {}",
                    channel, reply_code, reply_text
                ));
                self.close_channel(channel);
                self.send_method(channel, CLASS_CHANNEL, CHANNEL_CLOSE_OK, Vec::new());
                Ok(Next::Continue)
            }
            (CLASS_CHANNEL, CHANNEL_CLOSE_OK) => {
                self.close_channel(channel);
                Ok(Next::Continue)
            }

            // ---- exchange ---------------------------------------------------
            (CLASS_EXCHANGE, EXCHANGE_DECLARE) => {
                let _reserved = d.u16()?;
                let exchange = d.short_string()?;
                let kind = d.short_string()?;
                let bits = d.bits(5)?;
                let nowait = bits.get(4).copied().unwrap_or(false);
                Log::new(Some(&self.status_tx)).debug(format!(
                    "AMQP exchange.declare '{}' type={} on channel {}",
                    exchange, kind, channel
                ));
                if !nowait {
                    self.send_method(channel, CLASS_EXCHANGE, EXCHANGE_DECLARE_OK, Vec::new());
                }
                Ok(Next::Continue)
            }

            // ---- queue ------------------------------------------------------
            (CLASS_QUEUE, QUEUE_DECLARE) => {
                let _reserved = d.u16()?;
                let queue = d.short_string()?;
                let bits = d.bits(5)?;
                let arguments = d.field_table()?;
                let nowait = bits.get(4).copied().unwrap_or(false);
                self.on_queue_declare(channel, queue, &bits, arguments, nowait)
                    .await
            }
            (CLASS_QUEUE, QUEUE_BIND) => {
                let _reserved = d.u16()?;
                let queue = d.short_string()?;
                let exchange = d.short_string()?;
                let routing_key = d.short_string()?;
                let bits = d.bits(1)?;
                Log::new(Some(&self.status_tx)).debug(format!(
                    "AMQP queue.bind '{}' to exchange '{}' key '{}'",
                    queue, exchange, routing_key
                ));
                if !bits.first().copied().unwrap_or(false) {
                    self.send_method(channel, CLASS_QUEUE, QUEUE_BIND_OK, Vec::new());
                }
                Ok(Next::Continue)
            }

            // ---- basic ------------------------------------------------------
            (CLASS_BASIC, BASIC_QOS) => {
                let _prefetch_size = d.u32()?;
                let prefetch_count = d.u16()?;
                trace!("AMQP basic.qos prefetch_count={}", prefetch_count);
                self.send_method(channel, CLASS_BASIC, BASIC_QOS_OK, Vec::new());
                Ok(Next::Continue)
            }
            (CLASS_BASIC, BASIC_CONSUME) => {
                let _reserved = d.u16()?;
                let queue = d.short_string()?;
                let consumer_tag = d.short_string()?;
                let bits = d.bits(4)?;
                let arguments = d.field_table()?;
                self.on_basic_consume(channel, queue, consumer_tag, &bits, arguments)
                    .await
            }
            (CLASS_BASIC, BASIC_CANCEL) => {
                let consumer_tag = d.short_string()?;
                let bits = d.bits(1)?;
                // Scoped to this connection: a tag is client-chosen and unique only within
                // a connection, so without the check one client could cancel another's
                // consumer by naming its tag - after which that client silently stopped
                // receiving deliveries with no Basic.Cancel to explain it.
                let cancelled =
                    actions::unregister_consumer(self.server_id, self.connection_id, &consumer_tag);
                Log::new(Some(&self.status_tx)).debug(format!(
                    "AMQP basic.cancel '{}' (cancelled={})",
                    consumer_tag, cancelled
                ));
                if !bits.first().copied().unwrap_or(false) {
                    let mut args = Encoder::new();
                    args.short_string(&consumer_tag)?;
                    self.send_method(channel, CLASS_BASIC, BASIC_CANCEL_OK, args.into_vec());
                }
                Ok(Next::Continue)
            }
            (CLASS_BASIC, BASIC_PUBLISH) => {
                let _reserved = d.u16()?;
                let exchange = d.short_string()?;
                let routing_key = d.short_string()?;
                let bits = d.bits(2)?;
                if !self.channels.contains_key(&channel) {
                    return Err(anyhow!(
                        "basic.publish on channel {} which is not open",
                        channel
                    ));
                }
                let state = self.channels.entry(channel).or_default();
                state.pending = Some(PendingPublish {
                    exchange,
                    routing_key,
                    mandatory: bits.first().copied().unwrap_or(false),
                    immediate: bits.get(1).copied().unwrap_or(false),
                    properties: BasicProperties::default(),
                    body_size: 0,
                    body: Vec::new(),
                    header_seen: false,
                });
                Ok(Next::Continue)
            }
            (CLASS_BASIC, BASIC_ACK) => {
                let delivery_tag = d.u64()?;
                let bits = d.bits(1)?;
                trace!(
                    "AMQP basic.ack delivery_tag={} multiple={}",
                    delivery_tag,
                    bits.first().copied().unwrap_or(false)
                );
                Ok(Next::Continue)
            }
            (CLASS_BASIC, BASIC_REJECT) | (CLASS_BASIC, BASIC_NACK) => {
                let delivery_tag = d.u64()?;
                Log::new(Some(&self.status_tx)).debug(format!(
                    "AMQP client rejected delivery_tag={} (nothing is requeued: the broker \
                     stores no messages)",
                    delivery_tag
                ));
                Ok(Next::Continue)
            }

            // ---- everything else -------------------------------------------
            _ => {
                let name = method_name(class_id, method_id);
                Log::new(Some(&self.status_tx)).warn(format!(
                    "AMQP {} is not implemented; closing channel {} with 540",
                    name, channel
                ));
                let text = format!(
                    "NOT_IMPLEMENTED - {} is not implemented by this broker",
                    name
                );
                if channel == 0 {
                    self.send_connection_close(REPLY_NOT_IMPLEMENTED, &text, class_id, method_id);
                    Ok(Next::Close)
                } else {
                    self.send_channel_close(
                        channel,
                        REPLY_NOT_IMPLEMENTED,
                        &text,
                        class_id,
                        method_id,
                    );
                    self.close_channel(channel);
                    Ok(Next::Continue)
                }
            }
        }
    }

    async fn on_queue_declare(
        &mut self,
        channel: u16,
        queue: String,
        bits: &[bool],
        arguments: Value,
        nowait: bool,
    ) -> Result<Next> {
        Log::new(Some(&self.status_tx)).info(format!(
            "AMQP queue.declare '{}' on channel {}",
            queue, channel
        ));

        if nowait {
            // The client explicitly asked for no reply, so there is nothing to decide.
            debug!("AMQP queue.declare '{}' with no-wait; no reply owed", queue);
            return Ok(Next::Continue);
        }

        let event = Event::new(
            &actions::AMQP_QUEUE_DECLARE_EVENT,
            json!({
                "channel": channel,
                "queue": queue,
                "passive": bits.first().copied().unwrap_or(false),
                "durable": bits.get(1).copied().unwrap_or(false),
                "exclusive": bits.get(2).copied().unwrap_or(false),
                "auto_delete": bits.get(3).copied().unwrap_or(false),
                "arguments": arguments,
            }),
        );

        match self
            .run_handler(std::slice::from_ref(&event), channel, None, Some(&queue))
            .await
        {
            HandlerOutcome::Closed => Ok(Next::Close),
            HandlerOutcome::Wrote(mask)
                if mask & (RESP_QUEUE_DECLARE_OK | RESP_CHANNEL_CLOSE | RESP_CONNECTION_CLOSE)
                    != 0 =>
            {
                if mask & RESP_CONNECTION_CLOSE != 0 {
                    Ok(Next::Close)
                } else {
                    Ok(Next::Continue)
                }
            }
            _ => {
                // Queue.Declare-Ok is mandatory unless no-wait was set, and a queue's
                // existence is not a security decision — reporting an empty queue is the
                // least surprising answer and keeps the client from blocking forever.
                Log::new(Some(&self.status_tx)).warn(format!(
                    "AMQP no amqp_queue_declare_ok from handler for '{}'; reporting an empty \
                     queue",
                    queue
                ));
                self.send_queue_declare_ok(channel, &queue, 0, 0)?;
                Ok(Next::Continue)
            }
        }
    }

    async fn on_basic_consume(
        &mut self,
        channel: u16,
        queue: String,
        requested_tag: String,
        bits: &[bool],
        arguments: Value,
    ) -> Result<Next> {
        let nowait = bits.get(3).copied().unwrap_or(false);
        let consumer_tag = if requested_tag.is_empty() {
            actions::generate_consumer_tag(self.connection_id)
        } else {
            requested_tag
        };

        Log::new(Some(&self.status_tx)).info(format!(
            "AMQP basic.consume '{}' on queue '{}' (channel {})",
            consumer_tag, queue, channel
        ));

        // Refuse a tag another connection already holds, before spending a model call on it.
        // The consumer directory is keyed per server while tags are per connection, so
        // letting the second registration through meant overwriting the first connection's
        // socket handle - every later delivery for that tag went to the wrong client, and the
        // tags are handed to the model in `list_consumers` on every publish event.
        //
        // 405 RESOURCE_LOCKED is what a broker answers when a client asks for something
        // another connection is holding exclusively.
        if actions::consumer_tag_taken_by_other(self.server_id, self.connection_id, &consumer_tag) {
            Log::new(Some(&self.status_tx)).warn(format!(
                "AMQP basic.consume refused: consumer tag '{}' belongs to another connection",
                consumer_tag
            ));
            self.send_channel_close(
                channel,
                REPLY_RESOURCE_LOCKED,
                "RESOURCE_LOCKED - consumer tag is in use by another connection",
                CLASS_BASIC,
                BASIC_CONSUME,
            );
            self.close_channel(channel);
            return Ok(Next::Continue);
        }

        if nowait {
            // No Consume-Ok is owed, so there is no decision to make; register the
            // consumer so deliveries can reach it.
            self.register_consumer(&consumer_tag, channel, &queue);
            return Ok(Next::Continue);
        }

        let event = Event::new(
            &actions::AMQP_BASIC_CONSUME_EVENT,
            json!({
                "channel": channel,
                "queue": queue,
                "consumer_tag": consumer_tag,
                "no_local": bits.first().copied().unwrap_or(false),
                "no_ack": bits.get(1).copied().unwrap_or(false),
                "exclusive": bits.get(2).copied().unwrap_or(false),
                "arguments": arguments,
            }),
        );

        match self
            .run_handler(
                std::slice::from_ref(&event),
                channel,
                Some(&consumer_tag),
                Some(&queue),
            )
            .await
        {
            HandlerOutcome::Closed => Ok(Next::Close),
            HandlerOutcome::Wrote(mask)
                if mask & (RESP_CONSUME_OK | RESP_CHANNEL_CLOSE | RESP_CONNECTION_CLOSE) != 0 =>
            {
                if mask & RESP_CONNECTION_CLOSE != 0 {
                    Ok(Next::Close)
                } else {
                    Ok(Next::Continue)
                }
            }
            _ => {
                Log::new(Some(&self.status_tx)).warn(format!(
                    "AMQP no amqp_basic_consume_ok from handler for '{}'; registering the \
                     consumer with the tag it asked for",
                    consumer_tag
                ));
                self.register_consumer(&consumer_tag, channel, &queue);
                let mut args = Encoder::new();
                args.short_string(&consumer_tag)?;
                self.send_method(channel, CLASS_BASIC, BASIC_CONSUME_OK, args.into_vec());
                Ok(Next::Continue)
            }
        }
    }

    async fn on_content_header(&mut self, frame: Frame) -> Result<Next> {
        let channel = frame.channel;
        let completed = {
            let Some(state) = self.channels.get_mut(&channel) else {
                return Err(anyhow!(
                    "content header on channel {} which is not open",
                    channel
                ));
            };
            let Some(pending) = state.pending.as_mut() else {
                return Err(anyhow!(
                    "content header on channel {} with no basic.publish in progress",
                    channel
                ));
            };
            if pending.header_seen {
                return Err(anyhow!("two content headers for one basic.publish"));
            }

            let mut d = Decoder::new(&frame.payload);
            let class_id = d.u16()?;
            if class_id != CLASS_BASIC {
                return Err(anyhow!(
                    "content header declares class {}, expected {}",
                    class_id,
                    CLASS_BASIC
                ));
            }
            let _weight = d.u16()?;
            let body_size = d.u64()?;
            if body_size > MAX_BODY_SIZE {
                return Err(anyhow!(
                    "content body of {} bytes exceeds the {} byte limit",
                    body_size,
                    MAX_BODY_SIZE
                ));
            }
            pending.properties = BasicProperties::decode(&mut d)?;
            pending.body_size = body_size;
            pending.header_seen = true;
            // Reserve for the first chunk only, not for the whole declared size - see
            // BODY_RESERVE_CHUNK for why the declared size is not something to allocate on.
            pending
                .body
                .reserve(body_size.min(BODY_RESERVE_CHUNK) as usize);

            // A message with an empty body has no body frames at all.
            if body_size == 0 {
                state.pending.take()
            } else {
                None
            }
        };

        if let Some(publish) = completed {
            self.on_publish_complete(channel, publish).await
        } else {
            Ok(Next::Continue)
        }
    }

    async fn on_content_body(&mut self, frame: Frame) -> Result<Next> {
        let channel = frame.channel;
        let completed = {
            let Some(state) = self.channels.get_mut(&channel) else {
                return Err(anyhow!(
                    "content body on channel {} which is not open",
                    channel
                ));
            };
            let Some(pending) = state.pending.as_mut() else {
                return Err(anyhow!(
                    "content body on channel {} with no basic.publish in progress",
                    channel
                ));
            };
            if !pending.header_seen {
                return Err(anyhow!("content body arrived before its content header"));
            }
            let received = pending.body.len() as u64 + frame.payload.len() as u64;
            if received > pending.body_size {
                return Err(anyhow!(
                    "content body of {} bytes exceeds the {} declared in the content header",
                    received,
                    pending.body_size
                ));
            }
            pending.body.extend_from_slice(&frame.payload);
            if pending.body.len() as u64 >= pending.body_size {
                state.pending.take()
            } else {
                None
            }
        };

        if let Some(publish) = completed {
            self.on_publish_complete(channel, publish).await
        } else {
            Ok(Next::Continue)
        }
    }

    async fn on_publish_complete(&mut self, channel: u16, publish: PendingPublish) -> Result<Next> {
        let (body, body_is_text) = match std::str::from_utf8(&publish.body) {
            Ok(s) => (s.to_string(), true),
            Err(_) => (String::from_utf8_lossy(&publish.body).into_owned(), false),
        };

        Log::new(Some(&self.status_tx)).info(format!(
            "AMQP basic.publish exchange='{}' routing_key='{}' {} bytes",
            publish.exchange,
            publish.routing_key,
            publish.body.len()
        ));

        let event = Event::new(
            &actions::AMQP_BASIC_PUBLISH_EVENT,
            json!({
                "channel": channel,
                "exchange": publish.exchange,
                "routing_key": publish.routing_key,
                "mandatory": publish.mandatory,
                "immediate": publish.immediate,
                "body": body,
                "body_is_text": body_is_text,
                "body_size": publish.body.len(),
                "properties": publish.properties.to_json(),
                "active_consumers": actions::list_consumers(self.server_id),
            }),
        );

        // Basic.Publish owes nothing on the wire outside confirm mode, so publishes can share
        // a call: with batching on this one waits in `ready_publishes` for the session loop,
        // which collects whatever else is already here and answers them together.
        let batching = self
            .app_state
            .server_conversation_settings(self.server_id)
            .await
            .is_some_and(|(_, batching)| batching);
        if batching {
            self.ready_publishes.push((channel, event));
            return Ok(Next::Continue);
        }

        match self
            .run_handler(std::slice::from_ref(&event), channel, None, None)
            .await
        {
            HandlerOutcome::Closed => Ok(Next::Close),
            HandlerOutcome::Wrote(mask) if mask & RESP_CONNECTION_CLOSE != 0 => Ok(Next::Close),
            // A handler that produces nothing simply drops the message.
            _ => Ok(Next::Continue),
        }
    }

    // ---- helpers --------------------------------------------------------

    fn register_consumer(&self, consumer_tag: &str, channel: u16, queue: &str) {
        actions::register_consumer(
            self.server_id,
            self.connection_id,
            consumer_tag,
            channel,
            queue,
            self.out_tx.clone(),
            self.frame_max,
        );
    }

    fn close_channel(&mut self, channel: u16) {
        self.channels.remove(&channel);
        actions::unregister_consumers_for_channel(self.server_id, self.connection_id, channel);
    }

    fn send_method(&self, channel: u16, class_id: u16, method_id: u16, args: Vec<u8>) {
        let _ = self
            .out_tx
            .send(method_frame(channel, class_id, method_id, &args));
    }

    /// `Queue.Declare-Ok`. Returns `Err` for a queue name a `shortstr` cannot carry rather
    /// than shortening it: the name is what the client will bind and consume against, so a
    /// shortened one names a different queue and neither end can tell.
    fn send_queue_declare_ok(
        &self,
        channel: u16,
        queue: &str,
        message_count: u32,
        consumer_count: u32,
    ) -> Result<()> {
        let mut args = Encoder::new();
        args.short_string(queue)?;
        args.u32(message_count);
        args.u32(consumer_count);
        self.send_method(channel, CLASS_QUEUE, QUEUE_DECLARE_OK, args.into_vec());
        Ok(())
    }

    fn send_connection_close(
        &self,
        reply_code: u16,
        reply_text: &str,
        class_id: u16,
        method_id: u16,
    ) {
        let mut args = Encoder::new();
        args.u16(reply_code);
        args.reply_text(reply_text);
        args.u16(class_id);
        args.u16(method_id);
        self.send_method(0, CLASS_CONNECTION, CONNECTION_CLOSE, args.into_vec());
    }

    fn send_channel_close(
        &self,
        channel: u16,
        reply_code: u16,
        reply_text: &str,
        class_id: u16,
        method_id: u16,
    ) {
        let mut args = Encoder::new();
        args.u16(reply_code);
        args.reply_text(reply_text);
        args.u16(class_id);
        args.u16(method_id);
        self.send_method(channel, CLASS_CHANNEL, CHANNEL_CLOSE, args.into_vec());
    }

    /// Hand an event to the handler chain (script -> static -> LLM) and report which
    /// response actions it produced.
    ///
    /// `events` is one event, or a batch of publishes on `channel` (`flush_publishes`).
    async fn run_handler(
        &self,
        events: &[Event],
        channel: u16,
        consumer_tag: Option<&str>,
        queue: Option<&str>,
    ) -> HandlerOutcome {
        let Some(event) = events.last() else {
            return HandlerOutcome::Wrote(0);
        };
        self.protocol.begin(channel, consumer_tag, queue);

        match call_llm_batch(
            &self.llm_client,
            &self.app_state,
            self.server_id,
            Some(self.connection_id),
            events,
            self.protocol.as_ref(),
        )
        .await
        {
            Ok(result) => {
                if result
                    .protocol_results
                    .iter()
                    .any(|r| matches!(r, ActionResult::CloseConnection))
                {
                    return HandlerOutcome::Closed;
                }
                HandlerOutcome::Wrote(self.protocol.written())
            }
            Err(e) => {
                // Tagged as src/server/radius/ does, because on the wire the fail-closed
                // paths below cannot carry the distinction: a Connection.Close 403 looks the
                // same whether the model refused or the backend was down. The log is the only
                // place the difference survives, so it has to be there.
                let class = if crate::utils::WireFailure::classify(&e).is_overloaded() {
                    "overloaded"
                } else {
                    "unavailable"
                };
                Log::new(Some(&self.status_tx)).warn(format!(
                    "AMQP handler failed for {}: decision=fail_closed_llm_error class={} \
                     error={}",
                    event.event_type.id, class, e
                ));
                HandlerOutcome::Wrote(self.protocol.written())
            }
        }
    }
}

enum HandlerOutcome {
    /// The handler asked to drop the connection.
    Closed,
    /// Bitmask of the response kinds the handler actually wrote (see `RESP_*`).
    Wrote(u32),
}

/// Periodically emit a heartbeat frame, at half the negotiated interval as the spec
/// recommends. The task ends when the connection's writer channel is dropped.
async fn spawn_heartbeat(
    out_tx: mpsc::UnboundedSender<Vec<u8>>,
    heartbeat_secs: u16,
    app_state: Arc<AppState>,
    server_id: crate::state::ServerId,
) {
    let period = std::time::Duration::from_secs((heartbeat_secs as u64).max(2) / 2);
    // Tracked, not detached: stop_server must abort this task too.
    let task_owner = app_state.clone();
    task_owner
        .spawn_server_task(server_id, async move {
            loop {
                tokio::time::sleep(period).await;
                if out_tx.send(heartbeat_frame()).is_err() {
                    break;
                }
            }
        })
        .await;
}

/// `Connection.Start` arguments: version, server properties, SASL mechanisms, locales.
fn connection_start_args() -> Result<Vec<u8>> {
    let mut args = Encoder::new();
    args.u8(0); // version-major
    args.u8(9); // version-minor
    args.field_table(&json!({
        "product": "NetGet",
        "version": env!("CARGO_PKG_VERSION"),
        "platform": "Rust",
        "information": "LLM-controlled AMQP 0-9-1 broker",
    }))?;
    args.long_string(b"PLAIN");
    args.long_string(b"en_US");
    Ok(args.into_vec())
}

/// Bytes the connection's read buffer holds. What a batch can see without waiting; a frame
/// that does not fit is read normally and ends the batch.
const READ_BUFFER_BYTES: usize = 64 * 1024;

/// Whether `buf` starts with a whole frame that may join a publish batch on `channel`: a
/// `Basic.Publish` method, a content header or body frame on that channel, or a heartbeat.
fn frame_belongs_to_publish_batch(buf: &[u8], channel: u16, max_payload: usize) -> bool {
    if buf.len() < 7 {
        return false;
    }
    let frame_type = buf[0];
    let frame_channel = u16::from_be_bytes([buf[1], buf[2]]);
    let size = u32::from_be_bytes([buf[3], buf[4], buf[5], buf[6]]) as usize;
    if size > max_payload || buf.len() < FRAME_OVERHEAD + size {
        return false;
    }
    match frame_type {
        FRAME_HEARTBEAT => true,
        FRAME_HEADER | FRAME_BODY => frame_channel == channel,
        FRAME_METHOD => {
            frame_channel == channel
                && size >= 4
                && u16::from_be_bytes([buf[7], buf[8]]) == CLASS_BASIC
                && u16::from_be_bytes([buf[9], buf[10]]) == BASIC_PUBLISH
        }
        _ => false,
    }
}

/// Read one frame. `Ok(None)` means the peer closed cleanly between frames.
///
/// The declared payload size is checked against the negotiated maximum *before* any
/// allocation, so a peer cannot make the broker reserve an arbitrary buffer.
async fn read_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
    max_payload: usize,
) -> Result<Option<Frame>> {
    let mut header = [0u8; 7];
    match reader.read_exact(&mut header).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }

    let frame_type = header[0];
    let channel = u16::from_be_bytes([header[1], header[2]]);
    let size = u32::from_be_bytes([header[3], header[4], header[5], header[6]]) as usize;

    if size > max_payload {
        return Err(anyhow!(
            "frame payload of {} bytes exceeds the negotiated maximum of {}",
            size,
            max_payload
        ));
    }

    let mut payload = vec![0u8; size];
    reader.read_exact(&mut payload).await?;

    let mut end = [0u8; 1];
    reader.read_exact(&mut end).await?;
    if end[0] != FRAME_END {
        return Err(anyhow!(
            "frame end marker was 0x{:02X}, expected 0x{:02X}",
            end[0],
            FRAME_END
        ));
    }

    Ok(Some(Frame {
        frame_type,
        channel,
        payload,
    }))
}
