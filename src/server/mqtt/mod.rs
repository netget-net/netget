//! MQTT 3.1.1 and 5.0 broker with LLM-controlled responses
//!
//! Wire format is parsed by hand (see `packet` below): MQTT control packets are small enough
//! that a dedicated broker crate would not earn its keep, and `rumqttd` owns its own
//! routing/session model, which is exactly the part the LLM must own here.
//!
//! The version is the client's: a CONNECT with protocol level 5 makes the whole connection a
//! v5 one — properties in every variable header, reason codes in every acknowledgement — and
//! anything else is answered in 3.1.1 framing. [`v5`] holds the property codec and the reason
//! code tables; the packet functions below take a `v5` flag rather than being duplicated.
//!
//! What the LLM decides:
//! - whether a CONNECT is accepted, and with which return code (`mqtt_connack`)
//! - the SUBACK granted-QoS vector for every SUBSCRIBE (`mqtt_suback`)
//! - whether a QoS>0 PUBLISH is acknowledged (`mqtt_puback` / `mqtt_pubrec`)
//! - every broker-originated PUBLISH, including which connected client receives it
//!   (`mqtt_publish`, optionally targeted with `to_client_id`)
//!
//! What the broker does without asking (pure transport bookkeeping, no semantics):
//! - PINGREQ -> PINGRESP
//! - PUBREL -> PUBCOMP (second half of the QoS 2 handshake)
//! - a default reply when the LLM/handler fails or returns nothing, so a client is
//!   never left waiting on a response the spec says must arrive
//!
//! No storage: the broker keeps live socket handles for connected clients so a
//! message can be delivered, and nothing else. There is no topic registry, no
//! subscription table, no message queue and no retained-message store in Rust —
//! subscriptions are reported to the model in the event and tracked in its memory.

pub mod actions;
pub mod v5;

use crate::llm::action_helper::call_llm_batch;
use crate::llm::actions::protocol_trait::ActionResult;
use crate::llm::ollama_client::OllamaClient;
use crate::logging::emit::Log;
use crate::protocol::Event;
use crate::server::connection::ConnectionId;
use crate::state::app_state::AppState;
use crate::state::server::{ConnectionState, ConnectionStatus, ProtocolConnectionInfo};
use actions::{
    MqttProtocol, MQTT_CONNECT_EVENT, MQTT_PUBLISH_EVENT, MQTT_SUBSCRIBE_EVENT,
    MQTT_UNSUBSCRIBE_EVENT,
};
use anyhow::Result;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tracing::{debug, error, info, trace, warn};

/// Largest control packet accepted from a client, in bytes.
///
/// The MQTT fixed header allows a 268 435 455 byte remaining length. Trusting it
/// would let one client ask for a 256 MiB allocation per packet, so the value is
/// capped and the connection is dropped instead.
const DEFAULT_MAX_PACKET_SIZE: usize = 256 * 1024;

/// Hard ceiling on the configurable `max_packet_size` startup parameter.
pub const MAX_PACKET_SIZE_LIMIT: usize = 16 * 1024 * 1024;

// ============================================================================
// Packet type constants (MQTT 3.1.1 section 2.2.1)
// ============================================================================

pub const PKT_CONNECT: u8 = 1;
pub const PKT_CONNACK: u8 = 2;
pub const PKT_PUBLISH: u8 = 3;
pub const PKT_PUBACK: u8 = 4;
pub const PKT_PUBREC: u8 = 5;
pub const PKT_PUBREL: u8 = 6;
pub const PKT_PUBCOMP: u8 = 7;
pub const PKT_SUBSCRIBE: u8 = 8;
pub const PKT_SUBACK: u8 = 9;
pub const PKT_UNSUBSCRIBE: u8 = 10;
pub const PKT_UNSUBACK: u8 = 11;
pub const PKT_PINGREQ: u8 = 12;
pub const PKT_PINGRESP: u8 = 13;
pub const PKT_DISCONNECT: u8 = 14;
/// AUTH (MQTT 5.0 §3.15). Reserved in 3.1.1.
pub const PKT_AUTH: u8 = 15;

/// Topic aliases a v5 client may use towards this broker, advertised as Topic Alias Maximum
/// in every v5 CONNACK (§3.2.2.3.8). An alias maps a 16-bit number to a topic name for the
/// life of the connection, so the table is bounded by this number of entries.
pub const TOPIC_ALIAS_MAX: u16 = 16;

/// CONNACK return code 3, "Connection Refused, Server unavailable" (3.1.1 §3.2.2.3).
///
/// The spec requires the server to close the connection after any non-zero CONNACK, so this
/// is a complete refusal rather than a warning the client can ignore.
pub const CONNACK_SERVER_UNAVAILABLE: u8 = 3;

/// SUBACK return code 0x80, "Failure" (3.1.1 §3.9.3). One per topic filter.
pub const SUBACK_FAILURE: u8 = 0x80;

/// Concurrent connections this broker admits before it starts refusing.
///
/// [`crate::server::accept_bounded::DEFAULT_MAX_CONNECTIONS`]. An MQTT connection is a
/// *session*, not a request: a subscriber holds its socket open for the life of the
/// application, so unlike a request/response protocol this server's live-connection count is
/// its client count rather than its arrival rate. That argues for keeping the house default
/// rather than trimming it — 256 subscribed clients is a plausible small deployment, and the
/// per-connection cost is bounded by `max_packet_size` either way.
const MAX_CONNECTIONS: usize = crate::server::accept_bounded::DEFAULT_MAX_CONNECTIONS;

/// What a peer over [`MAX_CONNECTIONS`] is told before the socket closes.
///
/// CONNACK with return code 3, "Server unavailable" — the one code MQTT defines for "I am
/// working, come back later", and the same one this broker already sends when a handler
/// refuses a CONNECT. The bytes are [`build_connack`]`(`[`CONNACK_SERVER_UNAVAILABLE`]`,
/// false)`, written out here because a `const` cannot call it.
///
/// **It is the 3.1.1 framing, because the peer's version is not yet known.** A v5 CONNACK
/// carries an extra property-length field, so the two are not interchangeable, and the
/// version is read from the CONNECT — which `accept_bounded` writes this before reading. A
/// v5 client parses these four bytes as reason code 0x03, which is not a success code; it
/// fails the connect either way, and the close that follows is the refusal.
///
/// 3.1.1 §3.2 requires the server to close the connection after a non-zero CONNACK, which is
/// exactly what `accept_bounded` does next.
const CONNECTION_CAP_REFUSAL: &[u8] = &[PKT_CONNACK << 4, 0x02, 0x00, CONNACK_SERVER_UNAVAILABLE];

/// How long a connected peer may take to complete its CONNECT.
///
/// MQTT is client-speaks-first and 3.1.1 §3.1.4 says a server that receives no CONNECT "within
/// a reasonable amount of time" SHOULD close. Every client sends CONNECT the moment its socket
/// is up — including NetGet's own, whose `rumqttc` event loop writes it on its first poll inside
/// `connect()` — so a peer still silent after 30 seconds has begun no session at all. Declared
/// as the `first_byte_timeout_secs` startup parameter.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// How long a session whose client declared a Keep Alive of **0** may be silent.
///
/// A non-zero Keep Alive sets the bound itself — see [`session_idle_bound`] — but 0 turns the
/// mechanism off (§3.1.2.10), and a bound that the peer can switch off in its own CONNECT is no
/// bound at all: one byte of the CONNECT would hold a slot forever. So those sessions get this
/// instead: fifteen minutes, `tcp`'s number, far longer than any client that chose 0 on purpose
/// goes between packets in practice, and a clean reconnect for one that does. Declared as the
/// `idle_timeout_secs` startup parameter, because the operator knows whether their subscribers
/// are the long-silent kind.
pub const IDLE_WITHOUT_KEEP_ALIVE: Duration = Duration::from_secs(900);

/// The read deadlines a connection is served under, resolved from the startup parameters.
#[derive(Clone, Copy, Debug)]
pub struct MqttBounds {
    /// Until CONNECT has been accepted.
    pub connect: Duration,
    /// After CONNECT, for a client that declared Keep Alive 0.
    pub idle_without_keep_alive: Duration,
}

/// The silence a session is allowed once CONNECT has been accepted.
///
/// **One and a half times the client's own Keep Alive**, which is what 3.1.1 §3.1.2.10 requires
/// of the server: "If the Keep Alive value is non-zero and the Server does not receive a Control
/// Packet from the Client within one and a half times the Keep Alive time period, it MUST
/// disconnect the Network Connection to the Client as if the network had failed." A client that
/// has nothing to publish meets it with PINGREQ, so a healthy idle subscriber is never cut. A
/// Keep Alive of 0 falls back to `fallback` (see [`IDLE_WITHOUT_KEEP_ALIVE`]).
///
/// The answer is not on this clock: every packet is dispatched inline, so the read is not polled
/// while the model — or a human, through a `manual` rule — composes a reply.
pub fn session_idle_bound(keep_alive_secs: u16, fallback: Duration) -> Duration {
    if keep_alive_secs == 0 {
        fallback
    } else {
        Duration::from_millis(u64::from(keep_alive_secs) * 1500)
    }
}

/// MQTT broker
pub struct MqttServer;

impl MqttServer {
    /// Spawn the MQTT broker.
    ///
    /// Bind failure is propagated to the caller (the server is never reported
    /// `Running` on a port it does not hold).
    pub async fn spawn_with_llm_actions(
        listen_addr: SocketAddr,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        server_id: crate::state::ServerId,
        startup_params: Option<crate::protocol::StartupParams>,
    ) -> Result<SocketAddr> {
        let max_packet_size = match startup_params.as_ref() {
            Some(params) => match params.get_optional_u64("max_packet_size") {
                Ok(Some(v)) => (v as usize).clamp(64, MAX_PACKET_SIZE_LIMIT),
                Ok(None) => DEFAULT_MAX_PACKET_SIZE,
                Err(e) => return Err(anyhow::anyhow!("MQTT startup parameter error: {}", e)),
            },
            None => DEFAULT_MAX_PACKET_SIZE,
        };

        // Both read bounds are the operator's to tune; the defaults are argued beside
        // CONNECT_TIMEOUT and IDLE_WITHOUT_KEEP_ALIVE. A non-zero Keep Alive is the client's
        // own, and is not overridable: 3.1.1 §3.1.2.10 makes 1.5x of it a MUST.
        let secs = |name: &str| -> Result<Option<Duration>> {
            match startup_params.as_ref() {
                Some(params) => params
                    .get_optional_u64(name)
                    .map(|v| v.map(Duration::from_secs))
                    .map_err(|e| anyhow::anyhow!("MQTT startup parameter error: {}", e)),
                None => Ok(None),
            }
        };
        let bounds = MqttBounds {
            connect: secs("first_byte_timeout_secs")?.unwrap_or(CONNECT_TIMEOUT),
            idle_without_keep_alive: secs("idle_timeout_secs")?.unwrap_or(IDLE_WITHOUT_KEEP_ALIVE),
        };

        let listener = TcpListener::bind(listen_addr).await?;
        let local_addr = listener.local_addr()?;

        Log::new(Some(&status_tx)).info(format!("MQTT broker listening on {}", local_addr));

        let accept_state = app_state.clone();
        let accept_status_tx = status_tx.clone();

        let limiter = crate::server::accept_bounded::ConnectionLimiter::new(MAX_CONNECTIONS);
        let accept_handle = tokio::spawn(async move {
            loop {
                match crate::server::accept_bounded::accept_bounded(
                    &listener,
                    &limiter,
                    CONNECTION_CAP_REFUSAL,
                    "MQTT",
                    Some(&accept_status_tx),
                )
                .await
                {
                    Ok((socket, peer_addr, permit)) => {
                        Log::new(Some(&accept_status_tx))
                            .debug(format!("MQTT connection from {}", peer_addr));

                        let llm_client = llm_client.clone();
                        let app_state = accept_state.clone();
                        let status_tx = accept_status_tx.clone();

                        // Tracked, not detached: stop_server must abort this task too.
                        let task_owner = app_state.clone();
                        task_owner
                            .spawn_server_task(server_id, async move {
                                // One MQTT connection is *two* tasks — this one and the writer
                                // `handle_mqtt_connection` spawns — so the permit goes in as an
                                // `Arc` held by both and the slot comes back when the later of
                                // the two ends. Holding it here alone would release the slot
                                // while a writer was still draining, which un-caps the broker.
                                let permit = std::sync::Arc::new(permit);
                                if let Err(e) = handle_mqtt_connection(
                                    socket,
                                    peer_addr,
                                    local_addr,
                                    llm_client,
                                    app_state,
                                    status_tx,
                                    server_id,
                                    max_packet_size,
                                    permit,
                                    bounds,
                                )
                                .await
                                {
                                    error!("MQTT connection error ({}): {}", peer_addr, e);
                                }
                            })
                            .await;
                    }
                    Err(e) => {
                        Log::new(Some(&accept_status_tx))
                            .error(format!("MQTT accept error: {}", e));
                        break;
                    }
                }
            }
        });

        // Register the accept loop so stop_server can abort it and release the port.
        // register_server_task keeps only one handle per server, so this is the only call.
        app_state
            .register_server_task(server_id, accept_handle)
            .await;

        let _ = status_tx.send("__UPDATE_UI__".to_string());
        Ok(local_addr)
    }
}

/// A parsed MQTT control packet: fixed-header type, its 4 flag bits, and the
/// variable-header + payload bytes.
struct RawPacket {
    packet_type: u8,
    flags: u8,
    body: Vec<u8>,
}

/// What one connection knows about its own session.
#[derive(Default)]
struct Session {
    /// Set by an accepted CONNECT; a second CONNECT is a protocol violation.
    client_id: Option<String>,
    /// The Keep Alive the client declared in its CONNECT, once one has been accepted.
    keep_alive: Option<u16>,
    /// The client connected with protocol level 5.
    v5: bool,
    /// v5 Topic Aliases the client has defined on this connection (§3.3.2.3.4), bounded by
    /// [`TOPIC_ALIAS_MAX`].
    aliases: std::collections::HashMap<u16, String>,
}

impl Session {
    /// On a v5 connection, say why it is closing before it closes (§4.13.2: a server that
    /// detects a malformed packet or a protocol error SHOULD send DISCONNECT with the reason).
    /// 3.1.1 has no server DISCONNECT, so there the close itself is the whole message.
    fn refuse(&self, out_tx: &mpsc::UnboundedSender<Vec<u8>>, reason: u8) {
        if self.v5 {
            let _ = out_tx.send(build_disconnect_v5(reason, &v5::PropertyWriter::new()));
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_mqtt_connection(
    socket: TcpStream,
    peer_addr: SocketAddr,
    local_addr: SocketAddr,
    llm_client: OllamaClient,
    app_state: Arc<AppState>,
    status_tx: mpsc::UnboundedSender<String>,
    server_id: crate::state::ServerId,
    max_packet_size: usize,
    // This connection's slot in the accept loop's cap. Shared with the writer task below, so
    // the slot is released by whichever of the two ends last.
    permit: Arc<crate::server::accept_bounded::ConnectionPermit>,
    bounds: MqttBounds,
) -> Result<()> {
    let connection_id = ConnectionId::new(app_state.get_next_unified_id().await);

    let (mut read_half, write_half) = tokio::io::split(socket);

    // The write half is shared between the channel-draining writer task and the peer
    // command task. The writer task owns all outbound framing (below); the peer task
    // only ever `shutdown()`s it, which is how the dashboard's "disconnect this peer"
    // half-closes a connection from outside the read loop.
    let write_half = Arc::new(tokio::sync::Mutex::new(write_half));

    // All writes for this connection funnel through one channel so that packets
    // produced by the read loop and packets produced by an action (possibly for a
    // different connection) can never interleave mid-packet.
    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let writer_status_tx = status_tx.clone();
    let writer_write_half = write_half.clone();
    let writer_state = app_state.clone();
    let writer_permit = Arc::clone(&permit);
    // The Maximum Packet Size a v5 client declared in its CONNECT, 0 when it set none. A
    // server "MUST NOT send packets exceeding Maximum Packet Size to the Client" and discards
    // a PUBLISH that would (§3.1.2.11.4), so the one place every outbound packet passes is
    // where it is enforced.
    let client_max_packet = Arc::new(std::sync::atomic::AtomicU32::new(0));
    let writer_client_max = client_max_packet.clone();
    let writer_handle = tokio::spawn(async move {
        // The other half of this connection's cap slot. `finish_connection` waits at most 5
        // seconds for this task, so on the path where it gives up and abandons the writer the
        // slot is still held by the writer's own Arc until it really ends.
        let _permit = writer_permit;
        while let Some(bytes) = out_rx.recv().await {
            let n = bytes.len();
            let limit = writer_client_max.load(std::sync::atomic::Ordering::SeqCst) as usize;
            if limit > 0 && n > limit {
                Log::new(Some(&writer_status_tx)).warn(format!(
                    "MQTT dropped a {n}-byte packet (type {}) for connection {connection_id}: \
                     the client's Maximum Packet Size is {limit} \
                     decision=dropped_over_client_max_packet_size",
                    bytes.first().map(|b| b >> 4).unwrap_or(0)
                ));
                continue;
            }
            let mut guard = writer_write_half.lock().await;
            if let Err(e) = guard.write_all(&bytes).await {
                Log::new(Some(&writer_status_tx)).debug(format!("MQTT write failed: {}", e));
                break;
            }
            let _ = guard.flush().await;
            drop(guard);
            // Live byte/packet counters for the dashboard rail. Every outbound MQTT
            // packet crosses this channel, so this is the one place all writes are seen.
            writer_state
                .update_connection_stats(
                    server_id,
                    connection_id,
                    None,
                    Some(n as u64),
                    None,
                    Some(1),
                )
                .await;
        }
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
        protocol_info: ProtocolConnectionInfo::new(serde_json::json!({
            "client_id": serde_json::Value::Null,
        })),
    };
    app_state
        .add_connection_to_server(server_id, conn_state)
        .await;
    let _ = status_tx.send("__UPDATE_UI__".to_string());

    let protocol = Arc::new(MqttProtocol::for_connection(
        server_id,
        connection_id,
        out_tx.clone(),
        status_tx.clone(),
    ));

    // Peer injection: the dashboard's "message this peer" / "disconnect this peer" run an
    // action against THIS connection through the same executor the model path uses. A
    // messaging verb (e.g. mqtt_publish) writes through the connection's own out channel and
    // reports Executed; a close ({"type":"close_connection"}) half-closes the shared write
    // half. Registered before the first read so the operator can reach the connection while
    // it is idle - the read loop blocks in read() without a select.
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

    let mut session = Session::default();
    let mut buffer: Vec<u8> = Vec::with_capacity(1024);
    let mut chunk = vec![0u8; 4096];

    let close_reason = loop {
        // Before CONNECT: the connect bound. After it: 1.5x the client's own Keep Alive, or the
        // fallback when it declared 0. The deadline wraps the read and nothing else — packets
        // are dispatched inline below, so a model round-trip is never on this clock.
        let bound = match session.keep_alive {
            None => bounds.connect,
            Some(ka) => session_idle_bound(ka, bounds.idle_without_keep_alive),
        };
        let read = match tokio::time::timeout(bound, read_half.read(&mut chunk)).await {
            Ok(read) => read,
            Err(_) => {
                Log::new(Some(&status_tx)).info(format!(
                    "MQTT connection {} from {} sent nothing for {}ms decision=idle_timeout                      ({}); closing",
                    connection_id,
                    peer_addr,
                    bound.as_millis(),
                    match session.keep_alive {
                        None => "no CONNECT".to_string(),
                        Some(0) => "keep-alive 0".to_string(),
                        Some(ka) => format!("1.5x keep-alive {}s", ka),
                    }
                ));
                break "idle deadline expired";
            }
        };
        let n = match read {
            Ok(0) => break "peer closed the connection",
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
                n
            }
            Err(e) => {
                debug!("MQTT read error from {}: {}", peer_addr, e);
                break "read error";
            }
        };
        buffer.extend_from_slice(chunk.get(..n).unwrap_or(&[]));

        // Drain every complete packet currently in the buffer.
        loop {
            let packet = match take_packet(&mut buffer, max_packet_size) {
                Ok(Some(p)) => p,
                Ok(None) => break, // need more bytes
                Err(e) => {
                    Log::new(Some(&status_tx)).warn(format!(
                        "MQTT protocol error from {} decision=protocol_error: {}",
                        peer_addr, e
                    ));
                    // A malformed packet desynchronises the stream; the spec says close.
                    session.refuse(&out_tx, e.reason_code());
                    finish_connection(
                        protocol,
                        out_tx,
                        writer_handle,
                        &app_state,
                        server_id,
                        connection_id,
                        &session.client_id,
                        &status_tx,
                    )
                    .await;
                    return Ok(());
                }
            };

            trace!(
                "MQTT packet type={} flags={:#x} len={} from {}",
                packet.packet_type,
                packet.flags,
                packet.body.len(),
                peer_addr
            );

            // A QoS 0 PUBLISH owes the client nothing on the wire, so with batching on it is
            // answered together with every further QoS 0 PUBLISH already here - what the client
            // sent while the model answered the last. Everything else is answered one by one.
            let qos0_publish = packet.packet_type == PKT_PUBLISH
                && (packet.flags >> 1) & 0x03 == 0
                && session.client_id.is_some();
            if qos0_publish
                && app_state
                    .server_conversation_settings(server_id)
                    .await
                    .is_some_and(|(_, batching)| batching)
            {
                let keep_open = publish_batch(
                    packet,
                    &mut buffer,
                    &mut read_half,
                    &mut chunk,
                    max_packet_size,
                    &mut session,
                    &llm_client,
                    &app_state,
                    &status_tx,
                    server_id,
                    connection_id,
                    protocol.as_ref(),
                    &out_tx,
                )
                .await;
                if !keep_open {
                    finish_connection(
                        protocol,
                        out_tx,
                        writer_handle,
                        &app_state,
                        server_id,
                        connection_id,
                        &session.client_id,
                        &status_tx,
                    )
                    .await;
                    return Ok(());
                }
                continue;
            }

            let keep_open = dispatch_packet(
                packet,
                &mut session,
                &client_max_packet,
                max_packet_size,
                &llm_client,
                &app_state,
                &status_tx,
                server_id,
                connection_id,
                protocol.clone(),
                &out_tx,
            )
            .await;

            if !keep_open {
                finish_connection(
                    protocol,
                    out_tx,
                    writer_handle,
                    &app_state,
                    server_id,
                    connection_id,
                    &session.client_id,
                    &status_tx,
                )
                .await;
                return Ok(());
            }
        }
    };

    debug!(
        "MQTT connection {} closing: {}",
        connection_id, close_reason
    );
    Log::new(Some(&status_tx)).info(format!(
        "MQTT client {} disconnected ({})",
        session.client_id.as_deref().unwrap_or("<unidentified>"),
        close_reason
    ));

    finish_connection(
        protocol,
        out_tx,
        writer_handle,
        &app_state,
        server_id,
        connection_id,
        &session.client_id,
        &status_tx,
    )
    .await;
    Ok(())
}

/// Shut one connection down: flush whatever is still queued, then release everything.
///
/// The ordering is the whole point. The writer task ends when its receiver sees every sender
/// gone, and there are three: the local `out_tx`, a clone inside `MqttProtocol` (so actions can
/// write to this connection) and a clone in the global client directory (so *another*
/// connection's `mqtt_publish` can). Awaiting the writer while any of them is still alive waits
/// forever - which it did: `drop(out_tx); writer_handle.await;` on all three exit paths left
/// every MQTT connection task and its socket parked permanently, including on the ordinary
/// client-disconnect path and on `close_this_connection`.
///
/// So: unregister from the directory, drop the protocol handle, drop the local sender, and only
/// then wait for the queue to drain. The wait is bounded anyway - a sender leaked by some
/// future change must not be able to wedge a connection task again.
#[allow(clippy::too_many_arguments)]
async fn finish_connection(
    protocol: Arc<MqttProtocol>,
    out_tx: mpsc::UnboundedSender<Vec<u8>>,
    writer_handle: tokio::task::JoinHandle<()>,
    app_state: &Arc<AppState>,
    server_id: crate::state::ServerId,
    connection_id: ConnectionId,
    client_id: &Option<String>,
    status_tx: &mpsc::UnboundedSender<String>,
) {
    // Drop the peer handle first: the peer command task holds an Arc<MqttProtocol>, which
    // owns an out_tx clone, so the writer task below cannot finish until that task ends.
    // Removing the handle closes its command channel and lets it wind down.
    app_state
        .remove_peer_handle(server_id, connection_id.as_u32())
        .await;
    cleanup(app_state, server_id, connection_id, client_id, status_tx).await;
    drop(protocol);
    drop(out_tx);
    if tokio::time::timeout(std::time::Duration::from_secs(5), writer_handle)
        .await
        .is_err()
    {
        warn!(
            "MQTT connection {}: writer did not finish within 5s, abandoning it",
            connection_id
        );
    }
}

async fn cleanup(
    app_state: &AppState,
    server_id: crate::state::ServerId,
    connection_id: ConnectionId,
    client_id: &Option<String>,
    status_tx: &mpsc::UnboundedSender<String>,
) {
    if let Some(id) = client_id {
        actions::unregister_client(server_id, id);
    }
    app_state
        .update_connection_status(server_id, connection_id, ConnectionStatus::Closed)
        .await;
    let _ = status_tx.send("__UPDATE_UI__".to_string());
}

/// Handle one control packet. Returns false when the connection must close.
#[allow(clippy::too_many_arguments)]
async fn dispatch_packet(
    packet: RawPacket,
    session: &mut Session,
    client_max_packet: &std::sync::atomic::AtomicU32,
    max_packet_size: usize,
    llm_client: &OllamaClient,
    app_state: &Arc<AppState>,
    status_tx: &mpsc::UnboundedSender<String>,
    server_id: crate::state::ServerId,
    connection_id: ConnectionId,
    protocol: Arc<MqttProtocol>,
    out_tx: &mpsc::UnboundedSender<Vec<u8>>,
) -> bool {
    match packet.packet_type {
        PKT_CONNECT => {
            let connect = match parse_connect(&packet.body) {
                Ok(c) => c,
                Err(e) => {
                    Log::new(Some(&status_tx)).warn(format!(
                        "MQTT malformed CONNECT from client decision=protocol_error, closing: {e}"
                    ));
                    // A v5 client is told why in its own framing (§3.2.2.2: 0x81 Malformed
                    // Packet / 0x82 Protocol Error); a 3.1.1 CONNACK has no code for it.
                    if let Some(code) = e.v5_connack_code() {
                        let _ =
                            out_tx.send(build_connack_v5(code, false, &v5::PropertyWriter::new()));
                    }
                    return false;
                }
            };

            if session.client_id.is_some() {
                // 3.1.0-2: a second CONNECT on one connection is a protocol violation.
                Log::new(Some(&status_tx))
                    .warn("MQTT duplicate CONNECT decision=protocol_error, closing connection");
                session.refuse(out_tx, 0x82);
                return false;
            }

            session.v5 = connect.protocol_level == 5;
            protocol.set_v5(session.v5);
            // The client asked for enhanced authentication (§4.12), which this broker does not
            // perform. Only an explicit `mqtt_connack` from the handler admits such a client.
            let wants_enhanced_auth =
                session.v5 && connect.properties.text(v5::AUTHENTICATION_METHOD).is_some();
            let assigned = connect.client_id.is_empty();
            let effective_id = if assigned {
                format!("anon-{}", connection_id.as_u32())
            } else {
                connect.client_id.clone()
            };
            session.client_id = Some(effective_id.clone());
            session.keep_alive = Some(connect.keep_alive);
            if session.v5 {
                if let Some(limit) = connect.properties.int(v5::MAXIMUM_PACKET_SIZE) {
                    client_max_packet.store(limit, std::sync::atomic::Ordering::SeqCst);
                }
                // What every accepting v5 CONNACK carries without the handler having to say
                // it: the id this broker assigned when the client sent none (§3.2.2.3.7 makes
                // that a MUST), the largest packet it will accept, and the aliases it takes.
                let mut auto = v5::PropertyWriter::new();
                if assigned {
                    auto.text(v5::ASSIGNED_CLIENT_IDENTIFIER, &effective_id);
                }
                auto.u32(v5::MAXIMUM_PACKET_SIZE, max_packet_size as u32)
                    .u16(v5::TOPIC_ALIAS_MAXIMUM, TOPIC_ALIAS_MAX);
                protocol.set_connack_properties(auto);
            }
            actions::register_client(server_id, &effective_id, out_tx.clone(), session.v5);
            protocol.set_client_id(&effective_id);

            app_state
                .with_server_mut(server_id, |server| {
                    if let Some(conn) = server.connections.get_mut(&connection_id) {
                        conn.protocol_info = ProtocolConnectionInfo::new(serde_json::json!({
                            "client_id": effective_id,
                            "protocol_version": version_name(connect.protocol_level),
                        }));
                    }
                })
                .await;

            info!(
                "MQTT client '{}' connected (v{}, clean_session={}, keep_alive={}s)",
                effective_id,
                version_name(connect.protocol_level),
                connect.clean_session,
                connect.keep_alive
            );
            Log::new(Some(&status_tx)).info(format!(
                "MQTT CONNECT from client '{}' (MQTT {}, user={}, clean_session={})",
                effective_id,
                version_name(connect.protocol_level),
                connect.username.as_deref().unwrap_or("-"),
                connect.clean_session
            ));

            let mut data = serde_json::json!({
                "client_id": effective_id,
                "username": connect.username,
                "has_password": connect.has_password,
                "clean_session": connect.clean_session,
                "keep_alive": connect.keep_alive,
                "protocol_name": connect.protocol_name,
                "protocol_level": connect.protocol_level,
                "protocol_version": version_name(connect.protocol_level),
                "will_topic": connect.will_topic,
                "will_message": connect.will_message,
            });
            if session.v5 {
                data["properties"] = connect.properties.to_json();
                data["will_properties"] = connect.will_properties.to_json();
                data["assigned_client_id"] = serde_json::json!(assigned);
            }
            let event = Event::new(&MQTT_CONNECT_EVENT, data);

            let outcome = run_llm(
                llm_client,
                app_state,
                server_id,
                connection_id,
                std::slice::from_ref(&event),
                protocol.as_ref(),
                status_tx,
                Some(PKT_CONNACK),
            )
            .await;

            match outcome {
                LlmOutcome::Closed => false,
                // A refusing CONNACK ends the connection on the server's side too: 3.1.1
                // §3.2.2.3 and 5.0 §3.2.2.2 both say the server MUST close after one.
                LlmOutcome::Responded => !protocol.connack_refused(),
                LlmOutcome::Silent if wants_enhanced_auth => {
                    // The CONNECT names an Authentication Method and the handler said nothing.
                    // Accepting would admit a client whose authentication never ran, so silence
                    // refuses here: 0x8C Bad Authentication Method, and the server closes after
                    // a refusing CONNACK (§3.2.2.2).
                    Log::new(Some(&status_tx)).warn(format!(
                        "MQTT CONNECT from '{}' names an authentication method and the handler \
                         sent no mqtt_connack decision=fail_closed_auth_method, refusing with \
                         CONNACK 0x8C",
                        effective_id
                    ));
                    let _ = out_tx.send(build_connack_v5(0x8C, false, &v5::PropertyWriter::new()));
                    false
                }
                LlmOutcome::Silent => {
                    // CONNACK is mandatory (3.2). Accept by default rather than let the
                    // client sit in its connect timeout. Safe only because the handler ran
                    // and declined to decide - see `LlmOutcome::Failed`.
                    //
                    // Read that carefully before copying it: this is the one place in MQTT
                    // where a *permissive* packet follows a `decision=model_silent`. The
                    // session is accepted, credentials and all, because the model said
                    // nothing - which is the OAuth2 shape, narrowed to the case where the
                    // handler demonstrably ran and the client asked for no enhanced
                    // authentication (the arm above refuses that one). The preceding
                    // `decision=model_silent` line is what makes it auditable; see the
                    // fail-open note in `src/server/mqtt/AGENTS.md`.
                    Log::new(Some(&status_tx)).warn(format!(
                        "MQTT no mqtt_connack from handler for '{}'; accepting by default \
                         (CONNACK 0 — an accepted session nothing decided)",
                        effective_id
                    ));
                    let _ = out_tx.send(if session.v5 {
                        build_connack_v5(0, false, &protocol.connack_properties())
                    } else {
                        build_connack(0, false)
                    });
                    true
                }
                LlmOutcome::Failed(failure) => {
                    // CONNACK return code 3 is "Server unavailable" (3.2.2.3). It refuses the
                    // connection, and 3.2.2.3 requires the server to close afterwards - so a
                    // client cannot proceed to PUBLISH or SUBSCRIBE on the strength of a
                    // backend that never answered. Never code 0 here: that is an accepted
                    // connection, and for a CONNECT carrying credentials it is an
                    // authentication decision made by an outage.
                    //
                    // v5 can say which kind of outage: 0x89 Server Busy is the retryable one,
                    // 0x88 Server Unavailable the other, and a Reason String carries the
                    // category (never the error itself).
                    Log::new(Some(&status_tx)).warn(format!(
                        "MQTT refusing CONNECT from '{}' with CONNACK {} (server {}): \
                         backend failed",
                        effective_id,
                        if session.v5 { "0x88/0x89" } else { "3" },
                        if failure.is_overloaded() {
                            "busy"
                        } else {
                            "unavailable"
                        }
                    ));
                    let _ = out_tx.send(if session.v5 {
                        let code = if failure.is_overloaded() { 0x89 } else { 0x88 };
                        let mut props = v5::PropertyWriter::new();
                        props.text(v5::REASON_STRING, failure.text());
                        build_connack_v5(code, false, &props)
                    } else {
                        build_connack(CONNACK_SERVER_UNAVAILABLE, false)
                    });
                    false
                }
            }
        }

        PKT_PUBLISH => {
            let (event, qos, packet_id) =
                match publish_event(&packet, session, server_id, status_tx) {
                    Ok(prepared) => prepared,
                    Err(code) => {
                        session.refuse(out_tx, code);
                        return false;
                    }
                };

            let outcome = run_llm(
                llm_client,
                app_state,
                server_id,
                connection_id,
                std::slice::from_ref(&event),
                protocol.as_ref(),
                status_tx,
                match qos {
                    1 => Some(PKT_PUBACK),
                    2 => Some(PKT_PUBREC),
                    _ => None,
                },
            )
            .await;

            match outcome {
                LlmOutcome::Closed => false,
                LlmOutcome::Responded => true,
                LlmOutcome::Silent => {
                    // QoS 0 needs no acknowledgement; QoS 1/2 do, and the packet
                    // identifier must be echoed or the client retries forever. The two-byte
                    // form is a valid v5 acknowledgement too: Reason Code 0x00 and no
                    // properties may be omitted (§3.4.2.1).
                    match qos {
                        1 => {
                            let _ = out_tx.send(build_ack(PKT_PUBACK, packet_id));
                        }
                        2 => {
                            let _ = out_tx.send(build_ack(PKT_PUBREC, packet_id));
                        }
                        _ => {}
                    }
                    true
                }
                LlmOutcome::Failed(failure) => {
                    // MQTT 3.1.1 has no failure code in PUBACK or PUBREC - the acknowledgement
                    // is a two-byte packet identifier and nothing else - so there is no way to
                    // say "received but not handled". Sending one anyway would tell the
                    // publisher its message was taken, which is the one thing that must not
                    // happen when nothing looked at it. The spec's only channel for a broker
                    // error at this point is closing the connection, so that is what happens:
                    // the publisher gets no acknowledgement, keeps the message, and retries
                    // on reconnect exactly as QoS 1/2 promise.
                    //
                    // v5 does have failure codes in PUBACK, but a PUBACK of any kind completes
                    // the exchange and the publisher discards the message - so it is still the
                    // close, now preceded by a DISCONNECT saying why: 0x89 Server Busy when the
                    // backend is saturated, 0x80 Unspecified Error otherwise.
                    Log::new(Some(&status_tx)).warn(format!(
                        "MQTT closing connection: backend failed on PUBLISH (qos={}, id={}), \
                         acknowledging it would claim delivery",
                        qos, packet_id
                    ));
                    if session.v5 {
                        let mut props = v5::PropertyWriter::new();
                        props.text(v5::REASON_STRING, failure.text());
                        let code = if failure.is_overloaded() { 0x89 } else { 0x80 };
                        let _ = out_tx.send(build_disconnect_v5(code, &props));
                    }
                    false
                }
            }
        }

        PKT_PUBREL => {
            // Second half of the QoS 2 handshake: transport bookkeeping only, so it is
            // answered without consulting the model. The packet identifier is echoed.
            let packet_id = read_u16_at(&packet.body, 0).unwrap_or(0);
            trace!("MQTT PUBREL id={} -> PUBCOMP", packet_id);
            let _ = out_tx.send(build_ack(PKT_PUBCOMP, packet_id));
            true
        }

        PKT_SUBSCRIBE => {
            let sub = match parse_subscribe(&packet.body, session.v5) {
                Ok(s) => s,
                Err(e) => {
                    Log::new(Some(&status_tx)).warn(format!(
                        "MQTT malformed SUBSCRIBE decision=protocol_error, closing connection: {e}"
                    ));
                    session.refuse(out_tx, e.reason_code());
                    return false;
                }
            };
            if sub.topics.is_empty() {
                Log::new(Some(&status_tx))
                    .warn("MQTT SUBSCRIBE with no topic filter decision=protocol_error, closing");
                session.refuse(out_tx, 0x82);
                return false;
            }

            let name = session
                .client_id
                .clone()
                .unwrap_or_else(|| "<no CONNECT>".into());
            Log::new(Some(&status_tx)).info(format!(
                "MQTT SUBSCRIBE from '{}': {}",
                name,
                sub.topics
                    .iter()
                    .map(|(f, q)| format!("{} (qos {})", f, q))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));

            let topics: Vec<serde_json::Value> = sub
                .topics
                .iter()
                .zip(sub.options.iter())
                .map(|((filter, qos), opts)| {
                    let mut t = serde_json::json!({ "filter": filter, "qos": qos });
                    if session.v5 {
                        t["no_local"] = serde_json::json!(opts.no_local);
                        t["retain_as_published"] = serde_json::json!(opts.retain_as_published);
                        t["retain_handling"] = serde_json::json!(opts.retain_handling);
                    }
                    t
                })
                .collect();

            let mut data = serde_json::json!({
                "client_id": name,
                "packet_id": sub.packet_id,
                "topics": topics,
                "answer_with": subscribe_answer_with(sub.packet_id, &sub.topics),
            });
            if session.v5 {
                data["properties"] = sub.properties.to_json();
            }
            let event = Event::new(&MQTT_SUBSCRIBE_EVENT, data);

            let outcome = run_llm(
                llm_client,
                app_state,
                server_id,
                connection_id,
                std::slice::from_ref(&event),
                protocol.as_ref(),
                status_tx,
                Some(PKT_SUBACK),
            )
            .await;

            match outcome {
                LlmOutcome::Closed => false,
                LlmOutcome::Responded => true,
                LlmOutcome::Silent => {
                    // SUBACK is mandatory (3.8.4) and must echo the packet identifier.
                    let granted: Vec<u8> = sub.topics.iter().map(|(_, q)| *q).collect();
                    Log::new(Some(&status_tx)).warn(format!(
                        "MQTT no mqtt_suback from handler; granting requested QoS to '{}'",
                        name
                    ));
                    let _ = out_tx.send(if session.v5 {
                        build_suback_v5(sub.packet_id, &granted, &v5::PropertyWriter::new())
                    } else {
                        build_suback(sub.packet_id, &granted)
                    });
                    true
                }
                LlmOutcome::Failed(failure) => {
                    // SUBACK carries a per-filter return code, and 0x80 is Failure (3.9.3).
                    // This is the one place in 3.1.1 where a refusal has a proper wire form,
                    // so use it rather than granting: granting a subscription is an access
                    // decision, and nothing decided it. v5's 0x80 is Unspecified Error, and
                    // its Reason String carries the category.
                    let refused = vec![SUBACK_FAILURE; sub.topics.len()];
                    Log::new(Some(&status_tx)).warn(format!(
                        "MQTT refusing all {} subscription(s) from '{}' with SUBACK 0x80: \
                         backend failed",
                        sub.topics.len(),
                        name
                    ));
                    let _ = out_tx.send(if session.v5 {
                        let mut props = v5::PropertyWriter::new();
                        props.text(v5::REASON_STRING, failure.text());
                        build_suback_v5(sub.packet_id, &refused, &props)
                    } else {
                        build_suback(sub.packet_id, &refused)
                    });
                    true
                }
            }
        }

        PKT_UNSUBSCRIBE => {
            let unsub = match parse_unsubscribe(&packet.body, session.v5) {
                Ok(u) => u,
                Err(e) => {
                    Log::new(Some(&status_tx)).warn(format!(
                        "MQTT malformed UNSUBSCRIBE decision=protocol_error, closing connection: \
                         {e}"
                    ));
                    session.refuse(out_tx, e.reason_code());
                    return false;
                }
            };

            let name = session
                .client_id
                .clone()
                .unwrap_or_else(|| "<no CONNECT>".into());
            Log::new(Some(&status_tx)).info(format!(
                "MQTT UNSUBSCRIBE from '{}': {}",
                name,
                unsub.topics.join(", ")
            ));
            // A v5 UNSUBACK carries one reason code per filter (§3.11.3), so the executor has
            // to know how many this one had.
            protocol.note_unsubscribe(unsub.packet_id, unsub.topics.len());

            let mut data = serde_json::json!({
                "client_id": name,
                "packet_id": unsub.packet_id,
                "topics": unsub.topics,
            });
            if session.v5 {
                data["properties"] = unsub.properties.to_json();
            }
            let event = Event::new(&MQTT_UNSUBSCRIBE_EVENT, data);

            let outcome = run_llm(
                llm_client,
                app_state,
                server_id,
                connection_id,
                std::slice::from_ref(&event),
                protocol.as_ref(),
                status_tx,
                Some(PKT_UNSUBACK),
            )
            .await;

            match outcome {
                LlmOutcome::Closed => false,
                LlmOutcome::Responded => true,
                LlmOutcome::Silent => {
                    let _ = out_tx.send(if session.v5 {
                        build_unsuback_v5(
                            unsub.packet_id,
                            &vec![0x00; unsub.topics.len()],
                            &v5::PropertyWriter::new(),
                        )
                    } else {
                        build_ack(PKT_UNSUBACK, unsub.packet_id)
                    });
                    true
                }
                LlmOutcome::Failed(failure) if session.v5 => {
                    // v5 UNSUBACK has a failure code per filter, 0x80 Unspecified Error, which
                    // says the subscription was NOT removed. That is true, so it is the answer
                    // and the connection stays up.
                    Log::new(Some(&status_tx)).warn(format!(
                        "MQTT refusing UNSUBSCRIBE (id={}) from '{}' with UNSUBACK 0x80: \
                         backend failed",
                        unsub.packet_id, name
                    ));
                    let mut props = v5::PropertyWriter::new();
                    props.text(v5::REASON_STRING, failure.text());
                    let _ = out_tx.send(build_unsuback_v5(
                        unsub.packet_id,
                        &vec![0x80; unsub.topics.len()],
                        &props,
                    ));
                    true
                }
                LlmOutcome::Failed(_) => {
                    // Like PUBACK, UNSUBACK in 3.1.1 is a bare packet identifier with no
                    // failure code, and it means "the subscriptions are gone". Claiming that
                    // when nothing processed the request would leave the client believing it
                    // had unsubscribed. Close instead.
                    Log::new(Some(&status_tx)).warn(format!(
                        "MQTT closing connection: backend failed on UNSUBSCRIBE (id={}), \
                         acknowledging it would claim the subscriptions were removed",
                        unsub.packet_id
                    ));
                    false
                }
            }
        }

        PKT_PINGREQ => {
            // Keep-alive only: no semantics for the model to decide.
            trace!("MQTT PINGREQ -> PINGRESP");
            let _ = out_tx.send(vec![PKT_PINGRESP << 4, 0x00]);
            true
        }

        PKT_DISCONNECT => {
            // v5 DISCONNECT carries a reason code (absent means 0x00, §3.14.2.1) and may carry
            // a Reason String; both are reported, neither is answered.
            let (reason, detail) = if session.v5 {
                let reason = packet.body.first().copied().unwrap_or(0);
                let mut pos = 1usize;
                let text = if packet.body.len() > 1 {
                    v5::read_properties(&packet.body, &mut pos)
                        .ok()
                        .and_then(|p| p.text(v5::REASON_STRING).map(str::to_string))
                } else {
                    None
                };
                (Some(reason), text)
            } else {
                (None, None)
            };
            Log::new(Some(&status_tx)).info(format!(
                "MQTT client '{}' sent DISCONNECT{}{}",
                session.client_id.as_deref().unwrap_or("<unidentified>"),
                reason
                    .map(|r| format!(" reason=0x{r:02x}"))
                    .unwrap_or_default(),
                detail.map(|d| format!(" ({d})")).unwrap_or_default()
            ));
            false
        }

        PKT_AUTH if session.v5 => {
            // Enhanced authentication (§4.12) is not implemented: a CONNECT naming an
            // Authentication Method is the handler's to refuse with reason 0x8C. An AUTH that
            // arrives anyway is a Protocol Error.
            Log::new(Some(&status_tx)).warn(
                "MQTT AUTH packet: enhanced authentication is not supported \
                 decision=protocol_error, closing",
            );
            session.refuse(out_tx, 0x82);
            false
        }

        other => {
            // PUBACK/PUBREC/PUBCOMP/SUBACK from a client are acknowledgements of
            // broker-initiated traffic; nothing further is owed on the wire.
            trace!("MQTT ignoring inbound packet type {}", other);
            true
        }
    }
}

/// "3.1.1" / "5.0" / "3.1" for a CONNECT protocol level.
pub fn version_name(level: u8) -> &'static str {
    match level {
        3 => "3.1",
        4 => "3.1.1",
        5 => "5.0",
        _ => "unknown",
    }
}

/// What a SUBSCRIBE is answered with, spelled out for this one: the SUBACK, then the retained
/// messages.
///
/// The real-model eval (`mqtt/retained-message`, 0/5) found llama3.1:8b told "the topic holds
/// the retained reading 19.5" sending the SUBACK and nothing else, so the subscriber waited out
/// its timeout for a message that was never published. A broker that stores nothing can only
/// deliver a retained message if the model publishes it, and the model follows a per-request
/// hint far better than the general action list.
pub fn subscribe_answer_with(packet_id: u16, topics: &[(String, u8)]) -> String {
    let filters: Vec<&str> = topics.iter().map(|(f, _)| f.as_str()).collect();
    let granted: Vec<String> = topics.iter().map(|(_, q)| q.to_string()).collect();
    format!(
        "mqtt_suback with packet_id {packet_id} and granted_qos [{}] (one entry per filter; \
         128 refuses one). Then, for each topic matching {:?} that your instruction gives a \
         retained message or current value, mqtt_publish with that topic, the value as \
         payload and retain true - the subscriber is waiting for it. Publish nothing if the \
         instruction gives none.",
        granted.join(", "),
        filters
    )
}

/// Outcome of handing an event to the handler chain (script -> static -> LLM).
enum LlmOutcome {
    /// The handler produced the packet the protocol owes this client.
    Responded,
    /// The handler ran and produced no such packet; the caller applies its protocol default.
    Silent,
    /// The handler asked to close the connection.
    Closed,
    /// The handler could not run at all - the LLM backend failed, timed out, or answered with
    /// something unusable.
    ///
    /// This must stay distinct from [`LlmOutcome::Silent`], and the reason is the most
    /// dangerous bug this module had: `Silent`'s CONNECT default is `build_connack(0, ...)`,
    /// which is *Connection Accepted*. Collapsing a backend failure into `Silent` meant an
    /// LLM outage authenticated every MQTT client that asked, credentials and all, and made a
    /// model's explicit refusal indistinguishable from the backend being down. The `Silent`
    /// defaults are permissive on purpose - they encode "the handler had nothing to say about
    /// a decision the spec requires me to make" - and that is only safe when the handler
    /// actually ran.
    ///
    /// There is no retryable/non-retryable split here because MQTT 3.1.1 has no wire form for
    /// one: CONNACK's only "come back later" code is 3 (server unavailable), SUBACK's only
    /// failure code is 0x80, and PUBACK/UNSUBACK have no code at all. The overload
    /// distinction is therefore logged rather than encoded — on a 3.1.1 connection. v5 has
    /// both (CONNACK 0x88/0x89, DISCONNECT 0x80/0x89), which is what the category is for.
    Failed(crate::utils::wire_failure::WireFailure),
}

/// Parse a client PUBLISH and build its `mqtt_publish` event, applying its Topic Alias.
///
/// `Err` carries the reason code to refuse the connection with: the packet is malformed or
/// breaks a rule of the spec, and the caller closes. Shared by the one-at-a-time path and the
/// QoS 0 batch, so both decode and validate a PUBLISH identically.
fn publish_event(
    packet: &RawPacket,
    session: &mut Session,
    server_id: crate::state::ServerId,
    status_tx: &mpsc::UnboundedSender<String>,
) -> std::result::Result<(Event, u8, u16), u8> {
    let qos = (packet.flags >> 1) & 0x03;
    if qos > 2 {
        Log::new(Some(&status_tx))
            .warn("MQTT PUBLISH with invalid QoS 3 decision=protocol_error, closing");
        return Err(0x81);
    }
    let mut publish = match parse_publish(&packet.body, qos, session.v5) {
        Ok(p) => p,
        Err(e) => {
            Log::new(Some(&status_tx)).warn(format!(
                "MQTT malformed PUBLISH decision=protocol_error, closing connection: {e}"
            ));
            return Err(e.reason_code());
        }
    };

    // Topic Alias (§3.3.2.3.4): a non-empty topic with an alias defines it, an empty
    // topic with an alias uses it. The model always sees the topic name.
    if let Some(alias) = publish.properties.int(v5::TOPIC_ALIAS) {
        let alias = alias as u16;
        if alias == 0 || alias > TOPIC_ALIAS_MAX {
            Log::new(Some(&status_tx)).warn(format!(
                "MQTT PUBLISH with topic alias {alias} outside 1..={TOPIC_ALIAS_MAX} \
                     decision=protocol_error, closing"
            ));
            return Err(0x94);
        }
        if publish.topic.is_empty() {
            match session.aliases.get(&alias) {
                Some(topic) => publish.topic = topic.clone(),
                None => {
                    Log::new(Some(&status_tx)).warn(format!(
                        "MQTT PUBLISH uses topic alias {alias}, which this connection \
                             never defined decision=protocol_error, closing"
                    ));
                    return Err(0x82);
                }
            }
        } else {
            session.aliases.insert(alias, publish.topic.clone());
        }
    } else if session.v5 && publish.topic.is_empty() {
        Log::new(Some(&status_tx)).warn(
            "MQTT PUBLISH with an empty topic and no topic alias \
                 decision=protocol_error, closing",
        );
        return Err(0x82);
    }

    let (payload, payload_is_text) = decode_payload(&publish.payload);
    let name = session
        .client_id
        .clone()
        .unwrap_or_else(|| "<no CONNECT>".into());

    Log::new(Some(&status_tx)).debug(format!(
        "MQTT PUBLISH from '{}' topic='{}' qos={} retain={} {} bytes",
        name,
        publish.topic,
        qos,
        (packet.flags & 0x01) == 1,
        publish.payload.len()
    ));

    let mut data = serde_json::json!({
        "client_id": name,
        "topic": publish.topic,
        "payload": payload,
        "payload_is_text": payload_is_text,
        "payload_size": publish.payload.len(),
        "qos": qos,
        "retain": (packet.flags & 0x01) == 1,
        "duplicate": (packet.flags & 0x08) != 0,
        "packet_id": publish.packet_id,
        "connected_clients": actions::list_clients(server_id),
    });
    if session.v5 {
        data["properties"] = publish.properties.to_json();
    }
    let event = Event::new(&MQTT_PUBLISH_EVENT, data);
    Ok((event, qos, publish.packet_id))
}

/// Answer a QoS 0 PUBLISH together with every further QoS 0 PUBLISH already here, in one call.
///
/// Only QoS 0 is batched, because it is the only PUBLISH that owes the client nothing: a QoS 1
/// or 2 PUBLISH, a SUBSCRIBE and an UNSUBSCRIBE each owe an acknowledgement carrying its own
/// packet id, MQTT requires PUBACKs in the order the PUBLISHes arrived (§4.6), and the default
/// acknowledgement Rust writes for one the handler skipped would land after the handler's own
/// acknowledgements for later ones. Those stay one call each, and so does everything Rust
/// answers itself (PINGREQ, PUBREL, the client's own acks).
///
/// Collection takes complete packets out of `buffer`, reading the socket only for what is
/// readable without waiting, and stops at the first packet that is not a QoS 0 PUBLISH,
/// leaving it for the session loop to handle after the batch. Returns whether the connection
/// stays open.
#[allow(clippy::too_many_arguments)]
async fn publish_batch<R: tokio::io::AsyncRead + Unpin>(
    first: RawPacket,
    buffer: &mut Vec<u8>,
    read_half: &mut R,
    chunk: &mut [u8],
    max_packet_size: usize,
    session: &mut Session,
    llm_client: &OllamaClient,
    app_state: &Arc<AppState>,
    status_tx: &mpsc::UnboundedSender<String>,
    server_id: crate::state::ServerId,
    connection_id: ConnectionId,
    protocol: &MqttProtocol,
    out_tx: &mpsc::UnboundedSender<Vec<u8>>,
) -> bool {
    let mut events = Vec::new();
    match publish_event(&first, session, server_id, status_tx) {
        Ok((event, _, _)) => events.push(event),
        Err(code) => {
            session.refuse(out_tx, code);
            return false;
        }
    }
    // A packet in the run that turns out to break the spec closes the connection, but only
    // after the PUBLISHes before it - which were valid - have been answered.
    let mut refusal = None;
    while events.len() < crate::protocol::metadata::MAX_BATCH_EVENTS {
        let next_is_qos0_publish = buffer
            .first()
            .is_some_and(|&b| b >> 4 == PKT_PUBLISH && (b >> 1) & 0x03 == 0);
        if !buffer.is_empty() && !next_is_qos0_publish {
            break;
        }
        match take_packet(buffer, max_packet_size) {
            Ok(Some(packet)) => match publish_event(&packet, session, server_id, status_tx) {
                Ok((event, _, _)) => events.push(event),
                Err(code) => {
                    refusal = Some(code);
                    break;
                }
            },
            Ok(None) => {
                // A zero deadline polls the read once: whatever the kernel already holds,
                // nothing that would mean waiting. `read` is cancel-safe.
                match tokio::time::timeout(Duration::ZERO, read_half.read(chunk)).await {
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
                        buffer.extend_from_slice(chunk.get(..n).unwrap_or(&[]));
                    }
                    _ => break,
                }
            }
            // Left in the buffer for the session loop, which reports it and closes.
            Err(_) => break,
        }
    }

    if events.len() > 1 {
        Log::new(Some(status_tx)).debug(format!(
            "MQTT answering {} QoS 0 PUBLISHes on {} together",
            events.len(),
            connection_id
        ));
    }
    let outcome = run_llm(
        llm_client,
        app_state,
        server_id,
        connection_id,
        &events,
        protocol,
        status_tx,
        None,
    )
    .await;
    let keep_open = match outcome {
        LlmOutcome::Closed => false,
        LlmOutcome::Responded | LlmOutcome::Silent => true,
        LlmOutcome::Failed(failure) => {
            // The same answer a single QoS 0 PUBLISH gets: nothing looked at these messages,
            // and the spec's only channel for saying so is closing (with a v5 DISCONNECT
            // naming the category first).
            Log::new(Some(status_tx)).warn(format!(
                "MQTT closing connection: backend failed on {} QoS 0 PUBLISH(es)",
                events.len()
            ));
            if session.v5 {
                let mut props = v5::PropertyWriter::new();
                props.text(v5::REASON_STRING, failure.text());
                let code = if failure.is_overloaded() { 0x89 } else { 0x80 };
                let _ = out_tx.send(build_disconnect_v5(code, &props));
            }
            false
        }
    };
    if let (true, Some(code)) = (keep_open, refusal) {
        session.refuse(out_tx, code);
        return false;
    }
    keep_open
}

/// Hand an event to the handler chain and report whether the mandatory reply was
/// produced.
///
/// `required_reply` is the MQTT packet type the spec obliges the broker to send for
/// this event (`None` when nothing is owed, e.g. a QoS 0 PUBLISH). Checking the actual
/// packet type — rather than "did anything get written" — means a handler that
/// forwards a PUBLISH but forgets its PUBACK still gets the PUBACK default, instead of
/// leaving the publisher retrying forever.
#[allow(clippy::too_many_arguments)]
async fn run_llm(
    llm_client: &OllamaClient,
    app_state: &Arc<AppState>,
    server_id: crate::state::ServerId,
    connection_id: ConnectionId,
    events: &[Event],
    protocol: &MqttProtocol,
    status_tx: &mpsc::UnboundedSender<String>,
    required_reply: Option<u8>,
) -> LlmOutcome {
    protocol.clear_written_types();
    // One event, except for a batch of QoS 0 PUBLISHes (`publish_batch`), which owe nothing
    // on the wire, so `required_reply` is `None` for every batch. The newest event names the
    // decision in the log.
    let Some(event) = events.last() else {
        return LlmOutcome::Responded;
    };

    // call_llm dispatches script and static handlers first, so a deterministic
    // handler costs no model call. A batch falls back to one call per event whenever any of
    // them is routed to something other than the model.
    match call_llm_batch(
        llm_client,
        app_state,
        server_id,
        Some(connection_id),
        events,
        protocol,
    )
    .await
    {
        Ok(result) => {
            // One grep-able line per event saying how it was decided. Every branch below
            // ends in a packet (or a close) chosen by a different actor, and the wire form
            // is frequently identical — a CONNACK 0 sent because the model said so and one
            // sent because it said nothing are the same four bytes.
            let client = event
                .data
                .get("client_id")
                .and_then(|v| v.as_str())
                .unwrap_or("<unidentified>");
            let log = Log::new(Some(&status_tx));

            if result
                .protocol_results
                .iter()
                .any(|r| matches!(r, ActionResult::CloseConnection))
            {
                log.info(format!(
                    "MQTT {} from '{}' ({}) decision=model_reject (close_connection)",
                    event.event_type.id, client, connection_id
                ));
                return LlmOutcome::Closed;
            }

            let answered = match required_reply {
                // Nothing is owed on the wire (a QoS 0 PUBLISH), so "answered" is simply
                // whether the handler produced any action at all.
                None => !result.raw_actions.is_empty(),
                Some(packet_type) => protocol.wrote_packet_type(packet_type),
            };

            if answered {
                log.info(format!(
                    "MQTT {} from '{}' ({}) decision=model_answer",
                    event.event_type.id, client, connection_id
                ));
                LlmOutcome::Responded
            } else {
                // `actions=` matters: 0 is a handler with nothing to say, non-zero is a
                // handler that did something else and omitted the packet the spec requires.
                log.warn(format!(
                    "MQTT {} from '{}' ({}) decision=model_silent actions={} — the protocol \
                     default applies",
                    event.event_type.id,
                    client,
                    connection_id,
                    result.raw_actions.len()
                ));
                match required_reply {
                    None => LlmOutcome::Responded,
                    Some(_) => LlmOutcome::Silent,
                }
            }
        }
        Err(e) => {
            // `fail_closed_llm_*` is accurate for every caller of this function: each of the
            // four `LlmOutcome::Failed` arms refuses (CONNACK 3, SUBACK 0x80) or closes.
            // MQTT 3.1.1 has no retryable/permanent split to put on the wire, so the overload
            // distinction lives here and nowhere else.
            let decision = if crate::llm::is_overload_error(&e) {
                "fail_closed_llm_overloaded"
            } else {
                "fail_closed_llm_error"
            };
            let client = event
                .data
                .get("client_id")
                .and_then(|v| v.as_str())
                .unwrap_or("<unidentified>");
            Log::new(Some(&status_tx)).error(format!(
                "MQTT {} from '{}' ({}) decision={}: {}",
                event.event_type.id, client, connection_id, decision, e
            ));
            LlmOutcome::Failed(crate::utils::wire_failure::WireFailure::classify(&e))
        }
    }
}

// ============================================================================
// Wire format: decoding
// ============================================================================

/// Why a packet was refused, and the reason code a v5 client is told (§4.13).
#[derive(Debug, Clone)]
pub struct PacketError {
    /// 0x81 Malformed Packet, 0x82 Protocol Error or 0x95 Packet Too Large.
    pub reason: u8,
    pub message: String,
    /// The packet was a CONNECT that declared protocol level 5, so the refusal can be a v5
    /// CONNACK.
    pub v5_connect: bool,
}

impl PacketError {
    fn malformed(message: impl Into<String>) -> Self {
        Self {
            reason: 0x81,
            message: message.into(),
            v5_connect: false,
        }
    }

    fn protocol(message: impl Into<String>) -> Self {
        Self {
            reason: 0x82,
            message: message.into(),
            v5_connect: false,
        }
    }

    pub fn reason_code(&self) -> u8 {
        self.reason
    }

    /// The CONNACK reason code to refuse a malformed v5 CONNECT with, `None` for 3.1.1.
    pub fn v5_connack_code(&self) -> Option<u8> {
        self.v5_connect.then_some(self.reason)
    }
}

impl std::fmt::Display for PacketError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl From<v5::PropertyError> for PacketError {
    fn from(e: v5::PropertyError) -> Self {
        match e {
            v5::PropertyError::Malformed(_) => PacketError::malformed(e.to_string()),
            v5::PropertyError::Duplicate(_) | v5::PropertyError::Protocol(_) => {
                PacketError::protocol(e.to_string())
            }
        }
    }
}

/// Pull one complete control packet off the front of `buffer`.
///
/// Returns `Ok(None)` when more bytes are needed. Every index is bounds-checked;
/// no input can panic this function, and the declared remaining length is validated
/// against `max_packet_size` before any allocation.
fn take_packet(
    buffer: &mut Vec<u8>,
    max_packet_size: usize,
) -> std::result::Result<Option<RawPacket>, PacketError> {
    let Some(&first) = buffer.first() else {
        return Ok(None);
    };
    let packet_type = first >> 4;
    if packet_type == 0 {
        return Err(PacketError::malformed(format!(
            "invalid packet type {}",
            packet_type
        )));
    }

    let (remaining, len_bytes) = match decode_remaining_length(&buffer[1..]) {
        Some(v) => v,
        None => {
            // Either incomplete, or a varint longer than the legal 4 bytes.
            if buffer.len() > 5 {
                return Err(PacketError::malformed("malformed remaining length"));
            }
            return Ok(None);
        }
    };

    if remaining > max_packet_size {
        return Err(PacketError {
            reason: 0x95,
            message: format!(
                "packet of {} bytes exceeds max_packet_size {}",
                remaining, max_packet_size
            ),
            v5_connect: false,
        });
    }

    let total = 1 + len_bytes + remaining;
    if buffer.len() < total {
        return Ok(None);
    }

    let body = buffer[1 + len_bytes..total].to_vec();
    buffer.drain(..total);

    Ok(Some(RawPacket {
        packet_type,
        flags: first & 0x0F,
        body,
    }))
}

/// Decode the variable-length "remaining length" field (3.1.1 section 2.2.3).
/// Returns `(value, bytes_consumed)`, or `None` if incomplete or over 4 bytes.
fn decode_remaining_length(buf: &[u8]) -> Option<(usize, usize)> {
    let mut value: usize = 0;
    let mut multiplier: usize = 1;
    for i in 0..4 {
        let byte = *buf.get(i)?;
        value += (byte & 0x7F) as usize * multiplier;
        if byte & 0x80 == 0 {
            return Some((value, i + 1));
        }
        multiplier *= 128;
    }
    None
}

fn read_u16_at(buf: &[u8], pos: usize) -> Option<u16> {
    let hi = *buf.get(pos)?;
    let lo = *buf.get(pos + 1)?;
    Some(u16::from_be_bytes([hi, lo]))
}

/// Read a length-prefixed UTF-8 string, advancing `pos`.
fn read_string(buf: &[u8], pos: &mut usize) -> Option<String> {
    let len = read_u16_at(buf, *pos)? as usize;
    let start = pos.checked_add(2)?;
    let end = start.checked_add(len)?;
    let bytes = buf.get(start..end)?;
    *pos = end;
    Some(String::from_utf8_lossy(bytes).into_owned())
}

/// Read a length-prefixed binary field, advancing `pos`.
fn read_bytes(buf: &[u8], pos: &mut usize) -> Option<Vec<u8>> {
    let len = read_u16_at(buf, *pos)? as usize;
    let start = pos.checked_add(2)?;
    let end = start.checked_add(len)?;
    let bytes = buf.get(start..end)?.to_vec();
    *pos = end;
    Some(bytes)
}

/// Render a payload for the model: never raw bytes, never base64.
/// Non-UTF-8 payloads are reported lossily and flagged.
fn decode_payload(bytes: &[u8]) -> (String, bool) {
    match std::str::from_utf8(bytes) {
        Ok(s) => (s.to_string(), true),
        Err(_) => (String::from_utf8_lossy(bytes).into_owned(), false),
    }
}

/// A decoded CONNECT (3.1.1 §3.1, 5.0 §3.1).
pub struct ConnectPacket {
    pub protocol_name: String,
    pub protocol_level: u8,
    pub clean_session: bool,
    pub keep_alive: u16,
    pub client_id: String,
    pub username: Option<String>,
    pub has_password: bool,
    pub will_topic: Option<String>,
    pub will_message: Option<String>,
    /// v5 only; empty on 3.1.1.
    pub properties: v5::Properties,
    /// v5 only: the Will Properties that precede the will topic.
    pub will_properties: v5::Properties,
}

pub fn parse_connect(body: &[u8]) -> std::result::Result<ConnectPacket, PacketError> {
    let short = || PacketError::malformed("CONNECT is truncated");
    let mut pos = 0usize;
    let protocol_name = read_string(body, &mut pos).ok_or_else(short)?;
    let protocol_level = *body.get(pos).ok_or_else(short)?;
    pos += 1;
    let v5 = protocol_level == 5;
    let tag = |mut e: PacketError| {
        e.v5_connect = v5;
        e
    };
    let flags = *body.get(pos).ok_or_else(short).map_err(tag)?;
    pos += 1;
    let keep_alive = read_u16_at(body, pos).ok_or_else(short).map_err(tag)?;
    pos += 2;

    let properties = if v5 {
        let props = v5::read_properties(body, &mut pos)
            .map_err(PacketError::from)
            .map_err(tag)?;
        v5::forbid(&props, &[v5::SUBSCRIPTION_IDENTIFIER], "CONNECT")
            .map_err(PacketError::from)
            .map_err(tag)?;
        // §3.1.2.11.4: "It is a Protocol Error ... for the value to be set to zero." A limit of
        // 0 would also leave every packet the broker sends this client unsendable.
        if props.int(v5::MAXIMUM_PACKET_SIZE) == Some(0) {
            return Err(tag(PacketError::protocol("maximum packet size 0")));
        }
        props
    } else {
        v5::Properties::default()
    };

    let client_id = read_string(body, &mut pos).ok_or_else(short).map_err(tag)?;

    let mut will_properties = v5::Properties::default();
    let (will_topic, will_message) = if flags & 0x04 != 0 {
        if v5 {
            will_properties = v5::read_properties(body, &mut pos)
                .map_err(PacketError::from)
                .map_err(tag)?;
            v5::forbid(
                &will_properties,
                &[v5::SUBSCRIPTION_IDENTIFIER],
                "Will Properties",
            )
            .map_err(PacketError::from)
            .map_err(tag)?;
        }
        let topic = read_string(body, &mut pos).ok_or_else(short).map_err(tag)?;
        let message = read_bytes(body, &mut pos).ok_or_else(short).map_err(tag)?;
        (Some(topic), Some(decode_payload(&message).0))
    } else {
        (None, None)
    };

    let username = if flags & 0x80 != 0 {
        Some(read_string(body, &mut pos).ok_or_else(short).map_err(tag)?)
    } else {
        None
    };
    let has_password = flags & 0x40 != 0;

    Ok(ConnectPacket {
        protocol_name,
        protocol_level,
        clean_session: flags & 0x02 != 0,
        keep_alive,
        client_id,
        username,
        has_password,
        will_topic,
        will_message,
        properties,
        will_properties,
    })
}

/// A decoded PUBLISH. `topic` is empty when a v5 client used a Topic Alias alone.
pub struct PublishPacket {
    pub topic: String,
    pub packet_id: u16,
    pub payload: Vec<u8>,
    pub properties: v5::Properties,
}

pub fn parse_publish(
    body: &[u8],
    qos: u8,
    v5: bool,
) -> std::result::Result<PublishPacket, PacketError> {
    let short = || PacketError::malformed("PUBLISH is truncated");
    let mut pos = 0usize;
    let topic = read_string(body, &mut pos).ok_or_else(short)?;
    let packet_id = if qos > 0 {
        let id = read_u16_at(body, pos).ok_or_else(short)?;
        pos += 2;
        id
    } else {
        0
    };
    let properties = if v5 {
        let props = v5::read_properties(body, &mut pos)?;
        // [MQTT-3.3.4-6]: a PUBLISH from a client MUST NOT carry a Subscription Identifier.
        v5::forbid(&props, &[v5::SUBSCRIPTION_IDENTIFIER], "a client's PUBLISH")?;
        props
    } else {
        v5::Properties::default()
    };
    let payload = body.get(pos..).ok_or_else(short)?.to_vec();
    Ok(PublishPacket {
        topic,
        packet_id,
        payload,
        properties,
    })
}

/// v5 Subscription Options (§3.8.3.1). On 3.1.1 only the QoS bits exist and these are false/0.
#[derive(Clone, Copy, Debug, Default)]
pub struct SubscriptionOptions {
    pub no_local: bool,
    pub retain_as_published: bool,
    pub retain_handling: u8,
}

pub struct SubscribePacket {
    pub packet_id: u16,
    pub topics: Vec<(String, u8)>,
    /// One per entry of `topics`.
    pub options: Vec<SubscriptionOptions>,
    pub properties: v5::Properties,
}

pub fn parse_subscribe(body: &[u8], v5: bool) -> std::result::Result<SubscribePacket, PacketError> {
    let short = || PacketError::malformed("SUBSCRIBE is truncated");
    let mut pos = 0usize;
    let packet_id = read_u16_at(body, pos).ok_or_else(short)?;
    pos += 2;
    let properties = if v5 {
        // The one packet a client may put a Subscription Identifier in; `read_properties`
        // refuses a second one and the value 0 (§3.8.2.1.2) as Protocol Errors.
        v5::read_properties(body, &mut pos)?
    } else {
        v5::Properties::default()
    };

    let mut topics = Vec::new();
    let mut options = Vec::new();
    while pos < body.len() {
        let filter = read_string(body, &mut pos).ok_or_else(short)?;
        let byte = *body.get(pos).ok_or_else(short)?;
        pos += 1;
        let qos = byte & 0x03;
        let mut opts = SubscriptionOptions::default();
        if v5 {
            // §3.8.3.1: QoS 3, Retain Handling 3 and the two reserved bits are all
            // Malformed Packet.
            if qos == 3 || (byte >> 4) & 0x03 == 3 || byte & 0xC0 != 0 {
                return Err(PacketError::malformed(format!(
                    "invalid subscription options byte 0x{byte:02x} for '{filter}'"
                )));
            }
            opts = SubscriptionOptions {
                no_local: byte & 0x04 != 0,
                retain_as_published: byte & 0x08 != 0,
                retain_handling: (byte >> 4) & 0x03,
            };
        }
        topics.push((filter, qos));
        options.push(opts);
    }
    Ok(SubscribePacket {
        packet_id,
        topics,
        options,
        properties,
    })
}

pub struct UnsubscribePacket {
    pub packet_id: u16,
    pub topics: Vec<String>,
    pub properties: v5::Properties,
}

pub fn parse_unsubscribe(
    body: &[u8],
    v5: bool,
) -> std::result::Result<UnsubscribePacket, PacketError> {
    let short = || PacketError::malformed("UNSUBSCRIBE is truncated");
    let mut pos = 0usize;
    let packet_id = read_u16_at(body, pos).ok_or_else(short)?;
    pos += 2;
    let properties = if v5 {
        let props = v5::read_properties(body, &mut pos)?;
        v5::forbid(&props, &[v5::SUBSCRIPTION_IDENTIFIER], "UNSUBSCRIBE")?;
        props
    } else {
        v5::Properties::default()
    };

    let mut topics = Vec::new();
    while pos < body.len() {
        topics.push(read_string(body, &mut pos).ok_or_else(short)?);
    }
    Ok(UnsubscribePacket {
        packet_id,
        topics,
        properties,
    })
}

// ============================================================================
// Wire format: encoding
// ============================================================================

/// Encode the variable-length "remaining length" field.
pub fn encode_remaining_length(mut len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(4);
    loop {
        let mut byte = (len % 128) as u8;
        len /= 128;
        if len > 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if len == 0 || out.len() == 4 {
            break;
        }
    }
    out
}

/// CONNACK (3.2). `return_code` 0 accepts; 1-5 are the specified refusals.
pub fn build_connack(return_code: u8, session_present: bool) -> Vec<u8> {
    vec![
        PKT_CONNACK << 4,
        0x02,
        if session_present { 0x01 } else { 0x00 },
        return_code,
    ]
}

/// PUBACK / PUBREC / PUBCOMP / UNSUBACK: two-byte body echoing the packet identifier.
pub fn build_ack(packet_type: u8, packet_id: u16) -> Vec<u8> {
    let id = packet_id.to_be_bytes();
    let header = if packet_type == PKT_PUBREL {
        (packet_type << 4) | 0x02
    } else {
        packet_type << 4
    };
    vec![header, 0x02, id[0], id[1]]
}

/// SUBACK (3.9): echoes the packet identifier and one return code per filter.
/// 0x80 means "subscription refused".
pub fn build_suback(packet_id: u16, granted_qos: &[u8]) -> Vec<u8> {
    let mut body = packet_id.to_be_bytes().to_vec();
    body.extend_from_slice(granted_qos);
    let mut out = vec![PKT_SUBACK << 4];
    out.extend_from_slice(&encode_remaining_length(body.len()));
    out.extend_from_slice(&body);
    out
}

/// PUBLISH (3.3). `packet_id` is only present, and only required, for QoS > 0.
pub fn build_publish(topic: &str, payload: &str, qos: u8, retain: bool, packet_id: u16) -> Vec<u8> {
    let topic_bytes = topic.as_bytes();
    let payload_bytes = payload.as_bytes();

    let mut body = Vec::with_capacity(2 + topic_bytes.len() + 2 + payload_bytes.len());
    body.extend_from_slice(&(topic_bytes.len() as u16).to_be_bytes());
    body.extend_from_slice(topic_bytes);
    if qos > 0 {
        body.extend_from_slice(&packet_id.to_be_bytes());
    }
    body.extend_from_slice(payload_bytes);

    let mut flags = (qos & 0x03) << 1;
    if retain {
        flags |= 0x01;
    }

    let mut out = vec![(PKT_PUBLISH << 4) | flags];
    out.extend_from_slice(&encode_remaining_length(body.len()));
    out.extend_from_slice(&body);
    out
}

/// Fixed header + remaining length + body.
fn frame(first_byte: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![first_byte];
    out.extend_from_slice(&encode_remaining_length(body.len()));
    out.extend_from_slice(body);
    out
}

/// v5 CONNACK (5.0 §3.2): acknowledge flags, reason code, properties.
pub fn build_connack_v5(reason: u8, session_present: bool, props: &v5::PropertyWriter) -> Vec<u8> {
    let mut body = vec![u8::from(session_present), reason];
    body.extend_from_slice(&props.finish());
    frame(PKT_CONNACK << 4, &body)
}

/// v5 PUBACK / PUBREC / PUBCOMP (5.0 §3.4–3.7). Reason Code 0x00 with no properties is the
/// two-byte 3.1.1 form, which §3.4.2.1 allows and every v5 client accepts.
pub fn build_ack_v5(
    packet_type: u8,
    packet_id: u16,
    reason: u8,
    props: &v5::PropertyWriter,
) -> Vec<u8> {
    if reason == 0 && props.is_empty() {
        return build_ack(packet_type, packet_id);
    }
    let mut body = packet_id.to_be_bytes().to_vec();
    body.push(reason);
    body.extend_from_slice(&props.finish());
    let first = if packet_type == PKT_PUBREL {
        (packet_type << 4) | 0x02
    } else {
        packet_type << 4
    };
    frame(first, &body)
}

/// v5 SUBACK (5.0 §3.9): packet identifier, properties, one reason code per filter.
pub fn build_suback_v5(packet_id: u16, codes: &[u8], props: &v5::PropertyWriter) -> Vec<u8> {
    let mut body = packet_id.to_be_bytes().to_vec();
    body.extend_from_slice(&props.finish());
    body.extend_from_slice(codes);
    frame(PKT_SUBACK << 4, &body)
}

/// v5 UNSUBACK (5.0 §3.11): packet identifier, properties, one reason code per filter. Unlike
/// 3.1.1's bare identifier, the payload is required.
pub fn build_unsuback_v5(packet_id: u16, codes: &[u8], props: &v5::PropertyWriter) -> Vec<u8> {
    let mut body = packet_id.to_be_bytes().to_vec();
    body.extend_from_slice(&props.finish());
    body.extend_from_slice(codes);
    frame(PKT_UNSUBACK << 4, &body)
}

/// v5 DISCONNECT from the server (5.0 §3.14): reason code and properties.
pub fn build_disconnect_v5(reason: u8, props: &v5::PropertyWriter) -> Vec<u8> {
    let mut body = vec![reason];
    body.extend_from_slice(&props.finish());
    frame(PKT_DISCONNECT << 4, &body)
}

/// v5 PUBLISH (5.0 §3.3): the 3.1.1 layout with a property block after the packet identifier.
pub fn build_publish_v5(
    topic: &str,
    payload: &[u8],
    qos: u8,
    retain: bool,
    packet_id: u16,
    props: &v5::PropertyWriter,
) -> Vec<u8> {
    let mut body = Vec::with_capacity(2 + topic.len() + 2 + 8 + payload.len());
    body.extend_from_slice(&(topic.len() as u16).to_be_bytes());
    body.extend_from_slice(topic.as_bytes());
    if qos > 0 {
        body.extend_from_slice(&packet_id.to_be_bytes());
    }
    body.extend_from_slice(&props.finish());
    body.extend_from_slice(payload);
    let mut flags = (qos & 0x03) << 1;
    if retain {
        flags |= 0x01;
    }
    frame((PKT_PUBLISH << 4) | flags, &body)
}

/// A broker-originated PUBLISH before it is framed: framing depends on the recipient's version,
/// and one `mqtt_publish` to `"*"` can reach 3.1.1 and v5 clients at once.
#[derive(Clone, Debug)]
pub struct OutPublish {
    pub topic: String,
    pub payload: String,
    pub qos: u8,
    pub retain: bool,
    pub packet_id: u16,
    /// v5 properties. A 3.1.1 recipient has no field for them, so they are not sent there.
    pub properties: v5::PropertyWriter,
}

impl OutPublish {
    pub fn encode(&self, v5: bool) -> Vec<u8> {
        if v5 {
            build_publish_v5(
                &self.topic,
                self.payload.as_bytes(),
                self.qos,
                self.retain,
                self.packet_id,
                &self.properties,
            )
        } else {
            build_publish(
                &self.topic,
                &self.payload,
                self.qos,
                self.retain,
                self.packet_id,
            )
        }
    }
}
