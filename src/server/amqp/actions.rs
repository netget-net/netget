//! AMQP 0-9-1 broker actions, events and metadata.
//!
//! Every action declared here is executed by [`AmqpProtocol::execute_action`] and every
//! declared parameter is read. Sync actions write through the writer channel of the
//! connection they were produced for, except `amqp_basic_deliver`, which addresses a
//! consumer by tag and may therefore write to a different connection entirely.

use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter, ParameterDefinition,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::EventType;
use crate::server::amqp::codec::{
    body_frames, content_header_frame, method_frame, BasicProperties, Encoder, BASIC_CONSUME_OK,
    BASIC_DELIVER, BASIC_RETURN, CHANNEL_CLOSE, CLASS_BASIC, CLASS_CHANNEL, CLASS_CONNECTION,
    CLASS_QUEUE, CONNECTION_CLOSE, CONNECTION_OPEN, CONNECTION_OPEN_OK, QUEUE_DECLARE_OK,
};
use crate::server::connection::ConnectionId;
use crate::state::app_state::AppState;
use crate::state::ServerId;
use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex, RwLock};
use tokio::sync::mpsc;
use tracing::{debug, warn};

// ============================================================================
// Response kinds
// ============================================================================
//
// The connection loop needs to know whether a handler produced the reply the protocol
// owes a client, not merely whether it wrote *something*: a handler that answers a
// `basic.consume` with only a delivery still leaves the client waiting for its
// Consume-Ok. Each executed action sets its bit; the loop reads the mask afterwards.

pub const RESP_CONNECTION_OPEN_OK: u32 = 1 << 0;
pub const RESP_CONNECTION_CLOSE: u32 = 1 << 1;
pub const RESP_QUEUE_DECLARE_OK: u32 = 1 << 2;
pub const RESP_CONSUME_OK: u32 = 1 << 3;
pub const RESP_DELIVER: u32 = 1 << 4;
pub const RESP_CHANNEL_CLOSE: u32 = 1 << 5;
pub const RESP_RETURN: u32 = 1 << 6;

// ============================================================================
// Live consumer directory
// ============================================================================

/// One consumer that is attached right now: the socket to write to and the channel
/// number a `Basic.Deliver` has to carry.
///
/// This is a directory of *live sockets*, not storage. No message, queue, exchange or
/// binding is held here, and an entry disappears the moment its channel or connection
/// closes. It exists so that a delivery produced while handling a publish on one
/// connection can reach a consumer sitting on another.
#[derive(Clone)]
struct ConsumerHandle {
    connection_id: u32,
    channel: u16,
    queue: String,
    tx: mpsc::UnboundedSender<Vec<u8>>,
    frame_max: u32,
    next_delivery_tag: Arc<AtomicU64>,
}

static AMQP_CONSUMERS: LazyLock<Mutex<HashMap<(u32, String), ConsumerHandle>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Counter behind server-generated consumer tags.
static CONSUMER_TAG_SEQ: AtomicU64 = AtomicU64::new(1);

/// Tag for a client that asked the broker to pick one (an empty `consumer-tag`).
pub fn generate_consumer_tag(connection_id: ConnectionId) -> String {
    format!(
        "amq.ctag-{}-{}",
        connection_id.as_u32(),
        CONSUMER_TAG_SEQ.fetch_add(1, Ordering::Relaxed)
    )
}

#[allow(clippy::too_many_arguments)]
pub fn register_consumer(
    server_id: ServerId,
    connection_id: ConnectionId,
    consumer_tag: &str,
    channel: u16,
    queue: &str,
    tx: mpsc::UnboundedSender<Vec<u8>>,
    frame_max: u32,
) -> bool {
    if let Ok(mut map) = AMQP_CONSUMERS.lock() {
        // A consumer tag is chosen by the client and is unique only *within* a connection.
        // This directory is keyed per server, so a plain insert let connection B claim a tag
        // connection A was already using and overwrite A's socket handle - every subsequent
        // amqp_basic_deliver for that tag then went to B. The tags are not secret either:
        // `list_consumers` hands every connection's tags to the model on each publish event.
        //
        // Refusing the second registration is the safe direction. The AMQP-correct answer is
        // a channel error, and `on_basic_consume` turns this `false` into one.
        let key = (server_id.as_u32(), consumer_tag.to_string());
        if let Some(existing) = map.get(&key) {
            if existing.connection_id != connection_id.as_u32() {
                warn!(
                    "AMQP consumer tag '{}' is already held by connection {}; refusing to \
                     hand it to connection {}",
                    consumer_tag, existing.connection_id, connection_id
                );
                return false;
            }
        }
        map.insert(
            key,
            ConsumerHandle {
                connection_id: connection_id.as_u32(),
                channel,
                queue: queue.to_string(),
                tx,
                frame_max,
                next_delivery_tag: Arc::new(AtomicU64::new(1)),
            },
        );
        return true;
    }
    false
}

/// Whether `consumer_tag` is registered on this server by a *different* connection.
///
/// Consumer tags are client-chosen and unique only within a connection, but the directory is
/// keyed per server, so the two clash. `on_basic_consume` asks this before doing anything
/// else, and refuses with a channel error rather than letting the second registration
/// overwrite the first connection's socket handle.
pub fn consumer_tag_taken_by_other(
    server_id: ServerId,
    connection_id: ConnectionId,
    consumer_tag: &str,
) -> bool {
    let Ok(map) = AMQP_CONSUMERS.lock() else {
        return false;
    };
    map.get(&(server_id.as_u32(), consumer_tag.to_string()))
        .is_some_and(|handle| handle.connection_id != connection_id.as_u32())
}

/// Remove a consumer, but only if `connection_id` is the one that registered it.
///
/// The connection check is the point. `Basic.Cancel` carries a client-chosen tag, and
/// without it connection B could cancel connection A's consumer by naming A's tag - after
/// which A silently stopped receiving deliveries, with no `Basic.Cancel` to tell it why.
/// `unregister_consumers_for_connection` and `_for_channel` always checked; this did not.
pub fn unregister_consumer(
    server_id: ServerId,
    connection_id: ConnectionId,
    consumer_tag: &str,
) -> bool {
    if let Ok(mut map) = AMQP_CONSUMERS.lock() {
        let key = (server_id.as_u32(), consumer_tag.to_string());
        if let Some(handle) = map.get(&key) {
            if handle.connection_id != connection_id.as_u32() {
                warn!(
                    "AMQP connection {} tried to cancel consumer '{}', which belongs to \
                     connection {}; ignoring",
                    connection_id, consumer_tag, handle.connection_id
                );
                return false;
            }
            map.remove(&key);
            return true;
        }
    }
    false
}

pub fn unregister_consumers_for_connection(server_id: ServerId, connection_id: ConnectionId) {
    if let Ok(mut map) = AMQP_CONSUMERS.lock() {
        map.retain(|(sid, _), handle| {
            *sid != server_id.as_u32() || handle.connection_id != connection_id.as_u32()
        });
    }
}

pub fn unregister_consumers_for_channel(
    server_id: ServerId,
    connection_id: ConnectionId,
    channel: u16,
) {
    if let Ok(mut map) = AMQP_CONSUMERS.lock() {
        map.retain(|(sid, _), handle| {
            *sid != server_id.as_u32()
                || handle.connection_id != connection_id.as_u32()
                || handle.channel != channel
        });
    }
}

/// Consumers attached to one server, as `{"consumer_tag": ..., "queue": ...}`, sorted by
/// tag so the list is stable for the model between events.
pub fn list_consumers(server_id: ServerId) -> Vec<Value> {
    let Ok(map) = AMQP_CONSUMERS.lock() else {
        return Vec::new();
    };
    let mut rows: Vec<(String, String)> = map
        .iter()
        .filter(|((sid, _), _)| *sid == server_id.as_u32())
        .map(|((_, tag), handle)| (tag.clone(), handle.queue.clone()))
        .collect();
    rows.sort();
    rows.into_iter()
        .map(|(tag, queue)| json!({ "consumer_tag": tag, "queue": queue }))
        .collect()
}

fn lookup_consumer(server_id: u32, consumer_tag: &str) -> Option<ConsumerHandle> {
    AMQP_CONSUMERS
        .lock()
        .ok()
        .and_then(|map| map.get(&(server_id, consumer_tag.to_string())).cloned())
}

// ============================================================================
// Protocol
// ============================================================================

/// AMQP protocol action handler.
///
/// Two shapes: the registry-wide instance from [`AmqpProtocol::new`], used for
/// documentation, spawning and user-triggered async actions; and a per-connection
/// instance from [`AmqpProtocol::for_connection`] that owns one client's writer and can
/// therefore execute the response actions.
pub struct AmqpProtocol {
    server_id: Option<ServerId>,
    connection_id: Option<ConnectionId>,
    out_tx: Option<mpsc::UnboundedSender<Vec<u8>>>,
    status_tx: Option<mpsc::UnboundedSender<String>>,
    /// Channel the method currently being answered arrived on.
    channel: AtomicU32,
    /// Negotiated maximum frame size, used to chunk delivery bodies.
    frame_max: AtomicU32,
    /// Consumer tag from the `amqp_basic_consume` currently being answered.
    consumer_tag: RwLock<Option<String>>,
    /// Queue name from the method currently being answered.
    queue: RwLock<Option<String>>,
    /// Which `RESP_*` responses have been written since the last [`AmqpProtocol::begin`].
    written: AtomicU32,
}

impl Default for AmqpProtocol {
    fn default() -> Self {
        Self::new()
    }
}

impl AmqpProtocol {
    pub fn new() -> Self {
        Self {
            server_id: None,
            connection_id: None,
            out_tx: None,
            status_tx: None,
            channel: AtomicU32::new(0),
            frame_max: AtomicU32::new(131_072),
            consumer_tag: RwLock::new(None),
            queue: RwLock::new(None),
            written: AtomicU32::new(0),
        }
    }

    pub fn for_connection(
        server_id: ServerId,
        connection_id: ConnectionId,
        out_tx: mpsc::UnboundedSender<Vec<u8>>,
        status_tx: mpsc::UnboundedSender<String>,
        frame_max: u32,
    ) -> Self {
        Self {
            server_id: Some(server_id),
            connection_id: Some(connection_id),
            out_tx: Some(out_tx),
            status_tx: Some(status_tx),
            channel: AtomicU32::new(0),
            frame_max: AtomicU32::new(frame_max),
            consumer_tag: RwLock::new(None),
            queue: RwLock::new(None),
            written: AtomicU32::new(0),
        }
    }

    pub fn set_frame_max(&self, frame_max: u32) {
        self.frame_max.store(frame_max, Ordering::SeqCst);
    }

    /// Bind the context of the method about to be handed to the handler chain, and clear
    /// the record of what was written.
    pub fn begin(&self, channel: u16, consumer_tag: Option<&str>, queue: Option<&str>) {
        self.channel.store(channel as u32, Ordering::SeqCst);
        self.written.store(0, Ordering::SeqCst);
        if let Ok(mut guard) = self.consumer_tag.write() {
            *guard = consumer_tag.map(str::to_string);
        }
        if let Ok(mut guard) = self.queue.write() {
            *guard = queue.map(str::to_string);
        }
    }

    /// Bitmask of the `RESP_*` responses written since [`AmqpProtocol::begin`].
    pub fn written(&self) -> u32 {
        self.written.load(Ordering::SeqCst)
    }

    fn current_channel(&self) -> u16 {
        self.channel.load(Ordering::SeqCst) as u16
    }

    fn channel_of(&self, action: &Value) -> u16 {
        action
            .get("channel")
            .and_then(|v| v.as_u64())
            .map(|v| v.min(u16::MAX as u64) as u16)
            .unwrap_or_else(|| self.current_channel())
    }

    fn send(&self, response: u32, bytes: Vec<u8>) -> Result<()> {
        let tx = self.out_tx.as_ref().context(
            "This AMQP action can only run while answering a client method (no connection bound)",
        )?;
        tx.send(bytes)
            .map_err(|_| anyhow::anyhow!("AMQP connection is already closed"))?;
        self.written.fetch_or(response, Ordering::SeqCst);
        Ok(())
    }

    fn log(&self, message: String) {
        debug!("{}", message);
        if let Some(tx) = &self.status_tx {
            let _ = tx.send(format!("[DEBUG] {}", message));
        }
    }

    fn require_str<'a>(action: &'a Value, key: &str, hint: &str) -> Result<&'a str> {
        action
            .get(key)
            .and_then(|v| v.as_str())
            .with_context(|| format!("Missing '{}'. {}", key, hint))
    }

    /// The server this action addresses: our own id when the executor is bound to one,
    /// otherwise the model's `server_id`.
    ///
    /// The `None` arm used to end in `as u32`, which wraps in silence — `4294967297` becomes
    /// `1`, so an action naming a broker that does not exist is delivered to whichever broker
    /// happens to be number 1 rather than failing. The id is the only thing separating two
    /// running brokers, so the wrap publishes to the wrong one.
    fn require_server_id(&self, action: &Value) -> Result<u32> {
        if let Some(id) = self.server_id {
            return Ok(id.as_u32());
        }
        let raw = action.get("server_id").and_then(|v| v.as_u64()).context(
            "Missing 'server_id' (the id of the running AMQP server, from the server list)",
        )?;
        u32::try_from(raw).map_err(|_| {
            anyhow::anyhow!(
                "server_id {raw} is not a NetGet server id (0-4294967295); take it from the \
                 server list rather than inventing one"
            )
        })
    }

    // ---- executors -------------------------------------------------------

    fn execute_connection_open_ok(&self) -> Result<ActionResult> {
        let mut args = Encoder::new();
        args.short_string("")?; // reserved-1 (known-hosts)
        self.log("AMQP -> connection.open-ok".to_string());
        self.send(
            RESP_CONNECTION_OPEN_OK,
            method_frame(0, CLASS_CONNECTION, CONNECTION_OPEN_OK, args.as_slice()),
        )?;
        Ok(ActionResult::Custom {
            name: "amqp_connection_open_ok".to_string(),
            data: json!({ "accepted": true }),
        })
    }

    fn execute_connection_close(&self, action: Value) -> Result<ActionResult> {
        let reply_code = action
            .get("reply_code")
            .and_then(|v| v.as_u64())
            .unwrap_or(403);
        if !(200..=999).contains(&reply_code) {
            return Err(anyhow::anyhow!(
                "reply_code {} is not an AMQP reply code (200 is success; 320, 403, 501, 503, 530 and 540 are the usual refusals)",
                reply_code
            ));
        }
        let reply_text = Self::require_str(
            &action,
            "reply_text",
            "Say why the connection is being closed; the client surfaces this text to its caller.",
        )?;

        let mut args = Encoder::new();
        args.u16(reply_code as u16);
        args.reply_text(reply_text);
        args.u16(CLASS_CONNECTION);
        args.u16(CONNECTION_OPEN);
        self.log(format!(
            "AMQP -> connection.close {} {}",
            reply_code, reply_text
        ));
        self.send(
            RESP_CONNECTION_CLOSE,
            method_frame(0, CLASS_CONNECTION, CONNECTION_CLOSE, args.as_slice()),
        )?;
        Ok(ActionResult::Custom {
            name: "amqp_connection_close".to_string(),
            data: json!({ "reply_code": reply_code, "reply_text": reply_text }),
        })
    }

    fn execute_channel_close(&self, action: Value) -> Result<ActionResult> {
        let channel = self.channel_of(&action);
        let reply_code = action
            .get("reply_code")
            .and_then(|v| v.as_u64())
            .unwrap_or(404);
        if !(200..=999).contains(&reply_code) {
            return Err(anyhow::anyhow!(
                "reply_code {} is not an AMQP reply code (404 not found, 403 access refused, 406 precondition failed, 540 not implemented)",
                reply_code
            ));
        }
        let reply_text = Self::require_str(
            &action,
            "reply_text",
            "Say why the channel is being closed; the client surfaces this text to its caller.",
        )?;

        let mut args = Encoder::new();
        args.u16(reply_code as u16);
        args.reply_text(reply_text);
        args.u16(0);
        args.u16(0);
        self.log(format!(
            "AMQP -> channel.close {} on channel {}: {}",
            reply_code, channel, reply_text
        ));
        self.send(
            RESP_CHANNEL_CLOSE,
            method_frame(channel, CLASS_CHANNEL, CHANNEL_CLOSE, args.as_slice()),
        )?;
        Ok(ActionResult::Custom {
            name: "amqp_channel_close".to_string(),
            data: json!({ "channel": channel, "reply_code": reply_code, "reply_text": reply_text }),
        })
    }

    fn execute_queue_declare_ok(&self, action: Value) -> Result<ActionResult> {
        let channel = self.channel_of(&action);
        let queue = match action.get("queue").and_then(|v| v.as_str()) {
            Some(q) => q.to_string(),
            None => self
                .queue
                .read()
                .ok()
                .and_then(|g| g.clone())
                .context("Missing 'queue' and no queue name is bound to this event")?,
        };
        let message_count = action
            .get("message_count")
            .and_then(|v| v.as_u64())
            .unwrap_or(0)
            .min(u32::MAX as u64) as u32;
        let consumer_count = action
            .get("consumer_count")
            .and_then(|v| v.as_u64())
            .unwrap_or(0)
            .min(u32::MAX as u64) as u32;

        let mut args = Encoder::new();
        args.short_string(&queue)?;
        args.u32(message_count);
        args.u32(consumer_count);
        self.log(format!(
            "AMQP -> queue.declare-ok '{}' messages={} consumers={}",
            queue, message_count, consumer_count
        ));
        self.send(
            RESP_QUEUE_DECLARE_OK,
            method_frame(channel, CLASS_QUEUE, QUEUE_DECLARE_OK, args.as_slice()),
        )?;
        Ok(ActionResult::Custom {
            name: "amqp_queue_declare_ok".to_string(),
            data: json!({
                "queue": queue,
                "message_count": message_count,
                "consumer_count": consumer_count,
            }),
        })
    }

    fn execute_consume_ok(&self, action: Value) -> Result<ActionResult> {
        let channel = self.channel_of(&action);
        let consumer_tag = match action.get("consumer_tag").and_then(|v| v.as_str()) {
            Some(t) => t.to_string(),
            None => self
                .consumer_tag
                .read()
                .ok()
                .and_then(|g| g.clone())
                .context("Missing 'consumer_tag' and no consumer tag is bound to this event")?,
        };
        let queue = action
            .get("queue")
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .or_else(|| self.queue.read().ok().and_then(|g| g.clone()))
            .unwrap_or_default();

        let (Some(server_id), Some(connection_id), Some(tx)) =
            (self.server_id, self.connection_id, self.out_tx.clone())
        else {
            return Err(anyhow::anyhow!(
                "amqp_basic_consume_ok can only run while answering a client's basic.consume"
            ));
        };

        if !register_consumer(
            server_id,
            connection_id,
            &consumer_tag,
            channel,
            &queue,
            tx,
            self.frame_max.load(Ordering::SeqCst),
        ) {
            // Another connection holds the tag. Sending Consume-Ok anyway would tell this
            // client it has a consumer that will never receive anything.
            return Err(anyhow::anyhow!(
                "consumer tag '{}' is already held by another connection on this server",
                consumer_tag
            ));
        }

        let mut args = Encoder::new();
        args.short_string(&consumer_tag)?;
        self.log(format!(
            "AMQP -> basic.consume-ok '{}' on channel {}",
            consumer_tag, channel
        ));
        self.send(
            RESP_CONSUME_OK,
            method_frame(channel, CLASS_BASIC, BASIC_CONSUME_OK, args.as_slice()),
        )?;
        Ok(ActionResult::Custom {
            name: "amqp_basic_consume_ok".to_string(),
            data: json!({ "consumer_tag": consumer_tag, "queue": queue, "channel": channel }),
        })
    }

    /// `amqp_basic_deliver` (sync) and `amqp_deliver_to_consumer` (async) share this body.
    fn execute_deliver(&self, action: Value, action_name: &str) -> Result<ActionResult> {
        let consumer_tag = Self::require_str(
            &action,
            "consumer_tag",
            "Name the consumer that should receive this message. Consumers currently \
             attached are listed in the event's active_consumers, or use list_amqp_consumers.",
        )?;

        let server_id = self.require_server_id(&action)?;

        let handle = lookup_consumer(server_id, consumer_tag).ok_or_else(|| {
            anyhow::anyhow!(
                "No consumer '{}' is attached to AMQP server {}. Attached consumers: {}",
                consumer_tag,
                server_id,
                serde_json::to_string(&list_consumers(ServerId::new(server_id)))
                    .unwrap_or_else(|_| "[]".into())
            )
        })?;

        let body = action.get("body").and_then(|v| v.as_str()).unwrap_or("");
        let exchange = action
            .get("exchange")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let routing_key = action
            .get("routing_key")
            .and_then(|v| v.as_str())
            .unwrap_or(handle.queue.as_str());
        let redelivered = action
            .get("redelivered")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let delivery_tag = match action.get("delivery_tag").and_then(|v| v.as_u64()) {
            Some(tag) => tag,
            None => handle.next_delivery_tag.fetch_add(1, Ordering::SeqCst),
        };

        let properties = BasicProperties {
            content_type: action
                .get("content_type")
                .and_then(|v| v.as_str())
                .map(str::to_string),
            headers: action.get("headers").filter(|v| v.is_object()).cloned(),
            correlation_id: action
                .get("correlation_id")
                .and_then(|v| v.as_str())
                .map(str::to_string),
            reply_to: action
                .get("reply_to")
                .and_then(|v| v.as_str())
                .map(str::to_string),
            ..Default::default()
        };

        let mut args = Encoder::new();
        args.short_string(consumer_tag)?;
        args.u64(delivery_tag);
        args.bits(&[redelivered]);
        args.short_string(exchange)?;
        args.short_string(routing_key)?;

        let mut frames = vec![method_frame(
            handle.channel,
            CLASS_BASIC,
            BASIC_DELIVER,
            args.as_slice(),
        )];
        frames.push(content_header_frame(
            handle.channel,
            CLASS_BASIC,
            body.len() as u64,
            &properties.encode()?,
        ));
        frames.extend(body_frames(
            handle.channel,
            body.as_bytes(),
            handle.frame_max as usize,
        ));

        // A delivery is several frames that must not be interleaved with anything else on
        // that socket; the target's writer channel is a single consumer, so queueing them
        // back to back here is enough.
        for frame in frames {
            if handle.tx.send(frame).is_err() {
                warn!(
                    "AMQP consumer '{}' disconnected while a delivery was being written",
                    consumer_tag
                );
                // The handle we are holding *is* the owner, so cancel it as that owner
                // rather than going through the tag alone.
                unregister_consumer(
                    ServerId::new(server_id),
                    ConnectionId::new(handle.connection_id),
                    consumer_tag,
                );
                return Err(anyhow::anyhow!(
                    "Consumer '{}' disconnected before the delivery could be written",
                    consumer_tag
                ));
            }
        }
        self.written.fetch_or(RESP_DELIVER, Ordering::SeqCst);

        self.log(format!(
            "AMQP -> basic.deliver to '{}' routing_key='{}' delivery_tag={} ({} bytes)",
            consumer_tag,
            routing_key,
            delivery_tag,
            body.len()
        ));

        Ok(ActionResult::Custom {
            name: action_name.to_string(),
            data: json!({
                "consumer_tag": consumer_tag,
                "delivery_tag": delivery_tag,
                "exchange": exchange,
                "routing_key": routing_key,
                "body_size": body.len(),
            }),
        })
    }

    fn execute_return(&self, action: Value) -> Result<ActionResult> {
        let channel = self.channel_of(&action);
        let reply_code = action
            .get("reply_code")
            .and_then(|v| v.as_u64())
            .unwrap_or(312);
        if !(200..=999).contains(&reply_code) {
            return Err(anyhow::anyhow!(
                "reply_code {} is not an AMQP reply code (312 NO_ROUTE, 313 NO_CONSUMERS, 403 ACCESS_REFUSED)",
                reply_code
            ));
        }
        let reply_text = Self::require_str(
            &action,
            "reply_text",
            "Say why the message is being returned, e.g. 'NO_ROUTE'.",
        )?;
        let routing_key = Self::require_str(
            &action,
            "routing_key",
            "Copy routing_key from the amqp_basic_publish event so the publisher can match \
             the return to the message it sent.",
        )?;
        let exchange = action
            .get("exchange")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let body = action.get("body").and_then(|v| v.as_str()).unwrap_or("");

        let mut args = Encoder::new();
        args.u16(reply_code as u16);
        args.reply_text(reply_text);
        args.short_string(exchange)?;
        args.short_string(routing_key)?;

        let properties = BasicProperties {
            content_type: action
                .get("content_type")
                .and_then(|v| v.as_str())
                .map(str::to_string),
            ..Default::default()
        };

        self.send(
            RESP_RETURN,
            method_frame(channel, CLASS_BASIC, BASIC_RETURN, args.as_slice()),
        )?;
        self.send(
            RESP_RETURN,
            content_header_frame(
                channel,
                CLASS_BASIC,
                body.len() as u64,
                &properties.encode()?,
            ),
        )?;
        for frame in body_frames(
            channel,
            body.as_bytes(),
            self.frame_max.load(Ordering::SeqCst) as usize,
        ) {
            self.send(RESP_RETURN, frame)?;
        }

        self.log(format!(
            "AMQP -> basic.return {} {} routing_key='{}'",
            reply_code, reply_text, routing_key
        ));
        Ok(ActionResult::Custom {
            name: "amqp_basic_return".to_string(),
            data: json!({
                "reply_code": reply_code,
                "reply_text": reply_text,
                "exchange": exchange,
                "routing_key": routing_key,
            }),
        })
    }

    fn execute_list_consumers(&self, action: Value) -> Result<ActionResult> {
        let server_id = self.require_server_id(&action)?;
        Ok(ActionResult::Custom {
            name: "list_amqp_consumers".to_string(),
            data: json!({
                "server_id": server_id,
                "consumers": list_consumers(ServerId::new(server_id)),
            }),
        })
    }
}

// ============================================================================
// Protocol trait
// ============================================================================

impl Protocol for AmqpProtocol {
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "frame_max".to_string(),
                type_hint: "integer".to_string(),
                description: "Largest AMQP frame the broker offers in Connection.Tune, in bytes \
                              (default 131072, clamped to 4096..=1048576). A client may negotiate \
                              it down but never up."
                    .to_string(),
                required: false,
                example: json!(131072),
                default: Some(serde_json::json!(super::DEFAULT_FRAME_MAX)),
            },
            ParameterDefinition {
                name: "heartbeat_secs".to_string(),
                type_hint: "integer".to_string(),
                description: "Heartbeat interval offered in Connection.Tune, in seconds (default \
                              60). 0 disables heartbeats. A client that sends nothing for two \
                              intervals is disconnected."
                    .to_string(),
                required: false,
                example: json!(60),
                default: Some(serde_json::json!(super::DEFAULT_HEARTBEAT)),
            },
        ]
    }

    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![
            amqp_deliver_to_consumer_action(),
            list_amqp_consumers_action(),
        ]
    }

    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            amqp_connection_open_ok_action(),
            amqp_connection_close_action(),
            amqp_queue_declare_ok_action(),
            amqp_basic_consume_ok_action(),
            amqp_basic_deliver_action(),
            amqp_basic_return_action(),
            amqp_channel_close_action(),
        ]
    }

    fn protocol_name(&self) -> &'static str {
        "AMQP"
    }

    fn get_event_types(&self) -> Vec<EventType> {
        get_amqp_event_types()
    }

    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>AMQP"
    }

    fn keywords(&self) -> Vec<&'static str> {
        // NOTE: deliberately does NOT claim the bare word "queue" — it overlapped with
        // SQS's keyword and made "queue" resolve nondeterministically (HashMap order)
        // between AMQP and SQS. AMQP is selected by its own distinctive names.
        vec!["amqp", "rabbitmq", "broker", "messaging"]
    }

    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            // Beta: exercised against a real, independent client — lapin —
            // covering publish/consume round-trip, refusal, and an unimplemented method closing the channel. Not Stable: Stable additionally wants spec
            // compliance and scripting support reviewed, which has not been done here.
            .state(DevelopmentState::Beta)
            .well_known_port(5672)
            .implementation(
                "Hand-written AMQP 0-9-1 frame and method codec (lapin is a client library and \
                 is not used by the broker)",
            )
            .llm_control(
                "Whether a connection is accepted, what Queue.Declare reports, whether a \
                 consumer is registered, and every Basic.Deliver a consumer receives",
            )
            .e2e_testing(
                "lapin: full handshake, channel open, queue declare, publish and consume with \
                 the delivered body asserted",
            )
            .notes(
                "Implements only this subset, verified against lapin: the 0-9-1 protocol header, \
                 Connection.Start/Start-Ok, Tune/Tune-Ok, Open/Open-Ok, Close/Close-Ok, \
                 Channel.Open/Open-Ok and Close/Close-Ok, Exchange.Declare, Queue.Declare and \
                 Queue.Bind, Basic.Qos, Basic.Consume/Consume-Ok, Basic.Cancel/Cancel-Ok, \
                 Basic.Publish with its content header and body frames, Basic.Deliver, \
                 Basic.Return, and heartbeats in both directions. Only SASL PLAIN is offered, \
                 and the password is never surfaced. Any other method (Basic.Get, Queue.Purge, \
                 Queue.Delete, Queue.Unbind, Exchange.Delete/Bind, Confirm.Select, the Tx class) \
                 is answered with Channel.Close 540 NOT_IMPLEMENTED rather than being ignored. \
                 There is no TLS, no publisher confirms, no transactions and no prefetch \
                 enforcement (Basic.Qos is acknowledged and otherwise ignored). No queue, \
                 exchange, binding or message is stored: nothing is delivered automatically on \
                 publish, and every delivery comes from an amqp_basic_deliver action naming a \
                 live consumer. Basic.Ack, Basic.Nack and Basic.Reject are logged and otherwise \
                 ignored, since there is nothing to acknowledge or requeue. A connection whose \
                 amqp_connection_open handler produces no decision is refused with 403, so an \
                 LLM outage cannot silently open the broker.",
            )
            .max_inbound_bytes(crate::server::amqp::MAX_BODY_SIZE as usize)
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }

    fn description(&self) -> &'static str {
        "AMQP 0-9-1 broker (RabbitMQ wire protocol) with LLM-decided deliveries"
    }

    fn example_prompt(&self) -> &'static str {
        "Start an AMQP broker on port 5672 that accepts every client and delivers each \
         published message straight back to any consumer that is attached"
    }

    fn group_name(&self) -> &'static str {
        "Application"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;

        StartupExamples::new(
            // LLM mode
            json!({
                "type": "open_server",
                "port": 5672,
                "base_stack": "amqp",
                "instruction": "AMQP broker. Accept every connection with amqp_connection_open_ok. \
                                Answer queue.declare with amqp_queue_declare_ok reporting an empty \
                                queue. Accept every consumer with amqp_basic_consume_ok. When a \
                                message is published, forward it with amqp_basic_deliver to each \
                                consumer in active_consumers whose queue matches the routing key, \
                                copying the body verbatim."
            }),
            // Script mode: deterministic, no model call per method
            json!({
                "type": "open_server",
                "port": 5672,
                "base_stack": "amqp",
                "event_handlers": [
                    {
                        "event_pattern": "amqp_connection_open",
                        "handler": {
                            "type": "script",
                            "language": "python",
                            "code": "respond([{'type': 'amqp_connection_open_ok'}] if event['username'] == 'guest' else [{'type': 'amqp_connection_close', 'reply_code': 403, 'reply_text': 'ACCESS_REFUSED - unknown user'}])"
                        }
                    },
                    {
                        "event_pattern": "amqp_basic_publish",
                        "handler": {
                            "type": "script",
                            "language": "python",
                            "code": "respond([{'type': 'amqp_basic_deliver', 'consumer_tag': c['consumer_tag'], 'routing_key': event['routing_key'], 'body': event['body']} for c in event['active_consumers'] if c['queue'] == event['routing_key']])"
                        }
                    }
                ]
            }),
            // Static mode: {{event.*}} echoes the correlation identifiers
            json!({
                "type": "open_server",
                "port": 5672,
                "base_stack": "amqp",
                "event_handlers": [
                    {
                        "event_pattern": "amqp_connection_open",
                        "handler": {
                            "type": "static",
                            "actions": [{"type": "amqp_connection_open_ok"}]
                        }
                    },
                    {
                        "event_pattern": "amqp_queue_declare",
                        "handler": {
                            "type": "static",
                            "actions": [{"type": "amqp_queue_declare_ok", "queue": "{{event.queue}}", "message_count": 0, "consumer_count": 0}]
                        }
                    },
                    {
                        "event_pattern": "amqp_basic_consume",
                        "handler": {
                            "type": "static",
                            "actions": [{"type": "amqp_basic_consume_ok", "consumer_tag": "{{event.consumer_tag}}"}]
                        }
                    }
                ]
            }),
        )
    }
}

impl Server for AmqpProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            crate::server::amqp::AmqpServer::spawn_with_llm_actions(
                ctx.legacy_listen_addr(),
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.server_id,
                ctx.startup_params,
            )
            .await
        })
    }

    fn execute_action(&self, action: Value) -> Result<ActionResult> {
        let action_type = action
            .get("type")
            .and_then(|v| v.as_str())
            .context("Missing 'type' field in action")?
            .to_string();

        match action_type.as_str() {
            "amqp_connection_open_ok" => self.execute_connection_open_ok(),
            "amqp_connection_close" => self.execute_connection_close(action),
            "amqp_channel_close" => self.execute_channel_close(action),
            "amqp_queue_declare_ok" => self.execute_queue_declare_ok(action),
            "amqp_basic_consume_ok" => self.execute_consume_ok(action),
            "amqp_basic_deliver" => self.execute_deliver(action, "amqp_basic_deliver"),
            "amqp_deliver_to_consumer" => self.execute_deliver(action, "amqp_deliver_to_consumer"),
            "amqp_basic_return" => self.execute_return(action),
            "list_amqp_consumers" => self.execute_list_consumers(action),
            // Not offered to the model (a broker that wants to hang up sends
            // amqp_connection_close), but the dashboard's "disconnect this peer" injects it
            // through the peer command task, which half-closes the socket on this result.
            "close_connection" => Ok(ActionResult::CloseConnection),
            other => Err(anyhow::anyhow!(
                "Unknown AMQP action: {}. Valid actions: amqp_connection_open_ok, \
                 amqp_connection_close, amqp_channel_close, amqp_queue_declare_ok, \
                 amqp_basic_consume_ok, amqp_basic_deliver, amqp_basic_return, \
                 amqp_deliver_to_consumer, list_amqp_consumers",
                other
            )),
        }
    }
}

// ============================================================================
// Action definitions
// ============================================================================

pub fn amqp_connection_open_ok_action() -> ActionDefinition {
    ActionDefinition {
        name: "amqp_connection_open_ok".to_string(),
        description: "Accept a client connection. This is the broker's only authorisation \
                      decision: without it the connection is refused, so every client you want \
                      to serve needs exactly one of these."
            .to_string(),
        parameters: vec![],
        example: json!({"type": "amqp_connection_open_ok"}),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> AMQP connection accepted")
                .with_debug("AMQP amqp_connection_open_ok"),
        ),
    }
}

pub fn amqp_connection_close_action() -> ActionDefinition {
    ActionDefinition {
        name: "amqp_connection_close".to_string(),
        description: "Refuse or terminate a client connection. The client surfaces the code and \
                      text to its caller as the reason it could not connect."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "reply_code".to_string(),
                type_hint: "integer".to_string(),
                description: "AMQP reply code: 403 access refused (default), 530 not allowed, \
                              320 connection forced, 501 frame error, 540 not implemented."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "reply_text".to_string(),
                type_hint: "string".to_string(),
                description: "Why the connection is being closed, e.g. \
                              'ACCESS_REFUSED - login was refused for user guest'."
                    .to_string(),
                required: true,
            },
        ],
        example: json!({
            "type": "amqp_connection_close",
            "reply_code": 403,
            "reply_text": "ACCESS_REFUSED - unknown user"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> AMQP connection.close {reply_code}")
                .with_debug("AMQP amqp_connection_close: {reply_code} {reply_text}"),
        ),
    }
}

pub fn amqp_channel_close_action() -> ActionDefinition {
    ActionDefinition {
        name: "amqp_channel_close".to_string(),
        description: "Refuse an operation by closing the channel it arrived on. The connection \
                      stays up and the client can open a new channel; this is how AMQP reports \
                      a per-operation error such as a queue that does not exist."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "reply_code".to_string(),
                type_hint: "integer".to_string(),
                description: "AMQP reply code: 404 not found (default), 403 access refused, \
                              406 precondition failed, 405 resource locked."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "reply_text".to_string(),
                type_hint: "string".to_string(),
                description: "Why the operation was refused, e.g. \
                              \"NOT_FOUND - no queue 'orders'\"."
                    .to_string(),
                required: true,
            },
            Parameter {
                name: "channel".to_string(),
                type_hint: "integer".to_string(),
                description: "Channel to close. Defaults to the channel of the method being \
                              answered, which is what you almost always want."
                    .to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "amqp_channel_close",
            "reply_code": 404,
            "reply_text": "NOT_FOUND - no queue 'orders'"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> AMQP channel.close {reply_code}")
                .with_debug("AMQP amqp_channel_close: channel={channel} {reply_code} {reply_text}"),
        ),
    }
}

pub fn amqp_queue_declare_ok_action() -> ActionDefinition {
    ActionDefinition {
        name: "amqp_queue_declare_ok".to_string(),
        description: "Confirm a client's queue.declare. Required: the client blocks until it \
                      arrives. The broker stores no queues, so the counts you report are simply \
                      what the client is told."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "queue".to_string(),
                type_hint: "string".to_string(),
                description: "Queue name to confirm. Copy it from the amqp_queue_declare event; \
                              omit it to reuse the name the client asked for. When the client \
                              sent an empty name it expects you to invent one."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "message_count".to_string(),
                type_hint: "integer".to_string(),
                description: "How many messages to claim the queue holds (default 0).".to_string(),
                required: false,
            },
            Parameter {
                name: "consumer_count".to_string(),
                type_hint: "integer".to_string(),
                description: "How many consumers to claim the queue has (default 0).".to_string(),
                required: false,
            },
            Parameter {
                name: "channel".to_string(),
                type_hint: "integer".to_string(),
                description: "Channel to answer on. Defaults to the channel of the declare being \
                              answered."
                    .to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "amqp_queue_declare_ok",
            "queue": "orders",
            "message_count": 0,
            "consumer_count": 0
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> AMQP queue.declare-ok {queue}")
                .with_debug("AMQP amqp_queue_declare_ok: {queue} messages={message_count}"),
        ),
    }
}

pub fn amqp_basic_consume_ok_action() -> ActionDefinition {
    ActionDefinition {
        name: "amqp_basic_consume_ok".to_string(),
        description: "Accept a client's basic.consume and register it as a live consumer. \
                      Required: the client blocks until it arrives, and until it runs no \
                      amqp_basic_deliver can address this consumer."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "consumer_tag".to_string(),
                type_hint: "string".to_string(),
                description: "Copy consumer_tag from the amqp_basic_consume event verbatim. The \
                              client matches every later delivery to its consumer by this string."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "queue".to_string(),
                type_hint: "string".to_string(),
                description: "Queue this consumer is attached to, reported back in \
                              active_consumers on later publish events. Defaults to the queue \
                              from the event."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "channel".to_string(),
                type_hint: "integer".to_string(),
                description: "Channel to answer on. Defaults to the channel of the consume being \
                              answered."
                    .to_string(),
                required: false,
            },
        ],
        example: json!({"type": "amqp_basic_consume_ok", "consumer_tag": "ctag-1"}),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> AMQP basic.consume-ok {consumer_tag}")
                .with_debug("AMQP amqp_basic_consume_ok: {consumer_tag} queue={queue}"),
        ),
    }
}

/// Shared parameter list for the sync and async delivery actions.
fn delivery_parameters(include_server_id: bool) -> Vec<Parameter> {
    let mut params = Vec::new();
    if include_server_id {
        params.push(Parameter {
            name: "server_id".to_string(),
            type_hint: "integer".to_string(),
            description: "Id of the running AMQP server, as shown in the server list.".to_string(),
            required: true,
        });
    }
    params.extend([
        Parameter {
            name: "consumer_tag".to_string(),
            type_hint: "string".to_string(),
            description: "Which attached consumer receives the message. Take it from \
                          active_consumers in the publish event, or from list_amqp_consumers. \
                          Delivering to a tag that is not attached fails."
                .to_string(),
            required: true,
        },
        Parameter {
            name: "body".to_string(),
            type_hint: "string".to_string(),
            description: "Message body as text (JSON, plain text, anything); sent as UTF-8. \
                          Omit for an empty message."
                .to_string(),
            required: false,
        },
        Parameter {
            name: "routing_key".to_string(),
            type_hint: "string".to_string(),
            description: "Routing key the consumer sees on the delivery. Defaults to the queue \
                          the consumer subscribed to."
                .to_string(),
            required: false,
        },
        Parameter {
            name: "exchange".to_string(),
            type_hint: "string".to_string(),
            description: "Exchange name the consumer sees on the delivery. Empty string (the \
                          default) is the default exchange."
                .to_string(),
            required: false,
        },
        Parameter {
            name: "delivery_tag".to_string(),
            type_hint: "integer".to_string(),
            description: "Identifier the consumer will echo when it acknowledges. Omit and the \
                          broker allocates the next unused number for that consumer, which is \
                          normally what you want."
                .to_string(),
            required: false,
        },
        Parameter {
            name: "redelivered".to_string(),
            type_hint: "boolean".to_string(),
            description: "Mark the message as a redelivery (default false).".to_string(),
            required: false,
        },
        Parameter {
            name: "content_type".to_string(),
            type_hint: "string".to_string(),
            description: "MIME type of the body, e.g. 'application/json'.".to_string(),
            required: false,
        },
        Parameter {
            name: "headers".to_string(),
            type_hint: "object".to_string(),
            description: "Application headers as a flat JSON object of strings, numbers and \
                          booleans."
                .to_string(),
            required: false,
        },
        Parameter {
            name: "correlation_id".to_string(),
            type_hint: "string".to_string(),
            description: "Correlation id for request/reply patterns. Copy it from the publish \
                          event's properties when answering a request."
                .to_string(),
            required: false,
        },
        Parameter {
            name: "reply_to".to_string(),
            type_hint: "string".to_string(),
            description: "Queue name the consumer should send its reply to.".to_string(),
            required: false,
        },
    ]);
    params
}

pub fn amqp_basic_deliver_action() -> ActionDefinition {
    ActionDefinition {
        name: "amqp_basic_deliver".to_string(),
        description: "Send a message to an attached consumer. This is the only way a consumer \
                      ever receives anything: the broker keeps no queues and routes nothing by \
                      itself, so after a client publishes you deliver it yourself to each \
                      consumer that should get it."
            .to_string(),
        parameters: delivery_parameters(false),
        example: json!({
            "type": "amqp_basic_deliver",
            "consumer_tag": "ctag-1",
            "routing_key": "orders",
            "body": "{\"id\": 7}",
            "content_type": "application/json"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> AMQP basic.deliver to {consumer_tag}")
                .with_debug("AMQP amqp_basic_deliver: {consumer_tag} key={routing_key}"),
        ),
    }
}

pub fn amqp_deliver_to_consumer_action() -> ActionDefinition {
    ActionDefinition {
        name: "amqp_deliver_to_consumer".to_string(),
        description: "Push a message to an attached AMQP consumer outside of any client request, \
                      e.g. when the user asks to send something to a subscriber."
            .to_string(),
        parameters: delivery_parameters(true),
        example: json!({
            "type": "amqp_deliver_to_consumer",
            "server_id": 1,
            "consumer_tag": "ctag-1",
            "routing_key": "orders",
            "body": "hello"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> AMQP deliver to {consumer_tag}")
                .with_debug("AMQP amqp_deliver_to_consumer: server={server_id} {consumer_tag}"),
        ),
    }
}

pub fn amqp_basic_return_action() -> ActionDefinition {
    ActionDefinition {
        name: "amqp_basic_return".to_string(),
        description: "Hand a published message back to its publisher as undeliverable. Only \
                      meaningful when the publish event had mandatory set: a client that did not \
                      ask for mandatory delivery is not listening for returns."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "reply_code".to_string(),
                type_hint: "integer".to_string(),
                description: "312 NO_ROUTE (default), 313 NO_CONSUMERS, or 403 ACCESS_REFUSED."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "reply_text".to_string(),
                type_hint: "string".to_string(),
                description: "Why the message could not be delivered, e.g. 'NO_ROUTE'.".to_string(),
                required: true,
            },
            Parameter {
                name: "routing_key".to_string(),
                type_hint: "string".to_string(),
                description: "Copy routing_key from the amqp_basic_publish event so the \
                              publisher can tell which message came back."
                    .to_string(),
                required: true,
            },
            Parameter {
                name: "exchange".to_string(),
                type_hint: "string".to_string(),
                description: "Copy exchange from the publish event (empty string for the default \
                              exchange)."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "body".to_string(),
                type_hint: "string".to_string(),
                description: "Body to hand back, normally the body from the publish event."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "content_type".to_string(),
                type_hint: "string".to_string(),
                description: "MIME type of the returned body.".to_string(),
                required: false,
            },
            Parameter {
                name: "channel".to_string(),
                type_hint: "integer".to_string(),
                description: "Channel to answer on. Defaults to the channel the publish arrived \
                              on."
                .to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "amqp_basic_return",
            "reply_code": 312,
            "reply_text": "NO_ROUTE",
            "routing_key": "orders",
            "body": "{\"id\": 7}"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> AMQP basic.return {reply_code}")
                .with_debug("AMQP amqp_basic_return: {reply_code} key={routing_key}"),
        ),
    }
}

pub fn list_amqp_consumers_action() -> ActionDefinition {
    ActionDefinition {
        name: "list_amqp_consumers".to_string(),
        description: "List the consumers currently attached to an AMQP server, with the queue \
                      each one subscribed to."
            .to_string(),
        parameters: vec![Parameter {
            name: "server_id".to_string(),
            type_hint: "integer".to_string(),
            description: "Id of the running AMQP server, as shown in the server list.".to_string(),
            required: true,
        }],
        example: json!({"type": "list_amqp_consumers", "server_id": 1}),
        log_template: Some(
            LogTemplate::new()
                .with_info("AMQP list consumers")
                .with_debug("AMQP list_amqp_consumers: server={server_id}"),
        ),
    }
}

// ============================================================================
// Action constants
// ============================================================================

pub static AMQP_CONNECTION_OPEN_OK_ACTION: LazyLock<ActionDefinition> =
    LazyLock::new(amqp_connection_open_ok_action);
pub static AMQP_CONNECTION_CLOSE_ACTION: LazyLock<ActionDefinition> =
    LazyLock::new(amqp_connection_close_action);
pub static AMQP_CHANNEL_CLOSE_ACTION: LazyLock<ActionDefinition> =
    LazyLock::new(amqp_channel_close_action);
pub static AMQP_QUEUE_DECLARE_OK_ACTION: LazyLock<ActionDefinition> =
    LazyLock::new(amqp_queue_declare_ok_action);
pub static AMQP_BASIC_CONSUME_OK_ACTION: LazyLock<ActionDefinition> =
    LazyLock::new(amqp_basic_consume_ok_action);
pub static AMQP_BASIC_DELIVER_ACTION: LazyLock<ActionDefinition> =
    LazyLock::new(amqp_basic_deliver_action);
pub static AMQP_BASIC_RETURN_ACTION: LazyLock<ActionDefinition> =
    LazyLock::new(amqp_basic_return_action);

// ============================================================================
// Event types
// ============================================================================

/// The handshake finished and the client asked to open a virtual host. Nothing else can
/// happen on the connection until this is answered.
pub static AMQP_CONNECTION_OPEN_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "amqp_connection_open",
        "AMQP client finished the handshake and is waiting to be let in",
        json!({"type": "placeholder", "event_id": "amqp_connection_open"}),
    )
    .with_parameters(vec![
        Parameter {
            name: "virtual_host".to_string(),
            type_hint: "string".to_string(),
            description: "Virtual host the client asked for, normally '/'.".to_string(),
            required: true,
        },
        Parameter {
            name: "username".to_string(),
            type_hint: "string".to_string(),
            description: "Username from the SASL PLAIN exchange, or null if none was sent."
                .to_string(),
            required: false,
        },
        Parameter {
            name: "has_password".to_string(),
            type_hint: "boolean".to_string(),
            description: "Whether a password was supplied. The password itself is never surfaced."
                .to_string(),
            required: true,
        },
        Parameter {
            name: "mechanism".to_string(),
            type_hint: "string".to_string(),
            description: "SASL mechanism the client chose. Only PLAIN is offered.".to_string(),
            required: true,
        },
        Parameter {
            name: "locale".to_string(),
            type_hint: "string".to_string(),
            description: "Locale the client selected, normally 'en_US'.".to_string(),
            required: true,
        },
        Parameter {
            name: "client_properties".to_string(),
            type_hint: "object".to_string(),
            description: "The client's self-description: product, version, platform and the \
                          capabilities table it advertises."
                .to_string(),
            required: true,
        },
        Parameter {
            name: "peer_address".to_string(),
            type_hint: "string".to_string(),
            description: "Remote address and port of the client.".to_string(),
            required: true,
        },
        Parameter {
            name: "frame_max".to_string(),
            type_hint: "integer".to_string(),
            description: "Negotiated maximum frame size in bytes.".to_string(),
            required: true,
        },
        Parameter {
            name: "heartbeat_secs".to_string(),
            type_hint: "integer".to_string(),
            description: "Negotiated heartbeat interval in seconds; 0 means heartbeats are off."
                .to_string(),
            required: true,
        },
    ])
    .with_actions(vec![
        AMQP_CONNECTION_OPEN_OK_ACTION.clone(),
        AMQP_CONNECTION_CLOSE_ACTION.clone(),
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("AMQP connection.open vhost={virtual_host} user={username}")
            .with_debug(
                "AMQP connection.open: vhost={virtual_host} user={username} from {peer_address}",
            )
            .with_trace("AMQP connection.open: {json_pretty(.)}"),
    )
});

/// A client declared a queue and is waiting for Queue.Declare-Ok.
pub static AMQP_QUEUE_DECLARE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "amqp_queue_declare",
        "AMQP client declared a queue and is waiting for queue.declare-ok",
        json!({"type": "placeholder", "event_id": "amqp_queue_declare"}),
    )
    .with_parameters(vec![
        Parameter {
            name: "channel".to_string(),
            type_hint: "integer".to_string(),
            description: "Channel the declare arrived on; the reply must go back on the same one \
                          (which is the default)."
                .to_string(),
            required: true,
        },
        Parameter {
            name: "queue".to_string(),
            type_hint: "string".to_string(),
            description: "Queue name the client asked for. An empty string means the client \
                          wants the broker to invent a name."
                .to_string(),
            required: true,
        },
        Parameter {
            name: "passive".to_string(),
            type_hint: "boolean".to_string(),
            description: "The client is only checking whether the queue exists and expects a \
                          channel error with 404 if it does not."
                .to_string(),
            required: true,
        },
        Parameter {
            name: "durable".to_string(),
            type_hint: "boolean".to_string(),
            description: "Client asked for a queue that survives a broker restart.".to_string(),
            required: true,
        },
        Parameter {
            name: "exclusive".to_string(),
            type_hint: "boolean".to_string(),
            description: "Client asked for a queue only this connection may use.".to_string(),
            required: true,
        },
        Parameter {
            name: "auto_delete".to_string(),
            type_hint: "boolean".to_string(),
            description: "Client asked for a queue that disappears with its last consumer."
                .to_string(),
            required: true,
        },
        Parameter {
            name: "arguments".to_string(),
            type_hint: "object".to_string(),
            description: "Extra declaration arguments such as x-message-ttl, as a JSON object."
                .to_string(),
            required: true,
        },
    ])
    .with_actions(vec![
        AMQP_QUEUE_DECLARE_OK_ACTION.clone(),
        AMQP_CHANNEL_CLOSE_ACTION.clone(),
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("AMQP queue.declare {queue}")
            .with_debug("AMQP queue.declare: {queue} durable={durable} channel={channel}")
            .with_trace("AMQP queue.declare: {json_pretty(.)}"),
    )
});

/// A client asked to consume from a queue and is waiting for Basic.Consume-Ok.
pub static AMQP_BASIC_CONSUME_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "amqp_basic_consume",
        "AMQP client asked to consume from a queue and is waiting for basic.consume-ok",
        json!({"type": "placeholder", "event_id": "amqp_basic_consume"}),
    )
    .with_parameters(vec![
        Parameter {
            name: "channel".to_string(),
            type_hint: "integer".to_string(),
            description: "Channel the consume arrived on.".to_string(),
            required: true,
        },
        Parameter {
            name: "queue".to_string(),
            type_hint: "string".to_string(),
            description: "Queue the client wants to consume from.".to_string(),
            required: true,
        },
        Parameter {
            name: "consumer_tag".to_string(),
            type_hint: "string".to_string(),
            description: "Tag identifying this consumer. When the client sent an empty tag the \
                          broker has already generated one, and this is it — echo it verbatim in \
                          amqp_basic_consume_ok and in every later amqp_basic_deliver."
                .to_string(),
            required: true,
        },
        Parameter {
            name: "no_local".to_string(),
            type_hint: "boolean".to_string(),
            description: "Client does not want messages it published itself.".to_string(),
            required: true,
        },
        Parameter {
            name: "no_ack".to_string(),
            type_hint: "boolean".to_string(),
            description: "Client will not acknowledge deliveries. The broker ignores \
                          acknowledgements either way."
                .to_string(),
            required: true,
        },
        Parameter {
            name: "exclusive".to_string(),
            type_hint: "boolean".to_string(),
            description: "Client asked to be the queue's only consumer.".to_string(),
            required: true,
        },
        Parameter {
            name: "arguments".to_string(),
            type_hint: "object".to_string(),
            description: "Extra consume arguments, as a JSON object.".to_string(),
            required: true,
        },
    ])
    .with_actions(vec![
        AMQP_BASIC_CONSUME_OK_ACTION.clone(),
        AMQP_BASIC_DELIVER_ACTION.clone(),
        AMQP_CHANNEL_CLOSE_ACTION.clone(),
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("AMQP basic.consume {consumer_tag} on {queue}")
            .with_debug("AMQP basic.consume: tag={consumer_tag} queue={queue} no_ack={no_ack}")
            .with_trace("AMQP basic.consume: {json_pretty(.)}"),
    )
});

/// A client published a message and its content has fully arrived.
pub static AMQP_BASIC_PUBLISH_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "amqp_basic_publish",
        "AMQP client published a message",
        json!({"type": "placeholder", "event_id": "amqp_basic_publish"}),
    )
    .with_parameters(vec![
        Parameter {
            name: "channel".to_string(),
            type_hint: "integer".to_string(),
            description: "Channel the publish arrived on.".to_string(),
            required: true,
        },
        Parameter {
            name: "exchange".to_string(),
            type_hint: "string".to_string(),
            description: "Exchange the message was published to. An empty string is the default \
                          exchange, where the routing key is the queue name."
                .to_string(),
            required: true,
        },
        Parameter {
            name: "routing_key".to_string(),
            type_hint: "string".to_string(),
            description: "Routing key of the message. On the default exchange this is the target \
                          queue name."
                .to_string(),
            required: true,
        },
        Parameter {
            name: "mandatory".to_string(),
            type_hint: "boolean".to_string(),
            description: "The publisher wants the message handed back with amqp_basic_return if \
                          it cannot be delivered."
                .to_string(),
            required: true,
        },
        Parameter {
            name: "immediate".to_string(),
            type_hint: "boolean".to_string(),
            description: "The publisher wants the message dropped if no consumer can take it now."
                .to_string(),
            required: true,
        },
        Parameter {
            name: "body".to_string(),
            type_hint: "string".to_string(),
            description: "Message body decoded as UTF-8 text.".to_string(),
            required: true,
        },
        Parameter {
            name: "body_is_text".to_string(),
            type_hint: "boolean".to_string(),
            description: "False when the body was not valid UTF-8; body then holds a lossy \
                          rendering and body_size gives the true byte count."
                .to_string(),
            required: true,
        },
        Parameter {
            name: "body_size".to_string(),
            type_hint: "integer".to_string(),
            description: "Body length in bytes as received.".to_string(),
            required: true,
        },
        Parameter {
            name: "properties".to_string(),
            type_hint: "object".to_string(),
            description: "Message properties the publisher set: content_type, headers, \
                          correlation_id, reply_to, delivery_mode and so on. Only the ones \
                          actually set are present."
                .to_string(),
            required: true,
        },
        Parameter {
            name: "active_consumers".to_string(),
            type_hint: "array".to_string(),
            description: "Consumers currently attached to this server, as \
                          [{\"consumer_tag\": \"...\", \"queue\": \"...\"}]. Nothing is routed \
                          automatically: use these tags with amqp_basic_deliver to hand the \
                          message on."
                .to_string(),
            required: true,
        },
    ])
    .with_actions(vec![
        AMQP_BASIC_DELIVER_ACTION.clone(),
        AMQP_BASIC_RETURN_ACTION.clone(),
        AMQP_CHANNEL_CLOSE_ACTION.clone(),
        AMQP_CONNECTION_CLOSE_ACTION.clone(),
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("AMQP basic.publish exchange={exchange} key={routing_key}")
            .with_debug("AMQP basic.publish: key={routing_key} {body_size} bytes")
            .with_trace("AMQP basic.publish: {json_pretty(.)}"),
    )
});

pub fn get_amqp_event_types() -> Vec<EventType> {
    vec![
        AMQP_CONNECTION_OPEN_EVENT.clone(),
        AMQP_QUEUE_DECLARE_EVENT.clone(),
        AMQP_BASIC_CONSUME_EVENT.clone(),
        AMQP_BASIC_PUBLISH_EVENT.clone(),
    ]
}
