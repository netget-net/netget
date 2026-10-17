//! MQTT protocol actions, events and metadata
//!
//! Every action declared here is executed by [`MqttProtocol::execute_action`] and
//! every declared field is read. Sync actions write directly to the connection they
//! were produced for, so ordering with the read loop is preserved by the connection's
//! single writer channel.

use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter, ParameterDefinition,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::EventType;
use crate::server::connection::ConnectionId;
use crate::server::mqtt::v5::{self, PropertyWriter};
use crate::server::mqtt::{
    build_ack, build_ack_v5, build_connack, build_connack_v5, build_disconnect_v5, build_suback,
    build_suback_v5, build_unsuback_v5, OutPublish, PKT_CONNACK, PKT_PUBACK, PKT_PUBLISH,
    PKT_PUBREC, PKT_SUBACK, PKT_UNSUBACK,
};
use crate::state::app_state::AppState;
use crate::state::ServerId;
use anyhow::{Context, Result};
use serde_json::json;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{LazyLock, Mutex, RwLock};
use tokio::sync::mpsc;
use tracing::{debug, warn};

// ============================================================================
// Live connection directory
// ============================================================================

/// Senders for the currently connected MQTT clients, keyed by `(server id, client id)`, each
/// with whether that client speaks v5 — a PUBLISH is framed per recipient.
///
/// This is a directory of *live sockets*, not storage: nothing is retained after a
/// client disconnects, and no message, subscription, topic or retained value is ever
/// held here. It exists so the model can name a recipient for `mqtt_publish`.
type Directory = HashMap<(u32, String), (mpsc::UnboundedSender<Vec<u8>>, bool)>;
static MQTT_CLIENTS: LazyLock<Mutex<Directory>> = LazyLock::new(|| Mutex::new(HashMap::new()));

/// Record a connected client's writer so actions can address it by client id.
pub fn register_client(
    server_id: ServerId,
    client_id: &str,
    tx: mpsc::UnboundedSender<Vec<u8>>,
    v5: bool,
) {
    if let Ok(mut map) = MQTT_CLIENTS.lock() {
        map.insert((server_id.as_u32(), client_id.to_string()), (tx, v5));
    }
}

/// Drop a client from the directory when its connection ends.
pub fn unregister_client(server_id: ServerId, client_id: &str) {
    if let Ok(mut map) = MQTT_CLIENTS.lock() {
        map.remove(&(server_id.as_u32(), client_id.to_string()));
    }
}

/// Client ids currently connected to one server, sorted.
pub fn list_clients(server_id: ServerId) -> Vec<String> {
    let Ok(map) = MQTT_CLIENTS.lock() else {
        return Vec::new();
    };
    let mut ids: Vec<String> = map
        .keys()
        .filter(|(sid, _)| *sid == server_id.as_u32())
        .map(|(_, cid)| cid.clone())
        .collect();
    ids.sort();
    ids
}

/// Deliver a PUBLISH to one client id, or to every client on the server when `client_id` is
/// `"*"`, framed for each recipient's version. Returns `(client id, is v5)` for each client
/// actually written to.
fn deliver(server_id: u32, client_id: &str, message: &OutPublish) -> Vec<(String, bool)> {
    let Ok(map) = MQTT_CLIENTS.lock() else {
        return Vec::new();
    };
    let mut delivered = Vec::new();
    for ((sid, cid), (tx, v5)) in map.iter() {
        if *sid != server_id {
            continue;
        }
        if client_id != "*" && cid != client_id {
            continue;
        }
        if tx.send(message.encode(*v5)).is_ok() {
            delivered.push((cid.clone(), *v5));
        }
    }
    delivered.sort();
    delivered
}

// ============================================================================
// Protocol
// ============================================================================

/// MQTT protocol action handler.
///
/// Two shapes: the registry-wide instance built by [`MqttProtocol::new`] (used for
/// documentation, spawning and user-triggered async actions), and a per-connection
/// instance built by [`MqttProtocol::for_connection`] that owns the writer for one
/// client and therefore can execute the sync response actions.
pub struct MqttProtocol {
    server_id: Option<ServerId>,
    #[allow(dead_code)]
    connection_id: Option<ConnectionId>,
    out_tx: Option<mpsc::UnboundedSender<Vec<u8>>>,
    status_tx: Option<mpsc::UnboundedSender<String>>,
    client_id: RwLock<Option<String>>,
    /// Bitmask of MQTT packet types written to *this* connection, used by the
    /// connection loop to tell whether the handler produced the mandatory reply.
    written_types: AtomicU32,
    /// Whether this connection has had its CONNACK. Unlike `written_types` it is never
    /// cleared: a connection gets exactly one (MQTT 3.1.1 3.2), and a second is a protocol
    /// violation libmosquitto answers by dropping the connection.
    connack_sent: AtomicBool,
    /// The CONNACK this connection got refused it, so the broker closes after it.
    connack_refused: AtomicBool,
    /// The client connected with protocol level 5: acknowledgements carry reason codes and
    /// properties.
    v5: AtomicBool,
    /// Properties every accepting v5 CONNACK carries (assigned client id, maximum packet size,
    /// topic alias maximum), set by the connection loop before the handler runs.
    connack_properties: Mutex<PropertyWriter>,
    /// Filter count of each UNSUBSCRIBE awaiting its UNSUBACK, by packet id: a v5 UNSUBACK
    /// carries one reason code per filter.
    pending_unsubscribes: Mutex<HashMap<u16, usize>>,
}

impl Default for MqttProtocol {
    fn default() -> Self {
        Self::new()
    }
}

impl MqttProtocol {
    /// Registry-wide instance: no connection, so only async actions can execute.
    pub fn new() -> Self {
        Self {
            server_id: None,
            connection_id: None,
            out_tx: None,
            status_tx: None,
            client_id: RwLock::new(None),
            written_types: AtomicU32::new(0),
            connack_sent: AtomicBool::new(false),
            connack_refused: AtomicBool::new(false),
            v5: AtomicBool::new(false),
            connack_properties: Mutex::new(PropertyWriter::new()),
            pending_unsubscribes: Mutex::new(HashMap::new()),
        }
    }

    /// Instance bound to one client connection.
    pub fn for_connection(
        server_id: ServerId,
        connection_id: ConnectionId,
        out_tx: mpsc::UnboundedSender<Vec<u8>>,
        status_tx: mpsc::UnboundedSender<String>,
    ) -> Self {
        Self {
            server_id: Some(server_id),
            connection_id: Some(connection_id),
            out_tx: Some(out_tx),
            status_tx: Some(status_tx),
            client_id: RwLock::new(None),
            written_types: AtomicU32::new(0),
            connack_sent: AtomicBool::new(false),
            connack_refused: AtomicBool::new(false),
            v5: AtomicBool::new(false),
            connack_properties: Mutex::new(PropertyWriter::new()),
            pending_unsubscribes: Mutex::new(HashMap::new()),
        }
    }

    pub fn set_v5(&self, v5: bool) {
        self.v5.store(v5, Ordering::SeqCst);
    }

    pub fn is_v5(&self) -> bool {
        self.v5.load(Ordering::SeqCst)
    }

    pub fn set_connack_properties(&self, props: PropertyWriter) {
        if let Ok(mut guard) = self.connack_properties.lock() {
            *guard = props;
        }
    }

    pub fn connack_properties(&self) -> PropertyWriter {
        self.connack_properties
            .lock()
            .map(|g| g.clone())
            .unwrap_or_default()
    }

    /// True once this connection was sent a refusing CONNACK.
    pub fn connack_refused(&self) -> bool {
        self.connack_refused.load(Ordering::SeqCst)
    }

    pub fn note_unsubscribe(&self, packet_id: u16, filters: usize) {
        if let Ok(mut map) = self.pending_unsubscribes.lock() {
            // Bounded: one entry per packet id in flight, and a client reusing an id replaces
            // its own entry.
            map.insert(packet_id, filters);
        }
    }

    pub fn set_client_id(&self, client_id: &str) {
        if let Ok(mut guard) = self.client_id.write() {
            *guard = Some(client_id.to_string());
        }
    }

    fn current_client_id(&self) -> Option<String> {
        self.client_id.read().ok().and_then(|g| g.clone())
    }

    /// True if a packet of `packet_type` has been written to this connection since
    /// the last [`MqttProtocol::clear_written_types`].
    pub fn wrote_packet_type(&self, packet_type: u8) -> bool {
        self.written_types.load(Ordering::SeqCst) & (1u32 << (packet_type & 0x1F)) != 0
    }

    pub fn clear_written_types(&self) {
        self.written_types.store(0, Ordering::SeqCst);
    }

    /// Write a packet to this connection and record its type.
    fn send_to_connection(&self, packet_type: u8, bytes: Vec<u8>) -> Result<()> {
        let tx = self.out_tx.as_ref().context(
            "This MQTT action can only run in response to a client packet (no connection bound)",
        )?;
        tx.send(bytes)
            .map_err(|_| anyhow::anyhow!("MQTT connection is already closed"))?;
        self.written_types
            .fetch_or(1u32 << (packet_type & 0x1F), Ordering::SeqCst);
        Ok(())
    }

    fn log(&self, message: String) {
        debug!("{}", message);
        if let Some(tx) = &self.status_tx {
            let _ = tx.send(format!("[DEBUG] {}", message));
        }
    }

    fn require_packet_id(action: &serde_json::Value) -> Result<u16> {
        let id = action
            .get("packet_id")
            .and_then(|v| v.as_u64())
            .context("Missing 'packet_id'. Echo the packet_id from the triggering event so the client can match the acknowledgement to its request")?;
        if id > u16::MAX as u64 {
            return Err(anyhow::anyhow!(
                "packet_id {} is out of range (0-65535)",
                id
            ));
        }
        Ok(id as u16)
    }

    /// The broker this action addresses: our own id when the executor is bound to one,
    /// otherwise the model's `server_id`.
    ///
    /// The `None` arm used to end in `as u32`, which wraps in silence — `4294967297` becomes
    /// `1`, so an action naming a broker that does not exist is delivered to whichever broker
    /// happens to be number 1 rather than failing.
    fn require_server_id(&self, action: &serde_json::Value) -> Result<u32> {
        if let Some(id) = self.server_id {
            return Ok(id.as_u32());
        }
        let raw = action.get("server_id").and_then(|v| v.as_u64()).context(
            "Missing 'server_id' (the id of the running MQTT server, from the server list)",
        )?;
        u32::try_from(raw).map_err(|_| {
            anyhow::anyhow!(
                "server_id {raw} is not a NetGet server id (0-4294967295); take it from the \
                 server list rather than inventing one"
            )
        })
    }

    // ---- executors -------------------------------------------------------

    /// The Reason String and User Properties any v5 acknowledgement may carry.
    fn ack_properties(action: &serde_json::Value) -> Result<PropertyWriter> {
        let mut props = PropertyWriter::new();
        if let Some(text) = action.get("reason_string").and_then(|v| v.as_str()) {
            if text.len() > usize::from(u16::MAX) {
                return Err(anyhow::anyhow!("reason_string is longer than 65535 bytes"));
            }
            props.text(v5::REASON_STRING, text);
        }
        for (k, v) in v5::user_properties_from_json(action.get("user_properties"))
            .map_err(|e| anyhow::anyhow!(e))?
        {
            props.pair(&k, &v);
        }
        Ok(props)
    }

    /// An optional `reason_code` checked against one of the v5 tables.
    fn reason_code(
        action: &serde_json::Value,
        key: &str,
        table: &[(u8, &str)],
        packet: &str,
    ) -> Result<Option<u8>> {
        match action.get(key) {
            None | Some(serde_json::Value::Null) => Ok(None),
            Some(v) => {
                let code = v
                    .as_u64()
                    .with_context(|| format!("'{key}' must be an integer reason code"))?;
                v5::check_reason(code, table, packet)
                    .map(Some)
                    .map_err(|e| anyhow::anyhow!(e))
            }
        }
    }

    fn execute_connack(&self, action: serde_json::Value) -> Result<ActionResult> {
        // Either vocabulary answers either version: a 3.1.1 return code (0-5) or a v5 reason
        // code. Each is translated to the other's nearest equivalent, and a refusal always
        // stays a refusal.
        let v5_code =
            Self::reason_code(&action, "reason_code", v5::CONNACK_REASON_CODES, "CONNACK")?;
        let (v311, v5_reason) = match v5_code {
            Some(code) => (v5::connack_v5_to_v311(code), code),
            None => {
                // No default: a CONNACK is an admission decision, and a missing field must not
                // read as "accepted".
                let return_code = action
                    .get("return_code")
                    .and_then(|v| v.as_u64())
                    .context(
                        "Missing 'return_code' (0 accepts; 1-5 refuse) or, for an MQTT 5                          client, 'reason_code'",
                    )?;
                if return_code > 5 {
                    return Err(anyhow::anyhow!(
                        "return_code {} is not an MQTT 3.1.1 CONNACK code (0=accepted, 1=bad protocol version, 2=client id rejected, 3=server unavailable, 4=bad username/password, 5=not authorized). For an MQTT 5 reason code use reason_code instead",
                        return_code
                    ));
                }
                (return_code as u8, v5::connack_v311_to_v5(return_code as u8))
            }
        };
        let session_present = action
            .get("session_present")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let mut props = Self::ack_properties(&action)?;

        // A connection gets one CONNACK. A model answered one CONNECT with two, and the
        // subscriber dropped the connection as a protocol error before it could subscribe.
        if self.out_tx.is_some() && self.connack_sent.load(Ordering::SeqCst) {
            let message = format!(
                "MQTT decision=duplicate_response_dropped: a second CONNACK for '{}' was not \
                 sent; a connection gets exactly one",
                self.current_client_id().unwrap_or_else(|| "?".into())
            );
            warn!("{}", message);
            if let Some(tx) = &self.status_tx {
                let _ = tx.send(format!("[WARN] {}", message));
            }
            return Ok(ActionResult::NoAction);
        }

        let v5 = self.is_v5();
        // §3.2.2.1.1: Session Present MUST be 0 on a refusal, in both versions.
        let session_present = session_present && v311 == 0;
        self.log(format!(
            "MQTT -> CONNACK {} session_present={} to '{}'",
            if v5 {
                format!(
                    "reason=0x{v5_reason:02x} ({})",
                    v5::reason_name(v5_reason, v5::CONNACK_REASON_CODES)
                )
            } else {
                format!("rc={v311}")
            },
            session_present,
            self.current_client_id().unwrap_or_else(|| "?".into())
        ));

        let bytes = if v5 {
            if v5_reason == 0 {
                // The broker's own properties first, then whatever the handler added.
                let mut all = self.connack_properties();
                all.append(&props);
                props = all;
            }
            build_connack_v5(v5_reason, session_present, &props)
        } else {
            build_connack(v311, session_present)
        };
        self.send_to_connection(PKT_CONNACK, bytes)?;
        self.connack_sent.store(true, Ordering::SeqCst);
        if v311 != 0 {
            self.connack_refused.store(true, Ordering::SeqCst);
        }

        Ok(ActionResult::Custom {
            name: "mqtt_connack".to_string(),
            data: json!({
                "return_code": v311,
                "reason_code": v5_reason,
                "protocol_version": if v5 { "5.0" } else { "3.1.1" },
                "session_present": session_present
            }),
        })
    }

    /// PUBACK and PUBREC share everything but the packet type.
    fn execute_publish_ack(
        &self,
        action: serde_json::Value,
        packet_type: u8,
        name: &str,
    ) -> Result<ActionResult> {
        let packet_id = Self::require_packet_id(&action)?;
        let reason =
            Self::reason_code(&action, "reason_code", v5::PUBACK_REASON_CODES, name)?.unwrap_or(0);
        let label = if packet_type == PKT_PUBACK {
            "PUBACK"
        } else {
            "PUBREC"
        };
        let bytes = if self.is_v5() {
            build_ack_v5(
                packet_type,
                packet_id,
                reason,
                &Self::ack_properties(&action)?,
            )
        } else {
            // 3.1.1's acknowledgement is the identifier and nothing else, and it means "taken".
            // A failure code cannot be said, and sending the bare form instead would say the
            // opposite of what the handler meant.
            if reason >= 0x80 {
                return Err(anyhow::anyhow!(
                    "this client speaks MQTT 3.1.1, whose {label} has no reason code: \
                     reason_code {reason} cannot be sent. Acknowledge without it, or refuse \
                     the message with close_this_connection"
                ));
            }
            build_ack(packet_type, packet_id)
        };
        self.log(format!(
            "MQTT -> {label} id={packet_id} reason=0x{reason:02x}"
        ));
        self.send_to_connection(packet_type, bytes)?;
        Ok(ActionResult::Custom {
            name: name.to_string(),
            data: json!({ "packet_id": packet_id, "reason_code": reason }),
        })
    }

    fn execute_puback(&self, action: serde_json::Value) -> Result<ActionResult> {
        self.execute_publish_ack(action, PKT_PUBACK, "mqtt_puback")
    }

    fn execute_pubrec(&self, action: serde_json::Value) -> Result<ActionResult> {
        self.execute_publish_ack(action, PKT_PUBREC, "mqtt_pubrec")
    }

    fn execute_suback(&self, action: serde_json::Value) -> Result<ActionResult> {
        let packet_id = Self::require_packet_id(&action)?;
        let granted = action
            .get("granted_qos")
            .and_then(|v| v.as_array())
            .context("Missing 'granted_qos'. Provide one entry per topic filter in the subscribe event: 0, 1 or 2 to grant that QoS, or 128 to refuse the subscription")?;

        let v5 = self.is_v5();
        let mut codes = Vec::with_capacity(granted.len());
        for value in granted {
            let code = value
                .as_u64()
                .context("granted_qos entries must be integers (0, 1, 2 or 128)")?;
            let code = v5::check_reason(code, v5::SUBACK_REASON_CODES, "SUBACK")
                .map_err(|e| anyhow::anyhow!("granted_qos entry: {e}"))?;
            // 3.1.1 has one failure code, 0x80; every v5 refusal is that refusal there.
            codes.push(if !v5 && code >= 0x80 { 0x80 } else { code });
        }
        if codes.is_empty() {
            return Err(anyhow::anyhow!(
                "granted_qos must contain one entry per requested topic filter"
            ));
        }

        self.log(format!(
            "MQTT -> SUBACK id={} granted={:?}",
            packet_id, codes
        ));
        let bytes = if v5 {
            build_suback_v5(packet_id, &codes, &Self::ack_properties(&action)?)
        } else {
            build_suback(packet_id, &codes)
        };
        self.send_to_connection(PKT_SUBACK, bytes)?;

        Ok(ActionResult::Custom {
            name: "mqtt_suback".to_string(),
            data: json!({ "packet_id": packet_id, "granted_qos": codes }),
        })
    }

    fn execute_unsuback(&self, action: serde_json::Value) -> Result<ActionResult> {
        let packet_id = Self::require_packet_id(&action)?;
        let pending = self
            .pending_unsubscribes
            .lock()
            .ok()
            .and_then(|mut m| m.remove(&packet_id));
        let codes: Vec<u8> = match action.get("reason_codes").and_then(|v| v.as_array()) {
            Some(list) => list
                .iter()
                .map(|v| {
                    let code = v
                        .as_u64()
                        .context("reason_codes entries must be integers")?;
                    v5::check_reason(code, v5::UNSUBACK_REASON_CODES, "UNSUBACK")
                        .map_err(|e| anyhow::anyhow!(e))
                })
                .collect::<Result<_>>()?,
            None => vec![0x00; pending.unwrap_or(1).max(1)],
        };
        if let Some(n) = pending {
            if codes.len() != n {
                return Err(anyhow::anyhow!(
                    "reason_codes has {} entries but the UNSUBSCRIBE named {} topic filter(s); \
                     give one per filter, in order",
                    codes.len(),
                    n
                ));
            }
        }
        let bytes = if self.is_v5() {
            build_unsuback_v5(packet_id, &codes, &Self::ack_properties(&action)?)
        } else {
            if codes.iter().any(|c| *c >= 0x80) {
                return Err(anyhow::anyhow!(
                    "this client speaks MQTT 3.1.1, whose UNSUBACK has no reason code and \
                     means the subscriptions were removed; a refusal cannot be sent. \
                     Acknowledge it, or use close_this_connection"
                ));
            }
            build_ack(PKT_UNSUBACK, packet_id)
        };
        self.log(format!(
            "MQTT -> UNSUBACK id={} codes={:?}",
            packet_id, codes
        ));
        self.send_to_connection(PKT_UNSUBACK, bytes)?;
        Ok(ActionResult::Custom {
            name: "mqtt_unsuback".to_string(),
            data: json!({ "packet_id": packet_id, "reason_codes": codes }),
        })
    }

    fn execute_close(&self, action: serde_json::Value) -> Result<ActionResult> {
        // v5 lets the server say why (§3.14); 3.1.1 has no server DISCONNECT, so there the
        // close is the whole message. The writer drains this before the socket closes.
        if self.is_v5() && self.out_tx.is_some() {
            let reason = Self::reason_code(
                &action,
                "reason_code",
                v5::DISCONNECT_REASON_CODES,
                "DISCONNECT",
            )?
            .unwrap_or(0x00);
            let props = Self::ack_properties(&action)?;
            self.log(format!(
                "MQTT -> DISCONNECT reason=0x{reason:02x} ({})",
                v5::reason_name(reason, v5::DISCONNECT_REASON_CODES)
            ));
            self.send_to_connection(
                crate::server::mqtt::PKT_DISCONNECT,
                build_disconnect_v5(reason, &props),
            )?;
        }
        Ok(ActionResult::CloseConnection)
    }

    /// The v5 PUBLISH properties an `mqtt_publish` may set.
    fn publish_properties(action: &serde_json::Value) -> Result<PropertyWriter> {
        let mut props = PropertyWriter::new();
        if let Some(v) = action
            .get("payload_format_indicator")
            .and_then(|v| v.as_u64())
        {
            if v > 1 {
                return Err(anyhow::anyhow!(
                    "payload_format_indicator is 0 (unspecified bytes) or 1 (UTF-8 text)"
                ));
            }
            props.byte(v5::PAYLOAD_FORMAT_INDICATOR, v as u8);
        }
        if let Some(v) = action
            .get("message_expiry_interval")
            .and_then(|v| v.as_u64())
        {
            let v = u32::try_from(v)
                .map_err(|_| anyhow::anyhow!("message_expiry_interval is at most 4294967295"))?;
            props.u32(v5::MESSAGE_EXPIRY_INTERVAL, v);
        }
        for (key, id) in [
            ("content_type", v5::CONTENT_TYPE),
            ("response_topic", v5::RESPONSE_TOPIC),
        ] {
            if let Some(v) = action.get(key).and_then(|v| v.as_str()) {
                if v.len() > usize::from(u16::MAX) {
                    return Err(anyhow::anyhow!("{key} is longer than 65535 bytes"));
                }
                if key == "response_topic" && (v.contains('+') || v.contains('#')) {
                    return Err(anyhow::anyhow!(
                        "response_topic is a topic name, so it cannot contain '+' or '#'"
                    ));
                }
                props.text(id, v);
            }
        }
        if let Some(v) = action.get("correlation_data").and_then(|v| v.as_str()) {
            let bytes = v5::text_to_binary(
                v,
                action
                    .get("correlation_data_encoding")
                    .and_then(|e| e.as_str()),
            )
            .map_err(|e| anyhow::anyhow!("correlation_data: {e}"))?;
            if bytes.len() > usize::from(u16::MAX) {
                return Err(anyhow::anyhow!(
                    "correlation_data is longer than 65535 bytes"
                ));
            }
            props.binary(v5::CORRELATION_DATA, &bytes);
        }
        if let Some(v) = action
            .get("subscription_identifier")
            .and_then(|v| v.as_u64())
        {
            if v == 0 || v > u64::from(v5::VARINT_MAX) {
                return Err(anyhow::anyhow!(
                    "subscription_identifier is 1 to 268435455 (copy it from the subscribe \
                     event's properties)"
                ));
            }
            props.varint(v5::SUBSCRIPTION_IDENTIFIER, v as u32);
        }
        for (k, v) in v5::user_properties_from_json(action.get("user_properties"))
            .map_err(|e| anyhow::anyhow!(e))?
        {
            props.pair(&k, &v);
        }
        Ok(props)
    }

    /// `mqtt_publish` (sync) and `mqtt_publish_to_client` (async) share this body.
    /// `server_id` is taken from the bound connection for the sync form and from the
    /// action for the async form.
    fn execute_publish(
        &self,
        action: serde_json::Value,
        target_key: &str,
        require_target: bool,
    ) -> Result<ActionResult> {
        let topic = action
            .get("topic")
            .and_then(|v| v.as_str())
            .context("Missing 'topic'")?;
        if topic.is_empty() {
            return Err(anyhow::anyhow!("'topic' must not be empty"));
        }
        let payload = action
            .get("payload")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let qos = action.get("qos").and_then(|v| v.as_u64()).unwrap_or(0);
        if qos > 2 {
            return Err(anyhow::anyhow!("qos must be 0, 1 or 2 (got {})", qos));
        }
        let retain = action
            .get("retain")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let packet_id = if qos > 0 {
            Self::require_packet_id(&action)?
        } else {
            action
                .get("packet_id")
                .and_then(|v| v.as_u64())
                .unwrap_or(0)
                .min(u16::MAX as u64) as u16
        };
        let properties = Self::publish_properties(&action)?;
        let has_properties = !properties.is_empty();

        let message = OutPublish {
            topic: topic.to_string(),
            payload,
            qos: qos as u8,
            retain,
            packet_id,
            properties,
        };

        let target = action.get(target_key).and_then(|v| v.as_str());
        let (delivered, v5_flags): (Vec<Option<String>>, Vec<bool>) = match target {
            Some(client) => {
                let server_id = self.require_server_id(&action)?;
                let delivered = deliver(server_id, client, &message);
                if delivered.is_empty() {
                    warn!(
                        "MQTT publish to '{}' on server {} matched no connected client",
                        client, server_id
                    );
                    return Err(anyhow::anyhow!(
                        "No connected MQTT client matches '{}' on server {}. Connected clients: {:?}",
                        client,
                        server_id,
                        list_clients(ServerId::new(server_id))
                    ));
                }
                delivered.into_iter().map(|(c, v)| (Some(c), v)).unzip()
            }
            None => {
                if require_target {
                    return Err(anyhow::anyhow!(
                        "Missing '{}': name the connected client that should receive this message, or \"*\" for all of them",
                        target_key
                    ));
                }
                let v5 = self.is_v5();
                self.send_to_connection(PKT_PUBLISH, message.encode(v5))?;
                (vec![self.current_client_id()], vec![v5])
            }
        };
        // A 3.1.1 recipient has no field for v5 properties. Saying so beats a model wondering
        // why its Response Topic never arrived.
        let dropped_for: Vec<&Option<String>> = delivered
            .iter()
            .zip(v5_flags.iter())
            .filter(|(_, v5)| has_properties && !**v5)
            .map(|(c, _)| c)
            .collect();
        self.log(format!(
            "MQTT -> PUBLISH topic='{}' qos={} to {:?}",
            topic, qos, delivered
        ));
        let mut data = json!({
            "topic": topic,
            "qos": qos,
            "retain": retain,
            "packet_id": packet_id,
            "delivered_to": delivered,
        });
        if !dropped_for.is_empty() {
            data["properties_not_sent_to"] = json!(dropped_for);
            data["properties_not_sent_reason"] =
                json!("these clients speak MQTT 3.1.1, which has no PUBLISH properties");
        }
        Ok(ActionResult::Custom {
            name: "mqtt_publish".to_string(),
            data,
        })
    }

    fn execute_list_clients(&self, action: serde_json::Value) -> Result<ActionResult> {
        let server_id = self.require_server_id(&action)?;
        let clients = list_clients(ServerId::new(server_id));
        Ok(ActionResult::Custom {
            name: "list_mqtt_clients".to_string(),
            data: json!({ "server_id": server_id, "clients": clients }),
        })
    }
}

impl Protocol for MqttProtocol {
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
        ParameterDefinition {
            name: "max_packet_size".to_string(),
            type_hint: "integer".to_string(),
            description:
                "Largest MQTT control packet accepted from a client, in bytes (default 262144, \
                 maximum 16777216). Connections sending a larger packet are closed."
                    .to_string(),
            required: false,
            example: json!(262144),
            default: Some(serde_json::json!(super::DEFAULT_MAX_PACKET_SIZE)),
        },
        ParameterDefinition {
            name: "first_byte_timeout_secs".to_string(),
            type_hint: "integer".to_string(),
            description:
                "Seconds a connected peer may take to send its CONNECT before the broker closes \
                 it (default 30). Every MQTT client sends CONNECT as soon as it connects."
                    .to_string(),
            required: false,
            example: json!(30),
            default: Some(serde_json::json!(super::CONNECT_TIMEOUT.as_secs())),
        },
        ParameterDefinition {
            name: "idle_timeout_secs".to_string(),
            type_hint: "integer".to_string(),
            description:
                "Seconds a session whose client declared Keep Alive 0 may be silent before the \
                 broker closes it (default 900). A non-zero Keep Alive is honoured as MQTT \
                 requires: the session is closed after 1.5x the client's Keep Alive with no \
                 packet from it, and this setting does not change that."
                    .to_string(),
            required: false,
            example: json!(900),
            default: Some(serde_json::json!(super::IDLE_WITHOUT_KEEP_ALIVE.as_secs())),
        },
        ]
    }

    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![mqtt_publish_to_client_action(), list_mqtt_clients_action()]
    }

    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            mqtt_connack_action(),
            mqtt_suback_action(),
            mqtt_puback_action(),
            mqtt_pubrec_action(),
            mqtt_unsuback_action(),
            mqtt_publish_action(),
            close_this_connection_action(),
        ]
    }

    fn protocol_name(&self) -> &'static str {
        "MQTT"
    }

    fn get_event_types(&self) -> Vec<EventType> {
        get_mqtt_event_types()
    }

    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>MQTT"
    }

    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "mqtt",
            "mosquitto",
            "iot messaging",
            "message queue telemetry",
        ]
    }

    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Beta)
            .well_known_port(1883)
            .implementation(
                "Hand-written MQTT 3.1.1 and 5.0 control-packet codec (no broker crate); the \
                 version is the client's, from its CONNECT",
            )
            .llm_control(
                "CONNACK return code, SUBACK granted QoS, PUBACK/PUBREC for QoS>0 publishes, \
                 and broker-originated PUBLISH to any named connected client",
            )
            .e2e_testing(
                "TWO independent clients, neither #[ignore]d and neither able to skip. \
                 (1) rumqttc, in test_mqtt_basic_connect (CONNECT/CONNACK) and \
                 test_mqtt_subscribe_and_receive_a_published_message, where it completes \
                 CONNECT -> SUBSCRIBE -> SUBACK -> PUBLISH and receives the broker's own \
                 PUBLISH back on the same connection, topic and payload asserted. \
                 (2) Eclipse Mosquitto's C clients, in \
                 tests/server/mqtt/real_client_test.rs::\
                 test_mqtt_pubsub_session_against_mosquitto_clients, which FAILS rather than \
                 skips when mosquitto is absent: mosquitto_sub subscribes, mosquitto_pub \
                 publishes on a second connection, and the broker-originated PUBLISH is routed \
                 to the subscriber by client id, with mosquitto_sub's own '-v' output -- topic \
                 AND payload, printed only after libmosquitto parsed the packet -- asserted. \
                 MQTT 5.0 has its own two: tests/server/mqtt/v5_real_client_test.rs drives \
                 mosquitto_sub/mosquitto_pub at -V 5 (Content Type, Response Topic, \
                 Correlation Data, User Property and Message Expiry forwarded and printed by \
                 libmosquitto; CONNACK and SUBACK 0x87 reported by it) and Eclipse Paho's \
                 Python client at MQTTv5 (Assigned Client Identifier, mixed SUBACK [1, 0x87] \
                 with Reason String, binary Correlation Data echoed byte for byte, Topic Alias, \
                 PUBACK 0x87, UNSUBACK 0x11, server DISCONNECT 0x98) - both fail rather than \
                 skip; v5_wire_test.rs pins the bytes and runs the pcap oracle over them. \
                 UNPROVEN: TLS/8883, WebSocket transport, QoS 1 and 2 flows \
                 end to end, retained messages, wildcard filter matching, last-will delivery, \
                 session resume, and keep-alive reaping -- the broker implements no \
                 subscription table, no retained store and no keep-alive timer.",
            )
            .notes(
                "MQTT 3.1.1 and 5.0 (no TLS, no WebSocket). On a v5 connection every \
                 acknowledgement takes a reason code and a Reason String / User Properties, \
                 events carry the decoded properties (binary Correlation Data as text or hex), \
                 the CONNACK advertises Maximum Packet Size and Topic Alias Maximum 16 and \
                 assigns an id to a client that sent none, Topic Aliases are resolved, and \
                 protocol errors end with a DISCONNECT naming the reason. Enhanced \
                 authentication (AUTH) and session state are not implemented. PINGREQ/PINGRESP and \
                 PUBREL/PUBCOMP are answered by the broker without a model call. There is no \
                 subscription table or retained-message store: the model tracks subscriptions \
                 in its memory and names recipients explicitly in mqtt_publish, so nothing is \
                 delivered automatically on publish. Non-UTF-8 payloads reach the model as a \
                 lossy string with payload_is_text=false.",
            )
            .max_inbound_bytes(crate::server::mqtt::MAX_PACKET_SIZE_LIMIT)
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            // QoS 0 PUBLISHes already waiting behind the one being answered share one call
            // (`publish_batch` in mod.rs): they owe the client nothing on the wire. QoS 1/2
            // PUBLISH, SUBSCRIBE and UNSUBSCRIBE each owe an ack with its own packet id, in
            // order (§4.6), so they are never batched; nor is CONNECT.
            .batching(crate::protocol::metadata::BatchingMode::On)
            .build()
    }

    fn description(&self) -> &'static str {
        "MQTT 3.1.1 and 5.0 broker for IoT messaging"
    }

    fn example_prompt(&self) -> &'static str {
        "Start an MQTT broker on port 1883 that accepts every client and grants QoS 0 subscriptions"
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
                "port": 1883,
                "base_stack": "mqtt",
                "instruction": "MQTT broker for IoT sensors. Accept every CONNECT (mqtt_connack return_code 0). \
                                Grant every subscription at the QoS the client asked for. Acknowledge QoS 1 \
                                publishes with mqtt_puback echoing packet_id. Remember which client subscribed \
                                to which topic filter, and when a sensor publishes, forward it with mqtt_publish \
                                to each subscriber whose filter matches."
            }),
            // Script mode: deterministic, no model call per packet
            json!({
                "type": "open_server",
                "port": 1883,
                "base_stack": "mqtt",
                "event_handlers": [
                    {
                        "event_pattern": "mqtt_connect",
                        "handler": {
                            "type": "script",
                            "language": "python",
                            "code": "respond([{'type': 'mqtt_connack', 'return_code': 0 if event['username'] == 'sensor' else 5}])"
                        }
                    },
                    {
                        "event_pattern": "mqtt_subscribe",
                        "handler": {
                            "type": "script",
                            "language": "python",
                            "code": "respond([{'type': 'mqtt_suback', 'packet_id': event['packet_id'], 'granted_qos': [t['qos'] for t in event['topics']]}])"
                        }
                    }
                ]
            }),
            // Static mode: {{event.packet_id}} echoes the correlation id
            json!({
                "type": "open_server",
                "port": 1883,
                "base_stack": "mqtt",
                "event_handlers": [
                    {
                        "event_pattern": "mqtt_connect",
                        "handler": {
                            "type": "static",
                            "actions": [{"type": "mqtt_connack", "return_code": 0}]
                        }
                    },
                    {
                        "event_pattern": "mqtt_publish",
                        "handler": {
                            "type": "static",
                            "actions": [{"type": "mqtt_puback", "packet_id": "{{event.packet_id}}"}]
                        }
                    }
                ]
            }),
        )
    }
}

impl Server for MqttProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::server::mqtt::MqttServer;
            MqttServer::spawn_with_llm_actions(
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

    fn execute_action(&self, action: serde_json::Value) -> Result<ActionResult> {
        let action_type = action
            .get("type")
            .and_then(|v| v.as_str())
            .context("Missing 'type' field in action")?;

        match action_type {
            "mqtt_connack" => self.execute_connack(action),
            "mqtt_puback" => self.execute_puback(action),
            "mqtt_pubrec" => self.execute_pubrec(action),
            "mqtt_suback" => self.execute_suback(action),
            "mqtt_unsuback" => self.execute_unsuback(action),
            "mqtt_publish" => self.execute_publish(action, "to_client_id", false),
            "mqtt_publish_to_client" => self.execute_publish(action, "client_id", true),
            "list_mqtt_clients" => self.execute_list_clients(action),
            "close_this_connection" => self.execute_close(action),
            // The dashboard's "disconnect this peer" injects {"type":"close_connection"}.
            // Not offered to the model (close_this_connection is its verb); this arm exists
            // so the generic peer command task half-closes the shared write half on it.
            "close_connection" => Ok(ActionResult::CloseConnection),
            _ => Err(anyhow::anyhow!("Unknown MQTT action: {}", action_type)),
        }
    }
}

// ============================================================================
// Action definitions
// ============================================================================

/// `reason_string` and `user_properties`, which every v5 acknowledgement may carry.
fn ack_property_parameters() -> Vec<Parameter> {
    vec![
        Parameter {
            name: "reason_string".to_string(),
            type_hint: "string".to_string(),
            description: "MQTT 5 clients only: human-readable text explaining the reason code,                           shown by the client. Not sent to a 3.1.1 client, which has no field                           for it."
                .to_string(),
            required: false,
        },
        Parameter {
            name: "user_properties".to_string(),
            type_hint: "array".to_string(),
            description: "MQTT 5 clients only: name/value pairs, as [[\"name\", \"value\"], ...] \
                          or {\"name\": \"value\"}. Not sent to a 3.1.1 client."
                .to_string(),
            required: false,
        },
    ]
}

/// The v5 PUBLISH properties `mqtt_publish` and `mqtt_publish_to_client` accept.
fn publish_property_parameters() -> Vec<Parameter> {
    let p = |name: &str, type_hint: &str, description: &str| Parameter {
        name: name.to_string(),
        type_hint: type_hint.to_string(),
        description: description.to_string(),
        required: false,
    };
    vec![
        p(
            "content_type",
            "string",
            "MQTT 5 recipients only: MIME type of the payload, e.g. 'application/json'.",
        ),
        p(
            "response_topic",
            "string",
            "MQTT 5 recipients only: topic the recipient should publish its reply to \
             (request/response). A topic name, no wildcards.",
        ),
        p(
            "correlation_data",
            "string",
            "MQTT 5 recipients only: data the replier echoes back so the requester can match \
             the reply. To answer a request, copy properties.correlation_data from the event.",
        ),
        p(
            "correlation_data_encoding",
            "string",
            "\"utf8\" (default) or \"hex\": how correlation_data is written. Copy \
             properties.correlation_data_encoding from the event when echoing one.",
        ),
        p(
            "message_expiry_interval",
            "integer",
            "MQTT 5 recipients only: seconds after which the message should be discarded.",
        ),
        p(
            "payload_format_indicator",
            "integer",
            "MQTT 5 recipients only: 1 says the payload is UTF-8 text, 0 that it is bytes.",
        ),
        p(
            "subscription_identifier",
            "integer",
            "MQTT 5 recipients only: the identifier the recipient gave the subscription this \
             message matches (from the subscribe event's properties), so it can route it.",
        ),
        p(
            "user_properties",
            "array",
            "MQTT 5 recipients only: application name/value pairs, as \
             [[\"name\", \"value\"], ...] or {\"name\": \"value\"}.",
        ),
    ]
}

pub fn mqtt_connack_action() -> ActionDefinition {
    ActionDefinition {
        name: "mqtt_connack".to_string(),
        description: "Answer a client's CONNECT. Every MQTT connection needs exactly one CONNACK \
                      before the client will send anything else. Give return_code (works for \
                      both MQTT versions) or, for an MQTT 5 client, reason_code."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "return_code".to_string(),
                type_hint: "integer".to_string(),
                description: "0 = accept the client. Refusals: 1 unacceptable protocol version, \
                              2 client id rejected, 3 server unavailable, 4 bad username or \
                              password, 5 not authorized. Any refusal closes the connection. \
                              An MQTT 5 client receives the matching reason code."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "reason_code".to_string(),
                type_hint: "integer".to_string(),
                description: "MQTT 5 reason code instead of return_code: 0 accepts; refusals \
                              include 133 (0x85) client id not valid, 134 (0x86) bad user name \
                              or password, 135 (0x87) not authorized, 136 (0x88) server \
                              unavailable, 137 (0x89) server busy, 138 (0x8A) banned, 140 \
                              (0x8C) bad authentication method. A 3.1.1 client gets the nearest \
                              3.1.1 code."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "session_present".to_string(),
                type_hint: "boolean".to_string(),
                description: "True only when resuming a stored session for a client that \
                              connected with clean_session=false. Use false unless you are \
                              deliberately simulating a resumed session."
                    .to_string(),
                required: false,
            },
        ]
        .into_iter()
        .chain(ack_property_parameters())
        .collect(),
        example: json!({"type": "mqtt_connack", "return_code": 0}),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> MQTT CONNACK rc={return_code}")
                .with_debug(
                    "MQTT mqtt_connack: rc={return_code} session_present={session_present}",
                ),
        ),
    }
}

pub fn mqtt_suback_action() -> ActionDefinition {
    ActionDefinition {
        name: "mqtt_suback".to_string(),
        description: "Answer a client's SUBSCRIBE. Required: the client blocks until it arrives."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "packet_id".to_string(),
                type_hint: "integer".to_string(),
                description: "Copy packet_id from the mqtt_subscribe event verbatim. The client \
                              matches this reply to its request by that number."
                    .to_string(),
                required: true,
            },
            Parameter {
                name: "granted_qos".to_string(),
                type_hint: "array".to_string(),
                description: "One integer per topic filter in the event's topics list, in the \
                              same order: 0, 1 or 2 to grant that maximum QoS, or 128 to refuse \
                              that single subscription. An MQTT 5 client can also be told why: \
                              135 not authorized, 143 topic filter invalid, 151 quota exceeded, \
                              158 shared subscriptions not supported, 162 wildcards not \
                              supported (a 3.1.1 client receives 128 for each)."
                    .to_string(),
                required: true,
            },
        ]
        .into_iter()
        .chain(ack_property_parameters())
        .collect(),
        example: json!({"type": "mqtt_suback", "packet_id": 10, "granted_qos": [0]}),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> MQTT SUBACK id={packet_id}")
                .with_debug("MQTT mqtt_suback: id={packet_id} granted={granted_qos}"),
        ),
    }
}

pub fn mqtt_puback_action() -> ActionDefinition {
    ActionDefinition {
        name: "mqtt_puback".to_string(),
        description: "Acknowledge a QoS 1 PUBLISH. Without it the client republishes the message \
                      forever. Do not send it for a QoS 0 publish."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "packet_id".to_string(),
                type_hint: "integer".to_string(),
                description: "Copy packet_id from the mqtt_publish event verbatim.".to_string(),
                required: true,
            },
            Parameter {
                name: "reason_code".to_string(),
                type_hint: "integer".to_string(),
                description: "MQTT 5 clients only: 0 success (default), 16 (0x10) no matching \
                              subscribers, or a refusal - 128 unspecified error, 135 not \
                              authorized, 144 topic name invalid, 151 quota exceeded, 153 \
                              payload format invalid. A refusal cannot be sent to a 3.1.1 \
                              client; close_this_connection is the only refusal there."
                    .to_string(),
                required: false,
            },
        ]
        .into_iter()
        .chain(ack_property_parameters())
        .collect(),
        example: json!({"type": "mqtt_puback", "packet_id": 42}),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> MQTT PUBACK id={packet_id}")
                .with_debug("MQTT mqtt_puback: id={packet_id}"),
        ),
    }
}

pub fn mqtt_pubrec_action() -> ActionDefinition {
    ActionDefinition {
        name: "mqtt_pubrec".to_string(),
        description: "Acknowledge a QoS 2 PUBLISH (first half of the handshake). The broker \
                      answers the client's following PUBREL with PUBCOMP on its own."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "packet_id".to_string(),
                type_hint: "integer".to_string(),
                description: "Copy packet_id from the mqtt_publish event verbatim.".to_string(),
                required: true,
            },
            Parameter {
                name: "reason_code".to_string(),
                type_hint: "integer".to_string(),
                description: "MQTT 5 clients only: 0 success (default), 16 (0x10) no matching \
                              subscribers, or a refusal - 128 unspecified error, 135 not \
                              authorized, 144 topic name invalid, 151 quota exceeded, 153 \
                              payload format invalid. A refusal cannot be sent to a 3.1.1 \
                              client; close_this_connection is the only refusal there."
                    .to_string(),
                required: false,
            },
        ]
        .into_iter()
        .chain(ack_property_parameters())
        .collect(),
        example: json!({"type": "mqtt_pubrec", "packet_id": 42}),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> MQTT PUBREC id={packet_id}")
                .with_debug("MQTT mqtt_pubrec: id={packet_id}"),
        ),
    }
}

pub fn mqtt_unsuback_action() -> ActionDefinition {
    ActionDefinition {
        name: "mqtt_unsuback".to_string(),
        description: "Answer a client's UNSUBSCRIBE. Required: the client blocks until it arrives."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "packet_id".to_string(),
                type_hint: "integer".to_string(),
                description: "Copy packet_id from the mqtt_unsubscribe event verbatim.".to_string(),
                required: true,
            },
            Parameter {
                name: "reason_codes".to_string(),
                type_hint: "array".to_string(),
                description: "MQTT 5 clients only: one code per topic filter, in order - 0 \
                              removed (the default for every filter), 17 (0x11) no such \
                              subscription existed, 135 not authorized, 143 topic filter \
                              invalid. A 3.1.1 UNSUBACK has no codes."
                    .to_string(),
                required: false,
            },
        ]
        .into_iter()
        .chain(ack_property_parameters())
        .collect(),
        example: json!({"type": "mqtt_unsuback", "packet_id": 11}),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> MQTT UNSUBACK id={packet_id}")
                .with_debug("MQTT mqtt_unsuback: id={packet_id}"),
        ),
    }
}

pub fn mqtt_publish_action() -> ActionDefinition {
    ActionDefinition {
        name: "mqtt_publish".to_string(),
        description: "Send a message from the broker to a client. This is the only way a \
                      subscriber ever receives anything: the broker does no routing of its own, \
                      so after a client publishes, deliver it yourself to each subscriber you \
                      remember. Without to_client_id it goes to the client whose packet you are \
                      answering."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "topic".to_string(),
                type_hint: "string".to_string(),
                description: "Exact topic name to publish on, e.g. 'home/kitchen/temp'. Never a \
                              wildcard: '+' and '#' are only valid in subscriptions."
                    .to_string(),
                required: true,
            },
            Parameter {
                name: "payload".to_string(),
                type_hint: "string".to_string(),
                description: "Message body as text (JSON, a number, anything). Sent as UTF-8."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "qos".to_string(),
                type_hint: "integer".to_string(),
                description: "0 (default, fire and forget), 1 or 2. For 1 and 2 you must also \
                              supply packet_id, and the client will acknowledge it."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "retain".to_string(),
                type_hint: "boolean".to_string(),
                description: "Set the RETAIN flag on the delivered message: true for the \
                              retained message a subscriber gets right after its SUBACK. The \
                              broker stores nothing, so this only marks the packet for the \
                              receiving client."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "packet_id".to_string(),
                type_hint: "integer".to_string(),
                description: "Identifier 1-65535 for this message, required when qos is 1 or 2. \
                              Pick an unused number; the client echoes it back."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "to_client_id".to_string(),
                type_hint: "string".to_string(),
                description: "Client id of the recipient, taken from connected_clients in the \
                              event, or \"*\" for every client connected to this server. Omit to \
                              reply on the current connection."
                    .to_string(),
                required: false,
            },
        ]
        .into_iter()
        .chain(publish_property_parameters())
        .collect(),
        example: json!({
            "type": "mqtt_publish",
            "to_client_id": "dashboard",
            "topic": "home/kitchen/temp",
            "payload": "21.5",
            "qos": 0
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> MQTT PUBLISH {topic}")
                .with_debug("MQTT mqtt_publish: topic={topic} qos={qos} to={to_client_id}"),
        ),
    }
}

pub fn close_this_connection_action() -> ActionDefinition {
    ActionDefinition {
        name: "close_this_connection".to_string(),
        description: "Drop the current MQTT connection. An MQTT 5 client is first sent a \
                      DISCONNECT carrying reason_code; MQTT 3.1.1 has no server-side disconnect \
                      message, so a 3.1.1 client is simply ejected."
            .to_string(),
        parameters: vec![Parameter {
            name: "reason_code".to_string(),
            type_hint: "integer".to_string(),
            description: "MQTT 5 clients only: why the connection ends - 0 normal \
                          (default), 128 unspecified error, 130 protocol error, 135 not \
                          authorized, 137 server busy, 139 server shutting down, 142 session \
                          taken over, 152 administrative action, 156 use another server."
                .to_string(),
            required: false,
        }]
        .into_iter()
        .chain(ack_property_parameters())
        .collect(),
        example: json!({"type": "close_this_connection"}),
        log_template: Some(
            LogTemplate::new()
                .with_info("MQTT connection closed by handler")
                .with_debug("MQTT close_this_connection"),
        ),
    }
}

pub fn mqtt_publish_to_client_action() -> ActionDefinition {
    ActionDefinition {
        name: "mqtt_publish_to_client".to_string(),
        description: "Push a message to a connected MQTT client outside of any request, e.g. \
                      when the user asks to send a reading to a subscriber."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "server_id".to_string(),
                type_hint: "integer".to_string(),
                description: "Id of the running MQTT server, as shown in the server list."
                    .to_string(),
                required: true,
            },
            Parameter {
                name: "client_id".to_string(),
                type_hint: "string".to_string(),
                description: "Client id of the recipient, or \"*\" for every client connected to \
                              that server. Use list_mqtt_clients to see the current ids."
                    .to_string(),
                required: true,
            },
            Parameter {
                name: "topic".to_string(),
                type_hint: "string".to_string(),
                description: "Exact topic name (no wildcards).".to_string(),
                required: true,
            },
            Parameter {
                name: "payload".to_string(),
                type_hint: "string".to_string(),
                description: "Message body as text, sent as UTF-8.".to_string(),
                required: false,
            },
            Parameter {
                name: "qos".to_string(),
                type_hint: "integer".to_string(),
                description: "0 (default), 1 or 2. packet_id is required for 1 and 2.".to_string(),
                required: false,
            },
            Parameter {
                name: "retain".to_string(),
                type_hint: "boolean".to_string(),
                description: "Set the RETAIN flag on the delivered message.".to_string(),
                required: false,
            },
            Parameter {
                name: "packet_id".to_string(),
                type_hint: "integer".to_string(),
                description: "Identifier 1-65535, required when qos is 1 or 2.".to_string(),
                required: false,
            },
        ]
        .into_iter()
        .chain(publish_property_parameters())
        .collect(),
        example: json!({
            "type": "mqtt_publish_to_client",
            "server_id": 1,
            "client_id": "dashboard",
            "topic": "alerts/high_temp",
            "payload": "31.2"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> MQTT PUBLISH {topic} to {client_id}")
                .with_debug("MQTT mqtt_publish_to_client: {client_id} topic={topic}"),
        ),
    }
}

pub fn list_mqtt_clients_action() -> ActionDefinition {
    ActionDefinition {
        name: "list_mqtt_clients".to_string(),
        description: "List the client ids currently connected to an MQTT server.".to_string(),
        parameters: vec![Parameter {
            name: "server_id".to_string(),
            type_hint: "integer".to_string(),
            description: "Id of the running MQTT server, as shown in the server list.".to_string(),
            required: true,
        }],
        example: json!({"type": "list_mqtt_clients", "server_id": 1}),
        log_template: Some(
            LogTemplate::new()
                .with_info("MQTT list clients")
                .with_debug("MQTT list_mqtt_clients: server={server_id}"),
        ),
    }
}

// ============================================================================
// Action constants
// ============================================================================

pub static MQTT_CONNACK_ACTION: LazyLock<ActionDefinition> = LazyLock::new(mqtt_connack_action);
pub static MQTT_SUBACK_ACTION: LazyLock<ActionDefinition> = LazyLock::new(mqtt_suback_action);
pub static MQTT_PUBACK_ACTION: LazyLock<ActionDefinition> = LazyLock::new(mqtt_puback_action);
pub static MQTT_PUBREC_ACTION: LazyLock<ActionDefinition> = LazyLock::new(mqtt_pubrec_action);
pub static MQTT_UNSUBACK_ACTION: LazyLock<ActionDefinition> = LazyLock::new(mqtt_unsuback_action);
pub static MQTT_PUBLISH_ACTION: LazyLock<ActionDefinition> = LazyLock::new(mqtt_publish_action);
pub static MQTT_CLOSE_CONNECTION_ACTION: LazyLock<ActionDefinition> =
    LazyLock::new(close_this_connection_action);

// ============================================================================
// Event types
// ============================================================================

/// A client sent CONNECT. The connection stays silent until an `mqtt_connack` is
/// produced (the broker sends an accepting CONNACK itself if the handler produces none).
pub static MQTT_CONNECT_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "mqtt_connect",
        "MQTT client sent CONNECT and is waiting for CONNACK",
        json!({"type": "placeholder", "event_id": "mqtt_connect"}),
    )
    .with_parameters(vec![
        Parameter {
            name: "client_id".to_string(),
            type_hint: "string".to_string(),
            description: "Client identifier from the CONNECT packet. Empty client ids are \
                          replaced with 'anon-<connection id>'."
                .to_string(),
            required: true,
        },
        Parameter {
            name: "username".to_string(),
            type_hint: "string".to_string(),
            description: "Username supplied by the client, or null if none.".to_string(),
            required: false,
        },
        Parameter {
            name: "has_password".to_string(),
            type_hint: "boolean".to_string(),
            description: "Whether a password field was present. The password itself is not \
                          surfaced."
                .to_string(),
            required: true,
        },
        Parameter {
            name: "clean_session".to_string(),
            type_hint: "boolean".to_string(),
            description: "Client asked to start a fresh session.".to_string(),
            required: true,
        },
        Parameter {
            name: "keep_alive".to_string(),
            type_hint: "integer".to_string(),
            description: "Keep-alive interval in seconds requested by the client.".to_string(),
            required: true,
        },
        Parameter {
            name: "protocol_name".to_string(),
            type_hint: "string".to_string(),
            description: "Protocol name from the packet, normally 'MQTT'.".to_string(),
            required: true,
        },
        Parameter {
            name: "protocol_level".to_string(),
            type_hint: "integer".to_string(),
            description: "4 for MQTT 3.1.1, 5 for MQTT 5.0. The broker answers in the client's \
                          version."
                .to_string(),
            required: true,
        },
        Parameter {
            name: "protocol_version".to_string(),
            type_hint: "string".to_string(),
            description: "\"3.1.1\" or \"5.0\", the same as protocol_level in words.".to_string(),
            required: true,
        },
        Parameter {
            name: "properties".to_string(),
            type_hint: "object".to_string(),
            description: "MQTT 5 only: CONNECT properties, e.g. session_expiry_interval, \
                          receive_maximum, maximum_packet_size, user_properties ([[name, value], \
                          ...]) and authentication_method. Enhanced authentication is not \
                          supported: refuse a CONNECT naming an authentication_method with \
                          reason_code 140."
                .to_string(),
            required: false,
        },
        Parameter {
            name: "will_properties".to_string(),
            type_hint: "object".to_string(),
            description: "MQTT 5 only: properties of the last-will message (will_delay_interval, \
                          content_type, response_topic, ...)."
                .to_string(),
            required: false,
        },
        Parameter {
            name: "assigned_client_id".to_string(),
            type_hint: "boolean".to_string(),
            description: "MQTT 5 only: true when the client sent an empty client id and the \
                          broker assigned client_id; the CONNACK tells the client."
                .to_string(),
            required: false,
        },
        Parameter {
            name: "will_topic".to_string(),
            type_hint: "string".to_string(),
            description: "Last-will topic, or null when the client set no will.".to_string(),
            required: false,
        },
        Parameter {
            name: "will_message".to_string(),
            type_hint: "string".to_string(),
            description: "Last-will payload as text, or null. The broker never publishes it."
                .to_string(),
            required: false,
        },
    ])
    .with_actions(vec![
        MQTT_CONNACK_ACTION.clone(),
        MQTT_CLOSE_CONNECTION_ACTION.clone(),
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("MQTT CONNECT: {client_id}")
            .with_debug("MQTT CONNECT: client_id={client_id} user={username} clean={clean_session}")
            .with_trace("MQTT CONNECT: {json_pretty(.)}"),
    )
});

/// A client published a message.
pub static MQTT_PUBLISH_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "mqtt_publish",
        "MQTT client published a message to a topic",
        json!({"type": "placeholder", "event_id": "mqtt_publish"}),
    )
    .with_parameters(vec![
        Parameter {
            name: "client_id".to_string(),
            type_hint: "string".to_string(),
            description: "Client that sent the message.".to_string(),
            required: true,
        },
        Parameter {
            name: "topic".to_string(),
            type_hint: "string".to_string(),
            description: "Exact topic the message was published on.".to_string(),
            required: true,
        },
        Parameter {
            name: "payload".to_string(),
            type_hint: "string".to_string(),
            description: "Message body decoded as UTF-8 text.".to_string(),
            required: true,
        },
        Parameter {
            name: "payload_is_text".to_string(),
            type_hint: "boolean".to_string(),
            description: "False when the payload was not valid UTF-8; the payload field is then \
                          a lossy rendering and payload_size gives the true byte count."
                .to_string(),
            required: true,
        },
        Parameter {
            name: "payload_size".to_string(),
            type_hint: "integer".to_string(),
            description: "Payload length in bytes as received.".to_string(),
            required: true,
        },
        Parameter {
            name: "qos".to_string(),
            type_hint: "integer".to_string(),
            description: "0, 1 or 2. QoS 1 needs mqtt_puback, QoS 2 needs mqtt_pubrec, QoS 0 \
                          needs no reply."
                .to_string(),
            required: true,
        },
        Parameter {
            name: "retain".to_string(),
            type_hint: "boolean".to_string(),
            description: "Client asked the broker to retain this message for future subscribers."
                .to_string(),
            required: true,
        },
        Parameter {
            name: "duplicate".to_string(),
            type_hint: "boolean".to_string(),
            description: "DUP flag: the client is redelivering a message it thinks was lost."
                .to_string(),
            required: true,
        },
        Parameter {
            name: "packet_id".to_string(),
            type_hint: "integer".to_string(),
            description: "Packet identifier to echo in mqtt_puback or mqtt_pubrec. 0 for QoS 0, \
                          where no acknowledgement exists."
                .to_string(),
            required: true,
        },
        Parameter {
            name: "connected_clients".to_string(),
            type_hint: "array".to_string(),
            description: "Client ids currently connected to this server. Use these with \
                          mqtt_publish's to_client_id to forward the message to subscribers."
                .to_string(),
            required: true,
        },
        Parameter {
            name: "properties".to_string(),
            type_hint: "object".to_string(),
            description: "MQTT 5 only: the message's properties - content_type, response_topic \
                          and correlation_data (+ correlation_data_encoding) for \
                          request/response, message_expiry_interval, payload_format_indicator, \
                          user_properties as [[name, value], ...]. A topic alias is already \
                          resolved into topic. Pass these on to mqtt_publish when forwarding."
                .to_string(),
            required: false,
        },
    ])
    .with_actions(vec![
        MQTT_PUBACK_ACTION.clone(),
        MQTT_PUBREC_ACTION.clone(),
        MQTT_PUBLISH_ACTION.clone(),
        MQTT_CLOSE_CONNECTION_ACTION.clone(),
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("MQTT PUBLISH {topic} from {client_id}")
            .with_debug("MQTT PUBLISH: topic={topic} qos={qos} {payload_size} bytes")
            .with_trace("MQTT PUBLISH: {json_pretty(.)}"),
    )
});

/// A client subscribed to one or more topic filters.
pub static MQTT_SUBSCRIBE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "mqtt_subscribe",
        "MQTT client subscribed to topic filters and is waiting for SUBACK. A broker also \
         delivers, right after the SUBACK, the retained message of every topic the filters \
         match - this broker stores nothing, so those are the ones your instruction names, \
         sent with mqtt_publish and retain true. answer_with spells out both for this \
         subscription.",
        json!({"type": "placeholder", "event_id": "mqtt_subscribe"}),
    )
    .with_parameters(vec![
        Parameter {
            name: "client_id".to_string(),
            type_hint: "string".to_string(),
            description: "Client that subscribed.".to_string(),
            required: true,
        },
        Parameter {
            name: "packet_id".to_string(),
            type_hint: "integer".to_string(),
            description: "Packet identifier that mqtt_suback must echo.".to_string(),
            required: true,
        },
        Parameter {
            name: "topics".to_string(),
            type_hint: "array".to_string(),
            description: "Requested subscriptions, in order: [{\"filter\": \"home/#\", \
                          \"qos\": 1}]. granted_qos must have one entry per element. MQTT 5 \
                          entries also carry no_local, retain_as_published and retain_handling \
                          (0 send retained messages, 1 only for a new subscription, 2 never)."
                .to_string(),
            required: true,
        },
        Parameter {
            name: "properties".to_string(),
            type_hint: "object".to_string(),
            description: "MQTT 5 only: subscription_identifiers (echo one as \
                          subscription_identifier on messages you deliver for this \
                          subscription) and user_properties."
                .to_string(),
            required: false,
        },
        Parameter {
            name: "answer_with".to_string(),
            type_hint: "string".to_string(),
            description: "The SUBACK this subscription needs, and the retained messages that \
                          follow it"
                .to_string(),
            required: true,
        },
    ])
    .with_actions(vec![
        MQTT_SUBACK_ACTION.clone(),
        MQTT_PUBLISH_ACTION.clone(),
        MQTT_CLOSE_CONNECTION_ACTION.clone(),
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("MQTT SUBSCRIBE from {client_id}")
            .with_debug("MQTT SUBSCRIBE: client={client_id} id={packet_id} topics={topics}")
            .with_trace("MQTT SUBSCRIBE: {json_pretty(.)}"),
    )
});

/// A client removed one or more subscriptions.
pub static MQTT_UNSUBSCRIBE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "mqtt_unsubscribe",
        "MQTT client unsubscribed from topic filters and is waiting for UNSUBACK",
        json!({"type": "placeholder", "event_id": "mqtt_unsubscribe"}),
    )
    .with_parameters(vec![
        Parameter {
            name: "client_id".to_string(),
            type_hint: "string".to_string(),
            description: "Client that unsubscribed.".to_string(),
            required: true,
        },
        Parameter {
            name: "packet_id".to_string(),
            type_hint: "integer".to_string(),
            description: "Packet identifier that mqtt_unsuback must echo.".to_string(),
            required: true,
        },
        Parameter {
            name: "topics".to_string(),
            type_hint: "array".to_string(),
            description: "Topic filters being removed, as strings.".to_string(),
            required: true,
        },
        Parameter {
            name: "properties".to_string(),
            type_hint: "object".to_string(),
            description: "MQTT 5 only: the UNSUBSCRIBE's user_properties.".to_string(),
            required: false,
        },
    ])
    .with_actions(vec![
        MQTT_UNSUBACK_ACTION.clone(),
        MQTT_CLOSE_CONNECTION_ACTION.clone(),
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("MQTT UNSUBSCRIBE from {client_id}")
            .with_debug("MQTT UNSUBSCRIBE: client={client_id} id={packet_id}")
            .with_trace("MQTT UNSUBSCRIBE: {json_pretty(.)}"),
    )
});

pub fn get_mqtt_event_types() -> Vec<EventType> {
    vec![
        MQTT_CONNECT_EVENT.clone(),
        MQTT_PUBLISH_EVENT.clone(),
        MQTT_SUBSCRIBE_EVENT.clone(),
        MQTT_UNSUBSCRIBE_EVENT.clone(),
    ]
}
