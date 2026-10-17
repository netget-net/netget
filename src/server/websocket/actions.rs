//! WebSocket (RFC 6455) server actions, events and metadata.
//!
//! Every action declared here is executed by [`WebSocketProtocol::execute_action`], and every
//! field an action documents is actually read. Two shapes of the protocol object exist:
//!
//! - the registry-wide instance built by [`WebSocketProtocol::new`], used for documentation,
//!   spawning, and the *async* actions (which address a connection by id and are how the
//!   model speaks to a client nobody asked it to speak to);
//! - a per-connection instance built by [`WebSocketProtocol::for_connection`], which owns the
//!   outbound channel for one socket and therefore can execute the *sync* actions.
//!
//! No storage: [`WS_CONNECTIONS`] is a directory of live sockets so the model can name a
//! recipient. Nothing survives a disconnect, and no message is ever retained.

use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter, ParameterDefinition,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::EventType;
use crate::server::connection::ConnectionId;
use crate::state::app_state::AppState;
use crate::state::ServerId;
use anyhow::{Context, Result};
use serde_json::json;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{LazyLock, Mutex};
use tokio::sync::mpsc;
use tracing::{debug, warn};

// ============================================================================
// Outbound message channel
// ============================================================================

/// One thing the model asked us to put on the wire for a connection.
///
/// The writer task owns the `SplitSink`; every producer (the per-message handler, an async
/// action addressed at this connection, a scheduled task) sends one of these instead. That is
/// why no lock is ever held across an `.await` that performs I/O.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WsOut {
    Text(String),
    Binary(Vec<u8>),
    Ping(Vec<u8>),
    Close { code: u16, reason: String },
}

/// A live WebSocket connection, addressable by the model.
struct WsConnEntry {
    server_id: u32,
    remote_addr: String,
    path: String,
    subprotocol: Option<String>,
    tx: mpsc::UnboundedSender<WsOut>,
}

/// Directory of *live sockets*, keyed by connection id (globally unique — allocated by
/// `AppState::get_next_unified_id`). Not storage: an entry exists exactly as long as its
/// socket does.
static WS_CONNECTIONS: LazyLock<Mutex<HashMap<u32, WsConnEntry>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Record a connection's writer so actions can address it by id.
pub fn register_connection(
    server_id: ServerId,
    connection_id: ConnectionId,
    remote_addr: String,
    path: String,
    tx: mpsc::UnboundedSender<WsOut>,
) {
    if let Ok(mut map) = WS_CONNECTIONS.lock() {
        map.insert(
            connection_id.as_u32(),
            WsConnEntry {
                server_id: server_id.as_u32(),
                remote_addr,
                path,
                subprotocol: None,
                tx,
            },
        );
    }
}

/// Record the negotiated subprotocol once the handshake has completed.
pub fn set_connection_subprotocol(connection_id: ConnectionId, subprotocol: Option<String>) {
    if let Ok(mut map) = WS_CONNECTIONS.lock() {
        if let Some(entry) = map.get_mut(&connection_id.as_u32()) {
            entry.subprotocol = subprotocol;
        }
    }
}

/// Drop a connection from the directory when its socket ends.
pub fn unregister_connection(connection_id: ConnectionId) {
    if let Ok(mut map) = WS_CONNECTIONS.lock() {
        map.remove(&connection_id.as_u32());
    }
}

/// Describe the connections currently open, optionally restricted to one server.
pub fn list_connections(server_id: Option<u32>) -> Vec<serde_json::Value> {
    let Ok(map) = WS_CONNECTIONS.lock() else {
        return Vec::new();
    };
    let mut rows: Vec<(u32, serde_json::Value)> = map
        .iter()
        .filter(|(_, e)| server_id.is_none_or(|sid| e.server_id == sid))
        .map(|(id, e)| {
            (
                *id,
                json!({
                    "connection_id": ConnectionId::new(*id).to_string(),
                    "server_id": e.server_id,
                    "remote_addr": e.remote_addr,
                    "path": e.path,
                    "subprotocol": e.subprotocol,
                }),
            )
        })
        .collect();
    rows.sort_by_key(|(id, _)| *id);
    rows.into_iter().map(|(_, v)| v).collect()
}

/// Deliver a message to one connection id, or to every connection when `target` is `"*"`.
/// Returns the connection ids actually written to.
fn deliver(target: &str, server_id: Option<u32>, msg: WsOut) -> Vec<String> {
    let Ok(map) = WS_CONNECTIONS.lock() else {
        return Vec::new();
    };

    let wanted = if target == "*" {
        None
    } else {
        match ConnectionId::from_string(target) {
            Some(id) => Some(id.as_u32()),
            // An unparseable id matches nothing; the caller turns the empty result into a
            // descriptive error listing the ids that do exist.
            None => return Vec::new(),
        }
    };

    let mut delivered = Vec::new();
    for (id, entry) in map.iter() {
        if let Some(want) = wanted {
            if *id != want {
                continue;
            }
        }
        if let Some(sid) = server_id {
            if entry.server_id != sid {
                continue;
            }
        }
        if entry.tx.send(msg.clone()).is_ok() {
            delivered.push(ConnectionId::new(*id).to_string());
        }
    }
    delivered.sort();
    delivered
}

// ============================================================================
// Payload encoding — symmetric in both directions
// ============================================================================

/// Turn received binary-frame bytes into the `(data, encoding)` pair the model sees.
///
/// Printable ASCII is passed through as text so the model can read it; anything else is
/// base64. The pair is *exactly* what `send_websocket_binary` consumes, so echoing a frame is
/// `{"type": "send_websocket_binary", "data": event.data, "encoding": event.encoding}` and the
/// bytes on the wire are identical. Getting this asymmetric is the `send_tcp_data` bug
/// (`d70bb5b5`), where inbound was encoded and outbound was not and an echo server could not
/// echo.
pub fn encode_inbound_payload(bytes: &[u8]) -> (String, &'static str) {
    if !bytes.is_empty()
        && bytes
            .iter()
            .all(|b| b.is_ascii_graphic() || b.is_ascii_whitespace())
    {
        (String::from_utf8_lossy(bytes).into_owned(), "utf8")
    } else {
        use base64::Engine as _;
        (
            base64::engine::general_purpose::STANDARD.encode(bytes),
            "base64",
        )
    }
}

/// Turn an action's `data` + `encoding` pair into the exact bytes to put on the wire.
///
/// There is deliberately no auto-detection: `"48656c6c6f"` is simultaneously valid text, valid
/// hex and (nearly) valid base64, and only the sender knows which it means.
pub fn decode_outbound_payload(data: &str, encoding: Option<&str>) -> Result<Vec<u8>> {
    match encoding.unwrap_or("utf8") {
        "utf8" => Ok(data.as_bytes().to_vec()),
        "base64" => {
            use base64::Engine as _;
            let cleaned: String = data.chars().filter(|c| !c.is_ascii_whitespace()).collect();
            base64::engine::general_purpose::STANDARD
                .decode(&cleaned)
                .map_err(|e| {
                    anyhow::anyhow!(
                        "Invalid base64 in 'data' ({data:?}): {e}. Use standard base64 with \
                         padding, e.g. \"AP/+AQ==\" for the 4 bytes 00 ff fe 01. To send this \
                         string as literal text, set \"encoding\": \"utf8\" instead."
                    )
                })
        }
        "hex" => {
            let cleaned: String = data
                .chars()
                .filter(|c| !c.is_ascii_whitespace() && *c != ':')
                .collect();
            let cleaned = cleaned.strip_prefix("0x").unwrap_or(&cleaned);
            if cleaned.len() % 2 != 0 {
                return Err(anyhow::anyhow!(
                    "Invalid hex in 'data': expected an even number of hex digits, got {} \
                     ({data:?}). Each byte is two hex digits, e.g. \"48656c6c6f\" = \"Hello\".",
                    cleaned.len()
                ));
            }
            hex::decode(cleaned).map_err(|e| {
                anyhow::anyhow!(
                    "Invalid hex in 'data' ({data:?}): {e}. Use only 0-9/a-f, two digits per \
                     byte. To send this string as literal text, set \"encoding\": \"utf8\"."
                )
            })
        }
        other => Err(anyhow::anyhow!(
            "Invalid 'encoding' value {other:?}. Valid values are \"utf8\" (default — send the \
             characters of 'data' unchanged), \"base64\" and \"hex\" (decode 'data' into bytes)."
        )),
    }
}

// ============================================================================
// Protocol
// ============================================================================

/// WebSocket protocol action handler.
pub struct WebSocketProtocol {
    server_id: Option<ServerId>,
    connection_id: Option<ConnectionId>,
    out_tx: Option<mpsc::UnboundedSender<WsOut>>,
    status_tx: Option<mpsc::UnboundedSender<String>>,
    /// Subprotocols the client offered in `Sec-WebSocket-Protocol`, used to reject an
    /// `accept_websocket` naming one the client never asked for (RFC 6455 §4.2.2 step 5.5).
    offered_subprotocols: Vec<String>,
    /// Set while `websocket_connection_opened` is being answered. An empty text message
    /// there is dropped: it carries nothing, and websocat reads a zero-length message as the
    /// end of the stream, so nothing sent after it is ever shown.
    speaking_first: AtomicBool,
}

impl Default for WebSocketProtocol {
    fn default() -> Self {
        Self::new()
    }
}

impl WebSocketProtocol {
    /// The server an action scopes to: the model's `server_id` if it named one, otherwise
    /// whichever server this executor is bound to (`None` = every WebSocket server).
    ///
    /// This used to be `.map(|v| v as u32)`, which wraps in silence — `4294967297` becomes
    /// `1`, so a push or a close aimed at a server that does not exist is delivered to
    /// whichever server happens to be number 1 instead of failing.
    fn scope_server_id(&self, action: &serde_json::Value) -> Result<Option<u32>> {
        if let Some(raw) = action.get("server_id").and_then(|v| v.as_u64()) {
            let id = u32::try_from(raw).map_err(|_| {
                anyhow::anyhow!(
                    "server_id {raw} is not a NetGet server id (0-4294967295); take it from \
                     the server list rather than inventing one"
                )
            })?;
            return Ok(Some(id));
        }
        Ok(self.server_id.map(|s| s.as_u32()))
    }

    /// Registry-wide instance: no connection bound, so only async actions can execute.
    pub fn new() -> Self {
        Self {
            server_id: None,
            connection_id: None,
            out_tx: None,
            status_tx: None,
            offered_subprotocols: Vec::new(),
            speaking_first: AtomicBool::new(false),
        }
    }

    /// Instance bound to one connection.
    pub fn for_connection(
        server_id: ServerId,
        connection_id: ConnectionId,
        out_tx: mpsc::UnboundedSender<WsOut>,
        status_tx: mpsc::UnboundedSender<String>,
        offered_subprotocols: Vec<String>,
    ) -> Self {
        Self {
            server_id: Some(server_id),
            connection_id: Some(connection_id),
            out_tx: Some(out_tx),
            status_tx: Some(status_tx),
            offered_subprotocols,
            speaking_first: AtomicBool::new(false),
        }
    }

    /// Mark whether the event being answered is `websocket_connection_opened`, where the
    /// server speaks first. See `speaking_first`.
    pub fn set_speaking_first(&self, speaking_first: bool) {
        self.speaking_first.store(speaking_first, Ordering::SeqCst);
    }

    fn send(&self, msg: WsOut) -> Result<()> {
        let tx = self.out_tx.as_ref().context(
            "This WebSocket action can only run in response to an event on a connection \
             (no connection is bound). To speak to a connection outside an event, use \
             push_websocket_text / push_websocket_binary with a connection_id.",
        )?;
        tx.send(msg)
            .map_err(|_| anyhow::anyhow!("WebSocket connection is already closed"))
    }

    fn log(&self, message: String) {
        debug!("{}", message);
        if let Some(tx) = &self.status_tx {
            let _ = tx.send(format!("[DEBUG] {}", message));
        }
    }

    fn conn_label(&self) -> String {
        self.connection_id
            .map(|c| c.to_string())
            .unwrap_or_else(|| "<unbound>".into())
    }

    // ---- executors -------------------------------------------------------

    fn execute_accept(&self, action: serde_json::Value) -> Result<ActionResult> {
        let subprotocol = action
            .get("subprotocol")
            .and_then(|v| v.as_str())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());

        // RFC 6455 §4.2.2: the server MUST NOT echo a subprotocol the client did not offer,
        // and clients that check (websocat does) fail the connection if it does. What the
        // model decided is to accept; the subprotocol is a detail it got wrong, usually by
        // copying one from an example. So only that part is refused: the connection opens
        // without a subprotocol, which is a valid 101 for any client, and the log says what
        // was dropped. Refusing the whole action instead turned every such accept into the
        // fail-closed 503 - the network path does not re-prompt the model with the error.
        let subprotocol = match subprotocol {
            Some(chosen) if !self.offered_subprotocols.iter().any(|s| *s == chosen) => {
                let message = format!(
                    "WebSocket accept {} decision=subprotocol_dropped: {:?} was not offered \
                     (offered: {:?}); accepting without a subprotocol",
                    self.conn_label(),
                    chosen,
                    self.offered_subprotocols
                );
                warn!("{}", message);
                if let Some(tx) = &self.status_tx {
                    let _ = tx.send(format!("[WARN] {}", message));
                }
                None
            }
            other => other,
        };

        self.log(format!(
            "WebSocket accept {} subprotocol={:?}",
            self.conn_label(),
            subprotocol
        ));

        Ok(ActionResult::Custom {
            name: "accept_websocket".to_string(),
            data: json!({ "subprotocol": subprotocol }),
        })
    }

    fn execute_reject(&self, action: serde_json::Value) -> Result<ActionResult> {
        let status_code = action
            .get("status_code")
            .and_then(|v| v.as_u64())
            .unwrap_or(403);
        if !(400..=599).contains(&status_code) {
            return Err(anyhow::anyhow!(
                "status_code {} is not a rejection status. Use a 4xx or 5xx code, e.g. 401 \
                 (authentication required), 403 (forbidden), 404 (no such endpoint), \
                 429 (too many connections), 503 (unavailable).",
                status_code
            ));
        }
        let reason = action
            .get("reason")
            .and_then(|v| v.as_str())
            .unwrap_or("Upgrade refused")
            .to_string();

        self.log(format!(
            "WebSocket reject {} {} {}",
            self.conn_label(),
            status_code,
            reason
        ));

        Ok(ActionResult::Custom {
            name: "reject_websocket".to_string(),
            data: json!({ "status_code": status_code, "reason": reason }),
        })
    }

    fn execute_send_text(&self, action: serde_json::Value) -> Result<ActionResult> {
        let text = action
            .get("text")
            .and_then(|v| v.as_str())
            .context("Missing 'text'. Provide the message body to send as a WebSocket text frame")?
            .to_string();

        if text.is_empty() && self.speaking_first.load(Ordering::SeqCst) {
            // Told to say nothing on connect, llama3.1:8b sends "" instead of no action. It
            // is valid RFC 6455 and carries nothing, and websocat treats a zero-length message
            // as end of stream (checked against a Python `websockets` server: after one, the
            // echo that followed was never printed). A reply to a client's own empty message
            // is not affected: this applies only while the server is speaking first.
            let message = format!(
                "WebSocket {} decision=empty_greeting_dropped: an empty text message on \
                 connection open is treated as no greeting",
                self.conn_label()
            );
            warn!("{}", message);
            if let Some(tx) = &self.status_tx {
                let _ = tx.send(format!("[WARN] {}", message));
            }
            return Ok(ActionResult::Custom {
                name: "send_websocket_text".to_string(),
                data: json!({ "bytes": 0, "dropped": true }),
            });
        }

        self.log(format!(
            "WebSocket -> text {} bytes to {}",
            text.len(),
            self.conn_label()
        ));
        self.send(WsOut::Text(text.clone()))?;

        Ok(ActionResult::Custom {
            name: "send_websocket_text".to_string(),
            data: json!({ "bytes": text.len() }),
        })
    }

    fn execute_send_binary(&self, action: serde_json::Value) -> Result<ActionResult> {
        let data = action
            .get("data")
            .and_then(|v| v.as_str())
            .context("Missing 'data'. Provide the payload, interpreted per the 'encoding' field")?;
        let encoding = action.get("encoding").and_then(|v| v.as_str());
        let bytes = decode_outbound_payload(data, encoding)?;

        self.log(format!(
            "WebSocket -> binary {} bytes to {} (encoding={})",
            bytes.len(),
            self.conn_label(),
            encoding.unwrap_or("utf8")
        ));
        self.send(WsOut::Binary(bytes.clone()))?;

        Ok(ActionResult::Custom {
            name: "send_websocket_binary".to_string(),
            data: json!({ "bytes": bytes.len() }),
        })
    }

    fn execute_send_ping(&self, action: serde_json::Value) -> Result<ActionResult> {
        let payload = action
            .get("payload")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .as_bytes()
            .to_vec();
        // RFC 6455 §5.5: control frame payloads are limited to 125 bytes.
        if payload.len() > 125 {
            return Err(anyhow::anyhow!(
                "Ping payload is {} bytes; RFC 6455 §5.5 limits control frames to 125 bytes",
                payload.len()
            ));
        }
        self.log(format!("WebSocket -> ping to {}", self.conn_label()));
        self.send(WsOut::Ping(payload))?;
        Ok(ActionResult::Custom {
            name: "send_websocket_ping".to_string(),
            data: json!({}),
        })
    }

    fn execute_close(&self, action: serde_json::Value) -> Result<ActionResult> {
        let (code, reason) = close_fields(&action)?;
        self.log(format!(
            "WebSocket -> close {} code={} reason={:?}",
            self.conn_label(),
            code,
            reason
        ));
        self.send(WsOut::Close {
            code,
            reason: reason.clone(),
        })?;
        Ok(ActionResult::CloseConnection)
    }

    fn execute_push(&self, action: serde_json::Value, binary: bool) -> Result<ActionResult> {
        let target = action
            .get("connection_id")
            .and_then(|v| v.as_str())
            .context(
                "Missing 'connection_id': name the connection to write to (see \
                 list_websocket_connections), or \"*\" to broadcast to every open connection",
            )?;
        let server_id = self.scope_server_id(&action)?;

        let (msg, summary) = if binary {
            let data = action
                .get("data")
                .and_then(|v| v.as_str())
                .context("Missing 'data' for push_websocket_binary")?;
            let bytes =
                decode_outbound_payload(data, action.get("encoding").and_then(|v| v.as_str()))?;
            let len = bytes.len();
            (WsOut::Binary(bytes), format!("binary {len} bytes"))
        } else {
            let text = action
                .get("text")
                .and_then(|v| v.as_str())
                .context("Missing 'text' for push_websocket_text")?
                .to_string();
            let len = text.len();
            (WsOut::Text(text), format!("text {len} bytes"))
        };

        let delivered = deliver(target, server_id, msg);
        if delivered.is_empty() {
            warn!(
                "WebSocket push to '{}' matched no open connection (server {:?})",
                target, server_id
            );
            return Err(anyhow::anyhow!(
                "No open WebSocket connection matches '{}'. Open connections: {}",
                target,
                serde_json::to_string(&list_connections(server_id)).unwrap_or_default()
            ));
        }

        self.log(format!("WebSocket push {} to {:?}", summary, delivered));
        Ok(ActionResult::Custom {
            name: if binary {
                "push_websocket_binary".to_string()
            } else {
                "push_websocket_text".to_string()
            },
            data: json!({ "delivered_to": delivered }),
        })
    }

    fn execute_close_by_id(&self, action: serde_json::Value) -> Result<ActionResult> {
        let target = action
            .get("connection_id")
            .and_then(|v| v.as_str())
            .context("Missing 'connection_id' (or \"*\" to close every open connection)")?;
        let server_id = self.scope_server_id(&action)?;
        let (code, reason) = close_fields(&action)?;

        let delivered = deliver(target, server_id, WsOut::Close { code, reason });
        if delivered.is_empty() {
            return Err(anyhow::anyhow!(
                "No open WebSocket connection matches '{}'. Open connections: {}",
                target,
                serde_json::to_string(&list_connections(server_id)).unwrap_or_default()
            ));
        }
        Ok(ActionResult::Custom {
            name: "close_websocket_connection".to_string(),
            data: json!({ "closed": delivered, "code": code }),
        })
    }

    fn execute_list(&self, action: serde_json::Value) -> Result<ActionResult> {
        let server_id = self.scope_server_id(&action)?;
        Ok(ActionResult::Custom {
            name: "list_websocket_connections".to_string(),
            data: json!({ "connections": list_connections(server_id) }),
        })
    }
}

/// Read the shared `code` / `reason` pair of the two closing actions.
fn close_fields(action: &serde_json::Value) -> Result<(u16, String)> {
    let code = action.get("code").and_then(|v| v.as_u64()).unwrap_or(1000);
    // RFC 6455 §7.4: 1000-1015 are defined, 3000-4999 are usable by applications.
    // 1005/1006/1015 must never appear on the wire.
    let valid = (1000..=1003).contains(&code)
        || (1007..=1011).contains(&code)
        || (3000..=4999).contains(&code);
    if !valid {
        return Err(anyhow::anyhow!(
            "close code {} is not sendable. RFC 6455 §7.4 allows 1000 (normal), 1001 (going \
             away), 1002 (protocol error), 1003 (unsupported data), 1007 (invalid payload), \
             1008 (policy violation), 1009 (message too big), 1010 (extension expected), \
             1011 (internal error), or 3000-4999 for application use. 1005, 1006 and 1015 \
             are reserved and must never be sent.",
            code
        ));
    }
    let reason = action
        .get("reason")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if reason.len() > 123 {
        return Err(anyhow::anyhow!(
            "close reason is {} bytes; a close frame carries a 2-byte code plus at most 123 \
             bytes of reason (RFC 6455 §5.5)",
            reason.len()
        ));
    }
    Ok((code as u16, reason))
}

// ============================================================================
// Protocol trait
// ============================================================================

impl Protocol for WebSocketProtocol {
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "path".to_string(),
                type_hint: "string".to_string(),
                description:
                    "Only upgrade requests for this exact path are accepted; anything else gets \
                     HTTP 404 without reaching the model. Omit to accept every path (the model \
                     still sees the path in the websocket_handshake event and can reject it)."
                        .to_string(),
                required: false,
                example: json!("/ws"),
                default: None,
            },
            ParameterDefinition {
                name: "max_message_size".to_string(),
                type_hint: "integer".to_string(),
                description:
                    "Largest reassembled message accepted from a client, in bytes (default \
                     1048576, maximum 67108864). A larger message fails the connection."
                        .to_string(),
                required: false,
                example: json!(1048576),
                default: Some(serde_json::json!(super::DEFAULT_MAX_MESSAGE_SIZE)),
            },
            ParameterDefinition {
                name: "max_frame_size".to_string(),
                type_hint: "integer".to_string(),
                description:
                    "Largest single frame accepted from a client, in bytes (default 1048576, \
                     maximum 67108864). Fragmented messages are reassembled up to \
                     max_message_size."
                        .to_string(),
                required: false,
                example: json!(1048576),
                default: Some(serde_json::json!(super::DEFAULT_MAX_FRAME_SIZE)),
            },
            ParameterDefinition {
                name: "idle_timeout_secs".to_string(),
                type_hint: "integer".to_string(),
                description:
                    "Seconds an upgraded connection may send no frame at all before the server \
                     closes it with 1001 (default 600). The server pings at half of it and every \
                     client answers a ping with a pong automatically, so a live but silent \
                     client is never closed; a message still being answered never counts as \
                     idle."
                        .to_string(),
                required: false,
                example: json!(600),
                default: Some(serde_json::json!(super::IDLE_TIMEOUT.as_secs())),
            },
            ParameterDefinition {
                name: "permessage_deflate".to_string(),
                type_hint: "boolean".to_string(),
                description:
                    "Accept a client's RFC 7692 permessage-deflate offer, so messages are \
                     compressed on the wire in both directions (default true). Handlers see \
                     plain text either way; false makes every connection uncompressed."
                        .to_string(),
                required: false,
                example: json!(true),
                default: Some(serde_json::json!(super::DEFAULT_PERMESSAGE_DEFLATE)),
            },
        ]
    }

    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![
            push_websocket_text_action(),
            push_websocket_binary_action(),
            list_websocket_connections_action(),
            close_websocket_connection_action(),
        ]
    }

    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            accept_websocket_action(),
            reject_websocket_action(),
            send_websocket_text_action(),
            send_websocket_binary_action(),
            send_websocket_ping_action(),
            wait_for_websocket_data_action(),
            close_websocket_action(),
        ]
    }

    fn protocol_name(&self) -> &'static str {
        "WebSocket"
    }

    fn get_event_types(&self) -> Vec<EventType> {
        get_websocket_event_types()
    }

    fn stack_name(&self) -> &'static str {
        // Not "ETH>IP>TCP>WebSocket": WebRTC Signaling already claims that string, and
        // stack names are registered as parser keywords, so a duplicate would make
        // `parse_from_str` resolve by HashMap iteration order. The HTTP hop is also more
        // accurate — RFC 6455 starts as an HTTP/1.1 Upgrade.
        "ETH>IP>TCP>HTTP>WebSocket"
    }

    fn keywords(&self) -> Vec<&'static str> {
        // Deliberately no bare "ws" (matches "aws", "wsdl", …) and no bare "web"/"socket".
        // "websocket" is claimed here, which is why `parse_from_str` checks WebRTC Signaling
        // (whose keyword is the longer "websocket signaling") ahead of the generic loop.
        vec![
            "websocket",
            "web socket",
            "rfc 6455",
            "websocket server",
            "websocket endpoint",
        ]
    }

    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{
            DevelopmentState, PrivilegeRequirement, ProtocolMetadataV2,
        };

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Beta)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation(
                "Hand-written RFC 6455 HTTP Upgrade handshake (Sec-WebSocket-Accept via \
                 tungstenite's derive_accept_key) handed to tokio-tungstenite 0.21 \
                 WebSocketStream::from_partially_read for framing, masking, fragmentation \
                 reassembly, automatic pong and the close handshake",
            )
            .llm_control(
                "Whether an upgrade is accepted and with which Sec-WebSocket-Protocol \
                 subprotocol, every text and binary frame sent, ping payloads, close code and \
                 reason, plus unprompted pushes to any named open connection or a broadcast",
            )
            .e2e_testing(
                "Two peers, neither of them this repository. (1) websocat 1.14.1, in \
                 tests/server/websocket/e2e_test.rs::test_websocket_with_websocat, completes a \
                 handshake, receives an unprompted server greeting and gets its own message \
                 echoed back. websocat links websocket-0.27.1 / websocket-base-0.26.5 \
                 (rust-websocket), NOT tungstenite — read out of the installed binary's \
                 embedded crate paths — so it is a genuinely independent RFC 6455 \
                 implementation and not the circular case of the peer being the same crate \
                 this server frames with. That test is not #[ignore]d and FAILS rather than \
                 skips when websocat is absent; until September 2026 it printed \
                 \"skipping: websocat is not installed\" and returned Ok(()), a silent pass, \
                 which is what held this at Experimental. (2) A raw RFC 6455 client \
                 hand-written in the same file recomputes Sec-WebSocket-Accept from §4.2.2, \
                 masks its own frames per §5.3 and parses ours byte by byte, asserting that \
                 the server never masks (§5.1) and that close frames carry a big-endian \
                 status code (§5.5). (3) RFC 7692 permessage-deflate against Python \
                 websockets 15 and Node ws 8 (tests/server/websocket/\
                 deflate_real_client_test.rs): a relay shows every frame NetGet sent had RSV1 \
                 set and shrank, ws negotiates a 10-bit window with no context takeover, and a \
                 compressed frame that inflates past max_message_size is refused while \
                 inflating (1009). Untested: wss:// and any browser.",
            )
            .notes(
                "Validated against websocat 1.14.1 and curl 8.20.0 as real independent \
                 clients: handshake, subprotocol negotiation, text frames, a binary frame \
                 round-tripped byte-for-byte through base64, ping/pong and a close handshake \
                 with a status code. RFC 7692 permessage-deflate is negotiated (on by default, \
                 permessage_deflate: false turns it off) beneath tungstenite by \
                 websocket/deflate.rs, honouring window sizes 9-15 and no-context-takeover; \
                 handlers see plain text either way. Not implemented: TLS (wss:// — put a TLS \
                 terminator in front) and every other extension. Pong frames from \
                 the client are logged, not surfaced as an event, so a keepalive pong costs no \
                 model call. Every connection costs two model calls before the first message \
                 (websocket_handshake, then websocket_connection_opened); use script or static \
                 handlers for deterministic endpoints.",
            )
            .max_inbound_bytes(crate::server::websocket::MAX_SIZE_LIMIT)
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }

    fn description(&self) -> &'static str {
        "WebSocket (RFC 6455) server with LLM-controlled frames and subprotocol negotiation"
    }

    fn example_prompt(&self) -> &'static str {
        "Serve a WebSocket endpoint on port 9001 at /ws that greets each client and echoes messages back uppercased"
    }

    fn group_name(&self) -> &'static str {
        "Application"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;

        StartupExamples::new(
            // LLM mode: the model authors every frame.
            json!({
                "type": "open_server",
                "port": 9001,
                "base_stack": "websocket",
                "instruction": "WebSocket chat backend. Accept every upgrade with accept_websocket, \
                                choosing the 'chat' subprotocol when the client offers it. On \
                                websocket_connection_opened send a welcome text frame. Answer each \
                                websocket_text_message in character as a chat server."
            }),
            // Script mode: deterministic, no model call per frame.
            json!({
                "type": "open_server",
                "port": 9001,
                "base_stack": "websocket",
                "event_handlers": [
                    {
                        "event_pattern": "websocket_handshake",
                        "handler": {
                            "type": "script",
                            "language": "python",
                            "code": "respond([{'type': 'accept_websocket'}] if event['path'] == '/ws' else [{'type': 'reject_websocket', 'status_code': 404, 'reason': 'No such endpoint'}])"
                        }
                    },
                    {
                        "event_pattern": "websocket_text_message",
                        "handler": {
                            "type": "script",
                            "language": "python",
                            "code": "respond([{'type': 'send_websocket_text', 'text': event['text'].upper()}])"
                        }
                    }
                ]
            }),
            // Static mode: fixed frames, no model call at all.
            json!({
                "type": "open_server",
                "port": 9001,
                "base_stack": "websocket",
                "event_handlers": [
                    {
                        "event_pattern": "websocket_handshake",
                        "handler": {
                            "type": "static",
                            "actions": [{"type": "accept_websocket"}]
                        }
                    },
                    {
                        "event_pattern": "websocket_connection_opened",
                        "handler": {
                            "type": "static",
                            "actions": [{"type": "send_websocket_text", "text": "welcome"}]
                        }
                    },
                    {
                        "event_pattern": "websocket_text_message",
                        "handler": {
                            "type": "static",
                            "actions": [{"type": "send_websocket_text", "text": "{{event.text}}"}]
                        }
                    }
                ]
            }),
        )
    }
}

impl Server for WebSocketProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::server::websocket::WebSocketServer;
            WebSocketServer::spawn_with_llm_actions(
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
            "accept_websocket" => self.execute_accept(action),
            "reject_websocket" => self.execute_reject(action),
            "send_websocket_text" => self.execute_send_text(action),
            "send_websocket_binary" => self.execute_send_binary(action),
            "send_websocket_ping" => self.execute_send_ping(action),
            "wait_for_websocket_data" => Ok(ActionResult::WaitForMore),
            "close_websocket" => self.execute_close(action),
            "push_websocket_text" => self.execute_push(action, false),
            "push_websocket_binary" => self.execute_push(action, true),
            "close_websocket_connection" => self.execute_close_by_id(action),
            "list_websocket_connections" => self.execute_list(action),
            _ => Err(anyhow::anyhow!("Unknown WebSocket action: {}", action_type)),
        }
    }
}

// ============================================================================
// Action definitions
// ============================================================================

/// The `encoding` parameter shared by every action carrying a binary `data` field.
fn encoding_parameter() -> Parameter {
    Parameter {
        name: "encoding".to_string(),
        type_hint: "string".to_string(),
        description: "How to turn 'data' into the bytes of the frame. \"utf8\" (the default when \
             omitted) sends the characters of 'data' unchanged. \"base64\" decodes 'data' as \
             standard base64, \"hex\" as two hex digits per byte. There is no auto-detection: \
             to echo a websocket_binary_message back unchanged, pass that event's 'data' AND \
             its 'encoding' straight through."
            .to_string(),
        required: false,
    }
}

pub fn accept_websocket_action() -> ActionDefinition {
    ActionDefinition {
        name: "accept_websocket".to_string(),
        description: "Complete the RFC 6455 upgrade and open the connection. Required: a \
             websocket_handshake event that is answered with neither accept_websocket nor \
             reject_websocket is refused with HTTP 503, because silence must not read as \
             consent. Most clients offer no subprotocol; accept them with no 'subprotocol' \
             field."
            .to_string(),
        parameters: vec![Parameter {
            name: "subprotocol".to_string(),
            type_hint: "string".to_string(),
            description:
                "Only when the event's 'subprotocols' list is not empty: the one of those \
                 values to agree on, echoed back in Sec-WebSocket-Protocol. Omit it when the \
                 list is empty. A value the client did not offer is dropped (RFC 6455 \
                 forbids echoing it) and the connection opens without one."
                    .to_string(),
            required: false,
        }],
        example: json!({"type": "accept_websocket"}),
        log_template: Some(
            LogTemplate::new()
                .with_info("WS accept subprotocol={subprotocol}")
                .with_debug("WebSocket accept_websocket: subprotocol={subprotocol}"),
        ),
    }
}

pub fn reject_websocket_action() -> ActionDefinition {
    ActionDefinition {
        name: "reject_websocket".to_string(),
        description:
            "Refuse the upgrade with an HTTP error instead of opening the connection. Use it \
             for the wrong path, a missing credential, an unacceptable Origin, or a \
             subprotocol you will not speak."
                .to_string(),
        parameters: vec![
            Parameter {
                name: "status_code".to_string(),
                type_hint: "integer".to_string(),
                description:
                    "HTTP status to answer with: 401 authentication required, 403 forbidden, \
                     404 no such endpoint, 429 too many connections, 503 unavailable. \
                     Defaults to 403. Must be 4xx or 5xx."
                        .to_string(),
                required: false,
            },
            Parameter {
                name: "reason".to_string(),
                type_hint: "string".to_string(),
                description: "Short explanation sent as the response body and logged.".to_string(),
                required: false,
            },
        ],
        example: json!({"type": "reject_websocket", "status_code": 403, "reason": "Origin not allowed"}),
        log_template: Some(
            LogTemplate::new()
                .with_info("WS reject {status_code}")
                .with_debug("WebSocket reject_websocket: {status_code} {reason}"),
        ),
    }
}

pub fn send_websocket_text_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_websocket_text".to_string(),
        description:
            "Send a WebSocket text frame (opcode 0x1) to this connection. This is the normal \
             way to answer a client, and it is also how the server speaks first — it is valid \
             on websocket_connection_opened, with nothing received yet. The text is the words \
             your instructions give, exactly; the example's text is a placeholder, never data."
                .to_string(),
        parameters: vec![Parameter {
            name: "text".to_string(),
            type_hint: "string".to_string(),
            description:
                "The message body, sent as UTF-8. Send JSON by putting the serialised JSON in \
                 here as a string."
                    .to_string(),
            required: true,
        }],
        example: json!({"type": "send_websocket_text", "text": "<the message, word for word>"}),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> WS text: {preview(text,60)}")
                .with_debug("WebSocket send_websocket_text: {preview(text,120)}")
                .with_trace("WebSocket text: {preview(text,2000)}"),
        ),
    }
}

pub fn send_websocket_binary_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_websocket_binary".to_string(),
        description: "Send a WebSocket binary frame (opcode 0x2) to this connection. 'data' plus \
             'encoding' is the same pair a websocket_binary_message event carries, so echoing \
             a frame back unchanged is passing both fields straight through."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "data".to_string(),
                type_hint: "string".to_string(),
                description:
                    "The payload, interpreted according to 'encoding': literal characters by \
                     default, or decoded bytes when 'encoding' is \"base64\" or \"hex\"."
                        .to_string(),
                required: true,
            },
            encoding_parameter(),
        ],
        example: json!({"type": "send_websocket_binary", "data": "AP/+AQ==", "encoding": "base64"}),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> WS binary (encoding={encoding})")
                .with_debug(
                    "WebSocket send_websocket_binary: encoding={encoding} {preview(data,120)}",
                ),
        ),
    }
}

pub fn send_websocket_ping_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_websocket_ping".to_string(),
        description:
            "Send a ping control frame to check the connection is alive. The client's pong is \
             logged and does not trigger an event. Pings arriving from the client are answered \
             with a pong automatically — you never need to send one."
                .to_string(),
        parameters: vec![Parameter {
            name: "payload".to_string(),
            type_hint: "string".to_string(),
            description: "Optional payload echoed back in the pong, at most 125 bytes.".to_string(),
            required: false,
        }],
        example: json!({"type": "send_websocket_ping", "payload": "keepalive"}),
        log_template: Some(LogTemplate::new().with_debug("WebSocket send_websocket_ping")),
    }
}

pub fn wait_for_websocket_data_action() -> ActionDefinition {
    ActionDefinition {
        name: "wait_for_websocket_data".to_string(),
        description:
            "Do not answer this message yet. The connection enters the Accumulating state and \
             this message is held; the next message of the same kind is joined onto it and \
             delivered as one event. Use it when a client splits a logical request across \
             several frames."
                .to_string(),
        parameters: vec![],
        example: json!({"type": "wait_for_websocket_data"}),
        log_template: Some(LogTemplate::new().with_debug("WebSocket waiting for more data")),
    }
}

pub fn close_websocket_action() -> ActionDefinition {
    ActionDefinition {
        name: "close_websocket".to_string(),
        description:
            "Start the RFC 6455 closing handshake on this connection: send a close frame with \
             a status code, then wait for the peer's close frame before the socket goes away."
                .to_string(),
        parameters: vec![
            Parameter {
                name: "code".to_string(),
                type_hint: "integer".to_string(),
                description:
                    "Close status code (default 1000, normal). 1001 going away, 1002 protocol \
                     error, 1003 unsupported data, 1008 policy violation, 1009 message too \
                     big, 1011 internal error, or 3000-4999 for your own meanings. 1005, 1006 \
                     and 1015 are reserved and cannot be sent."
                        .to_string(),
                required: false,
            },
            Parameter {
                name: "reason".to_string(),
                type_hint: "string".to_string(),
                description: "Optional UTF-8 explanation, at most 123 bytes.".to_string(),
                required: false,
            },
        ],
        example: json!({"type": "close_websocket", "code": 1000, "reason": "bye"}),
        log_template: Some(
            LogTemplate::new()
                .with_info("WS close {code}")
                .with_debug("WebSocket close_websocket: code={code} reason={reason}"),
        ),
    }
}

pub fn push_websocket_text_action() -> ActionDefinition {
    ActionDefinition {
        name: "push_websocket_text".to_string(),
        description: "Send a text frame to a connection that did not just say anything — the \
             server-initiated direction WebSocket exists for. Use it from a scheduled task to \
             stream ticks, or to relay one client's message to another."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "connection_id".to_string(),
                type_hint: "string".to_string(),
                description: "Which connection to write to, e.g. \"conn-7\" from \
                     list_websocket_connections, or \"*\" to broadcast to every open connection."
                    .to_string(),
                required: true,
            },
            Parameter {
                name: "text".to_string(),
                type_hint: "string".to_string(),
                description: "The message body, sent as UTF-8.".to_string(),
                required: true,
            },
            Parameter {
                name: "server_id".to_string(),
                type_hint: "integer".to_string(),
                description:
                    "Restrict a \"*\" broadcast to one server's connections. Defaults to the \
                     server this action was produced for."
                        .to_string(),
                required: false,
            },
        ],
        example: json!({"type": "push_websocket_text", "connection_id": "*", "text": "{\"price\":42}"}),
        log_template: Some(
            LogTemplate::new()
                .with_info("WS push text -> {connection_id}")
                .with_debug("WebSocket push_websocket_text: {connection_id}"),
        ),
    }
}

pub fn push_websocket_binary_action() -> ActionDefinition {
    ActionDefinition {
        name: "push_websocket_binary".to_string(),
        description: "Send a binary frame to a named open connection, or to all of them."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "connection_id".to_string(),
                type_hint: "string".to_string(),
                description: "Connection to write to, or \"*\" to broadcast.".to_string(),
                required: true,
            },
            Parameter {
                name: "data".to_string(),
                type_hint: "string".to_string(),
                description: "The payload, interpreted according to 'encoding'.".to_string(),
                required: true,
            },
            encoding_parameter(),
            Parameter {
                name: "server_id".to_string(),
                type_hint: "integer".to_string(),
                description: "Restrict a \"*\" broadcast to one server's connections.".to_string(),
                required: false,
            },
        ],
        example: json!({"type": "push_websocket_binary", "connection_id": "conn-7", "data": "AP/+AQ==", "encoding": "base64"}),
        log_template: Some(
            LogTemplate::new().with_debug("WebSocket push_websocket_binary: {connection_id}"),
        ),
    }
}

pub fn list_websocket_connections_action() -> ActionDefinition {
    ActionDefinition {
        name: "list_websocket_connections".to_string(),
        description:
            "List the WebSocket connections that are open right now, with their id, remote \
             address, request path and negotiated subprotocol. Nothing is retained after a \
             connection closes."
                .to_string(),
        parameters: vec![Parameter {
            name: "server_id".to_string(),
            type_hint: "integer".to_string(),
            description: "Restrict the list to one server. Defaults to every WebSocket server."
                .to_string(),
            required: false,
        }],
        example: json!({"type": "list_websocket_connections"}),
        log_template: Some(LogTemplate::new().with_debug("WebSocket list_websocket_connections")),
    }
}

pub fn close_websocket_connection_action() -> ActionDefinition {
    ActionDefinition {
        name: "close_websocket_connection".to_string(),
        description: "Close a named open connection (or all of them) with a status code."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "connection_id".to_string(),
                type_hint: "string".to_string(),
                description: "Connection to close, or \"*\" for every open connection.".to_string(),
                required: true,
            },
            Parameter {
                name: "code".to_string(),
                type_hint: "integer".to_string(),
                description: "Close status code, default 1000.".to_string(),
                required: false,
            },
            Parameter {
                name: "reason".to_string(),
                type_hint: "string".to_string(),
                description: "Optional explanation, at most 123 bytes.".to_string(),
                required: false,
            },
            Parameter {
                name: "server_id".to_string(),
                type_hint: "integer".to_string(),
                description: "Restrict a \"*\" close to one server's connections.".to_string(),
                required: false,
            },
        ],
        example: json!({"type": "close_websocket_connection", "connection_id": "conn-7", "code": 1001, "reason": "shutting down"}),
        log_template: Some(
            LogTemplate::new().with_debug("WebSocket close_websocket_connection: {connection_id}"),
        ),
    }
}

// ============================================================================
// Action constants
// ============================================================================

pub static ACCEPT_WEBSOCKET_ACTION: LazyLock<ActionDefinition> =
    LazyLock::new(accept_websocket_action);
pub static REJECT_WEBSOCKET_ACTION: LazyLock<ActionDefinition> =
    LazyLock::new(reject_websocket_action);
pub static SEND_WEBSOCKET_TEXT_ACTION: LazyLock<ActionDefinition> =
    LazyLock::new(send_websocket_text_action);
pub static SEND_WEBSOCKET_BINARY_ACTION: LazyLock<ActionDefinition> =
    LazyLock::new(send_websocket_binary_action);
pub static SEND_WEBSOCKET_PING_ACTION: LazyLock<ActionDefinition> =
    LazyLock::new(send_websocket_ping_action);
pub static WAIT_FOR_WEBSOCKET_DATA_ACTION: LazyLock<ActionDefinition> =
    LazyLock::new(wait_for_websocket_data_action);
pub static CLOSE_WEBSOCKET_ACTION: LazyLock<ActionDefinition> =
    LazyLock::new(close_websocket_action);

// ============================================================================
// Event types — every one of these is emitted by src/server/websocket/mod.rs
// ============================================================================

/// The frames a handler may produce once the connection is open.
fn open_connection_actions() -> Vec<ActionDefinition> {
    vec![
        SEND_WEBSOCKET_TEXT_ACTION.clone(),
        SEND_WEBSOCKET_BINARY_ACTION.clone(),
        SEND_WEBSOCKET_PING_ACTION.clone(),
        CLOSE_WEBSOCKET_ACTION.clone(),
    ]
}

/// The `answer_with` field of `websocket_handshake`: what this upgrade takes.
///
/// llama3.1:8b, told only to echo messages or to greet each client, answered websocat's
/// upgrade - which offers no subprotocol - with `accept_websocket` naming the example's "chat"
/// subprotocol (five runs in five), and in another case with `reject_websocket` 403 "no
/// subprotocols offered" (five in five). Neither instruction said anything about the
/// handshake. The request now says whether any subprotocol was offered, that none is normal,
/// and that a refusal needs a reason from the instructions.
pub fn handshake_answer_with(offered: &[String]) -> String {
    let later = "This step only opens the connection: any message - a greeting, an echo, a \
                 reply - is sent after it has opened, never here";
    let refuse = "reject_websocket only when your instructions give a reason to refuse this \
                  client (its path, its Origin, a missing token)";
    if offered.is_empty() {
        format!(
            "this client offered no subprotocol, which is normal for most clients and never a \
             reason to refuse. Answer exactly {{\"type\": \"accept_websocket\"}} and nothing \
             else - unless your instructions give a reason to refuse this client (its path, \
             its Origin, a missing token), then reject_websocket. {later}"
        )
    } else {
        format!(
            "accept_websocket, naming at most one of the subprotocols this client offered ({}) \
             in 'subprotocol', or none. {refuse}. {later}",
            offered.join(", ")
        )
    }
}

/// The `answer_with` field of `websocket_connection_opened`.
///
/// The event's example used to be a `{"event":"welcome"}` greeting, and with it the model
/// spoke first on every connection: told only to echo messages, it greeted, and told to greet
/// with "Welcome to NetGet Eval", it sent the example's `{"event":"welcome"}` instead (real-model
/// eval, llama3.1:8b, seed 42). Speaking first is the instruction's call, and the words are its.
/// "No action" is spelled out as `{"actions": []}` because, told to "return no action", the model
/// sent an empty text message instead, and websocat reads a zero-length message as end of input
/// and prints nothing after it - the echo that followed was sent and never shown.
pub const OPENED_ANSWER_WITH: &str = "speak first only if your instructions say to greet or send \
     something as soon as a client connects: then send_websocket_text whose text is exactly the \
     words they give. If they say nothing about connecting - an echo server, a server that only \
     answers - answer {\"actions\": []}: no action at all, and never an empty message, which \
     some clients read as the end of the stream";

/// The `answer_with` field of `websocket_text_message`.
pub const TEXT_MESSAGE_ANSWER_WITH: &str = "send_websocket_text with the reply your instructions \
     call for; to echo, its text is this message's 'text' field exactly, unchanged";

/// Emitted for every well-formed upgrade request, before any 101 is written.
/// See `WebSocketServer::handle_connection`.
pub static WEBSOCKET_HANDSHAKE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "websocket_handshake",
        "A client asked to upgrade an HTTP request to WebSocket. Decide whether to accept, and \
         which of the offered subprotocols (if any) to agree on; answer_with says what this \
         request takes. Answering with neither accept_websocket nor reject_websocket refuses \
         the upgrade with HTTP 503.",
        json!({"type": "accept_websocket"}),
    )
    .with_parameters(vec![
        Parameter {
            name: "path".to_string(),
            type_hint: "string".to_string(),
            description: "Request path, without the query string (e.g. \"/ws\")".to_string(),
            required: true,
        },
        Parameter {
            name: "query".to_string(),
            type_hint: "string".to_string(),
            description: "Raw query string after '?', or empty when there is none. Tokens are \
                          often passed here."
                .to_string(),
            required: false,
        },
        Parameter {
            name: "subprotocols".to_string(),
            type_hint: "array".to_string(),
            description: "Subprotocols the client offered in Sec-WebSocket-Protocol, in its \
                          order of preference. accept_websocket may name one of these and \
                          nothing else."
                .to_string(),
            required: true,
        },
        Parameter {
            name: "answer_with".to_string(),
            type_hint: "string".to_string(),
            description: "What this handshake takes: accept_websocket (naming one of the \
                          offered subprotocols only when there are any), or reject_websocket \
                          for a reason the instructions give."
                .to_string(),
            required: true,
        },
        Parameter {
            name: "origin".to_string(),
            type_hint: "string".to_string(),
            description: "The Origin header, or empty. Browsers always send it; non-browser \
                          clients usually do not."
                .to_string(),
            required: false,
        },
        Parameter {
            name: "headers".to_string(),
            type_hint: "object".to_string(),
            description: "All request headers, lowercased names to values (repeated headers \
                          joined with ', ')."
                .to_string(),
            required: true,
        },
        Parameter {
            name: "client_ip".to_string(),
            type_hint: "string".to_string(),
            description: "Remote IP address of the client".to_string(),
            required: true,
        },
        Parameter {
            name: "client_port".to_string(),
            type_hint: "integer".to_string(),
            description: "Remote port of the client".to_string(),
            required: true,
        },
    ])
    .with_actions(vec![
        ACCEPT_WEBSOCKET_ACTION.clone(),
        REJECT_WEBSOCKET_ACTION.clone(),
    ])
    .with_alternative_example(json!({
        "type": "reject_websocket", "status_code": 404, "reason": "No such endpoint"
    }))
    .with_log_template(
        LogTemplate::new()
            .with_info("WS upgrade {path} from {client_ip}:{client_port}")
            .with_debug("WebSocket handshake {path} subprotocols={subprotocols}")
            .with_trace("WebSocket handshake: {json_pretty(.)}"),
    )
});

/// Emitted immediately after the 101 response is written. This is the server's chance to
/// speak first. See `WebSocketServer::run_connection`.
pub static WEBSOCKET_CONNECTION_OPENED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "websocket_connection_opened",
        "The WebSocket connection is open and nothing has been received yet. Send a greeting, \
         a server-hello frame or an initial snapshot now only if your instructions say to; \
         otherwise return no action and stay silent until the client speaks. answer_with says \
         which.",
        json!({"type": "send_websocket_text", "text": "<the greeting your instructions give>"}),
    )
    .with_parameters(vec![
        Parameter {
            name: "path".to_string(),
            type_hint: "string".to_string(),
            description: "Request path the client connected to".to_string(),
            required: true,
        },
        Parameter {
            name: "answer_with".to_string(),
            type_hint: "string".to_string(),
            description: "Whether to speak first: only when the instructions say to greet or \
                          announce on connect"
                .to_string(),
            required: true,
        },
        Parameter {
            name: "subprotocol".to_string(),
            type_hint: "string".to_string(),
            description: "The subprotocol agreed in the handshake, or empty if none".to_string(),
            required: false,
        },
        Parameter {
            name: "client_ip".to_string(),
            type_hint: "string".to_string(),
            description: "Remote IP address of the client".to_string(),
            required: true,
        },
        Parameter {
            name: "client_port".to_string(),
            type_hint: "integer".to_string(),
            description: "Remote port of the client".to_string(),
            required: true,
        },
        Parameter {
            name: "permessage_deflate".to_string(),
            type_hint: "object".to_string(),
            description: "The RFC 7692 compression parameters agreed with the client, or null \
                when the connection is uncompressed. Messages reach the handler as plain text \
                either way."
                .to_string(),
            required: false,
        },
    ])
    .with_actions(open_connection_actions())
    .with_log_template(
        LogTemplate::new()
            .with_info("WS open {path} {client_ip}:{client_port}")
            .with_debug("WebSocket connection opened {path} subprotocol={subprotocol}"),
    )
});

/// Emitted for every reassembled text message. See `WebSocketServer::handle_inbound`.
pub static WEBSOCKET_TEXT_MESSAGE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "websocket_text_message",
        "A text message arrived from the client. Answer it, push something to another \
         connection, or close.",
        json!({"type": "send_websocket_text", "text": "<the reply your instructions call for>"}),
    )
    .with_parameters(vec![
        Parameter {
            name: "text".to_string(),
            type_hint: "string".to_string(),
            description: "The complete message, already reassembled from any fragments".to_string(),
            required: true,
        },
        Parameter {
            name: "answer_with".to_string(),
            type_hint: "string".to_string(),
            description: "How this message is answered: the reply the instructions call for, \
                          which for an echo is 'text' itself, unchanged"
                .to_string(),
            required: true,
        },
        Parameter {
            name: "message_bytes".to_string(),
            type_hint: "integer".to_string(),
            description: "Length of the message in bytes".to_string(),
            required: true,
        },
        Parameter {
            name: "subprotocol".to_string(),
            type_hint: "string".to_string(),
            description: "The subprotocol agreed in the handshake, or empty if none".to_string(),
            required: false,
        },
    ])
    .with_actions({
        let mut a = open_connection_actions();
        a.push(WAIT_FOR_WEBSOCKET_DATA_ACTION.clone());
        a
    })
    .with_alternative_example(json!({"type": "wait_for_websocket_data"}))
    .with_alternative_example(json!({"type": "close_websocket", "code": 1000, "reason": "bye"}))
    .with_log_template(
        LogTemplate::new()
            .with_info("WS <- text {message_bytes}B")
            .with_debug("WebSocket text message {message_bytes}B")
            .with_trace("WebSocket text: {preview(text,200)}"),
    )
});

/// Emitted for every reassembled binary message. See `WebSocketServer::handle_inbound`.
pub static WEBSOCKET_BINARY_MESSAGE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "websocket_binary_message",
        "A binary message arrived from the client. To echo it back unchanged, pass this \
         event's 'data' AND its 'encoding' straight into send_websocket_binary.",
        json!({"type": "send_websocket_binary", "data": "AP/+AQ==", "encoding": "base64"}),
    )
    .with_parameters(vec![
        Parameter {
            name: "data".to_string(),
            type_hint: "string".to_string(),
            description: "The message payload, read according to the 'encoding' field".to_string(),
            required: true,
        },
        Parameter {
            name: "encoding".to_string(),
            type_hint: "string".to_string(),
            description:
                "How to read 'data': \"utf8\" means it is the received bytes as literal text \
                 (used when every byte is printable ASCII), \"base64\" means it is the \
                 received bytes base64-encoded. send_websocket_binary accepts the same values, \
                 so the pair round-trips."
                    .to_string(),
            required: true,
        },
        Parameter {
            name: "message_bytes".to_string(),
            type_hint: "integer".to_string(),
            description: "Length of the decoded message in bytes".to_string(),
            required: true,
        },
        Parameter {
            name: "subprotocol".to_string(),
            type_hint: "string".to_string(),
            description: "The subprotocol agreed in the handshake, or empty if none".to_string(),
            required: false,
        },
    ])
    .with_actions({
        let mut a = open_connection_actions();
        a.push(WAIT_FOR_WEBSOCKET_DATA_ACTION.clone());
        a
    })
    .with_log_template(
        LogTemplate::new()
            .with_info("WS <- binary {message_bytes}B")
            .with_debug("WebSocket binary message {message_bytes}B encoding={encoding}"),
    )
});

/// Emitted for every ping control frame. The pong is sent automatically by the framing layer;
/// this event exists so the model can react to a heartbeat (e.g. push fresh data).
pub static WEBSOCKET_PING_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "websocket_ping",
        "The client sent a ping. A pong is already on its way — this event is only an \
         opportunity to react to the heartbeat, for example by pushing fresh data. Returning \
         no action is normal.",
        json!({"type": "send_websocket_text", "text": "{\"event\":\"heartbeat\"}"}),
    )
    .with_parameters(vec![
        Parameter {
            name: "payload".to_string(),
            type_hint: "string".to_string(),
            description: "Ping payload, read according to 'encoding'".to_string(),
            required: true,
        },
        Parameter {
            name: "encoding".to_string(),
            type_hint: "string".to_string(),
            description: "\"utf8\" or \"base64\", same meaning as on websocket_binary_message"
                .to_string(),
            required: true,
        },
    ])
    .with_actions(open_connection_actions())
    .with_log_template(
        LogTemplate::new().with_debug("WebSocket ping received: {preview(payload,64)}"),
    )
});

/// Emitted when the client starts the closing handshake. See `WebSocketServer::run_connection`.
pub static WEBSOCKET_CLOSE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "websocket_close",
        "The client is closing the connection. The close frame is echoed back automatically; \
         this event is the last chance to record what happened or send a final frame.",
        json!({"type": "show_message", "message": "client disconnected"}),
    )
    .with_parameters(vec![
        Parameter {
            name: "code".to_string(),
            type_hint: "integer".to_string(),
            description:
                "Close status code sent by the client. 1000 normal, 1001 going away, 1005 means \
                 the client sent no code at all."
                    .to_string(),
            required: true,
        },
        Parameter {
            name: "reason".to_string(),
            type_hint: "string".to_string(),
            description: "Close reason text, or empty".to_string(),
            required: false,
        },
    ])
    .with_actions(vec![
        SEND_WEBSOCKET_TEXT_ACTION.clone(),
        CLOSE_WEBSOCKET_ACTION.clone(),
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("WS close from client code={code}")
            .with_debug("WebSocket close received: code={code} reason={reason}"),
    )
});

/// All WebSocket server event types. Each is emitted by `src/server/websocket/mod.rs`.
pub fn get_websocket_event_types() -> Vec<EventType> {
    vec![
        WEBSOCKET_HANDSHAKE_EVENT.clone(),
        WEBSOCKET_CONNECTION_OPENED_EVENT.clone(),
        WEBSOCKET_TEXT_MESSAGE_EVENT.clone(),
        WEBSOCKET_BINARY_MESSAGE_EVENT.clone(),
        WEBSOCKET_PING_EVENT.clone(),
        WEBSOCKET_CLOSE_EVENT.clone(),
    ]
}
