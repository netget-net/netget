//! WebSocket (RFC 6455) server with LLM-controlled frames.
//!
//! # Why the handshake is hand-written and the framing is not
//!
//! `tokio-tungstenite`'s `accept_hdr_async` takes a **synchronous** callback to inspect the
//! request and shape the 101 response. Choosing a subprotocol is the one genuinely
//! interesting decision in this protocol and it needs a model call, which is `async`. So the
//! HTTP Upgrade half of RFC 6455 §4.2 is done here by hand — read the request head, validate
//! it, emit `websocket_handshake`, and only then write the 101 with the
//! `Sec-WebSocket-Accept` derived from the client's `Sec-WebSocket-Key` — and the already
//! upgraded socket is handed to `WebSocketStream::from_partially_read` for everything below
//! §5: frame parsing, the mandatory client-to-server mask check, continuation-frame
//! reassembly, automatic pongs, and the closing handshake.
//!
//! # What the LLM decides
//!
//! - whether an upgrade is accepted at all, and with which `Sec-WebSocket-Protocol`
//! - every text and binary frame the server sends, including unprompted ones
//! - the close code and reason
//!
//! # What the server does without asking
//!
//! - rejects a malformed or non-WebSocket request with an HTTP error (no model call: there is
//!   no decision, the request is simply not a WebSocket upgrade)
//! - answers pings with pongs, echoes the peer's close frame, reassembles fragments
//! - refuses the upgrade when the model answers with neither `accept_websocket` nor
//!   `reject_websocket` — silence must not read as consent
//!
//! # No storage
//!
//! `actions::WS_CONNECTIONS` holds live socket handles so the model can address a recipient by
//! id. Nothing is retained past a disconnect: no message log, no rooms, no subscriptions.

pub mod actions;
pub mod deflate;

use anyhow::{Context, Result};
use futures::stream::StreamExt;
use futures::SinkExt;
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinSet;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::protocol::{CloseFrame, Role, WebSocketConfig};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;
use tracing::{debug, trace};

use crate::llm::action_helper::{call_llm, call_llm_batch};
use crate::llm::actions::protocol_trait::ActionResult;
use crate::llm::ollama_client::OllamaClient;
use crate::logging::emit::Log;
use crate::protocol::Event;
use crate::server::connection::ConnectionId;
use crate::state::app_state::AppState;
use crate::state::server::{ConnectionState, ConnectionStatus, ProtocolConnectionInfo};
use crate::state::ServerId;
use actions::{
    encode_inbound_payload, WebSocketProtocol, WsOut, WEBSOCKET_BINARY_MESSAGE_EVENT,
    WEBSOCKET_CLOSE_EVENT, WEBSOCKET_CONNECTION_OPENED_EVENT, WEBSOCKET_HANDSHAKE_EVENT,
    WEBSOCKET_PING_EVENT, WEBSOCKET_TEXT_MESSAGE_EVENT,
};

/// Largest HTTP request head accepted before the upgrade. Real handshakes are well under 2 KiB.
const MAX_REQUEST_HEAD: usize = 16 * 1024;

/// How long a client has to finish sending its request head after connecting.
const HANDSHAKE_TIMEOUT_SECS: u64 = 15;

const DEFAULT_MAX_MESSAGE_SIZE: usize = 1024 * 1024;
const DEFAULT_MAX_FRAME_SIZE: usize = 1024 * 1024;
pub const MAX_SIZE_LIMIT: usize = 64 * 1024 * 1024;

/// How long an upgraded connection may go without a single frame from the peer.
///
/// A WebSocket is a session the client is entitled to hold open with nothing to say — so this
/// bound is on the **peer's liveness**, not on its conversation. At half of it the server sends
/// a Ping; every RFC 6455 endpoint answers a Ping with a Pong by itself (§5.5.2 — browsers,
/// tungstenite, websocat and NetGet's own client all do, without any application code), and a
/// Pong is a frame, so a live-but-silent client never reaches the bound. What does is a peer
/// that has stopped reading or vanished without a FIN: exactly the socket that would otherwise
/// sit in a slot forever. Every inbound frame counts — text, binary, Ping, Pong, Close.
///
/// 600 seconds, twice the default window a `manual` rule gives a human (300s,
/// `src/state/intercepts.rs`). tungstenite, like most WebSocket libraries, answers a Ping from
/// inside a read, so a client that stops reading while its application thinks — a model turn,
/// a person — answers late. At twice that window a Ping sent at the worst moment is still
/// answered inside the bound. NetGet's own client keeps reading through a parked turn
/// (`tests/client/websocket/keepalive_test.rs` holds it to a 2-second bound); the margin is for
/// peers that do not. The keepalive costs one small frame per idle connection every five
/// minutes, which no deployment notices. Declared as the `idle_timeout_secs` startup parameter.
///
/// **A message still being answered is not silence.** Handlers run in their own tasks while the
/// frame loop keeps reading, so each holds the connection's `ConnectionActivity` busy for the
/// whole of its answer — a model round-trip, or a `manual` rule parked for a human — and the
/// watchdog neither pings nor closes while anything is in flight. On expiry the server sends
/// Close 1001 ("going away", RFC 6455 §7.4.1) and ends the connection.
pub const IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(600);

/// Whether the server accepts a client's RFC 7692 `permessage-deflate` offer. On by default:
/// browsers offer it on every connection, and accepting is what a WebSocket server does. The
/// `permessage_deflate` startup parameter turns it off.
pub const DEFAULT_PERMESSAGE_DEFLATE: bool = true;

/// Concurrent connections this server admits before it starts refusing.
///
/// [`crate::server::accept_bounded::DEFAULT_MAX_CONNECTIONS`]. [`HANDSHAKE_TIMEOUT_SECS`]
/// bounds how long a peer can hold a slot before it has sent a request head, and
/// [`IDLE_TIMEOUT`] how long an upgraded one can hold it without showing it is alive. Neither
/// bounds how many there are at once; this does.
///
/// So the number is a statement about sessions, not about arrival rate. Each one costs a
/// socket, two tasks and up to [`DEFAULT_MAX_MESSAGE_SIZE`] of reassembly buffer; 256 is far
/// above a browser application's fan-in to one endpoint and far below where a stranger's
/// `connect()` loop starts costing this process its descriptors. A deployment that needs the
/// per-connection cost lower should be tightening `max_message_size`, which is the half of the
/// product that describes the memory.
const MAX_CONNECTIONS: usize = crate::server::accept_bounded::DEFAULT_MAX_CONNECTIONS;

/// The reason phrase in [`CONNECTION_CAP_REFUSAL`].
const CONNECTION_CAP_REASON: &str = "Too many connections, try again later";

/// What a peer over [`MAX_CONNECTIONS`] is told before the socket closes.
///
/// **A WebSocket client is an HTTP client first, so this speaks HTTP.** RFC 6455 §4.1 makes
/// the opening handshake an ordinary HTTP/1.1 GET, and §4.2.2 has the server answer anything
/// it will not upgrade with a normal HTTP response — which is what this server already does
/// for a refused upgrade, a bad path and a timed-out head. 503 with `Retry-After` is HTTP's
/// own word for "full, come back", and every client surfaces it as a failed handshake with a
/// status: browsers fire `error` on the `WebSocket` rather than `close`, and `websocat`,
/// tungstenite and `wscat` all report the code. A close frame would be wrong twice over — it
/// belongs to a connection that was never upgraded, and the peer has no frame parser running
/// yet.
///
/// Writing it before the request head has arrived is deliberate and legal: RFC 9112 §3.3 lets
/// a server send a final response before the request is complete, and `Connection: close`
/// tells a client still sending its head to stop and read. Built through this server's own
/// [`build_error_response`] so the `Content-Length` cannot drift from the body.
static CONNECTION_CAP_REFUSAL: std::sync::LazyLock<Vec<u8>> = std::sync::LazyLock::new(|| {
    build_error_response(
        503,
        CONNECTION_CAP_REASON,
        &[("Retry-After".to_string(), "30".to_string())],
    )
});

// ============================================================================
// HTTP request head parsing
// ============================================================================

/// The request line and headers of an HTTP/1.1 request, parsed far enough to decide whether
/// it is a WebSocket upgrade.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestHead {
    pub method: String,
    /// Request target exactly as sent, e.g. `/ws?token=abc`.
    pub target: String,
    pub version: String,
    /// Header names lowercased, values trimmed, in the order received.
    pub headers: Vec<(String, String)>,
}

impl RequestHead {
    /// First value of a header, case-insensitively.
    pub fn header(&self, name: &str) -> Option<&str> {
        let lower = name.to_ascii_lowercase();
        self.headers
            .iter()
            .find(|(k, _)| *k == lower)
            .map(|(_, v)| v.as_str())
    }

    /// Every value of a header, in order.
    pub fn header_all(&self, name: &str) -> Vec<&str> {
        let lower = name.to_ascii_lowercase();
        self.headers
            .iter()
            .filter(|(k, _)| *k == lower)
            .map(|(_, v)| v.as_str())
            .collect()
    }

    /// The path, without the query string.
    pub fn path(&self) -> &str {
        match self.target.split_once('?') {
            Some((p, _)) => p,
            None => &self.target,
        }
    }

    /// The query string after `?`, or `""`.
    pub fn query(&self) -> &str {
        match self.target.split_once('?') {
            Some((_, q)) => q,
            None => "",
        }
    }

    /// All headers as a JSON object, repeated headers joined with `", "`.
    pub fn headers_json(&self) -> serde_json::Value {
        let mut map = serde_json::Map::new();
        for (k, v) in &self.headers {
            match map.get_mut(k) {
                Some(serde_json::Value::String(existing)) => {
                    existing.push_str(", ");
                    existing.push_str(v);
                }
                _ => {
                    map.insert(k.clone(), serde_json::Value::String(v.clone()));
                }
            }
        }
        serde_json::Value::Object(map)
    }

    /// Subprotocols offered in `Sec-WebSocket-Protocol`, in the client's order of preference.
    ///
    /// RFC 6455 §4.1: the header may appear more than once and each occurrence may hold a
    /// comma-separated list; both spellings mean the same thing.
    pub fn offered_subprotocols(&self) -> Vec<String> {
        self.header_all("sec-websocket-protocol")
            .into_iter()
            .flat_map(|v| v.split(','))
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    }
}

/// Parse an HTTP/1.1 request head (everything before the terminating blank line).
///
/// Deliberately hand-written rather than pulling in another HTTP parser: the upgrade request
/// is a request line plus headers, and the validation that matters (RFC 6455 §4.2.1) is done
/// on the result, not by the parser.
pub fn parse_request_head(bytes: &[u8]) -> std::result::Result<RequestHead, String> {
    let text =
        std::str::from_utf8(bytes).map_err(|_| "request head is not valid UTF-8".to_string())?;

    let mut lines = text.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    if request_line.is_empty() {
        return Err("empty request line".to_string());
    }

    let mut parts = request_line.split(' ');
    let method = parts.next().unwrap_or("").to_string();
    let target = parts.next().unwrap_or("").to_string();
    let version = parts.next().unwrap_or("").to_string();
    if method.is_empty() || target.is_empty() || version.is_empty() {
        return Err(format!("malformed request line: {request_line:?}"));
    }
    if !version.starts_with("HTTP/") {
        return Err(format!("unrecognised HTTP version: {version:?}"));
    }

    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        // Obsolete line folding (a header continuation starting with SP/HTAB) is rejected
        // rather than mis-parsed; RFC 7230 §3.2.4 deprecates it and no WebSocket client emits it.
        if line.starts_with(' ') || line.starts_with('\t') {
            return Err("obsolete header line folding is not supported".to_string());
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err(format!("malformed header line: {line:?}"));
        };
        if name.is_empty() || name.ends_with(' ') {
            return Err(format!("malformed header name: {name:?}"));
        }
        headers.push((name.to_ascii_lowercase(), value.trim().to_string()));
    }

    Ok(RequestHead {
        method,
        target,
        version,
        headers,
    })
}

/// Why an HTTP request is not an acceptable WebSocket upgrade.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpgradeRejection {
    pub status: u16,
    pub reason: String,
    /// Extra response headers, e.g. `Sec-WebSocket-Version: 13` on a version mismatch.
    pub extra_headers: Vec<(String, String)>,
}

/// Check a parsed request against RFC 6455 §4.2.1 and return the client's
/// `Sec-WebSocket-Key` when it is a valid upgrade.
///
/// This is pure mechanics with no decision in it, so it never reaches the model — a request
/// that is not a WebSocket handshake at all is answered with an HTTP error directly.
pub fn validate_upgrade(head: &RequestHead) -> std::result::Result<String, UpgradeRejection> {
    let reject = |status: u16, reason: &str| UpgradeRejection {
        status,
        reason: reason.to_string(),
        extra_headers: Vec::new(),
    };

    if !head.method.eq_ignore_ascii_case("GET") {
        return Err(reject(
            405,
            "WebSocket upgrade requires the GET method (RFC 6455 section 4.1)",
        ));
    }
    if head.version != "HTTP/1.1" {
        return Err(reject(
            505,
            "WebSocket upgrade requires HTTP/1.1 (RFC 6455 section 4.1)",
        ));
    }

    let upgrade_ok = head.header_all("upgrade").iter().any(|v| {
        v.split(',')
            .any(|t| t.trim().eq_ignore_ascii_case("websocket"))
    });
    if !upgrade_ok {
        return Err(reject(400, "missing or invalid Upgrade: websocket header"));
    }

    let connection_ok = head.header_all("connection").iter().any(|v| {
        v.split(',')
            .any(|t| t.trim().eq_ignore_ascii_case("upgrade"))
    });
    if !connection_ok {
        return Err(reject(400, "missing or invalid Connection: Upgrade header"));
    }

    match head.header("sec-websocket-version") {
        Some("13") => {}
        Some(other) => {
            return Err(UpgradeRejection {
                status: 426,
                reason: format!(
                    "unsupported Sec-WebSocket-Version {other:?}; this server speaks version 13"
                ),
                // RFC 6455 section 4.4: the 426 MUST name the versions we do support.
                extra_headers: vec![("Sec-WebSocket-Version".into(), "13".into())],
            });
        }
        None => {
            return Err(UpgradeRejection {
                status: 426,
                reason: "missing Sec-WebSocket-Version header".to_string(),
                extra_headers: vec![("Sec-WebSocket-Version".into(), "13".into())],
            })
        }
    }

    let key = head
        .header("sec-websocket-key")
        .ok_or_else(|| reject(400, "missing Sec-WebSocket-Key header"))?;

    // RFC 6455 section 4.1: the key is a base64-encoded 16-byte nonce.
    use base64::Engine as _;
    match base64::engine::general_purpose::STANDARD.decode(key) {
        Ok(raw) if raw.len() == 16 => {}
        _ => {
            return Err(reject(
                400,
                "Sec-WebSocket-Key is not a base64-encoded 16-byte value",
            ))
        }
    }

    Ok(key.to_string())
}

/// Build the `101 Switching Protocols` response for a validated handshake.
///
/// `Sec-WebSocket-Accept` is `base64(SHA-1(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))`,
/// computed by `tungstenite::handshake::derive_accept_key` — the same crate that then parses
/// the frames, so there is exactly one implementation of the GUID concatenation in the tree.
pub fn build_accept_response(
    key: &str,
    subprotocol: Option<&str>,
    extensions: Option<&str>,
) -> String {
    let accept = tokio_tungstenite::tungstenite::handshake::derive_accept_key(key.as_bytes());
    let mut response = String::from("HTTP/1.1 101 Switching Protocols\r\n");
    response.push_str("Upgrade: websocket\r\n");
    response.push_str("Connection: Upgrade\r\n");
    response.push_str(&format!("Sec-WebSocket-Accept: {accept}\r\n"));
    if let Some(sub) = subprotocol {
        response.push_str(&format!("Sec-WebSocket-Protocol: {sub}\r\n"));
    }
    if let Some(ext) = extensions {
        response.push_str(&format!("Sec-WebSocket-Extensions: {ext}\r\n"));
    }
    response.push_str("\r\n");
    response
}

/// Build a plain HTTP error response used to refuse an upgrade.
pub fn build_error_response(
    status: u16,
    reason: &str,
    extra_headers: &[(String, String)],
) -> Vec<u8> {
    let phrase = match status {
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        426 => "Upgrade Required",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        505 => "HTTP Version Not Supported",
        _ => "Error",
    };
    let body = format!("{reason}\n");
    let mut response = format!("HTTP/1.1 {status} {phrase}\r\n");
    for (name, value) in extra_headers {
        response.push_str(&format!("{name}: {value}\r\n"));
    }
    response.push_str("Connection: close\r\n");
    response.push_str("Content-Type: text/plain; charset=utf-8\r\n");
    response.push_str(&format!("Content-Length: {}\r\n\r\n", body.len()));
    response.push_str(&body);
    response.into_bytes()
}

// ============================================================================
// Per-connection state machine
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HandlerState {
    Idle,
    Processing,
    Accumulating,
}

/// One reassembled message from the client, waiting to be turned into an event.
#[derive(Debug, Clone)]
enum Inbound {
    Text(String),
    Binary(Vec<u8>),
    Ping(Vec<u8>),
}

impl Inbound {
    /// Join two messages of the same kind into one, for the `Accumulating` state.
    fn merge(self, next: Inbound) -> std::result::Result<Inbound, (Inbound, Inbound)> {
        match (self, next) {
            (Inbound::Text(mut a), Inbound::Text(b)) => {
                a.push_str(&b);
                Ok(Inbound::Text(a))
            }
            (Inbound::Binary(mut a), Inbound::Binary(b)) => {
                a.extend_from_slice(&b);
                Ok(Inbound::Binary(a))
            }
            (a, b) => Err((a, b)),
        }
    }
}

/// The event the model is asked about for one inbound message.
fn inbound_event(message: &Inbound, sub: &str) -> Event {
    match message {
        Inbound::Text(text) => Event::new(
            &WEBSOCKET_TEXT_MESSAGE_EVENT,
            serde_json::json!({
                "text": text,
                "message_bytes": text.len(),
                "subprotocol": sub,
                "answer_with": actions::TEXT_MESSAGE_ANSWER_WITH,
            }),
        ),
        Inbound::Binary(bytes) => {
            let (data, encoding) = encode_inbound_payload(bytes);
            Event::new(
                &WEBSOCKET_BINARY_MESSAGE_EVENT,
                serde_json::json!({
                    "data": data,
                    "encoding": encoding,
                    "message_bytes": bytes.len(),
                    "subprotocol": sub,
                }),
            )
        }
        Inbound::Ping(payload) => {
            let (data, encoding) = encode_inbound_payload(payload);
            Event::new(
                &WEBSOCKET_PING_EVENT,
                serde_json::json!({ "payload": data, "encoding": encoding }),
            )
        }
    }
}

struct ConnData {
    state: HandlerState,
    /// Messages that arrived while the model was thinking.
    queued: VecDeque<Inbound>,
    /// A message the model deferred with `wait_for_websocket_data`.
    pending: Option<Inbound>,
}

/// Everything a message handler task needs; grouped so the task spawn stays readable.
struct ConnCtx {
    server_id: ServerId,
    connection_id: ConnectionId,
    llm_client: OllamaClient,
    app_state: Arc<AppState>,
    status_tx: mpsc::UnboundedSender<String>,
    out_tx: mpsc::UnboundedSender<WsOut>,
    protocol: Arc<WebSocketProtocol>,
    data: Arc<Mutex<ConnData>>,
    subprotocol: Option<String>,
}

// ============================================================================
// Server
// ============================================================================

pub struct WebSocketServer;

impl WebSocketServer {
    /// Bind and start accepting. Bind failure is propagated so `server_startup` records
    /// `ServerStatus::Error` rather than reporting a server that never took the port.
    pub async fn spawn_with_llm_actions(
        listen_addr: SocketAddr,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        server_id: ServerId,
        startup_params: Option<crate::protocol::StartupParams>,
    ) -> Result<SocketAddr> {
        // Every parameter read here is declared in `get_startup_parameters()`, and every
        // parameter declared there is read here. Errors are propagated, never unwrapped.
        let permessage_deflate = match startup_params.as_ref() {
            Some(params) => params
                .get_optional_bool("permessage_deflate")
                .map_err(|e| anyhow::anyhow!("WebSocket startup parameter error: {e}"))?
                .unwrap_or(DEFAULT_PERMESSAGE_DEFLATE),
            None => DEFAULT_PERMESSAGE_DEFLATE,
        };
        let (path_filter, max_message_size, max_frame_size, idle_timeout) =
            match startup_params.as_ref() {
                Some(params) => {
                    let path = params
                        .get_optional_string("path")
                        .map_err(|e| anyhow::anyhow!("WebSocket startup parameter error: {e}"))?
                        .map(|p| {
                            if p.starts_with('/') {
                                p
                            } else {
                                format!("/{p}")
                            }
                        });
                    let msg = params
                        .get_optional_u64("max_message_size")
                        .map_err(|e| anyhow::anyhow!("WebSocket startup parameter error: {e}"))?
                        .map(|v| (v as usize).clamp(125, MAX_SIZE_LIMIT))
                        .unwrap_or(DEFAULT_MAX_MESSAGE_SIZE);
                    let frame = params
                        .get_optional_u64("max_frame_size")
                        .map_err(|e| anyhow::anyhow!("WebSocket startup parameter error: {e}"))?
                        .map(|v| (v as usize).clamp(125, MAX_SIZE_LIMIT))
                        .unwrap_or(DEFAULT_MAX_FRAME_SIZE);
                    let idle = params
                        .get_optional_u64("idle_timeout_secs")
                        .map_err(|e| anyhow::anyhow!("WebSocket startup parameter error: {e}"))?
                        .map(std::time::Duration::from_secs)
                        .unwrap_or(IDLE_TIMEOUT);
                    (path, msg, frame, idle)
                }
                None => (
                    None,
                    DEFAULT_MAX_MESSAGE_SIZE,
                    DEFAULT_MAX_FRAME_SIZE,
                    IDLE_TIMEOUT,
                ),
            };

        let ws_config = WebSocketConfig {
            max_message_size: Some(max_message_size),
            max_frame_size: Some(max_frame_size),
            // Left at the RFC default (false): a server MUST fail the connection on an
            // unmasked client frame (RFC 6455 section 5.1).
            accept_unmasked_frames: false,
            ..Default::default()
        };

        let listener =
            crate::server::socket_helpers::create_reusable_tcp_listener(listen_addr).await?;
        let local_addr = listener.local_addr()?;

        Log::new(Some(&status_tx)).info(format!("WebSocket server listening on {}", local_addr));
        if let Some(p) = &path_filter {
            Log::new(Some(&status_tx)).info(format!("WebSocket server only upgrades path {}", p));
        }

        let accept_state = app_state.clone();
        let accept_status_tx = status_tx.clone();

        let limiter = crate::server::accept_bounded::ConnectionLimiter::new(MAX_CONNECTIONS);
        let accept_handle = tokio::spawn(async move {
            loop {
                match crate::server::accept_bounded::accept_bounded(
                    &listener,
                    &limiter,
                    &CONNECTION_CAP_REFUSAL,
                    "WEBSOCKET",
                    Some(&accept_status_tx),
                )
                .await
                {
                    Ok((socket, peer_addr, permit)) => {
                        let llm_client = llm_client.clone();
                        let app_state = accept_state.clone();
                        let status_tx = accept_status_tx.clone();
                        let path_filter = path_filter.clone();
                        // Tracked, not detached: stop_server must abort this task too.
                        let task_owner = app_state.clone();
                        task_owner
                            .spawn_server_task(server_id, async move {
                                // One upgraded WebSocket is *two* tasks — this one and the
                                // writer `run_connection` spawns — and the read loop waits
                                // only five seconds for the writer before giving up on it, so
                                // the permit goes in as an `Arc` held by both and the slot
                                // comes back when the later of the two ends. Holding it here
                                // alone would release the slot while a writer was still
                                // draining a slow peer, which un-caps the server silently.
                                let permit = Arc::new(permit);
                                if let Err(e) = Self::handle_connection(
                                    socket,
                                    peer_addr,
                                    local_addr,
                                    llm_client,
                                    app_state,
                                    status_tx,
                                    server_id,
                                    path_filter,
                                    ws_config,
                                    permit,
                                    idle_timeout,
                                    permessage_deflate,
                                )
                                .await
                                {
                                    debug!("WebSocket connection from {} ended: {}", peer_addr, e);
                                }
                            })
                            .await;
                    }
                    Err(e) => {
                        Log::new(Some(&accept_status_tx))
                            .error(format!("WebSocket accept error: {}", e));
                        break;
                    }
                }
            }
        });

        // Without this the socket survives stop_server.
        app_state
            .register_server_task(server_id, accept_handle)
            .await;

        let _ = status_tx.send("__UPDATE_UI__".to_string());
        Ok(local_addr)
    }

    /// Read the HTTP request head, run the handshake decision, and hand off to the frame loop.
    #[allow(clippy::too_many_arguments)]
    async fn handle_connection(
        mut socket: TcpStream,
        peer_addr: SocketAddr,
        local_addr: SocketAddr,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        server_id: ServerId,
        path_filter: Option<String>,
        ws_config: WebSocketConfig,
        permit: Arc<crate::server::accept_bounded::ConnectionPermit>,
        idle_timeout: std::time::Duration,
        permessage_deflate: bool,
    ) -> Result<()> {
        // ---- 1. read the request head -------------------------------------
        let (head_bytes, leftover) = match tokio::time::timeout(
            std::time::Duration::from_secs(HANDSHAKE_TIMEOUT_SECS),
            read_request_head(&mut socket),
        )
        .await
        {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => {
                debug!("WebSocket handshake read failed from {}: {}", peer_addr, e);
                return Ok(());
            }
            Err(_) => {
                debug!("WebSocket handshake timed out for {}", peer_addr);
                let _ = socket
                    .write_all(&build_error_response(
                        408,
                        "Timed out waiting for the HTTP request",
                        &[],
                    ))
                    .await;
                return Ok(());
            }
        };

        let head = match parse_request_head(&head_bytes) {
            Ok(h) => h,
            Err(e) => {
                Log::new(Some(&status_tx)).warn(format!(
                    "WebSocket malformed request from {}: {}",
                    peer_addr, e
                ));
                let _ = socket.write_all(&build_error_response(400, &e, &[])).await;
                return Ok(());
            }
        };

        // ---- 2. mechanical validation (no model call) ----------------------
        let key = match validate_upgrade(&head) {
            Ok(k) => k,
            Err(rej) => {
                Log::new(Some(&status_tx)).debug(format!(
                    "WebSocket upgrade refused for {} ({}): {}",
                    peer_addr, rej.status, rej.reason
                ));
                let _ = socket
                    .write_all(&build_error_response(
                        rej.status,
                        &rej.reason,
                        &rej.extra_headers,
                    ))
                    .await;
                return Ok(());
            }
        };

        if let Some(want) = &path_filter {
            if head.path() != want {
                Log::new(Some(&status_tx)).debug(format!(
                    "WebSocket 404 for path {} (server serves {})",
                    head.path(),
                    want
                ));
                let _ = socket
                    .write_all(&build_error_response(
                        404,
                        &format!("This server only serves WebSocket at {want}"),
                        &[],
                    ))
                    .await;
                return Ok(());
            }
        }

        // ---- 3. register the connection ------------------------------------
        let connection_id = ConnectionId::new(app_state.get_next_unified_id().await);
        let offered = head.offered_subprotocols();
        let path = head.path().to_string();

        let (out_tx, out_rx) = mpsc::unbounded_channel::<WsOut>();
        actions::register_connection(
            server_id,
            connection_id,
            peer_addr.to_string(),
            path.clone(),
            out_tx.clone(),
        );

        let now = crate::utils::clock::Instant::now();
        app_state
            .add_connection_to_server(
                server_id,
                ConnectionState {
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
                        "path": path,
                        "subprotocol": serde_json::Value::Null,
                        "state": "Handshake",
                    })),
                },
            )
            .await;
        let _ = status_tx.send("__UPDATE_UI__".to_string());

        let protocol = Arc::new(WebSocketProtocol::for_connection(
            server_id,
            connection_id,
            out_tx.clone(),
            status_tx.clone(),
            offered.clone(),
        ));

        // ---- 4. ask the model whether to accept, and with which subprotocol -
        let decision = Self::run_handshake_decision(
            &head,
            peer_addr,
            &llm_client,
            &app_state,
            &status_tx,
            server_id,
            connection_id,
            protocol.as_ref(),
        )
        .await;

        let subprotocol = match decision {
            HandshakeDecision::Accept { subprotocol } => subprotocol,
            HandshakeDecision::Reject { status, reason } => {
                // The tag on the fail-closed refusals is written by `run_handshake_decision`,
                // which is the only place that knows *why* the upgrade was refused; this line
                // covers the one case it does not reach, an explicit `reject_websocket`.
                Log::new(Some(&status_tx)).info(format!(
                    "WebSocket upgrade from {} rejected by handler ({}): {}",
                    peer_addr, status, reason
                ));
                let _ = socket
                    .write_all(&build_error_response(status, &reason, &[]))
                    .await;
                Self::cleanup(&app_state, server_id, connection_id, &status_tx).await;
                return Ok(());
            }
        };

        // ---- 5. write the 101 ----------------------------------------------
        // RFC 7692 is mechanical, not a decision for the model: accept the first offer this
        // server can honour, or run uncompressed, which is always allowed.
        let deflate = if permessage_deflate {
            deflate::negotiate(head.header_all("sec-websocket-extensions"))
        } else {
            None
        };
        let response = build_accept_response(
            &key,
            subprotocol.as_deref(),
            deflate.as_ref().map(|(_, value)| value.as_str()),
        );
        let deflate = deflate.map(|(params, _)| params);
        trace!("WebSocket 101 response to {}:\n{}", peer_addr, response);
        if let Err(e) = socket.write_all(response.as_bytes()).await {
            debug!("WebSocket failed to write 101 to {}: {}", peer_addr, e);
            Self::cleanup(&app_state, server_id, connection_id, &status_tx).await;
            return Ok(());
        }
        if let Err(e) = socket.flush().await {
            debug!("WebSocket failed to flush 101 to {}: {}", peer_addr, e);
            Self::cleanup(&app_state, server_id, connection_id, &status_tx).await;
            return Ok(());
        }

        actions::set_connection_subprotocol(connection_id, subprotocol.clone());
        app_state
            .with_server_mut(server_id, |server| {
                if let Some(conn) = server.connections.get_mut(&connection_id) {
                    conn.protocol_info = ProtocolConnectionInfo::new(serde_json::json!({
                        "path": path,
                        "subprotocol": subprotocol,
                        "permessage_deflate": deflate.is_some(),
                        "state": "Open",
                    }));
                }
            })
            .await;

        Log::new(Some(&status_tx)).info(format!(
            "WebSocket {} open from {} ({}{}{})",
            connection_id,
            peer_addr,
            path,
            subprotocol
                .as_ref()
                .map(|s| format!(", subprotocol {s}"))
                .unwrap_or_default(),
            if deflate.is_some() {
                ", permessage-deflate"
            } else {
                ""
            }
        ));

        // ---- 6. hand the upgraded socket to the framing layer ---------------
        // `from_partially_read` rather than `from_raw_socket`: a pipelined client may already
        // have written frames into the same TCP segment as the request head, and those bytes
        // are in `leftover`. Discarding them would silently drop the client's first message.
        //
        // The leftover goes to the deflate layer, not tungstenite: it is frame bytes, and with
        // the extension on, a compressed first message may already be in it.
        let max_message = ws_config
            .max_message_size
            .unwrap_or(DEFAULT_MAX_MESSAGE_SIZE);
        let max_frame = ws_config.max_frame_size.unwrap_or(DEFAULT_MAX_FRAME_SIZE);
        let ws_stream = WebSocketStream::from_partially_read(
            deflate::DeflateStream::server(socket, deflate, max_message, max_frame, leftover),
            Vec::new(),
            Role::Server,
            Some(ws_config),
        )
        .await;

        Self::run_connection(
            ws_stream,
            out_rx,
            permit,
            ConnCtx {
                server_id,
                connection_id,
                llm_client,
                app_state: app_state.clone(),
                status_tx: status_tx.clone(),
                out_tx,
                protocol,
                data: Arc::new(Mutex::new(ConnData {
                    state: HandlerState::Idle,
                    queued: VecDeque::new(),
                    pending: None,
                })),
                subprotocol,
            },
            path,
            peer_addr,
            idle_timeout,
            deflate,
        )
        .await;

        Self::cleanup(&app_state, server_id, connection_id, &status_tx).await;
        Ok(())
    }

    /// Emit `websocket_handshake` and turn the answer into a decision.
    ///
    /// Default is refusal. An LLM outage, a handler that returns nothing, and a handler that
    /// returns an unrelated action all end here with a 503, and each is logged distinctly from
    /// an explicit `reject_websocket` — silence must never be indistinguishable from consent.
    #[allow(clippy::too_many_arguments)]
    async fn run_handshake_decision(
        head: &RequestHead,
        peer_addr: SocketAddr,
        llm_client: &OllamaClient,
        app_state: &Arc<AppState>,
        status_tx: &mpsc::UnboundedSender<String>,
        server_id: ServerId,
        connection_id: ConnectionId,
        protocol: &WebSocketProtocol,
    ) -> HandshakeDecision {
        let event = Event::new(
            &WEBSOCKET_HANDSHAKE_EVENT,
            serde_json::json!({
                "path": head.path(),
                "query": head.query(),
                "subprotocols": head.offered_subprotocols(),
                "answer_with": actions::handshake_answer_with(&head.offered_subprotocols()),
                "origin": head.header("origin").unwrap_or(""),
                "headers": head.headers_json(),
                "client_ip": peer_addr.ip().to_string(),
                "client_port": peer_addr.port(),
            }),
        );

        let result = match call_llm(
            llm_client,
            app_state,
            server_id,
            Some(connection_id),
            &event,
            protocol,
        )
        .await
        {
            Ok(r) => r,
            Err(e) => {
                // The 503 reason is a fixed string; the backend's error text stays here. The
                // two categories are kept apart in the log because the wire cannot carry the
                // distinction — an HTTP error body is all a pre-upgrade client ever sees.
                let tag = match crate::utils::wire_failure::WireFailure::classify(&e) {
                    crate::utils::wire_failure::WireFailure::Overloaded => {
                        "fail_closed_llm_overloaded"
                    }
                    crate::utils::wire_failure::WireFailure::Unavailable => "fail_closed_llm_error",
                };
                Log::new(Some(status_tx)).error(format!(
                    "WebSocket upgrade from {} refused decision={}: handler error ({})",
                    peer_addr, tag, e
                ));
                return HandshakeDecision::Reject {
                    status: 503,
                    reason: "The upgrade handler failed, so the connection was not opened"
                        .to_string(),
                };
            }
        };

        for msg in result.messages {
            let _ = status_tx.send(msg);
        }

        for r in &result.protocol_results {
            if let ActionResult::Custom { name, data } = r {
                match name.as_str() {
                    "accept_websocket" => {
                        let subprotocol = data
                            .get("subprotocol")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string());
                        Log::new(Some(status_tx)).info(format!(
                            "WebSocket upgrade from {} accepted decision=model_answer{}",
                            peer_addr,
                            subprotocol
                                .as_ref()
                                .map(|s| format!(" (subprotocol {s})"))
                                .unwrap_or_default()
                        ));
                        return HandshakeDecision::Accept { subprotocol };
                    }
                    "reject_websocket" => {
                        let status = data
                            .get("status_code")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(403) as u16;
                        Log::new(Some(status_tx)).info(format!(
                            "WebSocket upgrade from {} refused decision=model_reject ({})",
                            peer_addr, status
                        ));
                        return HandshakeDecision::Reject {
                            status,
                            reason: data
                                .get("reason")
                                .and_then(|v| v.as_str())
                                .unwrap_or("Upgrade refused")
                                .to_string(),
                        };
                    }
                    _ => {}
                }
            }
        }

        // Structurally distinct from the explicit rejection above: this is the fail-closed
        // path, and it says so in the log rather than quietly behaving like an approval. The
        // two tags separate a handler that said nothing at all from one whose answer this
        // protocol could not use — the second is a prompt or an executor problem, the first
        // is an absent decision.
        let tag = if result.raw_actions.is_empty() {
            "fail_closed_no_action"
        } else {
            "fail_closed_bad_action"
        };
        Log::new(Some(status_tx)).error(format!(
            "WebSocket upgrade from {} refused decision={}: handler returned neither \
             accept_websocket nor reject_websocket",
            peer_addr, tag
        ));
        HandshakeDecision::Reject {
            status: 503,
            reason: "The upgrade handler did not accept the connection".to_string(),
        }
    }

    /// The post-upgrade loop: writer task, `websocket_connection_opened`, then frames.
    #[allow(clippy::too_many_arguments)]
    async fn run_connection(
        ws_stream: WebSocketStream<deflate::DeflateStream<TcpStream>>,
        mut out_rx: mpsc::UnboundedReceiver<WsOut>,
        permit: Arc<crate::server::accept_bounded::ConnectionPermit>,
        ctx: ConnCtx,
        path: String,
        peer_addr: SocketAddr,
        idle_timeout: std::time::Duration,
        deflate: Option<deflate::DeflateParams>,
    ) {
        let (mut sink, mut stream) = ws_stream.split();

        // Single writer. Every producer — the message handlers, an async push action, a
        // scheduled task — funnels through `out_rx`, so no two frames can interleave and no
        // lock is ever held across the `.send().await`.
        let writer_status_tx = ctx.status_tx.clone();
        let writer_conn = ctx.connection_id;
        // The writer's own claim on the connection's slot. The read loop below waits at most
        // five seconds for this task, so it can outlive the task that accepted the peer; the
        // slot is released by whichever of the two drops its `Arc` last.
        let writer_permit = Arc::clone(&permit);
        let writer_handle = tokio::spawn(async move {
            let _permit = writer_permit;
            while let Some(out) = out_rx.recv().await {
                let closing = matches!(out, WsOut::Close { .. });
                let message = match out {
                    WsOut::Text(t) => Message::Text(t),
                    WsOut::Binary(b) => Message::Binary(b),
                    WsOut::Ping(p) => Message::Ping(p),
                    WsOut::Close { code, reason } => Message::Close(Some(CloseFrame {
                        code: CloseCode::from(code),
                        reason: reason.into(),
                    })),
                };
                if let Err(e) = sink.send(message).await {
                    Log::new(Some(&writer_status_tx))
                        .debug(format!("WebSocket write failed on {}: {}", writer_conn, e));
                    break;
                }
                if closing {
                    // RFC 6455 section 7.1.2: after sending a close frame the endpoint sends
                    // nothing more. The read half stays open until the peer's close arrives.
                    let _ = sink.flush().await;
                    break;
                }
            }
            let _ = sink.flush().await;
        });

        // `websocket_connection_opened` — the server's chance to speak first.
        let opened_event = Event::new(
            &WEBSOCKET_CONNECTION_OPENED_EVENT,
            serde_json::json!({
                "path": path,
                "answer_with": actions::OPENED_ANSWER_WITH,
                "subprotocol": ctx.subprotocol.clone().unwrap_or_default(),
                "permessage_deflate": deflate.map(|p| p.to_json()),
                "client_ip": peer_addr.ip().to_string(),
                "client_port": peer_addr.port(),
            }),
        );
        ctx.protocol.set_speaking_first(true);
        let opened_answer = call_llm(
            &ctx.llm_client,
            &ctx.app_state,
            ctx.server_id,
            Some(ctx.connection_id),
            &opened_event,
            ctx.protocol.as_ref(),
        )
        .await;
        ctx.protocol.set_speaking_first(false);
        match opened_answer {
            Ok(result) => {
                for msg in result.messages {
                    let _ = ctx.status_tx.send(msg);
                }
            }
            Err(e) => {
                // Not fatal: nothing has been promised to the client yet, so the connection
                // stays up and the first real message gets its own chance.
                //
                // `llm_error_notice_only` rather than `fail_closed_*`: the upgrade was already
                // decided by `websocket_handshake`, this event only offers the server a chance
                // to speak first, and nothing was refused or closed. Tagging it fail-closed
                // would put a line in front of every `grep decision=fail_closed` that denied
                // nothing.
                Log::new(Some(&ctx.status_tx)).warn(format!(
                    "WebSocket connection-opened handler failed on {} \
                     decision=llm_error_notice_only: {}",
                    ctx.connection_id, e
                ));
            }
        }

        // Frame loop. Handlers run in their own tasks so a slow model call does not stall
        // reading; the per-connection state machine keeps them from overlapping.
        let mut handlers: JoinSet<()> = JoinSet::new();
        let ctx = Arc::new(ctx);

        // Whether this connection is doing anything: touched by every inbound frame, held busy
        // by every handler for the whole of its answer. See IDLE_TIMEOUT.
        let activity = Arc::new(crate::server::accept_bounded::ConnectionActivity::new());

        loop {
            let keepalive_tx = ctx.out_tx.clone();
            let message = tokio::select! {
                message = stream.next() => message,
                _ = crate::server::accept_bounded::watch_idle_with_probe(
                    Arc::clone(&activity),
                    idle_timeout,
                    move || {
                        let _ = keepalive_tx.send(WsOut::Ping(
                            crate::server::accept_bounded::KEEPALIVE_PING_PAYLOAD.to_vec(),
                        ));
                    },
                ) => {
                    Log::new(Some(&ctx.status_tx)).info(format!(
                        "WebSocket {} sent no frame for {}s, not even a Pong; closing \
                         decision=idle_timeout",
                        ctx.connection_id,
                        idle_timeout.as_secs()
                    ));
                    let _ = ctx.out_tx.send(WsOut::Close {
                        code: 1001,
                        reason: "idle timeout".to_string(),
                    });
                    break;
                }
            };
            let Some(message) = message else { break };
            activity.touch();
            match message {
                Ok(Message::Text(text)) => {
                    trace!("WebSocket {} <- text {:?}", ctx.connection_id, text);
                    // Queued here, in the read loop, so messages keep their arrival
                    // order; a handler task is started only when none is running.
                    if Self::enqueue_inbound(&ctx, Inbound::Text(text)).await {
                        let ctx = ctx.clone();
                        let busy = activity.busy();
                        handlers.spawn(async move {
                            let _busy = busy;
                            Self::handle_inbound(ctx).await;
                        });
                    }
                }
                Ok(Message::Binary(bytes)) => {
                    trace!(
                        "WebSocket {} <- binary {} bytes: {}",
                        ctx.connection_id,
                        bytes.len(),
                        hex::encode(&bytes)
                    );
                    // Queued here, in the read loop, so messages keep their arrival
                    // order; a handler task is started only when none is running.
                    if Self::enqueue_inbound(&ctx, Inbound::Binary(bytes)).await {
                        let ctx = ctx.clone();
                        let busy = activity.busy();
                        handlers.spawn(async move {
                            let _busy = busy;
                            Self::handle_inbound(ctx).await;
                        });
                    }
                }
                Ok(Message::Ping(payload)) => {
                    // The pong is already queued by the framing layer.
                    // Queued here, in the read loop, so messages keep their arrival
                    // order; a handler task is started only when none is running.
                    if Self::enqueue_inbound(&ctx, Inbound::Ping(payload)).await {
                        let ctx = ctx.clone();
                        let busy = activity.busy();
                        handlers.spawn(async move {
                            let _busy = busy;
                            Self::handle_inbound(ctx).await;
                        });
                    }
                }
                Ok(Message::Pong(_)) => {
                    debug!("WebSocket {} <- pong", ctx.connection_id);
                }
                Ok(Message::Close(frame)) => {
                    let (code, reason) = match &frame {
                        Some(f) => (u16::from(f.code), f.reason.to_string()),
                        // 1005 "no status received" is the RFC's name for an empty close.
                        None => (1005u16, String::new()),
                    };
                    Log::new(Some(&ctx.status_tx)).info(format!(
                        "WebSocket {} closed by client (code {} reason {:?})",
                        ctx.connection_id, code, reason
                    ));
                    // Run inline: this is the terminal event and must not race the shutdown.
                    Self::handle_close(ctx.clone(), code, reason).await;
                    break;
                }
                Ok(Message::Frame(_)) => {}
                Err(e) => {
                    let text = e.to_string();
                    if text.contains("permessage-deflate") {
                        // The deflate layer refused the peer's bytes: a message that inflates
                        // past the limit, or compressed framing RFC 7692 forbids. 1009 is the
                        // RFC 6455 code for the first; the peer is told before the close.
                        Log::new(Some(&ctx.status_tx)).warn(format!(
                            "WebSocket {} closed: {} decision=permessage_deflate_refused",
                            ctx.connection_id, text
                        ));
                        let _ = ctx.out_tx.send(WsOut::Close {
                            code: 1009,
                            reason: "message too big".to_string(),
                        });
                    } else {
                        Log::new(Some(&ctx.status_tx)).debug(format!(
                            "WebSocket {} read error: {}",
                            ctx.connection_id, text
                        ));
                    }
                    break;
                }
            }
        }

        // Let in-flight handlers finish so a reply produced just before the peer went away
        // still reaches the writer.
        while handlers.join_next().await.is_some() {}

        // Dropping every sender ends the writer task.
        drop(ctx);
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), writer_handle).await;
        // Explicit rather than implicit: this is the read side's half of the shared permit,
        // and dropping it here — after the writer has been waited for — is what makes the
        // slot come back exactly once both halves are done with the connection.
        drop(permit);
    }

    /// Put one inbound message on the queue through the Idle -> Processing -> Accumulating
    /// machine. `true` when no handler is running and the caller must start
    /// [`Self::handle_inbound`].
    ///
    /// Called from the read loop itself, not from a spawned task: two tasks racing for the
    /// lock could queue the second message after the third.
    async fn enqueue_inbound(ctx: &ConnCtx, frame: Inbound) -> bool {
        let mut data = ctx.data.lock().await;
        if data.state == HandlerState::Processing {
            data.queued.push_back(frame);
            Log::new(Some(&ctx.status_tx))
                .debug(format!("Queued a message for {}", ctx.connection_id));
            return false;
        }
        data.state = HandlerState::Processing;

        // Join onto anything the model deferred with wait_for_websocket_data.
        match data.pending.take() {
            Some(pending) => match pending.merge(frame) {
                Ok(merged) => data.queued.push_front(merged),
                Err((held, new)) => {
                    // Different kinds cannot be joined; process them in arrival order.
                    data.queued.push_front(new);
                    data.queued.push_front(held);
                }
            },
            None => data.queued.push_front(frame),
        }
        true
    }

    /// Answer queued messages until the queue is empty, then go back to Idle.
    async fn handle_inbound(ctx: Arc<ConnCtx>) {
        loop {
            // With batching on, every data message queued while the model was answering the
            // previous one is answered in one call; off, one queued message per call. A ping
            // is a control frame, not conversation, and is always answered alone.
            let batching = ctx
                .app_state
                .server_conversation_settings(ctx.server_id)
                .await
                .is_some_and(|(_, batching)| batching);
            let mut batch: Vec<Inbound> = {
                let mut data = ctx.data.lock().await;
                let Some(first) = data.queued.pop_front() else {
                    data.state = HandlerState::Idle;
                    return;
                };
                let batch_data = batching && !matches!(first, Inbound::Ping(_));
                let mut batch = vec![first];
                while batch_data
                    && batch.len() < crate::protocol::metadata::MAX_BATCH_EVENTS
                    && matches!(
                        data.queued.front(),
                        Some(Inbound::Text(_) | Inbound::Binary(_))
                    )
                {
                    if let Some(more) = data.queued.pop_front() {
                        batch.push(more);
                    }
                }
                batch
            };

            let sub = ctx.subprotocol.clone().unwrap_or_default();
            let events: Vec<Event> = batch.iter().map(|m| inbound_event(m, &sub)).collect();
            // The newest message is the batch's trigger: it names the decision line, and it
            // is the one `wait_for_websocket_data` holds back.
            let (Some(next), Some(event)) = (batch.pop(), events.last()) else {
                continue;
            };

            match call_llm_batch(
                &ctx.llm_client,
                &ctx.app_state,
                ctx.server_id,
                Some(ctx.connection_id),
                &events,
                ctx.protocol.as_ref(),
            )
            .await
            {
                Ok(result) => {
                    for msg in result.messages {
                        let _ = ctx.status_tx.send(msg);
                    }

                    let mut should_close = false;
                    let mut should_wait = false;
                    for r in &result.protocol_results {
                        match r {
                            ActionResult::CloseConnection => should_close = true,
                            ActionResult::WaitForMore => should_wait = true,
                            _ => {}
                        }
                    }

                    // One `decision=` line per message. The silent case is the one that used
                    // to vanish entirely: a handler that returns nothing sends no frame, and
                    // this connection simply goes quiet — indistinguishable, in the log, from
                    // a handler that deliberately answered with nothing.
                    let log = Log::new(Some(&ctx.status_tx));
                    let subject =
                        format!("WebSocket {} {}", ctx.connection_id, event.event_type.id);
                    if result.raw_actions.is_empty() {
                        log.warn(format!(
                            "{} decision=model_silent: no action, so no frame was sent",
                            subject
                        ));
                    } else if !result.failures.is_empty() && result.protocol_results.is_empty() {
                        log.error(format!(
                            "{} decision=fail_closed_bad_action: {}",
                            subject,
                            result
                                .failures
                                .iter()
                                .map(|f| format!("{}: {}", f.action, f.error))
                                .collect::<Vec<_>>()
                                .join("; ")
                        ));
                    } else if should_close {
                        log.info(format!(
                            "{} decision=model_reject: the handler closed the connection",
                            subject
                        ));
                    } else {
                        log.info(format!("{} decision=model_answer", subject));
                    }

                    if should_wait {
                        let mut data = ctx.data.lock().await;
                        data.pending = Some(next);
                        data.state = HandlerState::Accumulating;
                        Log::new(Some(&ctx.status_tx)).debug(format!(
                            "Holding a message from {} until more arrives",
                            ctx.connection_id
                        ));
                        return;
                    }
                    if should_close {
                        let mut data = ctx.data.lock().await;
                        data.state = HandlerState::Idle;
                        data.queued.clear();
                        return;
                    }
                }
                Err(e) => {
                    // Do not reset to Idle and write nothing: the peer would wait for a reply
                    // that is never coming. 1011 is the RFC's "the server hit an unexpected
                    // condition"; 1013 ("try again later") is the one the RFC gives for a
                    // temporarily saturated server, so an overloaded backend tells a client to
                    // back off rather than to record a permanent fault. The reason string is a
                    // fixed literal in both cases — a close reason is peer-visible, and the
                    // backend's error text belongs in the line below it, not on the wire.
                    let overloaded = crate::llm::is_overload_error(&e);
                    let (code, tag) = if overloaded {
                        (1013u16, "fail_closed_llm_overloaded")
                    } else {
                        (1011u16, "fail_closed_llm_error")
                    };
                    Log::new(Some(&ctx.status_tx)).error(format!(
                        "WebSocket {} {} decision={}: handler failed, closing with {} ({})",
                        ctx.connection_id, event.event_type.id, tag, code, e
                    ));
                    let _ = ctx.out_tx.send(WsOut::Close {
                        code,
                        reason: "handler failed".to_string(),
                    });
                    let mut data = ctx.data.lock().await;
                    data.state = HandlerState::Idle;
                    data.queued.clear();
                    return;
                }
            }
        }
    }

    /// Emit `websocket_close` for a client-initiated close.
    async fn handle_close(ctx: Arc<ConnCtx>, code: u16, reason: String) {
        let event = Event::new(
            &WEBSOCKET_CLOSE_EVENT,
            serde_json::json!({ "code": code, "reason": reason }),
        );
        match call_llm(
            &ctx.llm_client,
            &ctx.app_state,
            ctx.server_id,
            Some(ctx.connection_id),
            &event,
            ctx.protocol.as_ref(),
        )
        .await
        {
            Ok(result) => {
                for msg in result.messages {
                    let _ = ctx.status_tx.send(msg);
                }
            }
            Err(e) => {
                // `llm_error_notice_only`: `websocket_close` fires because the peer has
                // already closed, so there is nothing left to refuse and nothing to send.
                // Raised from DEBUG to WARN — a backend failure that the operator can only
                // see by turning debug logging on is a backend failure nobody sees.
                Log::new(Some(&ctx.status_tx)).warn(format!(
                    "WebSocket close handler failed on {} decision=llm_error_notice_only: {}",
                    ctx.connection_id, e
                ));
            }
        }
    }

    async fn cleanup(
        app_state: &Arc<AppState>,
        server_id: ServerId,
        connection_id: ConnectionId,
        status_tx: &mpsc::UnboundedSender<String>,
    ) {
        actions::unregister_connection(connection_id);
        app_state
            .close_connection_on_server(server_id, connection_id)
            .await;
        let _ = status_tx.send("__UPDATE_UI__".to_string());
    }
}

/// The outcome of the `websocket_handshake` event.
enum HandshakeDecision {
    Accept { subprotocol: Option<String> },
    Reject { status: u16, reason: String },
}

/// Read bytes until the blank line that terminates an HTTP request head.
///
/// Returns the head (without the terminating CRLFCRLF) and any bytes that followed it in the
/// same read, which belong to the WebSocket stream.
async fn read_request_head(socket: &mut TcpStream) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut buf: Vec<u8> = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];

    loop {
        if let Some(pos) = find_head_end(&buf) {
            let leftover = buf.split_off(pos + 4);
            buf.truncate(pos);
            return Ok((buf, leftover));
        }
        if buf.len() > MAX_REQUEST_HEAD {
            anyhow::bail!("HTTP request head exceeded {MAX_REQUEST_HEAD} bytes");
        }
        let n = socket
            .read(&mut chunk)
            .await
            .context("read failed while waiting for the HTTP request head")?;
        if n == 0 {
            anyhow::bail!("peer closed before sending a complete HTTP request head");
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

/// Index of the `\r\n\r\n` that ends the request head.
fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}
