//! The HTTP half of a Nostr relay: one request head, then either a WebSocket upgrade (RFC 6455
//! §4.2), the NIP-11 relay information document, or a one-line page for a browser.
//!
//! Hand-written for the same reason `websocket` hand-writes its handshake: the head has to be
//! read before it is known whether the peer wants a WebSocket at all, and NIP-11 is served on
//! the same URL to a plain GET that carries `Accept: application/nostr+json`. Everything below
//! the upgrade — framing, masking, pings, the closing handshake — is tungstenite's.

use serde_json::{json, Value};

/// Largest request head accepted. A real upgrade is well under 2 KiB.
pub const MAX_REQUEST_HEAD: usize = 16 * 1024;

/// A request line and its headers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestHead {
    pub method: String,
    pub target: String,
    pub version: String,
    /// Names lowercased, values trimmed, in order.
    pub headers: Vec<(String, String)>,
}

impl RequestHead {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    fn header_has_token(&self, name: &str, token: &str) -> bool {
        self.headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case(name))
            .any(|(_, v)| v.split(',').any(|t| t.trim().eq_ignore_ascii_case(token)))
    }

    /// The peer asked for a WebSocket.
    pub fn wants_upgrade(&self) -> bool {
        self.header_has_token("upgrade", "websocket")
    }

    /// The peer asked for the NIP-11 document.
    pub fn wants_relay_info(&self) -> bool {
        self.header("accept")
            .is_some_and(|a| a.to_ascii_lowercase().contains("application/nostr+json"))
    }
}

/// Index of the blank line ending the head.
pub fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

/// Parse a request head (without its terminating blank line).
pub fn parse_request_head(bytes: &[u8]) -> Result<RequestHead, String> {
    let text = std::str::from_utf8(bytes).map_err(|_| "request head is not UTF-8".to_string())?;
    let mut lines = text.split("\r\n");
    let mut parts = lines.next().unwrap_or("").split(' ');
    let method = parts.next().unwrap_or("").to_string();
    let target = parts.next().unwrap_or("").to_string();
    let version = parts.next().unwrap_or("").to_string();
    if method.is_empty() || target.is_empty() || !version.starts_with("HTTP/") {
        return Err("malformed request line".to_string());
    }
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| "malformed header line".to_string())?;
        if name.is_empty() || name.ends_with(' ') || name.starts_with([' ', '\t']) {
            return Err("malformed header name".to_string());
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

/// Check an upgrade request against RFC 6455 §4.2.1 and return its `Sec-WebSocket-Key`.
/// The refusal is the status and a fixed reason.
pub fn validate_upgrade(head: &RequestHead) -> Result<String, (u16, &'static str)> {
    if !head.method.eq_ignore_ascii_case("GET") {
        return Err((405, "a WebSocket upgrade is a GET"));
    }
    if head.version != "HTTP/1.1" {
        return Err((505, "a WebSocket upgrade needs HTTP/1.1"));
    }
    if !head.header_has_token("connection", "upgrade") {
        return Err((400, "missing Connection: Upgrade"));
    }
    if head.header("sec-websocket-version") != Some("13") {
        return Err((426, "this relay speaks WebSocket version 13"));
    }
    let key = head
        .header("sec-websocket-key")
        .ok_or((400, "missing Sec-WebSocket-Key"))?;
    use base64::Engine as _;
    match base64::engine::general_purpose::STANDARD.decode(key) {
        Ok(raw) if raw.len() == 16 => Ok(key.to_string()),
        _ => Err((400, "Sec-WebSocket-Key is not a base64 16-byte nonce")),
    }
}

/// The `101 Switching Protocols` answer.
pub fn accept_response(key: &str) -> String {
    let accept = tokio_tungstenite::tungstenite::handshake::derive_accept_key(key.as_bytes());
    format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Accept: {accept}\r\n\r\n"
    )
}

/// NIP-11: "Relays MUST accept CORS requests by sending Access-Control-Allow-Origin,
/// Access-Control-Allow-Headers, and Access-Control-Allow-Methods headers."
const CORS: &str = "Access-Control-Allow-Origin: *\r\nAccess-Control-Allow-Headers: *\r\n\
                    Access-Control-Allow-Methods: GET, OPTIONS\r\n";

/// A complete HTTP response that closes the connection.
pub fn response(status: u16, content_type: &str, extra_headers: &str, body: &str) -> Vec<u8> {
    let phrase = match status {
        200 => "OK",
        204 => "No Content",
        400 => "Bad Request",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        426 => "Upgrade Required",
        431 => "Request Header Fields Too Large",
        503 => "Service Unavailable",
        505 => "HTTP Version Not Supported",
        _ => "Error",
    };
    let mut out = format!("HTTP/1.1 {status} {phrase}\r\n{extra_headers}");
    if status == 426 {
        out.push_str("Sec-WebSocket-Version: 13\r\n");
    }
    out.push_str("Connection: close\r\n");
    if !body.is_empty() {
        out.push_str(&format!("Content-Type: {content_type}\r\n"));
    }
    out.push_str(&format!("Content-Length: {}\r\n\r\n{body}", body.len()));
    out.into_bytes()
}

/// A plain-text error response.
pub fn error_response(status: u16, reason: &str) -> Vec<u8> {
    response(
        status,
        "text/plain; charset=utf-8",
        "",
        &format!("{reason}\n"),
    )
}

/// What a browser (a GET that asks for neither) is shown — the same page nostr-rs-relay serves.
pub fn browser_response() -> Vec<u8> {
    response(
        200,
        "text/plain; charset=utf-8",
        CORS,
        "Please use a Nostr client to connect.\n",
    )
}

/// The CORS preflight answer.
pub fn preflight_response() -> Vec<u8> {
    response(204, "", CORS, "")
}

/// The NIP-11 answer.
pub fn relay_info_response(document: &Value) -> Vec<u8> {
    let body = serde_json::to_string(document).expect("relay info is plain JSON");
    response(200, "application/nostr+json", CORS, &body)
}

/// What NIP-11 describes, all from startup parameters and the relay's own limits.
#[derive(Debug, Clone)]
pub struct RelayInfo {
    pub name: String,
    pub description: String,
    pub supported_nips: Vec<u64>,
    /// The key the relay signs the model's events with (NIP-11 `self`).
    pub relay_pubkey: String,
}

impl RelayInfo {
    pub fn document(&self) -> Value {
        use super::wire;
        json!({
            "name": self.name,
            "description": self.description,
            "self": self.relay_pubkey,
            "supported_nips": self.supported_nips,
            "software": "https://github.com/netget-net/netget",
            "version": env!("CARGO_PKG_VERSION"),
            "limitation": {
                "max_message_length": wire::MAX_MESSAGE_BYTES,
                "max_subscriptions": wire::MAX_SUBSCRIPTIONS,
                "max_filters": wire::MAX_FILTERS,
                "max_subid_length": wire::MAX_SUBSCRIPTION_ID_CHARS,
                "max_event_tags": wire::MAX_TAGS,
                "auth_required": false,
                "payment_required": false,
            },
        })
    }
}
