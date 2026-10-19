//! NATS client: NetGet joins a real messaging fabric as a peer.
//!
//! The connection is two tasks, and the split is the whole design:
//!
//! * **Reader** — owns the read half, frames `INFO`/`MSG`/`HMSG`/`+OK`/`-ERR`/`PING`/`PONG`
//!   ([`parse_server_frame`]), answers `PING` with `PONG` itself, and forwards everything that
//!   is a decision over a **bounded** channel.
//! * **Dispatcher** — owns the model. It makes one LLM call at a time, in arrival order, and
//!   also serves the injected-command channel that backs the dashboard's `[ send ]`.
//!
//! Answering `PING` in Rust is not an optimisation. A broker that gets no `PONG` within two
//! ping intervals declares the connection stale and drops it, and an instance created from the
//! dashboard defaults to a `*` → manual rule — so routing the keepalive through the model
//! would mean a human had to answer it, in seconds, forever. The same reasoning is why the
//! reader never blocks on the dispatcher's LLM call: the two tasks exist so that a parked
//! event cannot silence the keepalive.
//!
//! This is the `Idle → Processing → Accumulating` machine of `src/server/tcp/mod.rs` in a
//! different shape. The dispatcher being busy *is* `Processing`, the channel *is*
//! `queued_data`, and there is no `Accumulating` state because NATS frames are self-delimiting
//! — there is never a partial message to accumulate, so `wait_for_more` here means "say
//! nothing", not "the response was cut short".
//!
//! ## The action → event → action cycle, and why there is no depth bound here
//!
//! The chain that matters is: a `MSG` arrives, the model answers with `send_nats_publish`, the
//! bytes go on the wire, and whatever comes back arrives at the reader as another frame and
//! raises another event. That cycle passes through the socket and the reader task, so nothing
//! recurses and no future contains itself — this is the `datalink` case the root `CLAUDE.md`
//! describes, where "the chain continues by itself" and boxing would be ceremony. What bounds
//! it is [`crate::client::llm_budget`]'s per-client call budget, which is the backstop for
//! exactly this shape.
//!
//! Both tasks are registered with [`AppState::register_client_task`]: aborting a task does not
//! abort tasks it spawned, so a reader registered nowhere would keep the socket alive past
//! `remove_client()`.

pub mod actions;

pub mod jetstream;
pub use actions::NatsClientProtocol;

use anyhow::{Context, Result};
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, error, info, trace, warn};

use crate::client::llm_budget::call_llm_for_client_batch;
use crate::client::nats::actions::{
    NatsClientProtocol as Proto, NATS_CLIENT_CONNECTED_EVENT, NATS_CLIENT_ERROR_RECEIVED_EVENT,
    NATS_CLIENT_MESSAGE_RECEIVED_EVENT, NATS_CLIENT_PERMISSION_ERROR_EVENT,
};
use crate::llm::actions::client_trait::{Client, ClientActionResult};
use crate::llm::ollama_client::OllamaClient;
use crate::protocol::Event;
use crate::state::app_state::AppState;
use crate::state::{ClientId, ClientStatus};

/// Longest control line accepted before the peer is treated as not speaking NATS.
///
/// Deliberately far above the server half's 4096: an `INFO` from a real clustered
/// `nats-server` carries a `connect_urls` array with one entry per route, and rejecting the
/// greeting of a large cluster would be a bug that only shows up in production.
pub const MAX_CONTROL_LINE: usize = 65_536;

/// Payload ceiling used until the broker's own `max_payload` has been read from `INFO`, and
/// the floor applied to it afterwards. A broker that advertises less than this still cannot
/// send more than it accepts, so the floor costs nothing and protects the handshake.
pub const DEFAULT_MAX_PAYLOAD: usize = 1_048_576;

/// Hard ceiling on the broker's advertised `max_payload`. A broker is more trusted than a
/// random peer, but "trusted" is not "allowed to name any allocation size it likes".
pub const MAX_ACCEPTED_PAYLOAD: usize = 64 * 1_048_576;

/// Hard ceiling on the reader's frame buffer, over and above whatever any frame declares.
///
/// A frame is at most one control line plus `max_payload` plus its terminator, so anything
/// past that with nothing extractable is a peer that will never complete one.
const MAX_BUFFERED_SLACK: usize = MAX_CONTROL_LINE + 16;

/// How many decision frames may wait for the dispatcher before the reader stops reading.
///
/// Bounded on purpose. If the model is slower than the fabric for long enough to fill this,
/// the reader blocks and the connection eventually goes stale — which is a visible failure,
/// where an unbounded queue is an invisible one that ends in the process dying.
const FRAME_QUEUE_CAPACITY: usize = 256;

/// How long to wait for the broker's `INFO` greeting before giving up on the connection.
///
/// A NATS server writes `INFO` immediately on accept, so anything slower is not a NATS server.
/// Failing here means `connect()` returns `Err` and the client is marked `Error` rather than
/// sitting in `Connected` having never handshaked.
const INFO_TIMEOUT_SECS: u64 = 10;

// ============================================================================
// Wire framing (server -> client)
// ============================================================================

/// One decodable frame in the broker → client direction.
///
/// This is a different grammar from `crate::server::nats::Frame`, which decodes the client →
/// server direction. They share no verbs except `PING`/`PONG`, so they are two parsers rather
/// than one with a mode flag.
#[derive(Debug, Clone, PartialEq)]
pub enum ServerFrame {
    /// `INFO {json}` — the greeting, and occasionally re-sent mid-session when a cluster
    /// changes shape.
    Info(serde_json::Value),
    /// `MSG`/`HMSG`. `headers` is empty for a plain `MSG`.
    Message {
        subject: String,
        sid: String,
        reply_to: Option<String>,
        headers: BTreeMap<String, String>,
        payload: Vec<u8>,
    },
    /// `+OK`, sent per command when the client asked for `verbose`.
    Ok,
    /// `-ERR '<text>'`, carrying the text with its surrounding quotes removed.
    Err(String),
    Ping,
    Pong,
}

/// A frame the connection cannot continue after.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerFrameError {
    UnknownProtocolOperation,
    MaximumControlLineExceeded,
    MaximumPayloadViolation,
    InvalidInfo,
}

impl std::fmt::Display for ServerFrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::UnknownProtocolOperation => "Unknown Protocol Operation",
            Self::MaximumControlLineExceeded => "Maximum Control Line Exceeded",
            Self::MaximumPayloadViolation => "Maximum Payload Violation",
            Self::InvalidInfo => "Invalid INFO document",
        })
    }
}

fn parse_len(token: &str) -> Result<usize, ServerFrameError> {
    token
        .parse::<usize>()
        .map_err(|_| ServerFrameError::UnknownProtocolOperation)
}

/// Try to decode one broker frame from the front of `buf`.
///
/// `Ok(None)` means "only part of a frame has arrived" — read more and try again — and is the
/// normal case on a stream. `Ok(Some((frame, consumed)))` gives the number of bytes to remove
/// from the front, which for a `MSG` includes its byte-counted payload and the CRLF after it.
///
/// A bare LF is accepted as well as CRLF, so a hand-rolled broker (or `nc` on the other end of
/// a test) behaves rather than producing an error on every line.
pub fn parse_server_frame(
    buf: &[u8],
    max_payload: usize,
) -> Result<Option<(ServerFrame, usize)>, ServerFrameError> {
    let skipped = blank_line_prefix_len(buf);
    match parse_one_server_frame(&buf[skipped..], max_payload)? {
        Some((frame, consumed)) => Ok(Some((frame, skipped + consumed))),
        None => Ok(None),
    }
}

/// Length of the leading run of blank lines (`\n`, `\r\n`, or a line of only whitespace).
///
/// Skipping them iteratively rather than by recursing into `parse_server_frame` is the same
/// fix as on the server half, for the same reason: one stack frame per blank line, not in
/// tail position, so a broker (or anything on that socket) writing 8 KB of newlines — one
/// `read` — recursed about 8000 levels and overflowed the stack. A Rust stack overflow is
/// `SIGSEGV`, not a catchable panic, so it aborted the whole NetGet process.
///
/// The reader drains this prefix before parsing too: `parse_server_frame` folds it into
/// `consumed` when a frame follows, but reports `Ok(None)` having consumed nothing when none
/// does, so without the eager drain the buffer would grow by a chunk on every read.
pub fn blank_line_prefix_len(buf: &[u8]) -> usize {
    let mut offset = 0;
    while let Some(nl) = buf[offset..].iter().position(|&b| b == b'\n') {
        let line_end = offset + nl;
        let line = &buf[offset..line_end];
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if !line.iter().all(|b| b.is_ascii_whitespace()) {
            break;
        }
        offset = line_end + 1;
    }
    offset
}

/// Decode one frame from a buffer whose first line is known not to be blank.
fn parse_one_server_frame(
    buf: &[u8],
    max_payload: usize,
) -> Result<Option<(ServerFrame, usize)>, ServerFrameError> {
    let Some(nl) = buf.iter().position(|&b| b == b'\n') else {
        if buf.len() > MAX_CONTROL_LINE {
            return Err(ServerFrameError::MaximumControlLineExceeded);
        }
        return Ok(None);
    };
    if nl > MAX_CONTROL_LINE {
        return Err(ServerFrameError::MaximumControlLineExceeded);
    }

    let mut line_end = nl;
    if line_end > 0 && buf[line_end - 1] == b'\r' {
        line_end -= 1;
    }
    let after_line = nl + 1;

    let line = std::str::from_utf8(&buf[..line_end])
        .map_err(|_| ServerFrameError::UnknownProtocolOperation)?
        .trim();

    let mut parts = line.split_whitespace();
    let verb = parts
        .next()
        .ok_or(ServerFrameError::UnknownProtocolOperation)?;
    let args: Vec<&str> = parts.collect();

    if verb.eq_ignore_ascii_case("PING") {
        return Ok(Some((ServerFrame::Ping, after_line)));
    }
    if verb.eq_ignore_ascii_case("PONG") {
        return Ok(Some((ServerFrame::Pong, after_line)));
    }
    if verb.eq_ignore_ascii_case("+OK") {
        return Ok(Some((ServerFrame::Ok, after_line)));
    }
    if verb.eq_ignore_ascii_case("-ERR") {
        // `-ERR '<text>'`. The quotes are part of the framing, not of the message.
        let text = line[verb.len()..].trim();
        let text = text
            .strip_prefix('\'')
            .and_then(|t| t.strip_suffix('\''))
            .unwrap_or(text);
        return Ok(Some((ServerFrame::Err(text.to_string()), after_line)));
    }
    if verb.eq_ignore_ascii_case("INFO") {
        // The document is the remainder of the line verbatim: splitting on whitespace would
        // break any JSON string containing a space.
        let json_start = line
            .find(char::is_whitespace)
            .ok_or(ServerFrameError::InvalidInfo)?;
        let doc: serde_json::Value = serde_json::from_str(line[json_start..].trim())
            .map_err(|_| ServerFrameError::InvalidInfo)?;
        if !doc.is_object() {
            return Err(ServerFrameError::InvalidInfo);
        }
        return Ok(Some((ServerFrame::Info(doc), after_line)));
    }

    let is_hmsg = verb.eq_ignore_ascii_case("HMSG");
    if is_hmsg || verb.eq_ignore_ascii_case("MSG") {
        // MSG  <subject> <sid> [reply-to] <#bytes>
        // HMSG <subject> <sid> [reply-to] <#header bytes> <#total bytes>
        let (subject, sid, reply_to, header_len, total_len) = if is_hmsg {
            match args.len() {
                4 => (
                    args[0],
                    args[1],
                    None,
                    parse_len(args[2])?,
                    parse_len(args[3])?,
                ),
                5 => (
                    args[0],
                    args[1],
                    Some(args[2].to_string()),
                    parse_len(args[3])?,
                    parse_len(args[4])?,
                ),
                _ => return Err(ServerFrameError::UnknownProtocolOperation),
            }
        } else {
            match args.len() {
                3 => (args[0], args[1], None, 0, parse_len(args[2])?),
                4 => (
                    args[0],
                    args[1],
                    Some(args[2].to_string()),
                    0,
                    parse_len(args[3])?,
                ),
                _ => return Err(ServerFrameError::UnknownProtocolOperation),
            }
        };

        if subject.is_empty() || sid.is_empty() {
            return Err(ServerFrameError::UnknownProtocolOperation);
        }
        if header_len > total_len {
            return Err(ServerFrameError::UnknownProtocolOperation);
        }
        // The limit applies to the whole declared size, header block included — the same fix
        // as on the server half. Bounding only `total_len - header_len` left `header_len`
        // unbounded, and `header_len == total_len` gives a zero-length body that passed both
        // checks, so `HMSG s 1 4000000000 4000000000` made the reader buffer toward 4 GB and
        // `HMSG s 1 <usize::MAX> <usize::MAX>` overflowed the index below.
        if total_len > max_payload {
            return Err(ServerFrameError::MaximumPayloadViolation);
        }

        let Some(body_end) = after_line.checked_add(total_len) else {
            return Err(ServerFrameError::MaximumPayloadViolation);
        };
        if buf.len() <= body_end {
            return Ok(None);
        }
        let terminator = match buf[body_end] {
            b'\r' => {
                if buf.len() < body_end + 2 {
                    return Ok(None);
                }
                if buf[body_end + 1] != b'\n' {
                    return Err(ServerFrameError::UnknownProtocolOperation);
                }
                2
            }
            b'\n' => 1,
            _ => return Err(ServerFrameError::UnknownProtocolOperation),
        };

        let headers = if header_len > 0 {
            parse_headers(&buf[after_line..after_line + header_len])
        } else {
            BTreeMap::new()
        };
        let payload = buf[after_line + header_len..body_end].to_vec();

        return Ok(Some((
            ServerFrame::Message {
                subject: subject.to_string(),
                sid: sid.to_string(),
                reply_to,
                headers,
                payload,
            },
            body_end + terminator,
        )));
    }

    Err(ServerFrameError::UnknownProtocolOperation)
}

/// Decode a `NATS/1.0` header block into name/value pairs.
///
/// The version line is skipped and malformed lines are dropped rather than failing the frame:
/// a header a broker invented is not a reason to tear down a session.
pub fn parse_headers(block: &[u8]) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let text = String::from_utf8_lossy(block);
    for (index, line) in text.split('\n').enumerate() {
        let line = line.trim_end_matches('\r');
        if index == 0 {
            // `NATS/1.0 404 No Messages`: a status, exposed the way nats.go exposes it.
            let mut parts = line.splitn(3, ' ');
            parts.next();
            if let Some(code) = parts
                .next()
                .filter(|c| c.len() == 3 && c.bytes().all(|b| b.is_ascii_digit()))
            {
                out.insert("Status".to_string(), code.to_string());
                if let Some(text) = parts.next().map(str::trim).filter(|t| !t.is_empty()) {
                    out.insert("Description".to_string(), text.to_string());
                }
            }
            continue;
        }
        if line.trim().is_empty() {
            continue;
        }
        if let Some((name, value)) = line.split_once(':') {
            let name = name.trim();
            if !name.is_empty() {
                out.insert(name.to_string(), value.trim().to_string());
            }
        }
    }
    out
}

/// Render a payload for an event: the text itself when every byte is printable, hex otherwise.
///
/// The companion `payload_encoding` is what makes this reversible — echo both back on
/// `send_nats_publish` and the exact received bytes go out again. Sniffing on the way back in
/// would not be reversible, which is why the outbound side takes an explicit `encoding`.
pub fn payload_for_event(payload: &[u8]) -> (String, &'static str) {
    if payload
        .iter()
        .all(|&b| b.is_ascii_graphic() || b.is_ascii_whitespace())
    {
        (String::from_utf8_lossy(payload).to_string(), "utf8")
    } else {
        (hex::encode(payload), "hex")
    }
}

/// Split `-ERR 'Permissions Violation for Publish to "orders.eu"'` into the parts the model
/// can act on.
///
/// Returns `(operation, subject)` where operation is `"publish"`, `"subscription"` or
/// `"unknown"`. A permissions violation is the one `-ERR` a broker does not hang up after, so
/// telling the model *which* subject was denied is the difference between it retrying forever
/// and it choosing another.
pub fn classify_permission_error(message: &str) -> (&'static str, Option<String>) {
    let lower = message.to_ascii_lowercase();
    let operation = if lower.contains("publish") {
        "publish"
    } else if lower.contains("subscription") || lower.contains("subscribe") {
        "subscription"
    } else {
        "unknown"
    };

    // The subject is quoted in the real server's text; fall back to the last token otherwise.
    let subject = match (message.find('"'), message.rfind('"')) {
        (Some(start), Some(end)) if end > start + 1 => Some(message[start + 1..end].to_string()),
        _ => message
            .rsplit(' ')
            .next()
            .filter(|token| !token.is_empty() && *token != "to")
            .map(|token| token.trim_matches(['"', '\'']).to_string()),
    };
    (operation, subject)
}

/// True for the `-ERR` texts a broker treats as fatal (which is everything except a
/// permissions violation).
fn is_permission_error(message: &str) -> bool {
    message
        .to_ascii_lowercase()
        .contains("permissions violation")
}

// ============================================================================
// Connection
// ============================================================================

/// Startup parameters, already validated. See `get_startup_parameters()` in `actions.rs`.
#[derive(Debug, Clone)]
pub struct NatsConnectOptions {
    /// `name` field of the CONNECT document.
    pub client_name: String,
    /// Ask the broker to acknowledge every command with `+OK`.
    pub verbose: bool,
    /// Subjects subscribed to immediately after CONNECT, before the model is asked anything.
    pub subscribe_subjects: Vec<String>,
}

impl Default for NatsConnectOptions {
    fn default() -> Self {
        Self {
            client_name: "netget".to_string(),
            verbose: false,
            subscribe_subjects: Vec::new(),
        }
    }
}

/// What a dispatched answer asked the connection to do next.
enum Flow {
    Continue,
    Disconnect,
}

pub struct NatsClient;

impl NatsClient {
    /// Connect to a NATS broker and hand the session to the model.
    ///
    /// Returns only once `INFO` has been read and `CONNECT` written, so a peer that is not a
    /// NATS broker is an `Err` the caller turns into `ClientStatus::Error` rather than a client
    /// that reports `Connected` and never handshaked.
    pub async fn connect_with_llm_actions(
        remote_addr: String,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        client_id: ClientId,
        options: NatsConnectOptions,
    ) -> Result<SocketAddr> {
        let stream = TcpStream::connect(&remote_addr)
            .await
            .with_context(|| format!("Failed to connect to NATS broker at {}", remote_addr))?;
        // Control lines are small and latency-sensitive; Nagle would hold a SUB back waiting
        // for company. A failure here is not worth refusing the connection over.
        let _ = stream.set_nodelay(true);

        let local_addr = stream.local_addr()?;
        let remote_sock_addr = stream.peer_addr()?;

        let (mut read_half, write_half) = tokio::io::split(stream);
        let write_half = Arc::new(Mutex::new(write_half));

        // Command channel first, before anything that can park.
        //
        // The nats_connected event below goes through the routing table, and a `*` -> manual
        // rule holds it until a human answers. Registering afterwards would make the
        // dashboard's [ send ] read "no command channel" for that entire park, which looks
        // like a protocol limitation and is only a queue that does not exist yet.
        let command_rx =
            crate::client::command_support::register_command_channel(&app_state, client_id).await;

        // ---- Handshake: read INFO, write CONNECT ----------------------------------------
        let mut buffer: Vec<u8> = Vec::with_capacity(8192);
        let info = tokio::time::timeout(
            std::time::Duration::from_secs(INFO_TIMEOUT_SECS),
            Self::read_info(&mut read_half, &mut buffer),
        )
        .await
        .map_err(|_| {
            anyhow::anyhow!(
                "No INFO greeting from {} within {}s. A NATS broker writes INFO immediately on \
                 accept, so this peer is not speaking NATS.",
                remote_addr,
                INFO_TIMEOUT_SECS
            )
        })??;

        let max_payload = info
            .get("max_payload")
            .and_then(|v| v.as_u64())
            .map(|v| (v as usize).clamp(DEFAULT_MAX_PAYLOAD, MAX_ACCEPTED_PAYLOAD))
            .unwrap_or(DEFAULT_MAX_PAYLOAD);

        let connect_doc = serde_json::json!({
            "verbose": options.verbose,
            "pedantic": false,
            "tls_required": false,
            "name": options.client_name,
            "lang": "rust",
            "version": env!("CARGO_PKG_VERSION"),
            "protocol": 1,
            "headers": info.get("headers").and_then(|v| v.as_bool()).unwrap_or(false),
            "no_responders": false,
            "echo": true,
        });

        // CONNECT, then the startup subscriptions, then PING — one write, in that order. The
        // PING is what a real client sends to learn that CONNECT was accepted; the PONG comes
        // back to the reader and is logged, not surfaced.
        let mut handshake = format!("CONNECT {}\r\n", connect_doc).into_bytes();
        let mut subscriptions = Vec::new();
        for (index, subject) in options.subscribe_subjects.iter().enumerate() {
            let sid = (index + 1).to_string();
            handshake.extend_from_slice(format!("SUB {} {}\r\n", subject, sid).as_bytes());
            subscriptions.push(serde_json::json!({"subject": subject, "sid": sid}));
        }
        // JetStream replies come back under one inbox, subscribed once.
        let jetstream = info
            .get("jetstream")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let js_inbox = jetstream::inbox_for(client_id);
        if jetstream {
            handshake.extend_from_slice(
                format!("SUB {js_inbox}.> {}\r\n", jetstream::INBOX_SID).as_bytes(),
            );
        }
        handshake.extend_from_slice(b"PING\r\n");
        {
            let mut guard = write_half.lock().await;
            guard.write_all(&handshake).await?;
            guard.flush().await?;
        }

        info!(
            "NATS client {} connected to {} (local: {}), broker={} version={} max_payload={} \
             startup_subscriptions={}",
            client_id,
            remote_sock_addr,
            local_addr,
            info.get("server_name")
                .and_then(|v| v.as_str())
                .unwrap_or("?"),
            info.get("version").and_then(|v| v.as_str()).unwrap_or("?"),
            max_payload,
            subscriptions.len(),
        );
        app_state
            .update_client_status(client_id, ClientStatus::Connected)
            .await;
        let _ = status_tx.send(format!(
            "[CLIENT] NATS client {} connected to {} ({} startup subscription(s))",
            client_id,
            remote_sock_addr,
            subscriptions.len()
        ));
        let _ = status_tx.send("__UPDATE_UI__".to_string());

        // ---- Reader task -----------------------------------------------------------------
        let (frame_tx, frame_rx) = mpsc::channel::<ServerFrame>(FRAME_QUEUE_CAPACITY);

        let reader_state = app_state.clone();
        let reader_status_tx = status_tx.clone();
        let reader_write_half = write_half.clone();
        let reader_handle = tokio::spawn(async move {
            Self::run_reader(
                read_half,
                reader_write_half,
                buffer,
                max_payload,
                frame_tx,
                client_id,
                reader_state,
                reader_status_tx,
            )
            .await;
        });
        let reader_abort = reader_handle.abort_handle();
        app_state
            .register_client_task(client_id, reader_handle)
            .await;

        // ---- Dispatcher task -------------------------------------------------------------
        let connected_event = Event::new(
            &NATS_CLIENT_CONNECTED_EVENT,
            serde_json::json!({
                "remote_addr": remote_sock_addr.to_string(),
                "server_name": info.get("server_name").and_then(|v| v.as_str()).unwrap_or(""),
                "server_id": info.get("server_id").and_then(|v| v.as_str()).unwrap_or(""),
                "version": info.get("version").and_then(|v| v.as_str()).unwrap_or(""),
                "max_payload": max_payload,
                "headers": info.get("headers").and_then(|v| v.as_bool()).unwrap_or(false),
                "auth_required": info.get("auth_required").and_then(|v| v.as_bool()).unwrap_or(false),
                "tls_required": info.get("tls_required").and_then(|v| v.as_bool()).unwrap_or(false),
                "subscriptions": subscriptions,
                "jetstream": jetstream,
                "info": info,
            }),
        );

        let dispatcher_state = app_state.clone();
        let dispatcher_handle = tokio::spawn(async move {
            Self::run_dispatcher(
                write_half,
                frame_rx,
                command_rx,
                connected_event,
                client_id,
                llm_client,
                dispatcher_state,
                status_tx,
                reader_abort,
                js_inbox,
            )
            .await;
        });
        app_state
            .register_client_task(client_id, dispatcher_handle)
            .await;

        Ok(local_addr)
    }

    /// Read until the broker's `INFO` greeting is complete, leaving anything after it in
    /// `buffer` for the reader task.
    ///
    /// A `PING` before `INFO` would be a protocol violation, so nothing else is tolerated
    /// here: the first frame is the greeting or the peer is not a broker.
    async fn read_info(
        read_half: &mut tokio::io::ReadHalf<TcpStream>,
        buffer: &mut Vec<u8>,
    ) -> Result<serde_json::Value> {
        let mut chunk = vec![0u8; 8192];
        loop {
            match parse_server_frame(buffer, DEFAULT_MAX_PAYLOAD) {
                Ok(Some((ServerFrame::Info(doc), consumed))) => {
                    buffer.drain(..consumed);
                    return Ok(doc);
                }
                Ok(Some((other, _))) => {
                    return Err(anyhow::anyhow!(
                        "Expected INFO as the first NATS frame, got {:?}",
                        other
                    ))
                }
                Ok(None) => {}
                Err(e) => return Err(anyhow::anyhow!("Malformed NATS greeting: {}", e)),
            }

            let n = read_half.read(&mut chunk).await?;
            if n == 0 {
                return Err(anyhow::anyhow!(
                    "Broker closed the connection before sending INFO"
                ));
            }
            buffer.extend_from_slice(&chunk[..n]);
        }
    }

    /// Frame the stream, answer `PING`, forward decisions.
    #[allow(clippy::too_many_arguments)]
    async fn run_reader(
        mut read_half: tokio::io::ReadHalf<TcpStream>,
        write_half: Arc<Mutex<tokio::io::WriteHalf<TcpStream>>>,
        mut buffer: Vec<u8>,
        max_payload: usize,
        frame_tx: mpsc::Sender<ServerFrame>,
        client_id: ClientId,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
    ) {
        let mut chunk = vec![0u8; 8192];
        'outer: loop {
            // Drain every complete frame currently in the buffer before reading again.
            loop {
                // `parse_server_frame` folds a leading run of blank lines into `consumed`
                // when a frame follows one, but reports `Ok(None)` having consumed nothing
                // when none does. Draining here is what stops a peer sending only newlines
                // from growing `buffer` by a chunk on every read.
                let blank = blank_line_prefix_len(&buffer);
                if blank > 0 {
                    buffer.drain(..blank);
                }
                if buffer.len() > max_payload.saturating_add(MAX_BUFFERED_SLACK) {
                    // More buffered than any single frame could need, with none extractable.
                    error!(
                        "NATS client {} buffered {} bytes with no complete frame; closing",
                        client_id,
                        buffer.len()
                    );
                    let _ = status_tx.send(format!(
                        "[CLIENT] ✖ NATS client {} broker sent an unframeable stream",
                        client_id
                    ));
                    break 'outer;
                }
                match parse_server_frame(&buffer, max_payload) {
                    Ok(Some((frame, consumed))) => {
                        buffer.drain(..consumed);
                        match frame {
                            ServerFrame::Ping => {
                                // Answered here, never by the model. See the module docs.
                                let mut guard = write_half.lock().await;
                                if guard.write_all(b"PONG\r\n").await.is_err()
                                    || guard.flush().await.is_err()
                                {
                                    warn!(
                                        "NATS client {} could not answer PING; connection is \
                                         going away",
                                        client_id
                                    );
                                    break 'outer;
                                }
                                trace!("NATS client {} PING -> PONG", client_id);
                            }
                            ServerFrame::Pong => {
                                trace!("NATS client {} received PONG", client_id);
                            }
                            ServerFrame::Ok => {
                                trace!("NATS client {} received +OK", client_id);
                            }
                            ServerFrame::Info(doc) => {
                                // A mid-session INFO is a cluster update, not a new session.
                                // It is logged rather than raised so that "connected" keeps
                                // meaning "connected once".
                                debug!("NATS client {} received updated INFO: {}", client_id, doc);
                            }
                            decision => {
                                if frame_tx.send(decision).await.is_err() {
                                    debug!(
                                        "NATS client {} dispatcher is gone; reader stopping",
                                        client_id
                                    );
                                    break 'outer;
                                }
                            }
                        }
                    }
                    Ok(None) => break,
                    Err(e) => {
                        error!(
                            "NATS client {} could not frame the broker's output ({}); closing",
                            client_id, e
                        );
                        let _ = status_tx.send(format!(
                            "[CLIENT] ✖ NATS client {} protocol error: {}",
                            client_id, e
                        ));
                        break 'outer;
                    }
                }
            }

            match read_half.read(&mut chunk).await {
                Ok(0) => {
                    info!("NATS client {} broker closed the connection", client_id);
                    break;
                }
                Ok(n) => buffer.extend_from_slice(&chunk[..n]),
                Err(e) => {
                    error!("NATS client {} read error: {}", client_id, e);
                    app_state
                        .update_client_status(client_id, ClientStatus::Error(e.to_string()))
                        .await;
                    let _ = status_tx.send("__UPDATE_UI__".to_string());
                    break;
                }
            }
        }

        // Dropping frame_tx is what tells the dispatcher the session is over.
        drop(frame_tx);
        app_state
            .update_client_status(client_id, ClientStatus::Disconnected)
            .await;
        let _ = status_tx.send(format!("[CLIENT] NATS client {} disconnected", client_id));
        let _ = status_tx.send("__UPDATE_UI__".to_string());
    }

    /// Own the model: one LLM call at a time, plus the injected-command channel.
    #[allow(clippy::too_many_arguments)]
    async fn run_dispatcher(
        write_half: Arc<Mutex<tokio::io::WriteHalf<TcpStream>>>,
        mut frame_rx: mpsc::Receiver<ServerFrame>,
        mut command_rx: mpsc::Receiver<crate::state::client_handles::ClientCommand>,
        connected_event: Event,
        client_id: ClientId,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        reader_abort: tokio::task::AbortHandle,
        js_inbox: String,
    ) {
        let protocol = Proto::with_inbox(js_inbox.clone());
        let mut memory = String::new();

        // The connected event runs first, and the reader is already up — so a manual handler
        // may park this for as long as it likes without the keepalive going unanswered.
        let mut flow = Self::ask_and_execute(
            &protocol,
            &write_half,
            std::slice::from_ref(&connected_event),
            &mut memory,
            client_id,
            &llm_client,
            &app_state,
            &status_tx,
        )
        .await;

        while matches!(flow, Flow::Continue) {
            tokio::select! {
                frame = frame_rx.recv() => {
                    let Some(frame) = frame else { break };
                    // This frame, plus — with batching on — every frame already waiting: what
                    // the broker sent while the model was answering. Frames are whole
                    // messages, so each is one event; read per turn because batching is
                    // hot-changeable.
                    let mut events: Vec<Event> =
                        Self::event_for(frame, client_id, &js_inbox).into_iter().collect();
                    if app_state
                        .client_conversation_settings(client_id)
                        .await
                        .is_some_and(|(_, batching)| batching)
                    {
                        while events.len() < crate::protocol::metadata::MAX_BATCH_EVENTS {
                            let Ok(next) = frame_rx.try_recv() else { break };
                            events.extend(Self::event_for(next, client_id, &js_inbox));
                        }
                    }
                    if events.is_empty() {
                        continue;
                    }
                    flow = Self::ask_and_execute(
                        &protocol,
                        &write_half,
                        &events,
                        &mut memory,
                        client_id,
                        &llm_client,
                        &app_state,
                        &status_tx,
                    )
                    .await;
                }
                command = command_rx.recv() => {
                    let Some(command) = command else { break };
                    let disconnect = crate::client::command_support::handle_stream_client_command(
                        &protocol,
                        &write_half,
                        command,
                        client_id,
                        &app_state,
                        &status_tx,
                    )
                    .await;
                    if disconnect {
                        flow = Flow::Disconnect;
                    }
                }
            }
        }

        // Half-close so the broker reads EOF and tears the session down its own way, then stop
        // the reader: it is parked on a socket the peer may keep open indefinitely, and
        // dropping a JoinHandle only detaches it.
        {
            let mut guard = write_half.lock().await;
            let _ = guard.shutdown().await;
        }
        reader_abort.abort();

        app_state
            .update_client_status(client_id, ClientStatus::Disconnected)
            .await;
        // The dispatcher owns the only receiver; dropping the registered handle makes later
        // send_to_client calls fail fast instead of timing out.
        app_state.remove_client_handle(client_id).await;
        let _ = status_tx.send(format!("[CLIENT] NATS client {} session ended", client_id));
        let _ = status_tx.send("__UPDATE_UI__".to_string());
    }

    /// Turn a decision frame into the event the model is asked about.
    ///
    /// Returns `None` for frames the reader should have handled; that is a programming error
    /// rather than a peer error, so it is logged rather than raised.
    fn event_for(frame: ServerFrame, client_id: ClientId, js_inbox: &str) -> Option<Event> {
        match frame {
            ServerFrame::Message {
                subject,
                sid,
                reply_to,
                headers,
                payload,
            } => {
                if sid == jetstream::INBOX_SID {
                    if let Some(event) = jetstream::event_for(
                        js_inbox,
                        &subject,
                        reply_to.as_deref(),
                        &headers,
                        &payload,
                    ) {
                        return Some(event);
                    }
                }
                let (payload, encoding) = payload_for_event(&payload);
                Some(Event::new(
                    &NATS_CLIENT_MESSAGE_RECEIVED_EVENT,
                    serde_json::json!({
                        "subject": subject,
                        "sid": sid,
                        "reply_to": reply_to,
                        "payload": payload,
                        "payload_encoding": encoding,
                        "headers": headers,
                    }),
                ))
            }
            ServerFrame::Err(message) => {
                if is_permission_error(&message) {
                    let (operation, subject) = classify_permission_error(&message);
                    warn!(
                        "NATS client {} was denied: {} (operation={})",
                        client_id, message, operation
                    );
                    Some(Event::new(
                        &NATS_CLIENT_PERMISSION_ERROR_EVENT,
                        serde_json::json!({
                            "message": message,
                            "operation": operation,
                            "subject": subject,
                        }),
                    ))
                } else {
                    warn!("NATS client {} received -ERR: {}", client_id, message);
                    Some(Event::new(
                        &NATS_CLIENT_ERROR_RECEIVED_EVENT,
                        serde_json::json!({
                            "message": message,
                            // Everything except a permissions violation is fatal in NATS: the
                            // broker hangs up right after sending it.
                            "fatal": true,
                        }),
                    ))
                }
            }
            other => {
                debug!(
                    "NATS client {} dispatcher saw a frame the reader owns: {:?}",
                    client_id, other
                );
                None
            }
        }
    }

    /// Ask the model about one event — or, with batching on, every event that was waiting — in
    /// one call, and run every action it answers with.
    ///
    /// The actions are the point. Discarding them — `let _ =`, an `Err`-only arm, a `..` that
    /// swallows the field, or a `debug!` of `.len()` — is the single most common client defect
    /// in this repo: the event fires, the round-trip is paid for, the log shows a reply, and
    /// nothing reaches the wire.
    #[allow(clippy::too_many_arguments)]
    async fn ask_and_execute(
        protocol: &Proto,
        write_half: &Arc<Mutex<tokio::io::WriteHalf<TcpStream>>>,
        events: &[Event],
        memory: &mut String,
        client_id: ClientId,
        llm_client: &OllamaClient,
        app_state: &Arc<AppState>,
        status_tx: &mpsc::UnboundedSender<String>,
    ) -> Flow {
        let instruction = app_state
            .get_instruction_for_client(client_id)
            .await
            .unwrap_or_default();
        let ids = events
            .iter()
            .map(|e| e.id())
            .collect::<Vec<_>>()
            .join("', '");

        let outcome = call_llm_for_client_batch(
            llm_client,
            app_state,
            client_id.to_string(),
            &instruction,
            memory,
            events,
            protocol,
            status_tx,
        )
        .await;

        let result = match outcome {
            Ok(result) => result,
            Err(e) => {
                // Nothing is written to the broker on failure, deliberately: every frame this
                // client can send is a positive assertion (a publish, a subscription), and
                // inventing one because the backend was down would put fabricated traffic on
                // somebody's message bus. The log carries the error; the wire carries nothing.
                error!(
                    "NATS client {} could not answer '{}': {} (decision=fail_closed_llm_error)",
                    client_id, ids, e
                );
                let _ = status_tx.send(format!(
                    "[CLIENT] ✖ NATS client {} could not answer '{}'",
                    client_id, ids
                ));
                return Flow::Continue;
            }
        };

        if let Some(updated) = result.memory_updates {
            *memory = updated;
        }

        if result.actions.is_empty() {
            debug!(
                "NATS client {} answered '{}' with no actions (decision=model_no_actions)",
                client_id, ids
            );
        }

        for action in result.actions {
            match Self::apply_action(protocol, write_half, action, client_id).await {
                Flow::Disconnect => return Flow::Disconnect,
                Flow::Continue => {}
            }
        }
        Flow::Continue
    }

    /// Execute one model-authored action and write whatever it produced.
    async fn apply_action(
        protocol: &Proto,
        write_half: &Arc<Mutex<tokio::io::WriteHalf<TcpStream>>>,
        action: serde_json::Value,
        client_id: ClientId,
    ) -> Flow {
        let executed = match protocol.execute_action(action.clone()) {
            Ok(executed) => executed,
            Err(e) => {
                warn!(
                    "NATS client {} rejected its own model's action {}: {}",
                    client_id, action, e
                );
                return Flow::Continue;
            }
        };

        // `Multiple` nests one level deep at most — that is all the enum's producers use.
        let results = match executed {
            ClientActionResult::Multiple(results) => results,
            single => vec![single],
        };

        let mut flow = Flow::Continue;
        for result in results {
            match result {
                ClientActionResult::SendData(bytes) => {
                    let mut guard = write_half.lock().await;
                    if let Err(e) = guard.write_all(&bytes).await {
                        error!("NATS client {} write failed: {}", client_id, e);
                        return Flow::Disconnect;
                    }
                    if let Err(e) = guard.flush().await {
                        error!("NATS client {} flush failed: {}", client_id, e);
                        return Flow::Disconnect;
                    }
                    trace!(
                        "NATS client {} sent {} bytes: {}",
                        client_id,
                        bytes.len(),
                        String::from_utf8_lossy(&bytes).escape_debug()
                    );
                }
                ClientActionResult::Disconnect => {
                    info!(
                        "NATS client {} disconnecting on the model's request",
                        client_id
                    );
                    flow = Flow::Disconnect;
                }
                ClientActionResult::WaitForMore => {
                    trace!("NATS client {} is waiting for more traffic", client_id);
                }
                ClientActionResult::NoAction => {}
                ClientActionResult::Custom { name, .. } => {
                    warn!(
                        "NATS client {} produced an unexpected custom result '{}'; this \
                         protocol's actions are all SendData",
                        client_id, name
                    );
                }
                ClientActionResult::Multiple(_) => {
                    warn!(
                        "NATS client {} produced a nested Multiple; ignored",
                        client_id
                    );
                }
            }
        }
        flow
    }
}
