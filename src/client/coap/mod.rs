//! CoAP client: NetGet sends CoAP requests over UDP and the model decides what to ask.
//!
//! Three tasks per connection, all registered with the client:
//!
//! * **transport** owns the UDP socket and every exchange in flight: message ids and tokens,
//!   Confirmable retransmission (RFC 7252 §4.2, exponential back-off, bounded attempts), empty
//!   ACKs for separate responses and Confirmable notifications, RST for a token it does not know,
//!   Block1 uploads and Block2 reassembly (RFC 7959) and Observe registrations (RFC 7641). It
//!   never waits on the model.
//! * **turns** asks the model about each response, notification or error, in order, and hands
//!   its actions back to the transport. The chain request → response → model → request passes
//!   through that queue, so it needs no recursion.
//! * **commands** runs injected actions (`[ send ]`, MCP `send_to_client`) down the same path.
//!
//! Encoding and decoding are the server's own codec (`src/server/coap/codec.rs`), option
//! numbers and the Block1/Block2 value layout included.

pub mod actions;

pub use actions::CoapClientProtocol;

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use serde_json::{json, Value};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};
use tokio::time::Instant;
use tracing::{debug, error, info, warn};

use crate::client::coap::actions::{
    request_from_action, CoapRequest, ObserveAction, COAP_CONNECTED_EVENT, COAP_ERROR_EVENT,
    COAP_NOTIFICATION_EVENT, COAP_RESPONSE_EVENT, REQUEST_RESULT,
};
use crate::client::llm_budget::call_llm_for_client;
use crate::llm::actions::client_trait::{Client, ClientActionResult};
use crate::llm::actions::protocol_trait::Protocol;
use crate::llm::ollama_client::OllamaClient;
use crate::protocol::Event;
use crate::server::coap::codec::{
    code_class, code_to_string, content_format_name, szx_size, uint_option, BlockValue,
    CoapMessage, MessageType, CODE_CONTINUE, CODE_DELETE, CODE_EMPTY, CODE_GET, CODE_POST,
    CODE_PUT, MAX_MESSAGE_LEN, OPT_ACCEPT, OPT_CONTENT_FORMAT, OPT_ETAG, OPT_LOCATION_PATH,
    OPT_MAX_AGE, OPT_URI_PATH, OPT_URI_QUERY,
};
pub use crate::server::coap::codec::{OPT_BLOCK1, OPT_BLOCK2, OPT_OBSERVE, OPT_SIZE1, OPT_SIZE2};
use crate::state::app_state::AppState;
use crate::state::client_handles::{ClientCommand, ClientSendOutcome};
use crate::state::{AccessLogOwner, ClientId, ClientStatus};

/// Largest body a Block2 transfer may reassemble to. A server that keeps saying "more" past
/// this is reported as `coap_error {kind: body_too_large}` and the exchange is dropped.
pub const MAX_BODY: usize = 64 * 1024;

/// Exchanges in flight, observations included. The next request is refused.
pub const MAX_EXCHANGES: usize = 32;

/// How long to wait for a response once a Confirmable request is acknowledged with an empty
/// ACK (a separate response is coming), or after a Non-confirmable request is sent.
pub const RESPONSE_TIMEOUT: Duration = Duration::from_secs(30);

/// Server message ids remembered to recognise a retransmitted notification or separate
/// response (RFC 7252 §4.5 deduplication).
const RECENT_MIDS: usize = 64;

const TURN_QUEUE_CAPACITY: usize = 256;
const OUTBOUND_CAPACITY: usize = 64;

/// RFC 7252 §4.8 transmission parameters and the Block1 size, from the startup parameters.
#[derive(Debug, Clone, Copy)]
pub struct Reliability {
    pub ack_timeout: Duration,
    pub max_retransmit: u32,
    /// Block1 size exponent: a body over `2^(szx + 4)` bytes is uploaded in blocks.
    pub block_szx: u8,
}

enum Outbound {
    Request {
        request: CoapRequest,
        ack: oneshot::Sender<Result<usize, String>>,
    },
    Disconnect {
        ack: oneshot::Sender<()>,
    },
}

enum Applied {
    Sent(usize),
    Nothing,
    Disconnect,
}

/// One request (or one observation) and everything the transport needs to finish it.
struct Exchange {
    request: CoapRequest,
    /// The message currently on the wire for this exchange, for retransmission.
    message_id: u16,
    datagram: Vec<u8>,
    /// Confirmable and not yet acknowledged.
    awaiting_ack: bool,
    retransmissions: u32,
    interval: Duration,
    /// Next retransmission while `awaiting_ack`; otherwise when to give up waiting for a
    /// response. `None` for a registered observation, which has no end.
    deadline: Option<Instant>,
    /// Block2 reassembly.
    body: Vec<u8>,
    blocks: u32,
    next_block: u32,
    /// The observation was confirmed by a response carrying Observe.
    observing: bool,
    /// A Block1 upload in progress: the block on the wire. `None` once the last block's
    /// response arrived, or for a body that fits one message.
    upload: Option<BlockValue>,
    /// Block1 blocks put on the wire for this request.
    blocks_sent: u32,
}

pub struct CoapClient;

impl CoapClient {
    pub async fn connect_with_llm_actions(
        remote_addr: String,
        reliability: Reliability,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        client_id: ClientId,
    ) -> Result<SocketAddr> {
        if remote_addr.trim().is_empty() {
            return Err(anyhow!(
                "CoAP client needs a remote_addr (host:port); refusing to start without one"
            ));
        }
        let remote = tokio::net::lookup_host(&remote_addr)
            .await
            .with_context(|| format!("cannot resolve CoAP server {remote_addr}"))?
            .next()
            .with_context(|| format!("{remote_addr} resolved to no address"))?;
        let bind = if remote.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let socket = UdpSocket::bind(bind).await?;
        // Connected: the kernel then delivers only datagrams from the server.
        socket.connect(remote).await?;
        let local_addr = socket.local_addr()?;
        info!("CoAP client {client_id} ready for {remote} (local {local_addr})");
        app_state
            .update_client_status(client_id, ClientStatus::Connected)
            .await;
        let _ = status_tx.send(format!("[CLIENT] CoAP client {client_id} ready"));
        let _ = status_tx.send("__UPDATE_UI__".to_string());

        let protocol = Arc::new(CoapClientProtocol::new());
        let (outbound_tx, outbound_rx) = mpsc::channel::<Outbound>(OUTBOUND_CAPACITY);
        let (turn_tx, turn_rx) = mpsc::channel::<Event>(TURN_QUEUE_CAPACITY);

        let command_rx =
            crate::client::command_support::register_command_channel(&app_state, client_id).await;
        app_state
            .spawn_client_task(
                client_id,
                command_loop(
                    command_rx,
                    protocol.clone(),
                    outbound_tx.clone(),
                    client_id,
                    app_state.clone(),
                    status_tx.clone(),
                ),
            )
            .await;
        let turn_abort = app_state
            .spawn_client_task(
                client_id,
                run_turns(
                    turn_rx,
                    outbound_tx,
                    protocol,
                    llm_client,
                    app_state.clone(),
                    status_tx.clone(),
                    client_id,
                ),
            )
            .await;
        let _ = turn_tx.try_send(Event::new(
            &COAP_CONNECTED_EVENT,
            json!({"remote_addr": remote.to_string()}),
        ));
        app_state
            .spawn_client_task(
                client_id,
                run_transport(
                    socket,
                    reliability,
                    outbound_rx,
                    turn_tx,
                    app_state.clone(),
                    status_tx,
                    client_id,
                    turn_abort,
                ),
            )
            .await;
        Ok(local_addr)
    }
}

/// A Block2 value as `(num, more, szx)` (RFC 7959 §2.2).
fn parse_block(value: &[u8]) -> Option<(u32, bool, u8)> {
    BlockValue::parse(value).map(|b| (b.num, b.more, b.szx))
}

/// Which part of a request a message carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Part {
    /// The whole request in one message.
    Whole,
    /// One Block1 block of the body (RFC 7959 §2.3).
    Block1(BlockValue),
    /// A Block2 continuation: ask for block `num` at `szx` (RFC 7959 §2.4).
    Block2(u32, u8),
}

/// The first Block1 block of `request`, when its body does not fit one block of `szx`.
fn first_block(request: &CoapRequest, szx: u8) -> Option<BlockValue> {
    (request.payload.len() > szx_size(szx)).then_some(BlockValue {
        num: 0,
        more: true,
        szx,
    })
}

/// The Block1 block after `sent`, at the size the server asked for in its 2.31 (`echo`).
/// RFC 7959 §2.3: the server may lower SZX, and the client then continues at the smaller size
/// from where the bytes it has had acknowledged end. `None` when the body is done.
fn next_block(body_len: usize, sent: BlockValue, echo: Option<BlockValue>) -> Option<BlockValue> {
    let szx = echo.map_or(sent.szx, |e| e.szx.min(sent.szx));
    let acknowledged = sent.offset() + sent.size();
    if acknowledged >= body_len {
        return None;
    }
    let size = szx_size(szx);
    let num = u32::try_from(acknowledged / size).ok()?;
    Some(BlockValue {
        num,
        more: acknowledged + size < body_len,
        szx,
    })
}

fn method_code(method: &str) -> u8 {
    match method {
        "POST" => CODE_POST,
        "PUT" => CODE_PUT,
        "DELETE" => CODE_DELETE,
        _ => CODE_GET,
    }
}

/// The message that carries `request`, one Block1 block of it, or its Block2 continuation.
fn request_message(
    request: &CoapRequest,
    message_id: u16,
    token: &[u8],
    part: Part,
) -> CoapMessage {
    let mut options: Vec<(u16, Vec<u8>)> = Vec::new();
    // RFC 7959 §2.6: a continuation of an Observe registration does not repeat Observe.
    if !matches!(part, Part::Block2(..)) {
        match request.observe {
            ObserveAction::Register => options.push((OPT_OBSERVE, Vec::new())),
            ObserveAction::Cancel => options.push((OPT_OBSERVE, vec![1])),
            ObserveAction::None => {}
        }
    }
    for segment in &request.path {
        options.push((OPT_URI_PATH, segment.as_bytes().to_vec()));
    }
    if let Some(cf) = request.content_format {
        options.push((OPT_CONTENT_FORMAT, uint_option(u32::from(cf))));
    }
    for item in &request.query {
        options.push((OPT_URI_QUERY, item.as_bytes().to_vec()));
    }
    if let Some(accept) = request.accept {
        options.push((OPT_ACCEPT, uint_option(u32::from(accept))));
    }
    let payload = match part {
        Part::Whole => request.payload.clone(),
        Part::Block2(num, szx) => {
            options.push((
                OPT_BLOCK2,
                BlockValue {
                    num,
                    more: false,
                    szx,
                }
                .encode(),
            ));
            Vec::new()
        }
        Part::Block1(block) => {
            options.push((OPT_BLOCK1, block.encode()));
            if block.num == 0 {
                // RFC 7959 §4: announce the whole size, so a server can refuse it up front.
                options.push((OPT_SIZE1, uint_option(request.payload.len() as u32)));
            }
            let start = block.offset().min(request.payload.len());
            let end = (start + block.size()).min(request.payload.len());
            request.payload[start..end].to_vec()
        }
    };
    CoapMessage {
        mtype: if request.confirmable {
            MessageType::Confirmable
        } else {
            MessageType::NonConfirmable
        },
        code: method_code(request.method),
        message_id,
        token: token.to_vec(),
        options,
        payload,
    }
}

fn status_name(code: u8) -> &'static str {
    match code_to_string(code).as_str() {
        "2.01" => "Created",
        "2.02" => "Deleted",
        "2.03" => "Valid",
        "2.04" => "Changed",
        "2.05" => "Content",
        "2.31" => "Continue",
        "4.00" => "Bad Request",
        "4.01" => "Unauthorized",
        "4.02" => "Bad Option",
        "4.03" => "Forbidden",
        "4.04" => "Not Found",
        "4.05" => "Method Not Allowed",
        "4.06" => "Not Acceptable",
        "4.08" => "Request Entity Incomplete",
        "4.12" => "Precondition Failed",
        "4.13" => "Request Entity Too Large",
        "4.15" => "Unsupported Content-Format",
        "5.00" => "Internal Server Error",
        "5.01" => "Not Implemented",
        "5.02" => "Bad Gateway",
        "5.03" => "Service Unavailable",
        "5.04" => "Gateway Timeout",
        "5.05" => "Proxying Not Supported",
        _ => "Unknown",
    }
}

/// The event data for a response: code, payload as text (and parsed JSON when it is JSON), and
/// the options a model can act on. A payload that is not UTF-8 is reported by size only.
fn response_data(request: &CoapRequest, msg: &CoapMessage, payload: &[u8], blocks: u32) -> Value {
    let content_format = msg.option_uint(OPT_CONTENT_FORMAT);
    let mut data = json!({
        "method": request.method,
        "path": request.path_string(),
        "code": code_to_string(msg.code),
        "status": status_name(msg.code),
        "payload_size": payload.len(),
        "blocks": blocks.max(1),
    });
    if let Some(cf) = content_format {
        let name = u16::try_from(cf)
            .ok()
            .and_then(content_format_name)
            .map(str::to_string)
            .unwrap_or_else(|| cf.to_string());
        data["content_format"] = json!(name);
    }
    if let Ok(text) = std::str::from_utf8(payload) {
        if !text.is_empty() {
            data["payload"] = json!(text);
            if content_format == Some(50) {
                if let Ok(parsed) = serde_json::from_str::<Value>(text) {
                    data["payload_json"] = parsed;
                }
            }
        }
    }
    let mut options = serde_json::Map::new();
    if let Some(v) = msg.option_uint(OPT_MAX_AGE) {
        options.insert("max_age".into(), json!(v));
    }
    if let Some(v) = msg.option_values(OPT_ETAG).first() {
        options.insert("etag".into(), json!(hex::encode(v)));
    }
    let location: Vec<String> = msg
        .option_values(OPT_LOCATION_PATH)
        .iter()
        .map(|v| String::from_utf8_lossy(v).to_string())
        .collect();
    if !location.is_empty() {
        options.insert(
            "location_path".into(),
            json!(format!("/{}", location.join("/"))),
        );
    }
    if let Some(v) = msg.option_uint(OPT_OBSERVE) {
        options.insert("observe".into(), json!(v));
    }
    if let Some(v) = msg.option_uint(OPT_SIZE2) {
        options.insert("size2".into(), json!(v));
    }
    data["options"] = Value::Object(options);
    data
}

fn error_event(request: &CoapRequest, kind: &str, message: String) -> Event {
    Event::new(
        &COAP_ERROR_EVENT,
        json!({
            "kind": kind,
            "message": message,
            "method": request.method,
            "path": request.path_string(),
        }),
    )
}

fn enqueue(turn_tx: &mpsc::Sender<Event>, event: Event, client_id: ClientId) {
    if turn_tx.try_send(event).is_err() {
        warn!(
            "CoAP client {client_id} dropped an event: the model is {TURN_QUEUE_CAPACITY} events \
             behind decision=turn_queue_full"
        );
    }
}

/// Everything the transport task owns.
struct Transport {
    socket: UdpSocket,
    reliability: Reliability,
    exchanges: HashMap<Vec<u8>, Exchange>,
    next_mid: u16,
    recent: VecDeque<u16>,
    turn_tx: mpsc::Sender<Event>,
    client_id: ClientId,
}

impl Transport {
    fn fresh_mid(&mut self) -> u16 {
        let mid = self.next_mid;
        self.next_mid = self.next_mid.wrapping_add(1);
        mid
    }

    fn fresh_token(&self) -> Vec<u8> {
        loop {
            let token = rand::random::<u32>().to_be_bytes().to_vec();
            if !self.exchanges.contains_key(&token) {
                return token;
            }
        }
    }

    fn first_interval(&self) -> Duration {
        // RFC 7252 §4.2: a random duration between ACK_TIMEOUT and ACK_TIMEOUT * 1.5.
        let factor = 1.0 + rand::random::<f64>() * 0.5;
        self.reliability.ack_timeout.mul_f64(factor)
    }

    /// Put `msg` on the wire as the current message of the exchange under `token`.
    async fn transmit(&mut self, token: &[u8], msg: CoapMessage) -> std::io::Result<usize> {
        let datagram = msg
            .encode()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string()))?;
        self.socket.send(&datagram).await?;
        let confirmable = msg.mtype == MessageType::Confirmable;
        let interval = self.first_interval();
        let now = Instant::now();
        if let Some(ex) = self.exchanges.get_mut(token) {
            ex.message_id = msg.message_id;
            ex.datagram = datagram.clone();
            ex.awaiting_ack = confirmable;
            ex.retransmissions = 0;
            ex.interval = interval;
            ex.deadline = Some(if confirmable {
                now + interval
            } else {
                now + RESPONSE_TIMEOUT
            });
        }
        Ok(datagram.len())
    }

    async fn start(&mut self, request: CoapRequest) -> Result<usize, String> {
        let token = match request.observe {
            ObserveAction::Cancel => {
                let path = request.path_string();
                let Some(token) = self
                    .exchanges
                    .iter()
                    .find(|(_, ex)| {
                        ex.request.observe == ObserveAction::Register
                            && ex.request.path_string() == path
                    })
                    .map(|(t, _)| t.clone())
                else {
                    enqueue(
                        &self.turn_tx,
                        error_event(
                            &request,
                            "not_observing",
                            format!("there is no observation of {path} to cancel"),
                        ),
                        self.client_id,
                    );
                    return Ok(0);
                };
                // RFC 7641 §3.6: the cancellation is a GET with Observe 1 and the same token.
                if let Some(ex) = self.exchanges.get_mut(&token) {
                    ex.request = request.clone();
                    ex.body.clear();
                    ex.blocks = 0;
                    ex.next_block = 0;
                    ex.upload = None;
                }
                token
            }
            _ => {
                if self.exchanges.len() >= MAX_EXCHANGES {
                    return Err(format!(
                        "{MAX_EXCHANGES} exchanges (requests and observations) are already open"
                    ));
                }
                let token = self.fresh_token();
                self.exchanges.insert(
                    token.clone(),
                    Exchange {
                        request: request.clone(),
                        message_id: 0,
                        datagram: Vec::new(),
                        awaiting_ack: false,
                        retransmissions: 0,
                        interval: Duration::ZERO,
                        deadline: None,
                        body: Vec::new(),
                        blocks: 0,
                        next_block: 0,
                        observing: false,
                        upload: None,
                        blocks_sent: 0,
                    },
                );
                token
            }
        };
        let mid = self.fresh_mid();
        let part = match first_block(&request, self.reliability.block_szx) {
            Some(block) => {
                if let Some(ex) = self.exchanges.get_mut(&token) {
                    ex.upload = Some(block);
                    ex.blocks_sent = 1;
                }
                Part::Block1(block)
            }
            None => Part::Whole,
        };
        let msg = request_message(&request, mid, &token, part);
        match self.transmit(&token, msg).await {
            Ok(n) => {
                debug!(
                    "CoAP client {} sent {} {} mid {mid}",
                    self.client_id,
                    request.method,
                    request.path_string()
                );
                Ok(n)
            }
            Err(e) => {
                self.exchanges.remove(&token);
                Err(format!("send failed: {e}"))
            }
        }
    }

    async fn send_empty(&self, mtype: MessageType, message_id: u16) {
        let msg = CoapMessage {
            mtype,
            code: CODE_EMPTY,
            message_id,
            token: Vec::new(),
            options: Vec::new(),
            payload: Vec::new(),
        };
        if let Ok(bytes) = msg.encode() {
            let _ = self.socket.send(&bytes).await;
        }
    }

    /// Retransmit what is due, and give up on what has run out of attempts or time.
    async fn expire(&mut self) {
        let now = Instant::now();
        let due: Vec<Vec<u8>> = self
            .exchanges
            .iter()
            .filter(|(_, ex)| ex.deadline.is_some_and(|d| d <= now))
            .map(|(t, _)| t.clone())
            .collect();
        for token in due {
            let Some(ex) = self.exchanges.get_mut(&token) else {
                continue;
            };
            if ex.awaiting_ack && ex.retransmissions < self.reliability.max_retransmit {
                ex.retransmissions += 1;
                ex.interval *= 2;
                ex.deadline = Some(now + ex.interval);
                debug!(
                    "CoAP client {} retransmission {} of mid {}",
                    self.client_id, ex.retransmissions, ex.message_id
                );
                let datagram = ex.datagram.clone();
                let _ = self.socket.send(&datagram).await;
                continue;
            }
            let ex = self.exchanges.remove(&token).expect("present above");
            let message = if ex.awaiting_ack {
                format!(
                    "no acknowledgement after {} retransmissions",
                    ex.retransmissions
                )
            } else {
                format!("no response within {} seconds", RESPONSE_TIMEOUT.as_secs())
            };
            warn!(
                "CoAP client {} {} {} timed out decision=timeout",
                self.client_id,
                ex.request.method,
                ex.request.path_string()
            );
            enqueue(
                &self.turn_tx,
                error_event(&ex.request, "timeout", message),
                self.client_id,
            );
        }
    }

    async fn handle_datagram(&mut self, datagram: &[u8]) {
        let msg = match CoapMessage::decode(datagram) {
            Ok(m) => m,
            Err(e) => {
                warn!(
                    "CoAP client {} dropped an undecodable datagram: {e} decision=undecodable",
                    self.client_id
                );
                return;
            }
        };
        match msg.mtype {
            MessageType::Acknowledgement => {
                let Some(token) = self
                    .exchanges
                    .iter()
                    .find(|(_, ex)| ex.awaiting_ack && ex.message_id == msg.message_id)
                    .map(|(t, _)| t.clone())
                else {
                    return; // a duplicate ACK
                };
                if let Some(ex) = self.exchanges.get_mut(&token) {
                    ex.awaiting_ack = false;
                    ex.deadline = Some(Instant::now() + RESPONSE_TIMEOUT);
                }
                if msg.code != CODE_EMPTY && msg.token == token {
                    self.handle_response(token, msg).await;
                }
            }
            MessageType::Reset => {
                let Some(token) = self
                    .exchanges
                    .iter()
                    .find(|(_, ex)| ex.message_id == msg.message_id)
                    .map(|(t, _)| t.clone())
                else {
                    return;
                };
                if let Some(ex) = self.exchanges.remove(&token) {
                    enqueue(
                        &self.turn_tx,
                        error_event(
                            &ex.request,
                            "reset",
                            "the server rejected the message with RST".to_string(),
                        ),
                        self.client_id,
                    );
                }
            }
            MessageType::Confirmable | MessageType::NonConfirmable => {
                let is_response = code_class(msg.code) >= 2;
                let known = is_response && self.exchanges.contains_key(&msg.token);
                if !known {
                    // An unknown token (a notification after cancel, a response to a
                    // forgotten request), a request, or a CoAP ping: RST (RFC 7252 §4.2,
                    // RFC 7641 §3.6).
                    self.send_empty(MessageType::Reset, msg.message_id).await;
                    return;
                }
                if msg.mtype == MessageType::Confirmable {
                    self.send_empty(MessageType::Acknowledgement, msg.message_id)
                        .await;
                }
                if self.recent.contains(&msg.message_id) {
                    return; // a retransmission we already handled
                }
                self.recent.push_back(msg.message_id);
                if self.recent.len() > RECENT_MIDS {
                    self.recent.pop_front();
                }
                let token = msg.token.clone();
                self.handle_response(token, msg).await;
            }
        }
    }

    async fn handle_response(&mut self, token: Vec<u8>, msg: CoapMessage) {
        let client_id = self.client_id;
        let Some(ex) = self.exchanges.get_mut(&token) else {
            return;
        };
        let has_observe = msg.option_uint(OPT_OBSERVE).is_some();

        // Block1: a 2.31 Continue for the block on the wire sends the next one. Anything else
        // — the final block's answer, or a refusal part way (4.08, 4.13) — ends the upload and
        // is reported like any response.
        if let Some(sent) = ex.upload {
            let echo = msg
                .option_values(OPT_BLOCK1)
                .first()
                .and_then(|v| BlockValue::parse(v));
            if msg.code == CODE_CONTINUE {
                if echo.is_some_and(|e| e.num != sent.num) {
                    let ex = self.exchanges.remove(&token).expect("present above");
                    enqueue(
                        &self.turn_tx,
                        error_event(
                            &ex.request,
                            "bad_block",
                            format!(
                                "the server continued block {} while block {} was sent",
                                echo.map_or(0, |e| e.num),
                                sent.num
                            ),
                        ),
                        client_id,
                    );
                    return;
                }
                let Some(next) = next_block(ex.request.payload.len(), sent, echo) else {
                    let ex = self.exchanges.remove(&token).expect("present above");
                    enqueue(
                        &self.turn_tx,
                        error_event(
                            &ex.request,
                            "bad_block",
                            "the server asked for more after the last block".into(),
                        ),
                        client_id,
                    );
                    return;
                };
                ex.upload = Some(next);
                ex.blocks_sent += 1;
                let request = ex.request.clone();
                let mid = self.fresh_mid();
                let msg = request_message(&request, mid, &token, Part::Block1(next));
                if let Err(e) = self.transmit(&token, msg).await {
                    if let Some(ex) = self.exchanges.remove(&token) {
                        enqueue(
                            &self.turn_tx,
                            error_event(&ex.request, "timeout", format!("send failed: {e}")),
                            client_id,
                        );
                    }
                }
                return;
            }
            ex.upload = None;
        }

        if ex.request.observe == ObserveAction::Cancel {
            if has_observe {
                return; // a notification still in flight when the cancel went out
            }
            let ex = self.exchanges.remove(&token).expect("present above");
            let mut data = response_data(&ex.request, &msg, &msg.payload, 1);
            data["observing"] = json!(false);
            enqueue(
                &self.turn_tx,
                Event::new(&COAP_RESPONSE_EVENT, data),
                client_id,
            );
            return;
        }

        // A notification on a confirmed observation: report it, keep the observation.
        if ex.observing {
            let mut data = response_data(&ex.request, &msg, &msg.payload, 1);
            data["sequence"] = json!(msg.option_uint(OPT_OBSERVE).unwrap_or(0));
            if msg
                .option_values(OPT_BLOCK2)
                .first()
                .and_then(|v| parse_block(v))
                .is_some_and(|(_, more, _)| more)
            {
                data["truncated"] = json!(true);
            }
            enqueue(
                &self.turn_tx,
                Event::new(&COAP_NOTIFICATION_EVENT, data),
                client_id,
            );
            return;
        }

        // Block2 reassembly.
        if let Some(value) = msg.option_values(OPT_BLOCK2).first() {
            let Some((num, more, szx)) = parse_block(value) else {
                let ex = self.exchanges.remove(&token).expect("present above");
                enqueue(
                    &self.turn_tx,
                    error_event(&ex.request, "bad_block", "unreadable Block2 option".into()),
                    client_id,
                );
                return;
            };
            if num != ex.next_block {
                let expected = ex.next_block;
                let ex = self.exchanges.remove(&token).expect("present above");
                enqueue(
                    &self.turn_tx,
                    error_event(
                        &ex.request,
                        "bad_block",
                        format!("the server sent block {num}; block {expected} was expected"),
                    ),
                    client_id,
                );
                return;
            }
            if ex.body.len() + msg.payload.len() > MAX_BODY {
                let ex = self.exchanges.remove(&token).expect("present above");
                warn!(
                    "CoAP client {client_id} {} passed {MAX_BODY} bytes decision=body_too_large",
                    ex.request.path_string()
                );
                enqueue(
                    &self.turn_tx,
                    error_event(
                        &ex.request,
                        "body_too_large",
                        format!("the Block2 transfer passed {MAX_BODY} bytes"),
                    ),
                    client_id,
                );
                return;
            }
            ex.body.extend_from_slice(&msg.payload);
            ex.blocks += 1;
            if has_observe && ex.request.observe == ObserveAction::Register {
                ex.observing = true;
            }
            if more {
                ex.next_block = num + 1;
                let request = ex.request.clone();
                let mid = self.fresh_mid();
                let next = request_message(&request, mid, &token, Part::Block2(num + 1, szx));
                if let Err(e) = self.transmit(&token, next).await {
                    if let Some(ex) = self.exchanges.remove(&token) {
                        enqueue(
                            &self.turn_tx,
                            error_event(&ex.request, "timeout", format!("send failed: {e}")),
                            client_id,
                        );
                    }
                }
                return;
            }
        } else {
            ex.body = msg.payload.clone();
            ex.blocks = 1;
            if has_observe && ex.request.observe == ObserveAction::Register {
                ex.observing = true;
            }
        }

        // The response is complete.
        let body = std::mem::take(&mut ex.body);
        let mut data = response_data(&ex.request, &msg, &body, ex.blocks);
        if ex.blocks_sent > 0 {
            data["blocks_sent"] = json!(ex.blocks_sent);
        }
        if ex.request.observe == ObserveAction::Register {
            data["observing"] = json!(ex.observing);
        }
        if ex.observing {
            // The registration stands: no deadline, no retransmission.
            ex.deadline = None;
            ex.awaiting_ack = false;
        } else {
            self.exchanges.remove(&token);
        }
        enqueue(
            &self.turn_tx,
            Event::new(&COAP_RESPONSE_EVENT, data),
            client_id,
        );
    }
}

/// Own the socket for the life of the client.
#[allow(clippy::too_many_arguments)]
async fn run_transport(
    socket: UdpSocket,
    reliability: Reliability,
    mut outbound_rx: mpsc::Receiver<Outbound>,
    turn_tx: mpsc::Sender<Event>,
    app_state: Arc<AppState>,
    status_tx: mpsc::UnboundedSender<String>,
    client_id: ClientId,
    turn_abort: tokio::task::AbortHandle,
) {
    let mut t = Transport {
        socket,
        reliability,
        exchanges: HashMap::new(),
        next_mid: rand::random::<u16>(),
        recent: VecDeque::new(),
        turn_tx,
        client_id,
    };
    // One byte over the bound, so an oversize datagram is seen as oversize rather than
    // silently truncated to something that decodes.
    let mut buf = vec![0u8; MAX_MESSAGE_LEN + 1];

    let status = loop {
        let deadline = t.exchanges.values().filter_map(|ex| ex.deadline).min();
        tokio::select! {
            received = t.socket.recv(&mut buf) => match received {
                Ok(n) if n > MAX_MESSAGE_LEN => warn!(
                    "CoAP client {client_id} dropped a datagram over {MAX_MESSAGE_LEN} bytes \
                     decision=oversize"
                ),
                Ok(n) => {
                    let datagram = buf[..n].to_vec();
                    t.handle_datagram(&datagram).await;
                }
                // ICMP port unreachable on a connected socket: the server is not there (yet).
                // The exchange times out through its own retransmissions.
                Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
                    debug!("CoAP client {client_id}: {e}");
                }
                Err(e) => {
                    error!("CoAP client {client_id} socket error: {e}");
                    break ClientStatus::Error(e.to_string());
                }
            },
            _ = async {
                match deadline {
                    Some(d) => tokio::time::sleep_until(d).await,
                    None => std::future::pending::<()>().await,
                }
            } => t.expire().await,
            out = outbound_rx.recv() => match out {
                None => break ClientStatus::Disconnected,
                Some(Outbound::Disconnect { ack }) => {
                    let _ = ack.send(());
                    info!("CoAP client {client_id} stopped on request");
                    break ClientStatus::Disconnected;
                }
                Some(Outbound::Request { request, ack }) => {
                    let _ = ack.send(t.start(request).await);
                }
            },
        }
    };

    turn_abort.abort();
    app_state.remove_client_handle(client_id).await;
    app_state.update_client_status(client_id, status).await;
    let _ = status_tx.send(format!("[CLIENT] CoAP client {client_id} stopped"));
    let _ = status_tx.send("__UPDATE_UI__".to_string());
}

/// Answer queued events with the model, one at a time, in arrival order.
async fn run_turns(
    mut turn_rx: mpsc::Receiver<Event>,
    outbound_tx: mpsc::Sender<Outbound>,
    protocol: Arc<CoapClientProtocol>,
    llm_client: OllamaClient,
    app_state: Arc<AppState>,
    status_tx: mpsc::UnboundedSender<String>,
    client_id: ClientId,
) {
    while let Some(event) = turn_rx.recv().await {
        let Some(instruction) = app_state.get_instruction_for_client(client_id).await else {
            continue;
        };
        let memory = app_state
            .get_memory_for_client(client_id)
            .await
            .unwrap_or_default();
        match call_llm_for_client(
            &llm_client,
            &app_state,
            client_id.to_string(),
            &instruction,
            &memory,
            Some(&event),
            protocol.as_ref(),
            &status_tx,
        )
        .await
        {
            Ok(result) => {
                if let Some(mem) = result.memory_updates {
                    app_state.set_memory_for_client(client_id, mem).await;
                }
                info!(
                    "CoAP client {client_id} {} decision={} actions={}",
                    event.id(),
                    if result.actions.is_empty() {
                        "model_silent"
                    } else {
                        "model_actions"
                    },
                    result.actions.len()
                );
                for action in result.actions {
                    match apply_action(protocol.as_ref(), &outbound_tx, action).await {
                        Ok(Applied::Disconnect) => return,
                        Ok(_) => {}
                        Err(e) => {
                            error!("CoAP client {client_id} action failed: {e}");
                            let _ = status_tx.send(format!(
                                "[ERROR] CoAP client {client_id} action failed: {e}"
                            ));
                        }
                    }
                }
            }
            Err(e) => error!(
                "CoAP client {client_id} {} decision=llm_error: {e}",
                event.id()
            ),
        }
    }
}

/// Execute one action and hand its request to the transport. Shared by the model's turns and
/// injected commands.
async fn apply_action(
    protocol: &CoapClientProtocol,
    outbound_tx: &mpsc::Sender<Outbound>,
    action: Value,
) -> Result<Applied> {
    match protocol.execute_action(action)? {
        ClientActionResult::Custom { name, data } if name == REQUEST_RESULT => {
            let request = request_from_action(&data)?
                .ok_or_else(|| anyhow!("a request action produced no request"))?;
            let (ack, done) = oneshot::channel();
            outbound_tx
                .send(Outbound::Request { request, ack })
                .await
                .map_err(|_| anyhow!("the client is stopped"))?;
            let bytes = done
                .await
                .map_err(|_| anyhow!("the client stopped before the request was sent"))?
                .map_err(|e| anyhow!(e))?;
            Ok(if bytes == 0 {
                Applied::Nothing
            } else {
                Applied::Sent(bytes)
            })
        }
        ClientActionResult::Disconnect => {
            let (ack, done) = oneshot::channel();
            if outbound_tx.send(Outbound::Disconnect { ack }).await.is_ok() {
                let _ = done.await;
            }
            Ok(Applied::Disconnect)
        }
        _ => Ok(Applied::Nothing),
    }
}

async fn command_loop(
    mut command_rx: mpsc::Receiver<ClientCommand>,
    protocol: Arc<CoapClientProtocol>,
    outbound_tx: mpsc::Sender<Outbound>,
    client_id: ClientId,
    app_state: Arc<AppState>,
    status_tx: mpsc::UnboundedSender<String>,
) {
    while let Some(command) = command_rx.recv().await {
        let action = command.action.clone();
        let outcome = match apply_action(protocol.as_ref(), &outbound_tx, action.clone()).await {
            Ok(Applied::Sent(bytes_sent)) => ClientSendOutcome::Sent { bytes_sent },
            Ok(Applied::Nothing) => ClientSendOutcome::Executed {
                detail: "executed (nothing to send)".to_string(),
            },
            Ok(Applied::Disconnect) => ClientSendOutcome::Disconnected,
            Err(e) => ClientSendOutcome::Rejected {
                error: e.to_string(),
            },
        };
        app_state
            .record_access_log(
                AccessLogOwner::Client(client_id.as_u32()),
                protocol.protocol_name(),
                None,
                "injected_action",
                action,
                vec![serde_json::to_value(&outcome).unwrap_or_default()],
            )
            .await;
        let disconnect = matches!(outcome, ClientSendOutcome::Disconnected);
        let _ = status_tx.send("__UPDATE_UI__".to_string());
        crate::client::command_support::reply(command, Ok(outcome));
        if disconnect {
            break;
        }
    }
}
