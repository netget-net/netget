//! RADIUS client (a NAS): NetGet authenticates users and reports accounting to a RADIUS server,
//! and the model decides who and what.
//!
//! Three tasks per client, all registered with the client:
//!
//! * **transport** owns the UDP socket, the shared secret, the identifiers of requests in
//!   flight and their retransmission timers. Every reply is verified (`wire::verify_reply`)
//!   before anything in it reaches the model; one that does not verify is discarded and reported
//!   as `radius_error`, and the request goes on waiting for a genuine answer.
//! * **turns** asks the model about each reply or error, in order, and hands its actions back
//!   to the transport. The chain passes through that queue, so it needs no recursion.
//! * **commands** runs injected actions (`[ send ]`, MCP `send_to_client`) down the same path.
//!
//! The shared secret lives in the transport's `Settings` and is used for nothing but
//! authenticators. `Settings` deliberately does not implement `Debug`.

pub mod actions;
pub mod wire;

pub use actions::RadiusClientProtocol;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use serde_json::{json, Map, Value};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};
use tokio::time::Instant;
use tracing::{debug, error, info, warn};

use crate::client::llm_budget::call_llm_for_client;
use crate::client::radius::actions::{
    request_from_action, Method, RadiusRequest, RADIUS_ACCESS_ACCEPT_EVENT,
    RADIUS_ACCESS_CHALLENGE_EVENT, RADIUS_ACCESS_REJECT_EVENT, RADIUS_ACCOUNTING_RESPONSE_EVENT,
    RADIUS_CONNECTED_EVENT, RADIUS_ERROR_EVENT, RADIUS_STATUS_RESPONSE_EVENT, REQUEST_RESULT,
};
use crate::client::radius::wire::{
    access_request, accounting_request, status_server, verify_reply, Credential, ReplyError,
};
use crate::llm::actions::client_trait::{Client, ClientActionResult};
use crate::llm::actions::protocol_trait::Protocol;
use crate::llm::ollama_client::OllamaClient;
use crate::logging::emit::Log;
use crate::protocol::Event;
use crate::server::radius::packet::{
    attribute_info, attribute_value_json, code_name, Attribute, RadiusPacket,
    ATTR_MESSAGE_AUTHENTICATOR, ATTR_PROXY_STATE, ATTR_REPLY_MESSAGE, ATTR_STATE,
    CODE_ACCESS_ACCEPT, CODE_ACCESS_CHALLENGE, CODE_ACCESS_REQUEST, CODE_ACCOUNTING_REQUEST,
    CODE_STATUS_SERVER, MAX_PACKET_LEN,
};
use crate::state::app_state::AppState;
use crate::state::client_handles::{ClientCommand, ClientSendOutcome};
use crate::state::{AccessLogOwner, ClientId, ClientStatus};

/// Requests awaiting a reply. The next is refused; the identifier space is 256.
pub const MAX_IN_FLIGHT: usize = 32;

/// Challenge `State`s remembered for the next Access-Request of the same user.
const MAX_CHALLENGES: usize = 64;

const TURN_QUEUE_CAPACITY: usize = 256;
const OUTBOUND_CAPACITY: usize = 64;

/// What the transport needs, secret included. Not `Debug`, so it cannot be logged by accident.
pub struct Settings {
    pub secret: Vec<u8>,
    pub accounting_port: Option<u16>,
    pub timeout: Duration,
    pub retries: u32,
}

enum Outbound {
    Request {
        request: RadiusRequest,
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

struct InFlight {
    request: RadiusRequest,
    code: u8,
    target: SocketAddr,
    packet: Vec<u8>,
    authenticator: [u8; 16],
    retransmissions: u32,
    deadline: Instant,
}

/// Where packets go: a UDP socket (RADIUS) or a framed stream (RadSec, RFC 6614, which carries
/// the same packets over TLS). On a stream a request is never retransmitted — the transport is
/// reliable — but it waits the same total time before it is reported unanswered.
pub enum Link {
    Udp(UdpSocket),
    Stream {
        writer: Box<dyn tokio::io::AsyncWrite + Send + Unpin>,
        /// Whole packets, read by a separate registered task (see [`read_frames`]).
        frames: mpsc::Receiver<std::io::Result<Vec<u8>>>,
        peer: SocketAddr,
    },
}

impl Link {
    fn is_udp(&self) -> bool {
        matches!(self, Link::Udp(_))
    }

    async fn send(&mut self, packet: &[u8], target: SocketAddr) -> std::io::Result<()> {
        use tokio::io::AsyncWriteExt;
        match self {
            Link::Udp(socket) => socket.send_to(packet, target).await.map(|_| ()),
            Link::Stream { writer, .. } => {
                writer.write_all(packet).await?;
                writer.flush().await
            }
        }
    }

    async fn recv(&mut self, buf: &mut [u8]) -> std::io::Result<(Vec<u8>, SocketAddr)> {
        match self {
            Link::Udp(socket) => {
                let (n, from) = socket.recv_from(buf).await?;
                Ok((buf[..n].to_vec(), from))
            }
            Link::Stream { frames, peer, .. } => match frames.recv().await {
                Some(frame) => frame.map(|f| (f, *peer)),
                None => Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "the connection closed",
                )),
            },
        }
    }
}

pub use crate::server::radius::packet::read_frames;

pub struct RadiusClient;

impl RadiusClient {
    pub async fn connect_with_llm_actions(
        remote_addr: String,
        settings: Settings,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        client_id: ClientId,
    ) -> Result<SocketAddr> {
        if remote_addr.trim().is_empty() {
            return Err(anyhow!(
                "RADIUS client needs the authentication server's remote_addr (host:port); \
                 refusing to start without one"
            ));
        }
        let auth = tokio::net::lookup_host(&remote_addr)
            .await
            .with_context(|| format!("cannot resolve RADIUS server {remote_addr}"))?
            .next()
            .with_context(|| format!("{remote_addr} resolved to no address"))?;
        let acct_port = match settings.accounting_port {
            Some(p) => p,
            None => auth.port().checked_add(1).context(
                "the authentication port is 65535, so there is no default accounting port; set \
                 accounting_port",
            )?,
        };
        let acct = SocketAddr::new(auth.ip(), acct_port);
        let socket = UdpSocket::bind(if auth.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        })
        .await?;
        let local_addr = socket.local_addr()?;
        Self::run(
            Link::Udp(socket),
            auth,
            acct,
            settings,
            llm_client,
            app_state,
            status_tx,
            client_id,
        )
        .await;
        Ok(local_addr)
    }

    /// Start the client's three tasks over `link`. `auth` and `acct` are where each kind of
    /// request goes; on a stream both are its peer.
    #[allow(clippy::too_many_arguments)]
    pub async fn run(
        link: Link,
        auth: SocketAddr,
        acct: SocketAddr,
        settings: Settings,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        client_id: ClientId,
    ) {
        info!("RADIUS client {client_id} ready: auth {auth}, accounting {acct}");
        app_state
            .update_client_status(client_id, ClientStatus::Connected)
            .await;
        let _ = status_tx.send(format!("[CLIENT] RADIUS client {client_id} ready"));
        let _ = status_tx.send("__UPDATE_UI__".to_string());

        let protocol = Arc::new(RadiusClientProtocol::new());
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
            &RADIUS_CONNECTED_EVENT,
            json!({"auth_server": auth.to_string(), "accounting_server": acct.to_string()}),
        ));
        app_state
            .spawn_client_task(
                client_id,
                run_transport(
                    Transport {
                        link,
                        settings,
                        auth,
                        acct,
                        pending: HashMap::new(),
                        next_id: rand::random::<u8>(),
                        challenges: HashMap::new(),
                        turn_tx,
                        client_id,
                    },
                    outbound_rx,
                    app_state.clone(),
                    status_tx,
                    turn_abort,
                ),
            )
            .await;
    }
}

fn request_name(code: u8) -> &'static str {
    code_name(code)
}

fn user_of(request: &RadiusRequest) -> Option<&str> {
    match request {
        RadiusRequest::Access { user_name, .. } => Some(user_name),
        RadiusRequest::Accounting { user_name, .. } => user_name.as_deref(),
        RadiusRequest::Status { .. } => None,
    }
}

/// A reply's attributes by dictionary name, minus the ones that only mean something to the
/// transport (Message-Authenticator, State, Proxy-State). A repeated attribute becomes an array.
fn attributes_json(packet: &RadiusPacket) -> Value {
    let mut map = Map::new();
    for attr in &packet.attributes {
        if matches!(
            attr.attr_type,
            ATTR_MESSAGE_AUTHENTICATOR | ATTR_STATE | ATTR_PROXY_STATE
        ) {
            continue;
        }
        let (name, _) = attribute_info(attr.attr_type);
        let name = if name == "Unknown" {
            format!("Attribute-{}", attr.attr_type)
        } else {
            name.to_string()
        };
        let value = attribute_value_json(attr.attr_type, &attr.value);
        match map.get_mut(&name) {
            None => {
                map.insert(name, value);
            }
            Some(Value::Array(items)) => items.push(value),
            Some(existing) => {
                let first = existing.take();
                *existing = Value::Array(vec![first, value]);
            }
        }
    }
    Value::Object(map)
}

/// Reply-Message, all of them joined, as the peer's multi-line text.
fn reply_message(packet: &RadiusPacket) -> Option<String> {
    let parts: Vec<String> = packet
        .all(ATTR_REPLY_MESSAGE)
        .iter()
        .map(|v| crate::utils::sanitize::multiline(&String::from_utf8_lossy(v)))
        .collect();
    (!parts.is_empty()).then(|| parts.join("\n"))
}

struct Transport {
    link: Link,
    settings: Settings,
    auth: SocketAddr,
    acct: SocketAddr,
    pending: HashMap<u8, InFlight>,
    next_id: u8,
    challenges: HashMap<String, Vec<u8>>,
    turn_tx: mpsc::Sender<Event>,
    client_id: ClientId,
}

impl Transport {
    fn enqueue(&self, event: Event) {
        if self.turn_tx.try_send(event).is_err() {
            warn!(
                "RADIUS client {} dropped an event: the model is {TURN_QUEUE_CAPACITY} events \
                 behind decision=turn_queue_full",
                self.client_id
            );
        }
    }

    fn error(&self, request: &RadiusRequest, code: u8, kind: &str, message: String) {
        let mut data = json!({
            "kind": kind,
            "message": message,
            "request": request_name(code),
        });
        if let Some(user) = user_of(request) {
            data["user_name"] = json!(user);
        }
        self.enqueue(Event::new(&RADIUS_ERROR_EVENT, data));
    }

    fn fresh_id(&mut self) -> u8 {
        while self.pending.contains_key(&self.next_id) {
            self.next_id = self.next_id.wrapping_add(1);
        }
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        id
    }

    async fn start(&mut self, request: RadiusRequest) -> Result<usize, String> {
        if self.pending.len() >= MAX_IN_FLIGHT {
            return Err(format!(
                "{MAX_IN_FLIGHT} requests are already waiting for a reply"
            ));
        }
        let id = self.fresh_id();
        let secret = self.settings.secret.as_slice();
        let (code, target, packet, authenticator) = match &request {
            RadiusRequest::Access {
                user_name,
                method,
                attributes,
            } => {
                let ra: [u8; 16] = rand::random();
                let mut attrs = attributes.clone();
                // Answering a challenge: carry its State back (RFC 2865 §5.24).
                if let Some(state) = self.challenges.remove(user_name) {
                    attrs.push(Attribute::new(ATTR_STATE, state));
                }
                let credential = match method {
                    Method::Pap(p) => Credential::Pap(p.as_bytes()),
                    Method::Chap(p) => Credential::Chap(p.as_bytes()),
                    Method::None => Credential::None,
                };
                let packet = access_request(id, &ra, credential, &attrs, secret)
                    .map_err(|e| e.to_string())?;
                (CODE_ACCESS_REQUEST, self.auth, packet, ra)
            }
            RadiusRequest::Accounting { attributes, .. } => {
                let (packet, auth) =
                    accounting_request(id, attributes, secret).map_err(|e| e.to_string())?;
                (CODE_ACCOUNTING_REQUEST, self.acct, packet, auth)
            }
            RadiusRequest::Status { accounting_port } => {
                let ra: [u8; 16] = rand::random();
                let packet = status_server(id, &ra, secret).map_err(|e| e.to_string())?;
                let target = if *accounting_port {
                    self.acct
                } else {
                    self.auth
                };
                (CODE_STATUS_SERVER, target, packet, ra)
            }
        };
        self.link
            .send(&packet, target)
            .await
            .map_err(|e| format!("send failed: {e}"))?;
        debug!(
            "RADIUS client {} sent {} id {id} to {target}",
            self.client_id,
            request_name(code)
        );
        let len = packet.len();
        self.pending.insert(
            id,
            InFlight {
                request,
                code,
                target,
                packet,
                authenticator,
                retransmissions: 0,
                deadline: Instant::now() + self.settings.timeout,
            },
        );
        Ok(len)
    }

    async fn expire(&mut self) {
        let now = Instant::now();
        let due: Vec<u8> = self
            .pending
            .iter()
            .filter(|(_, p)| p.deadline <= now)
            .map(|(id, _)| *id)
            .collect();
        for id in due {
            let Some(p) = self.pending.get_mut(&id) else {
                continue;
            };
            if p.retransmissions < self.settings.retries {
                p.retransmissions += 1;
                p.deadline = now + self.settings.timeout;
                // RFC 2865 §2.5: a retransmission is the identical packet, same identifier and
                // authenticator. On a stream nothing is resent (RFC 6614 §2.5): the request
                // just waits the same total time.
                if self.link.is_udp() {
                    let (packet, target) = (p.packet.clone(), p.target);
                    let _ = self.link.send(&packet, target).await;
                }
                continue;
            }
            let p = self.pending.remove(&id).expect("present above");
            warn!(
                "RADIUS client {} {} id {id} unanswered decision=timeout",
                self.client_id,
                request_name(p.code)
            );
            self.error(
                &p.request,
                p.code,
                "timeout",
                format!("no reply after {} retransmission(s)", p.retransmissions),
            );
        }
    }

    fn handle_datagram(&mut self, datagram: &[u8], from: SocketAddr) {
        if datagram.len() < 2 {
            return;
        }
        let id = datagram[1];
        let Some(p) = self.pending.get(&id) else {
            debug!(
                "RADIUS client {} dropped a reply for identifier {id}, which is not in flight",
                self.client_id
            );
            return;
        };
        if p.target != from {
            warn!(
                "RADIUS client {} dropped a reply from {from}; request {id} went to {} \
                 decision=unexpected_source",
                self.client_id, p.target
            );
            return;
        }
        let packet = match verify_reply(datagram, p.code, &p.authenticator, &self.settings.secret) {
            Ok(packet) => packet,
            Err(ReplyError::Malformed(e)) => {
                warn!(
                    "RADIUS client {} dropped a malformed reply: {e} decision=malformed",
                    self.client_id
                );
                return;
            }
            Err(e) => {
                // Discarded (RFC 2865 §3: an invalid Response Authenticator is silently
                // discarded) — the request keeps waiting for a genuine reply — and reported,
                // because a reply that does not verify is exactly what an operator must see.
                warn!(
                    "RADIUS client {} discarded a reply to {} id {id}: {e} decision={}",
                    self.client_id,
                    request_name(p.code),
                    e.kind()
                );
                let (request, code) = (p.request.clone(), p.code);
                self.error(&request, code, e.kind(), e.to_string());
                return;
            }
        };
        let p = self.pending.remove(&id).expect("present above");
        let attributes = attributes_json(&packet);
        let event = match &p.request {
            RadiusRequest::Access {
                user_name, method, ..
            } => {
                let mut data = json!({
                    "user_name": user_name,
                    "method": method.name(),
                    "attributes": attributes,
                });
                if let Some(m) = reply_message(&packet) {
                    data["reply_message"] = json!(m);
                }
                match packet.code {
                    CODE_ACCESS_ACCEPT => Event::new(&RADIUS_ACCESS_ACCEPT_EVENT, data),
                    CODE_ACCESS_CHALLENGE => {
                        if let Some(state) = packet.first(ATTR_STATE) {
                            if self.challenges.len() >= MAX_CHALLENGES {
                                self.challenges.clear();
                            }
                            self.challenges.insert(user_name.clone(), state.to_vec());
                        }
                        Event::new(&RADIUS_ACCESS_CHALLENGE_EVENT, data)
                    }
                    _ => Event::new(&RADIUS_ACCESS_REJECT_EVENT, data),
                }
            }
            RadiusRequest::Accounting {
                status_type,
                session_id,
                ..
            } => Event::new(
                &RADIUS_ACCOUNTING_RESPONSE_EVENT,
                json!({
                    "status_type": status_type,
                    "session_id": session_id,
                    "attributes": attributes,
                }),
            ),
            RadiusRequest::Status { accounting_port } => Event::new(
                &RADIUS_STATUS_RESPONSE_EVENT,
                json!({
                    "port": if *accounting_port { "accounting" } else { "auth" },
                    "code": code_name(packet.code),
                    "attributes": attributes,
                }),
            ),
        };
        info!(
            "RADIUS client {} {} id {id} answered {}",
            self.client_id,
            request_name(p.code),
            code_name(packet.code)
        );
        self.enqueue(event);
    }
}

/// Own the socket for the life of the client.
async fn run_transport(
    mut t: Transport,
    mut outbound_rx: mpsc::Receiver<Outbound>,
    app_state: Arc<AppState>,
    status_tx: mpsc::UnboundedSender<String>,
    turn_abort: tokio::task::AbortHandle,
) {
    let client_id = t.client_id;
    // One byte over the RFC 2865 maximum, so an oversize datagram reaches the shared decoder
    // as oversize (`RadiusPacket::decode` refuses past 4096) rather than silently truncated to
    // something that decodes.
    let mut buf = vec![0u8; MAX_PACKET_LEN + 1];
    let status = loop {
        let deadline = t.pending.values().map(|p| p.deadline).min();
        tokio::select! {
            received = t.link.recv(&mut buf) => match received {
                Ok((datagram, from)) => {
                    t.handle_datagram(&datagram, from);
                }
                Err(e) if t.link.is_udp() && (e.kind() == std::io::ErrorKind::ConnectionRefused
                    || e.kind() == std::io::ErrorKind::ConnectionReset) => {
                    debug!("RADIUS client {client_id}: {e}");
                }
                Err(e) => {
                    error!("RADIUS client {client_id} socket error: {e}");
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
                    info!("RADIUS client {client_id} stopped on request");
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
    let _ = status_tx.send(format!("[CLIENT] RADIUS client {client_id} stopped"));
    let _ = status_tx.send("__UPDATE_UI__".to_string());
}

/// Answer queued events with the model, one at a time, in arrival order.
async fn run_turns(
    mut turn_rx: mpsc::Receiver<Event>,
    outbound_tx: mpsc::Sender<Outbound>,
    protocol: Arc<RadiusClientProtocol>,
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
                    "RADIUS client {client_id} {} decision={} actions={}",
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
                            Log::to(&status_tx)
                                .error(format!("RADIUS client {client_id} action failed: {e}"));
                        }
                    }
                }
            }
            Err(e) => error!(
                "RADIUS client {client_id} {} decision=llm_error: {e}",
                event.id()
            ),
        }
    }
}

/// Execute one action and hand its request to the transport. Shared by the model's turns and
/// injected commands.
async fn apply_action(
    protocol: &RadiusClientProtocol,
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
            Ok(Applied::Sent(bytes))
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
    protocol: Arc<RadiusClientProtocol>,
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
        // A password the operator typed is not the shared secret, but it is not something to
        // keep in an access log either.
        let mut logged = action;
        if logged.get("password").is_some() {
            logged["password"] = json!("<redacted>");
        }
        app_state
            .record_access_log(
                AccessLogOwner::Client(client_id.as_u32()),
                protocol.protocol_name(),
                None,
                "injected_action",
                logged,
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
