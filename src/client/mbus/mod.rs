//! M-Bus master: NetGet reads meters through an M-Bus/IP gateway and the model decides what to
//! read and write.
//!
//! Three tasks per connection, all registered with the client:
//!
//! * **transport** owns the socket and the bus: one operation at a time, each a sequence of
//!   telegrams that waits for every answer (a scan is hundreds of them). M-Bus is half duplex —
//!   a second telegram while a meter is still answering the first would garble both — so nothing
//!   is pipelined. It never waits on the model.
//! * **turns** asks the model about each result, in order, and hands its actions back to the
//!   transport. A result produced by an action the model gave in answer to a result is one
//!   turn deeper; at [`MAX_FOLLOWUP_DEPTH`] the chain stops and says so.
//! * **commands** runs injected actions (`[ send ]`, MCP `send_to_client`) down the same path.
//!
//! ## Collisions
//!
//! A master knows two meters answered at once when it reads something that is not one clean
//! answer: a broken telegram, or more bytes after a whole one. After every answer the transport
//! keeps reading for [`COLLISION_WINDOW`] and counts what else arrives, as libmbus does with its
//! "purge"; a secondary search narrows its mask by one digit wherever that happens.
pub mod actions;

use crate::client::llm_budget::call_llm_for_client;
use crate::llm::actions::client_trait::{Client, ClientActionResult};
use crate::llm::actions::protocol_trait::Protocol;
use crate::llm::ollama_client::OllamaClient;
use crate::protocol::Event;
use crate::server::mbus::frame::{self, addr, c, ci, Frame, Parsed};
use crate::server::mbus::records;
use crate::state::app_state::AppState;
use crate::state::client_handles::{ClientCommand, ClientSendOutcome};
use crate::state::{AccessLogOwner, ClientId, ClientStatus};
use actions::{MbusClientProtocol, Operation, Target};
use anyhow::{anyhow, Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};
use tracing::{error, info, warn};

/// How long the transport keeps listening after an answer for a second, colliding one.
pub const COLLISION_WINDOW: Duration = Duration::from_millis(100);
/// Operations accepted and not yet finished; the next is refused.
pub const MAX_QUEUED: usize = 16;
/// How many model turns may follow from one another before the chain stops.
pub const MAX_FOLLOWUP_DEPTH: u32 = 8;
/// The most telegrams one secondary search sends.
pub const MAX_SECONDARY_PROBES: usize = 2048;
/// The most meters one secondary search reports.
pub const MAX_FOUND: usize = 250;

const TURN_QUEUE_CAPACITY: usize = 64;

struct Job {
    operation: Operation,
    depth: u32,
}

enum Outbound {
    Job(Job),
    Disconnect(oneshot::Sender<()>),
}

/// One event for the model, and how deep in a chain it is.
struct Turn {
    event: Event,
    depth: u32,
}

pub struct MbusClient;

impl MbusClient {
    pub async fn connect(
        remote_addr: String,
        timeout: Duration,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        client_id: ClientId,
    ) -> Result<SocketAddr> {
        if remote_addr.trim().is_empty() {
            return Err(anyhow!(
                "the M-Bus client needs a remote_addr (the gateway's host:port); refusing to \
                 connect without one"
            ));
        }
        let stream = TcpStream::connect(&remote_addr)
            .await
            .with_context(|| format!("failed to connect to the M-Bus gateway at {remote_addr}"))?;
        let _ = stream.set_nodelay(true);
        let local_addr = stream.local_addr()?;
        let peer = stream.peer_addr()?;
        info!("M-Bus client {client_id} connected to gateway {peer}");
        app_state
            .update_client_status(client_id, ClientStatus::Connected)
            .await;
        let _ = status_tx.send(format!(
            "[CLIENT] M-Bus client {client_id} connected to {peer}"
        ));
        let _ = status_tx.send("__UPDATE_UI__".to_string());

        let protocol = Arc::new(MbusClientProtocol::new());
        let (outbound_tx, outbound_rx) = mpsc::channel::<Outbound>(MAX_QUEUED);
        let (turn_tx, turn_rx) = mpsc::channel::<Turn>(TURN_QUEUE_CAPACITY);

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
        let _ = turn_tx.try_send(Turn {
            event: Event::new(
                &actions::CONNECTED_EVENT,
                json!({"gateway": peer.to_string()}),
            ),
            depth: 0,
        });
        let (r, w) = tokio::io::split(stream);
        let bus = Bus {
            r,
            w,
            buf: Vec::new(),
            timeout,
            fcb: HashMap::new(),
            initialised: Default::default(),
            client_id,
        };
        app_state
            .spawn_client_task(
                client_id,
                run_transport(
                    bus,
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

/// What came back for one telegram.
#[derive(Debug)]
enum Reply {
    /// Nothing within the response timeout.
    Timeout,
    /// One clean answer and nothing else.
    One(Frame),
    /// More than one answer, or a broken one: meters talked over each other.
    Collision(String),
}

/// The socket and the link-layer state of this master.
struct Bus {
    r: ReadHalf<TcpStream>,
    w: WriteHalf<TcpStream>,
    buf: Vec<u8>,
    timeout: Duration,
    /// The FCB the next REQ_UD2 to each meter carries (keyed by primary address or mask).
    fcb: HashMap<String, bool>,
    /// Meters whose link this session has initialised with SND_NKE: `p<address>`, or a whole
    /// secondary address.
    initialised: std::collections::HashSet<String>,
    client_id: ClientId,
}

impl Bus {
    /// Send one telegram and collect what answers it.
    async fn exchange(&mut self, f: &Frame) -> Result<Reply> {
        // Anything still buffered belongs to an earlier exchange that already ended.
        self.buf.clear();
        let bytes = f.encode()?;
        self.w.write_all(&bytes).await?;
        self.w.flush().await?;
        let deadline = tokio::time::Instant::now() + self.timeout;
        let mut chunk = [0u8; frame::MAX_FRAME_LEN];
        // Until the first whole telegram (or proof of a broken one), within the timeout.
        let first = loop {
            match frame::parse(&self.buf) {
                Parsed::Frame(f, used) => {
                    self.buf.drain(..used);
                    break Ok(f);
                }
                Parsed::Invalid { reason, .. } => break Err(reason),
                Parsed::Incomplete(_) => {}
            }
            match tokio::time::timeout_at(deadline, self.r.read(&mut chunk)).await {
                Err(_) => {
                    if self.buf.is_empty() {
                        return Ok(Reply::Timeout);
                    }
                    break Err(format!(
                        "{} bytes that never became a whole telegram",
                        self.buf.len()
                    ));
                }
                Ok(Ok(0)) => anyhow::bail!("the gateway closed the connection"),
                Ok(Ok(n)) => {
                    self.buf.extend_from_slice(&chunk[..n]);
                    if self.buf.len() > frame::MAX_FRAME_LEN * 2 {
                        break Err("more bytes than a telegram".to_string());
                    }
                }
                Ok(Err(e)) => return Err(e.into()),
            }
        };
        // Then a short window for anyone answering at the same time.
        let window = tokio::time::Instant::now() + COLLISION_WINDOW.min(self.timeout);
        loop {
            match tokio::time::timeout_at(window, self.r.read(&mut chunk)).await {
                Err(_) => break,
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => {
                    self.buf.extend_from_slice(&chunk[..n]);
                    if self.buf.len() > frame::MAX_FRAME_LEN * 4 {
                        break;
                    }
                }
                Ok(Err(e)) => return Err(e.into()),
            }
        }
        let extra = std::mem::take(&mut self.buf);
        Ok(match first {
            Ok(f) if extra.is_empty() => Reply::One(f),
            Ok(_) => {
                let (frames, _) = frame::parse_all(&extra);
                Reply::Collision(format!(
                    "{} more byte(s) ({} more telegram(s)) arrived after the answer",
                    extra.len(),
                    frames.len()
                ))
            }
            Err(reason) => Reply::Collision(format!("a garbled answer: {reason}")),
        })
    }

    /// SND_NKE to a primary address: whether it acknowledged.
    async fn ping(&mut self, a: u8) -> Result<Reply> {
        let reply = self.exchange(&Frame::Short { c: c::SND_NKE, a }).await?;
        if matches!(reply, Reply::One(Frame::Ack)) {
            self.initialised.insert(format!("p{a}"));
            self.fcb.insert(format!("p{a}"), true);
        }
        Ok(reply)
    }

    /// Select by secondary address (mask): the reply.
    async fn select(&mut self, mask: &[u8; 8]) -> Result<Reply> {
        self.exchange(&Frame::Long {
            c: c::SND_UD | c::FCB,
            a: addr::NETWORK_LAYER,
            ci: ci::SELECT,
            data: mask.to_vec(),
        })
        .await
    }

    /// Make `target` addressable: its primary address, or 253 once it is selected.
    async fn address(&mut self, target: &Target) -> std::result::Result<(u8, String), Failure> {
        match target {
            Target::Primary(a) => {
                if !self.initialised.contains(&format!("p{a}")) {
                    // Initialise the link once per session, so the first FCB is the one the
                    // meter expects whatever an earlier master left it at.
                    match self.ping(*a).await.map_err(Failure::io)? {
                        Reply::One(Frame::Ack) => {}
                        Reply::Timeout => {
                            return Err(Failure::new("timeout", "the meter did not answer SND_NKE"))
                        }
                        Reply::Collision(m) => return Err(Failure::new("collision", m)),
                        Reply::One(other) => {
                            return Err(Failure::new(
                                "unexpected_reply",
                                format!("SND_NKE was answered with {}", other.describe()),
                            ))
                        }
                    }
                }
                Ok((*a, format!("p{a}")))
            }
            Target::Secondary(mask) => {
                let key = frame::mask_to_hex(mask);
                // A whole secondary address names one meter: initialise its link once per
                // session as for a primary address. SND_NKE at 253 also ends the selection,
                // so select, reset, select again. A wildcard mask is a probe, not a meter.
                if !key.contains('F') && !self.initialised.contains(&key) {
                    if let Reply::One(Frame::Ack) = self.select(mask).await.map_err(Failure::io)? {
                        let reset = self.exchange(&Frame::Short {
                            c: c::SND_NKE,
                            a: addr::NETWORK_LAYER,
                        });
                        if let Reply::One(Frame::Ack) = reset.await.map_err(Failure::io)? {
                            self.initialised.insert(key.clone());
                            self.fcb.insert(key.clone(), true);
                        }
                    }
                }
                self.select_target(mask, key).await
            }
        }
    }

    async fn select_target(
        &mut self,
        mask: &[u8; 8],
        key: String,
    ) -> std::result::Result<(u8, String), Failure> {
        match self.select(mask).await.map_err(Failure::io)? {
            Reply::One(Frame::Ack) => Ok((addr::NETWORK_LAYER, key)),
            Reply::Timeout => Err(Failure::new(
                "not_selected",
                "no meter answered the selection",
            )),
            Reply::Collision(m) => Err(Failure::new(
                "collision",
                format!("more than one meter matches the selection: {m}"),
            )),
            Reply::One(other) => Err(Failure::new(
                "unexpected_reply",
                format!("the selection was answered with {}", other.describe()),
            )),
        }
    }

    /// REQ_UD2 with the next FCB for `key`; the FCB toggles only when a whole answer came back.
    async fn req_ud2(&mut self, a: u8, key: &str) -> Result<Reply> {
        let fcb = *self.fcb.get(key).unwrap_or(&true);
        let mut reply = self
            .exchange(&Frame::Short {
                c: c::REQ_UD2 | if fcb { c::FCB } else { 0 },
                a,
            })
            .await?;
        if matches!(reply, Reply::Timeout) {
            // The same FCB again asks the meter to repeat what it may already have sent.
            reply = self
                .exchange(&Frame::Short {
                    c: c::REQ_UD2 | if fcb { c::FCB } else { 0 },
                    a,
                })
                .await?;
        }
        if matches!(reply, Reply::One(_)) {
            self.fcb.insert(key.to_string(), !fcb);
        }
        Ok(reply)
    }
}

/// Why an operation produced an error event.
struct Failure {
    kind: &'static str,
    message: String,
}

impl Failure {
    fn new(kind: &'static str, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }
    fn io(e: anyhow::Error) -> Self {
        Self::new("connection", format!("{e:#}"))
    }
}

fn error_event(op: &Operation, target: Option<&Target>, f: Failure) -> Event {
    Event::new(
        &actions::ERROR_EVENT,
        json!({
            "operation": op.name(),
            "target": target.map(Target::json),
            "kind": f.kind,
            "message": f.message,
        }),
    )
}

/// Read a whole readout from a meter.
async fn read(bus: &mut Bus, target: &Target, max: usize) -> std::result::Result<Value, Failure> {
    let (a, key) = bus.address(target).await?;
    let mut meter: Option<Value> = None;
    let mut all = Vec::new();
    let mut telegrams = 0usize;
    let mut truncated = false;
    loop {
        let reply = bus.req_ud2(a, &key).await.map_err(Failure::io)?;
        let f = match reply {
            Reply::One(f) => f,
            Reply::Timeout => {
                return Err(Failure::new(
                    "timeout",
                    format!("no answer to REQ_UD2 (telegram {})", telegrams + 1),
                ))
            }
            Reply::Collision(m) => return Err(Failure::new("collision", m)),
        };
        let (c_field, data, ci_byte) = match &f {
            Frame::Long { c, data, ci, .. } => (*c, data.as_slice(), *ci),
            Frame::Control { c, ci, .. } => (*c, &[][..], *ci),
            other => {
                return Err(Failure::new(
                    "unexpected_reply",
                    format!("REQ_UD2 was answered with {}", other.describe()),
                ))
            }
        };
        if c::function(c_field) != c::function(c::RSP_UD) {
            return Err(Failure::new(
                "unexpected_reply",
                format!("REQ_UD2 was answered with {}", f.describe()),
            ));
        }
        let (header, decoded) = records::decode_response(ci_byte, data)
            .map_err(|e| Failure::new("bad_frame", format!("{e:#}")))?;
        telegrams += 1;
        if meter.is_none() {
            meter = Some(records::header_json(&header));
        }
        all.extend(decoded.records);
        if !decoded.more_records_follow {
            break;
        }
        if telegrams >= max {
            truncated = true;
            // The meter still holds the rest of this readout and would continue it on the
            // next toggled FCB: initialise the link again before the next read.
            bus.initialised.remove(&key);
            break;
        }
    }
    Ok(json!({
        "target": target.json(),
        "meter": meter,
        "records": all,
        "telegrams": telegrams,
        "truncated": truncated,
    }))
}

/// SND_UD to a meter: whether it acknowledged.
async fn send(
    bus: &mut Bus,
    target: &Target,
    ci_byte: u8,
    data: Vec<u8>,
) -> std::result::Result<bool, Failure> {
    let (a, key) = bus.address(target).await?;
    let key = format!("snd-{key}");
    let fcb = *bus.fcb.get(&key).unwrap_or(&true);
    let reply = bus
        .exchange(&Frame::long(
            c::SND_UD | if fcb { c::FCB } else { 0 },
            a,
            ci_byte,
            data,
        ))
        .await
        .map_err(Failure::io)?;
    match reply {
        Reply::One(Frame::Ack) => {
            bus.fcb.insert(key, !fcb);
            Ok(true)
        }
        Reply::Timeout => Ok(false),
        Reply::Collision(m) => Err(Failure::new("collision", m)),
        Reply::One(other) => Err(Failure::new(
            "unexpected_reply",
            format!("SND_UD was answered with {}", other.describe()),
        )),
    }
}

async fn scan_primary(bus: &mut Bus, from: u8, to: u8) -> Result<Value> {
    let mut found = Vec::new();
    let mut collisions = Vec::new();
    let mut probes = 0usize;
    for a in from..=to {
        probes += 1;
        match bus.ping(a).await? {
            Reply::One(Frame::Ack) => found.push(a),
            Reply::Collision(_) => collisions.push(json!(a)),
            _ => {}
        }
    }
    Ok(json!({
        "kind": "primary",
        "found": found,
        "collisions": collisions,
        "probes": probes,
    }))
}

/// The libmbus-style search: select with the mask; where more than one meter answers, fix the
/// next wildcard nibble to each value in turn and look again.
async fn scan_secondary(bus: &mut Bus, mask: [u8; 8]) -> Result<Value> {
    let mut found: Vec<Value> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut collisions = Vec::new();
    let mut probes = 0usize;
    let mut truncated = false;
    // Masks still to try, as 16-character strings, with the position from which their next
    // wildcard is looked for.
    let mut stack: Vec<(String, usize)> = vec![(frame::mask_to_hex(&mask), 0)];
    while let Some((m, from)) = stack.pop() {
        if probes >= MAX_SECONDARY_PROBES || found.len() >= MAX_FOUND {
            truncated = true;
            break;
        }
        probes += 1;
        let bytes = frame::mask_from_hex(&m)?;
        match bus.select(&bytes).await? {
            Reply::Timeout => {}
            Reply::One(Frame::Ack) => {
                // One meter: read it for its whole secondary address.
                probes += 1;
                match bus.req_ud2(addr::NETWORK_LAYER, &m).await? {
                    Reply::One(Frame::Long { ci, data, .. }) => {
                        match records::decode_response(ci, &data) {
                            Ok((h, _)) => {
                                if seen.insert(h.address.to_hex()) {
                                    found.push(records::header_json(&h));
                                }
                            }
                            Err(e) => warn!(
                                "M-Bus client {}: meter selected by {m} sent an undecodable \
                                 answer: {e:#}",
                                bus.client_id
                            ),
                        }
                    }
                    Reply::Collision(_) => expand(&m, from, &mut stack, &mut collisions),
                    _ => {}
                }
            }
            Reply::Collision(_) => expand(&m, from, &mut stack, &mut collisions),
            Reply::One(_) => {}
        }
    }
    Ok(json!({
        "kind": "secondary",
        "found": found,
        "collisions": collisions,
        "probes": probes,
        "truncated": truncated,
    }))
}

/// Push the masks that fix the first wildcard nibble of `m` at or after `from`, highest first so
/// they pop in ascending order. The identification digits are BCD, so there the wildcard is
/// replaced by 0-9. In the manufacturer, version and medium nibbles a meter may hold a real F,
/// which no fixed value selects: after 0-E the nibble is also left a wildcard and the search
/// moves on to the next one.
fn expand(m: &str, from: usize, stack: &mut Vec<(String, usize)>, collisions: &mut Vec<Value>) {
    let chars: Vec<char> = m.chars().collect();
    let Some(pos) = (from..chars.len()).find(|i| chars[*i] == 'F' || chars[*i] == 'f') else {
        // Nothing left to narrow: two meters share this whole secondary address.
        collisions.push(json!(m));
        return;
    };
    let digits: &[char] = if pos < 8 {
        &['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']
    } else {
        &[
            '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F',
        ]
    };
    for d in digits.iter().rev() {
        let mut next = chars.clone();
        next[pos] = *d;
        stack.push((next.into_iter().collect(), pos + 1));
    }
}

/// Carry out one operation: the event it produces.
async fn perform(bus: &mut Bus, op: &Operation) -> Result<Event> {
    Ok(match op {
        Operation::Read {
            target,
            max_telegrams,
        } => match read(bus, target, *max_telegrams).await {
            Ok(v) => Event::new(&actions::DATA_EVENT, v),
            Err(f) if f.kind == "connection" => anyhow::bail!(f.message),
            Err(f) => error_event(op, Some(target), f),
        },
        Operation::ScanPrimary { from, to } => {
            Event::new(&actions::SCAN_EVENT, scan_primary(bus, *from, *to).await?)
        }
        Operation::ScanSecondary { mask } => {
            Event::new(&actions::SCAN_EVENT, scan_secondary(bus, *mask).await?)
        }
        Operation::Write { target, data, .. } => ack_or_error(
            op,
            target,
            send(bus, target, ci::DATA_SEND, data.clone()).await,
        )?,
        Operation::Reset { target, subcode } => ack_or_error(
            op,
            target,
            send(
                bus,
                target,
                ci::APPLICATION_RESET,
                subcode.map(|s| vec![s]).unwrap_or_default(),
            )
            .await,
        )?,
        Operation::Ping { address } => {
            let target = Target::Primary(*address);
            match bus.ping(*address).await? {
                Reply::One(Frame::Ack) => ack_event(op, &target, true),
                Reply::Timeout => ack_event(op, &target, false),
                Reply::Collision(m) => error_event(op, Some(&target), Failure::new("collision", m)),
                Reply::One(other) => error_event(
                    op,
                    Some(&target),
                    Failure::new(
                        "unexpected_reply",
                        format!("SND_NKE was answered with {}", other.describe()),
                    ),
                ),
            }
        }
    })
}

fn ack_event(op: &Operation, target: &Target, acknowledged: bool) -> Event {
    Event::new(
        &actions::ACK_EVENT,
        json!({"operation": op.name(), "target": target.json(), "acknowledged": acknowledged}),
    )
}

fn ack_or_error(
    op: &Operation,
    target: &Target,
    r: std::result::Result<bool, Failure>,
) -> Result<Event> {
    match r {
        Ok(ack) => Ok(ack_event(op, target, ack)),
        Err(f) if f.kind == "connection" => anyhow::bail!(f.message),
        Err(f) => Ok(error_event(op, Some(target), f)),
    }
}

async fn run_transport(
    mut bus: Bus,
    mut outbound_rx: mpsc::Receiver<Outbound>,
    turn_tx: mpsc::Sender<Turn>,
    app_state: Arc<AppState>,
    status_tx: mpsc::UnboundedSender<String>,
    client_id: ClientId,
    turn_abort: tokio::task::AbortHandle,
) {
    let status = loop {
        let Some(out) = outbound_rx.recv().await else {
            break ClientStatus::Disconnected;
        };
        let job = match out {
            Outbound::Disconnect(ack) => {
                let _ = bus.w.shutdown().await;
                let _ = ack.send(());
                info!("M-Bus client {client_id} disconnected on request");
                break ClientStatus::Disconnected;
            }
            Outbound::Job(job) => job,
        };
        let name = job.operation.name();
        match perform(&mut bus, &job.operation).await {
            Ok(event) => {
                info!(
                    "M-Bus client {client_id} {name} finished with {}",
                    event.event_type.id
                );
                if turn_tx
                    .try_send(Turn {
                        event,
                        depth: job.depth,
                    })
                    .is_err()
                {
                    warn!(
                        "M-Bus client {client_id} dropped the result of {name}: the model is \
                         {TURN_QUEUE_CAPACITY} events behind decision=turn_queue_full"
                    );
                }
            }
            Err(e) => {
                error!("M-Bus client {client_id} {name}: connection failed: {e:#}");
                break ClientStatus::Error(format!("{e:#}"));
            }
        }
    };
    turn_abort.abort();
    app_state.remove_client_handle(client_id).await;
    app_state.update_client_status(client_id, status).await;
    let _ = status_tx.send(format!("[CLIENT] M-Bus client {client_id} disconnected"));
    let _ = status_tx.send("__UPDATE_UI__".to_string());
}

enum Applied {
    Queued,
    Disconnect,
}

/// Validate one action and hand it to the transport. Shared by the model's turns and injected
/// commands.
async fn apply_action(
    protocol: &MbusClientProtocol,
    outbound_tx: &mpsc::Sender<Outbound>,
    action: Value,
    depth: u32,
) -> Result<Applied> {
    match protocol.execute_action(action)? {
        ClientActionResult::Custom { name, data } if name == actions::OPERATION_RESULT => {
            let operation = actions::require_operation(&data)?;
            // Queued, not awaited: a long scan must not hold the caller.
            outbound_tx
                .try_send(Outbound::Job(Job { operation, depth }))
                .map_err(|e| match e {
                    mpsc::error::TrySendError::Full(_) => {
                        anyhow!("{MAX_QUEUED} M-Bus operations are already waiting for the bus")
                    }
                    mpsc::error::TrySendError::Closed(_) => anyhow!("the connection is closed"),
                })?;
            Ok(Applied::Queued)
        }
        ClientActionResult::Disconnect => {
            let (ack, done) = oneshot::channel();
            if outbound_tx.send(Outbound::Disconnect(ack)).await.is_ok() {
                let _ = done.await;
            }
            Ok(Applied::Disconnect)
        }
        _ => Ok(Applied::Queued),
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_turns(
    mut turn_rx: mpsc::Receiver<Turn>,
    outbound_tx: mpsc::Sender<Outbound>,
    protocol: Arc<MbusClientProtocol>,
    llm_client: OllamaClient,
    app_state: Arc<AppState>,
    status_tx: mpsc::UnboundedSender<String>,
    client_id: ClientId,
) {
    while let Some(turn) = turn_rx.recv().await {
        let id = turn.event.event_type.id.clone();
        if turn.depth >= MAX_FOLLOWUP_DEPTH {
            warn!(
                "M-Bus client {client_id} {id} not sent to the model: {} turns deep \
                 decision=followup_depth",
                turn.depth
            );
            let _ = status_tx.send(format!(
                "[WARN] M-Bus client {client_id}: {id} not sent to the model, the chain of \
                 follow-ups reached {MAX_FOLLOWUP_DEPTH}"
            ));
            continue;
        }
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
            Some(&turn.event),
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
                    "M-Bus client {client_id} {id} decision={} actions={}",
                    if result.actions.is_empty() {
                        "model_silent"
                    } else {
                        "model_actions"
                    },
                    result.actions.len()
                );
                for action in result.actions {
                    match apply_action(protocol.as_ref(), &outbound_tx, action, turn.depth + 1)
                        .await
                    {
                        Ok(Applied::Disconnect) => return,
                        Ok(Applied::Queued) => {}
                        Err(e) => {
                            error!("M-Bus client {client_id} action refused: {e:#}");
                            let _ = status_tx.send(format!(
                                "[ERROR] M-Bus client {client_id} action refused: {e:#}"
                            ));
                        }
                    }
                }
            }
            Err(e) => error!("M-Bus client {client_id} {id} decision=llm_error: {e:#}"),
        }
    }
}

async fn command_loop(
    mut command_rx: mpsc::Receiver<ClientCommand>,
    protocol: Arc<MbusClientProtocol>,
    outbound_tx: mpsc::Sender<Outbound>,
    client_id: ClientId,
    app_state: Arc<AppState>,
    status_tx: mpsc::UnboundedSender<String>,
) {
    while let Some(command) = command_rx.recv().await {
        let action = command.action.clone();
        let outcome = match apply_action(protocol.as_ref(), &outbound_tx, action.clone(), 0).await {
            Ok(Applied::Queued) => ClientSendOutcome::Executed {
                detail: "queued for the bus; the result arrives as an event".to_string(),
            },
            Ok(Applied::Disconnect) => ClientSendOutcome::Disconnected,
            Err(e) => ClientSendOutcome::Rejected {
                error: format!("{e:#}"),
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
