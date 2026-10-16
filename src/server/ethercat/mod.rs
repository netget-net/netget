//! EtherCAT slave — NetGet as one or more SubDevices on a segment a master (MainDevice) scans,
//! configures and runs to OP.
//!
//! # What runs where
//!
//! One engine task owns the emulated chain ([`esc::Esc`] per slave) and everything with state.
//! A frame is processed by every slave in order the moment it arrives and sent straight back —
//! the model is never in that path, because a master measures a frame's round trip in
//! microseconds and reads a missing slave from the working counter.
//!
//! What a slave's firmware would decide is reported by the ESC as an event after the frame:
//! an upward AL state request, a mailbox the master filled, an output buffer completed. The
//! engine settles the first two by asking the model through a bounded queue (a worker task
//! calls it, one event at a time) and answers when the model does: the AL status stays where
//! it was while the master polls, and the SDO reply appears in the send mailbox when it is
//! ready. Output changes are reported to the model at most every [`OUTPUT_EVENT_INTERVAL`]
//! per slave.
//!
//! # Failing closed
//!
//! An unanswered state change is refused (AL status error bit, code 0x0001); an unanswered
//! SDO is aborted (0x08000020); inputs the model never set keep the slave out of SAFE-OP
//! (AL status code 0x0018), so a master never reads process data nobody chose. Each question
//! logs one `decision=`: `model_accept`, `model_reject`, `model_answer`, `model_silent`,
//! `fail_closed_bad_action`, `fail_closed_llm_error`, `fail_closed_llm_overloaded`,
//! `fail_closed_queue_full`, or `protocol_reject` (the slave refused without asking).
pub mod actions;
pub mod coe;
pub mod device;
pub mod esc;
pub mod frame;
pub mod link;
pub mod sdo;
pub mod sii;

use crate::llm::action_helper::call_llm;
use crate::llm::actions::protocol_trait::{ActionResult, Server};
use crate::llm::ollama_client::OllamaClient;
use crate::logging::emit::Log;
use crate::protocol::{Event, EventType};
use crate::server::connection::ConnectionId;
use crate::state::app_state::AppState;
use crate::state::client_handles::{ClientCommand, ClientSendOutcome};
use crate::state::server::{ConnectionState, ConnectionStatus, ProtocolConnectionInfo};
use crate::state::{AccessLogOwner, ServerId};
use actions::EthercatProtocol;
use anyhow::{bail, Context, Result};
use device::{DeviceSpec, Object};
use esc::{al_code, state, Esc, EscEvent};
use link::{Link, LinkTx, Peer, Received};
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

type Instant = crate::utils::clock::Instant;

/// Events waiting for the model.
pub const MAX_QUEUED_EVENTS: usize = 32;
/// Decisions owed by the model.
pub const MAX_PENDING: usize = 32;
/// At most one `ethercat_outputs_changed` per slave per this interval.
pub const OUTPUT_EVENT_INTERVAL: Duration = Duration::from_millis(200);
/// A master row is dropped after this long without a frame from it.
pub const MASTER_IDLE: Duration = Duration::from_secs(30);
/// Masters tracked at once (each is a connection row).
pub const MAX_MASTERS: usize = 8;
const TICK: Duration = Duration::from_millis(10);

struct Shared {
    app_state: Arc<AppState>,
    llm_client: OllamaClient,
    status_tx: mpsc::UnboundedSender<String>,
    server_id: ServerId,
}

impl Shared {
    fn log(&self) -> Log<'_> {
        Log::new(Some(&self.status_tx))
    }
}

pub struct EthercatServer;

fn transport_is_udp(params: Option<&crate::protocol::StartupParams>) -> Result<bool> {
    match params
        .map(|p| p.get_optional_string("transport"))
        .transpose()?
        .flatten()
        .as_deref()
    {
        None => Ok(false),
        Some(t) if t == link::TRANSPORT_RAW => Ok(false),
        Some(t) if t == link::TRANSPORT_UDP => Ok(true),
        Some(other) => bail!("transport is raw or udp, not {other:?}"),
    }
}

impl EthercatServer {
    pub async fn spawn(ctx: crate::protocol::SpawnContext) -> Result<SocketAddr> {
        let params = ctx.startup_params.as_ref();
        let udp = transport_is_udp(params)?;
        let slaves_param = params
            .map(|p| p.get_optional_array("slaves"))
            .transpose()?
            .flatten()
            .map(|a| Value::Array(a.clone()));
        let slaves = device::segment_from_params(slaves_param.as_ref())?;
        let mailbox = match params
            .map(|p| p.get_optional_u64("mailbox_size"))
            .transpose()?
            .flatten()
        {
            None => sii::DEFAULT_MAILBOX,
            Some(n) => {
                let n = n as usize;
                anyhow::ensure!(
                    (sii::MIN_MAILBOX..=sii::MAX_MAILBOX).contains(&n),
                    "mailbox_size must be {}-{}",
                    sii::MIN_MAILBOX,
                    sii::MAX_MAILBOX
                );
                n
            }
        };
        let link = if udp {
            let host: IpAddr = match ctx.host.as_deref() {
                None | Some("localhost") => IpAddr::V4(Ipv4Addr::LOCALHOST),
                Some(h) => h
                    .parse()
                    .with_context(|| format!("host {h:?} is not an IP address"))?,
            };
            let port = ctx.port.unwrap_or(frame::UDP_PORT);
            Link::open_udp(SocketAddr::new(host, port), None).await?
        } else {
            let iface = ctx.interface().context(
                "raw EtherCAT needs a network interface (the server's interface field, e.g. \
                 eth1); for an unprivileged run set transport to \"udp\"",
            )?;
            Link::open_raw(iface)?
        };
        let local = link
            .local_addr()
            .unwrap_or(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0));
        let n = slaves.len();
        let chain: Vec<Esc> = slaves
            .into_iter()
            .enumerate()
            .map(|(i, d)| Esc::new(i, n, d, mailbox))
            .collect();
        let shared = Arc::new(Shared {
            app_state: ctx.state.clone(),
            llm_client: ctx.llm_client.clone(),
            status_tx: ctx.status_tx.clone(),
            server_id: ctx.server_id,
        });
        shared.log().info(format!(
            "EtherCAT segment of {n} slave(s) [{}] on {}",
            chain
                .iter()
                .map(|e| format!(
                    "{} (vendor {:#010x} product {:#010x}, {} in / {} out octets)",
                    e.device.name,
                    e.device.vendor_id,
                    e.device.product_code,
                    e.device.inputs.bytes(),
                    e.device.outputs.bytes()
                ))
                .collect::<Vec<_>>()
                .join(", "),
            link.describe()
        ));
        let (job_tx, job_rx) = mpsc::channel::<Job>(MAX_QUEUED_EVENTS);
        let (result_tx, result_rx) = mpsc::channel::<WorkerResult>(MAX_QUEUED_EVENTS);
        ctx.state
            .spawn_server_task(ctx.server_id, worker(shared.clone(), job_rx, result_tx))
            .await;
        let (cmd_tx, cmd_rx) = mpsc::channel::<(ConnectionId, ClientCommand)>(16);
        let rt = (0..n).map(|_| SlaveRt::default()).collect();
        let mut engine = Engine {
            shared,
            tx: link.sender(),
            chain,
            rt,
            pending: HashMap::new(),
            next_job: 1,
            jobs: job_tx,
            masters: HashMap::new(),
            cmd_tx,
            bad_frames: 0,
        };
        let task = tokio::spawn(async move { engine.run(link, result_rx, cmd_rx).await });
        ctx.state.register_server_task(ctx.server_id, task).await;
        Ok(local)
    }
}

/// A decision the model owes, and what it settles.
enum Pending {
    State {
        slave: usize,
        to: u8,
    },
    SdoRead {
        slave: usize,
        object: Object,
        seq: u64,
    },
    SdoWrite {
        slave: usize,
        object: Object,
        segment: Option<bool>,
        seq: u64,
    },
    Notice {
        slave: usize,
    },
}

impl Pending {
    fn slave(&self) -> usize {
        match self {
            Pending::State { slave, .. }
            | Pending::SdoRead { slave, .. }
            | Pending::SdoWrite { slave, .. }
            | Pending::Notice { slave } => *slave,
        }
    }
}

struct Job {
    id: u64,
    event: Event,
    conn: Option<ConnectionId>,
}

struct WorkerResult {
    id: u64,
    outcome: std::result::Result<(Vec<(String, Value)>, Vec<String>), (&'static str, String)>,
}

/// The model worker: one event at a time, in order.
async fn worker(
    shared: Arc<Shared>,
    mut jobs: mpsc::Receiver<Job>,
    results: mpsc::Sender<WorkerResult>,
) {
    let protocol = EthercatProtocol::new();
    while let Some(job) = jobs.recv().await {
        let outcome = match call_llm(
            &shared.llm_client,
            &shared.app_state,
            shared.server_id,
            job.conn,
            &job.event,
            &protocol,
        )
        .await
        {
            Ok(exec) => {
                for m in exec.messages {
                    let _ = shared.status_tx.send(m);
                }
                let mut items = Vec::new();
                let mut stack = exec.protocol_results;
                while let Some(r) = stack.pop() {
                    match r {
                        ActionResult::Custom { name, data } => items.push((name, data)),
                        ActionResult::Multiple(v) => stack.extend(v),
                        _ => {}
                    }
                }
                items.reverse();
                let failures = exec
                    .failures
                    .iter()
                    .map(|f| format!("{}: {}", f.action, f.error))
                    .collect();
                Ok((items, failures))
            }
            Err(e) => Err((
                match crate::utils::wire_failure::WireFailure::classify(&e) {
                    crate::utils::wire_failure::WireFailure::Overloaded => {
                        "fail_closed_llm_overloaded"
                    }
                    crate::utils::wire_failure::WireFailure::Unavailable => "fail_closed_llm_error",
                },
                format!("{e:#}"),
            )),
        };
        if results
            .send(WorkerResult {
                id: job.id,
                outcome,
            })
            .await
            .is_err()
        {
            return;
        }
    }
}

/// What the engine keeps per slave besides its ESC.
#[derive(Default)]
struct SlaveRt {
    sdo: sdo::SdoServer,
    /// Counter of the mailboxes this slave sends.
    counter: u8,
    /// Counter of the last mailbox received (a repeat with the same counter is ignored).
    last_rx_counter: u8,
    /// Which SDO request the model is answering; a later request makes an older answer stale.
    sdo_seq: u64,
    outputs: Vec<u8>,
    reported: Option<Vec<u8>>,
    last_output_event: Option<Instant>,
}

struct MasterRow {
    conn_id: ConnectionId,
    last_seen: Instant,
    frames_in: u64,
    bytes_in: u64,
    bytes_out: u64,
    forwarder: tokio::task::AbortHandle,
}

struct Engine {
    shared: Arc<Shared>,
    tx: LinkTx,
    chain: Vec<Esc>,
    rt: Vec<SlaveRt>,
    pending: HashMap<u64, Pending>,
    next_job: u64,
    jobs: mpsc::Sender<Job>,
    masters: HashMap<Peer, MasterRow>,
    cmd_tx: mpsc::Sender<(ConnectionId, ClientCommand)>,
    bad_frames: u64,
}

impl Engine {
    fn log(&self) -> Log<'_> {
        self.shared.log()
    }

    async fn run(
        &mut self,
        mut link: Link,
        mut results: mpsc::Receiver<WorkerResult>,
        mut commands: mpsc::Receiver<(ConnectionId, ClientCommand)>,
    ) {
        let mut buf = vec![0u8; link::MAX_UDP];
        let mut tick = tokio::time::interval(TICK);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut stats_at = Instant::now();
        loop {
            tokio::select! {
                r = link.recv(&mut buf) => match r {
                    Some(r) => self.on_frame(r).await,
                    None => {
                        self.log().error("EtherCAT link closed; the segment stops".to_string());
                        return;
                    }
                },
                r = results.recv() => {
                    if let Some(r) = r {
                        self.on_result(r).await;
                    }
                }
                c = commands.recv() => {
                    if let Some((conn, c)) = c {
                        self.on_command(conn, c).await;
                    }
                }
                _ = tick.tick() => {
                    self.on_tick().await;
                    if stats_at.elapsed() >= Duration::from_secs(1) {
                        stats_at = Instant::now();
                        self.report_stats().await;
                    }
                }
            }
        }
    }

    fn slave_json(&self, i: usize) -> Map<String, Value> {
        let mut m = Map::new();
        m.insert("slave".into(), json!(i));
        m.insert(
            "station_address".into(),
            json!(self.chain[i].station_address()),
        );
        m.insert("name".into(), json!(self.chain[i].device.name));
        m
    }

    fn ask(&mut self, event: Event, pending: Pending) -> bool {
        if self.pending.len() >= MAX_PENDING {
            return false;
        }
        let id = self.next_job;
        self.next_job += 1;
        let conn = self.masters.values().next().map(|m| m.conn_id);
        match self.jobs.try_send(Job { id, event, conn }) {
            Ok(()) => {
                self.pending.insert(id, pending);
                true
            }
            Err(_) => false,
        }
    }

    // ------------------------------------------------------------------ frames

    async fn on_frame(&mut self, rx: Received) {
        let mut payload = rx.payload.clone();
        match esc::process_frame(&mut self.chain, &mut payload) {
            Ok(_) => {}
            Err(e) => {
                self.bad_frames += 1;
                tracing::debug!("EtherCAT frame from {} dropped: {e}", rx.from);
                return;
            }
        }
        if let Err(e) = self.tx.reply(&rx, &payload).await {
            self.log()
                .warn(format!("EtherCAT reply to {} failed: {e:#}", rx.from));
        }
        tracing::trace!("EtherCAT {} ← {}", rx.from, frame::summary(&payload));
        self.track_master(rx.from, payload.len() as u64).await;
        for i in 0..self.chain.len() {
            for ev in self.chain[i].take_events() {
                self.on_esc_event(i, ev).await;
            }
        }
    }

    async fn track_master(&mut self, from: Peer, len: u64) {
        let now = Instant::now();
        if let Some(m) = self.masters.get_mut(&from) {
            m.last_seen = now;
            m.frames_in += 1;
            m.bytes_in += len;
            m.bytes_out += len;
            return;
        }
        if self.masters.len() >= MAX_MASTERS {
            return;
        }
        let state = self.shared.app_state.clone();
        let server_id = self.shared.server_id;
        let conn_id = ConnectionId::new(state.get_next_unified_id().await);
        let (remote, info) = match from {
            Peer::Udp(a) => (a, json!({"master": a.to_string()})),
            Peer::Mac(m) => (
                SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                json!({"master_mac": crate::server::profinet::dcp::format_mac(&m)}),
            ),
        };
        state
            .add_connection_to_server(
                server_id,
                ConnectionState {
                    id: conn_id,
                    remote_addr: remote,
                    local_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                    bytes_sent: 0,
                    bytes_received: 0,
                    packets_sent: 0,
                    packets_received: 0,
                    last_activity: now,
                    status: ConnectionStatus::Active,
                    status_changed_at: now,
                    protocol_info: ProtocolConnectionInfo::new(info),
                },
            )
            .await;
        let mut peer_rx =
            crate::server::peer_support::register_peer_channel(&state, server_id, conn_id.as_u32())
                .await;
        let cmd_tx = self.cmd_tx.clone();
        let forwarder = state
            .spawn_server_task(server_id, async move {
                while let Some(c) = peer_rx.recv().await {
                    if cmd_tx.send((conn_id, c)).await.is_err() {
                        break;
                    }
                }
            })
            .await;
        let _ = self.shared.status_tx.send("__UPDATE_UI__".to_string());
        self.log()
            .info(format!("EtherCAT master {from} on the segment"));
        self.masters.insert(
            from,
            MasterRow {
                conn_id,
                last_seen: now,
                frames_in: 1,
                bytes_in: len,
                bytes_out: len,
                forwarder,
            },
        );
    }

    async fn on_esc_event(&mut self, i: usize, ev: EscEvent) {
        match ev {
            EscEvent::StateRequest { from, to } => {
                let mut data = self.slave_json(i);
                data.insert("from".into(), json!(state::name(from)));
                data.insert("to".into(), json!(state::name(to)));
                data.insert("inputs".into(), self.chain[i].device.inputs.describe());
                data.insert("outputs".into(), self.chain[i].device.outputs.describe());
                data.insert("inputs_set".into(), json!(self.chain[i].inputs_valid));
                let event = Event::new(&actions::STATE_CHANGE_REQUEST_EVENT, Value::Object(data));
                if !self.ask(event, Pending::State { slave: i, to }) {
                    self.chain[i].resolve_transition(to, Err(al_code::UNSPECIFIED));
                    self.log().warn(format!(
                        "EtherCAT slave {i} {} → {} refused: the model's queue is full \
                         decision=fail_closed_queue_full",
                        state::name(from),
                        state::name(to)
                    ));
                }
            }
            EscEvent::StateChanged {
                from,
                to,
                code,
                cause,
            } => {
                if to == state::INIT {
                    self.rt[i].sdo.reset();
                    self.rt[i].sdo_seq += 1;
                    self.rt[i].last_rx_counter = 0;
                }
                if to != state::OP {
                    self.rt[i].reported = None;
                }
                let line = format!(
                    "EtherCAT slave {i} {} → {} ({cause}{})",
                    state::name(from),
                    state::name(to),
                    if code != 0 {
                        format!(", AL status {code:#06x} {}", al_code::text(code))
                    } else {
                        String::new()
                    }
                );
                if code != 0 {
                    self.log().warn(line);
                } else {
                    self.log().info(line);
                }
            }
            EscEvent::StateRefused {
                from,
                to,
                code,
                why,
            } => {
                self.log().warn(format!(
                    "EtherCAT slave {i} {} → {} refused with AL status {code:#06x} ({}): {why} \
                     decision=protocol_reject",
                    state::name(from),
                    state::name(to),
                    al_code::text(code)
                ));
            }
            EscEvent::Mailbox(area) => {
                self.chain[i].mailbox_consumed();
                self.on_mailbox(i, &area).await;
            }
            EscEvent::Outputs(area) => {
                self.rt[i].outputs = area;
            }
        }
    }

    // ------------------------------------------------------------------ mailbox

    fn post_coe(&mut self, i: usize, data: Vec<u8>) {
        let c = coe::next_counter(self.rt[i].counter);
        self.rt[i].counter = c;
        let size = self.chain[i].send_mailbox_len();
        let m = coe::coe_mailbox(c, data).encode(size);
        self.chain[i].post_mailbox(m);
    }

    fn post_error(&mut self, i: usize, detail: u16) {
        let c = coe::next_counter(self.rt[i].counter);
        self.rt[i].counter = c;
        let size = self.chain[i].send_mailbox_len();
        let m = coe::error_reply(c, detail).encode(size);
        self.chain[i].post_mailbox(m);
    }

    async fn on_mailbox(&mut self, i: usize, area: &[u8]) {
        let m = match coe::Mailbox::parse(area) {
            Ok(m) => m,
            Err(e) => {
                tracing::debug!("EtherCAT slave {i}: bad mailbox: {e:#}");
                self.post_error(i, coe::mbx_error::INVALID_SIZE);
                return;
            }
        };
        if m.counter != 0 && m.counter == self.rt[i].last_rx_counter {
            // The master repeated a mailbox it already sent; it was answered.
            return;
        }
        self.rt[i].last_rx_counter = m.counter;
        if m.mbx_type != coe::mbx_type::COE {
            self.post_error(i, coe::mbx_error::UNSUPPORTED_PROTOCOL);
            return;
        }
        match coe::coe_service(&m.data) {
            Some(coe::service::SDO_REQUEST) => {}
            Some(_) => {
                self.post_error(i, coe::mbx_error::SERVICE_NOT_SUPPORTED);
                return;
            }
            None => {
                self.post_error(i, coe::mbx_error::SIZE_TOO_SHORT);
                return;
            }
        }
        let req = match coe::parse_request(&m.data) {
            Ok(r) => r,
            Err(e) => {
                tracing::debug!("EtherCAT slave {i}: bad SDO request: {e:#}");
                self.post_coe(i, coe::abort_response(0, 0, coe::abort::COMMAND));
                return;
            }
        };
        self.rt[i].sdo_seq += 1;
        let seq = self.rt[i].sdo_seq;
        let mailbox = self.chain[i].send_mailbox_len();
        let inputs = self.chain[i].input_image();
        let outputs = self.rt[i].outputs.clone();
        let dev = self.chain[i].device.clone();
        let outcome = self.rt[i].sdo.handle(&dev, req, mailbox, &inputs, &outputs);
        match outcome {
            sdo::Outcome::Reply(data) => self.post_coe(i, data),
            sdo::Outcome::Nothing => {}
            sdo::Outcome::AskRead(object) => {
                let mut data = self.slave_json(i);
                data.insert("index".into(), json!(object.index));
                data.insert("subindex".into(), json!(object.subindex));
                data.insert("object".into(), json!(object.name));
                data.insert("data_type".into(), json!(object.ty.name()));
                let event = Event::new(&actions::SDO_READ_EVENT, Value::Object(data));
                let (index, sub) = (object.index, object.subindex);
                if !self.ask(
                    event,
                    Pending::SdoRead {
                        slave: i,
                        object,
                        seq,
                    },
                ) {
                    self.post_coe(i, coe::abort_response(index, sub, coe::abort::TRANSFER));
                    self.log().warn(format!(
                        "EtherCAT slave {i} SDO read {index:#06x}:{sub} aborted: the model's \
                         queue is full decision=fail_closed_queue_full"
                    ));
                }
            }
            sdo::Outcome::AskWrite(object, value, segment) => {
                let mut data = self.slave_json(i);
                data.insert("index".into(), json!(object.index));
                data.insert("subindex".into(), json!(object.subindex));
                data.insert("object".into(), json!(object.name));
                data.insert("data_type".into(), json!(object.ty.name()));
                data.insert("value".into(), value);
                let event = Event::new(&actions::SDO_WRITE_EVENT, Value::Object(data));
                let (index, sub) = (object.index, object.subindex);
                if !self.ask(
                    event,
                    Pending::SdoWrite {
                        slave: i,
                        object,
                        segment,
                        seq,
                    },
                ) {
                    self.post_coe(i, coe::abort_response(index, sub, coe::abort::TRANSFER));
                    self.log().warn(format!(
                        "EtherCAT slave {i} SDO write {index:#06x}:{sub} aborted: the model's \
                         queue is full decision=fail_closed_queue_full"
                    ));
                }
            }
        }
    }

    // ------------------------------------------------------------------ the model's answers

    fn apply_inputs(&mut self, default_slave: usize, data: &Value) -> Result<()> {
        let (slave, values) = actions::input_values(data)?;
        let i = slave.unwrap_or(default_slave);
        let n = self.chain.len();
        let esc = self
            .chain
            .get_mut(i)
            .with_context(|| format!("there is no slave {i} (the segment has {n})"))?;
        anyhow::ensure!(!esc.device.inputs.is_empty(), "slave {i} has no inputs");
        let mut img = esc.input_image();
        esc.device.inputs.encode_into(&values, &mut img)?;
        esc.set_inputs(&img);
        Ok(())
    }

    async fn on_result(&mut self, r: WorkerResult) {
        let Some(pending) = self.pending.remove(&r.id) else {
            return;
        };
        let (items, mut refused, failure) = match r.outcome {
            Ok((items, failures)) => (items, failures, None),
            Err((tag, e)) => (Vec::new(), Vec::new(), Some((tag, e))),
        };
        let slave = pending.slave();
        let mut decisions = Vec::new();
        for (name, data) in items {
            if name == actions::SET_INPUTS {
                if let Err(e) = self.apply_inputs(slave, &data) {
                    refused.push(format!("{name}: {e:#}"));
                }
            } else {
                decisions.push((name, data));
            }
        }
        let refused_text = if refused.is_empty() {
            String::new()
        } else {
            format!(" (refused: {})", refused.join("; "))
        };
        let first = |names: &[&str]| {
            decisions
                .iter()
                .find(|(n, _)| names.contains(&n.as_str()))
                .cloned()
        };
        let why_none = |what: &str| -> (&'static str, String) {
            match &failure {
                Some((tag, e)) => (*tag, format!("{what}: {e}")),
                None if !refused.is_empty() => ("fail_closed_bad_action", what.to_string()),
                None => ("model_silent", what.to_string()),
            }
        };
        match pending {
            Pending::State { slave, to } => {
                let from = self.chain[slave].al_state();
                let decision = first(&[actions::ACCEPT_STATE, actions::REFUSE_STATE]);
                let (result, tag, why) = match decision {
                    Some((n, _)) if n == actions::ACCEPT_STATE => {
                        (Ok(()), "model_accept", String::new())
                    }
                    Some((_, d)) => match actions::refusal_code(d.get("al_status_code")) {
                        Ok(code) => (
                            Err(code),
                            "model_reject",
                            d.get("reason")
                                .and_then(Value::as_str)
                                .unwrap_or("")
                                .to_string(),
                        ),
                        Err(e) => (
                            Err(al_code::UNSPECIFIED),
                            "fail_closed_bad_action",
                            format!("{e:#}"),
                        ),
                    },
                    None => {
                        let (tag, why) = why_none("no decision");
                        (Err(al_code::UNSPECIFIED), tag, why)
                    }
                };
                let code = result.err();
                if !self.chain[slave].resolve_transition(to, result) {
                    self.log().info(format!(
                        "EtherCAT slave {slave}: the answer about {} came after the master asked \
                         for something else; ignored decision={tag}",
                        state::name(to)
                    ));
                    return;
                }
                let now = self.chain[slave].al_state();
                match (now == to, code) {
                    (true, _) => self.log().info(format!(
                        "EtherCAT slave {slave} {} → {} decision={tag}{refused_text}",
                        state::name(from),
                        state::name(to)
                    )),
                    (false, Some(c)) => self.log().warn(format!(
                        "EtherCAT slave {slave} {} → {} refused with AL status {c:#06x} ({}) \
                         decision={tag}: {why}{refused_text}",
                        state::name(from),
                        state::name(to),
                        al_code::text(c)
                    )),
                    (false, None) => self.log().warn(format!(
                        "EtherCAT slave {slave} {} → {} accepted by the model but refused by \
                         the slave: AL status {:#06x} ({}) decision=protocol_reject{refused_text}",
                        state::name(from),
                        state::name(to),
                        self.chain[slave].al_error().unwrap_or(0),
                        al_code::text(self.chain[slave].al_error().unwrap_or(0))
                    )),
                }
            }
            Pending::SdoRead { slave, object, seq } => {
                if seq != self.rt[slave].sdo_seq {
                    return;
                }
                let (index, sub) = (object.index, object.subindex);
                match first(&[actions::SDO_VALUE, actions::SDO_ABORT]) {
                    Some((n, d)) if n == actions::SDO_VALUE => {
                        match actions::sdo_value_bytes(&d, object.ty) {
                            Ok(bytes) => {
                                let mailbox = self.chain[slave].send_mailbox_len();
                                if let sdo::Outcome::Reply(data) =
                                    self.rt[slave].sdo.upload_reply(index, sub, &bytes, mailbox)
                                {
                                    self.post_coe(slave, data);
                                }
                                self.log().info(format!(
                                    "EtherCAT slave {slave} SDO read {index:#06x}:{sub} answered \
                                     decision=model_answer{refused_text}"
                                ));
                            }
                            Err(e) => {
                                self.post_coe(
                                    slave,
                                    coe::abort_response(index, sub, coe::abort::VALUE_RANGE),
                                );
                                self.log().warn(format!(
                                    "EtherCAT slave {slave} SDO read {index:#06x}:{sub} aborted: \
                                     the value does not fit {} decision=fail_closed_bad_action: \
                                     {e:#}",
                                    object.ty.name()
                                ));
                            }
                        }
                    }
                    Some((_, d)) => {
                        let code = coe::abort_code(d.get("abort")).unwrap_or(coe::abort::GENERAL);
                        self.post_coe(slave, coe::abort_response(index, sub, code));
                        self.log().info(format!(
                            "EtherCAT slave {slave} SDO read {index:#06x}:{sub} aborted with \
                             {code:#010x} decision=model_reject{refused_text}"
                        ));
                    }
                    None => {
                        let (tag, why) = why_none("no value");
                        self.post_coe(slave, coe::abort_response(index, sub, coe::abort::TRANSFER));
                        self.log().warn(format!(
                            "EtherCAT slave {slave} SDO read {index:#06x}:{sub} aborted \
                             decision={tag}: {why}{refused_text}"
                        ));
                    }
                }
            }
            Pending::SdoWrite {
                slave,
                object,
                segment,
                seq,
            } => {
                if seq != self.rt[slave].sdo_seq {
                    return;
                }
                let (index, sub) = (object.index, object.subindex);
                match first(&[actions::SDO_ACCEPT, actions::SDO_ABORT]) {
                    Some((n, _)) if n == actions::SDO_ACCEPT => {
                        self.post_coe(
                            slave,
                            sdo::SdoServer::finish_write_reply(index, sub, segment),
                        );
                        self.log().info(format!(
                            "EtherCAT slave {slave} SDO write {index:#06x}:{sub} accepted \
                             decision=model_accept{refused_text}"
                        ));
                    }
                    Some((_, d)) => {
                        let code = coe::abort_code(d.get("abort")).unwrap_or(coe::abort::GENERAL);
                        self.post_coe(slave, coe::abort_response(index, sub, code));
                        self.log().info(format!(
                            "EtherCAT slave {slave} SDO write {index:#06x}:{sub} aborted with \
                             {code:#010x} decision=model_reject{refused_text}"
                        ));
                    }
                    None => {
                        let (tag, why) = why_none("no decision");
                        self.post_coe(slave, coe::abort_response(index, sub, coe::abort::TRANSFER));
                        self.log().warn(format!(
                            "EtherCAT slave {slave} SDO write {index:#06x}:{sub} aborted \
                             decision={tag}: {why}{refused_text}"
                        ));
                    }
                }
            }
            Pending::Notice { slave } => {
                if let Some((tag, e)) = &failure {
                    self.log().warn(format!(
                        "EtherCAT slave {slave}: outputs notice not answered; inputs unchanged \
                         decision={tag}: {e}"
                    ));
                } else if !refused.is_empty() {
                    self.log().warn(format!(
                        "EtherCAT slave {slave}: outputs notice answered with refused actions \
                         decision=fail_closed_bad_action{refused_text}"
                    ));
                }
            }
        }
    }

    async fn on_command(&mut self, conn: ConnectionId, c: ClientCommand) {
        let action = c.action.clone();
        let outcome = match EthercatProtocol::new().execute_action(action.clone()) {
            Ok(ActionResult::Custom { name, data }) if name == actions::SET_INPUTS => {
                match self.apply_inputs(0, &data) {
                    Ok(()) => ClientSendOutcome::Executed {
                        detail: "inputs set".into(),
                    },
                    Err(e) => ClientSendOutcome::Rejected {
                        error: format!("{e:#}"),
                    },
                }
            }
            Ok(_) => ClientSendOutcome::Rejected {
                error: format!(
                    "only {} can be sent to a running segment; the others answer a request",
                    actions::SET_INPUTS
                ),
            },
            Err(e) => ClientSendOutcome::Rejected {
                error: format!("{e:#}"),
            },
        };
        self.shared
            .app_state
            .record_access_log(
                AccessLogOwner::Server(self.shared.server_id.as_u32()),
                "EtherCAT",
                Some(conn.as_u32()),
                "injected_action",
                action,
                vec![serde_json::to_value(&outcome).unwrap_or(Value::Null)],
            )
            .await;
        let _ = c.reply_tx.send(Ok(outcome));
    }

    // ------------------------------------------------------------------ the tick

    async fn on_tick(&mut self) {
        let now = Instant::now();
        for i in 0..self.chain.len() {
            self.chain[i].check_watchdog(now);
            for ev in self.chain[i].take_events() {
                self.on_esc_event(i, ev).await;
            }
            // Output changes in OP, at most one event per interval, with the latest values.
            if self.chain[i].al_state() != state::OP || self.chain[i].device.outputs.is_empty() {
                continue;
            }
            let rt = &self.rt[i];
            if rt.outputs.is_empty() || rt.reported.as_ref() == Some(&rt.outputs) {
                continue;
            }
            if rt
                .last_output_event
                .is_some_and(|t| now.duration_since(t) < OUTPUT_EVENT_INTERVAL)
            {
                continue;
            }
            let outputs = rt.outputs.clone();
            self.rt[i].reported = Some(outputs.clone());
            self.rt[i].last_output_event = Some(now);
            let mut data = self.slave_json(i);
            data.insert(
                "outputs".into(),
                Value::Object(self.chain[i].device.outputs.decode(&outputs)),
            );
            let event = Event::new(&actions::OUTPUTS_CHANGED_EVENT, Value::Object(data));
            if !self.ask(event, Pending::Notice { slave: i }) {
                self.log().warn(format!(
                    "EtherCAT slave {i} outputs change not sent to the model: the queue is full \
                     decision=fail_closed_queue_full"
                ));
            }
        }
        let idle: Vec<Peer> = self
            .masters
            .iter()
            .filter(|(_, m)| now.duration_since(m.last_seen) > MASTER_IDLE)
            .map(|(p, _)| *p)
            .collect();
        for p in idle {
            if let Some(m) = self.masters.remove(&p) {
                m.forwarder.abort();
                let state = self.shared.app_state.clone();
                state
                    .remove_peer_handle(self.shared.server_id, m.conn_id.as_u32())
                    .await;
                state
                    .remove_connection_from_server(self.shared.server_id, m.conn_id)
                    .await;
                let _ = self.shared.status_tx.send("__UPDATE_UI__".to_string());
                self.log().info(format!(
                    "EtherCAT master {p} silent for {} s; its row is closed",
                    MASTER_IDLE.as_secs()
                ));
            }
        }
    }

    async fn report_stats(&mut self) {
        let state = self.shared.app_state.clone();
        for m in self.masters.values_mut() {
            if m.frames_in == 0 {
                continue;
            }
            state
                .update_connection_stats(
                    self.shared.server_id,
                    m.conn_id,
                    Some(m.bytes_in),
                    Some(m.bytes_out),
                    Some(m.frames_in),
                    Some(m.frames_in),
                )
                .await;
            m.frames_in = 0;
            m.bytes_in = 0;
            m.bytes_out = 0;
        }
        if self.bad_frames > 0 {
            tracing::debug!(
                "EtherCAT: {} malformed frame(s) dropped in the last second",
                self.bad_frames
            );
            self.bad_frames = 0;
        }
    }
}

/// The events this server raises (for the emit-site ratchet's readers).
pub fn raised_events() -> Vec<&'static EventType> {
    vec![
        &actions::STATE_CHANGE_REQUEST_EVENT,
        &actions::SDO_READ_EVENT,
        &actions::SDO_WRITE_EVENT,
        &actions::OUTPUTS_CHANGED_EVENT,
    ]
}

/// The device description a segment runs (exposed for tests).
pub fn describe_segment(devices: &[DeviceSpec]) -> Value {
    Value::Array(
        devices
            .iter()
            .enumerate()
            .map(|(i, d)| d.describe(i, 0x1001 + i as u16))
            .collect(),
    )
}
