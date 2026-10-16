//! PROFINET IO device — NetGet as a field device an IO controller (a PLC) discovers,
//! parameterises and exchanges cyclic data with.
//!
//! # What runs where
//!
//! One engine task owns everything that has state: the DCP identity, the RPC endpoint, the
//! ARs, the replay cache and the decisions waiting for the model. It selects over received
//! layer-2 frames (DCP requests and the controller's cyclic output frames), RPC datagrams, the
//! model's answers, operator commands, and a 10 ms tick that runs the watchdogs, the
//! ApplicationReady retransmissions, delayed DCP responses and the output-change events.
//!
//! The model is asked by a separate worker through a bounded queue, so a slow model never
//! delays a cyclic frame, a DCP answer Rust can give alone, or an RPC retransmission reply.
//! Each AR's input provider is its own task, sending the current input image every cycle.
//!
//! # The AR, step by step
//!
//! 1. Connect (RPC opnum 0) — Rust checks every block (types, IOCR timing and FrameIDs, the
//!    frame layout against the expected submodules' data lengths, counts) and refuses a
//!    malformed one itself with the PNIO status naming the block. A well-formed one is put to
//!    the model with the expected layout compared against the device's own; `accept` answers
//!    ARBlockRes/IOCRBlockRes/AlarmCRBlockRes (+ ModuleDiffBlock), and the provider starts.
//! 2. Control/PrmEnd — answered Done by Rust, which then sends its own CControl
//!    ApplicationReady request to the controller and retransmits it until confirmed.
//! 3. Data — `profinet_ar_established` is raised; the controller's output changes arrive as
//!    `profinet_outputs_changed` (at most one per [`OUTPUT_EVENT_INTERVAL`] per AR, carrying
//!    the latest values); the watchdog drops the AR when output frames stop.
//! 4. Release — answered Done; the AR is removed and `profinet_ar_closed` raised.
//!
//! # Failing closed
//!
//! Inputs start with IOPS BAD and zero data and stay that way until the model sets them. A
//! Connect, DCP Set, record read or write the model did not answer is refused with the
//! protocol's own error. Each question logs one `decision=` line: `model_accept`,
//! `model_reject`, `model_answer`, `model_silent`, `fail_closed_bad_action`,
//! `fail_closed_llm_error` / `fail_closed_llm_overloaded`, `fail_closed_queue_full`, or
//! `protocol_reject` when Rust refused without asking.
pub mod actions;
pub mod blocks;
pub mod dcp;
pub mod gsdml;
pub mod l2;
pub mod rpc;
pub mod rt;
pub mod values;

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
use actions::ProfinetProtocol;
use anyhow::{bail, Context, Result};
use blocks::{
    block_type, control_command, iocr_type, AlarmCrBlockReq, ArBlockReq, ControlBlock,
    ExpectedSubmodule, IocrBlockReq, ModuleDiff, RecordRequest,
};
use dcp::{Identity, IpParameters, Pdu, SetItem};
use l2::L2Tx;
use rpc::{connect_error, error_code, error_decode, opnum, ptype, PnioStatus, Uuid};
use rt::{CrLayout, EthFrame};
use serde_json::{json, Map, Value};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use values::SubmoduleSpec;

type Instant = crate::utils::clock::Instant;

/// Events waiting for the model; a full queue refuses the request that raised the event.
pub const MAX_QUEUED_EVENTS: usize = 32;
/// Decisions waiting for the model at once (DCP Sets, Connects, record accesses).
pub const MAX_PENDING: usize = 32;
/// Concurrent ARs: one IO controller AR and one supervisor (device access) AR.
pub const MAX_ARS: usize = 2;
/// The fastest cycle accepted: soft real-time from a tokio timer.
pub const MIN_CYCLE_MICROS: u64 = 1000;
/// The slowest cycle accepted (512 × 128 × 31.25 µs = 2 s is the protocol's own maximum).
pub const MAX_CYCLE_MICROS: u64 = 2_048_000;
/// The longest watchdog accepted.
pub const MAX_WATCHDOG: Duration = Duration::from_secs(60);
/// How often ApplicationReady is retransmitted, and how many times.
pub const CCONTROL_RETRY: Duration = Duration::from_secs(1);
pub const CCONTROL_ATTEMPTS: u32 = 5;
/// At most one `profinet_outputs_changed` per AR per this interval; it carries the latest
/// values, so nothing is lost but intermediate states.
pub const OUTPUT_EVENT_INTERVAL: Duration = Duration::from_millis(200);
/// A controller has this long after ApplicationReady to send its first output frame.
pub const FIRST_FRAME_GRACE: Duration = Duration::from_secs(10);
/// A device-access AR with no RPC for this long is dropped (when the controller names no
/// CMInitiatorActivityTimeoutFactor).
pub const DEFAULT_ACTIVITY_TIMEOUT: Duration = Duration::from_secs(60);
/// RPC responses kept for replay to a retransmitted request.
pub const REPLAY_CACHE: usize = 32;
/// Delayed DCP Identify responses waiting to go out.
pub const MAX_DELAYED_FRAMES: usize = 64;
const TICK: Duration = Duration::from_millis(10);

/// What the startup parameters configure.
struct DeviceConfig {
    lab: bool,
    udp_peer: Option<SocketAddr>,
    identity: Identity,
    layout: Vec<SubmoduleSpec>,
    ip_override: Option<Ipv4Addr>,
    netmask_override: Option<Ipv4Addr>,
    gateway: Ipv4Addr,
}

fn parse_ipv4(params: &crate::protocol::StartupParams, key: &str) -> Result<Option<Ipv4Addr>> {
    params
        .get_optional_string(key)?
        .map(|s| {
            s.parse::<Ipv4Addr>()
                .with_context(|| format!("{key} must be an IPv4 address, got {s:?}"))
        })
        .transpose()
}

fn u16_param(params: &crate::protocol::StartupParams, key: &str, default: u16) -> Result<u16> {
    match params.get_optional_u64(key)? {
        None => Ok(default),
        Some(v) => u16::try_from(v).with_context(|| format!("{key} must be 0-65535, got {v}")),
    }
}

impl DeviceConfig {
    fn from_params(params: Option<&crate::protocol::StartupParams>) -> Result<Self> {
        let empty;
        let params = match params {
            Some(p) => p,
            None => {
                use crate::llm::actions::protocol_trait::Protocol;
                empty = crate::protocol::StartupParams::new(
                    json!({}),
                    ProfinetProtocol::new().get_startup_parameters(),
                )?;
                &empty
            }
        };
        let lab = match params.get_optional_string("transport")?.as_deref() {
            None => false,
            Some(t) if t == crate::server::profinet::l2::TRANSPORT_RAW => false,
            Some(t) if t == crate::server::profinet::l2::TRANSPORT_LAB => true,
            Some(other) => bail!(
                "transport must be \"raw\" (real Ethernet) or \"udp\" (the lab transport), got \
                 {other:?}"
            ),
        };
        let udp_peer = match params.get_optional_string("udp_peer")? {
            None => None,
            Some(t) => {
                if !lab {
                    bail!("udp_peer only applies to transport \"udp\"");
                }
                Some(
                    t.parse::<SocketAddr>()
                        .with_context(|| format!("udp_peer must be HOST:PORT, got {t:?}"))?,
                )
            }
        };
        let name = params
            .get_optional_string("name_of_station")?
            .unwrap_or_else(|| actions::DEFAULT_STATION_NAME.into());
        dcp::validate_station_name(&name)?;
        let type_of_station = params
            .get_optional_string("type_of_station")?
            .unwrap_or_else(|| actions::DEFAULT_TYPE_OF_STATION.into());
        anyhow::ensure!(
            type_of_station.len() <= dcp::MAX_VENDOR_VALUE_LEN
                && type_of_station.bytes().all(|c| (0x20..0x7f).contains(&c)),
            "type_of_station must be at most {} printable ASCII characters",
            dcp::MAX_VENDOR_VALUE_LEN
        );
        let modules = params
            .get_optional_array("modules")?
            .map(|a| Value::Array(a.clone()));
        let layout = actions::layout_from_params(modules.as_ref())?;
        Ok(Self {
            lab,
            udp_peer,
            identity: Identity {
                mac: [0; 6],
                name_of_station: name,
                type_of_station,
                vendor_id: u16_param(params, "vendor_id", actions::DEFAULT_VENDOR_ID)?,
                device_id: u16_param(params, "device_id", actions::DEFAULT_DEVICE_ID)?,
                role: dcp::role::IO_DEVICE,
                ip: IpParameters {
                    ip: Ipv4Addr::UNSPECIFIED,
                    netmask: Ipv4Addr::UNSPECIFIED,
                    gateway: Ipv4Addr::UNSPECIFIED,
                },
                ip_set: true,
                instance: Some((0, 1)),
            },
            layout,
            ip_override: parse_ipv4(params, "ip")?,
            netmask_override: parse_ipv4(params, "netmask")?,
            gateway: parse_ipv4(params, "gateway")?.unwrap_or(Ipv4Addr::UNSPECIFIED),
        })
    }
}

/// The parts of the server every task needs.
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

pub struct ProfinetServer;

impl ProfinetServer {
    pub async fn spawn(ctx: crate::protocol::SpawnContext) -> Result<SocketAddr> {
        let mut cfg = DeviceConfig::from_params(ctx.startup_params.as_ref())?;
        let host: IpAddr = match ctx.host.as_deref() {
            None => IpAddr::V4(Ipv4Addr::LOCALHOST),
            Some("localhost") => IpAddr::V4(Ipv4Addr::LOCALHOST),
            Some(h) => h
                .parse()
                .with_context(|| format!("host {h:?} is not an IP address"))?,
        };
        let IpAddr::V4(host4) = host else {
            bail!("PROFINET IO is IPv4-only; bind an IPv4 host");
        };
        let port = ctx.port.unwrap_or(rpc::RPC_PORT);
        let link = if cfg.lab {
            let seed = ctx.server_id.as_u32() ^ (std::process::id() << 8);
            l2::open_udp(SocketAddr::new(host, 0), cfg.udp_peer, l2::lab_mac(seed)).await?
        } else {
            let iface = ctx.interface().context(
                "raw PROFINET needs a network interface (the server's interface field, e.g. \
                 eth0); for an unprivileged lab run set transport to \"udp\"",
            )?;
            l2::open_raw(iface)?
        };
        // The IP DCP reports is the one controllers will send RPC to, so it has to be the one
        // the RPC endpoint is reachable at.
        let ip = match cfg.ip_override {
            Some(ip) => ip,
            None if !host4.is_unspecified() => host4,
            None => link.ipv4.map(|(ip, _)| ip).with_context(|| {
                format!(
                    "{} has no IPv4 address to report over DCP; give the ip startup parameter",
                    link.description
                )
            })?,
        };
        if !cfg.lab && host4.is_loopback() {
            bail!(
                "raw PROFINET reports {ip} over DCP, but the RPC endpoint would be bound to \
                 {host4}, which no controller on {} can reach. Bind the interface's address \
                 (host) or 0.0.0.0",
                link.description
            );
        }
        let netmask = cfg
            .netmask_override
            .or(link.ipv4.map(|(_, m)| m))
            .unwrap_or(Ipv4Addr::new(255, 255, 255, 0));
        cfg.identity.mac = link.mac;
        cfg.identity.ip = IpParameters {
            ip,
            netmask,
            gateway: cfg.gateway,
        };
        cfg.identity.ip.validate()?;

        let rpc_socket = Arc::new(
            UdpSocket::bind(SocketAddr::new(host, port))
                .await
                .with_context(|| format!("binding the PNIO RPC endpoint on {host}:{port}"))?,
        );
        let local = rpc_socket.local_addr()?;
        let shared = Arc::new(Shared {
            app_state: ctx.state.clone(),
            llm_client: ctx.llm_client.clone(),
            status_tx: ctx.status_tx.clone(),
            server_id: ctx.server_id,
        });
        let log = shared.log();
        if let Some(lab) = link.lab_addr {
            log.info(format!(
                "PROFINET lab link (Ethernet frames in UDP, no real PROFINET node speaks it) on \
                 {lab}"
            ));
        }
        log.info(format!(
            "PROFINET IO device {} ({}, vendor {:#06x} device {:#06x}, MAC {}, IP {ip}) with {} \
             submodules; DCP on {}; PNIO RPC on {local}",
            cfg.identity.name_of_station,
            cfg.identity.type_of_station,
            cfg.identity.vendor_id,
            cfg.identity.device_id,
            dcp::format_mac(&link.mac),
            cfg.layout.len(),
            link.description
        ));

        let (job_tx, job_rx) = mpsc::channel::<Job>(MAX_QUEUED_EVENTS);
        let (result_tx, result_rx) = mpsc::channel::<WorkerResult>(MAX_QUEUED_EVENTS);
        let worker_shared = shared.clone();
        ctx.state
            .spawn_server_task(ctx.server_id, worker(worker_shared, job_rx, result_tx))
            .await;
        let (cmd_tx, cmd_rx) = mpsc::channel::<(ConnectionId, ClientCommand)>(16);
        let image = Arc::new(Mutex::new(InputImage::new(&cfg.layout)));
        let boot = crate::utils::clock::SystemTime::now()
            .duration_since(crate::utils::clock::UNIX_EPOCH)
            .map(|d| d.as_secs() as u32)
            .unwrap_or(0);
        let mut engine = Engine {
            shared: shared.clone(),
            tx: link.tx.clone(),
            mac: link.mac,
            lab: cfg.lab,
            rpc: rpc_socket,
            initial_identity: cfg.identity.clone(),
            identity: cfg.identity,
            layout: cfg.layout,
            image,
            ars: Vec::new(),
            pending: HashMap::new(),
            next_job: 1,
            jobs: job_tx,
            replay: VecDeque::new(),
            in_flight: HashSet::new(),
            boot,
            cmd_tx,
            delayed: Vec::new(),
        };
        let task = tokio::spawn(async move { engine.run(link, result_rx, cmd_rx).await });
        ctx.state.register_server_task(ctx.server_id, task).await;
        Ok(local)
    }
}

/// The device's input image: every submodule's input octets and whether they are valid.
struct InputImage {
    inputs: HashMap<(u16, u16), (Vec<u8>, bool)>,
}

impl InputImage {
    fn new(layout: &[SubmoduleSpec]) -> Self {
        Self {
            inputs: layout
                .iter()
                .map(|s| {
                    // A submodule with no IO data has nothing to fabricate: its IOPS is good.
                    // One with input data is BAD until the model sets it.
                    let no_io = s.input_len() == 0 && s.output_len() == 0;
                    ((s.slot, s.subslot), (vec![0; s.input_len()], no_io))
                })
                .collect(),
        }
    }
}

/// What the provider task reads every cycle besides the image.
struct ProviderCtl {
    data_status: u8,
    iocs_good: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ArPhase {
    AwaitPrmEnd,
    AwaitAppReadyConfirm,
    Data,
}

struct InputCr {
    task: tokio::task::AbortHandle,
    ctl: Arc<Mutex<ProviderCtl>>,
    cycle: Duration,
}

struct OutputCr {
    frame_id: u16,
    layout: CrLayout,
    watchdog: Duration,
    last_rx: Option<Instant>,
    current: HashMap<(u16, u16), (Vec<u8>, u8)>,
    changed: HashSet<(u16, u16)>,
    last_event: Option<Instant>,
    frames: u64,
    frames_reported: u64,
}

struct CControl {
    activity: Uuid,
    datagram: Vec<u8>,
    dest: SocketAddr,
    attempts: u32,
    last_sent: Instant,
}

struct Ar {
    uuid: Uuid,
    session_key: u16,
    ar_type: u16,
    conn_id: ConnectionId,
    controller: ArBlockReq,
    rpc_from: SocketAddr,
    phase: ArPhase,
    input: Option<InputCr>,
    output: Option<OutputCr>,
    expected: Vec<ExpectedSubmodule>,
    cycle_ms: f64,
    established_at: Option<Instant>,
    last_rpc: Instant,
    activity_timeout: Duration,
    ccontrol: Option<CControl>,
    forwarder: tokio::task::AbortHandle,
}

impl Ar {
    fn uuid_text(&self) -> String {
        rpc::format_uuid(&self.uuid)
    }

    fn controller_json(&self) -> Value {
        json!({
            "station_name": self.controller.station_name,
            "mac": dcp::format_mac(&self.controller.initiator_mac),
            "address": self.rpc_from.to_string(),
        })
    }
}

/// A decision the model owes, and what to answer when it comes.
enum Pending {
    DcpSet {
        dst: [u8; 6],
        xid: u32,
        blocks: Vec<(u8, u8)>,
        items: Vec<SetItem>,
    },
    Connect {
        req: rpc::Header,
        from: SocketAddr,
        args_max: u32,
        connect: Box<ConnectPlan>,
    },
    Record {
        req: rpc::Header,
        from: SocketAddr,
        args_max: u32,
        rec: RecordRequest,
    },
    /// An event with nothing waiting on it (established, outputs changed, closed).
    Notice { ar: Option<Uuid> },
}

impl Pending {
    fn ar(&self) -> Option<Uuid> {
        match self {
            Pending::Notice { ar } => *ar,
            Pending::Record { rec, .. } if rec.ar_uuid != [0; 16] => Some(rec.ar_uuid),
            _ => None,
        }
    }
}

struct Job {
    id: u64,
    event: Event,
    conn: Option<ConnectionId>,
}

/// The model's answer: the actions it chose (name, data), the ones that failed validation,
/// or why there is no answer (a `decision=` tag and the error).
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
    let protocol = ProfinetProtocol::new();
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
                        ActionResult::CloseConnection => {
                            items.push((actions::ABORT_AR.to_string(), json!({})))
                        }
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

/// A Connect that passed every protocol check, waiting for the model.
struct ConnectPlan {
    ar: ArBlockReq,
    input: Option<(IocrBlockReq, CrLayout)>,
    output: Option<(IocrBlockReq, CrLayout, u16)>,
    alarm: Option<AlarmCrBlockReq>,
    expected: Vec<ExpectedSubmodule>,
    diffs: Vec<ModuleDiff>,
    states: Vec<(ExpectedSubmodule, &'static str)>,
    wrong: HashSet<(u16, u16)>,
}

/// A refusal Rust gives without asking the model.
struct Refusal {
    status: PnioStatus,
    why: String,
}

fn refuse(code1: u8, code2: u8, why: impl Into<String>) -> Refusal {
    Refusal {
        status: PnioStatus::new(error_code::CONNECT, error_decode::PNIO, code1, code2),
        why: why.into(),
    }
}

struct Engine {
    shared: Arc<Shared>,
    tx: L2Tx,
    mac: [u8; 6],
    lab: bool,
    rpc: Arc<UdpSocket>,
    identity: Identity,
    initial_identity: Identity,
    layout: Vec<SubmoduleSpec>,
    image: Arc<Mutex<InputImage>>,
    ars: Vec<Ar>,
    pending: HashMap<u64, Pending>,
    next_job: u64,
    jobs: mpsc::Sender<Job>,
    replay: VecDeque<(Uuid, u32, SocketAddr, Vec<u8>)>,
    /// (activity, seq) of requests waiting for the model, so a retransmission is not a second
    /// question.
    in_flight: HashSet<(Uuid, u32)>,
    boot: u32,
    cmd_tx: mpsc::Sender<(ConnectionId, ClientCommand)>,
    delayed: Vec<(Instant, Vec<u8>)>,
}

impl Engine {
    fn log(&self) -> Log<'_> {
        self.shared.log()
    }

    async fn run(
        &mut self,
        mut link: l2::L2Link,
        mut results: mpsc::Receiver<WorkerResult>,
        mut commands: mpsc::Receiver<(ConnectionId, ClientCommand)>,
    ) {
        let rpc = self.rpc.clone();
        let mut buf = vec![0u8; 2048];
        let mut tick = tokio::time::interval(TICK);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut stats_at = Instant::now();
        loop {
            tokio::select! {
                f = link.rx.recv() => match f {
                    Some(f) => self.on_frame(f).await,
                    None => {
                        self.log().error("PROFINET link closed; the device stops".to_string());
                        return;
                    }
                },
                r = rpc.recv_from(&mut buf) => match r {
                    Ok((n, from)) => {
                        let datagram = buf[..n].to_vec();
                        self.on_rpc(&datagram, from).await;
                    }
                    Err(e) => self.log().warn(format!("PNIO RPC receive failed: {e}")),
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

    // ---------------------------------------------------------------- the model's queue

    fn ask(&mut self, event: Event, conn: Option<ConnectionId>, pending: Pending) -> bool {
        if self.pending.len() >= MAX_PENDING {
            return false;
        }
        let id = self.next_job;
        self.next_job += 1;
        match self.jobs.try_send(Job { id, event, conn }) {
            Ok(()) => {
                self.pending.insert(id, pending);
                true
            }
            Err(_) => false,
        }
    }

    fn notify(&mut self, event: &'static EventType, data: Value, ar: &Ar) {
        let label = event.id.clone();
        if !self.ask(
            Event::new(event, data),
            Some(ar.conn_id),
            Pending::Notice { ar: Some(ar.uuid) },
        ) {
            self.log().warn(format!(
                "PROFINET {label} for AR {} not sent to the model: the queue is full \
                 decision=fail_closed_queue_full",
                ar.uuid_text()
            ));
        }
    }

    // ---------------------------------------------------------------- layer 2

    async fn on_frame(&mut self, f: EthFrame) {
        let Some(fid) = rt::frame_id_of(&f.payload) else {
            return;
        };
        if dcp::is_dcp_frame_id(fid) {
            if f.dst != self.mac && f.dst != dcp::MULTICAST_IDENTIFY && f.dst != [0xff; 6] {
                return;
            }
            match Pdu::parse(&f.payload) {
                Ok(pdu) => self.on_dcp(f.src, pdu).await,
                Err(e) => self.log().debug(format!(
                    "PROFINET DCP frame from {} dropped decision=protocol_reject: {e:#}",
                    dcp::format_mac(&f.src)
                )),
            }
            return;
        }
        if rt::RT_CLASS_1_FRAME_IDS.contains(&fid) {
            self.on_cyclic(f, fid);
        }
    }

    fn send_frame(&self, dst: [u8; 6], payload: &[u8]) {
        if let Err(e) = self.tx.send(rt::build_eth(dst, self.mac, None, payload)) {
            self.log().warn(format!(
                "PROFINET frame to {} not sent: {e:#}",
                dcp::format_mac(&dst)
            ));
        }
    }

    fn ar_active(&self) -> bool {
        self.ars
            .iter()
            .any(|a| a.ar_type == blocks::ar_type::IOC_AR_SINGLE)
    }

    async fn on_dcp(&mut self, src: [u8; 6], pdu: Pdu) {
        if !pdu.is_request() {
            return;
        }
        match (pdu.frame_id, pdu.service_id) {
            (dcp::frame_id::IDENTIFY_REQUEST, dcp::service::IDENTIFY) => {
                if !self.identity.matches_filter(&pdu.blocks) {
                    return;
                }
                let reply = Pdu {
                    frame_id: dcp::frame_id::IDENTIFY_RESPONSE,
                    service_id: dcp::service::IDENTIFY,
                    service_type: dcp::service_type::RESPONSE_SUCCESS,
                    xid: pdu.xid,
                    response_delay: 0,
                    blocks: self.identity.identify_blocks(),
                };
                let Ok(bytes) = reply.encode() else {
                    return;
                };
                let factor = pdu.response_delay.min(dcp::MAX_RESPONSE_DELAY_FACTOR);
                if factor > 1 {
                    // Spread the answers of many devices: a slot derived from our MAC.
                    let slot = u32::from_be_bytes([0, self.mac[3], self.mac[4], self.mac[5]])
                        % factor as u32;
                    if self.delayed.len() < MAX_DELAYED_FRAMES {
                        let frame = rt::build_eth(src, self.mac, None, &bytes);
                        self.delayed.push((
                            Instant::now() + Duration::from_millis(slot as u64 * 10),
                            frame,
                        ));
                    }
                } else {
                    self.send_frame(src, &bytes);
                }
                self.log().debug(format!(
                    "PROFINET DCP Identify from {} answered as {}",
                    dcp::format_mac(&src),
                    self.identity.name_of_station
                ));
            }
            (dcp::frame_id::GET_SET, dcp::service::GET) => {
                let blocks = pdu
                    .blocks
                    .iter()
                    .map(|b| {
                        self.identity
                            .block(b.option, b.suboption)
                            .unwrap_or_else(|| {
                                dcp::set_response_block(
                                    b.option,
                                    b.suboption,
                                    dcp::block_error::SUBOPTION_NOT_SUPPORTED,
                                )
                            })
                    })
                    .collect();
                self.dcp_reply(src, &pdu, blocks);
            }
            (dcp::frame_id::GET_SET, dcp::service::SET) => self.on_dcp_set(src, pdu),
            _ => {}
        }
    }

    fn dcp_reply(&self, dst: [u8; 6], req: &Pdu, blocks: Vec<dcp::Block>) {
        let reply = Pdu {
            frame_id: req.frame_id,
            service_id: req.service_id,
            service_type: dcp::service_type::RESPONSE_SUCCESS,
            xid: req.xid,
            response_delay: 0,
            blocks,
        };
        match reply.encode() {
            Ok(bytes) => self.send_frame(dst, &bytes),
            Err(e) => self
                .log()
                .error(format!("PROFINET DCP reply not encoded: {e:#}")),
        }
    }

    fn on_dcp_set(&mut self, src: [u8; 6], pdu: Pdu) {
        let opts: Vec<(u8, u8)> = pdu.blocks.iter().map(|b| (b.option, b.suboption)).collect();
        let answer_all = |code: u8| -> Vec<dcp::Block> {
            opts.iter()
                .map(|(o, s)| dcp::set_response_block(*o, *s, code))
                .collect()
        };
        let items = match dcp::parse_set_request(&pdu.blocks) {
            Ok(items) => items,
            Err(e) => {
                self.log().warn(format!(
                    "PROFINET DCP Set from {} refused decision=protocol_reject: {e:#}",
                    dcp::format_mac(&src)
                ));
                self.dcp_reply(src, &pdu, answer_all(dcp::block_error::SET_NOT_POSSIBLE));
                return;
            }
        };
        if !items.iter().any(SetItem::is_decision) {
            // Start/Stop brackets alone change nothing; unsupported options are answered so.
            let blocks = items
                .iter()
                .map(|i| {
                    let (o, s) = i.option();
                    let code = if matches!(i, SetItem::Unsupported { .. }) {
                        dcp::block_error::SUBOPTION_NOT_SUPPORTED
                    } else {
                        dcp::block_error::OK
                    };
                    dcp::set_response_block(o, s, code)
                })
                .collect();
            self.dcp_reply(src, &pdu, blocks);
            return;
        }
        let mut data = json!({
            "controller_mac": dcp::format_mac(&src),
            "current": {
                "name_of_station": self.identity.name_of_station,
                "ip": self.identity.ip.ip.to_string(),
                "netmask": self.identity.ip.netmask.to_string(),
                "gateway": self.identity.ip.gateway.to_string(),
            },
            "ar_active": self.ar_active(),
        });
        for item in &items {
            match item {
                SetItem::NameOfStation { name, permanent } => {
                    data["name_of_station"] = json!(name);
                    data["permanent"] = json!(permanent);
                }
                SetItem::Ip { ip, permanent } => {
                    data["ip"] = json!({"ip": ip.ip.to_string(), "netmask": ip.netmask.to_string(),
                                        "gateway": ip.gateway.to_string()});
                    data["permanent"] = json!(permanent);
                }
                SetItem::Signal => data["signal"] = json!(true),
                SetItem::FactoryReset | SetItem::ResetToFactory { .. } => {
                    data["factory_reset"] = json!(true)
                }
                _ => {}
            }
        }
        let xid = pdu.xid;
        if !self.ask(
            Event::new(&actions::DCP_SET_REQUEST_EVENT, data),
            None,
            Pending::DcpSet {
                dst: src,
                xid,
                blocks: opts.clone(),
                items,
            },
        ) {
            self.log().warn(format!(
                "PROFINET DCP Set from {} refused: the model's queue is full \
                 decision=fail_closed_queue_full",
                dcp::format_mac(&src)
            ));
            self.dcp_reply(src, &pdu, answer_all(dcp::block_error::RESOURCE_ERROR));
        }
    }

    fn send_set_response(&self, dst: [u8; 6], xid: u32, blocks: Vec<dcp::Block>) {
        let pdu = Pdu {
            frame_id: dcp::frame_id::GET_SET,
            service_id: dcp::service::SET,
            service_type: dcp::service_type::REQUEST,
            xid,
            response_delay: 0,
            blocks: Vec::new(),
        };
        self.dcp_reply(dst, &pdu, blocks);
    }

    fn apply_dcp_set(&mut self, items: &[SetItem]) -> Vec<dcp::Block> {
        let mut out = Vec::new();
        for item in items {
            let (o, s) = item.option();
            let code = match item {
                SetItem::NameOfStation { name, .. } => {
                    self.identity.name_of_station = name.clone();
                    self.log().info(format!(
                        "PROFINET station name is now {:?}",
                        self.identity.name_of_station
                    ));
                    dcp::block_error::OK
                }
                SetItem::Ip { ip, .. } => {
                    self.identity.ip = *ip;
                    self.identity.ip_set = ip.ip != Ipv4Addr::UNSPECIFIED;
                    self.log().info(format!(
                        "PROFINET IP parameters are now {}/{} gw {} (reported over DCP; the \
                         host's own address is unchanged)",
                        ip.ip, ip.netmask, ip.gateway
                    ));
                    dcp::block_error::OK
                }
                SetItem::Signal => {
                    self.log()
                        .info("PROFINET DCP Signal: the identification LED flashes".to_string());
                    dcp::block_error::OK
                }
                SetItem::FactoryReset | SetItem::ResetToFactory { .. } => {
                    self.identity = Identity {
                        mac: self.mac,
                        ..self.initial_identity.clone()
                    };
                    self.log()
                        .info("PROFINET identity reset to its startup values".to_string());
                    dcp::block_error::OK
                }
                SetItem::Start | SetItem::Stop => dcp::block_error::OK,
                SetItem::Unsupported { .. } => dcp::block_error::SUBOPTION_NOT_SUPPORTED,
            };
            out.push(dcp::set_response_block(o, s, code));
        }
        out
    }

    fn on_cyclic(&mut self, f: EthFrame, fid: u16) {
        let Some(ar) = self.ars.iter_mut().find(|a| {
            a.output.as_ref().is_some_and(|o| o.frame_id == fid)
                && a.controller.initiator_mac == f.src
        }) else {
            return;
        };
        let out = ar.output.as_mut().expect("checked above");
        let Ok(frame) = rt::parse_rt(&f.payload, out.layout.data_length) else {
            return;
        };
        out.last_rx = Some(Instant::now());
        out.frames += 1;
        for o in &out.layout.objects {
            let data = frame.c_sdu[o.offset..o.offset + o.len].to_vec();
            let iops = frame.c_sdu[o.iops_offset()];
            let key = (o.slot, o.subslot);
            if out.current.get(&key) != Some(&(data.clone(), iops)) {
                out.current.insert(key, (data, iops));
                out.changed.insert(key);
            }
        }
    }

    // ---------------------------------------------------------------- RPC

    async fn send_rpc(&self, bytes: &[u8], to: SocketAddr) {
        if let Err(e) = self.rpc.send_to(bytes, to).await {
            self.log()
                .warn(format!("PNIO RPC send to {to} failed: {e}"));
        }
    }

    async fn reply(&mut self, req: &rpc::Header, from: SocketAddr, ptype_value: u8, body: &[u8]) {
        let header = req.response_to(ptype_value, self.boot);
        match rpc::encode(&header, body) {
            Ok(bytes) => {
                self.send_rpc(&bytes, from).await;
                self.in_flight.remove(&(req.activity, req.seqnum));
                if ptype_value == ptype::RESPONSE {
                    if self.replay.len() >= REPLAY_CACHE {
                        self.replay.pop_front();
                    }
                    self.replay
                        .push_back((req.activity, req.seqnum, from, bytes));
                }
            }
            Err(e) => self
                .log()
                .error(format!("PNIO response not encoded: {e:#}")),
        }
    }

    async fn reply_status(
        &mut self,
        req: &rpc::Header,
        from: SocketAddr,
        args_max: u32,
        status: PnioStatus,
        blocks: &[u8],
    ) {
        let body = rpc::ndr_response(status, args_max, blocks);
        self.reply(req, from, ptype::RESPONSE, &body).await;
    }

    async fn on_rpc(&mut self, datagram: &[u8], from: SocketAddr) {
        let (hdr, body) = match rpc::parse(datagram) {
            Ok(x) => x,
            Err(e) => {
                self.log().debug(format!(
                    "PNIO datagram from {from} dropped decision=protocol_reject: {e:#}"
                ));
                return;
            }
        };
        let body = body.to_vec();
        match hdr.ptype {
            ptype::REQUEST => {}
            ptype::RESPONSE | ptype::FAULT | ptype::REJECT => {
                self.on_ccontrol_answer(&hdr, &body, from);
                return;
            }
            ptype::PING => {
                let cached = self
                    .replay
                    .iter()
                    .find(|(a, s, _, _)| *a == hdr.activity && *s == hdr.seqnum)
                    .map(|(_, _, _, b)| b.clone());
                if let Some(bytes) = cached {
                    self.send_rpc(&bytes, from).await;
                } else {
                    let t = if self.in_flight.contains(&(hdr.activity, hdr.seqnum)) {
                        ptype::WORKING
                    } else {
                        ptype::NOCALL
                    };
                    let h = hdr.response_to(t, self.boot);
                    if let Ok(bytes) = rpc::encode(&h, &[]) {
                        self.send_rpc(&bytes, from).await;
                    }
                }
                return;
            }
            _ => return,
        }
        // A retransmitted request: replay the answer, or keep quiet while the model thinks.
        if let Some((_, _, _, bytes)) = self
            .replay
            .iter()
            .find(|(a, s, _, _)| *a == hdr.activity && *s == hdr.seqnum)
        {
            let bytes = bytes.clone();
            self.send_rpc(&bytes, from).await;
            return;
        }
        if self.in_flight.contains(&(hdr.activity, hdr.seqnum)) {
            return;
        }
        if hdr.is_fragmented() {
            self.log().warn(format!(
                "PNIO {} from {from} is fragmented; refused decision=protocol_reject",
                opnum::name(hdr.opnum)
            ));
            self.reply(
                &hdr,
                from,
                ptype::REJECT,
                &rpc::fault_body(rpc::NCA_PROTO_ERROR),
            )
            .await;
            return;
        }
        if hdr.interface != rpc::IF_DEVICE {
            self.reply(
                &hdr,
                from,
                ptype::REJECT,
                &rpc::fault_body(rpc::NCA_UNKNOWN_INTERFACE),
            )
            .await;
            return;
        }
        let (ndr, blocks) = match rpc::parse_ndr_request(&body, hdr.little_endian) {
            Ok(x) => x,
            Err(e) => {
                self.log().warn(format!(
                    "PNIO {} from {from}: bad NDR header decision=protocol_reject: {e:#}",
                    opnum::name(hdr.opnum)
                ));
                let status = PnioStatus::new(
                    op_error_code(hdr.opnum),
                    error_decode::PNIO,
                    connect_error::CMRPC,
                    1,
                );
                self.reply_status(&hdr, from, 0, status, &[]).await;
                return;
            }
        };
        let blocks = blocks.to_vec();
        let args_max = ndr.args_maximum;
        match hdr.opnum {
            opnum::CONNECT => self.on_connect(hdr, from, args_max, &blocks).await,
            opnum::RELEASE => self.on_release(hdr, from, args_max, &blocks).await,
            opnum::CONTROL => self.on_control(hdr, from, args_max, &blocks).await,
            opnum::READ | opnum::READ_IMPLICIT | opnum::WRITE => {
                self.on_record(hdr, from, args_max, &blocks).await
            }
            _ => {
                self.reply(
                    &hdr,
                    from,
                    ptype::FAULT,
                    &rpc::fault_body(rpc::NCA_OP_RANGE_ERROR),
                )
                .await
            }
        }
    }

    async fn on_connect(
        &mut self,
        hdr: rpc::Header,
        from: SocketAddr,
        args_max: u32,
        blocks: &[u8],
    ) {
        let plan = match self.plan_connect(blocks) {
            Ok(p) => p,
            Err(r) => {
                self.log().warn(format!(
                    "PROFINET Connect from {from} refused with {} decision=protocol_reject: {}",
                    r.status.describe(),
                    r.why
                ));
                self.reply_status(&hdr, from, args_max, r.status, &[]).await;
                return;
            }
        };
        let ar_type_name = if plan.ar.ar_type == blocks::ar_type::IOS_AR {
            "supervisor_device_access"
        } else {
            "io_controller"
        };
        let cycle = plan
            .input
            .as_ref()
            .map(|(r, _)| r.cycle_micros() as f64 / 1000.0);
        let watchdog = plan
            .output
            .as_ref()
            .map(|(r, _, _)| r.cycle_micros() as f64 * r.watchdog_factor as f64 / 1000.0);
        let submodules: Vec<Value> = plan
            .states
            .iter()
            .map(|(e, state)| {
                let mut v = json!({
                    "slot": e.slot,
                    "subslot": e.subslot,
                    "module_ident": format!("{:#010x}", e.module_ident),
                    "submodule_ident": format!("{:#010x}", e.submodule_ident),
                    "input_length": e.input_length,
                    "output_length": e.output_length,
                    "state": state,
                });
                if let Some(s) = self.spec(e.slot, e.subslot) {
                    v["inputs"] = values::fields_json(&s.inputs);
                    v["outputs"] = values::fields_json(&s.outputs);
                }
                v
            })
            .collect();
        let data = json!({
            "ar_uuid": rpc::format_uuid(&plan.ar.ar_uuid),
            "ar_type": ar_type_name,
            "controller": {
                "station_name": plan.ar.station_name,
                "mac": dcp::format_mac(&plan.ar.initiator_mac),
                "address": from.to_string(),
            },
            "submodules": submodules,
            "cycle_ms": cycle,
            "watchdog_ms": watchdog,
        });
        self.in_flight.insert((hdr.activity, hdr.seqnum));
        let key = (hdr.activity, hdr.seqnum);
        if !self.ask(
            Event::new(&actions::CONNECT_REQUEST_EVENT, data),
            None,
            Pending::Connect {
                req: hdr.clone(),
                from,
                args_max,
                connect: Box::new(plan),
            },
        ) {
            self.in_flight.remove(&key);
            self.log().warn(format!(
                "PROFINET Connect from {from} refused: the model's queue is full \
                 decision=fail_closed_queue_full"
            ));
            let status = PnioStatus::new(
                error_code::CONNECT,
                error_decode::PNIO,
                connect_error::CMRPC,
                4,
            );
            self.reply_status(&hdr, from, args_max, status, &[]).await;
        }
    }

    fn spec(&self, slot: u16, subslot: u16) -> Option<&SubmoduleSpec> {
        self.layout
            .iter()
            .find(|s| s.slot == slot && s.subslot == subslot)
    }

    /// Every protocol check on a Connect, and the comparison of the expected layout with ours.
    fn plan_connect(&self, data: &[u8]) -> std::result::Result<ConnectPlan, Refusal> {
        let raw = blocks::split_blocks(data)
            .map_err(|e| refuse(connect_error::CMRPC, 1, format!("{e:#}")))?;
        let mut ar = None;
        let mut iocrs = Vec::new();
        let mut alarm = None;
        let mut expected = Vec::new();
        for b in &raw {
            match b.block_type {
                block_type::AR_REQ => {
                    if ar.is_some() {
                        return Err(refuse(connect_error::AR_BLOCK_REQ, 0, "two ARBlockReq"));
                    }
                    ar =
                        Some(ArBlockReq::parse(b.body).map_err(|e| {
                            refuse(connect_error::AR_BLOCK_REQ, 1, format!("{e:#}"))
                        })?);
                }
                block_type::IOCR_REQ => {
                    if iocrs.len() >= blocks::MAX_IOCRS {
                        return Err(refuse(connect_error::IOCR_BLOCK_REQ, 0, "too many IOCRs"));
                    }
                    iocrs.push(
                        IocrBlockReq::parse(b.body).map_err(|e| {
                            refuse(connect_error::IOCR_BLOCK_REQ, 1, format!("{e:#}"))
                        })?,
                    );
                }
                block_type::ALARM_CR_REQ => {
                    alarm = Some(AlarmCrBlockReq::parse(b.body).map_err(|e| {
                        refuse(connect_error::ALARM_CR_BLOCK_REQ, 1, format!("{e:#}"))
                    })?);
                }
                block_type::EXPECTED_SUBMODULE_REQ => {
                    let subs = blocks::parse_expected_submodules(b.body).map_err(|e| {
                        refuse(
                            connect_error::EXPECTED_SUBMODULE_BLOCK_REQ,
                            1,
                            format!("{e:#}"),
                        )
                    })?;
                    if expected.len() + subs.len() > blocks::MAX_SUBMODULES {
                        return Err(refuse(
                            connect_error::EXPECTED_SUBMODULE_BLOCK_REQ,
                            0,
                            format!("more than {} expected submodules", blocks::MAX_SUBMODULES),
                        ));
                    }
                    expected.extend(subs);
                }
                block_type::AR_VENDOR_REQ => {}
                other => {
                    return Err(refuse(
                        connect_error::CMRPC,
                        1,
                        format!("block {other:#06x} is not supported by this device"),
                    ))
                }
            }
        }
        let ar = ar.ok_or_else(|| refuse(connect_error::AR_BLOCK_REQ, 0, "no ARBlockReq"))?;
        let io_ar = match ar.ar_type {
            blocks::ar_type::IOC_AR_SINGLE => true,
            blocks::ar_type::IOS_AR => false,
            other => {
                return Err(refuse(
                    connect_error::AR_BLOCK_REQ,
                    4,
                    format!("ARType {other:#06x} is not IOCARSingle or IOSAR"),
                ))
            }
        };
        if ar.ar_uuid == [0; 16] {
            return Err(refuse(connect_error::AR_BLOCK_REQ, 5, "ARUUID is nil"));
        }
        if self.ars.iter().any(|a| a.uuid == ar.ar_uuid) {
            return Err(refuse(
                connect_error::AR_BLOCK_REQ,
                5,
                "that ARUUID is already in use",
            ));
        }
        if self.ars.len() >= MAX_ARS || (io_ar && self.ar_active()) {
            return Err(refuse(
                connect_error::CMRPC,
                4,
                "out of AR resources (one IO AR and one supervisor AR at a time)",
            ));
        }
        if crate::utils::sanitize::has_controls(&ar.station_name) {
            return Err(refuse(
                connect_error::AR_BLOCK_REQ,
                10,
                "control characters in CMInitiatorStationName",
            ));
        }
        let (mut input, mut output) = (None, None);
        if io_ar {
            if iocrs.len() != 2 {
                return Err(refuse(
                    connect_error::IOCR_BLOCK_REQ,
                    0,
                    format!(
                        "an IOCARSingle needs one input and one output IOCR, got {}",
                        iocrs.len()
                    ),
                ));
            }
            if expected.is_empty() {
                return Err(refuse(
                    connect_error::EXPECTED_SUBMODULE_BLOCK_REQ,
                    0,
                    "no ExpectedSubmoduleBlockReq",
                ));
            }
            for r in &iocrs {
                check_iocr(r)?;
                let is_input = r.iocr_type == iocr_type::INPUT;
                let api = r.apis.first().cloned().unwrap_or_default();
                if r.apis.len() > 1 {
                    return Err(refuse(
                        connect_error::IOCR_BLOCK_REQ,
                        0,
                        "only API 0 is supported",
                    ));
                }
                let len_of = |slot: u16, subslot: u16| {
                    expected
                        .iter()
                        .find(|e| e.slot == slot && e.subslot == subslot)
                        .map(|e| {
                            if is_input {
                                e.input_length as usize
                            } else {
                                e.output_length as usize
                            }
                        })
                };
                for d in api.io_data.iter().chain(api.iocs.iter()) {
                    if len_of(d.slot, d.subslot).is_none() {
                        return Err(refuse(
                            connect_error::IOCR_BLOCK_REQ,
                            0,
                            format!(
                                "IOCR names slot {}/{:#x}, which no ExpectedSubmoduleBlockReq does",
                                d.slot, d.subslot
                            ),
                        ));
                    }
                }
                let layout = CrLayout::from_request(r.data_length, &api.io_data, &api.iocs, len_of)
                    .map_err(|e| refuse(connect_error::IOCR_BLOCK_REQ, 8, format!("{e:#}")))?;
                if is_input {
                    if !rt::RT_CLASS_1_FRAME_IDS.contains(&r.frame_id) {
                        return Err(refuse(
                            connect_error::IOCR_BLOCK_REQ,
                            9,
                            format!("input FrameID {:#06x} is outside RT_CLASS_1", r.frame_id),
                        ));
                    }
                    input = Some((r.clone(), layout));
                } else {
                    let fid = if r.frame_id == 0xffff {
                        // Assign: the first RT_CLASS_1 FrameID no AR here uses.
                        let used: HashSet<u16> = self
                            .ars
                            .iter()
                            .filter_map(|a| a.output.as_ref().map(|o| o.frame_id))
                            .collect();
                        rt::RT_CLASS_1_FRAME_IDS
                            .clone()
                            .find(|f| !used.contains(f))
                            .ok_or_else(|| {
                                refuse(connect_error::IOCR_BLOCK_REQ, 9, "no free FrameID")
                            })?
                    } else if rt::RT_CLASS_1_FRAME_IDS.contains(&r.frame_id) {
                        r.frame_id
                    } else {
                        return Err(refuse(
                            connect_error::IOCR_BLOCK_REQ,
                            9,
                            format!("output FrameID {:#06x} is outside RT_CLASS_1", r.frame_id),
                        ));
                    };
                    output = Some((r.clone(), layout, fid));
                }
            }
            // An output FrameID the device assigned must not collide with the input's.
            if let (Some((i, _)), Some((o, layout, fid))) = (&input, &output) {
                if o.frame_id == 0xffff && i.frame_id == *fid {
                    let used: HashSet<u16> = self
                        .ars
                        .iter()
                        .filter_map(|a| a.output.as_ref().map(|x| x.frame_id))
                        .chain(std::iter::once(i.frame_id))
                        .collect();
                    let next = rt::RT_CLASS_1_FRAME_IDS
                        .clone()
                        .find(|f| !used.contains(f))
                        .ok_or_else(|| {
                            refuse(connect_error::IOCR_BLOCK_REQ, 9, "no free FrameID")
                        })?;
                    output = Some((o.clone(), layout.clone(), next));
                }
            }
            if input.is_none() || output.is_none() {
                return Err(refuse(
                    connect_error::IOCR_BLOCK_REQ,
                    0,
                    "an IOCARSingle needs one input and one output IOCR",
                ));
            }
            if let (Some((i, _)), Some((_, _, o))) = (&input, &output) {
                if i.frame_id == *o {
                    return Err(refuse(
                        connect_error::IOCR_BLOCK_REQ,
                        9,
                        "input and output share a FrameID",
                    ));
                }
            }
        } else if !iocrs.is_empty() {
            return Err(refuse(
                connect_error::IOCR_BLOCK_REQ,
                0,
                "a supervisor AR carries no IOCR",
            ));
        }
        // Compare what the controller expects with what this device has.
        let mut diffs: Vec<ModuleDiff> = Vec::new();
        let mut states = Vec::new();
        let mut wrong = HashSet::new();
        for e in &expected {
            let slot_module = self
                .layout
                .iter()
                .find(|s| s.slot == e.slot)
                .map(|s| s.module_ident);
            let real = self.spec(e.slot, e.subslot);
            let (mstate, sstate, name) = match (slot_module, real) {
                (None, _) => (
                    blocks::module_state::NO_MODULE,
                    blocks::submodule_state::NO_SUBMODULE,
                    "no_module",
                ),
                (Some(m), _) if m != e.module_ident => (
                    blocks::module_state::WRONG_MODULE,
                    blocks::submodule_state::WRONG,
                    "wrong_module",
                ),
                (Some(_), None) => (
                    blocks::module_state::PROPER_MODULE,
                    blocks::submodule_state::NO_SUBMODULE,
                    "no_submodule",
                ),
                (Some(_), Some(s))
                    if s.submodule_ident != e.submodule_ident
                        || s.input_len() != e.input_length as usize
                        || s.output_len() != e.output_length as usize =>
                {
                    (
                        blocks::module_state::PROPER_MODULE,
                        blocks::submodule_state::WRONG,
                        "wrong_submodule",
                    )
                }
                _ => (
                    blocks::module_state::PROPER_MODULE,
                    blocks::submodule_state::OK,
                    "ok",
                ),
            };
            states.push((e.clone(), name));
            if sstate == blocks::submodule_state::OK {
                continue;
            }
            wrong.insert((e.slot, e.subslot));
            let real_ident = real.map(|s| s.submodule_ident).unwrap_or(0);
            match diffs
                .iter_mut()
                .find(|d| d.api == e.api && d.slot == e.slot)
            {
                Some(d) => d.submodules.push((e.subslot, real_ident, sstate)),
                None => diffs.push(ModuleDiff {
                    api: e.api,
                    slot: e.slot,
                    module_ident: slot_module.unwrap_or(0),
                    module_state: mstate,
                    submodules: vec![(e.subslot, real_ident, sstate)],
                }),
            }
        }
        Ok(ConnectPlan {
            ar,
            input,
            output,
            alarm,
            expected,
            diffs,
            states,
            wrong,
        })
    }

    async fn on_release(&mut self, hdr: rpc::Header, from: SocketAddr, args_max: u32, data: &[u8]) {
        let control = blocks::split_blocks(data)
            .ok()
            .and_then(|b| b.first().copied())
            .filter(|b| b.block_type == block_type::RELEASE_REQ)
            .and_then(|b| ControlBlock::parse(&b).ok());
        let Some(c) = control else {
            let status = PnioStatus::new(
                error_code::RELEASE,
                error_decode::PNIO,
                connect_error::RELEASE_BLOCK,
                0,
            );
            self.reply_status(&hdr, from, args_max, status, &[]).await;
            return;
        };
        let Some(pos) = self
            .ars
            .iter()
            .position(|a| a.uuid == c.ar_uuid && a.session_key == c.session_key)
        else {
            let status = PnioStatus::new(
                error_code::RELEASE,
                error_decode::PNIO,
                connect_error::CMRPC,
                5,
            );
            self.reply_status(&hdr, from, args_max, status, &[]).await;
            return;
        };
        let done = c.done().encode();
        self.reply_status(&hdr, from, args_max, PnioStatus::OK, &done)
            .await;
        self.close_ar(pos, "released by the controller").await;
    }

    async fn on_control(&mut self, hdr: rpc::Header, from: SocketAddr, args_max: u32, data: &[u8]) {
        let control = blocks::split_blocks(data)
            .ok()
            .and_then(|b| b.first().copied())
            .and_then(|b| ControlBlock::parse(&b).ok());
        let fail = PnioStatus::new(
            error_code::CONTROL,
            error_decode::PNIO,
            connect_error::CONTROL_BLOCK,
            0,
        );
        let Some(c) = control else {
            self.reply_status(&hdr, from, args_max, fail, &[]).await;
            return;
        };
        let Some(pos) = self
            .ars
            .iter()
            .position(|a| a.uuid == c.ar_uuid && a.session_key == c.session_key)
        else {
            let status = PnioStatus::new(
                error_code::CONTROL,
                error_decode::PNIO,
                connect_error::CMRPC,
                5,
            );
            self.reply_status(&hdr, from, args_max, status, &[]).await;
            return;
        };
        self.ars[pos].last_rpc = Instant::now();
        match (c.block_type, c.control_command) {
            (block_type::PRM_BEGIN_REQ, control_command::PRM_BEGIN) => {
                let done = c.done().encode();
                self.reply_status(&hdr, from, args_max, PnioStatus::OK, &done)
                    .await;
            }
            (block_type::PRM_END_REQ, control_command::PRM_END)
                if self.ars[pos].phase == ArPhase::AwaitPrmEnd =>
            {
                let done = c.done().encode();
                self.reply_status(&hdr, from, args_max, PnioStatus::OK, &done)
                    .await;
                if self.ars[pos].ar_type == blocks::ar_type::IOS_AR {
                    self.ars[pos].phase = ArPhase::Data;
                    return;
                }
                self.start_application_ready(pos).await;
            }
            _ => {
                self.log().warn(format!(
                    "PROFINET Control {:#06x}/{:#06x} for AR {} refused decision=protocol_reject",
                    c.block_type,
                    c.control_command,
                    self.ars[pos].uuid_text()
                ));
                self.reply_status(&hdr, from, args_max, fail, &[]).await;
            }
        }
    }

    async fn start_application_ready(&mut self, pos: usize) {
        let ar = &self.ars[pos];
        let activity = rpc::random_uuid();
        let header = rpc::Header::request(
            ar.controller.initiator_object_uuid,
            rpc::IF_CONTROLLER,
            activity,
            0,
            opnum::CONTROL,
        );
        let block = ControlBlock {
            block_type: block_type::APP_READY_REQ,
            ar_uuid: ar.uuid,
            session_key: ar.session_key,
            control_command: control_command::APPLICATION_READY,
            properties: 0,
        }
        .encode();
        let body = rpc::ndr_request(256, &block);
        let dest = if self.lab {
            ar.rpc_from
        } else {
            SocketAddr::new(ar.rpc_from.ip(), rpc::RPC_PORT)
        };
        let Ok(datagram) = rpc::encode(&header, &body) else {
            return;
        };
        self.send_rpc(&datagram, dest).await;
        let ar = &mut self.ars[pos];
        ar.phase = ArPhase::AwaitAppReadyConfirm;
        if let Some(i) = &ar.input {
            i.ctl.lock().expect("provider ctl").data_status = rt::data_status::GOOD;
        }
        ar.ccontrol = Some(CControl {
            activity,
            datagram,
            dest,
            attempts: 1,
            last_sent: Instant::now(),
        });
    }

    fn on_ccontrol_answer(&mut self, hdr: &rpc::Header, body: &[u8], from: SocketAddr) {
        let Some(pos) = self.ars.iter().position(|a| {
            a.ccontrol
                .as_ref()
                .is_some_and(|c| c.activity == hdr.activity)
        }) else {
            return;
        };
        let confirmed = hdr.ptype == ptype::RESPONSE
            && rpc::parse_ndr_response(body, hdr.little_endian)
                .ok()
                .filter(|(s, _)| s.is_ok())
                .and_then(|(_, b)| {
                    blocks::split_blocks(b)
                        .ok()
                        .and_then(|v| v.first().copied())
                })
                .and_then(|b| ControlBlock::parse(&b).ok())
                .is_some_and(|c| {
                    c.block_type == block_type::APP_READY_RES
                        && c.control_command & control_command::DONE != 0
                });
        let ar = &mut self.ars[pos];
        ar.ccontrol = None;
        if !confirmed {
            self.shared.log().warn(format!(
                "PROFINET ApplicationReady for AR {} was not confirmed by {from} (ptype {}); \
                 the AR stays parameterised but not running",
                ar.uuid_text(),
                hdr.ptype
            ));
            return;
        }
        ar.phase = ArPhase::Data;
        ar.established_at = Some(Instant::now());
        if let Some(i) = &ar.input {
            i.ctl.lock().expect("provider ctl").iocs_good = true;
        }
        let submodules: Vec<Value> = ar
            .expected
            .iter()
            .filter_map(|e| {
                self.layout
                    .iter()
                    .find(|s| s.slot == e.slot && s.subslot == e.subslot)
            })
            .map(SubmoduleSpec::to_json)
            .collect();
        let data = json!({
            "ar_uuid": ar.uuid_text(),
            "controller": ar.controller_json(),
            "submodules": submodules,
            "cycle_ms": ar.cycle_ms,
        });
        self.shared.log().info(format!(
            "PROFINET AR {} with {} is running (cycle {} ms)",
            ar.uuid_text(),
            ar.controller.station_name,
            ar.cycle_ms
        ));
        let ar_ref = &self.ars[pos];
        let (event, ar_uuid, conn) = (
            Event::new(&actions::AR_ESTABLISHED_EVENT, data),
            ar_ref.uuid,
            ar_ref.conn_id,
        );
        if !self.ask(event, Some(conn), Pending::Notice { ar: Some(ar_uuid) }) {
            self.shared.log().warn(format!(
                "PROFINET AR {} established but the model's queue is full; inputs stay BAD \
                 decision=fail_closed_queue_full",
                rpc::format_uuid(&ar_uuid)
            ));
        }
    }

    async fn on_record(&mut self, hdr: rpc::Header, from: SocketAddr, args_max: u32, data: &[u8]) {
        let write = hdr.opnum == opnum::WRITE;
        let implicit = hdr.opnum == opnum::READ_IMPLICIT;
        let ec = if write {
            error_code::WRITE
        } else {
            error_code::READ
        };
        let rw = |code1: u8| PnioStatus::new(ec, error_decode::PNIORW, code1, 0);
        let parsed: Result<(RecordRequest, Vec<u8>)> = if write {
            blocks::split_write_request(data).map(|(r, d)| (r, d.to_vec()))
        } else {
            blocks::split_blocks(data)
                .and_then(|b| {
                    let first = *b.first().context("no IODReadReqHeader")?;
                    RecordRequest::parse(&first)
                })
                .map(|r| (r, Vec::new()))
        };
        let (rec, record) = match parsed {
            Ok(x) => x,
            Err(e) => {
                self.log().warn(format!(
                    "PNIO {} from {from} refused decision=protocol_reject: {e:#}",
                    opnum::name(hdr.opnum)
                ));
                let status =
                    PnioStatus::new(ec, error_decode::PNIO, connect_error::READ_WRITE_HEADER, 0);
                self.reply_status(&hdr, from, args_max, status, &[]).await;
                return;
            }
        };
        if rec.write != write {
            let status =
                PnioStatus::new(ec, error_decode::PNIO, connect_error::READ_WRITE_HEADER, 0);
            self.reply_status(&hdr, from, args_max, status, &[]).await;
            return;
        }
        // An explicit Read or a Write belongs to an AR this device knows.
        let conn = if implicit {
            None
        } else {
            match self.ars.iter_mut().find(|a| a.uuid == rec.ar_uuid) {
                Some(a) => {
                    a.last_rpc = Instant::now();
                    Some(a.conn_id)
                }
                None => {
                    self.log().warn(format!(
                        "PNIO {} for unknown AR {} refused decision=protocol_reject",
                        opnum::name(hdr.opnum),
                        rpc::format_uuid(&rec.ar_uuid)
                    ));
                    self.reply_status(&hdr, from, args_max, rw(rpc::rw_error::ACCESS_DENIED), &[])
                        .await;
                    return;
                }
            }
        };
        if rec.api != 0 || self.spec(rec.slot, rec.subslot).is_none() {
            self.reply_status(
                &hdr,
                from,
                args_max,
                rw(rpc::rw_error::ACCESS_INVALID_SLOT),
                &[],
            )
            .await;
            return;
        }
        if rec.index == blocks::index::WRITE_MULTIPLE || rec.index == blocks::index::IM4 {
            // WriteMultiple is not implemented; I&M4 is a binary signature nobody can author.
            self.log().info(format!(
                "PNIO {} of {} refused: not supported decision=protocol_reject",
                opnum::name(hdr.opnum),
                blocks::index::name(rec.index)
            ));
            self.reply_status(
                &hdr,
                from,
                args_max,
                rw(rpc::rw_error::ACCESS_INVALID_INDEX),
                &[],
            )
            .await;
            return;
        }
        let mut data = json!({
            "slot": rec.slot,
            "subslot": rec.subslot,
            "index": rec.index,
            "record": blocks::index::name(rec.index),
        });
        let event: &'static EventType = if write {
            data["length"] = json!(record.len());
            if let Some(d) = describe_record(rec.index, &record) {
                data["decoded"] = d;
            }
            if !record.is_empty() && record.iter().all(|c| (0x20..0x7f).contains(c)) {
                data["text"] = json!(String::from_utf8_lossy(&record));
            }
            &actions::WRITE_RECORD_EVENT
        } else {
            data["max_length"] = json!(rec.record_data_length);
            data["implicit"] = json!(implicit);
            &actions::READ_RECORD_EVENT
        };
        self.in_flight.insert((hdr.activity, hdr.seqnum));
        let key = (hdr.activity, hdr.seqnum);
        if !self.ask(
            Event::new(event, data),
            conn,
            Pending::Record {
                req: hdr.clone(),
                from,
                args_max,
                rec,
            },
        ) {
            self.in_flight.remove(&key);
            self.log().warn(format!(
                "PNIO {} from {from} refused: the model's queue is full \
                 decision=fail_closed_queue_full",
                opnum::name(hdr.opnum)
            ));
            self.reply_record_error(
                &hdr,
                from,
                args_max,
                &rec,
                rpc::rw_error::RESOURCE_UNAVAILABLE,
            )
            .await;
        }
    }

    async fn reply_record_error(
        &mut self,
        hdr: &rpc::Header,
        from: SocketAddr,
        args_max: u32,
        rec: &RecordRequest,
        code1: u8,
    ) {
        let ec = if rec.write {
            error_code::WRITE
        } else {
            error_code::READ
        };
        let status = PnioStatus::new(ec, error_decode::PNIORW, code1, 0);
        let blocks = if rec.write {
            rec.write_response(status)
        } else {
            Vec::new()
        };
        self.reply_status(hdr, from, args_max, status, &blocks)
            .await;
    }

    // ---------------------------------------------------------------- the model's answers

    async fn on_result(&mut self, r: WorkerResult) {
        let Some(pending) = self.pending.remove(&r.id) else {
            return;
        };
        let (items, mut refused, failure) = match r.outcome {
            Ok((items, failures)) => (items, failures, None),
            Err((tag, e)) => (Vec::new(), Vec::new(), Some((tag, e))),
        };
        // Side effects first: inputs and aborts apply whatever the question was.
        let mut decisions = Vec::new();
        let mut aborted = false;
        let scope = pending.ar();
        for (name, data) in items {
            match name.as_str() {
                actions::SET_INPUTS => {
                    if let Err(e) = self.apply_inputs(&data) {
                        refused.push(format!("{name}: {e:#}"));
                    }
                }
                actions::ABORT_AR => {
                    aborted = true;
                    if let Some(u) = scope {
                        if let Some(pos) = self.ars.iter().position(|a| a.uuid == u) {
                            self.close_ar(pos, "aborted by the model").await;
                        }
                    }
                }
                _ => decisions.push((name, data)),
            }
        }
        let refused_text = if refused.is_empty() {
            String::new()
        } else {
            format!(" (refused: {})", refused.join("; "))
        };
        let has = |n: &str| {
            decisions
                .iter()
                .find(|(name, _)| name == n)
                .map(|(_, d)| d.clone())
        };
        let why_none = |what: &str| -> (&'static str, String) {
            match &failure {
                Some((tag, e)) => (*tag, format!("{what}: {e}")),
                None if !refused.is_empty() => ("fail_closed_bad_action", what.to_string()),
                None => ("model_silent", what.to_string()),
            }
        };
        match pending {
            Pending::DcpSet {
                dst,
                xid,
                blocks,
                items,
            } => {
                if has(actions::ACCEPT_DCP_SET).is_some() {
                    let resp = self.apply_dcp_set(&items);
                    self.log().info(format!(
                        "PROFINET DCP Set from {} decision=model_accept{refused_text}",
                        dcp::format_mac(&dst)
                    ));
                    self.send_set_response(dst, xid, resp);
                } else {
                    let (tag, why) = if has(actions::REFUSE_DCP_SET).is_some() || aborted {
                        ("model_reject", "refused".to_string())
                    } else {
                        why_none("no decision")
                    };
                    self.log().warn(format!(
                        "PROFINET DCP Set from {} not taken decision={tag}: {why}{refused_text}",
                        dcp::format_mac(&dst)
                    ));
                    let resp = blocks
                        .iter()
                        .map(|(o, s)| {
                            dcp::set_response_block(*o, *s, dcp::block_error::SET_NOT_POSSIBLE)
                        })
                        .collect();
                    self.send_set_response(dst, xid, resp);
                }
            }
            Pending::Connect {
                req,
                from,
                args_max,
                connect,
            } => {
                if has(actions::ACCEPT_CONNECT).is_some() && !aborted {
                    match self.establish(&req, from, *connect).await {
                        Ok(blocks) => {
                            self.log().info(format!(
                                "PROFINET Connect from {from} decision=model_accept{refused_text}"
                            ));
                            self.reply_status(&req, from, args_max, PnioStatus::OK, &blocks)
                                .await;
                        }
                        Err(e) => {
                            self.log().error(format!(
                                "PROFINET Connect from {from} accepted but could not start \
                                 decision=fail_closed_bad_action: {e:#}"
                            ));
                            let status = PnioStatus::new(
                                error_code::CONNECT,
                                error_decode::PNIO,
                                connect_error::CMDEV,
                                0,
                            );
                            self.reply_status(&req, from, args_max, status, &[]).await;
                        }
                    }
                } else {
                    let (tag, why) = if has(actions::REFUSE_CONNECT).is_some() || aborted {
                        ("model_reject", "refused".to_string())
                    } else {
                        why_none("no decision")
                    };
                    self.log().warn(format!(
                        "PROFINET Connect from {from} refused decision={tag}: {why}{refused_text}"
                    ));
                    let status = PnioStatus::new(
                        error_code::CONNECT,
                        error_decode::PNIO,
                        connect_error::RMPM,
                        2,
                    );
                    self.reply_status(&req, from, args_max, status, &[]).await;
                }
            }
            Pending::Record {
                req,
                from,
                args_max,
                rec,
            } => {
                let what = blocks::index::name(rec.index);
                if rec.write {
                    if has(actions::ACCEPT_WRITE).is_some() {
                        self.log().info(format!(
                            "PROFINET write of {what} decision=model_accept{refused_text}"
                        ));
                        let blocks = rec.write_response(PnioStatus::OK);
                        self.reply_status(&req, from, args_max, PnioStatus::OK, &blocks)
                            .await;
                    } else {
                        let (tag, code, why) = match has(actions::REFUSE_RECORD) {
                            Some(d) => (
                                "model_reject",
                                actions::refuse_code(&d).unwrap_or(rpc::rw_error::ACCESS_DENIED),
                                "refused".to_string(),
                            ),
                            None => {
                                let (t, w) = why_none("no decision");
                                (t, rpc::rw_error::RESOURCE_UNAVAILABLE, w)
                            }
                        };
                        self.log().warn(format!(
                            "PROFINET write of {what} refused decision={tag}: {why}{refused_text}"
                        ));
                        self.reply_record_error(&req, from, args_max, &rec, code)
                            .await;
                    }
                    return;
                }
                if let Some(d) = has(actions::READ_RESPONSE) {
                    match actions::read_record_bytes(&d, rec.index, self.identity.vendor_id) {
                        Ok(bytes)
                            if bytes.len() as u32
                                <= rec.record_data_length.min(blocks::MAX_RECORD_LEN) =>
                        {
                            self.log().info(format!(
                                "PROFINET read of {what} decision=model_answer: {} octets{refused_text}",
                                bytes.len()
                            ));
                            let mut out = rec.read_response(bytes.len() as u32);
                            out.extend_from_slice(&bytes);
                            self.reply_status(&req, from, args_max, PnioStatus::OK, &out)
                                .await;
                        }
                        Ok(bytes) => {
                            self.log().warn(format!(
                                "PROFINET read of {what}: the answer is {} octets, the controller \
                                 accepts {} decision=fail_closed_bad_action",
                                bytes.len(),
                                rec.record_data_length
                            ));
                            self.reply_record_error(
                                &req,
                                from,
                                args_max,
                                &rec,
                                rpc::rw_error::ACCESS_INVALID_RANGE,
                            )
                            .await;
                        }
                        Err(e) => {
                            self.log().warn(format!(
                                "PROFINET read of {what}: unusable answer \
                                 decision=fail_closed_bad_action: {e:#}"
                            ));
                            self.reply_record_error(
                                &req,
                                from,
                                args_max,
                                &rec,
                                rpc::rw_error::RESOURCE_UNAVAILABLE,
                            )
                            .await;
                        }
                    }
                } else {
                    let (tag, code, why) = match has(actions::REFUSE_RECORD) {
                        Some(d) => (
                            "model_reject",
                            actions::refuse_code(&d).unwrap_or(rpc::rw_error::ACCESS_INVALID_INDEX),
                            "refused".to_string(),
                        ),
                        None => {
                            let (t, w) = why_none("no answer");
                            (t, rpc::rw_error::RESOURCE_UNAVAILABLE, w)
                        }
                    };
                    self.log().warn(format!(
                        "PROFINET read of {what} not answered decision={tag}: {why}{refused_text}"
                    ));
                    self.reply_record_error(&req, from, args_max, &rec, code)
                        .await;
                }
            }
            Pending::Notice { ar } => {
                let label = ar.map(|u| rpc::format_uuid(&u)).unwrap_or_default();
                match failure {
                    Some((tag, e)) => self.log().warn(format!(
                        "PROFINET event for AR {label} not answered; inputs unchanged \
                         decision={tag}: {e}"
                    )),
                    None if !refused.is_empty() => self.log().warn(format!(
                        "PROFINET event for AR {label}: actions refused \
                         decision=fail_closed_bad_action{refused_text}"
                    )),
                    None => self.log().debug(format!(
                        "PROFINET event for AR {label} handled decision=model_answer"
                    )),
                }
            }
        }
    }

    fn apply_inputs(&mut self, data: &Value) -> Result<()> {
        let u = actions::input_update(data)?;
        let spec = self
            .spec(u.slot, u.subslot)
            .with_context(|| format!("no submodule at slot {}/{}", u.slot, u.subslot))?;
        anyhow::ensure!(
            !spec.inputs.is_empty() || u.values.is_empty(),
            "slot {}/{} has no input fields",
            u.slot,
            u.subslot
        );
        let fields = spec.inputs.clone();
        let mut image = self.image.lock().expect("input image");
        let entry = image
            .inputs
            .get_mut(&(u.slot, u.subslot))
            .context("input image has no entry for this submodule")?;
        let mut next = entry.0.clone();
        values::encode_into(&fields, &u.values, &mut next)?;
        *entry = (next, u.good);
        Ok(())
    }

    /// Create the AR for an accepted Connect and return the response blocks.
    async fn establish(
        &mut self,
        req: &rpc::Header,
        from: SocketAddr,
        plan: ConnectPlan,
    ) -> Result<Vec<u8>> {
        let state = self.shared.app_state.clone();
        let server_id = self.shared.server_id;
        let conn_id = ConnectionId::new(state.get_next_unified_id().await);
        let now = Instant::now();
        let local = self.rpc.local_addr().unwrap_or(from);
        state
            .add_connection_to_server(
                server_id,
                ConnectionState {
                    id: conn_id,
                    remote_addr: from,
                    local_addr: local,
                    bytes_sent: 0,
                    bytes_received: 0,
                    packets_sent: 0,
                    packets_received: 0,
                    last_activity: now,
                    status: ConnectionStatus::Active,
                    status_changed_at: now,
                    protocol_info: ProtocolConnectionInfo::new(json!({
                        "ar_uuid": rpc::format_uuid(&plan.ar.ar_uuid),
                        "controller": plan.ar.station_name,
                    })),
                },
            )
            .await;
        let _ = self.shared.status_tx.send("__UPDATE_UI__".to_string());
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

        let mut out = blocks::ArBlockRes {
            ar_type: plan.ar.ar_type,
            ar_uuid: plan.ar.ar_uuid,
            session_key: plan.ar.session_key,
            responder_mac: self.mac,
            responder_udp_rt_port: rpc::RPC_PORT,
        }
        .encode();
        let mut input = None;
        let mut cycle_ms = 0.0;
        if let Some((r, layout)) = &plan.input {
            out.extend(
                blocks::IocrBlockRes {
                    iocr_type: r.iocr_type,
                    iocr_reference: r.iocr_reference,
                    frame_id: r.frame_id,
                }
                .encode(),
            );
            let cycle_us = r.cycle_micros();
            cycle_ms = cycle_us as f64 / 1000.0;
            let ctl = Arc::new(Mutex::new(ProviderCtl {
                data_status: rt::data_status::STOP,
                iocs_good: false,
            }));
            let task = state
                .spawn_server_task(
                    server_id,
                    provide(Provider {
                        tx: self.tx.clone(),
                        src: self.mac,
                        dst: plan.ar.initiator_mac,
                        tag: r.tag_header,
                        frame_id: r.frame_id,
                        cycle: Duration::from_micros(cycle_us),
                        ticks: r.send_clock_factor.wrapping_mul(r.reduction_ratio),
                        layout: layout.clone(),
                        image: self.image.clone(),
                        ctl: ctl.clone(),
                        wrong: plan.wrong.clone(),
                    }),
                )
                .await;
            input = Some(InputCr {
                task,
                ctl,
                cycle: Duration::from_micros(cycle_us),
            });
        }
        let mut output = None;
        if let Some((r, layout, fid)) = &plan.output {
            out.extend(
                blocks::IocrBlockRes {
                    iocr_type: r.iocr_type,
                    iocr_reference: r.iocr_reference,
                    frame_id: *fid,
                }
                .encode(),
            );
            let watchdog = Duration::from_micros(r.cycle_micros() * r.watchdog_factor as u64)
                .min(MAX_WATCHDOG);
            output = Some(OutputCr {
                frame_id: *fid,
                layout: layout.clone(),
                watchdog,
                last_rx: None,
                current: HashMap::new(),
                changed: HashSet::new(),
                last_event: None,
                frames: 0,
                frames_reported: 0,
            });
        }
        if let Some(a) = &plan.alarm {
            out.extend(
                blocks::AlarmCrBlockRes {
                    alarm_cr_type: a.alarm_cr_type,
                    local_alarm_reference: 1,
                    max_alarm_data_length: a.max_alarm_data_length.min(200),
                }
                .encode(),
            );
        }
        if !plan.diffs.is_empty() {
            out.extend(blocks::encode_module_diff(&plan.diffs));
        }
        if plan.ar.ar_properties & blocks::AR_PROPERTIES_STARTUP_ADVANCED != 0 {
            out.extend(blocks::encode_ar_server(&self.identity.name_of_station));
        }
        let activity_timeout = match plan.ar.activity_timeout_factor {
            0 => DEFAULT_ACTIVITY_TIMEOUT,
            f => Duration::from_millis(f as u64 * 100).max(Duration::from_secs(1)),
        };
        self.ars.push(Ar {
            uuid: plan.ar.ar_uuid,
            session_key: plan.ar.session_key,
            ar_type: plan.ar.ar_type,
            conn_id,
            controller: plan.ar,
            rpc_from: from,
            phase: ArPhase::AwaitPrmEnd,
            input,
            output,
            expected: plan.expected,
            cycle_ms,
            established_at: None,
            last_rpc: Instant::now(),
            activity_timeout,
            ccontrol: None,
            forwarder,
        });
        let _ = req;
        Ok(out)
    }

    async fn close_ar(&mut self, pos: usize, reason: &str) {
        let ar = self.ars.remove(pos);
        if let Some(i) = &ar.input {
            i.task.abort();
        }
        ar.forwarder.abort();
        let state = self.shared.app_state.clone();
        state
            .remove_peer_handle(self.shared.server_id, ar.conn_id.as_u32())
            .await;
        state
            .remove_connection_from_server(self.shared.server_id, ar.conn_id)
            .await;
        let _ = self.shared.status_tx.send("__UPDATE_UI__".to_string());
        self.log()
            .info(format!("PROFINET AR {} closed: {reason}", ar.uuid_text()));
        self.notify(
            &actions::AR_CLOSED_EVENT,
            json!({"ar_uuid": ar.uuid_text(), "reason": reason}),
            &ar,
        );
    }

    async fn on_command(&mut self, conn: ConnectionId, c: ClientCommand) {
        let action = c.action.clone();
        let outcome = match ProfinetProtocol::new().execute_action(action.clone()) {
            Ok(ActionResult::Custom { name, data }) if name == actions::SET_INPUTS => {
                match self.apply_inputs(&data) {
                    Ok(()) => ClientSendOutcome::Executed {
                        detail: "inputs set".into(),
                    },
                    Err(e) => ClientSendOutcome::Rejected {
                        error: format!("{e:#}"),
                    },
                }
            }
            Ok(ActionResult::Custom { name, .. }) if name == actions::ABORT_AR => {
                if let Some(pos) = self.ars.iter().position(|a| a.conn_id == conn) {
                    self.close_ar(pos, "aborted by the operator").await;
                }
                ClientSendOutcome::Disconnected
            }
            Ok(ActionResult::CloseConnection) => {
                if let Some(pos) = self.ars.iter().position(|a| a.conn_id == conn) {
                    self.close_ar(pos, "aborted by the operator").await;
                }
                ClientSendOutcome::Disconnected
            }
            Ok(_) => ClientSendOutcome::Rejected {
                error: format!(
                    "only {} and {} can be sent to a running AR; the others answer a request",
                    actions::SET_INPUTS,
                    actions::ABORT_AR
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
                "PROFINET",
                Some(conn.as_u32()),
                "injected_action",
                action,
                vec![serde_json::to_value(&outcome).unwrap_or(Value::Null)],
            )
            .await;
        let _ = c.reply_tx.send(Ok(outcome));
    }

    // ---------------------------------------------------------------- the tick

    async fn on_tick(&mut self) {
        let now = Instant::now();
        // Delayed DCP Identify responses.
        let mut due = Vec::new();
        self.delayed.retain(|(at, frame)| {
            if *at <= now {
                due.push(frame.clone());
                false
            } else {
                true
            }
        });
        for frame in due {
            let _ = self.tx.send(frame);
        }
        let mut to_close: Vec<(Uuid, String)> = Vec::new();
        let mut resend = Vec::new();
        let mut outputs = Vec::new();
        for ar in &mut self.ars {
            if let Some(c) = &mut ar.ccontrol {
                if now.duration_since(c.last_sent) >= CCONTROL_RETRY {
                    if c.attempts >= CCONTROL_ATTEMPTS {
                        to_close.push((
                            ar.uuid,
                            "the controller never confirmed ApplicationReady".into(),
                        ));
                    } else {
                        c.attempts += 1;
                        c.last_sent = now;
                        resend.push((c.datagram.clone(), c.dest));
                    }
                }
            }
            if ar.ar_type == blocks::ar_type::IOS_AR
                && now.duration_since(ar.last_rpc) >= ar.activity_timeout
            {
                to_close.push((
                    ar.uuid,
                    "no RPC from the supervisor within its activity timeout".into(),
                ));
                continue;
            }
            let Some(out) = &mut ar.output else {
                continue;
            };
            match (out.last_rx, ar.established_at) {
                (Some(last), _) if now.duration_since(last) > out.watchdog => {
                    to_close.push((
                        ar.uuid,
                        format!("watchdog: no output frame for {:?}", out.watchdog),
                    ));
                    continue;
                }
                (None, Some(at))
                    if now.duration_since(at) > FIRST_FRAME_GRACE.max(out.watchdog) =>
                {
                    to_close.push((
                        ar.uuid,
                        "watchdog: the controller never sent output data".into(),
                    ));
                    continue;
                }
                _ => {}
            }
            if ar.phase == ArPhase::Data
                && !out.changed.is_empty()
                && out
                    .last_event
                    .is_none_or(|t| now.duration_since(t) >= OUTPUT_EVENT_INTERVAL)
            {
                let mut changed: Vec<(u16, u16)> = out.changed.drain().collect();
                changed.sort();
                let list: Vec<Value> = changed
                    .iter()
                    .filter_map(|k| {
                        let (data, iops) = out.current.get(k)?;
                        let fields = self
                            .layout
                            .iter()
                            .find(|s| (s.slot, s.subslot) == *k)
                            .map(|s| s.outputs.clone())
                            .unwrap_or_else(|| values::anonymous_fields(data.len()));
                        Some(json!({
                            "slot": k.0,
                            "subslot": k.1,
                            "iops": if *iops & 0x80 != 0 { "good" } else { "bad" },
                            "values": Value::Object(values::decode(&fields, data)),
                        }))
                    })
                    .collect();
                out.last_event = Some(now);
                outputs.push((
                    ar.uuid,
                    ar.conn_id,
                    json!({"ar_uuid": rpc::format_uuid(&ar.uuid), "outputs": list}),
                ));
            }
        }
        for (bytes, dest) in resend {
            self.send_rpc(&bytes, dest).await;
        }
        for (uuid, conn, data) in outputs {
            if !self.ask(
                Event::new(&actions::OUTPUTS_CHANGED_EVENT, data),
                Some(conn),
                Pending::Notice { ar: Some(uuid) },
            ) {
                self.log().warn(format!(
                    "PROFINET output change on AR {} not sent to the model: the queue is full \
                     decision=fail_closed_queue_full",
                    rpc::format_uuid(&uuid)
                ));
            }
        }
        for (uuid, reason) in to_close {
            if let Some(pos) = self.ars.iter().position(|a| a.uuid == uuid) {
                self.close_ar(pos, &reason).await;
            }
        }
    }

    async fn report_stats(&mut self) {
        let state = self.shared.app_state.clone();
        for ar in &mut self.ars {
            let (rx, tx) = match (&mut ar.output, &ar.input) {
                (Some(o), i) => {
                    let rx = o.frames - o.frames_reported;
                    o.frames_reported = o.frames;
                    let tx = i.as_ref().map(|i| {
                        (Duration::from_secs(1).as_micros() / i.cycle.as_micros().max(1)) as u64
                    });
                    (rx, tx.unwrap_or(0))
                }
                _ => (0, 0),
            };
            if rx > 0 || tx > 0 {
                state
                    .update_connection_stats(
                        self.shared.server_id,
                        ar.conn_id,
                        None,
                        None,
                        Some(rx),
                        Some(tx),
                    )
                    .await;
            }
        }
    }
}

fn op_error_code(op: u16) -> u8 {
    match op {
        opnum::CONNECT => error_code::CONNECT,
        opnum::RELEASE => error_code::RELEASE,
        opnum::CONTROL => error_code::CONTROL,
        opnum::WRITE => error_code::WRITE,
        _ => error_code::READ,
    }
}

/// Timing and identity checks on one IOCR that do not depend on the layout.
fn check_iocr(r: &IocrBlockReq) -> std::result::Result<(), Refusal> {
    let bad = |code2: u8, why: String| Err(refuse(connect_error::IOCR_BLOCK_REQ, code2, why));
    if r.iocr_type != iocr_type::INPUT && r.iocr_type != iocr_type::OUTPUT {
        return bad(
            4,
            format!("IOCRType {} is not input (1) or output (2)", r.iocr_type),
        );
    }
    if r.lt != dcp::ETHERTYPE_PROFINET {
        return bad(
            6,
            format!(
                "LT {:#06x} is not 0x8892 (RT over UDP is not supported)",
                r.lt
            ),
        );
    }
    if r.rt_class() != blocks::RT_CLASS_1 {
        return bad(7, format!("RT class {} is not RT_CLASS_1", r.rt_class()));
    }
    if !(1..=128).contains(&r.send_clock_factor) {
        return bad(
            10,
            format!("SendClockFactor {} is outside 1..=128", r.send_clock_factor),
        );
    }
    if !rt::valid_reduction_ratio(r.reduction_ratio) {
        return bad(
            11,
            format!(
                "ReductionRatio {} is not a power of two up to 512",
                r.reduction_ratio
            ),
        );
    }
    let cycle = r.cycle_micros();
    if !(MIN_CYCLE_MICROS..=MAX_CYCLE_MICROS).contains(&cycle) {
        return bad(
            11,
            format!("a cycle of {cycle} µs is outside the {MIN_CYCLE_MICROS}..={MAX_CYCLE_MICROS} µs this device keeps"),
        );
    }
    if r.watchdog_factor == 0 || r.watchdog_factor > 7680 {
        return bad(
            15,
            format!("WatchdogFactor {} is outside 1..=7680", r.watchdog_factor),
        );
    }
    Ok(())
}

/// What a written record says, when this module knows how to read it.
fn describe_record(index: u16, data: &[u8]) -> Option<Value> {
    match index {
        blocks::index::IM1 | blocks::index::IM2 | blocks::index::IM3 => {
            blocks::ImText::parse(data).ok().map(|t| match t {
                blocks::ImText::Im1 {
                    tag_function,
                    tag_location,
                } => {
                    json!({"tag_function": tag_function, "tag_location": tag_location})
                }
                blocks::ImText::Im2 { installation_date } => {
                    json!({"installation_date": installation_date})
                }
                blocks::ImText::Im3 { descriptor } => json!({"descriptor": descriptor}),
            })
        }
        _ => match data.len() {
            1 => Some(json!({"u8": data[0], "i8": data[0] as i8})),
            2 => Some(
                json!({"u16": u16::from_be_bytes([data[0], data[1]]), "i16": i16::from_be_bytes([data[0], data[1]])}),
            ),
            4 => {
                let b = [data[0], data[1], data[2], data[3]];
                Some(
                    json!({"u32": u32::from_be_bytes(b), "i32": i32::from_be_bytes(b), "f32": f32::from_be_bytes(b).is_finite().then(|| f32::from_be_bytes(b))}),
                )
            }
            _ => None,
        },
    }
}

/// Everything one input provider needs.
struct Provider {
    tx: L2Tx,
    src: [u8; 6],
    dst: [u8; 6],
    tag: u16,
    frame_id: u16,
    cycle: Duration,
    ticks: u16,
    layout: CrLayout,
    image: Arc<Mutex<InputImage>>,
    ctl: Arc<Mutex<ProviderCtl>>,
    wrong: HashSet<(u16, u16)>,
}

/// Send the input image every cycle until aborted.
async fn provide(p: Provider) {
    let mut interval = tokio::time::interval(p.cycle);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut counter: u16 = 0;
    loop {
        interval.tick().await;
        let mut c_sdu = vec![0u8; p.layout.data_length];
        let (status, iocs) = {
            let ctl = p.ctl.lock().expect("provider ctl");
            (
                ctl.data_status,
                if ctl.iocs_good {
                    rt::IOXS_GOOD
                } else {
                    rt::IOXS_BAD
                },
            )
        };
        {
            let image = p.image.lock().expect("input image");
            for o in &p.layout.objects {
                let key = (o.slot, o.subslot);
                let mut iops = rt::IOXS_BAD;
                if !p.wrong.contains(&key) {
                    if let Some((data, good)) = image.inputs.get(&key) {
                        let n = o.len.min(data.len());
                        c_sdu[o.offset..o.offset + n].copy_from_slice(&data[..n]);
                        if *good {
                            iops = rt::IOXS_GOOD;
                        }
                    }
                }
                c_sdu[o.iops_offset()] = iops;
            }
        }
        for c in &p.layout.iocs {
            c_sdu[c.offset] = if p.wrong.contains(&(c.slot, c.subslot)) {
                rt::IOXS_BAD
            } else {
                iocs
            };
        }
        counter = counter.wrapping_add(p.ticks);
        let frame = rt::build_eth(
            p.dst,
            p.src,
            Some(p.tag),
            &rt::build_rt(p.frame_id, &c_sdu, counter, status),
        );
        let _ = p.tx.send(frame);
    }
}

/// The event types this server raises, for registries and tests.
pub fn raised_events() -> Vec<&'static EventType> {
    vec![
        &actions::DCP_SET_REQUEST_EVENT,
        &actions::CONNECT_REQUEST_EVENT,
        &actions::AR_ESTABLISHED_EVENT,
        &actions::OUTPUTS_CHANGED_EVENT,
        &actions::READ_RECORD_EVENT,
        &actions::WRITE_RECORD_EVENT,
        &actions::AR_CLOSED_EVENT,
    ]
}

/// Map an input layout into the JSON the events carry. Public for the controller side.
pub fn values_json(fields: &[values::Field], data: &[u8]) -> Map<String, Value> {
    values::decode(fields, data)
}
