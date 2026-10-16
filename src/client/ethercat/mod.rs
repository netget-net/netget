//! EtherCAT master — NetGet as the MainDevice of a segment: it scans it, reads every slave's
//! SII, walks slaves through the AL states, runs cyclic process data and talks CoE.
//!
//! Four tasks: the link reader (frames into a bounded queue), the bus dispatcher (hands each
//! returned frame to whoever is waiting on its datagram index), the session (owns the slaves
//! and runs one action at a time — a scan, a state walk, an SDO transfer), and, once a slave
//! is in SAFE-OP, the cyclic task sending one LRW over the logical image every period and
//! checking its working counter. A fifth asks the model, one event at a time, and hands its
//! actions back to the session; the chain is bounded by [`MAX_FOLLOWUP_DEPTH`].
//!
//! Outputs are zero until the model (or an operator) sets them, and OP is refused until every
//! slave that has outputs has had them set. On an LLM failure nothing is sent.
pub mod actions;

use crate::client::llm_budget::call_llm_for_client;
use crate::llm::actions::client_trait::{Client, ClientActionResult};
use crate::logging::emit::Log;
use crate::protocol::{ConnectContext, Event, EventType};
use crate::server::ethercat::coe::{self, SdoResponse};
use crate::server::ethercat::device::{DataType, Entry, Image};
use crate::server::ethercat::esc::{al_code, reg, state};
use crate::server::ethercat::frame::{self, cmd, Datagram};
use crate::server::ethercat::link::{self, Link, LinkTx};
use crate::server::ethercat::sii::{self, SiiInfo, SmConfig};
use crate::state::client_handles::{ClientCommand, ClientSendOutcome};
use crate::state::{AccessLogOwner, ClientStatus};
pub use actions::EthercatClientProtocol;
use anyhow::{anyhow, bail, ensure, Context, Result};
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};

type Instant = crate::utils::clock::Instant;

/// How many model turns may follow from one another before the chain stops.
pub const MAX_FOLLOWUP_DEPTH: u32 = 8;
/// Slaves a scan accepts.
pub const MAX_SLAVES: usize = 64;
/// The logical process image (one LRW datagram).
pub const MAX_IMAGE: usize = 1024;
/// How long one frame may take to come back, and how often it is sent before giving up.
pub const FRAME_TIMEOUT: Duration = Duration::from_millis(100);
pub const FRAME_ATTEMPTS: u32 = 3;
/// At most one `ethercat_inputs_changed` per slave per this interval.
pub const INPUT_EVENT_INTERVAL: Duration = Duration::from_millis(200);
/// At most one `ethercat_process_data_fault` per this interval.
pub const FAULT_EVENT_INTERVAL: Duration = Duration::from_secs(5);
const TURNS: usize = 64;
const POLL: Duration = Duration::from_millis(10);
const STATION_BASE: u16 = 0x1001;

// ---------------------------------------------------------------------- the bus

/// Sends frames and matches each answer to its request by the first datagram's index.
pub struct Bus {
    tx: LinkTx,
    waiting: Mutex<HashMap<u8, oneshot::Sender<Vec<u8>>>>,
    next: AtomicU8,
}

impl Bus {
    fn new(tx: LinkTx) -> Self {
        Self {
            tx,
            waiting: Mutex::new(HashMap::new()),
            next: AtomicU8::new(1),
        }
    }

    /// An answer arrived.
    fn deliver(&self, payload: &[u8]) {
        let Ok(ds) = frame::parse(payload) else {
            return;
        };
        let Some(first) = ds.first() else { return };
        let waiter = self
            .waiting
            .lock()
            .expect("ethercat bus")
            .remove(&first.idx);
        if let Some(w) = waiter {
            let _ = w.send(payload.to_vec());
        }
    }

    /// Send datagrams in one frame and wait for it to come back.
    pub async fn exchange(
        &self,
        mut dgs: Vec<Datagram>,
        timeout: Duration,
        attempts: u32,
    ) -> Result<Vec<Datagram>> {
        for _ in 0..attempts.max(1) {
            let (tx, rx) = oneshot::channel();
            let idx = {
                let mut w = self.waiting.lock().expect("ethercat bus");
                let mut idx = self.next.fetch_add(1, Ordering::Relaxed);
                for _ in 0..256 {
                    if !w.contains_key(&idx) {
                        break;
                    }
                    idx = self.next.fetch_add(1, Ordering::Relaxed);
                }
                w.insert(idx, tx);
                idx
            };
            for d in dgs.iter_mut() {
                d.idx = idx;
            }
            let payload = frame::encode(&dgs).map_err(|e| anyhow!("{e}"))?;
            if let Err(e) = self.tx.send(&payload).await {
                self.waiting.lock().expect("ethercat bus").remove(&idx);
                return Err(e);
            }
            match tokio::time::timeout(timeout, rx).await {
                Ok(Ok(answer)) => {
                    let back = frame::decode(&answer).map_err(|e| anyhow!("{e}"))?;
                    ensure!(
                        back.len() == dgs.len()
                            && back
                                .iter()
                                .zip(&dgs)
                                .all(|(a, b)| a.cmd == b.cmd && a.data.len() == b.data.len()),
                        "the frame came back with different datagrams"
                    );
                    return Ok(back);
                }
                _ => {
                    self.waiting.lock().expect("ethercat bus").remove(&idx);
                }
            }
        }
        bail!("no answer after {} attempts", attempts.max(1))
    }

    async fn one(&self, d: Datagram) -> Result<Datagram> {
        Ok(self
            .exchange(vec![d], FRAME_TIMEOUT, FRAME_ATTEMPTS)
            .await?
            .remove(0))
    }

    pub async fn bwr(&self, ado: u16, data: Vec<u8>) -> Result<u16> {
        Ok(self
            .one(Datagram::physical(cmd::BWR, 0, ado, data))
            .await?
            .wkc)
    }
    pub async fn brd(&self, ado: u16, len: usize) -> Result<Datagram> {
        self.one(Datagram::physical(cmd::BRD, 0, ado, vec![0; len]))
            .await
    }
    pub async fn apwr(&self, position: usize, ado: u16, data: Vec<u8>) -> Result<u16> {
        let adp = 0u16.wrapping_sub(position as u16);
        Ok(self
            .one(Datagram::physical(cmd::APWR, adp, ado, data))
            .await?
            .wkc)
    }
    pub async fn fprd(&self, station: u16, ado: u16, len: usize) -> Result<Datagram> {
        self.one(Datagram::physical(cmd::FPRD, station, ado, vec![0; len]))
            .await
    }
    pub async fn fpwr(&self, station: u16, ado: u16, data: Vec<u8>) -> Result<u16> {
        Ok(self
            .one(Datagram::physical(cmd::FPWR, station, ado, data))
            .await?
            .wkc)
    }
    /// FPRD that must be answered by exactly the addressed slave.
    pub async fn fprd_ok(&self, station: u16, ado: u16, len: usize) -> Result<Vec<u8>> {
        let d = self.fprd(station, ado, len).await?;
        ensure!(
            d.wkc == 1,
            "slave {station:#06x} did not answer a read of {ado:#06x} (working counter {})",
            d.wkc
        );
        Ok(d.data)
    }
    pub async fn fpwr_ok(&self, station: u16, ado: u16, data: Vec<u8>) -> Result<()> {
        let wkc = self.fpwr(station, ado, data).await?;
        ensure!(
            wkc == 1,
            "slave {station:#06x} did not take a write to {ado:#06x} (working counter {wkc})"
        );
        Ok(())
    }
}

// ---------------------------------------------------------------------- slaves

/// What the master knows about one slave.
#[derive(Clone)]
struct Slave {
    position: usize,
    station: u16,
    sii: SiiInfo,
    al_state: u8,
    inputs: Image,
    outputs: Image,
    /// Mailbox SyncManagers (receive = master writes, send = master reads): start, length.
    mbx_out: Option<(u16, u16)>,
    mbx_in: Option<(u16, u16, usize)>,
    counter: u8,
    /// Where the slave's data sits in the logical image: offset, octets.
    out_log: Option<(usize, usize)>,
    in_log: Option<(usize, usize)>,
    outputs_set: bool,
    /// The outputs as last set (zeros until the model sets them).
    output_image: Vec<u8>,
}

impl Slave {
    fn describe(&self) -> Value {
        let mut v = sii::describe(&self.sii);
        v["position"] = json!(self.position);
        v["station_address"] = json!(self.station);
        v["state"] = json!(state::name(self.al_state));
        v["inputs"] = self.inputs.describe();
        v["outputs"] = self.outputs.describe();
        v
    }
}

/// The SII image of a slave, read through its EEPROM registers.
async fn read_sii(bus: &Bus, station: u16, eight: bool) -> Result<Vec<u8>> {
    let chunk = if eight { 8 } else { 4 };
    let mut out: Vec<u8> = Vec::new();
    let mut word = 0u32;
    loop {
        let mut req = vec![0x00, 0x01];
        req.extend_from_slice(&word.to_le_bytes());
        bus.fpwr_ok(station, reg::SII_CONTROL as u16, req).await?;
        let started = Instant::now();
        loop {
            let st = bus.fprd_ok(station, reg::SII_CONTROL as u16, 2).await?;
            let st = u16::from_le_bytes([st[0], st[1]]);
            if st & 0x8000 == 0 {
                ensure!(
                    st & 0x7800 == 0,
                    "slave {station:#06x} reports an EEPROM error ({st:#06x}) at word {word}"
                );
                break;
            }
            ensure!(
                started.elapsed() < Duration::from_secs(2),
                "slave {station:#06x}'s EEPROM stayed busy"
            );
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        let data = bus.fprd_ok(station, reg::SII_DATA as u16, chunk).await?;
        out.extend_from_slice(&data);
        word += (chunk / 2) as u32;
        if out.len() >= sii::word::FIRST_CATEGORY * 2 {
            if let Some(end) = sii::chain_end(&out)? {
                out.truncate(end.max(out.len().min(end)));
                return Ok(out);
            }
        }
        ensure!(
            out.len() < sii::MAX_SII_BYTES,
            "slave {station:#06x}'s SII has no end marker in its first {} octets",
            sii::MAX_SII_BYTES
        );
    }
}

fn sm_bytes(c: &SmConfig, length: u16) -> Vec<u8> {
    let mut b = Vec::with_capacity(8);
    b.extend_from_slice(&c.start.to_le_bytes());
    b.extend_from_slice(&length.to_le_bytes());
    b.push(c.control);
    b.push(0);
    b.push((length > 0 && c.enable & 0x01 != 0) as u8);
    b.push(0);
    b
}

fn fmmu_bytes(logical: u32, len: u16, physical: u16, write: bool) -> Vec<u8> {
    let mut b = Vec::with_capacity(16);
    b.extend_from_slice(&logical.to_le_bytes());
    b.extend_from_slice(&len.to_le_bytes());
    b.push(0);
    b.push(7);
    b.extend_from_slice(&physical.to_le_bytes());
    b.push(0);
    b.push(if write { 2 } else { 1 });
    b.push(1);
    b.extend_from_slice(&[0, 0, 0]);
    b
}

// ---------------------------------------------------------------------- process data

/// What the cyclic task and the session share.
struct ProcessData {
    image: Vec<u8>,
    expected_wkc: u16,
    /// Each slave: position, output and input placement.
    slaves: Vec<(usize, Option<(usize, usize)>, Option<(usize, usize)>, Image)>,
    last_inputs: HashMap<usize, Vec<u8>>,
}

enum PdNote {
    Inputs(usize, Map<String, Value>),
    Fault { expected: u16, wkc: i64, bad: u64 },
}

async fn cyclic(
    bus: Arc<Bus>,
    pd: Arc<Mutex<ProcessData>>,
    period: Duration,
    stop: Arc<AtomicBool>,
    notes: mpsc::Sender<PdNote>,
) {
    let mut tick = tokio::time::interval(period);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut last_event: HashMap<usize, Instant> = HashMap::new();
    let mut reported: HashMap<usize, Vec<u8>> = HashMap::new();
    let mut bad: u64 = 0;
    let mut last_fault: Option<Instant> = None;
    while !stop.load(Ordering::SeqCst) {
        tick.tick().await;
        let (image, expected) = {
            let p = pd.lock().expect("ethercat process data");
            (p.image.clone(), p.expected_wkc)
        };
        if image.is_empty() {
            continue;
        }
        let r = bus
            .exchange(
                vec![Datagram::logical(cmd::LRW, 0, image)],
                period.max(Duration::from_millis(20)),
                1,
            )
            .await;
        let wkc = match &r {
            Ok(d) => d[0].wkc as i64,
            Err(_) => -1,
        };
        if wkc != expected as i64 {
            bad += 1;
            let now = Instant::now();
            if last_fault.is_none_or(|t| now.duration_since(t) >= FAULT_EVENT_INTERVAL) {
                last_fault = Some(now);
                let _ = notes.try_send(PdNote::Fault { expected, wkc, bad });
                bad = 0;
            }
            continue;
        }
        let Ok(d) = r else { continue };
        let back = &d[0].data;
        let now = Instant::now();
        let slaves = {
            let mut p = pd.lock().expect("ethercat process data");
            let mut out = Vec::new();
            for (pos, _, inp, img) in p.slaves.clone() {
                if let Some((off, len)) = inp {
                    let cur = back[off..off + len].to_vec();
                    p.last_inputs.insert(pos, cur.clone());
                    out.push((pos, cur, img));
                }
            }
            out
        };
        for (pos, cur, img) in slaves {
            if reported.get(&pos) == Some(&cur) {
                continue;
            }
            if last_event
                .get(&pos)
                .is_some_and(|t| now.duration_since(*t) < INPUT_EVENT_INTERVAL)
            {
                continue;
            }
            last_event.insert(pos, now);
            reported.insert(pos, cur.clone());
            let _ = notes.try_send(PdNote::Inputs(pos, img.decode(&cur)));
        }
    }
}

// ---------------------------------------------------------------------- config

struct Config {
    udp: bool,
    cycle: Duration,
    state_timeout: Duration,
    mailbox_timeout: Duration,
}

fn ms_param(ctx: &ConnectContext, key: &str, default: u64, max: u64) -> Result<Duration> {
    let v = ctx
        .startup_params
        .as_ref()
        .map(|p| p.get_optional_u64(key))
        .transpose()?
        .flatten()
        .unwrap_or(default);
    ensure!((1..=max).contains(&v), "{key} must be 1-{max}");
    Ok(Duration::from_millis(v))
}

impl Config {
    fn from(ctx: &ConnectContext) -> Result<Self> {
        let udp = match ctx
            .startup_params
            .as_ref()
            .map(|p| p.get_optional_string("transport"))
            .transpose()?
            .flatten()
            .as_deref()
        {
            None => false,
            Some(t) if t == link::TRANSPORT_RAW => false,
            Some(t) if t == link::TRANSPORT_UDP => true,
            Some(other) => bail!("transport is raw or udp, not {other:?}"),
        };
        Ok(Self {
            udp,
            cycle: ms_param(
                ctx,
                "cycle_ms",
                actions::DEFAULT_CYCLE_MS,
                actions::MAX_CYCLE_MS,
            )?,
            state_timeout: ms_param(
                ctx,
                "state_timeout_ms",
                actions::DEFAULT_STATE_TIMEOUT_MS,
                actions::MAX_TIMEOUT_MS,
            )?,
            mailbox_timeout: ms_param(
                ctx,
                "mailbox_timeout_ms",
                actions::DEFAULT_MAILBOX_TIMEOUT_MS,
                actions::MAX_TIMEOUT_MS,
            )?,
        })
    }
}

fn udp_remote(s: &str) -> Result<SocketAddr> {
    let s = s.trim();
    if let Ok(a) = s.parse::<SocketAddr>() {
        return Ok(a);
    }
    let ip: IpAddr = s.parse().with_context(|| {
        format!("with transport udp, remote_addr is HOST[:PORT] of an EtherCAT-in-UDP endpoint, got {s:?}")
    })?;
    Ok(SocketAddr::new(ip, frame::UDP_PORT))
}

pub async fn connect(ctx: ConnectContext) -> Result<SocketAddr> {
    let cfg = Config::from(&ctx)?;
    let link = if cfg.udp {
        let remote = udp_remote(&ctx.remote_addr)?;
        let bind = match remote.ip() {
            IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        };
        Link::open_udp(bind, Some(remote)).await?
    } else {
        Link::open_raw(ctx.remote_addr.trim())?
    };
    let local = link
        .local_addr()
        .unwrap_or(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0));
    let description = link.describe();
    let (mut frames, tx, pump) = link::reader(link);
    let bus = Arc::new(Bus::new(tx));
    ctx.state.spawn_client_task(ctx.client_id, pump).await;
    let dispatch_bus = bus.clone();
    ctx.state
        .spawn_client_task(ctx.client_id, async move {
            while let Some(r) = frames.recv().await {
                dispatch_bus.deliver(&r.payload);
            }
        })
        .await;
    ctx.state
        .update_client_status(ctx.client_id, ClientStatus::Connected)
        .await;
    Log::new(Some(&ctx.status_tx)).info(format!("EtherCAT master on {description}"));
    let external =
        crate::client::command_support::register_command_channel(&ctx.state, ctx.client_id).await;
    let (event_tx, event_rx) = mpsc::channel::<(Event, u32)>(TURNS);
    let (internal_tx, internal) = mpsc::channel::<(Value, u32)>(64);
    let dispatcher = ctx
        .state
        .spawn_client_task(ctx.client_id, run_turns(ctx.clone(), event_rx, internal_tx))
        .await;
    let (notes_tx, notes) = mpsc::channel::<PdNote>(64);
    let session_ctx = ctx.clone();
    ctx.state
        .spawn_client_task(ctx.client_id, async move {
            let mut s = Session {
                ctx: session_ctx.clone(),
                bus,
                cfg,
                slaves: Vec::new(),
                events: event_tx.clone(),
                pd: None,
                notes_tx,
            };
            let reason = s.run(external, internal, notes).await;
            s.stop_cyclic();
            Log::new(Some(&session_ctx.status_tx)).info(format!(
                "EtherCAT master {} stopped: {reason}",
                session_ctx.client_id
            ));
            drop(event_tx);
            drop(s);
            let _ = tokio::time::timeout(Duration::from_secs(30), async {
                while !dispatcher.is_finished() {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            })
            .await;
            dispatcher.abort();
            session_ctx
                .state
                .update_client_status(session_ctx.client_id, ClientStatus::Disconnected)
                .await;
            session_ctx
                .state
                .remove_client_handle(session_ctx.client_id)
                .await;
            let _ = session_ctx.status_tx.send("__UPDATE_UI__".into());
        })
        .await;
    Ok(local)
}

struct Cyclic {
    shared: Arc<Mutex<ProcessData>>,
    stop: Arc<AtomicBool>,
    task: tokio::task::AbortHandle,
}

struct Session {
    ctx: ConnectContext,
    bus: Arc<Bus>,
    cfg: Config,
    slaves: Vec<Slave>,
    events: mpsc::Sender<(Event, u32)>,
    pd: Option<Cyclic>,
    notes_tx: mpsc::Sender<PdNote>,
}

impl Session {
    fn log(&self) -> Log<'_> {
        Log::new(Some(&self.ctx.status_tx))
    }

    fn emit(&self, event: &'static EventType, data: Value, depth: u32) {
        if self
            .events
            .try_send((Event::new(event, data), depth))
            .is_err()
        {
            self.log().warn(format!(
                "EtherCAT {} not sent to the model: the queue is full decision=fail_closed_queue_full",
                event.id
            ));
        }
    }

    async fn run(
        &mut self,
        mut external: mpsc::Receiver<ClientCommand>,
        mut internal: mpsc::Receiver<(Value, u32)>,
        mut notes: mpsc::Receiver<PdNote>,
    ) -> String {
        if let Err(e) = self.scan(0).await {
            self.log().warn(format!("EtherCAT scan failed: {e:#}"));
            self.emit(
                &actions::SEGMENT_SCANNED_EVENT,
                json!({"count": 0, "slaves": [], "error": format!("{e:#}")}),
                0,
            );
        }
        loop {
            tokio::select! {
                c = external.recv() => match c {
                    Some(c) => {
                        self.ctx.state.record_access_log(
                            AccessLogOwner::Client(self.ctx.client_id.as_u32()),
                            "EtherCAT", None, "injected_action", c.action.clone(), vec![],
                        ).await;
                        let action = c.action.clone();
                        let (outcome, stop) = self.perform(&action, 0).await;
                        crate::client::command_support::reply(c, Ok(outcome));
                        if let Some(r) = stop {
                            return r;
                        }
                    }
                    None => return "the client was stopped".into(),
                },
                a = internal.recv() => match a {
                    Some((action, depth)) => {
                        let (outcome, stop) = self.perform(&action, depth + 1).await;
                        if let ClientSendOutcome::Rejected { error } = &outcome {
                            self.log().warn(format!(
                                "EtherCAT master: the model's {} was not carried out \
                                 decision=fail_closed_bad_action: {error}",
                                action["type"].as_str().unwrap_or("action")
                            ));
                        }
                        if let Some(r) = stop {
                            return r;
                        }
                    }
                    None => return "the client was stopped".into(),
                },
                n = notes.recv() => {
                    if let Some(n) = n {
                        self.on_note(n);
                    }
                }
            }
        }
    }

    fn on_note(&mut self, n: PdNote) {
        match n {
            PdNote::Inputs(pos, values) => {
                let station = self.slaves.get(pos).map(|s| s.station).unwrap_or_default();
                self.emit(
                    &actions::INPUTS_CHANGED_EVENT,
                    json!({"slave": pos, "station_address": station, "inputs": values}),
                    0,
                );
            }
            PdNote::Fault { expected, wkc, bad } => {
                self.log().warn(format!(
                    "EtherCAT process data: working counter {wkc} where {expected} was expected \
                     ({bad} bad frame(s))"
                ));
                self.emit(
                    &actions::PROCESS_DATA_FAULT_EVENT,
                    json!({"expected_wkc": expected, "wkc": wkc, "bad_frames": bad}),
                    0,
                );
            }
        }
    }

    async fn perform(&mut self, action: &Value, depth: u32) -> (ClientSendOutcome, Option<String>) {
        let name = match EthercatClientProtocol.execute_action(action.clone()) {
            Ok(ClientActionResult::Disconnect) => {
                return (
                    ClientSendOutcome::Disconnected,
                    Some("disconnected by request".into()),
                )
            }
            Ok(ClientActionResult::Custom { name, .. }) => name,
            Ok(_) => {
                return (
                    ClientSendOutcome::Executed {
                        detail: "nothing to do".into(),
                    },
                    None,
                )
            }
            Err(e) => {
                return (
                    ClientSendOutcome::Rejected {
                        error: format!("{e:#}"),
                    },
                    None,
                )
            }
        };
        let r = match name.as_str() {
            actions::SCAN => self.scan(depth).await,
            actions::REQUEST_STATE => self.request_state(action, depth).await,
            actions::SET_OUTPUTS => self.set_outputs(action),
            actions::SDO_READ => self.sdo_read_action(action, depth).await,
            actions::SDO_WRITE => self.sdo_write_action(action, depth).await,
            other => Err(anyhow!("unknown action {other}")),
        };
        match r {
            Ok(detail) => (ClientSendOutcome::Executed { detail }, None),
            Err(e) => (
                ClientSendOutcome::Rejected {
                    error: format!("{e:#}"),
                },
                None,
            ),
        }
    }

    // ------------------------------------------------------------------ scan

    async fn scan(&mut self, depth: u32) -> Result<String> {
        self.stop_cyclic();
        let bus = self.bus.clone();
        bus.bwr(
            reg::AL_CONTROL as u16,
            ((state::INIT | 0x10) as u16).to_le_bytes().to_vec(),
        )
        .await?;
        let count = bus.brd(reg::TYPE as u16, 1).await?.wkc as usize;
        ensure!(
            count <= MAX_SLAVES,
            "{count} slaves answered, more than {MAX_SLAVES}"
        );
        bus.bwr(reg::DL_CONTROL as u16 + 3, vec![0]).await?;
        bus.bwr(reg::FMMU0 as u16, vec![0; 16 * 4]).await?;
        bus.bwr(reg::SM0 as u16, vec![0; 8 * 4]).await?;
        bus.bwr(reg::SII_CONFIG as u16, vec![0]).await?;
        let mut slaves = Vec::with_capacity(count);
        for position in 0..count {
            let station = STATION_BASE + position as u16;
            let wkc = bus
                .apwr(
                    position,
                    reg::STATION_ADDRESS as u16,
                    station.to_le_bytes().to_vec(),
                )
                .await?;
            ensure!(
                wkc == 1,
                "slave {position} did not take its station address"
            );
            let st = bus.fprd_ok(station, reg::SII_CONTROL as u16, 2).await?;
            let eight = st[0] & 0x40 != 0;
            let sii_bytes = read_sii(&bus, station, eight).await?;
            let info = sii::parse(&sii_bytes).with_context(|| format!("slave {position}'s SII"))?;
            let al = bus.fprd_ok(station, reg::AL_STATUS as u16, 2).await?;
            let assigned = |p: &&sii::Pdo| p.sm != 0xFF;
            let inputs = sii::image_of(
                &info
                    .txpdos
                    .iter()
                    .filter(assigned)
                    .cloned()
                    .collect::<Vec<_>>(),
            );
            let outputs = sii::image_of(
                &info
                    .rxpdos
                    .iter()
                    .filter(assigned)
                    .cloned()
                    .collect::<Vec<_>>(),
            );
            slaves.push(Slave {
                position,
                station,
                al_state: al[0] & 0x0F,
                inputs,
                outputs,
                mbx_out: None,
                mbx_in: None,
                counter: 0,
                out_log: None,
                in_log: None,
                outputs_set: false,
                output_image: Vec::new(),
                sii: info,
            });
        }
        self.slaves = slaves;
        let list: Vec<Value> = self.slaves.iter().map(Slave::describe).collect();
        self.log().info(format!(
            "EtherCAT scan: {count} slave(s){}",
            self.slaves
                .iter()
                .map(|s| format!(
                    "; {} {} (vendor {:#010x} product {:#010x})",
                    s.position,
                    s.sii.name.clone().unwrap_or_default(),
                    s.sii.vendor_id,
                    s.sii.product_code
                ))
                .collect::<String>()
        ));
        self.emit(
            &actions::SEGMENT_SCANNED_EVENT,
            json!({"count": count, "slaves": list}),
            depth,
        );
        Ok(format!("{count} slave(s)"))
    }

    // ------------------------------------------------------------------ states

    async fn wait_state(&self, station: u16, want: u8) -> Result<(u8, Option<u16>)> {
        let started = Instant::now();
        loop {
            let st = self.bus.fprd_ok(station, reg::AL_STATUS as u16, 6).await?;
            let s = st[0] & 0x0F;
            if st[0] & 0x10 != 0 {
                let code = u16::from_le_bytes([st[4], st[5]]);
                return Ok((s, Some(code)));
            }
            if s == want || started.elapsed() >= self.cfg.state_timeout {
                return Ok((s, None));
            }
            tokio::time::sleep(POLL).await;
        }
    }

    async fn request(&mut self, i: usize, target: u8) -> Value {
        let station = self.slaves[i].station;
        let r: Result<(u8, Option<u16>)> = async {
            match target {
                state::PREOP => self.configure_mailbox(i).await?,
                state::SAFEOP => self.configure_process_data(i).await?,
                _ => {}
            }
            self.bus
                .fpwr_ok(
                    station,
                    reg::AL_CONTROL as u16,
                    ((target | 0x10) as u16).to_le_bytes().to_vec(),
                )
                .await?;
            self.wait_state(station, target).await
        }
        .await;
        match r {
            Ok((s, code)) => {
                self.slaves[i].al_state = s;
                let mut v = json!({"position": i, "station_address": station,
                    "state": state::name(s), "ok": s == target && code.is_none()});
                if let Some(c) = code {
                    v["al_status_code"] = json!(c);
                    v["al_status"] = json!(al_code::text(c));
                } else if s != target {
                    v["error"] = json!(format!(
                        "still {} after {} ms",
                        state::name(s),
                        self.cfg.state_timeout.as_millis()
                    ));
                }
                v
            }
            Err(e) => json!({"position": i, "station_address": station,
                "state": state::name(self.slaves[i].al_state), "ok": false,
                "error": format!("{e:#}")}),
        }
    }

    async fn request_state(&mut self, v: &Value, depth: u32) -> Result<String> {
        let target = state::parse(v["state"].as_str().unwrap_or_default())
            .context("state is init, preop, safeop or op")?;
        let only = match v.get("slave") {
            None | Some(Value::Null) => None,
            Some(_) => Some(actions::slave_of(v)?),
        };
        ensure!(
            !self.slaves.is_empty(),
            "no slaves were found on the segment"
        );
        let which: Vec<usize> = match only {
            Some(i) => {
                ensure!(i < self.slaves.len(), "there is no slave {i}");
                vec![i]
            }
            None => (0..self.slaves.len()).collect(),
        };
        if target == state::OP {
            if let Some(s) = which
                .iter()
                .map(|i| &self.slaves[*i])
                .find(|s| !s.outputs.is_empty() && !s.outputs_set)
            {
                bail!(
                    "slave {}'s outputs were never set; OP would apply zeros nobody chose — set \
                     them with ethercat_set_outputs first",
                    s.position
                );
            }
        }
        let tr = state::rank(target).unwrap_or(0);
        let mut results = Vec::new();
        for &i in &which {
            // Walk one step at a time from where the slave is.
            let mut last = Value::Null;
            loop {
                let cur = state::rank(self.slaves[i].al_state).unwrap_or(0);
                let next = if cur < tr {
                    [state::INIT, state::PREOP, state::SAFEOP, state::OP][cur as usize + 1]
                } else {
                    target
                };
                if cur == tr && !last.is_null() {
                    break;
                }
                if next == state::SAFEOP {
                    self.ensure_cyclic().await;
                }
                last = self.request(i, next).await;
                if last["ok"] != json!(true) || next == target {
                    break;
                }
            }
            results.push(last);
        }
        if state::rank(target).unwrap_or(0) < 2 {
            self.stop_cyclic();
        }
        let ok = results.iter().all(|r| r["ok"] == json!(true));
        self.log().info(format!(
            "EtherCAT state walk to {}: {}",
            state::name(target),
            results
                .iter()
                .map(|r| format!(
                    "{} {}{}",
                    r["position"],
                    r["state"].as_str().unwrap_or(""),
                    r.get("al_status")
                        .and_then(Value::as_str)
                        .map(|s| format!(" ({s})"))
                        .unwrap_or_default()
                ))
                .collect::<Vec<_>>()
                .join(", ")
        ));
        self.emit(
            &actions::STATE_RESULT_EVENT,
            json!({"requested": state::name(target), "slaves": results, "ok": ok}),
            depth,
        );
        Ok(format!("state walk to {}: ok={ok}", state::name(target)))
    }

    async fn configure_mailbox(&mut self, i: usize) -> Result<()> {
        let s = &self.slaves[i];
        if !s.sii.has_coe() && s.sii.rx_mailbox.1 == 0 {
            return Ok(());
        }
        let sms = s.sii.sync_managers.clone();
        let out = sms
            .iter()
            .position(|c| c.sm_type == sii::sm_type::MAILBOX_OUT)
            .context("the SII has no receive mailbox SyncManager")?;
        let inp = sms
            .iter()
            .position(|c| c.sm_type == sii::sm_type::MAILBOX_IN)
            .context("the SII has no send mailbox SyncManager")?;
        let station = s.station;
        let (oc, ic) = (sms[out], sms[inp]);
        // The standard mailbox words of the SII win over the SyncM category's defaults.
        let (orx, olen) = (s.sii.rx_mailbox.0, s.sii.rx_mailbox.1);
        let (otx, otlen) = (s.sii.tx_mailbox.0, s.sii.tx_mailbox.1);
        let oc = SmConfig {
            start: if olen > 0 { orx } else { oc.start },
            ..oc
        };
        let olen = if olen > 0 { olen } else { oc.length };
        let ic = SmConfig {
            start: if otlen > 0 { otx } else { ic.start },
            ..ic
        };
        let ilen = if otlen > 0 { otlen } else { ic.length };
        ensure!(
            (sii::MIN_MAILBOX as u16 / 2..=1486).contains(&olen)
                && (sii::MIN_MAILBOX as u16 / 2..=1486).contains(&ilen),
            "mailbox sizes {olen}/{ilen} are unusable"
        );
        self.bus
            .fpwr_ok(
                station,
                reg::SM0 as u16 + 8 * out as u16,
                sm_bytes(&oc, olen),
            )
            .await?;
        self.bus
            .fpwr_ok(
                station,
                reg::SM0 as u16 + 8 * inp as u16,
                sm_bytes(&ic, ilen),
            )
            .await?;
        let s = &mut self.slaves[i];
        s.mbx_out = Some((oc.start, olen));
        s.mbx_in = Some((ic.start, ilen, inp));
        Ok(())
    }

    /// The PDO layout from CoE: the assigned PDOs of `assign` (0x1C12/0x1C13) and their
    /// mapping, named from the SII where it names the same entry.
    async fn coe_image(&mut self, i: usize, assign: u16, pdos: &[sii::Pdo]) -> Result<Image> {
        let n = self.sdo_upload(i, assign, 0).await?;
        let n = *n.first().context("empty PDO assignment count")? as usize;
        ensure!(n <= 32, "{n} PDOs assigned");
        let mut img = Image::default();
        for k in 1..=n {
            let pdo = self.sdo_upload(i, assign, k as u8).await?;
            ensure!(pdo.len() >= 2, "a PDO assignment entry is two octets");
            let pdo = u16::from_le_bytes([pdo[0], pdo[1]]);
            let m = self.sdo_upload(i, pdo, 0).await?;
            let m = *m.first().context("empty PDO mapping count")? as usize;
            ensure!(m <= 64, "PDO {pdo:#06x} maps {m} entries");
            for e in 1..=m {
                let v = self.sdo_upload(i, pdo, e as u8).await?;
                ensure!(v.len() >= 4, "a mapping entry is four octets");
                let bits = v[0] as usize;
                let sub = v[1];
                let index = u16::from_le_bytes([v[2], v[3]]);
                if index != 0 {
                    let named = pdos
                        .iter()
                        .flat_map(|p| p.entries.iter())
                        .find(|x| x.index == index && x.subindex == sub);
                    let ty = named
                        .and_then(|x| DataType::from_code(x.data_type as u16))
                        .filter(|t| t.bits() == bits)
                        .or(match bits {
                            1 => Some(DataType::Bool),
                            8 => Some(DataType::U8),
                            16 => Some(DataType::U16),
                            32 => Some(DataType::U32),
                            64 => Some(DataType::U64),
                            _ => None,
                        });
                    if let Some(ty) = ty {
                        let mut name = named
                            .map(|x| x.name.clone())
                            .filter(|n| !n.is_empty())
                            .unwrap_or_else(|| format!("{index:#06x}:{sub}"));
                        if img.entries.iter().any(|x| x.name == name) {
                            name = format!("{name}_{index:#06x}_{sub}");
                        }
                        img.entries.push(Entry {
                            name,
                            ty,
                            bit_offset: img.bits,
                        });
                    }
                }
                img.bits += bits;
            }
        }
        ensure!(img.bytes() <= MAX_IMAGE, "the PDO layout is too large");
        Ok(img)
    }

    async fn configure_process_data(&mut self, i: usize) -> Result<()> {
        if self.slaves[i].sii.has_coe() && self.slaves[i].mbx_out.is_some() {
            let tx = self.slaves[i].sii.txpdos.clone();
            let rx = self.slaves[i].sii.rxpdos.clone();
            match self.coe_image(i, 0x1C13, &tx).await {
                Ok(img) => self.slaves[i].inputs = img,
                Err(e) => self.log().info(format!(
                    "EtherCAT slave {i}: input layout from the SII ({e:#})"
                )),
            }
            match self.coe_image(i, 0x1C12, &rx).await {
                Ok(img) => self.slaves[i].outputs = img,
                Err(e) => self.log().info(format!(
                    "EtherCAT slave {i}: output layout from the SII ({e:#})"
                )),
            }
        }
        let s = self.slaves[i].clone();
        let sms = &s.sii.sync_managers;
        let fmmus = &s.sii.fmmu_usage;
        let fmmu_for =
            |usage: u8, fallback: usize| fmmus.iter().position(|u| *u == usage).unwrap_or(fallback);
        // Place the slave in the logical image after everything placed so far.
        let used = self
            .slaves
            .iter()
            .flat_map(|x| [x.out_log, x.in_log])
            .flatten()
            .filter(|_| true)
            .map(|(o, l)| o + l)
            .max()
            .unwrap_or(0);
        let mut at = used;
        let mut out_log = None;
        let mut in_log = None;
        for (dir, img, sm_type, usage, write) in [
            (
                "output",
                &s.outputs,
                sii::sm_type::OUTPUTS,
                sii::fmmu_usage::OUTPUTS,
                true,
            ),
            (
                "input",
                &s.inputs,
                sii::sm_type::INPUTS,
                sii::fmmu_usage::INPUTS,
                false,
            ),
        ] {
            let Some(smi) = sms.iter().position(|c| c.sm_type == sm_type) else {
                ensure!(img.is_empty(), "the SII has no {dir} SyncManager");
                continue;
            };
            let len = img.bytes();
            self.bus
                .fpwr_ok(
                    s.station,
                    reg::SM0 as u16 + 8 * smi as u16,
                    sm_bytes(&sms[smi], len as u16),
                )
                .await?;
            if len == 0 {
                continue;
            }
            ensure!(
                at + len <= MAX_IMAGE,
                "the logical image would pass {MAX_IMAGE} octets"
            );
            let f = fmmu_for(usage, if write { 0 } else { 1 });
            self.bus
                .fpwr_ok(
                    s.station,
                    reg::FMMU0 as u16 + 16 * f as u16,
                    fmmu_bytes(at as u32, len as u16, sms[smi].start, write),
                )
                .await?;
            if write {
                out_log = Some((at, len));
            } else {
                in_log = Some((at, len));
            }
            at += len;
        }
        self.slaves[i].out_log = out_log;
        self.slaves[i].in_log = in_log;
        self.rebuild_process_data();
        Ok(())
    }

    fn rebuild_process_data(&mut self) {
        let Some(c) = &self.pd else { return };
        let mut p = c.shared.lock().expect("ethercat process data");
        let size = self
            .slaves
            .iter()
            .flat_map(|x| [x.out_log, x.in_log])
            .flatten()
            .map(|(o, l)| o + l)
            .max()
            .unwrap_or(0);
        p.image.resize(size, 0);
        for s in &self.slaves {
            if let Some((off, len)) = s.out_log {
                let mut img = s.output_image.clone();
                img.resize(len, 0);
                p.image[off..off + len].copy_from_slice(&img);
            }
        }
        p.expected_wkc = self
            .slaves
            .iter()
            .map(|s| 2 * s.out_log.is_some() as u16 + s.in_log.is_some() as u16)
            .sum();
        p.slaves = self
            .slaves
            .iter()
            .map(|s| (s.position, s.out_log, s.in_log, s.inputs.clone()))
            .collect();
    }

    async fn ensure_cyclic(&mut self) {
        if self.pd.is_some() {
            return;
        }
        let shared = Arc::new(Mutex::new(ProcessData {
            image: Vec::new(),
            expected_wkc: 0,
            slaves: Vec::new(),
            last_inputs: HashMap::new(),
        }));
        let stop = Arc::new(AtomicBool::new(false));
        let task = self
            .ctx
            .state
            .spawn_client_task(
                self.ctx.client_id,
                cyclic(
                    self.bus.clone(),
                    shared.clone(),
                    self.cfg.cycle,
                    stop.clone(),
                    self.notes_tx.clone(),
                ),
            )
            .await;
        self.pd = Some(Cyclic { shared, stop, task });
        self.rebuild_process_data();
    }

    fn stop_cyclic(&mut self) {
        if let Some(c) = self.pd.take() {
            c.stop.store(true, Ordering::SeqCst);
            c.task.abort();
        }
        for s in &mut self.slaves {
            s.out_log = None;
            s.in_log = None;
        }
    }

    fn set_outputs(&mut self, v: &Value) -> Result<String> {
        let i = actions::slave_of(v)?;
        let s = self
            .slaves
            .get(i)
            .with_context(|| format!("there is no slave {i}"))?;
        ensure!(!s.outputs.is_empty(), "slave {i} has no outputs");
        let values = v["values"].as_object().cloned().unwrap_or_default();
        let mut img = s.output_image.clone();
        img.resize(s.outputs.bytes(), 0);
        s.outputs.encode_into(&values, &mut img)?;
        self.slaves[i].output_image = img;
        self.slaves[i].outputs_set = true;
        self.rebuild_process_data();
        Ok(format!("outputs of slave {i} set"))
    }

    // ------------------------------------------------------------------ mailbox

    async fn mailbox_exchange(&mut self, i: usize, data: Vec<u8>) -> Result<Vec<u8>> {
        let (ostart, olen) = self.slaves[i]
            .mbx_out
            .context("the slave's mailbox is not configured (request preop first)")?;
        let (istart, ilen, ism) = self.slaves[i].mbx_in.context("no send mailbox")?;
        let station = self.slaves[i].station;
        // Anything left in the send mailbox is stale.
        let status = reg::SM0 as u16 + 8 * ism as u16 + 5;
        let st = self.bus.fprd_ok(station, status, 1).await?;
        if st[0] & 0x08 != 0 {
            let _ = self.bus.fprd(station, istart, ilen as usize).await?;
        }
        let c = coe::next_counter(self.slaves[i].counter);
        self.slaves[i].counter = c;
        let m = coe::coe_mailbox(c, data).encode(olen as usize);
        ensure!(
            m.len() <= olen as usize,
            "the request does not fit the mailbox"
        );
        let started = Instant::now();
        loop {
            if self.bus.fpwr(station, ostart, m.clone()).await? == 1 {
                break;
            }
            ensure!(
                started.elapsed() < self.cfg.mailbox_timeout,
                "the slave's receive mailbox stayed full"
            );
            tokio::time::sleep(POLL).await;
        }
        loop {
            let st = self.bus.fprd_ok(station, status, 1).await?;
            if st[0] & 0x08 != 0 {
                let d = self.bus.fprd(station, istart, ilen as usize).await?;
                if d.wkc == 1 {
                    let reply = coe::Mailbox::parse(&d.data)?;
                    if reply.mbx_type == coe::mbx_type::ERROR {
                        let detail = reply
                            .data
                            .get(2..4)
                            .map(|b| u16::from_le_bytes([b[0], b[1]]))
                            .unwrap_or(0);
                        bail!("the slave answered with mailbox error {detail:#06x}");
                    }
                    if reply.mbx_type == coe::mbx_type::COE
                        && coe::coe_service(&reply.data) == Some(coe::service::EMERGENCY)
                    {
                        continue;
                    }
                    return Ok(reply.data);
                }
            }
            ensure!(
                started.elapsed() < self.cfg.mailbox_timeout,
                "no SDO answer within {} ms",
                self.cfg.mailbox_timeout.as_millis()
            );
            tokio::time::sleep(POLL).await;
        }
    }

    /// Read an object's octets. An abort is an error naming its code.
    async fn sdo_upload(&mut self, i: usize, index: u16, sub: u8) -> Result<Vec<u8>> {
        let reply = self
            .mailbox_exchange(i, coe::upload_request(index, sub))
            .await?;
        match coe::parse_response(&reply)? {
            SdoResponse::Upload { size, mut data } => {
                let mut toggle = false;
                while data.len() < size {
                    let r = self
                        .mailbox_exchange(i, coe::upload_segment_request(toggle))
                        .await?;
                    match coe::parse_response(&r)? {
                        SdoResponse::UploadSegment { last, data: seg } => {
                            data.extend_from_slice(&seg);
                            ensure!(data.len() <= coe::MAX_SDO_BYTES, "the value is too long");
                            if last {
                                break;
                            }
                        }
                        SdoResponse::Abort { code } => return Err(SdoAbort(code).into()),
                        other => bail!("unexpected answer {other:?}"),
                    }
                    toggle = !toggle;
                }
                data.truncate(size);
                Ok(data)
            }
            SdoResponse::Abort { code } => Err(SdoAbort(code).into()),
            other => bail!("unexpected answer {other:?}"),
        }
    }

    async fn sdo_download(&mut self, i: usize, index: u16, sub: u8, value: &[u8]) -> Result<()> {
        let mailbox = self.slaves[i]
            .mbx_out
            .map(|m| m.1 as usize)
            .unwrap_or(sii::DEFAULT_MAILBOX);
        let (first, mut rest) = coe::download_request(index, sub, value, mailbox);
        let reply = self.mailbox_exchange(i, first).await?;
        match coe::parse_response(&reply)? {
            SdoResponse::Download => {}
            SdoResponse::Abort { code } => return Err(SdoAbort(code).into()),
            other => bail!("unexpected answer {other:?}"),
        }
        let mut toggle = false;
        while !rest.is_empty() {
            let (seg, r) = coe::download_segment_request(toggle, &rest, mailbox);
            rest = r;
            let reply = self.mailbox_exchange(i, seg).await?;
            match coe::parse_response(&reply)? {
                SdoResponse::DownloadSegment => {}
                SdoResponse::Abort { code } => return Err(SdoAbort(code).into()),
                other => bail!("unexpected answer {other:?}"),
            }
            toggle = !toggle;
        }
        Ok(())
    }

    fn sdo_result(
        &self,
        i: usize,
        op: &str,
        index: u16,
        sub: u8,
        r: Result<Value>,
        ty: Option<DataType>,
        depth: u32,
    ) {
        let mut v = json!({"slave": i, "operation": op, "index": index, "subindex": sub,
            "ok": r.is_ok()});
        if let Some(t) = ty {
            v["data_type"] = json!(t.name());
        }
        match r {
            Ok(val) => v["value"] = val,
            Err(e) => match e.downcast_ref::<SdoAbort>() {
                Some(SdoAbort(code)) => {
                    v["abort_code"] = json!(code);
                    v["abort"] = json!(coe::abort::name(*code));
                }
                None => v["error"] = json!(format!("{e:#}")),
            },
        }
        self.emit(&actions::SDO_RESULT_EVENT, v, depth);
    }

    async fn sdo_read_action(&mut self, v: &Value, depth: u32) -> Result<String> {
        let i = actions::slave_of(v)?;
        ensure!(i < self.slaves.len(), "there is no slave {i}");
        let (index, sub) = actions::object_of(v)?;
        let ty = actions::data_type_of(v)?;
        let r = self
            .sdo_upload(i, index, sub)
            .await
            .and_then(|b| decode_value(&b, ty));
        let detail = match &r {
            Ok(v) => format!("{index:#06x}:{sub} = {v}"),
            Err(e) => format!("{index:#06x}:{sub} failed: {e:#}"),
        };
        self.sdo_result(i, "read", index, sub, r, ty, depth);
        Ok(detail)
    }

    async fn sdo_write_action(&mut self, v: &Value, depth: u32) -> Result<String> {
        let i = actions::slave_of(v)?;
        ensure!(i < self.slaves.len(), "there is no slave {i}");
        let (index, sub) = actions::object_of(v)?;
        let ty = actions::data_type_of(v)?.context("data_type is required")?;
        let bytes = ty.encode(&v["value"])?;
        let r = self
            .sdo_download(i, index, sub, &bytes)
            .await
            .map(|_| v["value"].clone());
        let detail = match &r {
            Ok(_) => format!("{index:#06x}:{sub} written"),
            Err(e) => format!("{index:#06x}:{sub} failed: {e:#}"),
        };
        self.sdo_result(i, "write", index, sub, r, Some(ty), depth);
        Ok(detail)
    }
}

/// An SDO abort, kept typed so the result event can name its code.
#[derive(Debug)]
struct SdoAbort(u32);

impl std::fmt::Display for SdoAbort {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "SDO abort {:#010x}: {}",
            self.0,
            coe::abort::name(self.0)
        )
    }
}

impl std::error::Error for SdoAbort {}

/// A read value as JSON: by its declared type, or by its length when none was given.
fn decode_value(b: &[u8], ty: Option<DataType>) -> Result<Value> {
    if let Some(t) = ty {
        return t
            .decode(b)
            .with_context(|| format!("{} octets do not decode as {}", b.len(), t.name()));
    }
    Ok(match b.len() {
        1 => json!(b[0]),
        2 => json!(u16::from_le_bytes([b[0], b[1]])),
        4 => json!(u32::from_le_bytes([b[0], b[1], b[2], b[3]])),
        8 => json!(u64::from_le_bytes(b.try_into().unwrap_or([0; 8]))),
        n => {
            let text = String::from_utf8_lossy(b);
            if !text.contains('\u{FFFD}')
                && !crate::utils::sanitize::has_controls(text.trim_end_matches('\0'))
            {
                json!(text.trim_end_matches('\0'))
            } else {
                bail!("{n} octets with no data_type to decode them; give data_type")
            }
        }
    })
}

async fn run_turns(
    ctx: ConnectContext,
    mut events: mpsc::Receiver<(Event, u32)>,
    internal: mpsc::Sender<(Value, u32)>,
) {
    let protocol = EthercatClientProtocol;
    while let Some((event, depth)) = events.recv().await {
        if depth >= MAX_FOLLOWUP_DEPTH {
            tracing::warn!(
                "EtherCAT master {} not asking the model about {}: {depth} turns deep decision=followup_depth",
                ctx.client_id,
                event.id()
            );
            continue;
        }
        let instruction = ctx
            .state
            .get_instruction_for_client(ctx.client_id)
            .await
            .unwrap_or_default();
        let memory = ctx
            .state
            .get_memory_for_client(ctx.client_id)
            .await
            .unwrap_or_default();
        match call_llm_for_client(
            &ctx.llm_client,
            &ctx.state,
            ctx.client_id.to_string(),
            &instruction,
            &memory,
            Some(&event),
            &protocol,
            &ctx.status_tx,
        )
        .await
        {
            Ok(result) => {
                if let Some(memory) = result.memory_updates {
                    ctx.state.set_memory_for_client(ctx.client_id, memory).await;
                }
                if result.actions.is_empty() {
                    tracing::debug!(
                        "EtherCAT master {}: {} answered with nothing decision=model_silent",
                        ctx.client_id,
                        event.id()
                    );
                }
                for action in result.actions {
                    if internal.send((action, depth)).await.is_err() {
                        return;
                    }
                }
            }
            Err(e) => {
                let tag = match crate::utils::wire_failure::WireFailure::classify(&e) {
                    crate::utils::wire_failure::WireFailure::Overloaded => {
                        "fail_closed_llm_overloaded"
                    }
                    crate::utils::wire_failure::WireFailure::Unavailable => "fail_closed_llm_error",
                };
                Log::new(Some(&ctx.status_tx)).warn(format!(
                    "EtherCAT master {}: {} not answered; nothing sent, outputs unchanged decision={tag}: {e}",
                    ctx.client_id,
                    event.id()
                ))
            }
        }
    }
}
