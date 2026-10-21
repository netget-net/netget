//! Zigbee: NetGet as a coordinator's network co-processor (NCP), reached over TCP the way
//! network-attached coordinators are. A Zigbee host — zigpy's bellows, Zigbee2MQTT's ember
//! adapter — speaks Silicon Labs EZSP over ASH to it, forms or resumes a network, and talks to
//! the devices behind it. Rust owns ASH (`ash.rs`), EZSP (`ezsp.rs`, `ncp.rs`) and the devices'
//! ZDO and description-covered ZCL (`device.rs`); the model decides which devices join and how
//! they answer everything else.
//!
//! This is the host-to-co-processor link, not Zigbee over the air: there is no radio and no
//! 802.15.4, NWK or APS security. Every frame a device sends is built from its description or
//! the model's answer.
pub mod actions;
pub mod ash;
pub mod device;
pub mod ezsp;
pub mod ncp;

use crate::llm::action_helper::call_llm;
use crate::llm::actions::protocol_trait::ActionResult;
use crate::logging::emit::Log;
use crate::protocol::{Event, SpawnContext};
use crate::server::accept_bounded::{accept_bounded, ConnectionLimiter};
use crate::server::connection::ConnectionId;
use crate::state::client_handles::{ClientCommand, ClientSendOutcome};
use crate::state::server::{ConnectionState, ConnectionStatus, ProtocolConnectionInfo};
use crate::state::AccessLogOwner;
use crate::utils::wire_failure::WireFailure;
use anyhow::{bail, ensure, Context, Result};
use device::{Device, ZclOutcome, ZclRequest};
use ezsp::ApsFrame;
use ncp::{Callback, Effect, Nvram, Ram};
use serde_json::{json, Value};
use std::collections::{BTreeMap, VecDeque};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

/// The NCP has one UART: one host at a time.
pub const MAX_CONNECTIONS: usize = 1;
/// How long a device waits for the model's answer before replying FAILURE.
pub const DEFAULT_DECISION_TIMEOUT: Duration = Duration::from_secs(10);
pub const MAX_DECISION_TIMEOUT_SECS: u64 = 120;
/// A host that sends nothing at all for this long is disconnected. Hosts poll their NCP
/// (bellows' watchdog every 10 s, herdsman's counters hourly); an hour of silence is a dead
/// host.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(3600);
/// A write to the host that does not complete in this long ends the session.
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(10);
/// Model calls in flight across the server; another request is answered FAILURE at once.
pub const MAX_MODEL_CALLS: usize = 8;
/// Callbacks held while the host says it is not ready, or before the link is up.
pub const MAX_PENDING_CALLBACKS: usize = 64;
/// Bytes read from the socket at a time.
const READ_CHUNK: usize = 1024;

/// What the server was started with.
#[derive(Clone, Debug)]
pub struct Settings {
    pub version: u8,
    pub timeout: Duration,
}

fn parse_key(s: &str) -> Result<[u8; 16]> {
    let hex: String = s.chars().filter(|c| *c != ':' && *c != ' ').collect();
    let b = hex::decode(&hex).context("network_key is 32 hex digits")?;
    ensure!(b.len() == 16, "network_key is 16 bytes (32 hex digits)");
    let mut k = [0u8; 16];
    k.copy_from_slice(&b);
    Ok(k)
}

/// Read the startup parameters into the settings and the co-processor's initial flash.
pub fn configure(ctx: &SpawnContext) -> Result<(Settings, Nvram)> {
    let params = ctx.startup_params.as_ref();
    let version = params
        .map(|p| p.get_optional_u64("ezsp_version"))
        .transpose()?
        .flatten()
        .unwrap_or(ezsp::DEFAULT_VERSION as u64);
    ensure!(
        (ezsp::MIN_VERSION as u64..=ezsp::MAX_VERSION as u64).contains(&version),
        "ezsp_version is {} to {}",
        ezsp::MIN_VERSION,
        ezsp::MAX_VERSION
    );
    let timeout = params
        .map(|p| p.get_optional_u64("decision_timeout_secs"))
        .transpose()?
        .flatten()
        .unwrap_or(DEFAULT_DECISION_TIMEOUT.as_secs());
    ensure!(
        (1..=MAX_DECISION_TIMEOUT_SECS).contains(&timeout),
        "decision_timeout_secs is 1 to {MAX_DECISION_TIMEOUT_SECS}"
    );
    let eui64 = match params
        .map(|p| p.get_optional_string("ieee"))
        .transpose()?
        .flatten()
    {
        Some(s) => device::parse_eui(&s)?,
        None => ncp::DEFAULT_EUI64,
    };
    let key = params
        .map(|p| p.get_optional_string("network_key"))
        .transpose()?
        .flatten()
        .map(|k| parse_key(&k))
        .transpose()?;
    let network = match params
        .map(|p| p.get_optional_object("network"))
        .transpose()?
        .flatten()
    {
        Some(n) => {
            let n = Value::Object(n.clone());
            let channel = n["channel"].as_u64().context("network.channel is 11..26")?;
            ensure!((11..=26).contains(&channel), "network.channel is 11..26");
            let pan_id = device::parse_u16(&n["pan_id"], "network.pan_id")?;
            ensure!(pan_id < 0xFFFF, "network.pan_id 0xffff is not a PAN");
            let epid = device::parse_eui(
                n["extended_pan_id"]
                    .as_str()
                    .context("network.extended_pan_id is 16 hex digits")?,
            )?;
            let network_key = match key {
                Some(k) => k,
                None => rand::random(),
            };
            Some(ncp::Network {
                params: ezsp::NetworkParameters {
                    extended_pan_id: epid.to_le_bytes(),
                    pan_id,
                    radio_tx_power: 8,
                    radio_channel: channel as u8,
                    join_method: 0,
                    nwk_manager_id: 0,
                    nwk_update_id: 0,
                    channels: 1 << channel,
                },
                network_key,
                key_sequence: 0,
                tc_link_key: ncp::WELL_KNOWN_LINK_KEY,
                hashed_tclk: false,
            })
        }
        None => {
            ensure!(
                key.is_none(),
                "network_key belongs to a formed network: give network too"
            );
            None
        }
    };
    let mut waiting: Vec<Device> = Vec::new();
    if let Some(list) = params
        .map(|p| p.get_optional_array("devices"))
        .transpose()?
        .flatten()
    {
        ensure!(
            list.len() <= device::MAX_DEVICES,
            "devices holds at most {}",
            device::MAX_DEVICES
        );
        for (i, d) in list.iter().enumerate() {
            let taken: Vec<u16> = waiting.iter().map(|w| w.nwk).collect();
            let dev = device::parse_device(d, &taken).with_context(|| format!("devices[{i}]"))?;
            ensure!(
                !waiting
                    .iter()
                    .any(|w| w.ieee == dev.ieee || w.name == dev.name),
                "devices[{i}]: name {} or ieee {} is described twice",
                dev.name,
                device::eui_display(dev.ieee)
            );
            waiting.push(dev);
        }
    }
    Ok((
        Settings {
            version: version as u8,
            timeout: Duration::from_secs(timeout),
        },
        Nvram {
            eui64,
            network,
            nwk_frame_counter: 0,
            aps_frame_counter: 0,
            joined: Vec::new(),
            waiting,
            link_keys: Vec::new(),
        },
    ))
}

/// Shared by the server's sessions: the co-processor's flash outlives a host connection.
pub struct Shared {
    pub ctx: Arc<SpawnContext>,
    pub settings: Settings,
    pub nv: Mutex<Nvram>,
    /// One model question at a time.
    pub gate: tokio::sync::Mutex<()>,
    pub in_flight: AtomicUsize,
}

impl Shared {
    pub fn nv(&self) -> std::sync::MutexGuard<'_, Nvram> {
        self.nv.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Log how a decision went, in the `decision=` vocabulary every server shares.
    pub fn outcome(&self, op: &str, device: &str, decision: &str, detail: &str) {
        let line = format!(
            "Zigbee operation={op} device={} decision={decision} {}",
            crate::utils::sanitize::token(device, 64),
            crate::utils::sanitize::strip_controls(detail)
        );
        let log = Log::new(Some(&self.ctx.status_tx));
        if decision.starts_with("fail_closed_") || decision == "model_silent" {
            log.error(line);
        } else {
            log.info(line);
        }
    }
}

pub async fn spawn(ctx: SpawnContext) -> Result<SocketAddr> {
    let (settings, nv) = configure(&ctx)?;
    let listener = tokio::net::TcpListener::bind(ctx.legacy_listen_addr())
        .await
        .with_context(|| format!("binding {}", ctx.legacy_listen_addr()))?;
    let local = listener.local_addr()?;
    let shared = Arc::new(Shared {
        ctx: Arc::new(ctx.clone()),
        settings,
        nv: Mutex::new(nv),
        gate: tokio::sync::Mutex::new(()),
        in_flight: AtomicUsize::new(0),
    });
    Log::new(Some(&ctx.status_tx)).info(format!(
        "Zigbee EZSP v{} co-processor on {local}",
        shared.settings.version
    ));
    let task = tokio::spawn(accept_loop(listener, shared));
    ctx.state.register_server_task(ctx.server_id, task).await;
    Ok(local)
}

async fn accept_loop(listener: tokio::net::TcpListener, shared: Arc<Shared>) {
    let limiter = ConnectionLimiter::new(MAX_CONNECTIONS);
    let server_id = shared.ctx.server_id;
    let Ok(listening) = listener.local_addr() else {
        return;
    };
    loop {
        // ASH has no frame that says "busy": a second host is closed without a word.
        let (stream, peer, permit) = match accept_bounded(
            &listener,
            &limiter,
            b"",
            "Zigbee",
            Some(&shared.ctx.status_tx),
        )
        .await
        {
            Ok(v) => v,
            Err(_) => break,
        };
        let _ = stream.set_nodelay(true);
        let local = stream.local_addr().unwrap_or(listening);
        let id = ConnectionId::new(shared.ctx.state.get_next_unified_id().await);
        let now = crate::utils::clock::Instant::now();
        shared
            .ctx
            .state
            .add_connection_to_server(
                server_id,
                ConnectionState {
                    id,
                    remote_addr: peer,
                    local_addr: local,
                    bytes_sent: 0,
                    bytes_received: 0,
                    packets_sent: 0,
                    packets_received: 0,
                    last_activity: now,
                    status: ConnectionStatus::Active,
                    status_changed_at: now,
                    protocol_info: ProtocolConnectionInfo::new(json!({"role": "host"})),
                },
            )
            .await;
        let commands = crate::server::peer_support::register_peer_channel(
            &shared.ctx.state,
            server_id,
            id.as_u32(),
        )
        .await;
        let child = shared.clone();
        shared
            .ctx
            .state
            .spawn_server_task(server_id, async move {
                let _permit = permit;
                let (tx, rx) = mpsc::channel(32);
                let mut s = Session::new(child.clone(), id, tx);
                if let Err(e) = s.run(stream, rx, commands).await {
                    Log::new(Some(&child.ctx.status_tx))
                        .debug(format!("Zigbee host connection {id}: {e:#}"));
                }
                s.closed();
                child
                    .ctx
                    .state
                    .remove_peer_handle(server_id, id.as_u32())
                    .await;
                child
                    .ctx
                    .state
                    .update_connection_status(server_id, id, ConnectionStatus::Closed)
                    .await;
                let _ = child.ctx.status_tx.send("__UPDATE_UI__".into());
            })
            .await;
    }
}

/// Why the model gave no usable answer.
#[derive(Debug)]
pub enum Failure {
    Deadline,
    Llm(WireFailure),
    Silent,
    Invalid(String),
    Overloaded,
}

impl Failure {
    pub fn decision(&self) -> &'static str {
        match self {
            Failure::Deadline => "fail_closed_deadline",
            Failure::Llm(_) => "fail_closed_llm_error",
            Failure::Silent => "model_silent",
            Failure::Invalid(_) => "fail_closed_invalid_reply",
            Failure::Overloaded => "fail_closed_overloaded",
        }
    }
    pub fn detail(&self) -> String {
        match self {
            Failure::Deadline => "no answer before decision_timeout_secs".into(),
            Failure::Llm(_) => "the model backend failed".into(),
            Failure::Silent => "no answer".into(),
            Failure::Invalid(why) => why.clone(),
            Failure::Overloaded => format!("{MAX_MODEL_CALLS} model calls already in flight"),
        }
    }
}

/// What a model task hands back to its session.
enum Deferred {
    Permit {
        answers: std::result::Result<Vec<Value>, Failure>,
    },
    Zcl {
        ieee: u64,
        request: ZclRequest,
        host_endpoint: u8,
        profile: u16,
        answers: std::result::Result<Vec<Value>, Failure>,
    },
}

/// Ask the model one question; the answers are the actions it chose, validated by the
/// protocol's executor.
async fn ask(
    shared: &Shared,
    connection: ConnectionId,
    event: &Event,
    allowed: &[&str],
) -> std::result::Result<Vec<Value>, Failure> {
    if shared.in_flight.fetch_add(1, Ordering::SeqCst) >= MAX_MODEL_CALLS {
        shared.in_flight.fetch_sub(1, Ordering::SeqCst);
        return Err(Failure::Overloaded);
    }
    let deadline = tokio::time::Instant::now() + shared.settings.timeout;
    let result = async {
        let _gate = match tokio::time::timeout_at(deadline, shared.gate.lock()).await {
            Ok(g) => g,
            Err(_) => return Err(Failure::Deadline),
        };
        let call = call_llm(
            &shared.ctx.llm_client,
            &shared.ctx.state,
            shared.ctx.server_id,
            Some(connection),
            event,
            &actions::ZigbeeProtocol,
        );
        match tokio::time::timeout_at(deadline, call).await {
            Err(_) => Err(Failure::Deadline),
            Ok(Err(e)) => Err(Failure::Llm(WireFailure::classify(&e))),
            Ok(Ok(r)) => {
                let why = r.failure_summary();
                let mut answers = Vec::new();
                let mut stack = r.protocol_results;
                stack.reverse();
                while let Some(item) = stack.pop() {
                    match item {
                        ActionResult::Custom { data, .. } => answers.push(data),
                        ActionResult::Multiple(items) => {
                            stack.extend(items.into_iter().rev());
                        }
                        _ => {}
                    }
                }
                if !r.failures.is_empty() {
                    return Err(Failure::Invalid(
                        why.unwrap_or_else(|| "an action was refused".into()),
                    ));
                }
                if answers.is_empty() {
                    return Err(Failure::Silent);
                }
                if let Some(bad) = answers
                    .iter()
                    .find(|a| !allowed.contains(&a["type"].as_str().unwrap_or_default()))
                {
                    return Err(Failure::Invalid(format!(
                        "{} does not answer this event (expected {})",
                        bad["type"].as_str().unwrap_or("an action without a type"),
                        allowed.join(", ")
                    )));
                }
                Ok(answers)
            }
        }
    }
    .await;
    shared.in_flight.fetch_sub(1, Ordering::SeqCst);
    result
}

/// One host's session with the co-processor.
struct Session {
    shared: Arc<Shared>,
    id: ConnectionId,
    link: ash::Link,
    deframer: ash::Deframer,
    ram: Ram,
    /// Sequence number of the last command answered; callbacks carry it.
    last_sequence: u8,
    pending: VecDeque<Callback>,
    /// A callback was dropped for lack of room: the next response says so.
    overflowed: bool,
    permit_until: Option<tokio::time::Instant>,
    /// Every frame id the host sent, with how many times: what it actually uses.
    census: BTreeMap<u16, u64>,
    deferred: mpsc::Sender<Deferred>,
    out: Vec<u8>,
}

impl Session {
    fn new(shared: Arc<Shared>, id: ConnectionId, deferred: mpsc::Sender<Deferred>) -> Self {
        Self {
            shared,
            id,
            link: ash::Link::new(),
            deframer: ash::Deframer::new(),
            ram: Ram::new(),
            last_sequence: 0,
            pending: VecDeque::new(),
            overflowed: false,
            permit_until: None,
            census: BTreeMap::new(),
            deferred,
            out: Vec::new(),
        }
    }

    fn log(&self) -> Log<'_> {
        Log::new(Some(&self.shared.ctx.status_tx))
    }

    async fn run(
        &mut self,
        stream: TcpStream,
        mut deferred: mpsc::Receiver<Deferred>,
        mut commands: mpsc::Receiver<ClientCommand>,
    ) -> Result<()> {
        let (mut rd, mut wr) = stream.into_split();
        let mut buf = vec![0u8; READ_CHUNK];
        let mut idle_until = tokio::time::Instant::now() + IDLE_TIMEOUT;
        loop {
            let now = tokio::time::Instant::now();
            let mut wake = idle_until;
            if let Some(d) = self.link.deadline() {
                wake = wake.min(tokio::time::Instant::from_std(d));
            }
            if let Some(p) = self.permit_until {
                wake = wake.min(p);
            }
            if !self.pending.is_empty() {
                wake = wake.min(now + ash::T_REMOTE_NOTRDY);
            }
            tokio::select! {
                read = rd.read(&mut buf) => {
                    let n = read?;
                    if n == 0 {
                        return Ok(());
                    }
                    idle_until = tokio::time::Instant::now() + IDLE_TIMEOUT;
                    self.shared
                        .ctx
                        .state
                        .update_connection_stats(self.shared.ctx.server_id, self.id, Some(n as u64), None, Some(1), None)
                        .await;
                    let mut frames = Vec::new();
                    self.deframer.push(&buf[..n], &mut frames);
                    for f in frames {
                        if !self.receive(f).await {
                            return Ok(());
                        }
                    }
                }
                Some(d) = deferred.recv() => {
                    self.apply_deferred(d).await;
                }
                Some(c) = commands.recv() => {
                    self.injected(c).await;
                }
                _ = tokio::time::sleep_until(wake) => {
                    let now = tokio::time::Instant::now();
                    if now >= idle_until {
                        bail!("no frame from the host for {}s", IDLE_TIMEOUT.as_secs());
                    }
                    let mut o = ash::Output::default();
                    self.link.timeout(now.into_std(), &mut o);
                    if o.failed {
                        self.log().warn(format!(
                            "Zigbee host connection {}: {} acknowledgement timeouts; the link is in the failed state until the host resets it",
                            self.id,
                            ash::ACK_TIMEOUTS
                        ));
                    }
                    self.out.extend(o.wire);
                    if self.permit_until.is_some_and(|p| now >= p) {
                        self.permit_until = None;
                        self.ram.permit_secs = 0;
                        self.queue(ncp::network_opened(false));
                    }
                }
            }
            self.flush_callbacks();
            if !self.out.is_empty() {
                let bytes = std::mem::take(&mut self.out);
                tokio::time::timeout(WRITE_TIMEOUT, wr.write_all(&bytes))
                    .await
                    .context("the host stopped reading")??;
                self.shared
                    .ctx
                    .state
                    .update_connection_stats(
                        self.shared.ctx.server_id,
                        self.id,
                        None,
                        Some(bytes.len() as u64),
                        None,
                        Some(1),
                    )
                    .await;
            }
        }
    }

    fn closed(&self) {
        let census: Vec<String> = self
            .census
            .iter()
            .map(|(id, n)| match ezsp::name(*id) {
                Some(name) => format!("{name}×{n}"),
                None => format!("unknown 0x{id:04x}×{n}"),
            })
            .collect();
        let c = self.link.counters;
        self.log().info(format!(
            "Zigbee host connection {} closed; EZSP commands: {}; ASH rx_data={} bad_crc={} too_long={} corrupt={} out_of_sequence={} tx_data={} retransmits={} naks={}",
            self.id,
            census.join(" "),
            c.rx_data,
            c.rx_bad_crc,
            c.rx_too_long,
            c.rx_corrupt,
            c.rx_out_of_sequence,
            c.tx_data,
            c.tx_retransmits,
            c.tx_naks
        ));
    }

    /// Handle one deframed unit; `false` when the connection must close.
    async fn receive(&mut self, d: ash::Deframed) -> bool {
        let now = std::time::Instant::now();
        let mut o = ash::Output::default();
        self.link.receive(d, now, &mut o);
        self.out.extend(o.wire);
        if o.close {
            self.log().info(format!(
                "Zigbee host connection {}: a frame longer than {} bytes before any RST; not an ASH host, closing",
                self.id,
                ash::MAX_FRAME
            ));
            return false;
        }
        if o.reset {
            // The NCP rebooted: RAM is gone, the network is down until networkInit.
            self.ram = Ram::new();
            self.pending.clear();
            self.permit_until = None;
            self.log().debug(format!(
                "Zigbee host connection {}: RST, answered RSTACK (software reset)",
                self.id
            ));
        }
        for frame in o.delivered {
            self.command(&frame).await;
        }
        true
    }

    /// Queue a response frame for the host, flagging any callback that was dropped.
    fn respond(&mut self, mut frame: Vec<u8>) {
        if self.overflowed && frame.len() > 1 {
            frame[1] |= 0x01;
            self.overflowed = false;
        }
        let mut o = ash::Output::default();
        self.link.send(frame, std::time::Instant::now(), &mut o);
        self.out.extend(o.wire);
    }

    fn queue(&mut self, cb: Callback) {
        if self.pending.len() >= MAX_PENDING_CALLBACKS {
            self.overflowed = true;
            return;
        }
        self.pending.push_back(cb);
    }

    fn flush_callbacks(&mut self) {
        let now = std::time::Instant::now();
        if !self.link.connected() || self.ram.version.is_none() || self.link.host_not_ready(now) {
            return;
        }
        let mut o = ash::Output::default();
        while let Some(cb) = self.pending.pop_front() {
            let frame = ezsp::callback(self.last_sequence, cb.frame_id, &cb.params);
            self.link.send(frame, now, &mut o);
        }
        self.out.extend(o.wire);
    }

    async fn command(&mut self, frame: &[u8]) {
        let cmd = match ezsp::parse_command(frame) {
            Ok(c) => c,
            Err((seq, e)) => {
                let status = match e {
                    ezsp::HeaderError::UnsupportedControl => {
                        ezsp::ezsp_status::ERROR_UNSUPPORTED_CONTROL
                    }
                    _ => ezsp::ezsp_status::ERROR_INVALID_FRAME_ID,
                };
                let cmd = ezsp::Command {
                    sequence: seq,
                    frame_id: ezsp::id::INVALID_COMMAND,
                    legacy: false,
                    params: Vec::new(),
                };
                self.respond(ezsp::invalid_command(&cmd, status));
                return;
            }
        };
        *self.census.entry(cmd.frame_id).or_insert(0) += 1;
        self.last_sequence = cmd.sequence;
        let handled = {
            let mut nv = self.shared.nv();
            ncp::handle(self.shared.settings.version, &mut self.ram, &mut nv, &cmd)
        };
        match handled.name {
            Some(name) => self.log().trace(format!(
                "Zigbee EZSP {name} seq={} params={}",
                cmd.sequence,
                hex::encode(&cmd.params)
            )),
            None => self.log().debug(format!(
                "Zigbee EZSP unknown frame id 0x{:04x} answered invalidCommand(ERROR_INVALID_FRAME_ID)",
                cmd.frame_id
            )),
        }
        self.respond(handled.response);
        for cb in handled.callbacks {
            self.queue(cb);
        }
        for effect in handled.effects {
            self.effect(effect).await;
        }
    }

    async fn effect(&mut self, effect: Effect) {
        match effect {
            Effect::Permit(secs) => {
                if secs == 0 {
                    self.permit_until = None;
                    return;
                }
                // 255 keeps the network open until it is closed again.
                self.permit_until = (secs != 255)
                    .then(|| tokio::time::Instant::now() + Duration::from_secs(secs as u64));
                self.ask_permit(secs).await;
            }
            Effect::Formed => {
                let nv = self.shared.nv();
                if let Some(n) = &nv.network {
                    self.log().info(format!(
                        "Zigbee host formed a network: channel {} PAN 0x{:04x} extended PAN {}",
                        n.params.radio_channel,
                        n.params.pan_id,
                        device::eui_display(u64::from_le_bytes(n.params.extended_pan_id))
                    ));
                }
            }
            Effect::Left => self.log().info("Zigbee co-processor left its network"),
            Effect::Remove(ieee) => {
                let mut nv = self.shared.nv();
                for cb in leave(&mut nv, ieee) {
                    self.pending.push_back(cb);
                }
            }
            Effect::Unicast {
                nwk,
                aps,
                tag,
                message,
                message_type,
            } => self.unicast(nwk, aps, tag, message, message_type).await,
            Effect::Broadcast {
                destination,
                aps,
                tag,
                message,
            } => {
                let contents = self
                    .ram
                    .contents_in_callback()
                    .then_some(message.as_slice());
                self.queue(ncp::message_sent(
                    ezsp::sl::OK,
                    ncp::outgoing::BROADCAST,
                    destination,
                    &aps,
                    tag,
                    contents,
                ));
                if aps.profile_id == device::PROFILE_ZDO {
                    let replies: Vec<Callback> = {
                        let mut nv = self.shared.nv();
                        let mut out = Vec::new();
                        for d in nv.joined.iter_mut() {
                            if let Some(r) = device::zdo(d, aps.cluster_id, &message, true) {
                                out.push(from_device(d, &aps, r.cluster, 0, &r.payload));
                            }
                        }
                        out
                    };
                    for r in replies {
                        self.queue(r);
                    }
                }
            }
            Effect::Multicast { aps, tag, message } => {
                let contents = self
                    .ram
                    .contents_in_callback()
                    .then_some(message.as_slice());
                self.queue(ncp::message_sent(
                    ezsp::sl::OK,
                    ncp::outgoing::MULTICAST,
                    aps.group_id,
                    &aps,
                    tag,
                    contents,
                ));
            }
        }
    }

    async fn unicast(
        &mut self,
        nwk: u16,
        aps: ApsFrame,
        tag: u16,
        message: Vec<u8>,
        message_type: u8,
    ) {
        let contents = self.ram.contents_in_callback().then(|| message.clone());
        let sent = |status: u32| {
            ncp::message_sent(status, message_type, nwk, &aps, tag, contents.as_deref())
        };
        if nwk == ncp::COORDINATOR_NWK {
            // The coordinator's own stack answers ZDO addressed to it, from the endpoints the
            // host registered; anything else to itself is acknowledged and goes nowhere.
            self.queue(sent(ezsp::sl::OK));
            if aps.profile_id == device::PROFILE_ZDO {
                let reply = {
                    let nv = self.shared.nv();
                    let coordinator = self.ram.coordinator(&nv);
                    coordinator_zdo(&coordinator, &self.ram, aps.cluster_id, &message)
                        .map(|(c, p)| from_device(&coordinator, &aps, c, 0, &p))
                };
                if let Some(cb) = reply {
                    self.queue(cb);
                }
            }
            return;
        }
        let found = {
            let nv = self.shared.nv();
            nv.joined_by_nwk(nwk).map(|i| nv.joined[i].clone())
        };
        let Some(dev) = found.filter(|_| message_type == ncp::outgoing::DIRECT) else {
            self.queue(sent(ezsp::sl::ZIGBEE_DELIVERY_FAILED));
            return;
        };
        // The device's APS layer acknowledges first; its answer follows.
        self.queue(sent(ezsp::sl::OK));
        if aps.profile_id == device::PROFILE_ZDO {
            let reply = device::zdo(&dev, aps.cluster_id, &message, false);
            if let Some(r) = reply {
                let cb = {
                    let mut nv = self.shared.nv();
                    let Some(i) = nv.joined_by_ieee(dev.ieee) else {
                        return;
                    };
                    let d = &mut nv.joined[i];
                    from_device(d, &aps, r.cluster, 0, &r.payload)
                };
                self.queue(cb);
                self.record(
                    &dev,
                    "zigbee_zdo_from_description",
                    json!({"cluster": format!("0x{:04x}", aps.cluster_id)}),
                    "description",
                )
                .await;
                if r.leave_after {
                    let mut nv = self.shared.nv();
                    for cb in leave(&mut nv, dev.ieee) {
                        self.pending.push_back(cb);
                    }
                }
            }
            return;
        }
        match device::zcl(&dev, aps.destination_endpoint, aps.cluster_id, &message) {
            ZclOutcome::Nothing => {}
            ZclOutcome::Reply(frame) => {
                let cb = {
                    let mut nv = self.shared.nv();
                    let Some(i) = nv.joined_by_ieee(dev.ieee) else {
                        return;
                    };
                    let d = &mut nv.joined[i];
                    from_device(d, &aps, aps.cluster_id, aps.destination_endpoint, &frame)
                };
                self.queue(cb);
                self.record(
                    &dev,
                    "zigbee_zcl_from_description",
                    json!({"cluster": device::cluster_name(aps.cluster_id), "endpoint": aps.destination_endpoint}),
                    "description",
                )
                .await;
            }
            ZclOutcome::Ask(request) => {
                self.ask_zcl(&dev, request, aps.source_endpoint, aps.profile_id)
                    .await
            }
        }
    }

    async fn record(&self, dev: &Device, kind: &str, request: Value, answered_by: &str) {
        self.shared
            .ctx
            .state
            .record_access_log_only(
                AccessLogOwner::Server(self.shared.ctx.server_id.as_u32()),
                "Zigbee",
                Some(self.id.as_u32()),
                kind,
                json!({"device": dev.name, "request": request}),
                vec![json!({"answered_by": answered_by})],
            )
            .await;
    }

    async fn ask_permit(&mut self, secs: u8) {
        let event = {
            let nv = self.shared.nv();
            let (channel, pan) = nv
                .network
                .as_ref()
                .map(|n| (n.params.radio_channel, n.params.pan_id))
                .unwrap_or((0, 0));
            Event::new(
                &actions::PERMIT_EVENT,
                json!({
                    "duration_secs": secs,
                    "waiting_devices": nv.waiting.iter().map(Device::summary).collect::<Vec<_>>(),
                    "joined_devices": nv.joined.iter().map(|d| d.name.clone()).collect::<Vec<_>>(),
                    "channel": channel,
                    "pan_id": format!("0x{pan:04x}"),
                }),
            )
        };
        let shared = self.shared.clone();
        let tx = self.deferred.clone();
        let id = self.id;
        let state = shared.ctx.state.clone();
        let server_id = shared.ctx.server_id;
        state
            .spawn_server_task(server_id, async move {
                let answers = ask(
                    &shared,
                    id,
                    &event,
                    &[actions::JOIN_DEVICE, actions::IGNORE],
                )
                .await;
                let _ = tx.send(Deferred::Permit { answers }).await;
            })
            .await;
    }

    async fn ask_zcl(
        &mut self,
        dev: &Device,
        request: ZclRequest,
        host_endpoint: u8,
        profile: u16,
    ) {
        let kind = match request.kind {
            device::RequestKind::ClusterCommand => "cluster_command",
            device::RequestKind::WriteAttributes { .. } => "write_attributes",
            device::RequestKind::ManufacturerGlobal => "manufacturer_global",
        };
        let command = if request.header.cluster_specific() {
            device::command_name(request.cluster, request.header.command)
        } else {
            format!("0x{:02x}", request.header.command)
        };
        let event = Event::new(
            &actions::ZCL_EVENT,
            json!({
                "device": dev.name,
                "ieee": device::eui_display(dev.ieee),
                "nwk": format!("0x{:04x}", dev.nwk),
                "endpoint": request.endpoint,
                "cluster": device::cluster_name(request.cluster),
                "kind": kind,
                "command": command,
                "command_id": request.header.command,
                "manufacturer_code": request.header.manufacturer,
                "default_response_disabled": request.header.default_response_disabled(),
                "fields": request.fields,
                "payload": hex::encode(&request.payload),
                "payload_encoding": "hex",
                "current_attributes": dev.cluster_values(request.endpoint, request.cluster),
            }),
        );
        let shared = self.shared.clone();
        let tx = self.deferred.clone();
        let id = self.id;
        let ieee = dev.ieee;
        let state = shared.ctx.state.clone();
        let server_id = shared.ctx.server_id;
        state
            .spawn_server_task(server_id, async move {
                let answers = ask(
                    &shared,
                    id,
                    &event,
                    &[
                        actions::DEFAULT_RESPONSE,
                        actions::SET_ATTRIBUTES,
                        actions::CLUSTER_RESPONSE,
                        actions::NO_RESPONSE,
                    ],
                )
                .await;
                let _ = tx
                    .send(Deferred::Zcl {
                        ieee,
                        request,
                        host_endpoint,
                        profile,
                        answers,
                    })
                    .await;
            })
            .await;
    }

    async fn apply_deferred(&mut self, d: Deferred) {
        match d {
            Deferred::Permit { answers } => match answers {
                Err(f) => self
                    .shared
                    .outcome("permit_joining", "-", f.decision(), &f.detail()),
                Ok(list) => {
                    let mut joined = Vec::new();
                    let mut why = None;
                    for a in list
                        .iter()
                        .filter(|a| a["type"] == actions::JOIN_DEVICE)
                        .take(actions::MAX_JOINS_PER_ANSWER)
                    {
                        match self.join(&a["device"]) {
                            Ok(name) => joined.push(name),
                            Err(e) => why = Some(e.to_string()),
                        }
                    }
                    match (joined.is_empty(), why) {
                        (_, Some(why)) => self.shared.outcome(
                            "permit_joining",
                            &joined.join(","),
                            "fail_closed_invalid_reply",
                            &why,
                        ),
                        (true, None) => self.shared.outcome(
                            "permit_joining",
                            "-",
                            "model_reject",
                            "no device joins",
                        ),
                        (false, None) => self.shared.outcome(
                            "permit_joining",
                            &joined.join(","),
                            "model_answer",
                            "joined",
                        ),
                    }
                }
            },
            Deferred::Zcl {
                ieee,
                request,
                host_endpoint,
                profile,
                answers,
            } => {
                let (cbs, decision, detail, name) = {
                    let mut nv = self.shared.nv();
                    let Some(i) = nv.joined_by_ieee(ieee) else {
                        return;
                    };
                    let dev = &mut nv.joined[i];
                    let name = dev.name.clone();
                    let (cbs, decision, detail) = match answers {
                        Ok(list) => {
                            match zcl_answer(dev, &request, host_endpoint, profile, &list) {
                                Ok(cbs) => (cbs, "model_answer", String::new()),
                                Err(e) => (
                                    zcl_failure(dev, &request, host_endpoint, profile),
                                    "fail_closed_invalid_reply",
                                    e.to_string(),
                                ),
                            }
                        }
                        Err(f) => (
                            zcl_failure(dev, &request, host_endpoint, profile),
                            f.decision(),
                            f.detail(),
                        ),
                    };
                    (cbs, decision, detail, name)
                };
                let op = format!(
                    "zcl cluster={} command=0x{:02x}",
                    device::cluster_name(request.cluster),
                    request.header.command
                );
                self.shared.outcome(&op, &name, decision, &detail);
                for cb in cbs {
                    self.queue(cb);
                }
            }
        }
    }

    /// Make a device join: a described one by name or IEEE, or a new description.
    fn join(&mut self, which: &Value) -> Result<String> {
        ensure!(self.ram.up, "the network is not up");
        ensure!(
            self.ram.permit_secs > 0,
            "the network is not open for joining"
        );
        let mut nv = self.shared.nv();
        let dev = match which {
            Value::String(s) => {
                let s = s.trim();
                let ieee = device::parse_eui(s).ok();
                if let Some(d) = nv
                    .joined
                    .iter()
                    .find(|d| d.name == s || Some(d.ieee) == ieee)
                {
                    bail!("{} is already in the network", d.name);
                }
                let i = nv
                    .waiting
                    .iter()
                    .position(|d| d.name == s || Some(d.ieee) == ieee)
                    .with_context(|| format!("no described device is called {s}"))?;
                nv.waiting.remove(i)
            }
            Value::Object(_) => {
                let taken = nv.nwks_in_use();
                let d = device::parse_device(which, &taken)?;
                ensure!(
                    nv.joined_by_ieee(d.ieee).is_none(),
                    "{} is already in the network",
                    device::eui_display(d.ieee)
                );
                ensure!(
                    nv.joined.len() + nv.waiting.len() < device::MAX_DEVICES,
                    "the network holds at most {} devices",
                    device::MAX_DEVICES
                );
                nv.waiting.retain(|w| w.ieee != d.ieee);
                d
            }
            _ => bail!("device is a name, an IEEE address or a description"),
        };
        let mut dev = dev;
        if dev.kind.is_child() && ncp::child_count(&nv) >= ncp::max_children(&self.ram) {
            let name = dev.name.clone();
            nv.waiting.push(dev);
            bail!("the coordinator's child table is full; {name} cannot join it");
        }
        if nv.joined.iter().any(|d| d.nwk == dev.nwk) {
            let taken = nv.nwks_in_use();
            dev.nwk = (1..0xFFF8u16)
                .find(|n| !taken.contains(n))
                .unwrap_or(0x0001);
        }
        let name = dev.name.clone();
        let mut cbs = Vec::new();
        if dev.kind.is_child() {
            let index = ncp::child_count(&nv) as u8;
            cbs.push(ncp::child_join(
                index,
                true,
                dev.nwk,
                dev.ieee,
                dev.kind.ember_node_type(),
            ));
        }
        cbs.push(ncp::trust_center_join(
            dev.nwk,
            dev.ieee,
            ncp::join::STANDARD_SECURITY_UNSECURED_JOIN,
            ncp::join::USE_PRECONFIGURED_KEY,
        ));
        let tsn = dev.next_zcl_tsn();
        let announce = device::device_announce(&dev, tsn);
        let aps = ApsFrame {
            profile_id: device::PROFILE_ZDO,
            cluster_id: 0x0013,
            source_endpoint: 0,
            destination_endpoint: 0,
            options: 0,
            group_id: 0,
            sequence: dev.next_aps(),
        };
        cbs.push(ncp::incoming_message(
            ncp::incoming::BROADCAST,
            &aps,
            dev.nwk,
            dev.ieee,
            &announce,
        ));
        nv.joined.push(dev);
        drop(nv);
        for cb in cbs {
            self.queue(cb);
        }
        Ok(name)
    }

    /// An action injected through the dashboard or MCP `send_to_peer`.
    async fn injected(&mut self, c: ClientCommand) {
        let action = c.action.clone();
        let outcome = match actions::check(&action) {
            Err(e) => ClientSendOutcome::Rejected {
                error: e.to_string(),
            },
            Ok(()) => match self.run_injected(&action) {
                Ok(detail) => ClientSendOutcome::Executed { detail },
                Err(e) => ClientSendOutcome::Rejected {
                    error: e.to_string(),
                },
            },
        };
        self.shared
            .ctx
            .state
            .record_access_log(
                AccessLogOwner::Server(self.shared.ctx.server_id.as_u32()),
                "Zigbee",
                Some(self.id.as_u32()),
                "injected_action",
                action,
                vec![serde_json::to_value(&outcome).unwrap_or(Value::Null)],
            )
            .await;
        crate::client::command_support::reply(c, Ok(outcome));
    }

    fn run_injected(&mut self, action: &Value) -> Result<String> {
        let kind = action["type"].as_str().unwrap_or_default();
        match kind {
            actions::JOIN_DEVICE => {
                let name = self.join(&action["device"])?;
                Ok(format!("{name} joined"))
            }
            actions::LEAVE_DEVICE => {
                let mut nv = self.shared.nv();
                let i = find_joined(&nv, actions::name_of(action)?)?;
                let ieee = nv.joined[i].ieee;
                let name = nv.joined[i].name.clone();
                let cbs = leave(&mut nv, ieee);
                drop(nv);
                for cb in cbs {
                    self.queue(cb);
                }
                Ok(format!("{name} left"))
            }
            actions::REPORT_ATTRIBUTES | actions::SEND_COMMAND => {
                ensure!(self.ram.up, "the network is not up");
                let host_ep = self.host_endpoint();
                let mut nv = self.shared.nv();
                let i = find_joined(&nv, actions::name_of(action)?)?;
                let ep = actions::endpoint_of(action)?;
                let dev = &mut nv.joined[i];
                let profile = dev
                    .endpoint(ep)
                    .map(|e| e.profile)
                    .with_context(|| format!("{} has no endpoint {ep}", dev.name))?;
                let cb = if kind == actions::REPORT_ATTRIBUTES {
                    let list = action["attributes"].as_array().cloned().unwrap_or_default();
                    let mut by_cluster: BTreeMap<u16, Vec<Value>> = BTreeMap::new();
                    for a in list {
                        by_cluster
                            .entry(device::parse_cluster(&a["cluster"])?)
                            .or_default()
                            .push(a);
                    }
                    ensure!(
                        by_cluster.len() == 1,
                        "one report carries one cluster's attributes"
                    );
                    let (cluster, list) = by_cluster.into_iter().next().unwrap_or_default();
                    let written = device::apply_attributes(dev, ep, Some(cluster), &list)?;
                    let tsn = dev.next_zcl_tsn();
                    let records: Vec<(u16, device::Attribute)> =
                        written.into_iter().map(|(_, a, v)| (a, v)).collect();
                    let frame = device::report_frame(tsn, &records);
                    originate(dev, ep, host_ep, profile, cluster, &frame)
                } else {
                    let cluster = device::parse_cluster(&action["cluster"])?;
                    let command = device::parse_command(cluster, &action["command"])?;
                    let payload = actions::hex_payload(action)?;
                    let e = dev.endpoint(ep).context("endpoint")?;
                    ensure!(
                        e.out_clusters.contains(&cluster) || e.in_clusters.contains(&cluster),
                        "endpoint {ep} has no {} cluster",
                        device::cluster_name(cluster)
                    );
                    let tsn = dev.next_zcl_tsn();
                    let frame = device::command_frame(tsn, command, &payload);
                    originate(dev, ep, host_ep, profile, cluster, &frame)
                };
                let name = dev.name.clone();
                drop(nv);
                self.queue(cb);
                Ok(format!("{name}: {kind}"))
            }
            _ => bail!("{kind} is answered to an event, not sent on its own"),
        }
    }

    /// The host endpoint device-originated frames go to: the first Home Automation endpoint
    /// it registered, else its first, else 1.
    fn host_endpoint(&self) -> u8 {
        self.ram
            .endpoints
            .iter()
            .find(|e| e.profile == device::PROFILE_HA)
            .or_else(|| self.ram.endpoints.first())
            .map(|e| e.id)
            .unwrap_or(1)
    }
}

fn find_joined(nv: &Nvram, which: &str) -> Result<usize> {
    let ieee = device::parse_eui(which).ok();
    nv.joined
        .iter()
        .position(|d| d.name == which || Some(d.ieee) == ieee)
        .with_context(|| format!("no device called {which} is in the network"))
}

/// A device leaves: the trust center (and, for a child, the child table) tells the host.
fn leave(nv: &mut Nvram, ieee: u64) -> Vec<Callback> {
    let Some(i) = nv.joined_by_ieee(ieee) else {
        return Vec::new();
    };
    let child_index = nv
        .joined
        .iter()
        .filter(|d| d.kind.is_child())
        .position(|d| d.ieee == ieee);
    let dev = nv.joined.remove(i);
    let mut cbs = Vec::new();
    if let Some(index) = child_index {
        cbs.push(ncp::child_join(
            index as u8,
            false,
            dev.nwk,
            dev.ieee,
            dev.kind.ember_node_type(),
        ));
    }
    cbs.push(ncp::trust_center_join(
        dev.nwk,
        dev.ieee,
        ncp::join::DEVICE_LEFT,
        ncp::join::NO_ACTION,
    ));
    nv.waiting.push(dev);
    cbs
}

/// A frame a device sends in answer to the host: from the endpoint addressed back to the one
/// that asked, on the profile and response cluster given.
fn from_device(dev: &Device, req: &ApsFrame, cluster: u16, src_ep: u8, payload: &[u8]) -> Callback {
    let aps = ApsFrame {
        profile_id: req.profile_id,
        cluster_id: cluster,
        source_endpoint: src_ep,
        destination_endpoint: req.source_endpoint,
        options: 0,
        group_id: 0,
        sequence: dev.aps_counter.wrapping_add(1),
    };
    ncp::incoming_message(ncp::incoming::UNICAST, &aps, dev.nwk, dev.ieee, payload)
}

/// A frame a device originates (a report, a button press) to the host's endpoint.
fn originate(
    dev: &mut Device,
    ep: u8,
    host_ep: u8,
    profile: u16,
    cluster: u16,
    frame: &[u8],
) -> Callback {
    let aps = ApsFrame {
        profile_id: profile,
        cluster_id: cluster,
        source_endpoint: ep,
        destination_endpoint: host_ep,
        options: 0,
        group_id: 0,
        sequence: dev.next_aps(),
    };
    ncp::incoming_message(ncp::incoming::UNICAST, &aps, dev.nwk, dev.ieee, frame)
}

/// The coordinator's own ZDO answers.
fn coordinator_zdo(
    coordinator: &Device,
    ram: &Ram,
    cluster: u16,
    message: &[u8],
) -> Option<(u16, Vec<u8>)> {
    if cluster == 0x0002 {
        let tsn = *message.first()?;
        let mut p = vec![tsn, device::zdo_status::SUCCESS];
        p.extend_from_slice(&ncp::COORDINATOR_NWK.to_le_bytes());
        p.extend(ncp::coordinator_node_descriptor(ram.manufacturer_code));
        return Some((0x8002, p));
    }
    device::zdo(coordinator, cluster, message, false).map(|r| (r.cluster, r.payload))
}

/// The device's reply when the model gave nothing usable: the APS acknowledgement went out
/// already; the application answers FAILURE, as a device whose application rejected the
/// command does. A write with no response stays silent.
fn zcl_failure(dev: &mut Device, req: &ZclRequest, host_ep: u8, profile: u16) -> Vec<Callback> {
    if matches!(
        req.kind,
        device::RequestKind::WriteAttributes {
            no_response: true,
            ..
        }
    ) {
        return Vec::new();
    }
    let frame = device::reply_frame(
        &req.header,
        true,
        0x0B,
        &[req.header.command, device::zcl_status::FAILURE],
    );
    vec![reply_from(dev, req, host_ep, profile, &frame)]
}

fn reply_from(
    dev: &mut Device,
    req: &ZclRequest,
    host_ep: u8,
    profile: u16,
    frame: &[u8],
) -> Callback {
    let aps = ApsFrame {
        profile_id: profile,
        cluster_id: req.cluster,
        source_endpoint: req.endpoint,
        destination_endpoint: host_ep,
        options: 0,
        group_id: 0,
        sequence: dev.next_aps(),
    };
    ncp::incoming_message(ncp::incoming::UNICAST, &aps, dev.nwk, dev.ieee, frame)
}

/// Turn the model's answer to a ZCL request into the device's frames. Every action is
/// checked before any state changes, so a refused answer changes nothing.
fn zcl_answer(
    dev: &mut Device,
    req: &ZclRequest,
    host_ep: u8,
    profile: u16,
    answers: &[Value],
) -> Result<Vec<Callback>> {
    let mut status: Option<u8> = None;
    let mut sets: Vec<(&Value, bool)> = Vec::new();
    let mut cluster_response: Option<(u8, Vec<u8>)> = None;
    let mut silent = false;
    for a in answers {
        match a["type"].as_str().unwrap_or_default() {
            actions::DEFAULT_RESPONSE => {
                ensure!(status.is_none(), "two statuses for one request");
                status = Some(device::zcl_status::parse(&a["status"])?);
            }
            actions::SET_ATTRIBUTES => {
                sets.push((a, a["report"].as_bool().unwrap_or(false)));
            }
            actions::CLUSTER_RESPONSE => {
                ensure!(
                    cluster_response.is_none(),
                    "two cluster responses for one request"
                );
                ensure!(
                    req.kind == device::RequestKind::ClusterCommand,
                    "a cluster response answers a cluster command"
                );
                cluster_response = Some((
                    a["command_id"].as_u64().unwrap_or(0) as u8,
                    actions::hex_payload(a)?,
                ));
            }
            actions::NO_RESPONSE => silent = true,
            other => bail!("{other} does not answer a ZCL request"),
        }
    }
    ensure!(
        !(silent && (status.is_some() || cluster_response.is_some())),
        "zigbee_no_response with a response"
    );
    // Plan the attribute changes on a copy, so an invalid one leaves the device untouched.
    let mut trial = dev.clone();
    let mut reports: Vec<(u16, Vec<(u16, device::Attribute)>)> = Vec::new();
    for (a, report) in &sets {
        let list = a["attributes"].as_array().cloned().unwrap_or_default();
        let written = device::apply_attributes(&mut trial, req.endpoint, Some(req.cluster), &list)?;
        if *report {
            let mut by_cluster: BTreeMap<u16, Vec<(u16, device::Attribute)>> = BTreeMap::new();
            for (c, id, v) in written {
                by_cluster.entry(c).or_default().push((id, v));
            }
            reports.extend(by_cluster);
        }
    }
    let mut frames: Vec<(u16, Vec<u8>)> = Vec::new();
    match req.kind {
        device::RequestKind::WriteAttributes { no_response, .. } => {
            let st = status.unwrap_or(device::zcl_status::SUCCESS);
            if st == device::zcl_status::SUCCESS {
                // The host's own values, now the device's.
                let mut rest = req.payload.as_slice();
                let ep = trial
                    .endpoint_mut(req.endpoint)
                    .context("the endpoint is gone")?;
                while rest.len() >= 3 {
                    let attr = u16::from_le_bytes([rest[0], rest[1]]);
                    let Some((v, used)) = device::Attribute::decode(rest[2], &rest[3..]) else {
                        break;
                    };
                    ep.attributes.insert((req.cluster, attr), v);
                    rest = &rest[3 + used..];
                }
            }
            if !no_response && !silent {
                let payload = if st == device::zcl_status::SUCCESS {
                    vec![st]
                } else {
                    let mut p = Vec::new();
                    let mut rest = req.payload.as_slice();
                    while rest.len() >= 3 {
                        p.push(st);
                        p.extend_from_slice(&rest[..2]);
                        let Some((_, used)) = device::Attribute::decode(rest[2], &rest[3..]) else {
                            break;
                        };
                        rest = &rest[3 + used..];
                    }
                    p
                };
                frames.push((
                    req.cluster,
                    device::reply_frame(&req.header, true, 0x04, &payload),
                ));
            }
        }
        _ => {
            if !silent {
                if let Some((cmd, payload)) = &cluster_response {
                    frames.push((
                        req.cluster,
                        device::reply_frame(&req.header, false, *cmd, payload),
                    ));
                }
                let st = status.unwrap_or(device::zcl_status::SUCCESS);
                if cluster_response.is_none() || status.is_some() {
                    if let Some(f) = device::default_response(&req.header, st) {
                        frames.push((req.cluster, f));
                    }
                }
            }
        }
    }
    *dev = trial;
    let mut cbs = Vec::new();
    for (cluster, frame) in frames {
        let mut r = req.clone();
        r.cluster = cluster;
        cbs.push(reply_from(dev, &r, host_ep, profile, &frame));
    }
    for (cluster, records) in reports {
        let tsn = dev.next_zcl_tsn();
        let frame = device::report_frame(tsn, &records);
        cbs.push(originate(
            dev,
            req.endpoint,
            host_ep,
            profile,
            cluster,
            &frame,
        ));
    }
    Ok(cbs)
}
