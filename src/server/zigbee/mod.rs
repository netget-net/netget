//! Zigbee: NetGet as a coordinator's network co-processor (NCP), reached over TCP the way
//! network-attached coordinators are. A Zigbee host forms or resumes a network through it and
//! talks to the devices behind it, in one of two dialects chosen at startup (`dialect`):
//!
//! - **EZSP** — Silicon Labs EmberZNet firmware: EZSP carried by ASH (`ash.rs`, `ezsp.rs`,
//!   `ncp.rs`), the dialect of zigpy's bellows and Zigbee2MQTT's ember adapter.
//! - **ZNP** — TI Z-Stack 3.x.0 firmware: the Monitor and Test (MT) API (`mt.rs` for the
//!   framing, `znp.rs` for the command set and its NV memory, `zstack.rs` for the session),
//!   the dialect of zigpy-znp and Zigbee2MQTT's zstack adapter.
//!
//! The network both carry is one (`network.rs`): the devices' ZDO and description-covered ZCL
//! (`device.rs`), the joins the model decides and the answers it gives, and what the dashboard
//! injects. Only the host link differs.
//!
//! This is the host-to-co-processor link, not Zigbee over the air: there is no radio and no
//! 802.15.4, NWK or APS security. Every frame a device sends is built from its description or
//! the model's answer.
pub mod actions;
pub mod ash;
pub mod device;
pub mod ezsp;
pub mod legacy;
pub mod mt;
pub mod ncp;
pub mod network;
pub mod znp;
pub mod zstack;

use crate::llm::action_helper::call_llm;
use crate::llm::actions::protocol_trait::ActionResult;
use crate::logging::emit::Log;
use crate::protocol::{Event, SpawnContext};
use crate::server::accept_bounded::{accept_bounded, ConnectionLimiter};
use crate::server::connection::ConnectionId;
use crate::state::client_handles::ClientCommand;
use crate::state::server::{ConnectionState, ConnectionStatus, ProtocolConnectionInfo};
use crate::utils::wire_failure::WireFailure;
use anyhow::{bail, ensure, Context, Result};
use device::{Device, ZclRequest};
use ezsp::ApsFrame;
use ncp::{Callback, Effect, Nvram, Ram};
use network::{Net, Up, View};
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
/// The longest frame either dialect accepts: an ASH frame unstuffed (223 bytes) or a whole
/// MT frame (255). Nothing longer is buffered or executed.
pub const MAX_INBOUND_FRAME: usize = if mt::MAX_FRAME > ash::MAX_FRAME {
    mt::MAX_FRAME
} else {
    ash::MAX_FRAME
};
/// Bytes read from the socket at a time.
pub const READ_CHUNK: usize = 1024;

/// Which firmware the co-processor runs, and so which host dialect it speaks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dialect {
    /// Silicon Labs EmberZNet: EZSP over ASH.
    Ezsp,
    /// TI Z-Stack 3.x.0: the MT API (ZNP).
    Znp,
}

impl Dialect {
    pub fn name(self) -> &'static str {
        match self {
            Dialect::Ezsp => "ezsp",
            Dialect::Znp => "znp",
        }
    }
}

/// What the server was started with.
#[derive(Clone, Debug)]
pub struct Settings {
    pub dialect: Dialect,
    /// The EZSP version (EZSP dialect only).
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
    let dialect = match params
        .map(|p| p.get_optional_string("dialect"))
        .transpose()?
        .flatten()
        .as_deref()
        .map(str::trim)
    {
        None | Some("ezsp") => Dialect::Ezsp,
        Some("znp") => Dialect::Znp,
        Some(other) => bail!("dialect is ezsp or znp, not {other:?}"),
    };
    let version = params
        .map(|p| p.get_optional_u64("ezsp_version"))
        .transpose()?
        .flatten();
    ensure!(
        dialect == Dialect::Ezsp || version.is_none(),
        "ezsp_version belongs to the EZSP dialect; a Z-Stack co-processor (dialect znp) speaks MT"
    );
    let version = version.unwrap_or(ezsp::DEFAULT_VERSION as u64);
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
    let default_eui = match dialect {
        Dialect::Ezsp => ncp::DEFAULT_EUI64,
        Dialect::Znp => znp::DEFAULT_EUI64,
    };
    let eui64 = match params
        .map(|p| p.get_optional_string("ieee"))
        .transpose()?
        .flatten()
    {
        Some(s) => device::parse_eui(&s)?,
        None => default_eui,
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
            dialect,
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
    /// Z-Stack's NV items (ZNP dialect). Locked on its own, never while `nv` is held.
    pub flash: Mutex<znp::Flash>,
    /// One model question at a time.
    pub gate: tokio::sync::Mutex<()>,
    pub in_flight: AtomicUsize,
}

impl Shared {
    pub fn nv(&self) -> std::sync::MutexGuard<'_, Nvram> {
        self.nv.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn flash(&self) -> std::sync::MutexGuard<'_, znp::Flash> {
        self.flash.lock().unwrap_or_else(|e| e.into_inner())
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
    let flash = znp::Flash::initial(&nv);
    let listener = tokio::net::TcpListener::bind(ctx.legacy_listen_addr())
        .await
        .with_context(|| format!("binding {}", ctx.legacy_listen_addr()))?;
    let local = listener.local_addr()?;
    let banner = match settings.dialect {
        Dialect::Ezsp => format!("Zigbee EZSP v{} co-processor on {local}", settings.version),
        Dialect::Znp => format!(
            "Zigbee Z-Stack {} (MT) co-processor on {local}",
            znp::FIRMWARE_NAME
        ),
    };
    let shared = Arc::new(Shared {
        ctx: Arc::new(ctx.clone()),
        settings,
        nv: Mutex::new(nv),
        flash: Mutex::new(flash),
        gate: tokio::sync::Mutex::new(()),
        in_flight: AtomicUsize::new(0),
    });
    Log::new(Some(&ctx.status_tx)).info(banner);
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
        // Neither ASH nor MT has a frame that says "busy": a second host is closed without a
        // word.
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
                    protocol_info: ProtocolConnectionInfo::new(
                        json!({"role": "host", "dialect": shared.settings.dialect.name()}),
                    ),
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
                let result = match child.settings.dialect {
                    Dialect::Ezsp => {
                        let mut s = Session::new(child.clone(), id, tx);
                        let r = s.run(stream, rx, commands).await;
                        s.closed();
                        r
                    }
                    Dialect::Znp => {
                        let mut s = zstack::Session::new(child.clone(), id, tx);
                        let r = s.run(stream, rx, commands).await;
                        s.closed();
                        r
                    }
                };
                if let Err(e) = result {
                    Log::new(Some(&child.ctx.status_tx))
                        .debug(format!("Zigbee host connection {id}: {e:#}"));
                }
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
pub enum Deferred {
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
pub(crate) async fn ask(
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

/// An `Up` as EZSP carries it.
pub fn ezsp_callback(up: Up) -> Callback {
    match up {
        Up::Incoming {
            broadcast,
            aps,
            nwk,
            ieee,
            payload,
        } => ncp::incoming_message(
            if broadcast {
                ncp::incoming::BROADCAST
            } else {
                ncp::incoming::UNICAST
            },
            &aps,
            nwk,
            ieee,
            &payload,
        ),
        Up::Child {
            index,
            joining,
            nwk,
            ieee,
            node_type,
        } => ncp::child_join(index, joining, nwk, ieee, node_type),
        Up::TrustCenter { nwk, ieee, joined } => {
            if joined {
                ncp::trust_center_join(
                    nwk,
                    ieee,
                    ncp::join::STANDARD_SECURITY_UNSECURED_JOIN,
                    ncp::join::USE_PRECONFIGURED_KEY,
                )
            } else {
                ncp::trust_center_join(nwk, ieee, ncp::join::DEVICE_LEFT, ncp::join::NO_ACTION)
            }
        }
    }
}

/// One host's EZSP session with the co-processor.
struct Session {
    net: Net,
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
    out: Vec<u8>,
}

impl Session {
    fn new(shared: Arc<Shared>, id: ConnectionId, deferred: mpsc::Sender<Deferred>) -> Self {
        Self {
            net: Net::new(shared, id, deferred),
            link: ash::Link::new(),
            deframer: ash::Deframer::new(),
            ram: Ram::new(),
            last_sequence: 0,
            pending: VecDeque::new(),
            overflowed: false,
            permit_until: None,
            census: BTreeMap::new(),
            out: Vec::new(),
        }
    }

    fn shared(&self) -> &Arc<Shared> {
        &self.net.shared
    }

    /// The EZSP version in use: the negotiated one, else the co-processor's own.
    fn version(&self) -> u8 {
        self.ram.version.unwrap_or(self.net.shared.settings.version)
    }

    fn log(&self) -> Log<'_> {
        Log::new(Some(&self.net.shared.ctx.status_tx))
    }

    /// What the network needs to know about this host link.
    fn view(&self) -> View {
        let endpoints: Vec<device::Endpoint> = self.ram.coordinator_endpoints();
        View {
            up: self.ram.up,
            permit_open: self.ram.permit_secs > 0,
            host_endpoint: View::host_endpoint_of(&endpoints),
            max_children: ncp::max_children(&self.ram),
            endpoints,
            manufacturer_code: self.ram.manufacturer_code,
        }
    }

    /// Queue what the network said, as EZSP callbacks.
    fn flush_net(&mut self) {
        for up in self.net.drain() {
            self.queue(ezsp_callback(up));
        }
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
                    let (server_id, id) = (self.shared().ctx.server_id, self.net.id);
                    self.shared()
                        .ctx
                        .state
                        .update_connection_stats(server_id, id, Some(n as u64), None, Some(1), None)
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
                    let view = self.view();
                    self.net.apply_deferred(&view, d);
                    self.flush_net();
                }
                Some(c) = commands.recv() => {
                    let view = self.view();
                    self.net.injected(&view, c).await;
                    self.flush_net();
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
                            self.net.id,
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
                let (server_id, id) = (self.shared().ctx.server_id, self.net.id);
                self.shared()
                    .ctx
                    .state
                    .update_connection_stats(
                        server_id,
                        id,
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
            .map(|(id, n)| match legacy::name(self.version(), *id) {
                Some(name) => format!("{name}×{n}"),
                None => format!("unknown 0x{id:04x}×{n}"),
            })
            .collect();
        let c = self.link.counters;
        self.log().info(format!(
            "Zigbee host connection {} closed; EZSP v{} commands: {}; ASH rx_data={} bad_crc={} too_long={} corrupt={} out_of_sequence={} tx_data={} retransmits={} naks={}",
            self.net.id,
            self.ram.version.unwrap_or(0),
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
                self.net.id,
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
                self.net.id
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
        let v = self.version();
        while let Some(cb) = self.pending.pop_front() {
            let cb = legacy::callback(v, cb);
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
                let refusal = ezsp::invalid_command(&cmd, status);
                let v = self.version();
                self.respond(legacy::downgrade_frame(v, &cmd, &refusal));
                return;
            }
        };
        *self.census.entry(cmd.frame_id).or_insert(0) += 1;
        self.last_sequence = cmd.sequence;
        let handled = {
            let v = self.version();
            let mut nv = self.net.shared.nv();
            legacy::handle(v, &mut self.ram, &mut nv, &cmd)
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
                self.net.ask_permit(secs).await;
            }
            Effect::Formed => {
                let nv = self.net.shared.nv();
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
                self.net.leave(ieee);
                for up in self.net.drain() {
                    self.pending.push_back(ezsp_callback(up));
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
                    self.net.broadcast_zdo(&aps, &message);
                    self.flush_net();
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
        let known = nwk == ncp::COORDINATOR_NWK || {
            let nv = self.net.shared.nv();
            nv.joined_by_nwk(nwk).is_some()
        };
        if !known || (nwk != ncp::COORDINATOR_NWK && message_type != ncp::outgoing::DIRECT) {
            self.queue(sent(ezsp::sl::ZIGBEE_DELIVERY_FAILED));
            return;
        }
        // The device's APS layer acknowledges first; its answer follows.
        self.queue(sent(ezsp::sl::OK));
        let view = self.view();
        self.net.unicast(&view, nwk, aps, &message).await;
        self.flush_net();
    }
}
