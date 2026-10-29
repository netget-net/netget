//! NVMe over TCP target (NVMe/TCP Transport Specification 1.0, NVMe over Fabrics, NVMe Base).
//! Rust owns the wire — PDU framing, digests and alignment, ICReq/ICResp, Connect and the
//! dynamic controller model, properties, the admin commands, R2T and H2CData, C2HData, the
//! NVM Read/Write/Flush/Write Zeroes/Dataset Management commands and the discovery
//! controller; the model decides which subsystems the discovery log lists, which hosts may
//! connect to which subsystem, and what each namespace contains. It is asked at admission (the
//! admin queue Connect), never per I/O command.
//!
//! Every TCP connection is one queue. The admin queue's Connect creates a controller (an
//! association); each I/O queue's Connect names that controller's CNTLID and joins it. A
//! controller lives as long as its admin queue: when that closes, or the host's keep-alive
//! timeout passes with no command, the controller and every I/O queue of it go, with the
//! writes it held.
pub mod actions;
pub mod auth;
pub mod ffdhe;
pub mod ns;
pub mod nvme;
pub mod pdu;
pub mod resv;
mod target_auth;
#[cfg(unix)]
pub mod tls;
pub mod tls_psk;
mod target_io;

use crate::llm::action_helper::call_llm;
use crate::llm::actions::protocol_trait::ActionResult;
use crate::logging::emit::Log;
use crate::protocol::{Event, SpawnContext};
use crate::server::accept_bounded::{accept_bounded, ConnectionLimiter, DEFAULT_MAX_CONNECTIONS};
use crate::server::connection::ConnectionId;
use crate::state::server::{ConnectionState, ConnectionStatus, ProtocolConnectionInfo};
use crate::utils::clock::Instant;
use crate::utils::wire_failure::WireFailure;
use anyhow::{Context, Result};
use ns::{Overlay, SubsystemDescription};
use nvme::{
    admin, cns, fctype, feature, io, log, prop, sgl, ConnectRequest, Cqe, DiscoveryEntry, Sqe,
    Status,
};
use pdu::{fes, flag, kind, Digests, Fatal, Limits, Pdu, ReadError};
use serde_json::json;
use std::collections::{BTreeSet, HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::watch;

/// The ICReq must arrive within this long of the connection opening.
pub const IC_DEADLINE: Duration = Duration::from_secs(30);
/// The first command (a Connect) must arrive within this long of the ICResp.
pub const CONNECT_DEADLINE: Duration = Duration::from_secs(30);
/// The rest of any PDU once its first byte has arrived.
pub const PDU_DEADLINE: Duration = Duration::from_secs(60);
/// MAXH2CDATA: the most data one H2CData PDU may carry.
pub const MAX_H2C_DATA: usize = 128 * 1024;
/// In-capsule data a CapsuleCmd may carry, on the admin queue and on I/O queues.
pub const IN_CAPSULE_DATA: usize = 8192;
/// Identify's IOCCSZ: the 64-byte command plus the in-capsule data, in 16-byte units.
pub const IOCCSZ: u32 = ((64 + IN_CAPSULE_DATA) / 16) as u32;
/// MDTS as Identify reports it: 2^8 × the 4 KiB minimum page size.
pub const MDTS: u8 = 8;
/// The most data one command moves in either direction (MDTS).
pub const MAX_TRANSFER: usize = 4096 << MDTS;
/// C2HData PDUs carry at most this much each.
pub const C2H_CHUNK: usize = 128 * 1024;
/// CAP.MQES: the largest SQSIZE (0's based) an I/O queue may have; the admin queue too.
pub const MQES: u16 = 127;
/// The smallest admin queue (0's based): 32 entries.
pub const MIN_ADMIN_SQSIZE: u16 = 31;
/// I/O queues a controller grants.
pub const MAX_IO_QUEUES: u16 = 8;
/// Controllers (associations) the target holds at once.
pub const MAX_CONTROLLERS: usize = 64;
/// AERL (0's based): Asynchronous Event Requests a controller holds.
pub const AERL: u8 = 3;
/// Commands per queue with an R2T open at once; the rest wait their turn.
pub const MAX_OPEN_R2T: usize = 4;
/// What a keep-alive timeout is given past KATO before the controller is torn down.
pub const KEEP_ALIVE_GRACE: Duration = Duration::from_secs(2);
/// The longest KATO honoured, so a timer never overflows.
pub const MAX_KATO_MS: u32 = 3_600_000;
/// The default for the `digests` startup parameter.
pub const DEFAULT_DIGESTS: &str = "either";
/// Keep Alive granularity (KAS), in 100 ms units.
pub const KAS: u16 = 10;
/// The port group every portal of this target belongs to.
pub const PORT_ID: u16 = 1;
/// A queue the model required to authenticate must finish within this long of its Connect.
pub const AUTH_DEADLINE: Duration = Duration::from_secs(30);
/// AUTH_Negotiate messages one queue may send (each challenge costs a Diffie-Hellman
/// exponentiation); past this, negotiations fail without one.
pub const MAX_AUTH_ATTEMPTS: u8 = 4;
/// The DH-HMAC-CHAP hashes and groups this target prefers, in order, when the startup
/// parameters name none: the first the host offers is used.
pub const DEFAULT_DHCHAP_HASHES: &str = "sha256,sha384,sha512";
pub const DEFAULT_DHCHAP_DHGROUPS: &str = "ffdhe2048,ffdhe3072,ffdhe4096,ffdhe6144,ffdhe8192,null";
/// Namespaces (of live subsystems) holding a reservation table at once.
pub const MAX_RESERVATION_TABLES: usize = 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DigestPolicy {
    /// Enable whichever digests the host asks for.
    Either,
    /// Require both: a host that does not ask for them is refused.
    Crc32c,
    /// Enable neither.
    None,
}

impl DigestPolicy {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "either" => Some(Self::Either),
            "crc32c" => Some(Self::Crc32c),
            "none" => Some(Self::None),
            _ => None,
        }
    }
}

/// DH-HMAC-CHAP as the operator configured it: the secrets never leave this struct (its
/// `Debug` redacts them), and the model only ever learns that authentication is available.
#[derive(Debug, Clone)]
pub struct AuthConfig {
    /// The host secret every host the model requires to authenticate must prove.
    pub host_secret: auth::Secret,
    /// The controller secret, for a host that asks the controller to prove itself.
    pub ctrl_secret: Option<auth::Secret>,
    pub hashes: Vec<auth::Hash>,
    pub groups: Vec<auth::DhGroup>,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub digests: DigestPolicy,
    /// The NVMe/TCP port discovery entries point at when the model names no address.
    pub io_port: u16,
    pub auth: Option<Arc<AuthConfig>>,
    /// The configured PSK every connection must open a TLS 1.3 secure channel with, when set;
    /// the discovery log then says TLS is required.
    pub tls_key: Option<tls_psk::ConfiguredKey>,
}

pub fn parse_config(ctx: &SpawnContext) -> Result<(Config, Option<u16>)> {
    let mut digests = DigestPolicy::Either;
    let mut discovery_port = None;
    let mut auth = None;
    let mut tls_key = None;
    if let Some(params) = ctx.startup_params.as_ref() {
        if let Some(text) = params.get_optional_string("tls_key")? {
            tls_key = Some(
                tls_psk::ConfiguredKey::parse(&text).map_err(|e| anyhow::anyhow!("tls_key: {e}"))?,
            );
        }
        if let Some(d) = params.get_optional_string("digests")? {
            digests = DigestPolicy::parse(&d).context("digests is either, crc32c or none")?;
        }
        if let Some(p) = params.get_optional_u64("discovery_port")? {
            discovery_port =
                Some(u16::try_from(p).context("discovery_port is a port number (0-65535)")?);
        }
        let secret = |name: &str| -> Result<Option<auth::Secret>> {
            match params.get_optional_string(name)? {
                None => Ok(None),
                Some(s) => auth::Secret::parse(&s)
                    .map(Some)
                    .map_err(|e| anyhow::anyhow!("{name}: {e}")),
            }
        };
        let host_secret = secret("dhchap_secret")?;
        let ctrl_secret = secret("dhchap_ctrl_secret")?;
        let hashes = params
            .get_optional_string("dhchap_hashes")?
            .unwrap_or_else(|| DEFAULT_DHCHAP_HASHES.into());
        let hashes = auth::parse_list(&hashes, auth::Hash::parse)
            .context("dhchap_hashes is a list of sha256, sha384 and sha512")?;
        let groups = params
            .get_optional_string("dhchap_dhgroups")?
            .unwrap_or_else(|| DEFAULT_DHCHAP_DHGROUPS.into());
        let groups = auth::parse_list(&groups, auth::DhGroup::parse).context(
            "dhchap_dhgroups is a list of null, ffdhe2048, ffdhe3072, ffdhe4096, ffdhe6144 and \
             ffdhe8192",
        )?;
        auth = match (host_secret, ctrl_secret) {
            (Some(host_secret), ctrl_secret) => Some(Arc::new(AuthConfig {
                host_secret,
                ctrl_secret,
                hashes,
                groups,
            })),
            (None, Some(_)) => anyhow::bail!(
                "dhchap_ctrl_secret needs dhchap_secret: the controller proves itself only to a \
                 host that has proved itself"
            ),
            (None, None) => None,
        };
    }
    Ok((
        Config {
            digests,
            io_port: 0,
            auth,
            tls_key,
        },
        discovery_port,
    ))
}

/// Shared by every connection of the server: the configuration and the controllers.
pub struct Target {
    pub config: Config,
    controllers: Mutex<Controllers>,
    /// Reservation tables by (subsystem NQN, NSID), shared by every controller of the
    /// subsystem and dropped with the last of them.
    reservations: Mutex<HashMap<(String, u32), resv::Table>>,
}

#[derive(Default)]
struct Controllers {
    map: HashMap<u16, Arc<Controller>>,
    next: u16,
}

/// The epoch value a controller's watch takes when it is gone.
const DEAD: u64 = u64::MAX;

/// SMART counters.
#[derive(Default, Clone, Copy)]
struct Stats {
    bytes_read: u64,
    bytes_written: u64,
    reads: u64,
    writes: u64,
    media_errors: u64,
}

struct CtrlState {
    cc: u32,
    csts: u32,
    kato_ms: u32,
    queues_granted: Option<u16>,
    io_qids: BTreeSet<u16>,
    aec: u32,
    write_cache: bool,
    last_command: Instant,
    stats: Stats,
    discovery: Option<Vec<DiscoveryEntry>>,
    epoch: u64,
}

/// A controller: what one admin queue Connect created.
pub struct Controller {
    pub cntlid: u16,
    pub discovery: bool,
    pub subnqn: String,
    pub hostnqn: String,
    pub hostid: [u8; 16],
    pub desc: Option<Arc<SubsystemDescription>>,
    /// The model required this host to authenticate before it may use the controller.
    pub auth_required: bool,
    state: Mutex<CtrlState>,
    overlay: Mutex<Overlay>,
    epoch: watch::Sender<u64>,
    created: Instant,
}

impl Controller {
    fn state(&self) -> std::sync::MutexGuard<'_, CtrlState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
    fn overlay(&self) -> std::sync::MutexGuard<'_, Overlay> {
        self.overlay.lock().unwrap_or_else(|e| e.into_inner())
    }
    fn ready(&self) -> bool {
        let s = self.state();
        s.cc & 1 != 0 && s.csts & 1 != 0
    }
    fn touch(&self) {
        self.state().last_command = Instant::now();
    }
    /// When keep-alive expires, if the host asked for it.
    fn keep_alive_deadline(&self) -> Option<Instant> {
        let s = self.state();
        (s.kato_ms > 0).then(|| {
            s.last_command
                + Duration::from_millis(s.kato_ms.min(MAX_KATO_MS) as u64)
                + KEEP_ALIVE_GRACE
        })
    }
}

impl Target {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            controllers: Mutex::new(Controllers {
                map: HashMap::new(),
                next: 1,
            }),
            reservations: Mutex::new(HashMap::new()),
        }
    }

    fn controllers(&self) -> std::sync::MutexGuard<'_, Controllers> {
        self.controllers.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// A new controller with a free CNTLID, or `None` when the target holds its limit.
    fn create(
        &self,
        req: &ConnectRequest,
        subnqn: &str,
        hostnqn: &str,
        desc: Option<Arc<SubsystemDescription>>,
    ) -> Option<Arc<Controller>> {
        let mut c = self.controllers();
        if c.map.len() >= MAX_CONTROLLERS {
            return None;
        }
        let mut id = c.next;
        while id == 0 || id >= 0xFFF0 || c.map.contains_key(&id) {
            id = if id >= 0xFFEF { 1 } else { id + 1 };
        }
        c.next = id + 1;
        let (epoch, _) = watch::channel(0u64);
        let ctrl = Arc::new(Controller {
            cntlid: id,
            discovery: desc.is_none(),
            subnqn: subnqn.to_string(),
            hostnqn: hostnqn.to_string(),
            hostid: req.hostid,
            auth_required: desc.as_ref().is_some_and(|d| d.require_authentication),
            desc,
            state: Mutex::new(CtrlState {
                cc: 0,
                csts: 0,
                kato_ms: req.kato_ms,
                queues_granted: None,
                io_qids: BTreeSet::new(),
                aec: 0,
                write_cache: true,
                last_command: Instant::now(),
                stats: Stats::default(),
                discovery: None,
                epoch: 0,
            }),
            overlay: Mutex::new(Overlay::default()),
            epoch,
            created: Instant::now(),
        });
        c.map.insert(id, ctrl.clone());
        Some(ctrl)
    }

    fn find(&self, cntlid: u16) -> Option<Arc<Controller>> {
        self.controllers().map.get(&cntlid).cloned()
    }

    /// End a controller: forget it and tell its I/O queues to close.
    fn destroy(&self, ctrl: &Controller) {
        let last = {
            let mut c = self.controllers();
            c.map.remove(&ctrl.cntlid);
            !c.map.values().any(|o| o.subnqn == ctrl.subnqn)
        };
        if last {
            // No association with the subsystem remains: its reservations go with it, as a
            // target that persists nothing through a power loss would lose them.
            self.reservations()
                .retain(|(nqn, _), _| *nqn != ctrl.subnqn);
        }
        let _ = ctrl.epoch.send(DEAD);
    }

    fn reservations(&self) -> std::sync::MutexGuard<'_, HashMap<(String, u32), resv::Table>> {
        self.reservations.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn controller_count(&self) -> usize {
        self.controllers().map.len()
    }
}

#[cfg(unix)]
type TlsAcceptor = tls::Acceptor;
/// No TLS outside Unix: `tls_key` is refused at startup there, so none is ever built.
#[cfg(not(unix))]
#[derive(Clone)]
enum TlsAcceptor {}

/// How long a host has to complete the TLS handshake: the Linux host's own default
/// (`nvme_tcp.tls_handshake_timeout`, 10 seconds).
pub const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// A connection's byte stream: the TCP socket, or a TLS session over it.
trait Io: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + Sync {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + Sync> Io for T {}

pub async fn spawn(ctx: SpawnContext) -> Result<SocketAddr> {
    let (mut config, discovery_port) = parse_config(&ctx)?;
    let listener = tokio::net::TcpListener::bind(ctx.legacy_listen_addr()).await?;
    let local = listener.local_addr()?;
    config.io_port = local.port();
    let discovery = match discovery_port {
        Some(port) => {
            let addr = SocketAddr::new(ctx.legacy_listen_addr().ip(), port);
            let l = tokio::net::TcpListener::bind(addr)
                .await
                .with_context(|| format!("binding the discovery port {addr}"))?;
            Some(l)
        }
        None => None,
    };
    let tls: Option<TlsAcceptor> = match &config.tls_key {
        None => None,
        #[cfg(unix)]
        Some(key) => Some(
            tls::Acceptor::new(key.clone()).context("setting up TLS for the configured tls_key")?,
        ),
        #[cfg(not(unix))]
        Some(_) => anyhow::bail!("tls_key needs a Unix build: NVMe/TCP TLS is OpenSSL's"),
    };
    let target = Arc::new(Target::new(config));
    let shared = Arc::new(ctx.clone());
    let limiter = ConnectionLimiter::new(DEFAULT_MAX_CONNECTIONS);
    let log = Log::new(Some(&ctx.status_tx));
    log.info(format!("NVMe/TCP target on {local}"));
    for listener in std::iter::once(listener).chain(discovery) {
        if let Ok(a) = listener.local_addr() {
            if a != local {
                log.info(format!("NVMe/TCP discovery port on {a}"));
            }
        }
        let accept = tokio::spawn(accept_loop(
            listener,
            shared.clone(),
            target.clone(),
            limiter.clone(),
            tls.clone(),
        ));
        ctx.state.register_server_task(ctx.server_id, accept).await;
    }
    Ok(local)
}

async fn accept_loop(
    listener: tokio::net::TcpListener,
    shared: Arc<SpawnContext>,
    target: Arc<Target>,
    limiter: ConnectionLimiter,
    tls: Option<TlsAcceptor>,
) {
    let server_id = shared.server_id;
    let Ok(listening) = listener.local_addr() else {
        return;
    };
    loop {
        let (stream, peer, permit) = match accept_bounded(
            &listener,
            &limiter,
            b"",
            "NVMe/TCP",
            Some(&shared.status_tx),
        )
        .await
        {
            Ok(v) => v,
            Err(_) => break,
        };
        let _ = stream.set_nodelay(true);
        let local = stream.local_addr().unwrap_or(listening);
        let id = ConnectionId::new(shared.state.get_next_unified_id().await);
        let now = Instant::now();
        shared
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
                    protocol_info: ProtocolConnectionInfo::empty(),
                },
            )
            .await;
        let child = shared.clone();
        let target = target.clone();
        let tls = tls.clone();
        shared
            .state
            .spawn_server_task(server_id, async move {
                let _permit = permit;
                // With a tls_key the TLS session comes first: the host's first PDU travels
                // inside it. A host that cannot complete it is closed before any NVMe/TCP.
                let (stream, tls_identity): (Box<dyn Io>, Option<tls_psk::Identity>) = match tls
                {
                    None => (Box::new(stream), None),
                    #[cfg(unix)]
                    Some(acceptor) => {
                        match tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, acceptor.accept(stream))
                            .await
                        {
                            Ok(Ok((s, identity))) => {
                                outcome(
                                    &child,
                                    id,
                                    "tls",
                                    "protocol_accept",
                                    &format!("TLS 1.3 secure channel, PSK identity {}", identity.text()),
                                );
                                (Box::new(s), Some(identity))
                            }
                            Ok(Err(e)) => {
                                outcome(&child, id, "tls", "fail_closed_tls", &e.to_string());
                                closed(&child, server_id, id).await;
                                return;
                            }
                            Err(_) => {
                                outcome(
                                    &child,
                                    id,
                                    "tls",
                                    "fail_closed_tls",
                                    &format!(
                                        "no TLS handshake within {} s",
                                        TLS_HANDSHAKE_TIMEOUT.as_secs()
                                    ),
                                );
                                closed(&child, server_id, id).await;
                                return;
                            }
                        }
                    }
                    #[cfg(not(unix))]
                    Some(never) => match never {},
                };
                let mut c = Conn::new(&child, target, id, peer, local, stream, tls_identity);
                if let Err(e) = c.run().await {
                    Log::new(Some(&child.status_tx))
                        .debug(format!("NVMe/TCP connection {id}: {e:#}"));
                }
                // The controller (or this queue's place in it) goes before the host can see the
                // connection close, so a queue reconnecting at once finds its QID free.
                c.finish();
                let _ = c.stream.shutdown().await;
                closed(&child, server_id, id).await;
            })
            .await;
    }
}

async fn closed(ctx: &SpawnContext, server_id: crate::state::ServerId, id: ConnectionId) {
    ctx.state
        .update_connection_status(server_id, id, ConnectionStatus::Closed)
        .await;
    let _ = ctx.status_tx.send("__UPDATE_UI__".into());
}

/// Log how a decision went, in the `decision=` vocabulary every server shares.
fn outcome(ctx: &SpawnContext, id: ConnectionId, operation: &str, decision: &str, detail: &str) {
    let summary =
        format!("NVMe/TCP connection {id} operation={operation} decision={decision} {detail}");
    let log = Log::new(Some(&ctx.status_tx));
    if decision.starts_with("fail_closed_") || decision == "model_silent" {
        log.error(summary);
    } else if decision == "protocol_refusal" {
        log.warn(summary);
    } else {
        log.info(summary);
    }
}

/// An NQN as it may appear in a log line.
fn shown(s: &str) -> String {
    crate::utils::sanitize::token(s, 223)
}

/// What a queue is, once its Connect succeeded.
struct Queue {
    qid: u16,
    sqsize: u16,
    sqflow_disabled: bool,
    ctrl: Arc<Controller>,
    epoch: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PendingKind {
    Connect,
    Write,
    DatasetManagement,
    AuthSend,
    Compare,
    Copy,
    Reservation,
}

/// A command waiting for its data from the host.
struct Pending {
    sqe: Sqe,
    kind: PendingKind,
    expected: usize,
    buf: Vec<u8>,
    /// The R2T outstanding: its tag, offset, length and the bytes of it received.
    r2t: Option<(u16, usize, usize, usize)>,
    /// A data digest failed: the command completes with this once its data is in.
    failed: Option<Status>,
}

/// How a command ended.
enum Done {
    /// Complete it with a status and DW0/DW1.
    Status(Status, u32, u32),
    /// Return this data, then complete it successfully.
    Data(Vec<u8>, u32),
    /// Nothing yet: it waits for data, or is an Asynchronous Event Request held.
    Later,
    /// Complete it successfully, then close the connection.
    Close,
}

fn ok() -> Done {
    Done::Status(Status::SUCCESS, 0, 0)
}

fn err(s: Status) -> Done {
    Done::Status(s, 0, 0)
}

/// Where the data of a host-to-controller command is.
enum Incoming {
    InCapsule(Vec<u8>),
    Solicited,
}

/// The data of a command that sends data to the controller, per its SGL: in the capsule, or to
/// be asked for with R2T. `need` is the length the command implies.
fn incoming(sqe: &Sqe, data: Vec<u8>, need: usize) -> Result<Incoming, Status> {
    let (address, length, kind) = sqe.sgl();
    match kind {
        sgl::IN_CAPSULE => {
            if address != 0 {
                return Err(Status::generic(0x16)); // SGL Offset Invalid
            }
            if length as usize != need || data.len() < need {
                return Err(Status::SGL_LENGTH_INVALID);
            }
            let mut data = data;
            data.truncate(need);
            Ok(Incoming::InCapsule(data))
        }
        sgl::TRANSPORT => {
            if !data.is_empty() {
                return Err(Status::INVALID_FIELD);
            }
            if length as usize != need {
                return Err(Status::SGL_LENGTH_INVALID);
            }
            Ok(Incoming::Solicited)
        }
        _ => Err(Status::SGL_TYPE_INVALID),
    }
}

/// Check the SGL of a command that returns `need` bytes to the host.
fn outgoing(sqe: &Sqe, data: &[u8], need: usize) -> Result<(), Status> {
    let (_, length, kind) = sqe.sgl();
    if !data.is_empty() {
        return Err(Status::INVALID_FIELD);
    }
    if kind != sgl::TRANSPORT {
        return Err(Status::SGL_TYPE_INVALID);
    }
    if length as usize != need {
        return Err(Status::SGL_LENGTH_INVALID);
    }
    Ok(())
}

/// The CAP property this target reports.
pub fn cap() -> u64 {
    MQES as u64
        | 1 << 16 // CQR: contiguous queues required
        | 15 << 24 // TO: 7.5 s
        | 1 << 37 // CSS: the NVM command set
}

struct Conn<'a> {
    ctx: &'a SpawnContext,
    target: Arc<Target>,
    id: ConnectionId,
    peer: SocketAddr,
    local: SocketAddr,
    stream: Box<dyn Io>,
    /// The identity the host proved in the TLS handshake; every Connect on this connection
    /// must name its host and subsystem.
    tls_identity: Option<tls_psk::Identity>,
    digests: Digests,
    /// The host's PDU data alignment (HPDA) for C2HData.
    hpda: u8,
    queue: Option<Queue>,
    /// The submission queue head, advanced by every command taken.
    sqhd: u16,
    pending: HashMap<u16, Pending>,
    /// Commands waiting for an R2T slot, oldest first.
    r2t_wait: VecDeque<u16>,
    /// Asynchronous Event Requests held.
    aers: Vec<u16>,
    next_ttag: u16,
    epoch_rx: Option<watch::Receiver<u64>>,
    /// DH-HMAC-CHAP on this queue: where the exchange stands, whether it succeeded, by when
    /// it must, and how many negotiations it has started.
    auth: target_auth::AuthState,
    authenticated: bool,
    auth_by: Option<Instant>,
    auth_attempts: u8,
    /// Commands this queue received, by name (at most a few dozen names exist), logged when
    /// the queue ends.
    received: std::collections::BTreeMap<String, u64>,
}

impl<'a> Conn<'a> {
    fn new(
        ctx: &'a SpawnContext,
        target: Arc<Target>,
        id: ConnectionId,
        peer: SocketAddr,
        local: SocketAddr,
        stream: Box<dyn Io>,
        tls_identity: Option<tls_psk::Identity>,
    ) -> Self {
        Self {
            ctx,
            target,
            id,
            peer,
            local,
            stream,
            tls_identity,
            digests: Digests::default(),
            hpda: 0,
            queue: None,
            sqhd: 0,
            pending: HashMap::new(),
            r2t_wait: VecDeque::new(),
            aers: Vec::new(),
            next_ttag: 0,
            epoch_rx: None,
            auth: target_auth::AuthState::None,
            authenticated: false,
            auth_by: None,
            auth_attempts: 0,
            received: std::collections::BTreeMap::new(),
        }
    }

    fn limits(&self) -> Limits {
        Limits {
            accepted: Limits::types(&[kind::CAPSULE_CMD, kind::H2C_DATA, kind::H2C_TERM_REQ]),
            digests: self.digests,
            max_capsule_data: IN_CAPSULE_DATA,
            max_data_pdu: MAX_H2C_DATA,
        }
    }

    async fn send(&mut self, p: &Pdu) -> Result<()> {
        let bytes = p.encode(self.digests, self.hpda);
        self.stream.write_all(&bytes).await?;
        self.ctx
            .state
            .update_connection_stats(
                self.ctx.server_id,
                self.id,
                None,
                Some(bytes.len() as u64),
                None,
                Some(1),
            )
            .await;
        Ok(())
    }

    async fn received(&self, p: &Pdu) {
        self.ctx
            .state
            .update_connection_stats(
                self.ctx.server_id,
                self.id,
                Some((p.header.len() + p.data.len()) as u64),
                None,
                Some(1),
                None,
            )
            .await;
    }

    /// A fatal transport error: C2HTermReq, logged, and the connection closes.
    async fn terminate(&mut self, e: &Fatal, offending: &[u8]) {
        outcome(
            self.ctx,
            self.id,
            "pdu",
            "protocol_refusal",
            &format!("{} ({}); C2HTermReq sent", e.reason, fes::name(e.fes)),
        );
        let term = pdu::term_req(kind::C2H_TERM_REQ, e, offending);
        let _ = self.send(&term).await;
    }

    /// ICReq → ICResp. `Ok(false)`: refused and closed.
    async fn initialize(&mut self) -> Result<bool> {
        let limits = Limits {
            accepted: Limits::types(&[kind::IC_REQ]),
            digests: Digests::default(),
            max_capsule_data: 0,
            max_data_pdu: 0,
        };
        let req = match tokio::time::timeout(
            IC_DEADLINE,
            pdu::read_pdu(&mut self.stream, &limits, PDU_DEADLINE),
        )
        .await
        {
            Err(_) => {
                outcome(
                    self.ctx,
                    self.id,
                    "icreq",
                    "protocol_refusal",
                    "no ICReq within 30 s",
                );
                return Ok(false);
            }
            Ok(Err(ReadError::Fatal(e, header))) => {
                self.terminate(&e, &header).await;
                return Ok(false);
            }
            Ok(Err(ReadError::Closed)) => return Ok(false),
            Ok(Err(e)) => {
                outcome(
                    self.ctx,
                    self.id,
                    "icreq",
                    "protocol_refusal",
                    &e.to_string(),
                );
                return Ok(false);
            }
            Ok(Ok(p)) => p,
        };
        self.received(&req).await;
        let pfv = req.u16_at(8);
        let hpda = req.u8_at(10);
        let dgst = req.u8_at(11);
        let maxr2t = req.u32_at(12);
        let refuse = |fei: u32, reason: String| Fatal {
            fes: fes::UNSUPPORTED_PARAMETER,
            fei,
            reason,
        };
        let refusal = if pfv != 0 {
            Some(refuse(8, format!("ICReq PFV {pfv} (only 0 is defined)")))
        } else if hpda > 31 {
            Some(refuse(10, format!("ICReq HPDA {hpda} (0 to 31)")))
        } else {
            None
        };
        let (want_h, want_d) = (dgst & 1 != 0, dgst & 2 != 0);
        let digests = match self.target.config.digests {
            DigestPolicy::Either => Digests {
                header: want_h,
                data: want_d,
            },
            DigestPolicy::None => Digests::default(),
            DigestPolicy::Crc32c => Digests {
                header: true,
                data: true,
            },
        };
        let refusal = refusal.or_else(|| {
            (self.target.config.digests == DigestPolicy::Crc32c && !(want_h && want_d)).then(|| {
                refuse(
                    11,
                    "the host did not ask for header and data digests, which this target \
                         requires"
                        .into(),
                )
            })
        });
        if let Some(e) = refusal {
            let header = req.header.clone();
            self.terminate(&e, &header).await;
            return Ok(false);
        }
        self.hpda = hpda;
        let mut resp = Pdu::new(kind::IC_RESP);
        resp.set_u16(8, 0); // PFV
        resp.header[10] = 0; // CPDA: no alignment asked of the host
        resp.header[11] = digests.header as u8 | (digests.data as u8) << 1;
        resp.set_u32(12, MAX_H2C_DATA as u32);
        // ICResp itself carries no digest.
        let bytes = resp.encode(Digests::default(), 0);
        self.stream.write_all(&bytes).await?;
        self.digests = digests;
        outcome(
            self.ctx,
            self.id,
            "icreq",
            "protocol_accept",
            &format!(
                "HPDA {hpda}, MAXR2T {maxr2t}, header digest {}, data digest {}",
                digests.header, digests.data
            ),
        );
        Ok(true)
    }

    async fn run(&mut self) -> Result<()> {
        if !self.initialize().await? {
            return Ok(());
        }
        let connect_by = Instant::now() + CONNECT_DEADLINE;
        loop {
            let deadline = match &self.queue {
                None => Some(connect_by),
                Some(q) if q.qid == 0 => match (q.ctrl.keep_alive_deadline(), self.auth_by) {
                    (Some(a), Some(b)) => Some(a.min(b)),
                    (a, b) => a.or(b),
                },
                Some(_) => None,
            };
            let (admin, epoch) = self
                .queue
                .as_ref()
                .map_or((true, 0), |q| (q.qid == 0, q.epoch));
            let mut first = [0u8; 1];
            tokio::select! {
                r = self.stream.read(&mut first) => match r {
                    Ok(0) => return Ok(()),
                    Ok(_) => {}
                    Err(e) => return Err(e.into()),
                },
                _ = ended(&mut self.epoch_rx, epoch, admin) => {
                    outcome(self.ctx, self.id, "queue", "protocol_refusal",
                        "the controller this queue belongs to ended (its admin queue closed, keep-alive expired, or it was reset)");
                    return Ok(());
                }
                _ = sleep_until(deadline) => {
                    match &self.queue {
                        None => {
                            outcome(self.ctx, self.id, "connect", "protocol_refusal", "no Connect within 30 s of the ICResp");
                            return Ok(());
                        }
                        Some(_) if self.auth_by.is_some_and(|d| d <= Instant::now()) => {
                            outcome(self.ctx, self.id, "authenticate", "protocol_refusal",
                                &format!("the host did not authenticate within {} s of its Connect", AUTH_DEADLINE.as_secs()));
                            return Ok(());
                        }
                        Some(q) => {
                            let expired = q.ctrl.keep_alive_deadline().is_some_and(|d| d <= Instant::now());
                            if expired {
                                outcome(self.ctx, self.id, "keep_alive", "protocol_refusal",
                                    &format!("controller {} saw no command within its keep-alive timeout; it and its queues end", q.ctrl.cntlid));
                                return Ok(());
                            }
                            continue;
                        }
                    }
                }
            }
            let limits = self.limits();
            let p = match pdu::read_rest(&mut self.stream, first[0], &limits, PDU_DEADLINE).await {
                Ok(p) => p,
                Err(ReadError::Fatal(e, header)) => {
                    self.terminate(&e, &header).await;
                    return Ok(());
                }
                Err(ReadError::DataDigest(p)) => {
                    self.received(&p).await;
                    outcome(
                        self.ctx,
                        self.id,
                        "pdu",
                        "protocol_refusal",
                        &format!(
                            "data digest mismatch on a {}; the command fails with TRANSIENT TRANSPORT ERROR",
                            kind::name(p.kind())
                        ),
                    );
                    if !self.data_digest_failed(*p).await? {
                        return Ok(());
                    }
                    continue;
                }
                Err(ReadError::Stalled) => {
                    outcome(
                        self.ctx,
                        self.id,
                        "pdu",
                        "protocol_refusal",
                        "a PDU stalled part-way for 60 s",
                    );
                    return Ok(());
                }
                Err(ReadError::Closed) => return Ok(()),
                Err(ReadError::Io(e)) => return Err(e.into()),
            };
            self.received(&p).await;
            let go_on = match p.kind() {
                kind::CAPSULE_CMD => self.capsule(p).await?,
                kind::H2C_DATA => self.h2c_data(p).await?,
                _ => {
                    // H2CTermReq: the host is ending the connection.
                    outcome(
                        self.ctx,
                        self.id,
                        "pdu",
                        "protocol_refusal",
                        &format!(
                            "the host sent H2CTermReq: {} (FEI {})",
                            fes::name(p.u16_at(8)),
                            p.u32_at(10)
                        ),
                    );
                    false
                }
            };
            if !go_on {
                return Ok(());
            }
        }
    }

    /// The connection is over: an admin queue takes its controller with it.
    fn finish(&mut self) {
        if !self.received.is_empty() {
            let list: Vec<String> = self
                .received
                .iter()
                .map(|(name, n)| format!("{name} x{n}"))
                .collect();
            outcome(
                self.ctx,
                self.id,
                "commands",
                "protocol_accept",
                &format!(
                    "{} received: {}",
                    self.queue
                        .as_ref()
                        .map_or("an unconnected queue".to_string(), |q| format!(
                            "queue {} of controller {}",
                            q.qid, q.ctrl.cntlid
                        )),
                    list.join(", ")
                ),
            );
        }
        let Some(q) = self.queue.take() else {
            return;
        };
        if q.qid == 0 {
            self.target.destroy(&q.ctrl);
            outcome(
                self.ctx,
                self.id,
                "disconnect",
                "protocol_accept",
                &format!(
                    "controller {} ended; {} bytes of writes discarded",
                    q.ctrl.cntlid,
                    q.ctrl.overlay().bytes()
                ),
            );
        } else {
            let mut s = q.ctrl.state();
            if s.epoch == q.epoch {
                s.io_qids.remove(&q.qid);
            }
        }
    }

    // ------------------------------------------------------------- completions

    async fn complete(&mut self, cid: u16, status: Status, dw0: u32, dw1: u32) -> Result<()> {
        let (sqid, sqhd) = match &self.queue {
            Some(q) if q.sqflow_disabled => (q.qid, 0xFFFF),
            Some(q) => (q.qid, self.sqhd),
            None => (0, self.sqhd),
        };
        let cqe = Cqe {
            dw0,
            dw1,
            sqhd,
            sqid,
            cid,
            status: status.field(),
        };
        let mut p = Pdu::new(kind::CAPSULE_RESP);
        p.header[8..24].copy_from_slice(&cqe.encode());
        self.send(&p).await
    }

    /// Return data in C2HData PDUs; with SQ flow control disabled the last carries SUCCESS and
    /// no completion follows.
    async fn send_data(&mut self, cid: u16, data: &[u8], dw0: u32) -> Result<()> {
        let success_flag = self.queue.as_ref().is_some_and(|q| q.sqflow_disabled) && dw0 == 0;
        let chunks: Vec<&[u8]> = if data.is_empty() {
            vec![]
        } else {
            data.chunks(C2H_CHUNK).collect()
        };
        let n = chunks.len();
        for (i, chunk) in chunks.into_iter().enumerate() {
            let mut p = Pdu::new(kind::C2H_DATA);
            p.set_u16(8, cid);
            p.set_u32(12, (i * C2H_CHUNK) as u32);
            p.set_u32(16, chunk.len() as u32);
            if i + 1 == n {
                p.set_flags(if success_flag {
                    flag::LAST_PDU | flag::SUCCESS
                } else {
                    flag::LAST_PDU
                });
            }
            p.data = chunk.to_vec();
            self.send(&p).await?;
        }
        if !(success_flag && n > 0) {
            self.complete(cid, Status::SUCCESS, dw0, 0).await?;
        }
        Ok(())
    }

    async fn finish_command(&mut self, cid: u16, done: Done) -> Result<bool> {
        match done {
            Done::Status(s, dw0, dw1) => {
                self.complete(cid, s, dw0, dw1).await?;
                Ok(true)
            }
            Done::Data(d, dw0) => {
                self.send_data(cid, &d, dw0).await?;
                Ok(true)
            }
            Done::Later => Ok(true),
            Done::Close => {
                self.complete(cid, Status::SUCCESS, 0, 0).await?;
                Ok(false)
            }
        }
    }

    // ---------------------------------------------------------------- capsules

    async fn capsule(&mut self, p: Pdu) -> Result<bool> {
        let sqe = Sqe(p.header[8..72].try_into().expect("64 bytes"));
        let cid = sqe.cid();
        let admin_queue = self.queue.as_ref().is_none_or(|q| q.qid == 0);
        *self
            .received
            .entry(nvme::command_name(admin_queue, &sqe))
            .or_default() += 1;
        let data = p.data;
        // The command takes a submission queue slot.
        let size = self.queue.as_ref().map_or(u16::MAX, |q| q.sqsize);
        self.sqhd = if size == u16::MAX {
            self.sqhd.wrapping_add(1)
        } else {
            (self.sqhd + 1) % (size + 1)
        };
        if let Some(q) = &self.queue {
            q.ctrl.touch();
            let outstanding = self.pending.len() + self.aers.len();
            if outstanding > q.sqsize as usize {
                let e = Fatal {
                    fes: fes::PDU_SEQUENCE_ERROR,
                    fei: 0,
                    reason: format!(
                        "a command beyond the queue's {} entries while {outstanding} are outstanding",
                        q.sqsize as usize + 1
                    ),
                };
                let header = p.header.clone();
                self.terminate(&e, &header).await;
                return Ok(false);
            }
        }
        // A held Asynchronous Event Request whose CID comes back has been given up by the host:
        // SPDK, shutting a controller down, completes its AERs itself and reuses their CIDs for
        // the Property Get/Set that follow. Forget the AER and run the command.
        if let Some(i) = self.aers.iter().position(|a| *a == cid) {
            self.aers.swap_remove(i);
            outcome(
                self.ctx,
                self.id,
                "command",
                "protocol_accept",
                &format!(
                    "command ID {cid} reused: the Asynchronous Event Request it named is dropped"
                ),
            );
        }
        if self.pending.contains_key(&cid) {
            outcome(
                self.ctx,
                self.id,
                "command",
                "protocol_refusal",
                &format!("command ID {cid} is already outstanding"),
            );
            self.complete(cid, Status::CID_CONFLICT, 0, 0).await?;
            return Ok(true);
        }
        let done = if self.queue.is_none() {
            if sqe.opcode() == admin::FABRICS && sqe.fctype() == fctype::CONNECT {
                match incoming(&sqe, data, nvme::CONNECT_DATA_LEN) {
                    Ok(Incoming::InCapsule(d)) => self.connect(&sqe, &d).await?,
                    Ok(Incoming::Solicited) => {
                        self.solicit(sqe.clone(), PendingKind::Connect, nvme::CONNECT_DATA_LEN)
                            .await?
                    }
                    Err(s) => err(s),
                }
            } else {
                outcome(
                    self.ctx,
                    self.id,
                    "command",
                    "protocol_refusal",
                    &format!("opcode {:#04x} before Connect", sqe.opcode()),
                );
                err(Status::COMMAND_SEQUENCE_ERROR)
            }
        } else if self.queue.as_ref().is_some_and(|q| q.qid == 0) {
            self.admin_command(&sqe, data).await?
        } else {
            self.io_command(&sqe, data).await?
        };
        self.finish_command(cid, done).await
    }

    /// Ask for a command's data with R2T, now or when a slot frees.
    async fn solicit(&mut self, sqe: Sqe, kind: PendingKind, expected: usize) -> Result<Done> {
        let cid = sqe.cid();
        self.pending.insert(
            cid,
            Pending {
                sqe,
                kind,
                expected,
                buf: Vec::new(),
                r2t: None,
                failed: None,
            },
        );
        self.r2t_wait.push_back(cid);
        self.issue_r2ts().await?;
        Ok(Done::Later)
    }

    /// Send R2Ts for waiting commands while slots are free.
    async fn issue_r2ts(&mut self) -> Result<()> {
        loop {
            let open = self.pending.values().filter(|p| p.r2t.is_some()).count();
            if open >= MAX_OPEN_R2T {
                return Ok(());
            }
            let Some(cid) = self.r2t_wait.pop_front() else {
                return Ok(());
            };
            self.next_r2t(cid).await?;
        }
    }

    /// The next R2T of a command: from where its data stands, at most MAXH2CDATA.
    async fn next_r2t(&mut self, cid: u16) -> Result<()> {
        let mut ttag = self.next_ttag;
        while self
            .pending
            .values()
            .any(|p| p.r2t.is_some_and(|r| r.0 == ttag))
        {
            ttag = ttag.wrapping_add(1);
        }
        self.next_ttag = ttag.wrapping_add(1);
        let Some(p) = self.pending.get_mut(&cid) else {
            return Ok(());
        };
        if p.buf.capacity() == 0 {
            p.buf.reserve_exact(p.expected);
        }
        let offset = p.buf.len();
        let length = (p.expected - offset).min(MAX_H2C_DATA);
        p.r2t = Some((ttag, offset, length, 0));
        let mut r2t = Pdu::new(kind::R2T);
        r2t.set_u16(8, cid);
        r2t.set_u16(10, ttag);
        r2t.set_u32(12, offset as u32);
        r2t.set_u32(16, length as u32);
        self.send(&r2t).await
    }

    async fn h2c_data(&mut self, p: Pdu) -> Result<bool> {
        let cccid = p.u16_at(8);
        let ttag = p.u16_at(10);
        let datao = p.u32_at(12) as usize;
        let datal = p.u32_at(16) as usize;
        let fail = |fes: u16, fei: u32, reason: String| Fatal { fes, fei, reason };
        let check = match self.pending.get(&cccid) {
            None => Err(fail(
                fes::INVALID_PDU_HEADER_FIELD,
                8,
                format!("H2CData for command {cccid}, which is waiting for no data"),
            )),
            Some(w) => match w.r2t {
                None => Err(fail(
                    fes::INVALID_PDU_HEADER_FIELD,
                    8,
                    format!("H2CData for command {cccid} before its R2T"),
                )),
                Some((tag, _, _, _)) if tag != ttag => Err(fail(
                    fes::INVALID_PDU_HEADER_FIELD,
                    10,
                    format!("H2CData with TTAG {ttag}, where the R2T gave {tag}"),
                )),
                Some(_) if datal != p.data.len() => Err(fail(
                    fes::INVALID_PDU_HEADER_FIELD,
                    16,
                    format!("DATAL {datal} on a PDU carrying {} bytes", p.data.len()),
                )),
                Some((_, offset, length, got)) => {
                    if datao != offset + got || got + datal > length || datal == 0 {
                        Err(fail(
                            fes::DATA_TRANSFER_OUT_OF_RANGE,
                            0,
                            format!(
                                "H2CData at offset {datao} for {datal} bytes, where the R2T \
                                 expects offset {} and {} more",
                                offset + got,
                                length - got
                            ),
                        ))
                    } else if p.flags() & flag::LAST_PDU != 0 && got + datal != length {
                        Err(fail(
                            fes::PDU_SEQUENCE_ERROR,
                            0,
                            "LAST_PDU before the R2T's data was all sent".into(),
                        ))
                    } else {
                        Ok(())
                    }
                }
            },
        };
        if let Err(e) = check {
            let header = p.header.clone();
            self.terminate(&e, &header).await;
            return Ok(false);
        }
        self.take_h2c(cccid, &p.data, None).await
    }

    /// Account H2CData (whose header checked out) to its command; finish the R2T and the
    /// command when they are complete.
    async fn take_h2c(&mut self, cid: u16, data: &[u8], failed: Option<Status>) -> Result<bool> {
        let Some(w) = self.pending.get_mut(&cid) else {
            return Ok(true);
        };
        let Some((tag, offset, length, got)) = w.r2t else {
            return Ok(true);
        };
        w.buf.extend_from_slice(data);
        if failed.is_some() {
            w.failed = failed;
        }
        let got = got + data.len();
        if got < length {
            w.r2t = Some((tag, offset, length, got));
            return Ok(true);
        }
        w.r2t = None;
        if w.buf.len() < w.expected {
            self.next_r2t(cid).await?;
            return Ok(true);
        }
        let w = self.pending.remove(&cid).expect("present");
        let done = match w.failed {
            Some(s) => err(s),
            None => match w.kind {
                PendingKind::Connect => self.connect(&w.sqe, &w.buf).await?,
                PendingKind::Write => self.write_now(&w.sqe, &w.buf),
                PendingKind::DatasetManagement => self.dsm_now(&w.sqe, &w.buf),
                PendingKind::AuthSend => self.auth_send(&w.sqe, &w.buf),
                PendingKind::Compare => self.compare_now(&w.sqe, &w.buf),
                PendingKind::Copy => self.copy_now(&w.sqe, &w.buf),
                PendingKind::Reservation => self.reservation_change(&w.sqe, &w.buf).await?,
            },
        };
        let go_on = self.finish_command(cid, done).await?;
        self.issue_r2ts().await?;
        Ok(go_on)
    }

    /// A PDU whose data digest failed: its command fails with TRANSIENT TRANSPORT ERROR; the
    /// stream is in step, so the connection goes on.
    async fn data_digest_failed(&mut self, p: Pdu) -> Result<bool> {
        match p.kind() {
            kind::CAPSULE_CMD => {
                let cid = u16::from_le_bytes([p.header[10], p.header[11]]);
                let size = self.queue.as_ref().map_or(u16::MAX, |q| q.sqsize);
                self.sqhd = if size == u16::MAX {
                    self.sqhd.wrapping_add(1)
                } else {
                    (self.sqhd + 1) % (size + 1)
                };
                self.complete(cid, Status::TRANSIENT_TRANSPORT_ERROR, 0, 0)
                    .await?;
                Ok(true)
            }
            kind::H2C_DATA => {
                let cccid = p.u16_at(8);
                let valid = self.pending.get(&cccid).is_some_and(|w| {
                    w.r2t.is_some_and(|(tag, offset, length, got)| {
                        tag == p.u16_at(10)
                            && p.u32_at(12) as usize == offset + got
                            && got + p.data.len() <= length
                    })
                });
                if !valid {
                    let e = Fatal {
                        fes: fes::DATA_TRANSFER_OUT_OF_RANGE,
                        fei: 0,
                        reason: "H2CData (with a bad data digest) outside any open R2T".into(),
                    };
                    let header = p.header.clone();
                    self.terminate(&e, &header).await;
                    return Ok(false);
                }
                self.take_h2c(cccid, &p.data, Some(Status::TRANSIENT_TRANSPORT_ERROR))
                    .await
            }
            _ => Ok(false),
        }
    }

    // ----------------------------------------------------------------- connect

    async fn connect(&mut self, sqe: &Sqe, data: &[u8]) -> Result<Done> {
        let Some(req) = ConnectRequest::decode(sqe, data) else {
            return Ok(err(Status::SGL_LENGTH_INVALID));
        };
        let invalid = |offset: u16, in_data: bool| {
            Done::Status(
                Status::CONNECT_INVALID_PARAMETERS,
                nvme::invalid_parameter(offset, in_data),
                0,
            )
        };
        let refuse = |this: &Self, why: String| {
            outcome(this.ctx, this.id, "connect", "protocol_refusal", &why);
        };
        if req.recfmt != 0 {
            refuse(self, format!("Connect RECFMT {}", req.recfmt));
            return Ok(err(Status::CONNECT_INCOMPATIBLE_FORMAT));
        }
        let subnqn = match &req.subnqn {
            Ok(s) => s.clone(),
            Err(at) => {
                refuse(self, "SUBNQN is not an NQN".into());
                return Ok(invalid(*at, true));
            }
        };
        let hostnqn = match &req.hostnqn {
            Ok(s) => s.clone(),
            Err(at) => {
                refuse(self, "HOSTNQN is not an NQN".into());
                return Ok(invalid(*at, true));
            }
        };
        // A secure channel belongs to the host and subsystem its PSK identity names: a host
        // that proved one key may not connect as another host, or to a subsystem it holds no
        // key for.
        if let Some(identity) = &self.tls_identity {
            if identity.hostnqn != hostnqn {
                refuse(
                    self,
                    format!(
                        "Connect as {hostnqn} on a secure channel established for {}",
                        identity.hostnqn
                    ),
                );
                return Ok(Done::Status(
                    Status::CONNECT_INVALID_HOST,
                    nvme::invalid_parameter(nvme::connect::DATA_HOSTNQN, true),
                    0,
                ));
            }
            if identity.subnqn != subnqn {
                refuse(
                    self,
                    format!(
                        "Connect to {subnqn} on a secure channel established for {}",
                        identity.subnqn
                    ),
                );
                return Ok(invalid(nvme::connect::DATA_SUBNQN, true));
            }
        }
        if req.sqsize == 0 || req.sqsize > MQES || (req.qid == 0 && req.sqsize < MIN_ADMIN_SQSIZE) {
            refuse(self, format!("SQSIZE {} for queue {}", req.sqsize, req.qid));
            return Ok(invalid(nvme::connect::SQSIZE, false));
        }
        let sqflow_disabled = req.cattr & nvme::connect::CATTR_DISABLE_SQ_FLOW != 0;
        if req.qid == 0 {
            if req.cntlid != nvme::CNTLID_DYNAMIC {
                refuse(
                    self,
                    format!(
                        "admin Connect asked for controller {} (this target's controllers are dynamic)",
                        req.cntlid
                    ),
                );
                return Ok(invalid(nvme::connect::DATA_CNTLID, true));
            }
            let desc = if subnqn == nvme::DISCOVERY_NQN {
                None
            } else {
                match self.admit(&req, &subnqn, &hostnqn).await {
                    Ok(d) => Some(d),
                    Err(done) => return Ok(done),
                }
            };
            let Some(ctrl) = self.target.create(&req, &subnqn, &hostnqn, desc) else {
                refuse(
                    self,
                    format!("the target holds {MAX_CONTROLLERS} controllers"),
                );
                return Ok(err(Status::CONNECT_CONTROLLER_BUSY));
            };
            outcome(
                self.ctx,
                self.id,
                "connect",
                "protocol_accept",
                &format!(
                    "admin queue of {} controller {} for {} (SQSIZE {}, KATO {} ms)",
                    if ctrl.discovery { "discovery" } else { "I/O" },
                    ctrl.cntlid,
                    shown(&hostnqn),
                    req.sqsize,
                    req.kato_ms
                ),
            );
            let auth_required = ctrl.auth_required;
            self.attach(ctrl, 0, req.sqsize, sqflow_disabled);
            let cntlid = self.queue.as_ref().map_or(0, |q| q.ctrl.cntlid);
            if auth_required {
                // AUTHREQ.ATR: nothing but Authentication Send/Receive runs on this queue until
                // the host proves it holds the secret.
                self.auth = target_auth::AuthState::Negotiate;
                self.auth_by = Some(Instant::now() + AUTH_DEADLINE);
                return Ok(Done::Status(
                    Status::SUCCESS,
                    cntlid as u32 | auth::CONNECT_ATR,
                    0,
                ));
            }
            return Ok(Done::Status(Status::SUCCESS, cntlid as u32, 0));
        }
        // An I/O queue joins an existing controller of the same host and subsystem.
        let ctrl = self
            .target
            .find(req.cntlid)
            .filter(|c| c.subnqn == subnqn && c.hostnqn == hostnqn && c.hostid == req.hostid);
        let Some(ctrl) = ctrl else {
            refuse(
                self,
                format!(
                    "I/O queue {} for controller {}, which this host has no association with",
                    req.qid, req.cntlid
                ),
            );
            return Ok(invalid(nvme::connect::DATA_CNTLID, true));
        };
        if ctrl.discovery {
            refuse(self, "an I/O queue for a discovery controller".into());
            return Ok(invalid(nvme::connect::QID, false));
        }
        let epoch = {
            let mut s = ctrl.state();
            if s.cc & 1 == 0 || s.csts & 1 == 0 {
                drop(s);
                refuse(
                    self,
                    format!(
                        "I/O queue {} before controller {} is ready",
                        req.qid, ctrl.cntlid
                    ),
                );
                return Ok(err(Status::COMMAND_SEQUENCE_ERROR));
            }
            let granted = s.queues_granted.unwrap_or(MAX_IO_QUEUES);
            if req.qid > granted {
                drop(s);
                refuse(
                    self,
                    format!("I/O queue {} where {granted} were granted", req.qid),
                );
                return Ok(invalid(nvme::connect::QID, false));
            }
            if !s.io_qids.insert(req.qid) {
                drop(s);
                refuse(self, format!("I/O queue {} is already connected", req.qid));
                return Ok(err(Status::COMMAND_SEQUENCE_ERROR));
            }
            s.epoch
        };
        outcome(
            self.ctx,
            self.id,
            "connect",
            "protocol_accept",
            &format!(
                "I/O queue {} of controller {} (SQSIZE {})",
                req.qid, ctrl.cntlid, req.sqsize
            ),
        );
        let cntlid = ctrl.cntlid;
        self.attach(ctrl, req.qid, req.sqsize, sqflow_disabled);
        if let Some(q) = self.queue.as_mut() {
            q.epoch = epoch;
        }
        Ok(Done::Status(Status::SUCCESS, cntlid as u32, 0))
    }

    fn attach(&mut self, ctrl: Arc<Controller>, qid: u16, sqsize: u16, sqflow_disabled: bool) {
        self.epoch_rx = Some(ctrl.epoch.subscribe());
        self.sqhd = 1 % (sqsize + 1);
        self.queue = Some(Queue {
            qid,
            sqsize,
            sqflow_disabled,
            ctrl,
            epoch: 0,
        });
    }

    /// Ask the model whether this host may connect to the subsystem, and what it contains.
    async fn admit(
        &mut self,
        req: &ConnectRequest,
        subnqn: &str,
        hostnqn: &str,
    ) -> Result<Arc<SubsystemDescription>, Done> {
        let event = Event::new(
            &actions::CONNECT_EVENT,
            json!({
                "host_nqn": hostnqn,
                "host_id": nvme::uuid_text(&req.hostid),
                "subsystem_nqn": subnqn,
                "host_address": self.peer.to_string(),
                "keep_alive_ms": req.kato_ms,
                "authentication_available": self.target.config.auth.is_some(),
            }),
        );
        let refused = |this: &Self, decision: &str, detail: String, done: Done| {
            outcome(
                this.ctx,
                this.id,
                "connect",
                decision,
                &format!("{} -> {}: {detail}", shown(hostnqn), shown(subnqn)),
            );
            done
        };
        let answer = match self.ask(&event).await {
            Ok(a) => a,
            Err((decision, status, detail)) => {
                return Err(refused(self, decision, detail, err(status)));
            }
        };
        match answer["type"].as_str() {
            Some(actions::ACCEPT_CONNECT) => {
                match SubsystemDescription::from_action(&answer, subnqn) {
                    Ok(d) if d.require_authentication && self.target.config.auth.is_none() => {
                        Err(refused(
                            self,
                            "fail_closed_invalid_reply",
                            "the model requires authentication, but no dhchap_secret is \
                             configured to check it against"
                                .into(),
                            err(Status::INTERNAL_ERROR),
                        ))
                    }
                    Ok(d) => {
                        outcome(
                            self.ctx,
                            self.id,
                            "connect",
                            "model_answer",
                            &format!(
                                "{} admitted to {} with {} namespace(s){}",
                                shown(hostnqn),
                                shown(subnqn),
                                d.namespaces.len(),
                                if d.require_authentication {
                                    ", once it authenticates (DH-HMAC-CHAP)"
                                } else {
                                    ""
                                }
                            ),
                        );
                        Ok(Arc::new(d))
                    }
                    Err(e) => Err(refused(
                        self,
                        "fail_closed_invalid_reply",
                        format!("{e:#}"),
                        err(Status::INTERNAL_ERROR),
                    )),
                }
            }
            Some(actions::REJECT_CONNECT) => {
                if answer["reason"] == "not_found" {
                    Err(refused(
                        self,
                        "model_reject",
                        "no such subsystem".into(),
                        Done::Status(
                            Status::CONNECT_INVALID_PARAMETERS,
                            nvme::invalid_parameter(nvme::connect::DATA_SUBNQN, true),
                            0,
                        ),
                    ))
                } else {
                    Err(refused(
                        self,
                        "model_reject",
                        "host not allowed".into(),
                        Done::Status(
                            Status::CONNECT_INVALID_HOST,
                            nvme::invalid_parameter(nvme::connect::DATA_HOSTNQN, true),
                            0,
                        ),
                    ))
                }
            }
            _ => Err(refused(
                self,
                "fail_closed_invalid_reply",
                "an answer that is not a connect decision".into(),
                err(Status::INTERNAL_ERROR),
            )),
        }
    }

    /// One model call that must produce exactly one answer; on failure the decision, the
    /// status to refuse with and why.
    async fn ask(
        &mut self,
        event: &Event,
    ) -> Result<serde_json::Value, (&'static str, Status, String)> {
        let result = match call_llm(
            &self.ctx.llm_client,
            &self.ctx.state,
            self.ctx.server_id,
            Some(self.id),
            event,
            &actions::NvmeTcpProtocol,
        )
        .await
        {
            Ok(r) => r,
            Err(e) => {
                let status = match WireFailure::classify(&e) {
                    WireFailure::Overloaded => Status::CONNECT_CONTROLLER_BUSY,
                    WireFailure::Unavailable => Status::INTERNAL_ERROR.retry(),
                };
                return Err((
                    "fail_closed_llm_error",
                    status,
                    "the model backend failed".into(),
                ));
            }
        };
        let mut answers = Vec::new();
        let mut queue = result.protocol_results;
        while let Some(r) = queue.pop() {
            match r {
                ActionResult::Custom { data, .. } => answers.push(data),
                ActionResult::Multiple(items) => queue.extend(items),
                _ => {}
            }
        }
        if answers.is_empty() && result.failures.is_empty() {
            return Err(("model_silent", Status::INTERNAL_ERROR, "no answer".into()));
        }
        if answers.len() != 1 || !result.failures.is_empty() {
            return Err((
                "fail_closed_invalid_reply",
                Status::INTERNAL_ERROR,
                "not exactly one valid answer".into(),
            ));
        }
        Ok(answers.remove(0))
    }

    // ------------------------------------------------------------------- admin

    async fn admin_command(&mut self, sqe: &Sqe, data: Vec<u8>) -> Result<Done> {
        let ctrl = self.queue.as_ref().expect("connected").ctrl.clone();
        let op = sqe.opcode();
        if op == admin::FABRICS && matches!(sqe.fctype(), fctype::AUTH_SEND | fctype::AUTH_RECEIVE)
        {
            return self.auth_command(sqe, data).await;
        }
        if ctrl.auth_required && !self.authenticated {
            outcome(
                self.ctx,
                self.id,
                "command",
                "protocol_refusal",
                &format!(
                    "{} before the host authenticated",
                    if op == admin::FABRICS {
                        format!("Fabrics command {:#04x}", sqe.fctype())
                    } else {
                        format!("admin opcode {op:#04x}")
                    }
                ),
            );
            return Ok(err(Status::AUTHENTICATION_REQUIRED));
        }
        if op == admin::FABRICS {
            return Ok(match sqe.fctype() {
                fctype::PROPERTY_GET => self.property_get(&ctrl, sqe),
                fctype::PROPERTY_SET => self.property_set(&ctrl, sqe),
                fctype::CONNECT => {
                    outcome(
                        self.ctx,
                        self.id,
                        "connect",
                        "protocol_refusal",
                        "a second Connect on a connected queue",
                    );
                    err(Status::COMMAND_SEQUENCE_ERROR)
                }
                fctype::DISCONNECT => err(Status::INVALID_FIELD),
                _ => err(Status::INVALID_OPCODE),
            });
        }
        if sqe.psdt() == 0 {
            return Ok(err(Status::INVALID_FIELD));
        }
        if !ctrl.ready() {
            outcome(
                self.ctx,
                self.id,
                "command",
                "protocol_refusal",
                &format!("admin opcode {op:#04x} before CC.EN"),
            );
            return Ok(err(Status::COMMAND_SEQUENCE_ERROR));
        }
        Ok(match op {
            admin::IDENTIFY => self.identify(&ctrl, sqe, &data),
            admin::GET_LOG_PAGE => self.get_log_page(&ctrl, sqe, &data).await,
            admin::SET_FEATURES if ctrl.discovery && !discovery_feature(sqe) => {
                err(Status::INVALID_FIELD)
            }
            admin::SET_FEATURES => self.set_features(&ctrl, sqe),
            admin::GET_FEATURES => self.get_features(&ctrl, sqe),
            admin::KEEP_ALIVE => ok(),
            admin::ASYNC_EVENT_REQUEST => {
                if self.aers.len() > AERL as usize {
                    err(Status::AER_LIMIT_EXCEEDED)
                } else {
                    // Held: this target has no event to report, and an AER is never completed
                    // without one.
                    self.aers.push(sqe.cid());
                    Done::Later
                }
            }
            admin::ABORT if !ctrl.discovery => {
                // DW0 bit 0: the command was not aborted. Every command here either completes
                // at once or waits for data the host controls.
                Done::Status(Status::SUCCESS, 1, 0)
            }
            _ => err(Status::INVALID_OPCODE),
        })
    }

    fn property_get(&self, ctrl: &Controller, sqe: &Sqe) -> Done {
        let size8 = sqe.0[40] & 0x07 == 1;
        let offset = sqe.u32(44);
        let s = ctrl.state();
        let value: u64 = match (offset, size8) {
            (prop::CAP, true) => cap(),
            (prop::CAP, false) => cap() & 0xFFFF_FFFF,
            (prop::VS, false) => nvme::VERSION as u64,
            (prop::CC, false) => s.cc as u64,
            (prop::CSTS, false) => s.csts as u64,
            (prop::NSSR, false) => 0,
            _ => return err(Status::INVALID_FIELD),
        };
        Done::Status(Status::SUCCESS, value as u32, (value >> 32) as u32)
    }

    fn property_set(&self, ctrl: &Controller, sqe: &Sqe) -> Done {
        let size8 = sqe.0[40] & 0x07 == 1;
        let offset = sqe.u32(44);
        let value = sqe.u64(48);
        if offset != prop::CC || size8 {
            return err(Status::INVALID_FIELD);
        }
        let new = value as u32;
        let mut s = ctrl.state();
        let old = s.cc;
        s.cc = new;
        if new & 1 != 0 && old & 1 == 0 {
            let iosqes = (new >> 16) & 0xF;
            let iocqes = (new >> 20) & 0xF;
            let mps = (new >> 7) & 0xF;
            let css = (new >> 4) & 0x7;
            let ams = (new >> 11) & 0x7;
            let valid = mps == 0
                && css == 0
                && ams == 0
                && (ctrl.discovery || (iosqes == 6 && iocqes == 4));
            if valid {
                s.csts |= 1;
            } else {
                s.csts |= 2; // CFS
                drop(s);
                outcome(
                    self.ctx,
                    self.id,
                    "enable",
                    "protocol_refusal",
                    &format!("CC {new:#010x} cannot be enabled (CSTS.CFS set)"),
                );
                return ok();
            }
        } else if new & 1 == 0 && old & 1 != 0 {
            // A controller reset: not ready, and its I/O queues go.
            s.csts &= !1;
            s.csts &= !0x0C;
            s.io_qids.clear();
            s.epoch += 1;
            let epoch = s.epoch;
            drop(s);
            let _ = ctrl.epoch.send(epoch);
            return ok();
        }
        // Shutdown notification: done at once, there is nothing to flush.
        let shn = (new >> 14) & 3;
        s.csts = (s.csts & !0x0C) | if shn != 0 { 0b10 << 2 } else { 0 };
        ok()
    }

    fn identify(&self, ctrl: &Controller, sqe: &Sqe, data: &[u8]) -> Done {
        if let Err(s) = outgoing(sqe, data, nvme::IDENTIFY_LEN) {
            return err(s);
        }
        let c = (sqe.cdw(10) & 0xFF) as u8;
        let nsid = sqe.nsid();
        if ctrl.discovery && c != cns::CONTROLLER {
            return err(Status::INVALID_FIELD);
        }
        let desc = ctrl.desc.as_deref();
        match c {
            cns::CONTROLLER => Done::Data(identify_controller(ctrl), 0),
            cns::NAMESPACE => {
                if nsid == 0 || nsid > ns::MAX_NSID {
                    return err(Status::INVALID_NAMESPACE);
                }
                match desc.and_then(|d| d.namespace(nsid)) {
                    Some(n) => Done::Data(n.identify(), 0),
                    // A valid NSID that is not active reads as zeroes.
                    None => Done::Data(vec![0u8; nvme::IDENTIFY_LEN], 0),
                }
            }
            cns::ACTIVE_NAMESPACES => {
                if nsid >= 0xFFFF_FFFE {
                    return err(Status::INVALID_NAMESPACE);
                }
                let mut b = vec![0u8; nvme::IDENTIFY_LEN];
                let ids = desc
                    .map(|d| d.namespaces.iter().map(|n| n.nsid).filter(|n| *n > nsid))
                    .into_iter()
                    .flatten()
                    .take(1024);
                for (i, id) in ids.enumerate() {
                    b[i * 4..i * 4 + 4].copy_from_slice(&id.to_le_bytes());
                }
                Done::Data(b, 0)
            }
            cns::NAMESPACE_DESCRIPTORS => match desc.and_then(|d| d.namespace(nsid)) {
                Some(n) => Done::Data(n.descriptors(), 0),
                None => err(Status::INVALID_NAMESPACE),
            },
            // The NVM command set's own Identify Controller (CSI 0): every limit it reports is
            // 0, "not reported". The Linux host asks for it of any controller past NVMe 1.2.
            cns::IO_COMMAND_SET_CONTROLLER if sqe.cdw(11) >> 24 == 0 => {
                Done::Data(vec![0u8; nvme::IDENTIFY_LEN], 0)
            }
            _ => err(Status::INVALID_FIELD),
        }
    }

    async fn get_log_page(&mut self, ctrl: &Arc<Controller>, sqe: &Sqe, data: &[u8]) -> Done {
        let lid = (sqe.cdw(10) & 0xFF) as u8;
        let known = match lid {
            log::DISCOVERY => ctrl.discovery,
            log::ERROR => true,
            log::SMART | log::FIRMWARE_SLOT | log::CHANGED_NAMESPACES => !ctrl.discovery,
            _ => false,
        };
        if !known {
            return err(Status::INVALID_LOG_PAGE);
        }
        let numd = (((sqe.cdw(11) & 0xFFFF) as u64) << 16 | (sqe.cdw(10) >> 16) as u64) + 1;
        let len = numd * 4;
        let lpo = sqe.cdw(12) as u64 | (sqe.cdw(13) as u64) << 32;
        if len > MAX_TRANSFER as u64 || !lpo.is_multiple_of(4) {
            return err(Status::INVALID_FIELD);
        }
        let len = len as usize;
        if let Err(s) = outgoing(sqe, data, len) {
            return err(s);
        }
        let page = match (lid, ctrl.discovery) {
            (log::DISCOVERY, true) => {
                let entries = self.discovery_entries(ctrl).await;
                nvme::discovery_log(1, &entries)
            }
            (log::ERROR, _) => vec![0u8; 64],
            (log::SMART, false) => smart(ctrl).encode(),
            (log::FIRMWARE_SLOT, false) => {
                let mut b = vec![0u8; 512];
                b[0] = 1; // AFI: slot 1 active
                if let Some(d) = &ctrl.desc {
                    nvme::put_padded(&mut b[8..16], &d.firmware);
                }
                b
            }
            (log::CHANGED_NAMESPACES, false) => vec![0u8; nvme::IDENTIFY_LEN],
            _ => return err(Status::INVALID_LOG_PAGE),
        };
        if lpo > page.len() as u64 {
            return err(Status::INVALID_FIELD);
        }
        let mut out = page[lpo as usize..].to_vec();
        out.resize(len, 0);
        Done::Data(out, 0)
    }

    /// The model's discovery log, asked once per discovery controller. A failure lists nothing.
    async fn discovery_entries(&mut self, ctrl: &Arc<Controller>) -> Vec<DiscoveryEntry> {
        if let Some(d) = ctrl.state().discovery.clone() {
            return d;
        }
        let event = Event::new(
            &actions::DISCOVERY_EVENT,
            json!({
                "host_nqn": ctrl.hostnqn,
                "host_id": nvme::uuid_text(&ctrl.hostid),
                "host_address": self.peer.to_string(),
            }),
        );
        let subsystems = match self.ask(&event).await {
            Ok(a) if a["type"] == actions::DISCOVERY_ENTRIES => match actions::entries_of(&a) {
                Ok(s) => {
                    outcome(
                        self.ctx,
                        self.id,
                        "discovery",
                        "model_answer",
                        &format!("{} subsystem(s)", s.len()),
                    );
                    s
                }
                Err(e) => {
                    outcome(
                        self.ctx,
                        self.id,
                        "discovery",
                        "fail_closed_invalid_reply",
                        &format!("{e:#}; no subsystems listed"),
                    );
                    vec![]
                }
            },
            Ok(_) => {
                outcome(
                    self.ctx,
                    self.id,
                    "discovery",
                    "fail_closed_invalid_reply",
                    "not a discovery answer; no subsystems listed",
                );
                vec![]
            }
            Err((decision, _, detail)) => {
                outcome(
                    self.ctx,
                    self.id,
                    "discovery",
                    decision,
                    &format!("{detail}; no subsystems listed"),
                );
                vec![]
            }
        };
        let entries: Vec<DiscoveryEntry> = subsystems
            .into_iter()
            .map(|(nqn, address)| {
                let a = address.unwrap_or_else(|| {
                    SocketAddr::new(self.local.ip(), self.target.config.io_port)
                });
                DiscoveryEntry {
                    trtype: nvme::TRTYPE_TCP,
                    adrfam: if a.is_ipv4() {
                        nvme::ADRFAM_IPV4
                    } else {
                        nvme::ADRFAM_IPV6
                    },
                    subtype: nvme::SUBTYPE_NVME,
                    // Disabling SQ flow control is supported, and TLS is required exactly when
                    // a key is configured (TREQ 01b) — otherwise not specified (00b).
                    treq: 0x04 | u8::from(self.target.config.tls_key.is_some()),
                    portid: PORT_ID,
                    cntlid: nvme::CNTLID_DYNAMIC,
                    asqsz: MIN_ADMIN_SQSIZE + 1,
                    trsvcid: a.port().to_string(),
                    subnqn: nqn,
                    traddr: a.ip().to_string(),
                    // TSAS SECTYPE: TLS 1.3, or no security.
                    sectype: if self.target.config.tls_key.is_some() { 2 } else { 0 },
                }
            })
            .collect();
        ctrl.state().discovery = Some(entries.clone());
        entries
    }

    fn set_features(&self, ctrl: &Controller, sqe: &Sqe) -> Done {
        let cdw10 = sqe.cdw(10);
        if cdw10 & (1 << 31) != 0 {
            return err(Status::FEATURE_NOT_SAVEABLE);
        }
        let fid = (cdw10 & 0xFF) as u8;
        let v = sqe.cdw(11);
        let mut s = ctrl.state();
        match fid {
            feature::NUMBER_OF_QUEUES => {
                let (nsqr, ncqr) = (v & 0xFFFF, v >> 16);
                if nsqr == 0xFFFF || ncqr == 0xFFFF {
                    return err(Status::INVALID_FIELD);
                }
                if !s.io_qids.is_empty() {
                    return err(Status::COMMAND_SEQUENCE_ERROR);
                }
                let granted = (nsqr.min(ncqr) + 1).min(MAX_IO_QUEUES as u32) as u16;
                s.queues_granted = Some(granted);
                let g = (granted - 1) as u32;
                Done::Status(Status::SUCCESS, g | g << 16, 0)
            }
            feature::KEEP_ALIVE_TIMER => {
                s.kato_ms = v;
                ok()
            }
            feature::ASYNC_EVENT_CONFIG => {
                s.aec = v;
                ok()
            }
            feature::VOLATILE_WRITE_CACHE => {
                s.write_cache = v & 1 != 0;
                ok()
            }
            _ => err(Status::INVALID_FIELD),
        }
    }

    fn get_features(&self, ctrl: &Controller, sqe: &Sqe) -> Done {
        let cdw10 = sqe.cdw(10);
        let fid = (cdw10 & 0xFF) as u8;
        let sel = (cdw10 >> 8) & 0x7;
        let changeable = matches!(
            fid,
            feature::NUMBER_OF_QUEUES
                | feature::KEEP_ALIVE_TIMER
                | feature::ASYNC_EVENT_CONFIG
                | feature::VOLATILE_WRITE_CACHE
        );
        let known = changeable
            || matches!(
                fid,
                feature::ARBITRATION
                    | feature::POWER_MANAGEMENT
                    | feature::TEMPERATURE_THRESHOLD
                    | feature::ERROR_RECOVERY
                    | feature::WRITE_ATOMICITY
            );
        if !known || (ctrl.discovery && !discovery_feature(sqe)) {
            return err(Status::INVALID_FIELD);
        }
        if sel == 3 {
            // Supported capabilities: changeable, not saveable, not namespace specific.
            return Done::Status(Status::SUCCESS, if changeable { 0b100 } else { 0 }, 0);
        }
        if sel > 3 {
            return err(Status::INVALID_FIELD);
        }
        let current = sel == 0;
        let s = ctrl.state();
        let dw0 = match fid {
            feature::NUMBER_OF_QUEUES => {
                let g = (if current { s.queues_granted } else { None }).unwrap_or(MAX_IO_QUEUES)
                    as u32
                    - 1;
                g | g << 16
            }
            feature::KEEP_ALIVE_TIMER => {
                if current {
                    s.kato_ms
                } else {
                    0
                }
            }
            feature::ASYNC_EVENT_CONFIG => {
                if current {
                    s.aec
                } else {
                    0
                }
            }
            feature::VOLATILE_WRITE_CACHE => (!current || s.write_cache) as u32,
            // 343 K (70 °C) as the over-temperature threshold.
            feature::TEMPERATURE_THRESHOLD => 0x0157,
            _ => 0,
        };
        Done::Status(Status::SUCCESS, dw0, 0)
    }

    // --------------------------------------------------------------------- I/O

    async fn io_command(&mut self, sqe: &Sqe, data: Vec<u8>) -> Result<Done> {
        let ctrl = self.queue.as_ref().expect("connected").ctrl.clone();
        let op = sqe.opcode();
        if op == admin::FABRICS {
            return Ok(match sqe.fctype() {
                fctype::DISCONNECT => {
                    outcome(
                        self.ctx,
                        self.id,
                        "disconnect",
                        "protocol_accept",
                        "the host disconnected this I/O queue",
                    );
                    Done::Close
                }
                fctype::CONNECT => err(Status::COMMAND_SEQUENCE_ERROR),
                // I/O queues join a controller whose admin queue authenticated, and are never
                // asked to (AUTHREQ is clear in their Connect), as nvmet does; a host may
                // still prove itself on one (SPDK does), and the exchange runs.
                fctype::AUTH_SEND | fctype::AUTH_RECEIVE => {
                    return self.auth_command(sqe, data).await;
                }
                _ => err(Status::INVALID_OPCODE),
            });
        }
        if sqe.psdt() == 0 {
            return Ok(err(Status::INVALID_FIELD));
        }
        if !ctrl.ready() {
            return Ok(err(Status::COMMAND_SEQUENCE_ERROR));
        }
        let Some(desc) = ctrl.desc.clone() else {
            return Ok(err(Status::INVALID_OPCODE));
        };
        let nsid = sqe.nsid();
        if sqe.fuse() != 0 {
            // Fused operations (Compare and Write) are not supported: ONCS bit 0 of FUSES clear.
            return Ok(err(Status::INVALID_FIELD));
        }
        if op == io::FLUSH {
            if nsid == 0xFFFF_FFFF {
                return Ok(ok());
            }
            if desc.namespace(nsid).is_none() {
                return Ok(err(Status::INVALID_NAMESPACE));
            }
            return Ok(match self.reservation_denies(&ctrl, nsid, true) {
                Some(s) => err(s),
                None => ok(),
            });
        }
        if !matches!(
            op,
            io::READ
                | io::WRITE
                | io::WRITE_ZEROES
                | io::DATASET_MANAGEMENT
                | io::COMPARE
                | io::VERIFY
                | io::COPY
                | io::RESV_REGISTER
                | io::RESV_REPORT
                | io::RESV_ACQUIRE
                | io::RESV_RELEASE
        ) {
            return Ok(err(Status::INVALID_OPCODE));
        }
        let Some(ns) = desc.namespace(nsid) else {
            return Ok(err(Status::INVALID_NAMESPACE));
        };
        if matches!(
            op,
            io::RESV_REGISTER | io::RESV_REPORT | io::RESV_ACQUIRE | io::RESV_RELEASE
        ) {
            return self.reservation(sqe, data).await;
        }
        let write = matches!(
            op,
            io::WRITE | io::WRITE_ZEROES | io::DATASET_MANAGEMENT | io::COPY
        );
        if let Some(s) = self.reservation_denies(&ctrl, nsid, write) {
            return Ok(err(s));
        }
        if op == io::COPY {
            return self.copy(sqe, data, ns).await;
        }
        if op == io::VERIFY {
            return Ok(self.verify(&ctrl, sqe, &data, ns));
        }
        if op == io::DATASET_MANAGEMENT {
            let need = ((sqe.cdw(10) & 0xFF) as usize + 1) * 16;
            return Ok(match incoming(sqe, data, need) {
                Ok(Incoming::InCapsule(d)) => self.dsm_now(sqe, &d),
                Ok(Incoming::Solicited) => {
                    self.solicit(sqe.clone(), PendingKind::DatasetManagement, need)
                        .await?
                }
                Err(s) => err(s),
            });
        }
        let (slba, blocks) = sqe.lba_range();
        if !ns.in_range(slba, blocks) {
            return Ok(err(Status::LBA_OUT_OF_RANGE));
        }
        // Protection information: this namespace has no metadata, so PRINFO must be 0.
        if (sqe.cdw(12) >> 26) & 0xF != 0 {
            return Ok(err(Status::INVALID_FIELD));
        }
        let len = blocks as usize * ns.block_size as usize;
        match op {
            io::READ => {
                if len > MAX_TRANSFER {
                    return Ok(err(Status::INVALID_FIELD));
                }
                if let Err(s) = outgoing(sqe, &data, len) {
                    return Ok(err(s));
                }
                if let Some(s) = ns.failure(slba, blocks, false) {
                    ctrl.state().stats.media_errors += 1;
                    return Ok(err(s));
                }
                let bytes = ns.read(slba, blocks, &ctrl.overlay());
                let mut s = ctrl.state();
                s.stats.reads += 1;
                s.stats.bytes_read += bytes.len() as u64;
                Ok(Done::Data(bytes, 0))
            }
            io::WRITE => {
                if len > MAX_TRANSFER {
                    return Ok(err(Status::INVALID_FIELD));
                }
                if !ns.writable {
                    return Ok(err(Status::NAMESPACE_WRITE_PROTECTED));
                }
                if let Some(s) = ns.failure(slba, blocks, true) {
                    ctrl.state().stats.media_errors += 1;
                    return Ok(err(s));
                }
                match incoming(sqe, data, len) {
                    Ok(Incoming::InCapsule(d)) => Ok(self.write_now(sqe, &d)),
                    Ok(Incoming::Solicited) => {
                        self.solicit(sqe.clone(), PendingKind::Write, len).await
                    }
                    Err(s) => Ok(err(s)),
                }
            }
            io::COMPARE => {
                if len > MAX_TRANSFER {
                    return Ok(err(Status::INVALID_FIELD));
                }
                if let Some(s) = ns.failure(slba, blocks, false) {
                    ctrl.state().stats.media_errors += 1;
                    return Ok(err(s));
                }
                match incoming(sqe, data, len) {
                    Ok(Incoming::InCapsule(d)) => Ok(self.compare_now(sqe, &d)),
                    Ok(Incoming::Solicited) => {
                        self.solicit(sqe.clone(), PendingKind::Compare, len).await
                    }
                    Err(s) => Ok(err(s)),
                }
            }
            _ => {
                // Write Zeroes.
                if !ns.writable {
                    return Ok(err(Status::NAMESPACE_WRITE_PROTECTED));
                }
                if let Some(s) = ns.failure(slba, blocks, true) {
                    return Ok(err(s));
                }
                Ok(match ctrl.overlay().zero(ns, slba, blocks) {
                    Ok(()) => ok(),
                    Err(s) => err(s),
                })
            }
        }
    }

    /// A Write whose data is all here.
    fn write_now(&self, sqe: &Sqe, data: &[u8]) -> Done {
        let Some(q) = self.queue.as_ref() else {
            return err(Status::COMMAND_SEQUENCE_ERROR);
        };
        let ctrl = &q.ctrl;
        let Some(ns) = ctrl.desc.as_ref().and_then(|d| d.namespace(sqe.nsid())) else {
            return err(Status::INVALID_NAMESPACE);
        };
        let (slba, _) = sqe.lba_range();
        let result = ctrl.overlay().write(ns, slba, data);
        match result {
            Ok(()) => {
                let mut s = ctrl.state();
                s.stats.writes += 1;
                s.stats.bytes_written += data.len() as u64;
                ok()
            }
            Err(s) => {
                outcome(
                    self.ctx,
                    self.id,
                    "write",
                    "protocol_refusal",
                    &format!(
                        "the controller's writes would pass {} bytes",
                        ns::MAX_OVERLAY_BYTES
                    ),
                );
                err(s)
            }
        }
    }

    /// Dataset Management whose ranges are all here. Deallocate is advisory and changes
    /// nothing (Identify Namespace's DLFEAT says so); the ranges are still checked.
    fn dsm_now(&self, sqe: &Sqe, data: &[u8]) -> Done {
        let Some(q) = self.queue.as_ref() else {
            return err(Status::COMMAND_SEQUENCE_ERROR);
        };
        let Some(ns) = q.ctrl.desc.as_ref().and_then(|d| d.namespace(sqe.nsid())) else {
            return err(Status::INVALID_NAMESPACE);
        };
        let deallocate = sqe.cdw(11) & 0x04 != 0;
        for r in data.chunks_exact(16) {
            let blocks = u32::from_le_bytes(r[4..8].try_into().expect("4 bytes")) as u64;
            let slba = u64::from_le_bytes(r[8..16].try_into().expect("8 bytes"));
            if !ns.in_range(slba, blocks) {
                return err(Status::LBA_OUT_OF_RANGE);
            }
        }
        if deallocate && !ns.writable {
            return err(Status::NAMESPACE_WRITE_PROTECTED);
        }
        ok()
    }
}

/// Discovery controllers take only the keep-alive and asynchronous event features.
fn discovery_feature(sqe: &Sqe) -> bool {
    matches!(
        (sqe.cdw(10) & 0xFF) as u8,
        feature::KEEP_ALIVE_TIMER | feature::ASYNC_EVENT_CONFIG
    )
}

async fn ended(rx: &mut Option<watch::Receiver<u64>>, epoch: u64, admin: bool) {
    let Some(rx) = rx.as_mut() else {
        return std::future::pending().await;
    };
    loop {
        {
            let v = *rx.borrow_and_update();
            if v == DEAD || (!admin && v != epoch) {
                return;
            }
        }
        if rx.changed().await.is_err() {
            return;
        }
    }
}

async fn sleep_until(deadline: Option<Instant>) {
    match deadline {
        Some(d) => tokio::time::sleep(d.saturating_duration_since(Instant::now())).await,
        None => std::future::pending().await,
    }
}

/// The SMART / Health log of a controller.
fn smart(ctrl: &Controller) -> nvme::Smart {
    let s = ctrl.state().stats;
    // Data units are thousands of 512-byte units, rounded up.
    let units = |bytes: u64| (bytes / 512).div_ceil(1000) as u128;
    nvme::Smart {
        critical_warning: 0,
        temperature_kelvin: 313,
        available_spare: 100,
        percentage_used: 0,
        data_units_read: units(s.bytes_read),
        data_units_written: units(s.bytes_written),
        host_read_commands: s.reads as u128,
        host_write_commands: s.writes as u128,
        power_on_hours: (ctrl.created.elapsed().as_secs() / 3600) as u128,
        media_errors: s.media_errors as u128,
    }
}

/// Identify Controller (CNS 01h), for an I/O or a discovery controller.
pub fn identify_controller(ctrl: &Controller) -> Vec<u8> {
    let mut b = vec![0u8; nvme::IDENTIFY_LEN];
    let (model, serial, firmware, nn) = match &ctrl.desc {
        Some(d) => (
            d.model.clone(),
            d.serial.clone(),
            d.firmware.clone(),
            d.nn(),
        ),
        None => (
            "NetGet NVMe/TCP discovery".to_string(),
            ns::default_serial(nvme::DISCOVERY_NQN),
            "1.0".to_string(),
            0,
        ),
    };
    nvme::put_padded(&mut b[4..24], &serial);
    nvme::put_padded(&mut b[24..64], &model);
    nvme::put_padded(&mut b[64..72], &firmware);
    b[72] = 6; // RAB
    b[76] = if ctrl.discovery { 0 } else { 0x02 }; // CMIC: the subsystem may have several controllers
    b[77] = MDTS;
    b[78..80].copy_from_slice(&ctrl.cntlid.to_le_bytes());
    b[80..84].copy_from_slice(&nvme::VERSION.to_le_bytes());
    b[111] = if ctrl.discovery { 2 } else { 1 }; // CNTRLTYPE
    b[258] = 3; // ACL
    b[259] = AERL;
    b[260] = 0x03; // FRMW: one slot, read-only
    b[261] = 0x04; // LPA: extended data (NUMDU, LPO)
    b[262] = 0; // ELPE: one error log entry
    b[266..268].copy_from_slice(&0x0157u16.to_le_bytes()); // WCTEMP
    b[268..270].copy_from_slice(&0x0175u16.to_le_bytes()); // CCTEMP
    b[320..322].copy_from_slice(&KAS.to_le_bytes());
    b[512] = 0x66; // SQES
    b[513] = 0x44; // CQES
    b[514..516].copy_from_slice(&(MQES + 1).to_le_bytes()); // MAXCMD
    b[516..520].copy_from_slice(&nn.to_le_bytes());
    if !ctrl.discovery {
        b[520..522].copy_from_slice(&nvme::ONCS.to_le_bytes());
        b[525] = 0x01; // VWC: present
        b[534..536].copy_from_slice(&1u16.to_le_bytes()); // OCFS: Copy descriptor format 0
    }
    // SGLS: SGLs supported, and the Data Block descriptor's address is an offset (in-capsule).
    b[536..540].copy_from_slice(&(1u32 | 1 << 20).to_le_bytes());
    nvme::put_nul_padded(&mut b[768..1024], &ctrl.subnqn);
    b[1792..1796].copy_from_slice(&IOCCSZ.to_le_bytes());
    b[1796..1800].copy_from_slice(&1u32.to_le_bytes()); // IORCSZ
    b[1803] = 1; // MSDBD
    b[1804..1806].copy_from_slice(&1u16.to_le_bytes()); // OFCS: Disconnect supported
    b[2048..2050].copy_from_slice(&900u16.to_le_bytes()); // PSD0: 9 W
    b
}
