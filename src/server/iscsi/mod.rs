//! iSCSI target (RFC 7143). Rust owns the wire — PDU framing and digests, login and text-key
//! negotiation, CHAP, sequence numbers, R2T and Data-In/Out, sessions of several connections,
//! task management, error recovery and the SCSI block commands; the model decides which
//! targets discovery reveals, who may log in, what each LUN contains, and whether a reset may
//! go ahead. Every SCSI command is served from the model's description without another model
//! call.
//!
//! | File | What it does |
//! |---|---|
//! | `mod.rs` | configuration, the accept loop, a connection's state, login |
//! | `session.rs` | what a session's connections share: the CmdSN window, tasks, unit attentions |
//! | `ffp.rs` | the full feature phase loop, CmdSN admission, text, NOP, logout |
//! | `scsi.rs` | SCSI commands, Data-In, writes and their data |
//! | `tmf.rs` | task management, the model's reset decisions, task reassignment |
//! | `recovery.rs` | SNACK, DataACK and retransmission (error recovery levels 1 and 2) |
pub mod actions;
pub mod chap;
mod ffp;
pub mod lun;
pub mod pdu;
mod recovery;
mod scsi;
pub mod session;
pub mod text;
mod tmf;

use crate::llm::action_helper::call_llm;
use crate::llm::actions::protocol_trait::ActionResult;
use crate::logging::emit::Log;
use crate::protocol::{Event, SpawnContext};
use crate::server::accept_bounded::{accept_bounded, ConnectionLimiter, DEFAULT_MAX_CONNECTIONS};
use crate::server::connection::ConnectionId;
use crate::server::scsi_common::Sense;
use crate::state::server::{ConnectionState, ConnectionStatus, ProtocolConnectionInfo};
use crate::utils::clock::Instant;
use crate::utils::wire_failure::WireFailure;
use anyhow::{bail, Context, Result};
use chap::Credential;
use lun::TargetDescription;
use pdu::{login_status, op, stage, Digests, Pdu, PduReader, ReadError};
use serde_json::json;
use session::{
    lock, lock_registry, CommandWindow, ConnSlot, Gone, Life, Nexus, Registry, RegistryCell,
    Session, SessionCell,
};
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use text::{DigestPreference, Params, TargetOffer};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

/// The whole login, from the first byte to full feature phase.
pub const LOGIN_DEADLINE: Duration = Duration::from_secs(60);
/// The rest of any PDU once its first byte has arrived.
pub const PDU_DEADLINE: Duration = Duration::from_secs(60);
/// How long a logged-out connection waits for the initiator to close it.
pub const LOGOUT_LINGER: Duration = Duration::from_secs(5);
/// Commands an initiator may have outstanding: MaxCmdSN - ExpCmdSN + 1.
pub const COMMAND_WINDOW: u32 = 32;
/// Bytes one command may move in either direction.
pub const MAX_COMMAND_BYTES: u64 = 32 * 1024 * 1024;
/// Login PDUs one login may take.
pub const MAX_LOGIN_PDUS: usize = 64;
/// This target's InitialR2T unless the `initial_r2t` startup parameter says otherwise: Yes, the
/// RFC 7143 default and what LIO and tgt declare.
pub const DEFAULT_INITIAL_R2T: bool = true;
/// The default for the `digests` startup parameter.
pub const DEFAULT_DIGESTS: &str = "either";
/// MaxConnections this target offers unless `max_connections` says otherwise. The result
/// function is the minimum, so an initiator that offers 1 (libiscsi, open-iscsi) gets 1.
pub const DEFAULT_MAX_CONNECTIONS_PER_SESSION: u32 = 4;
/// The ErrorRecoveryLevel this target offers unless `error_recovery_level` says otherwise
/// (minimum function: an initiator offering 0 gets 0).
pub const DEFAULT_ERROR_RECOVERY_LEVEL: u32 = 2;
/// A CHAP secret's length bounds (RFC 7143 §12.1.3 requires at least 12 bytes for CHAP over
/// an unprotected link; the 255-byte ceiling is ours).
pub const MIN_SECRET: usize = 12;
pub const MAX_SECRET: usize = 255;
/// The target portal group every portal of this server belongs to.
pub const PORTAL_GROUP_TAG: u16 = 1;
/// How often retained sessions and tasks are checked for the end of their retention.
pub const JANITOR_TICK: Duration = Duration::from_secs(1);
/// Status PDUs one connection keeps for Status SNACK (error recovery level >= 1) until the
/// initiator acknowledges them, by count and by bytes.
pub const MAX_STATUS_RING: usize = 256;
pub const MAX_STATUS_RING_BYTES: usize = 4 * 1024 * 1024;

/// What the operator configured.
#[derive(Debug)]
pub struct Config {
    pub accounts: Vec<Credential>,
    pub target_credential: Option<Credential>,
    pub digests: Option<DigestPreference>,
    /// This target's InitialR2T: whether non-immediate write data waits for an R2T.
    pub initial_r2t: bool,
    pub max_connections: u32,
    pub error_recovery_level: u32,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            accounts: Vec::new(),
            target_credential: None,
            digests: None,
            initial_r2t: DEFAULT_INITIAL_R2T,
            max_connections: DEFAULT_MAX_CONNECTIONS_PER_SESSION,
            error_recovery_level: DEFAULT_ERROR_RECOVERY_LEVEL,
        }
    }
}

impl Config {
    fn digests(&self) -> DigestPreference {
        self.digests.unwrap_or(DigestPreference::Either)
    }
    fn chap_required(&self) -> bool {
        !self.accounts.is_empty()
    }
    fn offer(&self) -> TargetOffer {
        TargetOffer {
            digests: self.digests(),
            initial_r2t: self.initial_r2t,
            max_connections: self.max_connections,
            error_recovery_level: self.error_recovery_level,
        }
    }
}

fn check_secret(secret: &str, what: &str) -> Result<()> {
    anyhow::ensure!(
        (MIN_SECRET..=MAX_SECRET).contains(&secret.len()),
        "{what} must be {MIN_SECRET} to {MAX_SECRET} bytes"
    );
    Ok(())
}

pub fn parse_config(ctx: &SpawnContext) -> Result<Config> {
    let mut config = Config::default();
    let Some(params) = ctx.startup_params.as_ref() else {
        return Ok(config);
    };
    if let Some(list) = params.get_optional_array("chap_accounts")? {
        for entry in list {
            let name = entry["name"]
                .as_str()
                .context("each CHAP account needs a name (a string)")?;
            let secret = entry["secret"]
                .as_str()
                .context("each CHAP account needs a secret (a string)")?;
            anyhow::ensure!(
                !name.is_empty() && name.len() <= MAX_SECRET,
                "a CHAP name is 1 to 255 bytes"
            );
            check_secret(secret, "a CHAP secret")?;
            config.accounts.push(Credential {
                name: name.into(),
                secret: secret.into(),
            });
        }
    }
    let target_name = params.get_optional_string("target_chap_name")?;
    let target_secret = params.get_optional_string("target_chap_secret")?;
    match (target_name, target_secret) {
        (Some(name), Some(secret)) => {
            check_secret(&secret, "target_chap_secret")?;
            config.target_credential = Some(Credential { name, secret });
        }
        (None, None) => {}
        _ => bail!("target_chap_name and target_chap_secret go together"),
    }
    if let Some(v) = params.get_optional_bool("initial_r2t")? {
        config.initial_r2t = v;
    }
    if let Some(d) = params.get_optional_string("digests")? {
        config.digests =
            Some(DigestPreference::parse(&d).context("digests is either, crc32c or none")?);
    }
    if let Some(n) = params.get_optional_u64("max_connections")? {
        anyhow::ensure!(
            (1..=session::MAX_CONNECTIONS_PER_SESSION as u64).contains(&n),
            "max_connections is 1 to {}",
            session::MAX_CONNECTIONS_PER_SESSION
        );
        config.max_connections = n as u32;
    }
    if let Some(n) = params.get_optional_u64("error_recovery_level")? {
        anyhow::ensure!(n <= 2, "error_recovery_level is 0, 1 or 2");
        config.error_recovery_level = n as u32;
    }
    Ok(config)
}

pub async fn spawn(ctx: SpawnContext) -> Result<SocketAddr> {
    let config = Arc::new(parse_config(&ctx)?);
    let listener = tokio::net::TcpListener::bind(ctx.legacy_listen_addr()).await?;
    let local = listener.local_addr()?;
    Log::new(Some(&ctx.status_tx)).info(format!("iSCSI target on {local}"));
    let shared = Arc::new(ctx.clone());
    let server_id = ctx.server_id;
    let registry: RegistryCell = Arc::new(Mutex::new(Registry::new()));
    // Retained sessions and tasks end when their retention does, whether or not anything
    // else happens on the server.
    let janitor = registry.clone();
    ctx.state
        .spawn_server_task(server_id, async move {
            let mut tick = tokio::time::interval(JANITOR_TICK);
            loop {
                tick.tick().await;
                lock_registry(&janitor).purge(Instant::now());
            }
        })
        .await;
    let accept = tokio::spawn(async move {
        let limiter = ConnectionLimiter::new(DEFAULT_MAX_CONNECTIONS);
        loop {
            let (stream, peer, permit) =
                match accept_bounded(&listener, &limiter, b"", "iSCSI", Some(&shared.status_tx))
                    .await
                {
                    Ok(v) => v,
                    Err(_) => break,
                };
            let _ = stream.set_nodelay(true);
            let local = stream.local_addr().unwrap_or(local);
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
            let config = config.clone();
            let registry = registry.clone();
            shared
                .state
                .spawn_server_task(server_id, async move {
                    let _permit = permit;
                    let mut c = Conn::new(&child, config, registry, id, peer, local, stream);
                    if let Err(e) = c.run().await {
                        Log::new(Some(&child.status_tx))
                            .debug(format!("iSCSI connection {id}: {e:#}"));
                    }
                    child
                        .state
                        .update_connection_status(server_id, id, ConnectionStatus::Closed)
                        .await;
                    let _ = child.status_tx.send("__UPDATE_UI__".into());
                })
                .await;
        }
    });
    ctx.state.register_server_task(server_id, accept).await;
    Ok(local)
}

/// Log how a decision went, in the `decision=` vocabulary every server shares.
fn outcome(ctx: &SpawnContext, id: ConnectionId, operation: &str, decision: &str, detail: &str) {
    let summary =
        format!("iSCSI connection {id} operation={operation} decision={decision} {detail}");
    let log = Log::new(Some(&ctx.status_tx));
    if decision.starts_with("fail_closed_") || decision == "model_silent" {
        log.error(summary);
    } else if decision == "protocol_refusal" || decision == "auth_failure" {
        log.warn(summary);
    } else {
        log.info(summary);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SessionType {
    Normal,
    Discovery,
}

/// Where CHAP stands during the security stage.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Auth {
    Start,
    /// AuthMethod=CHAP was agreed; the initiator's CHAP_A comes next.
    ChapChosen,
    /// We sent CHAP_I and CHAP_C.
    Challenged {
        id: u8,
        challenge: Vec<u8>,
    },
    /// Authenticated (as this CHAP name, or with no authentication at all).
    Done(Option<String>),
}

/// A SendTargets answer too long for one PDU, waiting for the initiator to ask for the rest.
struct TextContinuation {
    itt: u32,
    ttt: u32,
    rest: Vec<u8>,
}

/// Why login failed: the status to answer with, and how to log it.
struct LoginFailure {
    status: u16,
    decision: &'static str,
    detail: String,
}

fn fail(status: u16, decision: &'static str, detail: impl Into<String>) -> LoginFailure {
    LoginFailure {
        status,
        decision,
        detail: detail.into(),
    }
}

/// A status PDU sent and not yet acknowledged, for Status SNACK.
struct Sent {
    stat_sn: u32,
    pdu: Pdu,
    resent: u32,
}

/// One TCP connection: login, then its part of a session.
struct Conn<'a> {
    ctx: &'a SpawnContext,
    config: Arc<Config>,
    registry: RegistryCell,
    id: ConnectionId,
    peer: SocketAddr,
    local: SocketAddr,
    stream: TcpStream,
    reader: PduReader,
    /// This connection's ISID, TSIH and CID as its login named them.
    isid: [u8; 6],
    tsih: u16,
    cid: u16,
    /// A login naming a TSIH this target does not know is served as a new session under it.
    requested_tsih: Option<u16>,
    /// The negotiated parameters (the session's for the leading-only keys).
    params: Params,
    digests: Digests,
    stat_sn: u32,
    /// The initiator's ExpStatSN: every status before it is acknowledged.
    exp_stat_sn: u32,
    session_type: SessionType,
    initiator_name: String,
    target_name: String,
    authenticated: Option<String>,
    /// The model's description, between the leading login's decision and the session.
    target: Option<Arc<TargetDescription>>,
    /// The session this connection belongs to (normal sessions, after login).
    session: Option<SessionCell>,
    /// The session a login with its TSIH is adding this connection to.
    joining: Option<SessionCell>,
    /// A discovery session's own command window (it has no shared session).
    window: CommandWindow,
    wake: Arc<Notify>,
    close: CancellationToken,
    text_in: Option<(u32, Vec<u8>)>,
    text_out: Option<TextContinuation>,
    discovered: Option<Vec<(String, Vec<String>)>>,
    /// A Logout Response for this connection has been sent: the initiator closes next.
    logged_out: bool,
    /// A protocol violation ends this connection once what it owes is sent.
    hang_up: bool,
    /// A discovery session's Target Transfer Tags (a normal session's come from the session).
    local_ttt: u32,
    /// Status PDUs kept for Status SNACK (error recovery level >= 1).
    ring: VecDeque<Sent>,
    ring_bytes: usize,
}

impl<'a> Conn<'a> {
    fn new(
        ctx: &'a SpawnContext,
        config: Arc<Config>,
        registry: RegistryCell,
        id: ConnectionId,
        peer: SocketAddr,
        local: SocketAddr,
        stream: TcpStream,
    ) -> Self {
        Self {
            ctx,
            config,
            registry,
            id,
            peer,
            local,
            stream,
            reader: PduReader::new(),
            isid: [0; 6],
            tsih: 0,
            cid: 0,
            requested_tsih: None,
            params: Params::default(),
            digests: Digests::default(),
            stat_sn: 0,
            exp_stat_sn: 0,
            session_type: SessionType::Normal,
            initiator_name: String::new(),
            target_name: String::new(),
            authenticated: None,
            target: None,
            session: None,
            joining: None,
            window: CommandWindow::default(),
            wake: Arc::new(Notify::new()),
            close: CancellationToken::new(),
            text_in: None,
            text_out: None,
            discovered: None,
            logged_out: false,
            hang_up: false,
            local_ttt: 1,
            ring: VecDeque::new(),
            ring_bytes: 0,
        }
    }

    /// The session's error recovery level (discovery sessions run at 0).
    fn erl(&self) -> u32 {
        if self.session.is_some() {
            self.params.error_recovery_level
        } else {
            0
        }
    }

    async fn send(&mut self, p: &Pdu) -> Result<()> {
        let bytes = p.encode(self.digests);
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

    async fn send_all(&mut self, out: Vec<Pdu>) -> Result<()> {
        for p in &out {
            self.send(p).await?;
        }
        Ok(())
    }

    async fn received(&self, p: &Pdu) {
        self.ctx
            .state
            .update_connection_stats(
                self.ctx.server_id,
                self.id,
                Some((pdu::BHS_LEN + p.ahs.len() + p.data.len()) as u64),
                None,
                Some(1),
                None,
            )
            .await;
    }

    /// ExpCmdSN and MaxCmdSN as they stand: the session's, or a discovery session's own.
    fn numbers(&self, s: Option<&Session>) -> (u32, u32) {
        match s {
            Some(s) => (s.window.exp_cmd_sn, s.max_cmd_sn()),
            None => (
                self.window.exp_cmd_sn,
                self.window
                    .exp_cmd_sn
                    .wrapping_add(COMMAND_WINDOW)
                    .wrapping_sub(1),
            ),
        }
    }

    /// Fill StatSN (consuming one), ExpCmdSN and MaxCmdSN at their usual offsets, and keep the
    /// PDU for Status SNACK at error recovery level >= 1.
    fn stamp(&mut self, p: &mut Pdu, s: Option<&Session>) {
        let (exp, max) = self.numbers(s);
        p.set_u32(24, self.stat_sn);
        p.set_u32(28, exp);
        p.set_u32(32, max);
        if self.erl() >= 1 {
            self.keep_status(self.stat_sn, p.clone());
        }
        self.stat_sn = self.stat_sn.wrapping_add(1);
    }

    /// ExpCmdSN and MaxCmdSN only (R2T, non-final Data-In, retransmissions).
    fn window_fields(&self, p: &mut Pdu, s: Option<&Session>) {
        let (exp, max) = self.numbers(s);
        p.set_u32(28, exp);
        p.set_u32(32, max);
    }

    fn keep_status(&mut self, stat_sn: u32, p: Pdu) {
        let size = pdu::BHS_LEN + p.data.len();
        self.ring.push_back(Sent {
            stat_sn,
            pdu: p,
            resent: 0,
        });
        self.ring_bytes += size;
        while self.ring.len() > MAX_STATUS_RING || self.ring_bytes > MAX_STATUS_RING_BYTES {
            match self.ring.pop_front() {
                Some(old) => self.ring_bytes -= pdu::BHS_LEN + old.pdu.data.len(),
                None => break,
            }
        }
    }

    /// The initiator's ExpStatSN, carried by every PDU it sends: statuses before it need not
    /// be kept. A value past what was sent is ignored.
    fn acknowledge(&mut self, exp_stat_sn: u32) {
        if !pdu::sn_le(exp_stat_sn, self.stat_sn) || exp_stat_sn == self.exp_stat_sn {
            return;
        }
        if pdu::sn_lt(self.exp_stat_sn, exp_stat_sn) {
            self.exp_stat_sn = exp_stat_sn;
        }
        while let Some(front) = self.ring.front() {
            if pdu::sn_lt(front.stat_sn, exp_stat_sn) {
                let old = self.ring.pop_front().expect("front");
                self.ring_bytes -= pdu::BHS_LEN + old.pdu.data.len();
            } else {
                break;
            }
        }
        if self.erl() >= 1 {
            if let Some(s) = self.session.clone() {
                lock(&s).acknowledge(self.id, exp_stat_sn);
            }
        }
    }

    async fn run(&mut self) -> Result<()> {
        match tokio::time::timeout(LOGIN_DEADLINE, self.login()).await {
            Ok(Ok(true)) => {}
            Ok(Ok(false)) => return Ok(()),
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                outcome(
                    self.ctx,
                    self.id,
                    "login",
                    "protocol_refusal",
                    "login did not finish within 60 s",
                );
                return Ok(());
            }
        }
        let result = self.full_feature().await;
        // However the connection ended, the session learns of it (unless a logout, a reset
        // or a reinstatement already took it out).
        self.leave(Gone::Failed(Instant::now()));
        result
    }

    /// Take this connection out of its session, if it is still in it: at error recovery level
    /// 2 a failed connection's tasks wait for recovery; otherwise they end, and the other
    /// connections owe the initiator a unit attention for them (RFC 7143 §11.14.5). A session
    /// left with nothing ends.
    fn leave(&mut self, how: Gone) {
        let Some(cell) = self.session.clone() else {
            return;
        };
        let (idle, tsih) = {
            let mut s = lock(&cell);
            if s.conn(self.id).is_some_and(|c| c.life == Life::Live) {
                let others = s.live_connections() > 1;
                let luns = s.connection_gone(self.id, how);
                if others {
                    for l in luns {
                        s.unit_attention(l, Sense::COMMANDS_CLEARED_BY_ISCSI_EVENT);
                    }
                }
                for c in s.conns.iter().filter(|c| c.life == Life::Live) {
                    c.wake.notify_one();
                }
            }
            let idle = s.ended || s.idle();
            if idle {
                s.ended = true;
            }
            (idle, s.tsih)
        };
        if idle {
            let mut r = lock_registry(&self.registry);
            if r.get(tsih).is_some_and(|cur| Arc::ptr_eq(&cur, &cell)) {
                r.remove(tsih);
            }
        }
    }

    // ----------------------------------------------------------------- login

    #[allow(clippy::too_many_arguments)]
    async fn login_response(
        &mut self,
        req: &Pdu,
        transit: bool,
        csg: u8,
        nsg: u8,
        pairs: &[(String, String)],
        status: u16,
    ) -> Result<()> {
        let mut r = Pdu::new(op::LOGIN_RESPONSE);
        let mut flags = (csg << 2) & 0x0C;
        if transit {
            flags |= 0x80 | (nsg & 0x03);
        }
        r.set_flags(flags);
        r.bhs[2] = 0; // version-max
        r.bhs[3] = 0; // version-active
        r.bhs[8..14].copy_from_slice(&req.bhs[8..14]); // ISID
        if transit && nsg == stage::FULL_FEATURE && status == login_status::SUCCESS {
            r.set_u16(14, self.tsih);
        }
        r.set_itt(req.itt());
        r.set_u32(24, self.stat_sn);
        self.stat_sn = self.stat_sn.wrapping_add(1);
        let (exp, max) = match self.session.as_ref().or(self.joining.as_ref()) {
            Some(cell) => {
                let s = lock(cell);
                (s.window.exp_cmd_sn, s.max_cmd_sn())
            }
            None => self.numbers(None),
        };
        r.set_u32(28, exp);
        r.set_u32(32, max);
        r.bhs[36] = (status >> 8) as u8;
        r.bhs[37] = status as u8;
        r.data = text::encode(pairs);
        // Login PDUs never carry digests.
        let bytes = r.encode(Digests::default());
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

    /// Run the login. `Ok(true)`: full feature phase; `Ok(false)`: refused and answered.
    async fn login(&mut self) -> Result<bool> {
        let mut first = true;
        let mut csg = stage::SECURITY;
        let mut auth = Auth::Start;
        let mut text_acc: Vec<u8> = Vec::new();
        let mut declared_mrdsl = false;
        let mut sent_tpgt = false;
        let mut decided = false;
        for _ in 0..MAX_LOGIN_PDUS {
            let req = match self
                .reader
                .next(
                    &mut self.stream,
                    Digests::default(),
                    pdu::DEFAULT_MAX_RECV_DATA_SEGMENT,
                    PDU_DEADLINE,
                )
                .await
            {
                Ok(p) => p,
                Err(ReadError::Closed) => return Ok(false),
                Err(ReadError::Oversize { declared, limit }) => {
                    outcome(
                        self.ctx,
                        self.id,
                        "login",
                        "protocol_refusal",
                        &format!("a login data segment of {declared} bytes (limit {limit})"),
                    );
                    return Ok(false);
                }
                Err(e) => bail!("login: {e}"),
            };
            self.received(&req).await;
            if req.opcode() != op::LOGIN_REQUEST {
                outcome(
                    self.ctx,
                    self.id,
                    "login",
                    "protocol_refusal",
                    &format!("{} during login", op::name(req.opcode())),
                );
                if first {
                    // No login has begun, so there is nothing to answer: close, as LIO does.
                    // A Login Response here could only carry the stray PDU's ITT, which names
                    // no login (libiscsi, reconnecting, sends a queued command ahead of its
                    // Login, and that command is what arrives first).
                    let _ = self.stream.shutdown().await;
                    return Ok(false);
                }
                let f = fail(
                    login_status::INVALID_DURING_LOGIN,
                    "protocol_refusal",
                    "not a login request",
                );
                self.refuse_login(&req, csg, f).await?;
                return Ok(false);
            }
            let flags = req.flags();
            let (transit, cont) = (flags & 0x80 != 0, flags & 0x40 != 0);
            let req_csg = (flags >> 2) & 0x03;
            let nsg = flags & 0x03;
            if first {
                first = false;
                // Versions: we speak version 0 (RFC 7143 keeps it).
                let (vmax, vmin) = (req.bhs[2], req.bhs[3]);
                self.stat_sn = req.u32_at(28);
                self.exp_stat_sn = self.stat_sn;
                self.window = CommandWindow::new(req.u32_at(24));
                self.isid = req.bhs[8..14].try_into().expect("6 bytes");
                self.cid = req.u16_at(20);
                if vmin > 0 || vmax < vmin {
                    let f = fail(
                        login_status::UNSUPPORTED_VERSION,
                        "protocol_refusal",
                        format!("versions {vmin}-{vmax}"),
                    );
                    self.refuse_login(&req, req_csg, f).await?;
                    return Ok(false);
                }
                let tsih = req.u16_at(14);
                if tsih != 0 {
                    // A TSIH names the session this connection joins (another connection of
                    // it, or a reinstatement of one). A TSIH this target does not know is
                    // served as a new session under it, as an initiator reconnecting after a
                    // dropped single-connection session expects.
                    let found = lock_registry(&self.registry).get(tsih);
                    match found {
                        Some(s) if !lock(&s).ended => {
                            self.params = lock(&s).params.clone();
                            self.params.our_max_recv_data_segment =
                                pdu::DEFAULT_MAX_RECV_DATA_SEGMENT as u32;
                            self.params.peer_max_recv_data_segment =
                                pdu::DEFAULT_MAX_RECV_DATA_SEGMENT as u32;
                            self.params.header_digest = false;
                            self.params.data_digest = false;
                            self.joining = Some(s);
                        }
                        _ => self.requested_tsih = Some(tsih),
                    }
                }
                csg = req_csg;
                if csg == stage::FULL_FEATURE {
                    let f = fail(
                        login_status::INITIATOR_ERROR,
                        "protocol_refusal",
                        "a login starting in full feature phase",
                    );
                    self.refuse_login(&req, req_csg, f).await?;
                    return Ok(false);
                }
            } else if req_csg != csg {
                let f = fail(
                    login_status::INITIATOR_ERROR,
                    "protocol_refusal",
                    format!("stage {req_csg} while in stage {csg}"),
                );
                self.refuse_login(&req, csg, f).await?;
                return Ok(false);
            }
            if text_acc.len() + req.data.len() > text::MAX_TEXT {
                let f = fail(
                    login_status::INITIATOR_ERROR,
                    "protocol_refusal",
                    "more than 64 KiB of login text",
                );
                self.refuse_login(&req, csg, f).await?;
                return Ok(false);
            }
            text_acc.extend(&req.data);
            if cont {
                // More text follows: acknowledge with an empty response in the same stage.
                self.login_response(&req, false, csg, 0, &[], login_status::SUCCESS)
                    .await?;
                continue;
            }
            let pairs = match text::parse(&std::mem::take(&mut text_acc)) {
                Ok(p) => p,
                Err(e) => {
                    let f = fail(
                        login_status::INITIATOR_ERROR,
                        "protocol_refusal",
                        e.to_string(),
                    );
                    self.refuse_login(&req, csg, f).await?;
                    return Ok(false);
                }
            };
            let step = self
                .login_step(
                    csg,
                    transit,
                    nsg,
                    &pairs,
                    &mut auth,
                    &mut declared_mrdsl,
                    &mut sent_tpgt,
                    &mut decided,
                )
                .await;
            let step = match step {
                Ok((reply, Some(stage::FULL_FEATURE))) => {
                    // The session exists (or this connection joins it) before the final
                    // response, which carries its TSIH.
                    self.establish().map(|_| (reply, Some(stage::FULL_FEATURE)))
                }
                other => other,
            };
            match step {
                Ok((reply, next)) => {
                    let done = next == Some(stage::FULL_FEATURE);
                    match next {
                        Some(n) => {
                            self.login_response(&req, true, csg, n, &reply, login_status::SUCCESS)
                                .await?;
                            csg = n;
                        }
                        None => {
                            self.login_response(&req, false, csg, 0, &reply, login_status::SUCCESS)
                                .await?
                        }
                    }
                    if done {
                        self.digests = Digests {
                            header: self.params.header_digest,
                            data: self.params.data_digest,
                        };
                        outcome(
                            self.ctx,
                            self.id,
                            "login",
                            "logged_in",
                            &format!(
                                "{} session {} connection {} for {} (header digest {}, data digest {}, MaxRecvDataSegmentLength {}/{}, ErrorRecoveryLevel {}, MaxConnections {})",
                                if self.session_type == SessionType::Discovery { "discovery" } else { "normal" },
                                self.tsih,
                                self.cid,
                                self.initiator_name,
                                self.params.header_digest,
                                self.params.data_digest,
                                self.params.our_max_recv_data_segment,
                                self.params.peer_max_recv_data_segment,
                                self.erl(),
                                self.params.max_connections,
                            ),
                        );
                        return Ok(true);
                    }
                }
                Err(f) => {
                    self.refuse_login(&req, csg, f).await?;
                    return Ok(false);
                }
            }
        }
        outcome(
            self.ctx,
            self.id,
            "login",
            "protocol_refusal",
            &format!("more than {MAX_LOGIN_PDUS} login PDUs"),
        );
        Ok(false)
    }

    async fn refuse_login(&mut self, req: &Pdu, csg: u8, f: LoginFailure) -> Result<()> {
        outcome(
            self.ctx,
            self.id,
            "login",
            f.decision,
            &format!(
                "status=0x{:04x} ({}) {}",
                f.status,
                login_status::describe(f.status),
                f.detail
            ),
        );
        // A refused login answers once and closes (RFC 7143 §11.13.5).
        self.login_response(req, false, csg, 0, &[], f.status)
            .await?;
        let _ = self.stream.shutdown().await;
        Ok(())
    }

    /// One complete login request's keys: the reply keys, and the next stage when the
    /// initiator asked to move on and may.
    #[allow(clippy::too_many_arguments)]
    async fn login_step(
        &mut self,
        csg: u8,
        transit: bool,
        nsg: u8,
        pairs: &[(String, String)],
        auth: &mut Auth,
        declared_mrdsl: &mut bool,
        sent_tpgt: &mut bool,
        decided: &mut bool,
    ) -> Result<(Vec<(String, String)>, Option<u8>), LoginFailure> {
        let mut reply: Vec<(String, String)> = Vec::new();
        let offer = self.config.offer();
        // Declarative keys first, wherever they appear.
        if let Some(name) = text::get(pairs, "InitiatorName") {
            if !actions::valid_name(name) {
                return Err(fail(
                    login_status::INITIATOR_ERROR,
                    "protocol_refusal",
                    "InitiatorName is not an iSCSI name",
                ));
            }
            self.initiator_name = name.to_string();
        }
        if self.initiator_name.is_empty() {
            return Err(fail(
                login_status::MISSING_PARAMETER,
                "protocol_refusal",
                "no InitiatorName",
            ));
        }
        if let Some(t) = text::get(pairs, "SessionType") {
            self.session_type = match t {
                "Normal" => SessionType::Normal,
                "Discovery" => SessionType::Discovery,
                _ => {
                    return Err(fail(
                        login_status::SESSION_TYPE_NOT_SUPPORTED,
                        "protocol_refusal",
                        format!("SessionType={t}"),
                    ))
                }
            };
        }
        if let Some(t) = text::get(pairs, "TargetName") {
            if !actions::valid_name(t) {
                return Err(fail(
                    login_status::NOT_FOUND,
                    "protocol_refusal",
                    "TargetName is not an iSCSI name",
                ));
            }
            self.target_name = t.to_string();
        }
        if self.session_type == SessionType::Normal && self.target_name.is_empty() {
            return Err(fail(
                login_status::MISSING_PARAMETER,
                "protocol_refusal",
                "a normal session without TargetName",
            ));
        }
        if self.joining.is_some() && self.session_type == SessionType::Discovery {
            return Err(fail(
                login_status::SESSION_DOES_NOT_EXIST,
                "protocol_refusal",
                "a discovery login naming a normal session's TSIH",
            ));
        }
        if self.session_type == SessionType::Normal && !*sent_tpgt {
            reply.push(("TargetPortalGroupTag".into(), PORTAL_GROUP_TAG.to_string()));
            *sent_tpgt = true;
        }

        if csg == stage::SECURITY {
            self.security_keys(pairs, auth, &mut reply)?;
            if *auth == Auth::Start {
                // No AuthMethod offered: its default is None, which only an open target accepts.
                if self.config.chap_required() {
                    if transit {
                        return Err(fail(
                            login_status::AUTHENTICATION_FAILURE,
                            "auth_failure",
                            "no AuthMethod offered while CHAP is required",
                        ));
                    }
                } else {
                    *auth = Auth::Done(None);
                }
            }
        } else if self.config.chap_required() && !matches!(auth, Auth::Done(_)) {
            return Err(fail(
                login_status::AUTHENTICATION_FAILURE,
                "auth_failure",
                "skipped the security stage while CHAP is required",
            ));
        } else if *auth == Auth::Start {
            *auth = Auth::Done(None);
        }

        // Operational keys, in either stage.
        if csg == stage::OPERATIONAL && !*declared_mrdsl {
            self.params.our_max_recv_data_segment = text::OUR_MAX_RECV_DATA_SEGMENT;
        }
        for (k, v) in pairs {
            match k.as_str() {
                "InitiatorName" | "SessionType" | "TargetName" | "InitiatorAlias"
                | "AuthMethod" | "CHAP_A" | "CHAP_N" | "CHAP_R" | "CHAP_I" | "CHAP_C" => {}
                // A connection joining a session answers the session-wide keys with what
                // the leading login settled (RFC 7143 §13: "LO").
                key if self.joining.is_some() && text::LEADING_ONLY.contains(&key) => {
                    if let Some(v) = text::session_value(&self.params, key) {
                        reply.push((k.clone(), v));
                    }
                }
                // Discovery sessions run at error recovery level 0 (§7.4.1) with one
                // connection.
                "ErrorRecoveryLevel" if self.session_type == SessionType::Discovery => {
                    reply.push((k.clone(), "0".into()));
                }
                "MaxConnections" if self.session_type == SessionType::Discovery => {
                    reply.push((k.clone(), "Irrelevant".into()));
                }
                _ => match text::negotiate_as_target(&mut self.params, k, v, &offer) {
                    Some(answer) => {
                        if k == "MaxRecvDataSegmentLength" {
                            *declared_mrdsl = true;
                        }
                        reply.push((k.clone(), answer));
                    }
                    None => reply.push((k.clone(), "NotUnderstood".into())),
                },
            }
        }
        if csg == stage::OPERATIONAL && !*declared_mrdsl {
            reply.push((
                "MaxRecvDataSegmentLength".into(),
                self.params.our_max_recv_data_segment.to_string(),
            ));
            *declared_mrdsl = true;
        }

        if !transit {
            return Ok((reply, None));
        }
        if nsg <= csg || nsg == 2 {
            return Err(fail(
                login_status::INITIATOR_ERROR,
                "protocol_refusal",
                format!("a transit from stage {csg} to {nsg}"),
            ));
        }
        if !matches!(auth, Auth::Done(_)) {
            // Still authenticating: stay in the security stage.
            return Ok((reply, None));
        }
        if let Auth::Done(user) = auth {
            self.authenticated = user.clone();
        }
        if self.session_type == SessionType::Normal && !*decided {
            *decided = true;
            if self.joining.is_some() {
                // Another connection of a session the model already admitted: Rust checks it
                // belongs, and the model is not asked again.
                self.check_join()?;
            } else {
                match self.ask_login().await {
                    Ok(t) => self.target = Some(t),
                    Err(f) => return Err(f),
                }
            }
        }
        if nsg == stage::FULL_FEATURE {
            // The alias goes in the final response, where an initiator records the session.
            if let Some(alias) = self.target.as_ref().and_then(|t| t.alias.clone()) {
                reply.push(("TargetAlias".into(), alias));
            }
        }
        Ok((reply, Some(nsg)))
    }

    /// A login adding a connection to an existing session: same initiator port and target,
    /// the same CHAP identity, and within the session's MaxConnections (a reinstatement of one
    /// of its CIDs replaces that connection rather than adding one).
    fn check_join(&mut self) -> Result<(), LoginFailure> {
        let Some(cell) = self.joining.clone() else {
            return Ok(());
        };
        let s = lock(&cell);
        if s.ended
            || s.nexus.initiator != self.initiator_name
            || s.nexus.isid != self.isid
            || s.nexus.target != self.target_name
        {
            return Err(fail(
                login_status::SESSION_DOES_NOT_EXIST,
                "protocol_refusal",
                "a TSIH that names another initiator's or another target's session",
            ));
        }
        if self.config.chap_required() && s.authenticated != self.authenticated {
            return Err(fail(
                login_status::AUTHORIZATION_FAILURE,
                "auth_failure",
                "a connection authenticated as another CHAP user than its session",
            ));
        }
        let reinstating = s
            .conns
            .iter()
            .any(|c| c.cid == self.cid && c.life == Life::Live);
        let live = s.live_connections();
        if !reinstating && live as u32 >= s.params.max_connections {
            return Err(fail(
                login_status::TOO_MANY_CONNECTIONS,
                "protocol_refusal",
                format!(
                    "session {} already has {live} of MaxConnections {}",
                    s.tsih, s.params.max_connections
                ),
            ));
        }
        self.target = Some(s.target.clone());
        Ok(())
    }

    /// Bring the session up as the login completes: a new one (replacing any session of the
    /// same I_T nexus — session reinstatement, RFC 7143 §6.3.5), or this connection added to
    /// the session it named (replacing a connection of the same CID — connection
    /// reinstatement, §6.3.4).
    fn establish(&mut self) -> Result<(), LoginFailure> {
        let now = Instant::now();
        if self.session_type == SessionType::Discovery {
            self.tsih = lock_registry(&self.registry)
                .allocate_tsih()
                .ok_or_else(|| {
                    fail(
                        login_status::OUT_OF_RESOURCES,
                        "protocol_refusal",
                        "no TSIH left",
                    )
                })?;
            return Ok(());
        }
        let slot = ConnSlot {
            cid: self.cid,
            id: self.id,
            wake: self.wake.clone(),
            close: self.close.clone(),
            life: Life::Live,
        };
        if let Some(cell) = self.joining.take() {
            let mut s = lock(&cell);
            if s.ended {
                return Err(fail(
                    login_status::SESSION_DOES_NOT_EXIST,
                    "protocol_refusal",
                    "the session ended during the login",
                ));
            }
            // Connection reinstatement: the old connection of this CID is logged out
            // implicitly — for recovery at error recovery level 2, closed below it.
            if let Some(old) = s
                .conns
                .iter()
                .find(|c| c.cid == self.cid && c.life == Life::Live)
                .map(|c| (c.id, c.close.clone()))
            {
                old.1.cancel();
                let how = if s.erl() >= 2 {
                    Gone::Recovering(now)
                } else {
                    Gone::Closed
                };
                let luns = s.connection_gone(old.0, how);
                for l in luns {
                    s.unit_attention(l, Sense::COMMANDS_CLEARED_BY_ISCSI_EVENT);
                }
                outcome(
                    self.ctx,
                    self.id,
                    "login",
                    "reinstated",
                    &format!("connection {} of session {} replaced", self.cid, s.tsih),
                );
            }
            s.conns.push(slot);
            self.tsih = s.tsih;
            // The leading-only keys stay the session's whatever this login said.
            let own = self.params.clone();
            self.params = Params {
                header_digest: own.header_digest,
                data_digest: own.data_digest,
                peer_max_recv_data_segment: own.peer_max_recv_data_segment,
                our_max_recv_data_segment: own.our_max_recv_data_segment,
                ..s.params.clone()
            };
            drop(s);
            self.session = Some(cell);
            return Ok(());
        }
        let Some(target) = self.target.clone() else {
            return Err(fail(
                login_status::TARGET_ERROR,
                "fail_closed_invalid_reply",
                "no target description",
            ));
        };
        let nexus = Nexus {
            initiator: self.initiator_name.clone(),
            isid: self.isid,
            target: self.target_name.clone(),
        };
        let mut reg = lock_registry(&self.registry);
        reg.purge(now);
        // Session reinstatement: the nexus's old session ends, its tasks with it.
        if let Some(old) = reg.by_nexus(&nexus) {
            let tsih = {
                let mut o = lock(&old);
                o.ended = true;
                for c in &o.conns {
                    c.close.cancel();
                }
                o.tsih
            };
            reg.remove(tsih);
            outcome(
                self.ctx,
                self.id,
                "login",
                "reinstated",
                &format!("session {tsih} of {} replaced", nexus.initiator),
            );
        }
        if reg.len() >= session::MAX_SESSIONS {
            return Err(fail(
                login_status::OUT_OF_RESOURCES,
                "protocol_refusal",
                format!("{} sessions already", session::MAX_SESSIONS),
            ));
        }
        let tsih = match self.requested_tsih.filter(|t| reg.get(*t).is_none()) {
            Some(t) => t,
            None => reg.allocate_tsih().ok_or_else(|| {
                fail(
                    login_status::OUT_OF_RESOURCES,
                    "protocol_refusal",
                    "no TSIH left",
                )
            })?,
        };
        let owed = reg.take_owed(&nexus);
        let mut s = Session::new(
            tsih,
            nexus,
            self.authenticated.clone(),
            target,
            self.params.clone(),
            self.window.exp_cmd_sn,
        );
        for sense in owed {
            s.unit_attention_all(sense);
        }
        s.conns.push(slot);
        let cell: SessionCell = Arc::new(Mutex::new(s));
        reg.insert(tsih, cell.clone());
        drop(reg);
        self.tsih = tsih;
        self.session = Some(cell);
        Ok(())
    }

    fn security_keys(
        &mut self,
        pairs: &[(String, String)],
        auth: &mut Auth,
        reply: &mut Vec<(String, String)>,
    ) -> Result<(), LoginFailure> {
        let auth_fail = |detail: &str| {
            Err(fail(
                login_status::AUTHENTICATION_FAILURE,
                "auth_failure",
                detail.to_string(),
            ))
        };
        if let Some(methods) = text::get(pairs, "AuthMethod") {
            let offered: Vec<&str> = methods.split(',').collect();
            if self.config.chap_required() {
                if !offered.contains(&"CHAP") {
                    return auth_fail("CHAP is required and the initiator does not offer it");
                }
                reply.push(("AuthMethod".into(), "CHAP".into()));
                *auth = Auth::ChapChosen;
            } else if offered.contains(&"None") {
                reply.push(("AuthMethod".into(), "None".into()));
                *auth = Auth::Done(None);
            } else {
                return auth_fail(
                    "no CHAP accounts are configured and the initiator requires authentication",
                );
            }
        }
        if let Some(algorithms) = text::get(pairs, "CHAP_A") {
            if *auth != Auth::ChapChosen {
                return auth_fail("CHAP_A out of turn");
            }
            if !algorithms.split(',').any(|a| a == chap::ALGORITHM_MD5) {
                return auth_fail("the initiator offers no CHAP algorithm but MD5");
            }
            let (id, challenge) = chap::challenge();
            reply.push(("CHAP_A".into(), chap::ALGORITHM_MD5.into()));
            reply.push(("CHAP_I".into(), id.to_string()));
            reply.push(("CHAP_C".into(), chap::encode_binary(&challenge)));
            *auth = Auth::Challenged {
                id,
                challenge: challenge.to_vec(),
            };
        }
        let (name, response) = (text::get(pairs, "CHAP_N"), text::get(pairs, "CHAP_R"));
        if name.is_some() || response.is_some() {
            let Auth::Challenged { id, challenge } = auth.clone() else {
                return auth_fail("a CHAP response before a challenge");
            };
            let (Some(name), Some(response)) = (name, response) else {
                return auth_fail("CHAP_N without CHAP_R");
            };
            let Some(response) = chap::decode_binary(response) else {
                return auth_fail("CHAP_R is not a binary value");
            };
            // Look at every account, so the time taken says nothing about which names exist.
            let mut matched = false;
            for account in &self.config.accounts {
                let expected = chap::response(id, account.secret.as_bytes(), &challenge);
                let ok = chap::same(&expected, &response);
                matched |= ok && account.name == name;
            }
            if !matched {
                return auth_fail(&format!("CHAP response for {name:?} did not verify"));
            }
            // Mutual CHAP: the initiator challenges us back.
            if let (Some(i), Some(c)) = (text::get(pairs, "CHAP_I"), text::get(pairs, "CHAP_C")) {
                let Some(target) = self.config.target_credential.clone() else {
                    return auth_fail("the initiator asks for mutual CHAP and no target_chap_secret is configured");
                };
                let Ok(their_id) = i.parse::<u8>() else {
                    return auth_fail("CHAP_I is not 0-255");
                };
                let Some(their_challenge) = chap::decode_binary(c) else {
                    return auth_fail("CHAP_C is not a binary value");
                };
                if chap::same(&their_challenge, &challenge) {
                    return auth_fail("the initiator reflected our own challenge");
                }
                let r = chap::response(their_id, target.secret.as_bytes(), &their_challenge);
                reply.push(("CHAP_N".into(), target.name.clone()));
                reply.push(("CHAP_R".into(), chap::encode_binary(&r)));
            }
            *auth = Auth::Done(Some(name.to_string()));
            outcome(
                self.ctx,
                self.id,
                "chap",
                "authenticated",
                &format!("as {name}"),
            );
        }
        Ok(())
    }

    /// Ask the model whether this initiator may log in to the target, and what it contains.
    async fn ask_login(&mut self) -> Result<Arc<TargetDescription>, LoginFailure> {
        let event = Event::new(
            &actions::LOGIN_EVENT,
            json!({
                "initiator_name": self.initiator_name,
                "target_name": self.target_name,
                "initiator_address": self.peer.to_string(),
                "authenticated_user": self.authenticated,
            }),
        );
        let answer = match self.ask(&event).await {
            Ok(a) => a,
            Err(f) => return Err(f),
        };
        match answer["type"].as_str() {
            Some(actions::ACCEPT_LOGIN) => {
                match TargetDescription::from_action(&answer, &self.target_name) {
                    Ok(t) => {
                        outcome(
                            self.ctx,
                            self.id,
                            "login",
                            "model_answer",
                            &format!(
                                "{} admitted to {} with {} LUN(s)",
                                self.initiator_name,
                                self.target_name,
                                t.luns.len()
                            ),
                        );
                        Ok(Arc::new(t))
                    }
                    Err(e) => Err(fail(
                        login_status::TARGET_ERROR,
                        "fail_closed_invalid_reply",
                        format!("{e:#}"),
                    )),
                }
            }
            Some(actions::REJECT_LOGIN) => {
                let status = if answer["reason"] == "not_found" {
                    login_status::NOT_FOUND
                } else {
                    login_status::AUTHORIZATION_FAILURE
                };
                Err(fail(status, "model_reject", ""))
            }
            _ => Err(fail(
                login_status::TARGET_ERROR,
                "fail_closed_invalid_reply",
                "an answer that is not a login decision",
            )),
        }
    }

    /// One model call that must produce exactly one answer.
    async fn ask(&mut self, event: &Event) -> Result<serde_json::Value, LoginFailure> {
        let result = match call_llm(
            &self.ctx.llm_client,
            &self.ctx.state,
            self.ctx.server_id,
            Some(self.id),
            event,
            &actions::IscsiProtocol,
        )
        .await
        {
            Ok(r) => r,
            Err(e) => {
                let status = match WireFailure::classify(&e) {
                    WireFailure::Overloaded => login_status::SERVICE_UNAVAILABLE,
                    WireFailure::Unavailable => login_status::TARGET_ERROR,
                };
                return Err(fail(status, "fail_closed_llm_error", ""));
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
            return Err(fail(login_status::TARGET_ERROR, "model_silent", ""));
        }
        if answers.len() != 1 || !result.failures.is_empty() {
            return Err(fail(
                login_status::TARGET_ERROR,
                "fail_closed_invalid_reply",
                "not exactly one valid answer",
            ));
        }
        Ok(answers.remove(0))
    }
}
