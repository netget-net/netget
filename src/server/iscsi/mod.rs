//! iSCSI target (RFC 7143). Rust owns the wire — PDU framing and digests, login and text-key
//! negotiation, CHAP, sequence numbers, R2T and Data-In/Out, task management and the SCSI
//! block commands; the model decides which targets discovery reveals, who may log in, and what
//! each LUN contains. Every SCSI command is served from the model's description without
//! another model call.
pub mod actions;
pub mod chap;
pub mod lun;
pub mod pdu;
pub mod text;

use crate::llm::action_helper::call_llm;
use crate::llm::actions::protocol_trait::ActionResult;
use crate::logging::emit::Log;
use crate::protocol::{Event, SpawnContext};
use crate::server::accept_bounded::{accept_bounded, ConnectionLimiter, DEFAULT_MAX_CONNECTIONS};
use crate::server::connection::ConnectionId;
use crate::server::scsi_common::{self as scsi, opcode, status, Sense};
use crate::state::server::{ConnectionState, ConnectionStatus, ProtocolConnectionInfo};
use crate::utils::clock::Instant;
use crate::utils::wire_failure::WireFailure;
use anyhow::{bail, Context, Result};
use chap::Credential;
use lun::{Lun, Overlay, TargetDescription};
use pdu::{login_status, op, reject, stage, Digests, Pdu, ReadError, RESERVED_TAG};
use serde_json::json;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use text::{DigestPreference, Params};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

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
/// A CHAP secret's length bounds (RFC 7143 §12.1.3 requires at least 12 bytes for CHAP over
/// an unprotected link; the 255-byte ceiling is ours).
pub const MIN_SECRET: usize = 12;
pub const MAX_SECRET: usize = 255;
/// The target portal group every portal of this server belongs to.
pub const PORTAL_GROUP_TAG: u16 = 1;

/// What the operator configured.
#[derive(Debug)]
pub struct Config {
    pub accounts: Vec<Credential>,
    pub target_credential: Option<Credential>,
    pub digests: Option<DigestPreference>,
    /// This target's InitialR2T: whether non-immediate write data waits for an R2T.
    pub initial_r2t: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            accounts: Vec::new(),
            target_credential: None,
            digests: None,
            initial_r2t: DEFAULT_INITIAL_R2T,
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
    Ok(config)
}

pub async fn spawn(ctx: SpawnContext) -> Result<SocketAddr> {
    let config = Arc::new(parse_config(&ctx)?);
    let listener = tokio::net::TcpListener::bind(ctx.legacy_listen_addr()).await?;
    let local = listener.local_addr()?;
    Log::new(Some(&ctx.status_tx)).info(format!("iSCSI target on {local}"));
    let shared = Arc::new(ctx.clone());
    let server_id = ctx.server_id;
    let accept = tokio::spawn(async move {
        let limiter = ConnectionLimiter::new(DEFAULT_MAX_CONNECTIONS);
        let mut next_tsih: u16 = 1;
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
            let tsih = next_tsih;
            next_tsih = next_tsih.checked_add(1).unwrap_or(1);
            let child = shared.clone();
            let config = config.clone();
            shared
                .state
                .spawn_server_task(server_id, async move {
                    let _permit = permit;
                    let mut c = Conn::new(&child, config, id, peer, local, stream, tsih);
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

/// A write waiting for its data.
struct PendingWrite {
    lun: u16,
    lba: u64,
    expected: usize,
    buf: Vec<u8>,
    /// Unsolicited data still allowed to arrive (TTT 0xffffffff), and the DataSN expected.
    unsolicited_open: bool,
    unsolicited_limit: usize,
    unsolicited_data_sn: u32,
    /// The R2T outstanding: its TTT, where it ends, and the DataSN expected next.
    r2t: Option<(u32, usize, u32)>,
    r2t_sn: u32,
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

struct Conn<'a> {
    ctx: &'a SpawnContext,
    config: Arc<Config>,
    id: ConnectionId,
    peer: SocketAddr,
    local: SocketAddr,
    stream: TcpStream,
    tsih: u16,
    params: Params,
    digests: Digests,
    stat_sn: u32,
    exp_cmd_sn: u32,
    session_type: SessionType,
    initiator_name: String,
    target_name: String,
    authenticated: Option<String>,
    target: Option<Arc<TargetDescription>>,
    overlay: Overlay,
    pending: HashMap<u32, PendingWrite>,
    next_ttt: u32,
    text_in: Option<(u32, Vec<u8>)>,
    text_out: Option<TextContinuation>,
    discovered: Option<Vec<(String, Vec<String>)>>,
    /// CmdSNs an ABORT TASK named before the command arrived; dropped when they do.
    aborted_before_arrival: Vec<u32>,
    /// A Logout Response has been sent: the initiator closes next.
    logged_out: bool,
}

impl<'a> Conn<'a> {
    fn new(
        ctx: &'a SpawnContext,
        config: Arc<Config>,
        id: ConnectionId,
        peer: SocketAddr,
        local: SocketAddr,
        stream: TcpStream,
        tsih: u16,
    ) -> Self {
        Self {
            ctx,
            config,
            id,
            peer,
            local,
            stream,
            tsih,
            params: Params::default(),
            digests: Digests::default(),
            stat_sn: 0,
            exp_cmd_sn: 0,
            session_type: SessionType::Normal,
            initiator_name: String::new(),
            target_name: String::new(),
            authenticated: None,
            target: None,
            overlay: Overlay::default(),
            pending: HashMap::new(),
            next_ttt: 1,
            text_in: None,
            text_out: None,
            discovered: None,
            aborted_before_arrival: Vec::new(),
            logged_out: false,
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

    /// MaxCmdSN: the window shrinks by the writes still waiting for data.
    fn max_cmd_sn(&self) -> u32 {
        let open = COMMAND_WINDOW.saturating_sub(self.pending.len() as u32);
        self.exp_cmd_sn.wrapping_add(open).wrapping_sub(1)
    }

    /// Fill StatSN (consuming one), ExpCmdSN and MaxCmdSN at their usual offsets.
    fn status_fields(&mut self, p: &mut Pdu) {
        p.set_u32(24, self.stat_sn);
        self.stat_sn = self.stat_sn.wrapping_add(1);
        p.set_u32(28, self.exp_cmd_sn);
        p.set_u32(32, self.max_cmd_sn());
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
        self.full_feature().await
    }

    // ----------------------------------------------------------------- login

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
        self.status_fields(&mut r);
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
            let req = match pdu::read_pdu(
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
                self.exp_cmd_sn = req.u32_at(24);
                if vmin > 0 || vmax < vmin {
                    let f = fail(
                        login_status::UNSUPPORTED_VERSION,
                        "protocol_refusal",
                        format!("versions {vmin}-{vmax}"),
                    );
                    self.refuse_login(&req, req_csg, f).await?;
                    return Ok(false);
                }
                if req.u16_at(14) != 0 {
                    // A login naming a session's TSIH reinstates it. At error recovery level 0
                    // nothing of the old connection survives (its writes went with it), so it
                    // starts afresh under the TSIH the initiator asked for, as an initiator
                    // that reconnects after a dropped connection expects.
                    self.tsih = req.u16_at(14);
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
            match self
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
                .await
            {
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
                                "{} session for {} (header digest {}, data digest {}, MaxRecvDataSegmentLength {}/{})",
                                if self.session_type == SessionType::Discovery { "discovery" } else { "normal" },
                                self.initiator_name,
                                self.params.header_digest,
                                self.params.data_digest,
                                self.params.our_max_recv_data_segment,
                                self.params.peer_max_recv_data_segment
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
        let digests = self.config.digests();
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
                _ => match text::negotiate_as_target(
                    &mut self.params,
                    k,
                    v,
                    digests,
                    self.config.initial_r2t,
                ) {
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
            match self.ask_login().await {
                Ok(t) => self.target = Some(t),
                Err(f) => return Err(f),
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

    // ----------------------------------------------------------- full feature

    async fn full_feature(&mut self) -> Result<()> {
        loop {
            let req = match pdu::read_pdu(
                &mut self.stream,
                self.digests,
                self.params.our_max_recv_data_segment as usize,
                PDU_DEADLINE,
            )
            .await
            {
                Ok(p) => p,
                Err(ReadError::Closed) => return Ok(()),
                Err(ReadError::Oversize { declared, limit }) => {
                    outcome(
                        self.ctx,
                        self.id,
                        "pdu",
                        "protocol_refusal",
                        &format!("a data segment of {declared} bytes over MaxRecvDataSegmentLength {limit}"),
                    );
                    let _ = self.stream.shutdown().await;
                    return Ok(());
                }
                Err(ReadError::DataDigest(p)) => {
                    // The PDU was read whole, so the stream is in step: reject it alone.
                    outcome(
                        self.ctx,
                        self.id,
                        "pdu",
                        "protocol_refusal",
                        "data digest mismatch",
                    );
                    self.reject(&p, reject::DATA_DIGEST_ERROR).await?;
                    continue;
                }
                Err(ReadError::HeaderDigest) => {
                    outcome(
                        self.ctx,
                        self.id,
                        "pdu",
                        "protocol_refusal",
                        "header digest mismatch; the stream cannot be trusted",
                    );
                    let _ = self.stream.shutdown().await;
                    return Ok(());
                }
                Err(e) => bail!("{e}"),
            };
            self.received(&req).await;
            if !self.dispatch(req).await? {
                if self.logged_out {
                    // The initiator closes after reading the Logout Response (RFC 7143
                    // §11.15); closing first races it, and libiscsi reads the hang-up as a
                    // dropped connection and logs in again. Wait for its close, bounded.
                    let mut sink = [0u8; 512];
                    let _ = tokio::time::timeout(LOGOUT_LINGER, async {
                        while matches!(self.stream.read(&mut sink).await, Ok(n) if n > 0) {}
                    })
                    .await;
                }
                let _ = self.stream.shutdown().await;
                return Ok(());
            }
        }
    }

    /// Whether a command-bearing PDU is in sequence. A non-immediate command must carry
    /// ExpCmdSN; anything else is outside the window and silently dropped (RFC 7143 §4.2.2.1).
    fn admit(&mut self, req: &Pdu) -> bool {
        let cmd_sn = req.u32_at(24);
        if req.immediate() {
            return true;
        }
        if cmd_sn == self.exp_cmd_sn {
            self.exp_cmd_sn = self.exp_cmd_sn.wrapping_add(1);
            if let Some(i) = self
                .aborted_before_arrival
                .iter()
                .position(|c| *c == cmd_sn)
            {
                self.aborted_before_arrival.swap_remove(i);
                outcome(
                    self.ctx,
                    self.id,
                    "sequence",
                    "aborted",
                    &format!("CmdSN {cmd_sn} was aborted before it arrived: dropped"),
                );
                return false;
            }
            return true;
        }
        outcome(
            self.ctx,
            self.id,
            "sequence",
            "protocol_refusal",
            &format!(
                "{} with CmdSN {cmd_sn} while ExpCmdSN is {}: dropped",
                op::name(req.opcode()),
                self.exp_cmd_sn
            ),
        );
        false
    }

    /// Returns false to end the connection.
    async fn dispatch(&mut self, req: Pdu) -> Result<bool> {
        match req.opcode() {
            op::NOP_OUT => {
                if req.itt() == RESERVED_TAG {
                    // A ping answer or a bare ExpStatSN update: nothing to say.
                    return Ok(true);
                }
                if !self.admit(&req) {
                    return Ok(true);
                }
                let mut r = Pdu::new(op::NOP_IN);
                r.set_flags(0x80);
                r.set_lun(req.lun());
                r.set_itt(req.itt());
                r.set_u32(20, RESERVED_TAG);
                self.status_fields(&mut r);
                r.data = req.data;
                self.send(&r).await?;
                Ok(true)
            }
            op::SCSI_COMMAND => {
                if self.session_type == SessionType::Discovery {
                    self.reject(&req, reject::COMMAND_NOT_SUPPORTED).await?;
                    return Ok(true);
                }
                if !self.admit(&req) {
                    return Ok(true);
                }
                self.scsi_command(req).await
            }
            op::DATA_OUT => self.data_out(req).await,
            op::TASK_MGMT_REQUEST => {
                if !self.admit(&req) {
                    return Ok(true);
                }
                self.task_management(req).await
            }
            op::TEXT_REQUEST => {
                if !self.admit(&req) {
                    return Ok(true);
                }
                self.text_request(req).await
            }
            op::LOGOUT_REQUEST => {
                if !self.admit(&req) {
                    return Ok(true);
                }
                let reason = req.flags() & 0x7F;
                let mut r = Pdu::new(op::LOGOUT_RESPONSE);
                r.set_flags(0x80);
                // Close the session or this connection (its only one) succeeds; removing a
                // connection for recovery is not supported at error recovery level 0.
                r.bhs[2] = if reason == 2 { 2 } else { 0 };
                r.set_itt(req.itt());
                self.status_fields(&mut r);
                r.set_u16(40, self.params.default_time2wait as u16);
                r.set_u16(42, self.params.default_time2retain as u16);
                self.send(&r).await?;
                outcome(
                    self.ctx,
                    self.id,
                    "logout",
                    "logged_out",
                    &format!("reason {reason}"),
                );
                self.logged_out = reason != 2;
                Ok(reason == 2)
            }
            op::SNACK_REQUEST => {
                // Error recovery level 0 has no SNACK.
                self.reject(&req, reject::PROTOCOL_ERROR).await?;
                Ok(true)
            }
            other => {
                outcome(
                    self.ctx,
                    self.id,
                    "pdu",
                    "protocol_refusal",
                    &format!("opcode 0x{other:02x} ({})", op::name(other)),
                );
                self.reject(&req, reject::COMMAND_NOT_SUPPORTED).await?;
                Ok(true)
            }
        }
    }

    async fn reject(&mut self, req: &Pdu, reason: u8) -> Result<()> {
        let mut r = Pdu::new(op::REJECT);
        r.set_flags(0x80);
        r.bhs[2] = reason;
        r.set_itt(RESERVED_TAG);
        self.status_fields(&mut r);
        r.data = req.bhs.to_vec();
        self.send(&r).await
    }

    // ------------------------------------------------------------ SCSI

    /// SCSI Response: status, sense, residual and how many Data-In PDUs went before it.
    async fn respond(
        &mut self,
        itt: u32,
        st: u8,
        sense: Option<Sense>,
        residual: (u8, u32),
        exp_data_sn: u32,
    ) -> Result<()> {
        let mut r = Pdu::new(op::SCSI_RESPONSE);
        r.set_flags(0x80 | residual.0);
        r.bhs[2] = 0; // command completed at target
        r.bhs[3] = st;
        r.set_itt(itt);
        self.status_fields(&mut r);
        r.set_u32(36, exp_data_sn);
        r.set_u32(44, residual.1);
        if let Some(s) = sense {
            let fixed = s.fixed();
            r.data = (fixed.len() as u16).to_be_bytes().to_vec();
            r.data.extend(fixed);
        }
        self.send(&r).await
    }

    async fn check_condition(&mut self, itt: u32, sense: Sense, edtl: u32) -> Result<bool> {
        // Nothing moved, so all of the expected transfer is residual.
        let residual = if edtl > 0 { (0x02, edtl) } else { (0, 0) };
        self.respond(itt, status::CHECK_CONDITION, Some(sense), residual, 0)
            .await?;
        Ok(true)
    }

    /// Send `data` as Data-In for a command that expected `edtl` bytes, collapsing GOOD status
    /// into the last PDU.
    async fn data_in(&mut self, itt: u32, lun: [u8; 8], data: &[u8], edtl: u32) -> Result<()> {
        let edtl = edtl as usize;
        let send_len = data.len().min(edtl);
        let residual = if data.len() > edtl {
            (0x04u8, (data.len() - edtl) as u32)
        } else if data.len() < edtl {
            (0x02u8, (edtl - data.len()) as u32)
        } else {
            (0, 0)
        };
        if send_len == 0 {
            return self.respond(itt, status::GOOD, None, residual, 0).await;
        }
        let max_pdu = (self.params.peer_max_recv_data_segment as usize).max(512);
        let burst = (self.params.max_burst as usize).max(max_pdu);
        let mut offset = 0usize;
        let mut data_sn = 0u32;
        while offset < send_len {
            let burst_end = ((offset / burst) + 1) * burst;
            let end = (offset + max_pdu).min(send_len).min(burst_end);
            let last = end == send_len;
            let mut r = Pdu::new(op::DATA_IN);
            let mut flags = 0u8;
            if last || end == burst_end {
                flags |= 0x80;
            }
            r.set_lun(lun);
            r.set_itt(itt);
            r.set_u32(20, RESERVED_TAG);
            if last {
                flags |= 0x01 | residual.0;
                r.bhs[3] = status::GOOD;
                self.status_fields(&mut r);
                r.set_u32(44, residual.1);
            } else {
                r.set_u32(28, self.exp_cmd_sn);
                r.set_u32(32, self.max_cmd_sn());
            }
            r.set_flags(flags);
            r.set_u32(36, data_sn);
            r.set_u32(40, offset as u32);
            r.data = data[offset..end].to_vec();
            self.send(&r).await?;
            data_sn += 1;
            offset = end;
        }
        Ok(())
    }

    async fn scsi_command(&mut self, req: Pdu) -> Result<bool> {
        let itt = req.itt();
        let edtl = req.u32_at(20);
        let lun_field = req.lun();
        let cdb: [u8; 16] = req.bhs[32..48].try_into()?;
        let op_code = cdb[0];
        if !req.ahs.is_empty() {
            // An extended CDB (AHS type 1) or bidirectional read length: neither is supported.
            return self
                .check_condition(itt, Sense::INVALID_FIELD_IN_CDB, edtl)
                .await;
        }
        let Some(target) = self.target.clone() else {
            return self
                .check_condition(itt, Sense::LUN_NOT_SUPPORTED, edtl)
                .await;
        };
        let lun_number = scsi::lun_from_field(&lun_field);
        let lun = lun_number.and_then(|n| target.lun(n)).cloned();
        if op_code == opcode::REPORT_LUNS {
            let alloc = u32::from_be_bytes(cdb[6..10].try_into()?);
            if alloc < 16 {
                return self
                    .check_condition(itt, Sense::INVALID_FIELD_IN_CDB, edtl)
                    .await;
            }
            let numbers: Vec<u16> = target.luns.iter().map(|l| l.number).collect();
            let mut d = scsi::report_luns(&numbers);
            d.truncate(alloc as usize);
            self.data_in(itt, lun_field, &d, edtl).await?;
            return Ok(true);
        }
        if op_code == opcode::INQUIRY && lun.is_none() {
            // INQUIRY answers for any LUN: qualifier 3 says nothing is there.
            let alloc = u16::from_be_bytes([cdb[3], cdb[4]]) as usize;
            let mut d = scsi::absent_lun_inquiry();
            d.truncate(alloc);
            self.data_in(itt, lun_field, &d, edtl).await?;
            return Ok(true);
        }
        if op_code == opcode::REQUEST_SENSE && lun.is_none() {
            let alloc = cdb[4] as usize;
            let mut d = Sense::LUN_NOT_SUPPORTED.fixed().to_vec();
            d.truncate(alloc);
            self.data_in(itt, lun_field, &d, edtl).await?;
            return Ok(true);
        }
        let Some(lun) = lun else {
            return self
                .check_condition(itt, Sense::LUN_NOT_SUPPORTED, edtl)
                .await;
        };
        match op_code {
            opcode::TEST_UNIT_READY
            | opcode::START_STOP_UNIT
            | opcode::PREVENT_ALLOW_MEDIUM_REMOVAL => {
                let residual = if edtl > 0 { (0x02, edtl) } else { (0, 0) };
                self.respond(itt, status::GOOD, None, residual, 0).await?;
            }
            opcode::REQUEST_SENSE => {
                let alloc = cdb[4] as usize;
                let mut d = Sense::NO_SENSE.fixed().to_vec();
                d.truncate(alloc);
                self.data_in(itt, lun_field, &d, edtl).await?;
            }
            opcode::INQUIRY => match self.inquiry(&lun, &cdb) {
                Ok(d) => self.data_in(itt, lun_field, &d, edtl).await?,
                Err(s) => return self.check_condition(itt, s, edtl).await,
            },
            opcode::READ_CAPACITY_10 => {
                let d = scsi::read_capacity_10(lun.last_lba(), lun.block_size);
                self.data_in(itt, lun_field, &d, edtl).await?;
            }
            opcode::SERVICE_ACTION_IN_16 if cdb[1] & 0x1F == scsi::SA_READ_CAPACITY_16 => {
                let alloc = u32::from_be_bytes(cdb[10..14].try_into()?) as usize;
                let mut d = scsi::read_capacity_16(lun.last_lba(), lun.block_size).to_vec();
                d.truncate(alloc);
                self.data_in(itt, lun_field, &d, edtl).await?;
            }
            opcode::MODE_SENSE_6 | opcode::MODE_SENSE_10 => match mode_sense(&lun, &cdb) {
                Ok(d) => self.data_in(itt, lun_field, &d, edtl).await?,
                Err(s) => return self.check_condition(itt, s, edtl).await,
            },
            opcode::SYNCHRONIZE_CACHE_10 | opcode::SYNCHRONIZE_CACHE_16 => {
                let (lba, blocks) = if op_code == opcode::SYNCHRONIZE_CACHE_10 {
                    (
                        u32::from_be_bytes(cdb[2..6].try_into()?) as u64,
                        u16::from_be_bytes([cdb[7], cdb[8]]) as u64,
                    )
                } else {
                    (
                        u64::from_be_bytes(cdb[2..10].try_into()?),
                        u32::from_be_bytes(cdb[10..14].try_into()?) as u64,
                    )
                };
                // Zero blocks means "to the end of the medium".
                if !lun.in_range(lba, blocks.max(if lba < lun.blocks { 0 } else { 1 })) {
                    return self
                        .check_condition(itt, Sense::LBA_OUT_OF_RANGE, edtl)
                        .await;
                }
                let residual = if edtl > 0 { (0x02, edtl) } else { (0, 0) };
                self.respond(itt, status::GOOD, None, residual, 0).await?;
            }
            _ => match scsi::decode_read_write(&cdb) {
                Some(rw) if rw.write => return self.write(req, &lun, rw).await,
                Some(rw) => {
                    if rw.protect != 0 {
                        return self
                            .check_condition(itt, Sense::INVALID_FIELD_IN_CDB, edtl)
                            .await;
                    }
                    if !lun.in_range(rw.lba, rw.blocks as u64) {
                        return self
                            .check_condition(itt, Sense::LBA_OUT_OF_RANGE, edtl)
                            .await;
                    }
                    let bytes = rw.blocks as u64 * lun.block_size as u64;
                    if bytes > MAX_COMMAND_BYTES {
                        return self
                            .check_condition(itt, Sense::INVALID_FIELD_IN_CDB, edtl)
                            .await;
                    }
                    if let Some(s) = lun.failure(rw.lba, rw.blocks as u64, false) {
                        return self.check_condition(itt, s, edtl).await;
                    }
                    let d = lun.read(rw.lba, rw.blocks as u64, &self.overlay);
                    self.data_in(itt, lun_field, &d, edtl).await?;
                }
                None => return self.check_condition(itt, Sense::INVALID_OPCODE, edtl).await,
            },
        }
        Ok(true)
    }

    fn inquiry(&self, lun: &Lun, cdb: &[u8; 16]) -> Result<Vec<u8>, Sense> {
        let alloc = u16::from_be_bytes([cdb[3], cdb[4]]) as usize;
        let evpd = cdb[1] & 0x01 != 0;
        let page = cdb[2];
        let mut d = if !evpd {
            if page != 0 {
                return Err(Sense::INVALID_FIELD_IN_CDB);
            }
            scsi::standard_inquiry(
                &lun.identity,
                false,
                0x06, // SPC-4
                true,
                &[
                    scsi::VERSION_SAM5,
                    scsi::VERSION_ISCSI,
                    scsi::VERSION_SPC4,
                    scsi::VERSION_SBC3,
                ],
            )
        } else {
            match page {
                0x00 => scsi::vpd_supported_pages(&[0x00, 0x80, 0x83, 0xB0, 0xB1]),
                0xB0 => {
                    let max = (MAX_COMMAND_BYTES / lun.block_size as u64) as u32;
                    let optimal = (self.params.max_burst / lun.block_size).max(1);
                    scsi::vpd_block_limits(max, optimal)
                }
                0xB1 => scsi::vpd_block_device_characteristics(),
                0x80 => scsi::vpd_serial(&lun.serial),
                0x83 => scsi::vpd_device_identification(&[
                    scsi::Designator::Naa6(scsi::naa6_from(&format!(
                        "{}/{}/{}",
                        self.target_name, lun.number, lun.serial
                    ))),
                    scsi::Designator::T10 {
                        vendor: lun.identity.vendor.clone(),
                        id: lun.serial.clone(),
                    },
                    scsi::Designator::IscsiTargetName(self.target_name.clone()),
                ]),
                _ => return Err(Sense::INVALID_FIELD_IN_CDB),
            }
        };
        d.truncate(alloc);
        Ok(d)
    }

    async fn write(&mut self, req: Pdu, lun: &Lun, rw: scsi::ReadWrite) -> Result<bool> {
        let itt = req.itt();
        let edtl = req.u32_at(20);
        if rw.protect != 0 {
            return self
                .check_condition(itt, Sense::INVALID_FIELD_IN_CDB, edtl)
                .await;
        }
        if !lun.in_range(rw.lba, rw.blocks as u64) {
            return self
                .check_condition(itt, Sense::LBA_OUT_OF_RANGE, edtl)
                .await;
        }
        let expected = rw.blocks as u64 * lun.block_size as u64;
        if expected > MAX_COMMAND_BYTES {
            return self
                .check_condition(itt, Sense::INVALID_FIELD_IN_CDB, edtl)
                .await;
        }
        if !lun.writable {
            return self
                .check_condition(itt, Sense::WRITE_PROTECTED, edtl)
                .await;
        }
        if expected == 0 {
            let residual = if edtl > 0 { (0x02, edtl) } else { (0, 0) };
            self.respond(itt, status::GOOD, None, residual, 0).await?;
            return Ok(true);
        }
        if edtl as u64 != expected {
            // The command and its iSCSI transfer length disagree about how much data comes;
            // refuse rather than write a guess, as LIO does (INVALID FIELD IN INFORMATION
            // UNIT), naming the difference as the residual. Any data the initiator still sends
            // for the task is discarded as belonging to no task.
            let residual = if (edtl as u64) < expected {
                (0x04, (expected - edtl as u64) as u32)
            } else {
                (0x02, (edtl as u64 - expected) as u32)
            };
            self.respond(
                itt,
                status::CHECK_CONDITION,
                Some(Sense::INVALID_FIELD_IN_IU),
                residual,
                0,
            )
            .await?;
            return Ok(true);
        }
        let expected = expected as usize;
        let first_burst = (self.params.first_burst as usize).min(expected);
        if !req.data.is_empty() && (!self.params.immediate_data || req.data.len() > first_burst) {
            outcome(
                self.ctx,
                self.id,
                "write",
                "protocol_refusal",
                &format!(
                    "{} bytes of immediate data (ImmediateData {}, FirstBurstLength {})",
                    req.data.len(),
                    self.params.immediate_data,
                    self.params.first_burst
                ),
            );
            self.reject(&req, reject::PROTOCOL_ERROR).await?;
            return Ok(false);
        }
        let unsolicited_open = !self.params.initial_r2t && !req.final_bit();
        let mut w = PendingWrite {
            lun: lun.number,
            lba: rw.lba,
            expected,
            buf: Vec::with_capacity(expected),
            unsolicited_open,
            unsolicited_limit: if self.params.initial_r2t {
                req.data.len()
            } else {
                first_burst
            },
            unsolicited_data_sn: 0,
            r2t: None,
            r2t_sn: 0,
        };
        w.buf.extend(&req.data);
        self.pending.insert(itt, w);
        self.advance_write(itt).await
    }

    /// After data arrives: finish the write, or solicit the next burst.
    async fn advance_write(&mut self, itt: u32) -> Result<bool> {
        let Some(w) = self.pending.get_mut(&itt) else {
            return Ok(true);
        };
        if w.buf.len() == w.expected {
            let w = self.pending.remove(&itt).expect("pending write");
            return self.finish_write(itt, w).await;
        }
        if w.unsolicited_open || w.r2t.is_some() {
            return Ok(true);
        }
        let offset = w.buf.len();
        let len = (w.expected - offset).min(self.params.max_burst as usize);
        let ttt = self.next_ttt;
        self.next_ttt = self.next_ttt.wrapping_add(1).max(1);
        if self.next_ttt == RESERVED_TAG {
            self.next_ttt = 1;
        }
        w.r2t = Some((ttt, offset + len, 0));
        let r2t_sn = w.r2t_sn;
        w.r2t_sn += 1;
        let lun = scsi::lun_field(w.lun);
        let mut r = Pdu::new(op::R2T);
        r.set_flags(0x80);
        r.set_lun(lun);
        r.set_itt(itt);
        r.set_u32(20, ttt);
        // R2T carries StatSN without consuming one.
        r.set_u32(24, self.stat_sn);
        r.set_u32(28, self.exp_cmd_sn);
        r.set_u32(32, self.max_cmd_sn());
        r.set_u32(36, r2t_sn);
        r.set_u32(40, offset as u32);
        r.set_u32(44, len as u32);
        self.send(&r).await?;
        Ok(true)
    }

    async fn data_out(&mut self, req: Pdu) -> Result<bool> {
        let itt = req.itt();
        let ttt = req.u32_at(20);
        let data_sn = req.u32_at(36);
        let offset = req.u32_at(40) as usize;
        let Some(w) = self.pending.get_mut(&itt) else {
            // Data for a task already answered (refused before its data) or aborted.
            return Ok(true);
        };
        let violation = if ttt == RESERVED_TAG {
            if !w.unsolicited_open {
                Some("unsolicited data after the unsolicited burst ended")
            } else if data_sn != w.unsolicited_data_sn {
                Some("DataSN out of order")
            } else if offset != w.buf.len() || offset + req.data.len() > w.unsolicited_limit {
                Some("unsolicited data beyond FirstBurstLength or out of order")
            } else {
                None
            }
        } else {
            match w.r2t {
                Some((t, end, sn)) if t == ttt => {
                    if data_sn != sn {
                        Some("DataSN out of order")
                    } else if offset != w.buf.len() || offset + req.data.len() > end {
                        Some("data outside the R2T it answers")
                    } else {
                        None
                    }
                }
                _ => Some("a Target Transfer Tag this target did not issue"),
            }
        };
        if let Some(why) = violation {
            outcome(
                self.ctx,
                self.id,
                "data_out",
                "protocol_refusal",
                &format!("{why} (ITT 0x{itt:08x}, DataSN {data_sn}, offset {offset})"),
            );
            self.reject(&req, reject::PROTOCOL_ERROR).await?;
            // Error recovery level 0: the connection cannot resynchronise.
            return Ok(false);
        }
        w.buf.extend(&req.data);
        if ttt == RESERVED_TAG {
            w.unsolicited_data_sn += 1;
            if req.final_bit() {
                w.unsolicited_open = false;
            }
        } else if let Some((t, end, sn)) = w.r2t {
            if req.final_bit() || w.buf.len() >= end {
                w.r2t = None;
            } else {
                w.r2t = Some((t, end, sn + 1));
            }
        }
        self.advance_write(itt).await
    }

    async fn finish_write(&mut self, itt: u32, w: PendingWrite) -> Result<bool> {
        let Some(target) = self.target.clone() else {
            return Ok(true);
        };
        let Some(lun) = target.lun(w.lun) else {
            return self.check_condition(itt, Sense::LUN_NOT_SUPPORTED, 0).await;
        };
        let blocks = (w.expected / lun.block_size as usize) as u64;
        if let Some(s) = lun.failure(w.lba, blocks, true) {
            self.respond(itt, status::CHECK_CONDITION, Some(s), (0, 0), 0)
                .await?;
            return Ok(true);
        }
        match self.overlay.write(lun, w.lba, &w.buf) {
            Ok(()) => self.respond(itt, status::GOOD, None, (0, 0), 0).await?,
            Err(s) => {
                outcome(
                    self.ctx,
                    self.id,
                    "write",
                    "protocol_refusal",
                    &format!(
                        "the session's write overlay is full ({} bytes)",
                        self.overlay.bytes()
                    ),
                );
                self.respond(itt, status::CHECK_CONDITION, Some(s), (0, 0), 0)
                    .await?
            }
        }
        Ok(true)
    }

    async fn task_management(&mut self, req: Pdu) -> Result<bool> {
        let function = req.flags() & 0x7F;
        let referenced = req.u32_at(20);
        let ref_cmd_sn = req.u32_at(32);
        let cmd_sn = req.u32_at(24);
        let lun = scsi::lun_from_field(&req.lun());
        let mut close = false;
        let response: u8 = match function {
            // ABORT TASK
            1 => {
                if self.pending.remove(&referenced).is_some() {
                    0
                } else if pdu::sn_lt(ref_cmd_sn, cmd_sn) && pdu::sn_le(self.exp_cmd_sn, ref_cmd_sn)
                {
                    // Not received yet but inside the window: RFC 7143 §11.5.1 has the target
                    // take it as received and aborted, so it is dropped if it turns up.
                    if self.aborted_before_arrival.len() < COMMAND_WINDOW as usize {
                        self.aborted_before_arrival.push(ref_cmd_sn);
                    }
                    0
                } else {
                    // Received and already answered, or never in the window.
                    1
                }
            }
            // ABORT TASK SET, CLEAR TASK SET, LUN RESET
            2 | 4 | 5 => {
                match lun.and_then(|n| self.target.as_ref()?.lun(n).map(|_| n)) {
                    Some(n) => {
                        self.pending.retain(|_, w| w.lun != n);
                        0
                    }
                    None => 2, // LUN does not exist
                }
            }
            // TARGET WARM RESET, TARGET COLD RESET
            6 | 7 => {
                self.pending.clear();
                close = function == 7;
                0
            }
            // CLEAR ACA (no ACA), TASK REASSIGN (error recovery level 0)
            3 => 5,
            8 => 4,
            _ => 255,
        };
        let mut r = Pdu::new(op::TASK_MGMT_RESPONSE);
        r.set_flags(0x80);
        r.bhs[2] = response;
        r.set_itt(req.itt());
        self.status_fields(&mut r);
        self.send(&r).await?;
        outcome(
            self.ctx,
            self.id,
            "task_management",
            "answered",
            &format!("function {function} -> response {response}"),
        );
        Ok(!close)
    }

    // ------------------------------------------------------------ text

    async fn text_request(&mut self, req: Pdu) -> Result<bool> {
        let itt = req.itt();
        let ttt = req.u32_at(20);
        let cont = req.flags() & 0x40 != 0;
        // The initiator asking for the rest of a long answer.
        if ttt != RESERVED_TAG {
            match self.text_out.take() {
                Some(c) if c.itt == itt && c.ttt == ttt => {
                    self.send_text(itt, c.rest).await?;
                }
                _ => self.reject(&req, reject::INVALID_PDU_FIELD).await?,
            }
            return Ok(true);
        }
        self.text_out = None;
        let mut acc = match self.text_in.take() {
            Some((i, buf)) if i == itt => buf,
            _ => Vec::new(),
        };
        if acc.len() + req.data.len() > text::MAX_TEXT {
            outcome(
                self.ctx,
                self.id,
                "text",
                "protocol_refusal",
                "more than 64 KiB of text",
            );
            self.reject(&req, reject::PROTOCOL_ERROR).await?;
            return Ok(true);
        }
        acc.extend(&req.data);
        if cont {
            self.text_in = Some((itt, acc));
            let mut r = Pdu::new(op::TEXT_RESPONSE);
            r.set_itt(itt);
            let t = self.issue_ttt();
            r.set_u32(20, t);
            self.status_fields(&mut r);
            self.send(&r).await?;
            return Ok(true);
        }
        let pairs = match text::parse(&acc) {
            Ok(p) => p,
            Err(e) => {
                outcome(
                    self.ctx,
                    self.id,
                    "text",
                    "protocol_refusal",
                    &e.to_string(),
                );
                self.reject(&req, reject::PROTOCOL_ERROR).await?;
                return Ok(true);
            }
        };
        // Full feature phase text is SendTargets and nothing else here: its value is All, empty
        // (this session's target) or a target name. Anything else is refused with Reject, as
        // LIO does, rather than answered with an empty list the initiator would read as "no
        // targets" (keys are case-sensitive, so sENDtARGETS is not SendTargets either).
        let valid = !pairs.is_empty()
            && pairs.iter().all(|(k, v)| {
                k == "SendTargets" && (v == "All" || v.is_empty() || actions::valid_name(v))
            });
        if !valid {
            outcome(
                self.ctx,
                self.id,
                "text",
                "protocol_refusal",
                "a text request that is not SendTargets=All, a target name or empty",
            );
            self.reject(&req, reject::PROTOCOL_ERROR).await?;
            return Ok(true);
        }
        let mut answer: Vec<(String, String)> = Vec::new();
        for (_, v) in &pairs {
            answer.extend(self.send_targets(v).await);
        }
        self.send_text(itt, text::encode(&answer)).await?;
        Ok(true)
    }

    fn issue_ttt(&mut self) -> u32 {
        let t = self.next_ttt;
        self.next_ttt = self.next_ttt.wrapping_add(1);
        if self.next_ttt == RESERVED_TAG || self.next_ttt == 0 {
            self.next_ttt = 1;
        }
        t
    }

    /// Send a text answer, in as many PDUs as the initiator's MaxRecvDataSegmentLength needs:
    /// the first part now, the rest when it asks.
    async fn send_text(&mut self, itt: u32, mut body: Vec<u8>) -> Result<()> {
        let max = (self.params.peer_max_recv_data_segment as usize).max(512);
        let mut r = Pdu::new(op::TEXT_RESPONSE);
        r.set_itt(itt);
        if body.len() > max {
            // Split on a key boundary where one fits, so no key straddles two PDUs.
            let cut = body[..max]
                .iter()
                .rposition(|b| *b == 0)
                .map(|i| i + 1)
                .unwrap_or(max);
            let rest = body.split_off(cut);
            let ttt = self.issue_ttt();
            r.set_flags(0x40);
            r.set_u32(20, ttt);
            self.text_out = Some(TextContinuation { itt, ttt, rest });
        } else {
            r.set_flags(0x80);
            r.set_u32(20, RESERVED_TAG);
        }
        self.status_fields(&mut r);
        r.data = body;
        self.send(&r).await
    }

    /// The answer to SendTargets: the model's list for All in a discovery session, this
    /// session's own target otherwise.
    async fn send_targets(&mut self, value: &str) -> Vec<(String, String)> {
        let portal = format!(
            "{}:{},{}",
            match self.local.ip() {
                std::net::IpAddr::V6(v6) => format!("[{v6}]"),
                ip => ip.to_string(),
            },
            self.local.port(),
            PORTAL_GROUP_TAG
        );
        let targets: Vec<(String, Vec<String>)> = match (self.session_type, value) {
            (SessionType::Discovery, "All") => self.discover().await,
            // In a normal session the initiator already has its target: All and the empty
            // value both name it alone.
            (SessionType::Normal, "" | "All") => vec![(self.target_name.clone(), vec![])],
            (SessionType::Normal, name) if name == self.target_name => {
                vec![(self.target_name.clone(), vec![])]
            }
            (SessionType::Discovery, name) if !name.is_empty() => self
                .discover()
                .await
                .into_iter()
                .filter(|(n, _)| n == name)
                .collect(),
            _ => vec![],
        };
        let mut out = Vec::new();
        for (name, addresses) in targets {
            out.push(("TargetName".to_string(), name));
            if addresses.is_empty() {
                out.push(("TargetAddress".to_string(), portal.clone()));
            }
            for a in addresses {
                out.push((
                    "TargetAddress".to_string(),
                    format!("{a},{PORTAL_GROUP_TAG}"),
                ));
            }
        }
        out
    }

    /// The model's SendTargets list, asked once per connection. A failure lists nothing.
    async fn discover(&mut self) -> Vec<(String, Vec<String>)> {
        if let Some(d) = &self.discovered {
            return d.clone();
        }
        let event = Event::new(
            &actions::DISCOVERY_EVENT,
            json!({
                "initiator_name": self.initiator_name,
                "initiator_address": self.peer.to_string(),
                "authenticated_user": self.authenticated,
            }),
        );
        let targets = match self.ask(&event).await {
            Ok(a) if a["type"] == actions::SEND_TARGETS => match actions::targets_of(&a) {
                Ok(t) => {
                    outcome(
                        self.ctx,
                        self.id,
                        "discovery",
                        "model_answer",
                        &format!("{} target(s)", t.len()),
                    );
                    t
                }
                Err(e) => {
                    outcome(
                        self.ctx,
                        self.id,
                        "discovery",
                        "fail_closed_invalid_reply",
                        &format!("{e:#}"),
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
                    "not a target list",
                );
                vec![]
            }
            Err(f) => {
                outcome(
                    self.ctx,
                    self.id,
                    "discovery",
                    f.decision,
                    "no targets listed",
                );
                vec![]
            }
        };
        self.discovered = Some(targets.clone());
        targets
    }
}

/// MODE SENSE(6) or (10): a block descriptor unless DBD, and the caching (0x08) and control
/// (0x0A) pages. Write protection shows in the device-specific parameter.
fn mode_sense(lun: &Lun, cdb: &[u8; 16]) -> Result<Vec<u8>, Sense> {
    let ten = cdb[0] == opcode::MODE_SENSE_10;
    let dbd = cdb[1] & 0x08 != 0;
    let pc = cdb[2] >> 6;
    let page = cdb[2] & 0x3F;
    let subpage = cdb[3];
    if pc == 3 {
        return Err(Sense::SAVING_NOT_SUPPORTED);
    }
    if subpage != 0 && subpage != 0xFF {
        return Err(Sense::INVALID_FIELD_IN_CDB);
    }
    let changeable = pc == 1;
    let caching = {
        let mut p = vec![0u8; 20];
        p[0] = 0x08;
        p[1] = 0x12;
        p
    };
    let control = {
        let mut p = vec![0u8; 12];
        p[0] = 0x0A;
        p[1] = 0x0A;
        if !changeable {
            // D_SENSE 0 (fixed-format sense), QErr 0; busy timeout unlimited.
            p[8] = 0xFF;
            p[9] = 0xFF;
        }
        p
    };
    let mut pages = Vec::new();
    match page {
        0x08 => pages.extend(&caching),
        0x0A => pages.extend(&control),
        0x3F => {
            pages.extend(&caching);
            pages.extend(&control);
        }
        _ => return Err(Sense::INVALID_FIELD_IN_CDB),
    }
    let mut block = Vec::new();
    if !dbd {
        // A count past 24 bits reads as 0xFFFFFF, sending the host to READ CAPACITY.
        let blocks = lun.blocks.min(0x00FF_FFFF) as u32;
        block.push(0); // density
        block.extend(&blocks.to_be_bytes()[1..]);
        block.push(0);
        block.extend(&lun.block_size.to_be_bytes()[1..]);
    }
    // WP for a read-only LUN; DPOFUA, since DPO and FUA are honoured trivially (nothing is
    // cached, so every write is already where a later read finds it).
    let wp = if lun.writable { 0x10 } else { 0x90 };
    let mut d = Vec::new();
    if ten {
        let len = (6 + block.len() + pages.len()) as u16;
        d.extend(len.to_be_bytes());
        d.extend([0x00, wp, 0x00, 0x00]);
        d.extend((block.len() as u16).to_be_bytes());
        d.extend(&block);
        d.extend(&pages);
        let alloc = u16::from_be_bytes([cdb[7], cdb[8]]) as usize;
        d.truncate(alloc);
    } else {
        let len = (3 + block.len() + pages.len()).min(255) as u8;
        d.extend([len, 0x00, wp, block.len() as u8]);
        d.extend(&block);
        d.extend(&pages);
        d.truncate(cdb[4] as usize);
    }
    Ok(d)
}
