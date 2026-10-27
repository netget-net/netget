//! Stratum V2 server roles, chosen by the `role` startup parameter:
//!
//! - `pool` (default): the Mining Protocol. Rust owns each connection — the Noise NX handshake
//!   and the certificate it presents, every frame's encryption and encoding, channels,
//!   extranonce prefixes, jobs, the share arithmetic and every refusal that arithmetic decides —
//!   and asks the model only whether a device may connect, whether a channel opens and at what
//!   difficulty, and whether a share already proven to meet its target is credited.
//! - `template_provider`: the Template Distribution Protocol (`template_provider.rs`).
//! - `job_declarator`: the Job Declaration Protocol's server (`job_declarator.rs`).
//! - `pool_and_job_declarator`: both on one listener, the protocol each connection names in
//!   SetupConnection choosing which serves it. The pool then takes work selection
//!   (SetCustomMiningJob), redeeming the tokens the job declarator issued — one token table,
//!   because one server holds it.
//!
//! All share the handshake, the certificate and the framing. With `bitcoin_rpc_url`, every role
//! hands the blocks it verifies to that Bitcoin Core node (`node.rs`), and the job declarator
//! checks each declaration against the node's tip.
pub mod actions;
pub mod bitcoin;
pub mod job_declarator;
pub mod node;
pub mod noise;
pub mod template_provider;
pub mod wire;

use crate::llm::action_helper::call_llm;
use crate::llm::actions::protocol_trait::ActionResult;
use crate::logging::emit::Log;
use crate::protocol::{Event, SpawnContext};
use crate::server::accept_bounded::{accept_bounded, ConnectionLimiter, DEFAULT_MAX_CONNECTIONS};
use crate::server::connection::ConnectionId;
use crate::state::server::{ConnectionState, ConnectionStatus, ProtocolConnectionInfo};
use anyhow::{anyhow, Result};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use wire::Message;

pub const IDLE_TIMEOUT: Duration = Duration::from_secs(900);
pub const MAX_IDLE_TIMEOUT_SECS: u64 = 86400;
/// A device has this long to send its half of the handshake.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
pub const DEFAULT_CERT_VALIDITY_SECS: u64 = 3600;
pub const MAX_CERT_VALIDITY_SECS: u64 = 31_536_000;
pub const DEFAULT_SHARES_PER_MINUTE: f64 = 6.0;
/// The largest frame payload a device may send. The biggest message a mining device has any
/// reason to send is a SetupConnection with five full strings, about 1.3 KiB.
pub const MAX_INBOUND_PAYLOAD: usize = 16 * 1024;
/// The largest frame payload a connection that negotiated work selection may send: a
/// SetCustomMiningJob with a full B0_64K of coinbase outputs and a 255-deep merkle path is
/// about 73 KiB.
pub const MAX_WORK_SELECTION_PAYLOAD: usize = 80 * 1024;
/// Block hashes remembered as handed to the node, so a block reported twice (PushSolution and
/// the share that found it) is relayed once.
pub const MAX_RELAYED: usize = 1024;
/// Channels one connection may hold open.
pub const MAX_CHANNELS: usize = 16;
/// Jobs a channel keeps valid at once; older ones become stale.
pub const MAX_JOBS: usize = 16;
/// Retired job ids remembered so their shares are called stale rather than unknown.
pub const MAX_RETIRED_JOBS: usize = 64;
/// Shares remembered per channel to refuse duplicates.
pub const MAX_SEEN_SHARES: usize = 4096;
/// The extranonce an extended channel gets when the device asks for less.
pub const DEFAULT_EXTRANONCE_SIZE: u16 = 8;
/// The lowest default difficulty, so a channel declaring no hash rate is not handed a target
/// every hash meets.
pub const MIN_DEFAULT_DIFFICULTY: f64 = 0.001;
/// nbits of the pool's own jobs: the easiest target there is, as on regtest.
pub const POOL_NBITS: u32 = 0x207f_ffff;
pub const POOL_VERSION: u32 = 0x2000_0000;

/// Which Stratum V2 protocol this server speaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Pool,
    TemplateProvider,
    JobDeclarator,
    PoolAndJobDeclarator,
}

impl Role {
    pub fn parse(s: &str) -> Result<Self> {
        Ok(match s {
            "pool" => Role::Pool,
            "template_provider" => Role::TemplateProvider,
            "job_declarator" => Role::JobDeclarator,
            "pool_and_job_declarator" => Role::PoolAndJobDeclarator,
            other => anyhow::bail!(
                "role must be pool, template_provider, job_declarator or pool_and_job_declarator, not {other:?}"
            ),
        })
    }

    pub fn name(self) -> &'static str {
        match self {
            Role::Pool => "pool",
            Role::TemplateProvider => "template provider",
            Role::JobDeclarator => "job declarator",
            Role::PoolAndJobDeclarator => "pool and job declarator",
        }
    }

    /// The largest frame payload a peer of this role may send before SetupConnection has said
    /// more (work selection, or the Job Declaration Protocol on a combined listener).
    pub fn max_inbound_payload(self) -> usize {
        match self {
            Role::Pool | Role::PoolAndJobDeclarator => MAX_INBOUND_PAYLOAD,
            Role::TemplateProvider => template_provider::MAX_INBOUND_PAYLOAD,
            Role::JobDeclarator => job_declarator::MAX_INBOUND_PAYLOAD,
        }
    }
}

/// What every connection of one server shares.
pub(crate) struct Pool {
    key: noise::EllKey,
    authority: noise::Authority,
    cert_validity: u32,
    shares_per_minute: f64,
    next_prefix: AtomicU32,
    next_job: AtomicU32,
    role: Role,
    network: bitcoin::Network,
    mempool: std::sync::Mutex<job_declarator::Mempool>,
    /// Accepted declarations by token, which the pool side redeems.
    redeemable: std::sync::Mutex<job_declarator::Redeemable>,
    /// The node blocks are relayed to and declarations checked against, if configured.
    node: Option<node::Node>,
    relayed: std::sync::Mutex<VecDeque<String>>,
}

struct Job {
    id: u32,
    version: u32,
    ntime_start: u32,
    nbits: u32,
    prev_hash: [u8; 32],
    coinbase_prefix: Vec<u8>,
    coinbase_suffix: Vec<u8>,
    /// For standard channels: the root of the coinbase with the channel's extranonce prefix.
    merkle_root: [u8; 32],
    /// A custom job's path (the pool's own jobs carry no transactions).
    merkle_path: Vec<[u8; 32]>,
    /// The declaration a custom job redeemed: its transactions complete a block.
    custom: Option<Arc<job_declarator::Accepted>>,
}

type ShareKey = (u32, u32, u32, u32, Vec<u8>);

struct Channel {
    id: u32,
    /// None for a standard channel, the device's extranonce size for an extended one.
    extranonce_size: Option<u16>,
    user: String,
    prefix: [u8; wire::EXTRANONCE_PREFIX_LEN],
    target: [u8; 32],
    max_target: [u8; 32],
    prev_hash: [u8; 32],
    height: u32,
    jobs: VecDeque<Job>,
    retired: VecDeque<u32>,
    seen: HashSet<ShareKey>,
}

impl Channel {
    fn kind(&self) -> &'static str {
        if self.extranonce_size.is_some() {
            "extended"
        } else {
            "standard"
        }
    }

    fn make_job(&mut self, pool: &Pool, message: &str) -> Job {
        self.height = self.height.wrapping_add(1).max(1);
        let extranonce_len =
            wire::EXTRANONCE_PREFIX_LEN + usize::from(self.extranonce_size.unwrap_or(0));
        let (coinbase_prefix, coinbase_suffix) =
            wire::coinbase_halves(self.height, message.as_bytes(), extranonce_len);
        let merkle_root = if self.extranonce_size.is_none() {
            let coinbase = [&coinbase_prefix[..], &self.prefix, &coinbase_suffix].concat();
            wire::merkle_root(&coinbase, &[])
        } else {
            [0u8; 32]
        };
        Job {
            id: pool.next_job.fetch_add(1, Ordering::Relaxed),
            version: POOL_VERSION,
            ntime_start: wire::now_secs(),
            nbits: POOL_NBITS,
            prev_hash: self.prev_hash,
            coinbase_prefix,
            coinbase_suffix,
            merkle_root,
            merkle_path: Vec::new(),
            custom: None,
        }
    }

    fn job_message(&self, job: &Job, min_ntime: Option<u32>) -> Message {
        match self.extranonce_size {
            None => Message::NewMiningJob {
                channel_id: self.id,
                job_id: job.id,
                min_ntime,
                version: job.version,
                merkle_root: job.merkle_root,
            },
            Some(_) => Message::NewExtendedMiningJob {
                channel_id: self.id,
                job_id: job.id,
                min_ntime,
                version: job.version,
                version_rolling_allowed: true,
                merkle_path: Vec::new(),
                coinbase_tx_prefix: job.coinbase_prefix.clone(),
                coinbase_tx_suffix: job.coinbase_suffix.clone(),
            },
        }
    }

    fn retire(&mut self, id: u32) {
        if self.retired.len() >= MAX_RETIRED_JOBS {
            self.retired.pop_front();
        }
        self.retired.push_back(id);
    }

    /// New work on a new prev hash: a future job, then SetNewPrevHash making it the only one.
    fn reset_work(&mut self, pool: &Pool, message: &str, prev_hash: [u8; 32]) -> Vec<Message> {
        while let Some(old) = self.jobs.pop_front() {
            self.retire(old.id);
        }
        self.seen.clear();
        self.prev_hash = prev_hash;
        let job = self.make_job(pool, message);
        let out = vec![
            self.job_message(&job, None),
            Message::SetNewPrevHash {
                channel_id: self.id,
                job_id: job.id,
                prev_hash,
                min_ntime: job.ntime_start,
                nbits: job.nbits,
            },
        ];
        self.jobs.push_back(job);
        out
    }

    /// Another job on the current prev hash, active at once.
    fn add_job(&mut self, pool: &Pool, message: &str) -> Vec<Message> {
        let job = self.make_job(pool, message);
        if self.jobs.len() >= MAX_JOBS {
            if let Some(old) = self.jobs.pop_front() {
                self.retire(old.id);
            }
        }
        let out = vec![self.job_message(&job, Some(job.ntime_start))];
        self.jobs.push_back(job);
        out
    }
}

struct Conn {
    setup: bool,
    flags: u32,
    /// The device negotiated REQUIRES_WORK_SELECTION (only a `pool_and_job_declarator` allows it).
    work_selection: bool,
    channels: HashMap<u32, Channel>,
    next_channel_id: u32,
}

/// What answering one message produced: frames to send, and whether to hang up after them.
#[derive(Default)]
struct Step {
    out: Vec<Message>,
    close: bool,
}

impl Step {
    fn send(m: Message) -> Self {
        Self {
            out: vec![m],
            close: false,
        }
    }
    fn close() -> Self {
        Self {
            out: Vec::new(),
            close: true,
        }
    }
    fn send_and_close(m: Message) -> Self {
        Self {
            out: vec![m],
            close: true,
        }
    }
}

fn params(ctx: &SpawnContext) -> Result<(Pool, Duration)> {
    let p = ctx.startup_params.as_ref();
    let authority = match p
        .map(|p| p.get_optional_string("authority_secret_key"))
        .transpose()?
        .flatten()
    {
        Some(s) => noise::decode_secret_key(&s)
            .map_err(|e| anyhow!("authority_secret_key is not a base58check secret key: {e}"))?,
        None => noise::Authority::generate(),
    };
    let validity = p
        .map(|p| p.get_optional_u64("cert_validity_secs"))
        .transpose()?
        .flatten()
        .unwrap_or(DEFAULT_CERT_VALIDITY_SECS);
    anyhow::ensure!(
        (60..=MAX_CERT_VALIDITY_SECS).contains(&validity),
        "cert_validity_secs must be between 60 and {MAX_CERT_VALIDITY_SECS}"
    );
    let spm = p
        .map(|p| p.get_optional_f64("shares_per_minute"))
        .transpose()?
        .flatten()
        .unwrap_or(DEFAULT_SHARES_PER_MINUTE);
    anyhow::ensure!(
        (0.01..=600.0).contains(&spm),
        "shares_per_minute must be between 0.01 and 600"
    );
    let idle = p
        .map(|p| p.get_optional_u64("idle_timeout_secs"))
        .transpose()?
        .flatten()
        .unwrap_or(IDLE_TIMEOUT.as_secs());
    anyhow::ensure!(
        (1..=MAX_IDLE_TIMEOUT_SECS).contains(&idle),
        "idle_timeout_secs must be between 1 and {MAX_IDLE_TIMEOUT_SECS}"
    );
    let role = Role::parse(
        &p.map(|p| p.get_optional_string("role"))
            .transpose()?
            .flatten()
            .unwrap_or_else(|| actions::DEFAULT_ROLE.into()),
    )?;
    let network = bitcoin::Network::parse(
        &p.map(|p| p.get_optional_string("network"))
            .transpose()?
            .flatten()
            .unwrap_or_else(|| actions::DEFAULT_NETWORK.into()),
    )?;
    let string = |key: &str| -> Result<Option<String>> {
        Ok(p.map(|p| p.get_optional_string(key))
            .transpose()?
            .flatten()
            .filter(|s| !s.is_empty()))
    };
    let (user, password) = (string("bitcoin_rpc_user")?, string("bitcoin_rpc_password")?);
    let node = match string("bitcoin_rpc_url")? {
        Some(url) => Some(node::Node::new(&url, user, password)?),
        None => {
            anyhow::ensure!(
                user.is_none() && password.is_none(),
                "bitcoin_rpc_user and bitcoin_rpc_password need bitcoin_rpc_url"
            );
            None
        }
    };
    Ok((
        Pool {
            key: noise::EllKey::generate(),
            authority,
            cert_validity: validity as u32,
            shares_per_minute: spm,
            next_prefix: AtomicU32::new(rand::random()),
            next_job: AtomicU32::new(1),
            role,
            network,
            mempool: std::sync::Mutex::new(job_declarator::Mempool::default()),
            redeemable: std::sync::Mutex::new(job_declarator::Redeemable::default()),
            node,
            relayed: std::sync::Mutex::new(VecDeque::new()),
        },
        Duration::from_secs(idle),
    ))
}

pub async fn spawn(ctx: SpawnContext) -> Result<SocketAddr> {
    let (pool, idle) = params(&ctx)?;
    let listener = TcpListener::bind(ctx.legacy_listen_addr()).await?;
    let addr = listener.local_addr()?;
    Log::new(Some(&ctx.status_tx)).info(format!(
        "Stratum V2 {} listening on {addr}; authority public key {} (clients pin this){}",
        pool.role.name(),
        noise::encode_authority_key(&pool.authority.public_xonly()),
        match &pool.node {
            Some(n) => format!("; blocks are relayed to {}", n.url()),
            None => String::new(),
        }
    ));
    let pool = Arc::new(pool);
    let state = ctx.state.clone();
    let server_id = ctx.server_id;
    let accept = tokio::spawn(async move {
        let limiter = ConnectionLimiter::new(DEFAULT_MAX_CONNECTIONS);
        loop {
            let (socket, peer, permit) =
                match accept_bounded(&listener, &limiter, b"", "Stratum V2", Some(&ctx.status_tx))
                    .await
                {
                    Ok(v) => v,
                    Err(_) => break,
                };
            let id = ConnectionId::new(ctx.state.get_next_unified_id().await);
            let now = crate::utils::clock::Instant::now();
            ctx.state
                .add_connection_to_server(
                    server_id,
                    ConnectionState {
                        id,
                        remote_addr: peer,
                        local_addr: addr,
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
            let child = ctx.clone();
            let pool = pool.clone();
            ctx.state
                .spawn_server_task(server_id, async move {
                    let _permit = permit;
                    if let Err(e) = session(&child, &pool, id, socket, peer, idle).await {
                        Log::new(Some(&child.status_tx))
                            .warn(format!("Stratum V2 connection {id} ended: {e:#}"));
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
    state.register_server_task(server_id, accept).await;
    Ok(addr)
}

fn outcome(ctx: &SpawnContext, id: ConnectionId, operation: &str, decision: &str) {
    let summary = format!("Stratum V2 connection {id} operation={operation} decision={decision}");
    let log = Log::new(Some(&ctx.status_tx));
    if decision.starts_with("fail_closed_") || decision == "model_silent" {
        log.error(summary);
    } else {
        log.info(summary);
    }
}

/// The model's answer, split into its verdict and what accompanies it.
struct Answer {
    verdict: Option<Result<(), String>>,
    extras: Vec<Value>,
}

/// How a request the model was asked about ends.
enum Verdict {
    Accept(Vec<Value>),
    Reject(String, Vec<Value>),
    /// The model failed, answered nothing usable, or answered both ways: the code the peer gets.
    Fail(&'static str),
}

fn failure_code(e: &anyhow::Error) -> &'static str {
    match crate::utils::WireFailure::classify(e) {
        crate::utils::WireFailure::Overloaded => "service-overloaded",
        crate::utils::WireFailure::Unavailable => "service-unavailable",
    }
}

fn split(results: Vec<ActionResult>) -> (Answer, bool) {
    let mut stack = results;
    let mut ordered = Vec::new();
    while let Some(r) = stack.pop() {
        match r {
            ActionResult::Custom { data, .. } => ordered.push(data),
            ActionResult::Multiple(items) => stack.extend(items),
            _ => {}
        }
    }
    ordered.reverse();
    let mut verdicts = Vec::new();
    let mut extras = Vec::new();
    for a in ordered {
        match a["type"].as_str().unwrap_or_default() {
            actions::ACCEPT => verdicts.push(Ok(())),
            actions::REJECT => verdicts.push(Err(a["error_code"]
                .as_str()
                .unwrap_or("rejected")
                .to_string())),
            _ => extras.push(a),
        }
    }
    let invalid = verdicts.len() > 1;
    (
        Answer {
            verdict: verdicts.into_iter().next(),
            extras,
        },
        invalid,
    )
}

/// What the model said about an event that may or may not call for a verdict.
pub(crate) enum Consult {
    Answer {
        verdict: Option<Result<(), String>>,
        extras: Vec<Value>,
    },
    /// The model failed or answered both ways: the code a peer gets, where there is one.
    Fail(&'static str),
}

/// Ask the model about an event of the template provider or job declarator roles, logging the
/// decision the same way `ask` does.
pub(crate) async fn consult(
    ctx: &SpawnContext,
    id: ConnectionId,
    event: Event,
    operation: &str,
) -> Consult {
    match call_llm(
        &ctx.llm_client,
        &ctx.state,
        ctx.server_id,
        Some(id),
        &event,
        &actions::StratumV2Protocol,
    )
    .await
    {
        Ok(r) if r.failures.is_empty() => {
            let (answer, invalid) = split(r.protocol_results);
            if invalid {
                outcome(ctx, id, operation, "fail_closed_invalid_reply");
                return Consult::Fail("service-unavailable");
            }
            let decision = match (&answer.verdict, answer.extras.is_empty()) {
                (Some(Err(_)), _) => "model_reject",
                (None, true) => "model_silent",
                _ => "model_answer",
            };
            outcome(ctx, id, operation, decision);
            Consult::Answer {
                verdict: answer.verdict,
                extras: answer.extras,
            }
        }
        Ok(_) => {
            outcome(ctx, id, operation, "fail_closed_invalid_reply");
            Consult::Fail("service-unavailable")
        }
        Err(e) => {
            outcome(ctx, id, operation, "fail_closed_llm_error");
            Consult::Fail(failure_code(&e))
        }
    }
}

async fn ask(ctx: &SpawnContext, id: ConnectionId, event: Event, operation: &str) -> Verdict {
    match call_llm(
        &ctx.llm_client,
        &ctx.state,
        ctx.server_id,
        Some(id),
        &event,
        &actions::StratumV2Protocol,
    )
    .await
    {
        Ok(r) if r.failures.is_empty() => {
            let (answer, invalid) = split(r.protocol_results);
            if invalid {
                outcome(ctx, id, operation, "fail_closed_invalid_reply");
                return Verdict::Fail("service-unavailable");
            }
            match answer.verdict {
                Some(Ok(())) => {
                    outcome(ctx, id, operation, "model_answer");
                    Verdict::Accept(answer.extras)
                }
                Some(Err(code)) => {
                    outcome(ctx, id, operation, "model_reject");
                    Verdict::Reject(code, answer.extras)
                }
                None => {
                    outcome(ctx, id, operation, "model_silent");
                    Verdict::Fail("service-unavailable")
                }
            }
        }
        Ok(_) => {
            outcome(ctx, id, operation, "fail_closed_invalid_reply");
            Verdict::Fail("service-unavailable")
        }
        Err(e) => {
            outcome(ctx, id, operation, "fail_closed_llm_error");
            Verdict::Fail(failure_code(&e))
        }
    }
}

fn default_difficulty(nominal_hash_rate: f32, shares_per_minute: f64) -> f64 {
    let hashes_per_share = f64::from(nominal_hash_rate) * 60.0 / shares_per_minute;
    (hashes_per_share / 4_294_967_296.0).max(MIN_DEFAULT_DIFFICULTY)
}

/// Work, targets and closures accompanying an answer on `channel`. On an opening channel the
/// target is the channel's first and needs no SetTarget.
fn apply_extras(
    pool: &Pool,
    conn: &mut Conn,
    channel_id: u32,
    extras: &[Value],
    opening: bool,
) -> Vec<Message> {
    let mut out = Vec::new();
    let mut close: Option<String> = None;
    let Some(ch) = conn.channels.get_mut(&channel_id) else {
        return out;
    };
    for a in extras {
        match a["type"].as_str().unwrap_or_default() {
            actions::SET_TARGET => {
                if let Some(d) = a["difficulty"].as_f64() {
                    ch.target = wire::min_target(wire::target_for(d), ch.max_target);
                    if !opening {
                        out.push(Message::SetTarget {
                            channel_id,
                            maximum_target: ch.target,
                        });
                    }
                }
            }
            actions::NEW_JOB => {
                let message = a["message"]
                    .as_str()
                    .unwrap_or(actions::DEFAULT_COINBASE_MESSAGE);
                match a["prev_hash"].as_str().filter(|s| !s.is_empty()) {
                    Some(h) => {
                        let prev = wire::parse_display_hash(Some(h)).unwrap_or(ch.prev_hash);
                        out.extend(ch.reset_work(pool, message, prev));
                    }
                    None if opening => {
                        let prev = ch.prev_hash;
                        out.extend(ch.reset_work(pool, message, prev));
                    }
                    None => out.extend(ch.add_job(pool, message)),
                }
            }
            actions::CLOSE_CHANNEL => {
                close = Some(a["reason_code"].as_str().unwrap_or("closed").to_string());
            }
            _ => {}
        }
    }
    if opening && ch.jobs.is_empty() {
        let prev = ch.prev_hash;
        out.extend(ch.reset_work(pool, actions::DEFAULT_COINBASE_MESSAGE, prev));
    }
    if let Some(reason) = close {
        conn.channels.remove(&channel_id);
        out.push(Message::CloseChannel {
            channel_id,
            reason_code: reason.into_bytes(),
        });
    }
    out
}

/// Answer one message from the device.
#[allow(clippy::too_many_arguments)]
async fn handle(
    ctx: &SpawnContext,
    pool: &Pool,
    conn: &mut Conn,
    id: ConnectionId,
    peer: SocketAddr,
    message: Message,
) -> Step {
    let log = Log::new(Some(&ctx.status_tx));
    let refuse_close = |why: &str| {
        log.warn(format!("Stratum V2 connection {id} refused: {why}"));
        Step::close()
    };
    if !conn.setup && !matches!(message, Message::SetupConnection { .. }) {
        return refuse_close(&format!("{} before SetupConnection", message.name()));
    }
    match message {
        Message::SetupConnection {
            protocol,
            min_version,
            max_version,
            flags,
            endpoint_host,
            endpoint_port,
            vendor,
            hardware_version,
            firmware,
            device_id,
        } => {
            if conn.setup {
                return refuse_close("a second SetupConnection");
            }
            let error = |flags: u32, code: &str| {
                log.info(format!("Stratum V2 connection {id} setup refused: {code}"));
                Step::send_and_close(Message::SetupConnectionError {
                    flags,
                    error_code: code.as_bytes().to_vec(),
                })
            };
            if protocol != wire::MINING_PROTOCOL {
                return error(0, "unsupported-protocol");
            }
            if min_version > wire::PROTOCOL_VERSION || max_version < wire::PROTOCOL_VERSION {
                return error(0, "protocol-version-mismatch");
            }
            // Work selection needs a job declarator to have issued the token a custom job
            // redeems, so only the combined role offers it.
            let mut supported = wire::REQUIRES_STANDARD_JOBS | wire::REQUIRES_VERSION_ROLLING;
            if pool.role == Role::PoolAndJobDeclarator {
                supported |= wire::REQUIRES_WORK_SELECTION;
            }
            let unsupported = flags & !supported;
            if unsupported != 0 {
                return error(unsupported, "unsupported-feature-flags");
            }
            let event = Event::new(
                &actions::SETUP_EVENT,
                json!({"vendor": wire::text(&vendor), "hardware_version": wire::text(&hardware_version),
                       "firmware": wire::text(&firmware), "device_id": wire::text(&device_id),
                       "endpoint_host": wire::text(&endpoint_host), "endpoint_port": endpoint_port,
                       "flags": wire::flag_names(flags), "remote_addr": peer.to_string()}),
            );
            match ask(ctx, id, event, "setup_connection").await {
                Verdict::Accept(_) => {
                    conn.setup = true;
                    conn.flags = flags;
                    conn.work_selection = flags & wire::REQUIRES_WORK_SELECTION != 0;
                    Step::send(Message::SetupConnectionSuccess {
                        used_version: wire::PROTOCOL_VERSION,
                        flags: 0,
                    })
                }
                Verdict::Reject(code, _) => error(0, &code),
                Verdict::Fail(code) => error(0, code),
            }
        }
        Message::OpenStandardMiningChannel {
            request_id,
            user_identity,
            nominal_hash_rate,
            max_target,
        } => {
            open_channel(
                ctx,
                pool,
                conn,
                id,
                peer,
                request_id,
                user_identity,
                nominal_hash_rate,
                max_target,
                None,
            )
            .await
        }
        Message::OpenExtendedMiningChannel {
            request_id,
            user_identity,
            nominal_hash_rate,
            max_target,
            min_extranonce_size,
        } => {
            open_channel(
                ctx,
                pool,
                conn,
                id,
                peer,
                request_id,
                user_identity,
                nominal_hash_rate,
                max_target,
                Some(min_extranonce_size),
            )
            .await
        }
        Message::UpdateChannel {
            channel_id,
            max_target,
            ..
        } => match conn.channels.get_mut(&channel_id) {
            None => Step::send(Message::UpdateChannelError {
                channel_id,
                error_code: b"invalid-channel-id".to_vec(),
            }),
            Some(ch) => {
                ch.max_target = max_target;
                if wire::meets(&ch.target, &max_target) {
                    Step::default()
                } else {
                    ch.target = max_target;
                    Step::send(Message::SetTarget {
                        channel_id,
                        maximum_target: max_target,
                    })
                }
            }
        },
        Message::CloseChannel {
            channel_id,
            reason_code,
        } => {
            conn.channels.remove(&channel_id);
            log.info(format!(
                "Stratum V2 connection {id} closed channel {channel_id}: {}",
                wire::text(&reason_code)
            ));
            Step::default()
        }
        Message::SubmitSharesStandard {
            channel_id,
            sequence_number,
            job_id,
            nonce,
            ntime,
            version,
        } => {
            submit(
                ctx,
                pool,
                conn,
                id,
                peer,
                Share {
                    channel_id,
                    sequence_number,
                    job_id,
                    nonce,
                    ntime,
                    version,
                    extranonce: None,
                },
            )
            .await
        }
        Message::SubmitSharesExtended {
            channel_id,
            sequence_number,
            job_id,
            nonce,
            ntime,
            version,
            extranonce,
        } => {
            submit(
                ctx,
                pool,
                conn,
                id,
                peer,
                Share {
                    channel_id,
                    sequence_number,
                    job_id,
                    nonce,
                    ntime,
                    version,
                    extranonce: Some(extranonce),
                },
            )
            .await
        }
        m @ Message::SetCustomMiningJob { .. } => {
            if !conn.work_selection {
                return refuse_close("SetCustomMiningJob without REQUIRES_WORK_SELECTION");
            }
            custom_job(ctx, pool, conn, id, peer, &m).await
        }
        other => refuse_close(&format!("{} is not a message a device sends", other.name())),
    }
}

/// Why a SetCustomMiningJob does not describe the job its token's declaration accepted, as the
/// error code SetCustomMiningJob.Error carries (SRI's vocabulary) and a detail for the log.
/// `full_extranonce` is the channel's: the pool's prefix and the device's part.
pub(crate) fn check_custom_job(
    job: &job_declarator::Accepted,
    network: bitcoin::Network,
    full_extranonce: usize,
    m: &Message,
) -> std::result::Result<(), (&'static str, String)> {
    let Message::SetCustomMiningJob {
        version,
        prev_hash,
        min_ntime,
        nbits,
        coinbase_tx_version,
        coinbase_prefix,
        coinbase_tx_input_n_sequence,
        coinbase_tx_outputs,
        coinbase_tx_locktime,
        merkle_path,
        ..
    } = m
    else {
        return Err(("invalid-job", "not a SetCustomMiningJob".into()));
    };
    if *version != job.version {
        return Err((
            "invalid-version",
            format!("0x{version:08x}, declared 0x{:08x}", job.version),
        ));
    }
    if let Some(tip) = job.tip {
        if *prev_hash != tip.prev_hash {
            return Err((
                "stale-chain-tip",
                format!(
                    "builds on {}, declared on {}",
                    wire::display_hex(prev_hash),
                    wire::display_hex(&tip.prev_hash)
                ),
            ));
        }
        if *nbits != tip.nbits {
            return Err((
                "invalid-nbits",
                format!("{nbits:08x}, the node's next block needs {:08x}", tip.nbits),
            ));
        }
    }
    if let Err(e) = bitcoin::check_bits(network, *nbits) {
        return Err(("invalid-nbits", format!("{e:#}")));
    }
    if *min_ntime > wire::now_secs().saturating_add(wire::MAX_FUTURE_NTIME) {
        return Err((
            "invalid-min-ntime",
            format!("{min_ntime} is more than two hours ahead"),
        ));
    }
    let coinbase = &job.coinbase;
    if *coinbase_tx_version != coinbase.version {
        return Err((
            "invalid-coinbase-tx-version",
            format!("{coinbase_tx_version}, declared {}", coinbase.version),
        ));
    }
    let script = &coinbase.inputs[0].script_sig;
    let declared_prefix = &script[..script.len().saturating_sub(job.extranonce_len)];
    if coinbase_prefix[..] != *declared_prefix {
        return Err((
            "invalid-coinbase-prefix",
            format!(
                "{}, declared {}",
                hex::encode(coinbase_prefix),
                hex::encode(declared_prefix)
            ),
        ));
    }
    if job.extranonce_len != full_extranonce {
        return Err((
            "invalid-coinbase-prefix",
            format!(
                "the declaration leaves {} bytes of extranonce and this channel's is {full_extranonce}",
                job.extranonce_len
            ),
        ));
    }
    if *coinbase_tx_input_n_sequence != coinbase.inputs[0].sequence {
        return Err((
            "invalid-coinbase-tx-input-n-sequence",
            format!(
                "0x{coinbase_tx_input_n_sequence:08x}, declared 0x{:08x}",
                coinbase.inputs[0].sequence
            ),
        ));
    }
    if coinbase_tx_outputs[..] != bitcoin::output_vector_bytes(&coinbase.outputs)[..] {
        return Err((
            "invalid-coinbase-tx-outputs",
            "not the declared coinbase's outputs".into(),
        ));
    }
    if *coinbase_tx_locktime != coinbase.locktime {
        return Err((
            "invalid-coinbase-tx-locktime",
            format!("{coinbase_tx_locktime}, declared {}", coinbase.locktime),
        ));
    }
    let txids: Vec<[u8; 32]> = job.txs.iter().map(bitcoin::Tx::txid).collect();
    if *merkle_path != bitcoin::coinbase_merkle_path(&txids) {
        return Err((
            "invalid-merkle-path",
            format!(
                "{} hashes that are not the path of the declared {} transactions",
                merkle_path.len(),
                txids.len()
            ),
        ));
    }
    // The coinbase the custom job describes, around a zero extranonce of the channel's size,
    // must be the declared one byte for byte: its prefix and its suffix.
    let outputs = bitcoin::parse_output_vector(coinbase_tx_outputs, 255)
        .map_err(|e| ("invalid-coinbase-tx-outputs", format!("{e:#}")))?;
    let rebuilt = bitcoin::Tx {
        version: *coinbase_tx_version,
        inputs: vec![bitcoin::TxIn {
            prev_txid: [0u8; 32],
            vout: u32::MAX,
            script_sig: [&coinbase_prefix[..], &vec![0u8; full_extranonce]].concat(),
            sequence: *coinbase_tx_input_n_sequence,
            witness: coinbase.inputs[0].witness.clone(),
        }],
        outputs,
        locktime: *coinbase_tx_locktime,
    }
    .serialize(coinbase.has_witness());
    let declared = [
        &job.prefix[..],
        &vec![0u8; job.extranonce_len],
        &job.suffix[..],
    ]
    .concat();
    if rebuilt != declared {
        return Err((
            "invalid-coinbase-tx",
            "the coinbase it describes is not the declared one".into(),
        ));
    }
    Ok(())
}

/// SetCustomMiningJob: redeem the token, check the job against its declaration, ask the model,
/// and on yes make it the channel's work.
async fn custom_job(
    ctx: &SpawnContext,
    pool: &Pool,
    conn: &mut Conn,
    id: ConnectionId,
    peer: SocketAddr,
    m: &Message,
) -> Step {
    let Message::SetCustomMiningJob {
        channel_id,
        request_id,
        token,
        version,
        prev_hash,
        min_ntime,
        nbits,
        merkle_path,
        ..
    } = m
    else {
        return Step::default();
    };
    let (channel_id, request_id) = (*channel_id, *request_id);
    let log = Log::new(Some(&ctx.status_tx));
    let error = |code: &str, why: String| {
        log.info(format!(
            "Stratum V2 connection {id} custom job {request_id} on channel {channel_id} refused: {code} ({why})"
        ));
        Step::send(Message::SetCustomMiningJobError {
            channel_id,
            request_id,
            error_code: code.as_bytes().to_vec(),
        })
    };
    let Some(ch) = conn.channels.get(&channel_id) else {
        return error("invalid-channel-id", "no such channel".into());
    };
    let Some(size) = ch.extranonce_size else {
        return error(
            "invalid-channel-id",
            "custom jobs run on extended channels".into(),
        );
    };
    let full = wire::EXTRANONCE_PREFIX_LEN + usize::from(size);
    let user = ch.user.clone();
    // The token is spent by asking, whatever follows: a declaration is redeemed at most once.
    let Some(job) = job_declarator::redeemable(pool).take(token) else {
        outcome(ctx, id, "set_custom_mining_job", "refused_invalid_token");
        return error(
            "invalid-mining-job-token",
            "not a token this server's job declarator issued for an accepted job, or one already redeemed".into(),
        );
    };
    if let Err((code, why)) = check_custom_job(&job, pool.network, full, m) {
        outcome(
            ctx,
            id,
            "set_custom_mining_job",
            "refused_invalid_custom_job",
        );
        return error(code, why);
    }
    let event = Event::new(
        &actions::CUSTOM_JOB_EVENT,
        json!({"channel_id": channel_id, "request_id": request_id, "user_identity": user,
               "declaration_request_id": job.request_id, "height": job.height,
               "prev_hash": wire::display_hex(prev_hash), "nbits": format!("{nbits:08x}"),
               "version": version, "min_ntime": min_ntime, "transactions": job.txs.len(),
               "coinbase_outputs": job.coinbase.outputs.iter().map(bitcoin::describe_output).collect::<Vec<_>>(),
               "coinbase_value_sats": job.coinbase.outputs.iter().map(|o| o.value).sum::<u64>(),
               "tip_checked": job.tip.is_some(), "remote_addr": peer.to_string()}),
    );
    match ask(ctx, id, event, "set_custom_mining_job").await {
        Verdict::Accept(_) => {}
        Verdict::Reject(code, _) => return error(&code, "the model refused it".into()),
        Verdict::Fail(code) => return error(code, "the model gave no usable answer".into()),
    }
    let Some(ch) = conn.channels.get_mut(&channel_id) else {
        return error(
            "invalid-channel-id",
            "the channel closed while the model was asked".into(),
        );
    };
    let job_id = pool.next_job.fetch_add(1, Ordering::Relaxed);
    if *prev_hash != ch.prev_hash {
        while let Some(old) = ch.jobs.pop_front() {
            ch.retire(old.id);
        }
        ch.seen.clear();
        ch.prev_hash = *prev_hash;
    } else if ch.jobs.len() >= MAX_JOBS {
        if let Some(old) = ch.jobs.pop_front() {
            ch.retire(old.id);
        }
    }
    log.info(format!(
        "Stratum V2 connection {id} channel {channel_id}: custom job {job_id} for declaration {} at height {:?} on {}",
        job.request_id,
        job.height,
        wire::display_hex(prev_hash)
    ));
    ch.jobs.push_back(Job {
        id: job_id,
        version: *version,
        ntime_start: *min_ntime,
        nbits: *nbits,
        prev_hash: *prev_hash,
        coinbase_prefix: job.prefix.clone(),
        coinbase_suffix: job.suffix.clone(),
        merkle_root: [0u8; 32],
        merkle_path: merkle_path.clone(),
        custom: Some(job),
    });
    Step::send(Message::SetCustomMiningJobSuccess {
        channel_id,
        request_id,
        job_id,
    })
}

/// Hand a block Rust verified to the configured node, once per hash. What the node said, for
/// the event: `accepted`, its reason (`duplicate`, `inconclusive`, `high-hash`, …),
/// `already-relayed` or `relay-failed`; None without a node.
pub(crate) async fn relay(
    ctx: &SpawnContext,
    pool: &Pool,
    id: ConnectionId,
    hash: &str,
    block: &[u8],
) -> Option<String> {
    let node = pool.node.as_ref()?;
    {
        let mut seen = pool.relayed.lock().unwrap_or_else(|e| e.into_inner());
        if seen.iter().any(|h| h == hash) {
            return Some("already-relayed".into());
        }
        if seen.len() >= MAX_RELAYED {
            seen.pop_front();
        }
        seen.push_back(hash.to_string());
    }
    let log = Log::new(Some(&ctx.status_tx));
    match node.submit_block(block).await {
        Ok(None) => {
            log.info(format!(
                "Stratum V2 connection {id}: Bitcoin Core accepted block {hash}"
            ));
            outcome(ctx, id, "relay_block", "relayed");
            Some("accepted".into())
        }
        Ok(Some(reason)) => {
            log.warn(format!(
                "Stratum V2 connection {id}: Bitcoin Core answered block {hash} with {reason}"
            ));
            outcome(ctx, id, "relay_block", "relay_refused");
            Some(reason)
        }
        Err(e) => {
            log.warn(format!(
                "Stratum V2 connection {id}: block {hash} was not relayed: {e:#}"
            ));
            outcome(ctx, id, "relay_block", "relay_failed");
            // Not remembered, so the next report of it tries again.
            let mut seen = pool.relayed.lock().unwrap_or_else(|e| e.into_inner());
            seen.retain(|h| h != hash);
            Some("relay-failed".into())
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn open_channel(
    ctx: &SpawnContext,
    pool: &Pool,
    conn: &mut Conn,
    id: ConnectionId,
    peer: SocketAddr,
    request_id: u32,
    user_identity: Vec<u8>,
    nominal_hash_rate: f32,
    max_target: [u8; 32],
    min_extranonce_size: Option<u16>,
) -> Step {
    let error = |code: &str| {
        Log::new(Some(&ctx.status_tx)).info(format!(
            "Stratum V2 connection {id} channel refused: {code}"
        ));
        Step::send(Message::OpenMiningChannelError {
            request_id,
            error_code: code.as_bytes().to_vec(),
        })
    };
    if conn.channels.len() >= MAX_CHANNELS {
        return error("max-channels-reached");
    }
    let extranonce_size = match min_extranonce_size {
        None => None,
        Some(_) if conn.flags & wire::REQUIRES_STANDARD_JOBS != 0 => {
            return error("unsupported-extended-channel");
        }
        Some(n) if usize::from(n) > wire::MAX_EXTRANONCE => {
            return error("min-extranonce-size-too-large");
        }
        Some(n) => Some(n.max(DEFAULT_EXTRANONCE_SIZE)),
    };
    let user = wire::text(&user_identity);
    let default = default_difficulty(nominal_hash_rate, pool.shares_per_minute);
    let mut data = json!({"channel_kind": if extranonce_size.is_some() {"extended"} else {"standard"},
        "user_identity": user, "nominal_hash_rate": nominal_hash_rate,
        "max_target_difficulty": wire::target_difficulty(&max_target),
        "default_difficulty": default, "remote_addr": peer.to_string()});
    if let Some(n) = extranonce_size {
        data["extranonce_size"] = json!(n);
    }
    let event = Event::new(&actions::OPEN_CHANNEL_EVENT, data);
    let extras = match ask(ctx, id, event, "open_channel").await {
        Verdict::Accept(extras) => extras,
        Verdict::Reject(code, _) => return error(&code),
        Verdict::Fail(code) => return error(code),
    };
    conn.next_channel_id = conn.next_channel_id.wrapping_add(1).max(1);
    while conn.channels.contains_key(&conn.next_channel_id) {
        conn.next_channel_id = conn.next_channel_id.wrapping_add(1).max(1);
    }
    let channel_id = conn.next_channel_id;
    let prefix = pool
        .next_prefix
        .fetch_add(1, Ordering::Relaxed)
        .to_be_bytes();
    conn.channels.insert(
        channel_id,
        Channel {
            id: channel_id,
            extranonce_size,
            user: user.clone(),
            prefix,
            target: wire::min_target(wire::target_for(default), max_target),
            max_target,
            prev_hash: [0u8; 32],
            height: 0,
            jobs: VecDeque::new(),
            retired: VecDeque::new(),
            seen: HashSet::new(),
        },
    );
    // The target the extras settle on is the one the success message carries.
    let follow = apply_extras(pool, conn, channel_id, &extras, true);
    let target = conn
        .channels
        .get(&channel_id)
        .map(|c| c.target)
        .unwrap_or(max_target);
    Log::new(Some(&ctx.status_tx)).info(format!(
        "Stratum V2 connection {id} opened {} channel {channel_id} for {user:?} at difficulty {:.6}",
        if extranonce_size.is_some() { "extended" } else { "standard" },
        wire::target_difficulty(&target)
    ));
    let success = match extranonce_size {
        None => Message::OpenStandardMiningChannelSuccess {
            request_id,
            channel_id,
            target,
            extranonce_prefix: prefix.to_vec(),
            group_channel_id: 0,
        },
        Some(n) => Message::OpenExtendedMiningChannelSuccess {
            request_id,
            channel_id,
            target,
            extranonce_size: n,
            extranonce_prefix: prefix.to_vec(),
            group_channel_id: 0,
        },
    };
    let mut out = vec![success];
    out.extend(follow);
    Step { out, close: false }
}

struct Share {
    channel_id: u32,
    sequence_number: u32,
    job_id: u32,
    nonce: u32,
    ntime: u32,
    version: u32,
    extranonce: Option<Vec<u8>>,
}

async fn submit(
    ctx: &SpawnContext,
    pool: &Pool,
    conn: &mut Conn,
    id: ConnectionId,
    peer: SocketAddr,
    s: Share,
) -> Step {
    let refuse = |code: &str, detail: String| {
        Log::new(Some(&ctx.status_tx)).info(format!(
            "Stratum V2 connection {id} share {} on channel {} refused: {code}{detail}",
            s.sequence_number, s.channel_id
        ));
        Step::send(Message::SubmitSharesError {
            channel_id: s.channel_id,
            sequence_number: s.sequence_number,
            error_code: code.as_bytes().to_vec(),
        })
    };
    let Some(ch) = conn.channels.get_mut(&s.channel_id) else {
        return refuse("invalid-channel-id", String::new());
    };
    match (ch.extranonce_size, &s.extranonce) {
        (None, None) => {}
        (Some(n), Some(e)) if e.len() == usize::from(n) => {}
        (Some(n), Some(e)) => {
            return refuse(
                "invalid-extranonce-size",
                format!(" ({} bytes, the channel rolls {n})", e.len()),
            )
        }
        _ => return refuse("invalid-channel-type", String::new()),
    }
    let Some(job) = ch.jobs.iter().find(|j| j.id == s.job_id) else {
        let code = if ch.retired.contains(&s.job_id) {
            "stale-share"
        } else {
            "invalid-job-id"
        };
        return refuse(code, String::new());
    };
    let now = wire::now_secs();
    if s.ntime < job.ntime_start || s.ntime > now.saturating_add(wire::MAX_FUTURE_NTIME) {
        return refuse(
            "invalid-timestamp",
            format!(" (ntime {}, job starts {})", s.ntime, job.ntime_start),
        );
    }
    if !wire::version_allowed(job.version, s.version, true) {
        return refuse(
            "invalid-version",
            format!(
                " (0x{:08x} against the job's 0x{:08x})",
                s.version, job.version
            ),
        );
    }
    let key: ShareKey = (
        s.job_id,
        s.nonce,
        s.ntime,
        s.version,
        s.extranonce.clone().unwrap_or_default(),
    );
    if ch.seen.contains(&key) {
        return refuse("duplicate-share", String::new());
    }
    let mut coinbase = Vec::new();
    let root = match &s.extranonce {
        None => job.merkle_root,
        Some(e) => {
            coinbase = [
                &job.coinbase_prefix[..],
                &ch.prefix,
                e,
                &job.coinbase_suffix,
            ]
            .concat();
            match &job.custom {
                // The pool's own coinbases are legacy-serialised and carry no transactions.
                None => wire::merkle_root(&coinbase, &[]),
                // A declared coinbase is serialised as declared (segwit, usually): its txid,
                // folded up the custom job's path.
                Some(_) => match bitcoin::Tx::parse(&coinbase) {
                    Ok(tx) => bitcoin::fold_path(tx.txid(), &job.merkle_path),
                    Err(e) => return refuse("invalid-share", format!(" ({e:#})")),
                },
            }
        }
    };
    let header = wire::header(
        s.version,
        &job.prev_hash,
        &root,
        s.ntime,
        job.nbits,
        s.nonce,
    );
    let hash = wire::sha256d(&header);
    // A custom job is a real block template: a share meeting its nbits is a block.
    let block = job
        .custom
        .as_ref()
        .filter(|_| {
            bitcoin::compact_to_target(job.nbits)
                .map(|t| wire::meets(&hash, &t))
                .unwrap_or(false)
        })
        .map(|c| (c.height, bitcoin::block_bytes(&header, &coinbase, &c.txs)));
    let custom = job.custom.is_some();
    let hash_hex = wire::display_hex(&hash);
    let share_difficulty = wire::difficulty(&hash);
    let difficulty = wire::target_difficulty(&ch.target);
    // A block is never refused for missing the channel's target: a work-selecting client
    // (SRI's jd_client does) forwards every share that meets the network target, whatever the
    // channel's difficulty, and a pool that dropped one would be dropping the block.
    if block.is_none() && !wire::meets(&hash, &ch.target) {
        return refuse(
            "difficulty-too-low",
            format!(" ({share_difficulty:.6} < {difficulty:.6}): {hash_hex}"),
        );
    }
    if ch.seen.len() >= MAX_SEEN_SHARES {
        ch.seen.clear();
    }
    ch.seen.insert(key);
    let user = ch.user.clone();
    let kind = ch.kind();
    let relay = match &block {
        None => None,
        Some((height, bytes)) => {
            let log = Log::new(Some(&ctx.status_tx));
            log.info(format!(
                "Stratum V2 connection {id}: share {} on custom job {} is block {hash_hex} at height {height:?} ({} bytes)",
                s.sequence_number,
                s.job_id,
                bytes.len()
            ));
            log.info_to(
                crate::logging::emit::Sink::FileOnly,
                format!("Stratum V2 pool block {hash_hex}: {}", hex::encode(bytes)),
            );
            relay(ctx, pool, id, &hash_hex, bytes).await
        }
    };
    let event = Event::new(
        &actions::SHARE_EVENT,
        json!({"user_identity": user, "channel_id": s.channel_id, "channel_kind": kind,
               "job_id": s.job_id, "sequence_number": s.sequence_number, "hash": hash_hex,
               "share_difficulty": share_difficulty, "difficulty": difficulty, "nonce": s.nonce,
               "ntime": s.ntime, "version": s.version, "custom_job": custom,
               "solves_block": block.is_some(), "relay": relay,
               "remote_addr": peer.to_string()}),
    );
    match ask(ctx, id, event, "share").await {
        Verdict::Accept(extras) => {
            let mut out = vec![Message::SubmitSharesSuccess {
                channel_id: s.channel_id,
                last_sequence_number: s.sequence_number,
                new_submits_accepted_count: 1,
                // U64 cannot carry a fractional difficulty; a share below 1 counts as 1.
                new_shares_sum: difficulty.round().max(1.0) as u64,
            }];
            out.extend(apply_extras(pool, conn, s.channel_id, &extras, false));
            Step { out, close: false }
        }
        Verdict::Reject(code, extras) => {
            let mut out = vec![Message::SubmitSharesError {
                channel_id: s.channel_id,
                sequence_number: s.sequence_number,
                error_code: code.into_bytes(),
            }];
            out.extend(apply_extras(pool, conn, s.channel_id, &extras, false));
            Step { out, close: false }
        }
        Verdict::Fail(code) => Step::send(Message::SubmitSharesError {
            channel_id: s.channel_id,
            sequence_number: s.sequence_number,
            error_code: code.as_bytes().to_vec(),
        }),
    }
}

async fn session(
    ctx: &SpawnContext,
    pool: &Pool,
    id: ConnectionId,
    mut socket: TcpStream,
    peer: SocketAddr,
    idle: Duration,
) -> Result<()> {
    let log = Log::new(Some(&ctx.status_tx));
    let session = match wire::accept_handshake(
        &mut socket,
        &pool.key,
        &pool.authority,
        pool.cert_validity,
        HANDSHAKE_TIMEOUT,
    )
    .await
    {
        Ok(s) => s,
        Err(e) => {
            log.info(format!(
                "Stratum V2 connection {id} handshake failed: {e:#}"
            ));
            return Ok(());
        }
    };
    let (r, w) = tokio::io::split(socket);
    let (mut reader, mut writer) = wire::transport(r, w, session, pool.role.max_inbound_payload());
    let mut first = None;
    match pool.role {
        Role::Pool => {}
        Role::PoolAndJobDeclarator => {
            // One listener, two protocols: the first message is SetupConnection, and its first
            // byte names the protocol this connection speaks.
            let Some(frame) = reader.next(idle).await? else {
                return Ok(());
            };
            if frame.extension() == 0
                && frame.msg_type == wire::msg::SETUP_CONNECTION
                && frame.payload.first() == Some(&wire::JOB_DECLARATION_PROTOCOL)
            {
                reader.set_max_payload(job_declarator::MAX_INBOUND_PAYLOAD);
                let result = job_declarator::run(
                    ctx,
                    pool,
                    id,
                    peer,
                    &mut reader,
                    &mut writer,
                    idle,
                    Some(frame),
                )
                .await;
                writer.shutdown().await;
                return result;
            }
            first = Some(frame);
        }
        Role::TemplateProvider => {
            let result =
                template_provider::run(ctx, pool, id, peer, &mut reader, &mut writer, idle).await;
            writer.shutdown().await;
            return result;
        }
        Role::JobDeclarator => {
            let result =
                job_declarator::run(ctx, pool, id, peer, &mut reader, &mut writer, idle, None)
                    .await;
            writer.shutdown().await;
            return result;
        }
    }
    let mut conn = Conn {
        setup: false,
        flags: 0,
        work_selection: false,
        channels: HashMap::new(),
        next_channel_id: 0,
    };
    let mut received: std::collections::BTreeMap<&'static str, u64> = Default::default();
    let result = async {
        loop {
            let frame = match first.take() {
                Some(f) => f,
                None => match reader.next(idle).await? {
                    Some(f) => f,
                    None => break,
                },
            };
            ctx.state
                .update_connection_stats(ctx.server_id, id, None, None, Some(1), None)
                .await;
            if frame.extension() != 0 {
                log.debug(format!(
                    "Stratum V2 connection {id} ignored extension 0x{:04x} message 0x{:02x}",
                    frame.extension(),
                    frame.msg_type
                ));
                continue;
            }
            let message = Message::decode(&frame)?;
            *received.entry(message.name()).or_default() += 1;
            let step = handle(ctx, pool, &mut conn, id, peer, message).await;
            if conn.work_selection {
                reader.set_max_payload(MAX_WORK_SELECTION_PAYLOAD);
            }
            let mut sent = 0;
            for m in &step.out {
                sent += writer.send(m).await?;
            }
            if !step.out.is_empty() {
                ctx.state
                    .update_connection_stats(
                        ctx.server_id,
                        id,
                        None,
                        Some(sent as u64),
                        None,
                        Some(step.out.len() as u64),
                    )
                    .await;
            }
            if step.close {
                break;
            }
        }
        Ok::<(), anyhow::Error>(())
    }
    .await;
    if !received.is_empty() {
        log.info(format!(
            "Stratum V2 pool connection {id} received: {}",
            template_provider::summary(&received)
        ));
    }
    writer.shutdown().await;
    result
}
