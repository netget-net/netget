//! Kerberos V5 KDC (RFC 4120): AS and TGS exchanges over UDP and TCP on one port.
//!
//! The model decides policy; this module owns the sockets, the bounds and the guarantee that
//! **no decision means no ticket**. `kdc.rs` owns the cryptography and the request analysis,
//! `actions.rs` the model's vocabulary, `codec.rs` the bounded DER walk and the keys.
//!
//! Per request: the per-source rate limit, then the lookaside cache (a retransmission of a
//! request already answered gets the same answer, one still in flight waits for it, and
//! neither reaches the model twice), then [`kdc::Kdc::analyze`], which answers mechanical
//! refusals itself and hands policy questions to the model, then [`decide`], the fail-closed
//! rule. See `src/server/kerberos/AGENTS.md`.

pub mod actions;
pub mod codec;
pub mod kdc;

pub use actions::KerberosProtocol;

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, watch, Semaphore};
use tracing::{debug, trace, warn};

use crate::llm::action_helper::call_llm;
use crate::llm::ollama_client::OllamaClient;
use crate::logging::emit::Log;
use crate::protocol::{Event, SpawnContext};
use crate::server::accept_bounded::{accept_bounded, ConnectionLimiter, DEFAULT_MAX_CONNECTIONS};
use crate::server::connection::ConnectionId;
use crate::state::app_state::AppState;
use crate::state::server::{ConnectionState, ConnectionStatus, ProtocolConnectionInfo};
use crate::state::ServerId;

use actions::{
    Record, RequestContext, DEFAULT_MAX_CLOCK_SKEW_SECS, DEFAULT_MAX_RENEWABLE_LIFETIME_SECS,
    DEFAULT_MAX_REQUESTS_PER_MINUTE, DEFAULT_MAX_TICKET_LIFETIME_SECS, DEFAULT_REALM,
    KERBEROS_AS_REQUEST_EVENT, KERBEROS_TGS_REQUEST_EVENT, MAX_CLOCK_SKEW_LIMIT_SECS,
    MAX_TICKET_LIFETIME_LIMIT_SECS,
};
use codec::{
    KDC_ERR_SVC_UNAVAILABLE, KRB_ERR_FIELD_TOOLONG, KRB_ERR_GENERIC, KRB_ERR_RESPONSE_TOO_BIG,
    MAX_MESSAGE_LEN,
};
use kdc::{Analysis, Exchange, Kdc, KdcConfig, Pending};

/// How long a new TCP connection may take to send its first length prefix.
pub const FIRST_BYTE_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a TCP connection may sit idle between requests before it is closed.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(30);
/// How long the body of a request may take to arrive once its length is known.
pub const BODY_READ_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a reply may take to write before the connection is dropped.
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(10);

/// The largest reply sent over UDP. A larger one is replaced by KRB_ERR_RESPONSE_TOO_BIG, which
/// tells the client to retry over TCP (RFC 4120 §7.2.1). 1400 keeps a reply in one unfragmented
/// datagram on any ordinary path.
pub const MAX_UDP_REPLY: usize = 1400;

/// UDP requests being answered at once, across all sources. A datagram past it is dropped:
/// UDP sources are forgeable, so the per-source limit alone cannot bound the total.
pub const MAX_UDP_IN_FLIGHT: usize = 256;

/// How long an answer is remembered for retransmissions, and the most remembered at once.
pub const LOOKASIDE_TTL: Duration = Duration::from_secs(120);
pub const MAX_LOOKASIDE_ENTRIES: usize = 4096;

/// How long a retransmission waits for the original's answer.
const LOOKASIDE_WAIT: Duration = Duration::from_secs(330);

/// Source addresses tracked by the rate limiter at once.
pub const MAX_RATE_SOURCES: usize = 16_384;

/// Attempts at finding a port free on both UDP and TCP when the caller asked for port 0.
const BIND_ATTEMPTS: usize = 16;

/// A request's answer, or `None` for "send nothing" (a message that was not a request).
type Answer = Option<Vec<u8>>;

enum Lookaside {
    InFlight(watch::Receiver<Option<Answer>>),
    Done(Answer),
}

struct LookasideEntry {
    at: crate::utils::clock::Instant,
    state: Lookaside,
}

/// A per-source token bucket: `per_minute` requests a minute, bursting to the same number.
struct RateLimiter {
    per_minute: f64,
    buckets: HashMap<IpAddr, (f64, crate::utils::clock::Instant)>,
}

impl RateLimiter {
    fn allow(&mut self, ip: IpAddr) -> bool {
        let now = crate::utils::clock::Instant::now();
        if self.buckets.len() >= MAX_RATE_SOURCES && !self.buckets.contains_key(&ip) {
            // Forget sources whose buckets have refilled; they are indistinguishable from new.
            let per_minute = self.per_minute;
            self.buckets.retain(|_, (tokens, at)| {
                let refilled = *tokens + now.duration_since(*at).as_secs_f64() * per_minute / 60.0;
                refilled < per_minute
            });
            if self.buckets.len() >= MAX_RATE_SOURCES {
                return false;
            }
        }
        let (tokens, at) = self.buckets.entry(ip).or_insert((self.per_minute, now));
        *tokens = (*tokens + now.duration_since(*at).as_secs_f64() * self.per_minute / 60.0)
            .min(self.per_minute);
        *at = now;
        if *tokens >= 1.0 {
            *tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

struct Shared {
    kdc: Arc<Kdc>,
    lookaside: Mutex<HashMap<(IpAddr, [u8; 32]), LookasideEntry>>,
    limiter: Mutex<RateLimiter>,
    llm_client: OllamaClient,
    state: Arc<AppState>,
    status_tx: mpsc::UnboundedSender<String>,
    server_id: ServerId,
}

impl Shared {
    fn allow(&self, ip: IpAddr) -> bool {
        self.limiter
            .lock()
            .map(|mut l| l.allow(ip))
            .unwrap_or(false)
    }
}

pub struct KerberosServer;

/// Read the startup parameters into a configuration, deriving every key.
fn config_from(ctx: &SpawnContext) -> Result<(KdcConfig, u64)> {
    let params = ctx.startup_params.as_ref().context(
        "the Kerberos KDC needs startup parameter principal_passwords: an object mapping each \
         principal to its password",
    )?;
    let realm = params
        .get_optional_string("realm")?
        .unwrap_or_else(|| DEFAULT_REALM.to_string());
    let object = params.get_object("principal_passwords")?;
    let mut passwords = Vec::with_capacity(object.len());
    for (name, value) in object.iter() {
        let password = value
            .as_str()
            .with_context(|| format!("principal_passwords['{name}'] must be a string"))?;
        passwords.push((name.clone(), password.to_string()));
    }
    let no_preauth = match params.get_optional_array("no_preauth_principals")? {
        Some(list) => list
            .iter()
            .map(|v| {
                v.as_str()
                    .map(str::to_string)
                    .context("no_preauth_principals must list principal names")
            })
            .collect::<Result<Vec<_>>>()?,
        None => Vec::new(),
    };
    let max_life = params
        .get_optional_u64("max_ticket_lifetime_secs")?
        .unwrap_or(DEFAULT_MAX_TICKET_LIFETIME_SECS);
    let max_renew = params
        .get_optional_u64("max_renewable_lifetime_secs")?
        .unwrap_or(DEFAULT_MAX_RENEWABLE_LIFETIME_SECS);
    let skew = params
        .get_optional_u64("max_clock_skew_secs")?
        .unwrap_or(DEFAULT_MAX_CLOCK_SKEW_SECS);
    let per_minute = params
        .get_optional_u64("max_requests_per_minute_per_source")?
        .unwrap_or(DEFAULT_MAX_REQUESTS_PER_MINUTE);
    anyhow::ensure!(
        (60..=MAX_TICKET_LIFETIME_LIMIT_SECS).contains(&max_life),
        "max_ticket_lifetime_secs must be between 60 and {MAX_TICKET_LIFETIME_LIMIT_SECS}"
    );
    anyhow::ensure!(
        max_renew <= MAX_TICKET_LIFETIME_LIMIT_SECS,
        "max_renewable_lifetime_secs must be at most {MAX_TICKET_LIFETIME_LIMIT_SECS}"
    );
    anyhow::ensure!(
        (1..=MAX_CLOCK_SKEW_LIMIT_SECS).contains(&skew),
        "max_clock_skew_secs must be between 1 and {MAX_CLOCK_SKEW_LIMIT_SECS}"
    );
    anyhow::ensure!(
        (1..=100_000).contains(&per_minute),
        "max_requests_per_minute_per_source must be between 1 and 100000"
    );
    let config = KdcConfig::new(
        &realm,
        &passwords,
        &no_preauth,
        max_life as i64,
        max_renew as i64,
        skew as i64,
    )?;
    Ok((config, per_minute))
}

/// Bind UDP and TCP on the same port. For port 0, the UDP port the system picks is tried on
/// TCP, again with a fresh one if it is taken there.
async fn bind_both(addr: SocketAddr) -> Result<(UdpSocket, TcpListener)> {
    let mut last = None;
    for _ in 0..BIND_ATTEMPTS {
        let udp = UdpSocket::bind(addr)
            .await
            .with_context(|| format!("Kerberos could not bind UDP {addr}"))?;
        let local = udp.local_addr()?;
        match TcpListener::bind(local).await {
            Ok(tcp) => return Ok((udp, tcp)),
            Err(e) if addr.port() == 0 => last = Some(e),
            Err(e) => {
                return Err(anyhow!(e))
                    .with_context(|| format!("Kerberos could not bind TCP {local}"))
            }
        }
    }
    Err(anyhow!(
        "Kerberos found no port free on both UDP and TCP after {BIND_ATTEMPTS} attempts: {}",
        last.map(|e| e.to_string()).unwrap_or_default()
    ))
}

impl KerberosServer {
    /// Derive the keys, bind both sockets and serve. Returns `Err` — so the server is marked
    /// as failed — without principals, with a bad parameter, or when a socket cannot be bound.
    pub async fn spawn(ctx: SpawnContext) -> Result<SocketAddr> {
        let (config, per_minute) = config_from(&ctx)?;
        let (udp, tcp) = bind_both(ctx.legacy_listen_addr()).await?;
        let local = udp.local_addr()?;
        Log::new(Some(&ctx.status_tx)).info(format!(
            "Kerberos KDC for realm {} listening on {local} (UDP and TCP); principals: {}",
            config.realm,
            config.principal_names().join(", ")
        ));
        let shared = Arc::new(Shared {
            kdc: Arc::new(Kdc::new(config)),
            lookaside: Mutex::new(HashMap::new()),
            limiter: Mutex::new(RateLimiter {
                per_minute: per_minute as f64,
                buckets: HashMap::new(),
            }),
            llm_client: ctx.llm_client.clone(),
            state: ctx.state.clone(),
            status_tx: ctx.status_tx.clone(),
            server_id: ctx.server_id,
        });

        let udp = Arc::new(udp);
        let udp_shared = shared.clone();
        let udp_loop = tokio::spawn(async move { udp_loop(udp, udp_shared, local).await });
        ctx.state
            .register_server_task(ctx.server_id, udp_loop)
            .await;

        let tcp_shared = shared.clone();
        let tcp_loop = tokio::spawn(async move { tcp_loop(tcp, tcp_shared, local).await });
        ctx.state
            .register_server_task(ctx.server_id, tcp_loop)
            .await;
        Ok(local)
    }
}

async fn new_connection(
    shared: &Shared,
    peer: SocketAddr,
    local: SocketAddr,
    bytes: usize,
) -> ConnectionId {
    let id = ConnectionId::new(shared.state.get_next_unified_id().await);
    let now = crate::utils::clock::Instant::now();
    shared
        .state
        .add_connection_to_server(
            shared.server_id,
            ConnectionState {
                id,
                remote_addr: peer,
                local_addr: local,
                bytes_sent: 0,
                bytes_received: bytes as u64,
                packets_sent: 0,
                packets_received: u64::from(bytes > 0),
                last_activity: now,
                status: ConnectionStatus::Active,
                status_changed_at: now,
                protocol_info: ProtocolConnectionInfo::empty(),
            },
        )
        .await;
    let _ = shared.status_tx.send("__UPDATE_UI__".to_string());
    id
}

async fn udp_loop(socket: Arc<UdpSocket>, shared: Arc<Shared>, local: SocketAddr) {
    let in_flight = Arc::new(Semaphore::new(MAX_UDP_IN_FLIGHT));
    // One byte past the bound, so an oversize datagram is seen as oversize rather than truncated
    // into something that might parse.
    let mut buf = vec![0u8; MAX_MESSAGE_LEN + 1];
    loop {
        let (n, peer) = match socket.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionRefused
                ) =>
            {
                continue
            }
            Err(e) => {
                Log::new(Some(&shared.status_tx)).error(format!("Kerberos UDP receive error: {e}"));
                break;
            }
        };
        if n > MAX_MESSAGE_LEN {
            warn!("Kerberos dropped a {n}-byte datagram from {peer} decision=fail_closed_oversize");
            continue;
        }
        if !shared.allow(peer.ip()) {
            debug!("Kerberos dropped a datagram from {peer} decision=rate_limited");
            continue;
        }
        let Ok(permit) = in_flight.clone().try_acquire_owned() else {
            warn!("Kerberos dropped a datagram from {peer}: {MAX_UDP_IN_FLIGHT} already in flight decision=fail_closed_busy");
            continue;
        };
        let message = buf[..n].to_vec();
        trace!("Kerberos {n} bytes from {peer} over UDP");
        let conn = new_connection(&shared, peer, local, n).await;
        let task_shared = shared.clone();
        let sock = socket.clone();
        shared
            .state
            .spawn_server_task(shared.server_id, async move {
                let _permit = permit;
                let Some(mut reply) = serve(&task_shared, message, peer, "udp", Some(conn)).await
                else {
                    return;
                };
                if reply.len() > MAX_UDP_REPLY {
                    debug!(
                        "Kerberos reply to {peer} is {} bytes; answering KRB_ERR_RESPONSE_TOO_BIG \
                         decision=response_too_big",
                        reply.len()
                    );
                    reply = task_shared
                        .kdc
                        .error(KRB_ERR_RESPONSE_TOO_BIG, None, None, None, None);
                }
                match sock.send_to(&reply, peer).await {
                    Ok(sent) => {
                        task_shared
                            .state
                            .update_connection_stats(
                                task_shared.server_id,
                                conn,
                                None,
                                Some(sent as u64),
                                None,
                                Some(1),
                            )
                            .await;
                    }
                    Err(e) => warn!("Kerberos could not answer {peer}: {e}"),
                }
            })
            .await;
    }
}

async fn tcp_loop(listener: TcpListener, shared: Arc<Shared>, local: SocketAddr) {
    let limiter = ConnectionLimiter::new(DEFAULT_MAX_CONNECTIONS);
    loop {
        // No refusal bytes: a KDC has nothing to say to a connection that sent no request.
        let (stream, peer, permit) = match accept_bounded(
            &listener,
            &limiter,
            &[],
            "Kerberos",
            Some(&shared.status_tx),
        )
        .await
        {
            Ok(v) => v,
            Err(e) => {
                Log::new(Some(&shared.status_tx)).error(format!("Kerberos TCP accept error: {e}"));
                break;
            }
        };
        let task_shared = shared.clone();
        shared
            .state
            .spawn_server_task(shared.server_id, async move {
                let _permit = permit;
                let conn = new_connection(&task_shared, peer, local, 0).await;
                handle_stream(&task_shared, stream, peer, conn).await;
                task_shared
                    .state
                    .update_connection_status(task_shared.server_id, conn, ConnectionStatus::Closed)
                    .await;
                let _ = task_shared.status_tx.send("__UPDATE_UI__".to_string());
            })
            .await;
    }
}

/// Serve length-prefixed requests on one connection until the peer closes, goes idle, or
/// breaks a bound.
async fn handle_stream(
    shared: &Arc<Shared>,
    mut stream: TcpStream,
    peer: SocketAddr,
    conn: ConnectionId,
) {
    let mut first = true;
    loop {
        let wait = if first {
            FIRST_BYTE_TIMEOUT
        } else {
            IDLE_TIMEOUT
        };
        first = false;
        let mut prefix = [0u8; 4];
        match tokio::time::timeout(wait, stream.read_exact(&mut prefix)).await {
            Ok(Ok(_)) => {}
            Ok(Err(_)) => return,
            Err(_) => {
                debug!("Kerberos TCP {peer} idle for {wait:?}; closing decision=idle_timeout");
                return;
            }
        }
        let declared = u32::from_be_bytes(prefix);
        // RFC 4120 §7.2.2: the high bit is reserved, and a length the KDC cannot handle is
        // answered with KRB_ERR_FIELD_TOOLONG before the stream is closed. Nothing past the
        // prefix is read.
        if declared & 0x8000_0000 != 0 || declared as usize > MAX_MESSAGE_LEN {
            warn!(
                "Kerberos TCP {peer} declared a {declared}-byte request (limit {MAX_MESSAGE_LEN}) \
                 decision=fail_closed_oversize"
            );
            let reply = shared
                .kdc
                .error(KRB_ERR_FIELD_TOOLONG, None, None, None, None);
            let _ = write_record(&mut stream, &reply).await;
            return;
        }
        let mut message = vec![0u8; declared as usize];
        match tokio::time::timeout(BODY_READ_TIMEOUT, stream.read_exact(&mut message)).await {
            Ok(Ok(_)) => {}
            Ok(Err(_)) => return,
            Err(_) => {
                debug!("Kerberos TCP {peer} stalled mid-request decision=body_timeout");
                return;
            }
        }
        if !shared.allow(peer.ip()) {
            debug!("Kerberos closed TCP {peer} decision=rate_limited");
            return;
        }
        shared
            .state
            .update_connection_stats(
                shared.server_id,
                conn,
                Some(4 + declared as u64),
                None,
                Some(1),
                None,
            )
            .await;
        let Some(reply) = serve(shared, message, peer, "tcp", Some(conn)).await else {
            return;
        };
        if write_record(&mut stream, &reply).await.is_err() {
            return;
        }
        shared
            .state
            .update_connection_stats(
                shared.server_id,
                conn,
                None,
                Some(4 + reply.len() as u64),
                None,
                Some(1),
            )
            .await;
    }
}

async fn write_record(stream: &mut TcpStream, reply: &[u8]) -> std::io::Result<()> {
    let mut framed = Vec::with_capacity(4 + reply.len());
    framed.extend_from_slice(&(reply.len() as u32).to_be_bytes());
    framed.extend_from_slice(reply);
    match tokio::time::timeout(WRITE_TIMEOUT, stream.write_all(&framed)).await {
        Ok(r) => r,
        Err(_) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "write timed out",
        )),
    }
}

/// The lookaside cache in front of [`answer`].
async fn serve(
    shared: &Arc<Shared>,
    message: Vec<u8>,
    peer: SocketAddr,
    transport: &'static str,
    conn: Option<ConnectionId>,
) -> Answer {
    let digest: [u8; 32] = Sha256::digest(&message).into();
    let key = (peer.ip(), digest);
    enum Step {
        Replay(Answer),
        Wait(watch::Receiver<Option<Answer>>),
        Decide(Option<watch::Sender<Option<Answer>>>),
    }
    // Decided under the lock, acted on after it is released: the guard never crosses an await.
    let step = match shared.lookaside.lock() {
        Err(_) => return None,
        Ok(mut cache) => {
            let now = crate::utils::clock::Instant::now();
            if cache.len() >= MAX_LOOKASIDE_ENTRIES {
                cache.retain(|_, e| now.duration_since(e.at) < LOOKASIDE_TTL);
                if cache.len() >= MAX_LOOKASIDE_ENTRIES {
                    // Everything is fresh: forget the finished answers before refusing to cache.
                    cache.retain(|_, e| matches!(e.state, Lookaside::InFlight(_)));
                }
            }
            match cache.get(&key) {
                Some(e) if now.duration_since(e.at) < LOOKASIDE_TTL => match &e.state {
                    Lookaside::Done(answer) => Step::Replay(answer.clone()),
                    Lookaside::InFlight(rx) => Step::Wait(rx.clone()),
                },
                _ if cache.len() >= MAX_LOOKASIDE_ENTRIES => Step::Decide(None),
                _ => {
                    let (tx, rx) = watch::channel(None);
                    cache.insert(
                        key,
                        LookasideEntry {
                            at: now,
                            state: Lookaside::InFlight(rx),
                        },
                    );
                    Step::Decide(Some(tx))
                }
            }
        }
    };
    let sender = match step {
        Step::Replay(answer) => {
            debug!("Kerberos {peer} retransmitted an answered request decision=lookaside_replay");
            return answer;
        }
        Step::Wait(mut rx) => {
            debug!("Kerberos {peer} retransmitted a request still being decided decision=lookaside_wait");
            return match tokio::time::timeout(LOOKASIDE_WAIT, rx.wait_for(|v| v.is_some())).await {
                Ok(Ok(v)) => v.clone().flatten(),
                _ => None,
            };
        }
        Step::Decide(sender) => sender,
    };
    let result = answer(shared, &message, peer, transport, conn).await;
    if let Some(tx) = sender {
        if let Ok(mut cache) = shared.lookaside.lock() {
            cache.insert(
                key,
                LookasideEntry {
                    at: crate::utils::clock::Instant::now(),
                    state: Lookaside::Done(result.clone()),
                },
            );
        }
        let _ = tx.send(Some(result.clone()));
    }
    result
}

/// Analyse one request and answer it: mechanically, or by asking the model.
async fn answer(
    shared: &Arc<Shared>,
    message: &[u8],
    peer: SocketAddr,
    transport: &'static str,
    conn: Option<ConnectionId>,
) -> Answer {
    match shared.kdc.analyze(message, peer, transport) {
        Analysis::Ignore(why) => {
            debug!("Kerberos ignored a message from {peer}: {why} decision=not_a_request");
            None
        }
        Analysis::Answer(m) => {
            Log::new(Some(&shared.status_tx)).info(format!(
                "Kerberos request from {peer} over {transport} refused by the KDC decision={} ({})",
                m.decision, m.detail
            ));
            Some(m.reply)
        }
        Analysis::Ask(pending) => Some(ask_model(shared, *pending, conn).await),
    }
}

async fn ask_model(shared: &Arc<Shared>, pending: Pending, conn: Option<ConnectionId>) -> Vec<u8> {
    let pending = Arc::new(pending);
    let records = Arc::new(Mutex::new(Vec::<Record>::new()));
    let protocol = KerberosProtocol::for_request(RequestContext {
        kdc: shared.kdc.clone(),
        pending: pending.clone(),
        records: records.clone(),
    });
    let event_type = match pending.exchange {
        Exchange::As => &KERBEROS_AS_REQUEST_EVENT,
        Exchange::Tgs => &KERBEROS_TGS_REQUEST_EVENT,
    };
    let event = Event::new(event_type, shared.kdc.event_data(&pending));
    let outcome = call_llm(
        &shared.llm_client,
        &shared.state,
        shared.server_id,
        conn,
        &event,
        &protocol,
    )
    .await;
    let records = records.lock().map(|r| r.clone()).unwrap_or_default();
    let (decision, detail, reply) = decide(&shared.kdc, &pending, outcome, &records);
    let label = match pending.exchange {
        Exchange::As => "AS-REQ",
        Exchange::Tgs => "TGS-REQ",
    };
    let line = format!(
        "Kerberos {label} {}@{} -> {} from {} decision={decision} {detail}",
        pending.client, pending.client_realm, pending.service, pending.source
    );
    let log = Log::new(Some(&shared.status_tx));
    if decision.starts_with("fail_closed") {
        log.error(format!(
            "{line} (refused because no usable decision was produced)"
        ));
    } else {
        log.info(line);
    }
    reply
}

/// **The fail-closed rule.** Returns the decision tag, a detail for the log, and the reply.
///
/// - The first reply an action built (its [`Record`]) is sent, tagged with what it decided.
/// - The LLM call failed: KDC_ERR_SVC_UNAVAILABLE, `fail_closed_llm_error`.
/// - The model answered nothing: KRB_ERR_GENERIC, `fail_closed_no_action`.
/// - The model answered, but no action could be executed: KRB_ERR_GENERIC,
///   `fail_closed_action_error`.
///
/// None of these codes is in the model's own refusal vocabulary, so a refusal the model chose
/// and one nobody chose differ on the wire as well as in the log. Nothing here issues a ticket.
pub fn decide(
    kdc: &Kdc,
    pending: &Pending,
    outcome: Result<crate::llm::ExecutionResult>,
    records: &[Record],
) -> (&'static str, String, Vec<u8>) {
    let result = match outcome {
        Ok(r) => r,
        Err(e) => {
            let category = match crate::utils::wire_failure::WireFailure::classify(&e) {
                crate::utils::wire_failure::WireFailure::Overloaded => "overloaded",
                crate::utils::wire_failure::WireFailure::Unavailable => "unavailable",
            };
            return (
                "fail_closed_llm_error",
                format!("category={category}: {e}"),
                kdc.fail_closed(
                    pending,
                    KDC_ERR_SVC_UNAVAILABLE,
                    "no policy decision: the policy engine is unavailable",
                ),
            );
        }
    };
    if let Some(first) = records.first() {
        if records.len() > 1 {
            warn!(
                "Kerberos ignored {} extra answer(s) for {}; one request gets one reply",
                records.len() - 1,
                pending.client
            );
        }
        return (first.decision, first.detail.clone(), first.reply.clone());
    }
    let (decision, detail) = if result.raw_actions.is_empty() {
        (
            "fail_closed_no_action",
            "the model answered with nothing".to_string(),
        )
    } else {
        (
            "fail_closed_action_error",
            result
                .failure_summary()
                .unwrap_or_else(|| "no action produced a reply".to_string()),
        )
    };
    (
        decision,
        detail,
        kdc.fail_closed(pending, KRB_ERR_GENERIC, "no policy decision was produced"),
    )
}
