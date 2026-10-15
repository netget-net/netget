//! H.323 gatekeeper: H.225.0 RAS over UDP.
//!
//! NetGet decodes and encodes every RAS message and keeps the gatekeeper's runtime state —
//! registrations (bounded by [`MAX_REGISTRATIONS`], each expiring at its time-to-live) and
//! admitted calls (bounded by [`MAX_CALLS`]). Nothing is stored past the process.
//!
//! The model decides the policy:
//!
//! - **GRQ** → `h323_gatekeeper_request`: GCF or GRJ.
//! - **RRQ** (full) → `h323_registration_request`: RCF with the aliases and time-to-live it
//!   chooses, or RRJ. A lightweight RRQ (`keepAlive`) for a live registration is refreshed by
//!   NetGet without asking; for an unknown endpoint it is RRJ `fullRegistrationRequired`.
//! - **ARQ** → `h323_admission_request`: ACF naming the destination signalling address — a
//!   registered endpoint's, chosen by alias, or an explicit `ip:port` — or ARJ.
//! - **LRQ** → `h323_location_request`: LCF or LRJ.
//!
//! NetGet answers the rest itself: URQ (UCF / URJ `notCurrentlyRegistered`), DRQ (DCF / DRJ
//! `notRegistered`), BRQ (BCF up to the configured bandwidth), IRR (IACK when asked for one),
//! an ARQ from an endpoint that is not registered (ARJ `callerNotRegistered`), and a
//! retransmitted request: the cached answer again, or RIP while the model is still deciding.
//!
//! ## Failing closed
//!
//! Every request that goes to the model is answered with a reject unless the model confirms
//! it: a backend failure is `resourceUnavailable` (overloaded) or `undefinedReason`, tagged
//! `decision=fail_closed_llm_*`; an answer with no confirm or reject is `undefinedReason`,
//! `decision=model_silent`; an action NetGet cannot carry out (an alias another endpoint holds,
//! a destination it cannot resolve) is the matching reject, `decision=fail_closed_bad_action`.
//! Nothing here can admit or register on its own.

use super::actions::{self as act, GkCommand};
use super::h225;
use crate::llm::action_helper::call_llm;
use crate::llm::actions::protocol_trait::ActionResult;
use crate::llm::ollama_client::OllamaClient;
use crate::logging::emit::Log;
use crate::protocol::Event;
use crate::server::connection::ConnectionId;
use crate::state::app_state::AppState;
use crate::state::server::{ConnectionState, ConnectionStatus, ProtocolConnectionInfo};
use crate::state::ServerId;
use crate::utils::clock::Instant;
use anyhow::Result;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

/// Largest RAS datagram read; anything longer is truncated by the read and refused by the
/// decoder.
pub const MAX_RAS_DATAGRAM: usize = 4096;
/// Endpoints registered at once.
pub const MAX_REGISTRATIONS: usize = 256;
/// Calls admitted and not yet disengaged.
pub const MAX_CALLS: usize = 512;
/// Requests being decided by the model at once; past this a request is refused at once.
pub const MAX_IN_FLIGHT: usize = 64;
/// Answers remembered for retransmitted requests.
const ANSWER_CACHE: usize = 256;
/// How long a remembered answer is replayed for a retransmission.
const ANSWER_TTL: Duration = Duration::from_secs(30);
/// RequestInProgress delay sent while the model decides (milliseconds).
const RIP_DELAY_MS: u64 = 15_000;
/// Time-to-live when the model gives none and the endpoint asked for none.
pub const DEFAULT_TTL_SECS: u64 = 300;
/// The longest time-to-live NetGet grants.
pub const MAX_TTL_SECS: u64 = 3600;
/// How long past its time-to-live a registration survives (endpoints refresh late).
const TTL_GRACE: Duration = Duration::from_secs(30);

pub const ADMISSION_REASONS: &[&str] = &[
    "calledPartyNotRegistered",
    "invalidPermission",
    "requestDenied",
    "undefinedReason",
    "callerNotRegistered",
    "routeCallToGatekeeper",
    "invalidEndpointIdentifier",
    "resourceUnavailable",
    "securityDenial",
    "qosControlNotSupported",
    "incompleteAddress",
    "aliasesInconsistent",
    "exceedsCallCapacity",
    "collectDestination",
    "collectPIN",
    "noRouteToDestination",
    "unallocatedNumber",
];

pub const REGISTRATION_REASONS: &[&str] = &[
    "discoveryRequired",
    "invalidRevision",
    "invalidCallSignalAddress",
    "invalidRASAddress",
    "duplicateAlias",
    "invalidTerminalType",
    "undefinedReason",
    "transportNotSupported",
    "transportQOSNotSupported",
    "resourceUnavailable",
    "invalidAlias",
    "securityDenial",
    "fullRegistrationRequired",
];

pub const GATEKEEPER_REASONS: &[&str] = &[
    "resourceUnavailable",
    "terminalExcluded",
    "invalidRevision",
    "undefinedReason",
    "securityDenial",
];

pub const LOCATION_REASONS: &[&str] = &[
    "notRegistered",
    "invalidPermission",
    "requestDenied",
    "undefinedReason",
    "securityDenial",
    "aliasesInconsistent",
    "resourceUnavailable",
    "hopCountExceeded",
    "incompleteAddress",
    "noRouteToDestination",
    "unallocatedNumber",
];

/// Startup configuration.
#[derive(Clone, Debug)]
pub struct GatekeeperConfig {
    pub gatekeeper_id: String,
    pub default_ttl: u64,
    pub max_bandwidth: u64,
}

#[derive(Clone, Debug)]
struct Registration {
    endpoint_id: String,
    aliases: Vec<Value>,
    call_signal: Vec<Value>,
    ras: Vec<Value>,
    ttl: u64,
    expires: Instant,
    endpoint: Value,
}

#[derive(Clone, Debug)]
struct AdmittedCall {
    endpoint_id: String,
    bandwidth: u64,
}

#[derive(Default)]
struct State {
    registrations: HashMap<String, Registration>,
    calls: HashMap<String, AdmittedCall>,
    next_endpoint: u64,
    answers: VecDeque<((SocketAddr, u16), Vec<u8>, Instant)>,
    in_flight: HashSet<(SocketAddr, u16)>,
}

impl State {
    fn expire(&mut self) {
        let now = Instant::now();
        self.registrations
            .retain(|_, r| r.expires + TTL_GRACE > now);
        let live: HashSet<String> = self.registrations.keys().cloned().collect();
        self.calls.retain(|_, c| live.contains(&c.endpoint_id));
        while self
            .answers
            .front()
            .is_some_and(|(_, _, at)| now.duration_since(*at) > ANSWER_TTL)
        {
            self.answers.pop_front();
        }
    }

    fn remember(&mut self, key: (SocketAddr, u16), answer: Vec<u8>) {
        if self.answers.len() >= ANSWER_CACHE {
            self.answers.pop_front();
        }
        self.answers.push_back((key, answer, Instant::now()));
    }

    fn cached(&self, key: (SocketAddr, u16)) -> Option<Vec<u8>> {
        self.answers
            .iter()
            .rev()
            .find(|(k, _, _)| *k == key)
            .map(|(_, a, _)| a.clone())
    }

    /// The registration holding `alias`, if any.
    fn holder_of(&self, alias: &Value) -> Option<&Registration> {
        self.registrations
            .values()
            .find(|r| r.aliases.iter().any(|a| h225::same_alias(a, alias)))
    }

    fn by_call_signal(&self, addrs: &[Value]) -> Option<String> {
        self.registrations
            .values()
            .find(|r| r.call_signal.iter().any(|a| addrs.contains(a)))
            .map(|r| r.endpoint_id.clone())
    }
}

struct Shared {
    socket: Arc<UdpSocket>,
    local: SocketAddr,
    config: GatekeeperConfig,
    state: Mutex<State>,
    app_state: Arc<AppState>,
    llm_client: OllamaClient,
    status_tx: mpsc::UnboundedSender<String>,
    server_id: ServerId,
}

impl Shared {
    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn log(&self) -> Log<'_> {
        Log::new(Some(&self.status_tx))
    }

    /// This gatekeeper's RAS address as `peer` sees it: the bound address, or — when bound
    /// to the unspecified address — the source address the route to `peer` uses.
    fn ras_address_for(&self, peer: SocketAddr) -> SocketAddr {
        if !self.local.ip().is_unspecified() {
            return self.local;
        }
        let ip = route_source(peer).unwrap_or(self.local.ip());
        SocketAddr::new(ip, self.local.port())
    }
}

/// The local address the kernel would send from to reach `peer`.
pub fn route_source(peer: SocketAddr) -> Option<IpAddr> {
    let bind: SocketAddr = if peer.is_ipv4() {
        "0.0.0.0:0".parse().ok()?
    } else {
        "[::]:0".parse().ok()?
    };
    let s = std::net::UdpSocket::bind(bind).ok()?;
    s.connect(peer).ok()?;
    s.local_addr().ok().map(|a| a.ip())
}

pub async fn spawn(
    listen_addr: SocketAddr,
    llm_client: OllamaClient,
    app_state: Arc<AppState>,
    status_tx: mpsc::UnboundedSender<String>,
    server_id: ServerId,
    config: GatekeeperConfig,
) -> Result<SocketAddr> {
    let socket = Arc::new(UdpSocket::bind(listen_addr).await?);
    let local = socket.local_addr()?;
    Log::new(Some(&status_tx)).info(format!(
        "H.323 gatekeeper {} (RAS) listening on {local}",
        config.gatekeeper_id
    ));
    let shared = Arc::new(Shared {
        socket: socket.clone(),
        local,
        config,
        state: Mutex::new(State::default()),
        app_state: app_state.clone(),
        llm_client,
        status_tx: status_tx.clone(),
        server_id,
    });
    let registrar = app_state.clone();
    let task = tokio::spawn(async move {
        let mut buf = vec![0u8; MAX_RAS_DATAGRAM];
        loop {
            let (n, peer) = match socket.recv_from(&mut buf).await {
                Ok(x) => x,
                Err(e) => {
                    Log::new(Some(&status_tx))
                        .error(format!("H.323 gatekeeper receive failed, stopping: {e}"));
                    break;
                }
            };
            let datagram = buf[..n].to_vec();
            let shared = shared.clone();
            app_state
                .spawn_server_task(server_id, async move {
                    handle_datagram(shared, datagram, peer).await;
                })
                .await;
        }
    });
    registrar.register_server_task(server_id, task).await;
    Ok(local)
}

async fn track(shared: &Shared, peer: SocketAddr, n: usize) -> ConnectionId {
    let id = ConnectionId::new(shared.app_state.get_next_unified_id().await);
    let now = Instant::now();
    shared
        .app_state
        .add_connection_to_server(
            shared.server_id,
            ConnectionState {
                id,
                remote_addr: peer,
                local_addr: shared.local,
                bytes_sent: 0,
                bytes_received: n as u64,
                packets_sent: 0,
                packets_received: 1,
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

async fn send(
    shared: &Shared,
    id: ConnectionId,
    peer: SocketAddr,
    kind: &str,
    body: Value,
) -> Option<Vec<u8>> {
    let bytes = match h225::encode_ras(kind, body) {
        Ok(b) => b,
        Err(e) => {
            shared.log().error(format!(
                "H.323 gatekeeper: could not encode {}: {e:#}",
                h225::ras_abbreviation(kind)
            ));
            return None;
        }
    };
    match shared.socket.send_to(&bytes, peer).await {
        Ok(n) => {
            shared
                .app_state
                .update_connection_stats(shared.server_id, id, None, Some(n as u64), None, Some(1))
                .await;
            shared.log().debug(format!(
                "H.323 gatekeeper → {peer}: {}",
                h225::ras_abbreviation(kind)
            ));
            Some(bytes)
        }
        Err(e) => {
            shared
                .log()
                .error(format!("H.323 gatekeeper: send to {peer} failed: {e}"));
            None
        }
    }
}

async fn handle_datagram(shared: Arc<Shared>, datagram: Vec<u8>, peer: SocketAddr) {
    let id = track(&shared, peer, datagram.len()).await;
    let (kind, body) = match h225::decode_ras(&datagram) {
        Ok(x) => x,
        Err(e) => {
            shared.log().warn(format!(
                "H.323 gatekeeper: {} octets from {peer} are not a RAS message decision=protocol_error: {e:#}",
                datagram.len()
            ));
            return;
        }
    };
    let abbrev = h225::ras_abbreviation(&kind);
    let Some(seq) = h225::seq_num(&body) else {
        shared.log().warn(format!(
            "H.323 gatekeeper: {abbrev} from {peer} without a sequence number decision=protocol_error"
        ));
        return;
    };
    shared
        .log()
        .debug(format!("H.323 gatekeeper ← {peer}: {abbrev} seq {seq}"));
    let key = (peer, seq);
    let (cached, in_flight) = {
        let mut st = shared.state();
        st.expire();
        (st.cached(key), st.in_flight.contains(&key))
    };
    if let Some(answer) = cached {
        let _ = shared.socket.send_to(&answer, peer).await;
        shared.log().debug(format!(
            "H.323 gatekeeper: {abbrev} seq {seq} from {peer} retransmitted; answered again"
        ));
        return;
    }
    if in_flight {
        send(
            &shared,
            id,
            peer,
            "requestInProgress",
            json!({"requestSeqNum": seq, "delay": RIP_DELAY_MS}),
        )
        .await;
        return;
    }
    let answer = match kind.as_str() {
        "gatekeeperRequest" => gatekeeper_request(&shared, id, peer, seq, &body).await,
        "registrationRequest" => registration_request(&shared, id, peer, seq, &body).await,
        "unregistrationRequest" => unregistration_request(&shared, seq, &body),
        "admissionRequest" => admission_request(&shared, id, peer, seq, &body).await,
        "disengageRequest" => disengage_request(&shared, seq, &body),
        "locationRequest" => location_request(&shared, id, peer, seq, &body).await,
        "bandwidthRequest" => Some((
            "bandwidthConfirm",
            json!({
                "requestSeqNum": seq,
                "bandWidth": body.get("bandWidth").and_then(|b| b.as_u64()).unwrap_or(0).min(shared.config.max_bandwidth),
            }),
        )),
        "infoRequestResponse" => {
            let wants = body
                .get("needResponse")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            wants.then(|| ("infoRequestAck", json!({"requestSeqNum": seq})))
        }
        "resourcesAvailableIndicate" => Some((
            "resourcesAvailableConfirm",
            json!({"requestSeqNum": seq, "protocolIdentifier": h225::PROTOCOL_ID}),
        )),
        other
            if other.ends_with("Confirm")
                || other.ends_with("Reject")
                || other == "requestInProgress" =>
        {
            shared.log().debug(format!(
                "H.323 gatekeeper: ignoring {abbrev} from {peer}: a gatekeeper sends these, it does not answer them"
            ));
            None
        }
        _ => {
            shared.log().info(format!(
                "H.323 gatekeeper: {abbrev} from {peer} is not handled; answering XRS"
            ));
            Some((
                "unknownMessageResponse",
                json!({"requestSeqNum": seq, "messageNotUnderstood": hex::encode(&datagram)}),
            ))
        }
    };
    if let Some((kind, body)) = answer {
        if let Some(bytes) = send(&shared, id, peer, kind, body).await {
            shared.state().remember(key, bytes);
        }
    }
}

/// Run one request past the model with the in-flight bound held. `None` when the bound is
/// reached (the caller refuses at once).
async fn consult(
    shared: &Shared,
    id: ConnectionId,
    key: (SocketAddr, u16),
    event: Event,
) -> Option<Consulted> {
    {
        let mut st = shared.state();
        if st.in_flight.len() >= MAX_IN_FLIGHT {
            return None;
        }
        st.in_flight.insert(key);
    }
    let result = call_llm(
        &shared.llm_client,
        &shared.app_state,
        shared.server_id,
        Some(id),
        &event,
        &act::H323GatekeeperProtocol::new(),
    )
    .await;
    shared.state().in_flight.remove(&key);
    let execution = match result {
        Ok(x) => x,
        Err(e) => {
            let overloaded = matches!(
                crate::utils::wire_failure::WireFailure::classify(&e),
                crate::utils::wire_failure::WireFailure::Overloaded
            );
            shared.log().error(format!(
                "H.323 gatekeeper: {} from {} not answered decision={}: {e}",
                event.event_type.id,
                key.0,
                if overloaded {
                    "fail_closed_llm_overloaded"
                } else {
                    "fail_closed_llm_error"
                }
            ));
            return Some(Consulted::Failed { overloaded });
        }
    };
    for m in execution.messages {
        let _ = shared.status_tx.send(m);
    }
    let mut commands = Vec::new();
    let mut stack = execution.protocol_results;
    stack.reverse();
    while let Some(r) = stack.pop() {
        match r {
            ActionResult::Custom { data, .. } => {
                if let Ok(c) = act::parse_gk_command(&data) {
                    commands.push(c);
                }
            }
            ActionResult::Multiple(inner) => stack.extend(inner.into_iter().rev()),
            _ => {}
        }
    }
    let refused: Vec<String> = execution
        .failures
        .iter()
        .map(|f| format!("{}: {}", f.action, f.error))
        .collect();
    Some(Consulted::Answered { commands, refused })
}

enum Consulted {
    Failed {
        overloaded: bool,
    },
    Answered {
        commands: Vec<GkCommand>,
        refused: Vec<String>,
    },
}

/// What the model decided about one request kind, after picking out the commands that answer it.
enum Verdict<C, R> {
    Confirm(C),
    Reject(R),
    /// No usable answer (already logged with its decision tag); the reject reason to send.
    Refuse(&'static str),
}

fn verdict<C, R>(
    shared: &Shared,
    name: &str,
    peer: SocketAddr,
    consulted: Option<Consulted>,
    pick: impl Fn(GkCommand) -> Option<Result<C, R>>,
) -> Verdict<C, R> {
    match consulted {
        None => {
            shared.log().warn(format!(
                "H.323 gatekeeper: {name} from {peer} refused decision=fail_closed_in_flight_cap ({MAX_IN_FLIGHT} requests already with the model)"
            ));
            Verdict::Refuse("resourceUnavailable")
        }
        Some(Consulted::Failed { overloaded }) => Verdict::Refuse(if overloaded {
            "resourceUnavailable"
        } else {
            "undefinedReason"
        }),
        Some(Consulted::Answered { commands, refused }) => {
            for c in commands {
                if let Some(v) = pick(c) {
                    return match v {
                        Ok(c) => Verdict::Confirm(c),
                        Err(r) => Verdict::Reject(r),
                    };
                }
            }
            if refused.is_empty() {
                shared.log().warn(format!(
                    "H.323 gatekeeper: {name} from {peer} answered with no confirm or reject decision=model_silent; refusing"
                ));
                Verdict::Refuse("undefinedReason")
            } else {
                shared.log().error(format!(
                    "H.323 gatekeeper: {name} from {peer}: no usable action decision=fail_closed_bad_action ({})",
                    refused.join("; ")
                ));
                Verdict::Refuse("undefinedReason")
            }
        }
    }
}

fn gk_identifier_ok(s: &str) -> bool {
    !s.is_empty() && s.chars().count() <= 128 && !crate::utils::sanitize::has_controls(s)
}

async fn gatekeeper_request(
    shared: &Shared,
    id: ConnectionId,
    peer: SocketAddr,
    seq: u16,
    body: &Value,
) -> Option<(&'static str, Value)> {
    let reply_to = body.get("rasAddress").and_then(h225::socket_addr);
    let event = Event::new(
        &act::GRQ_EVENT,
        json!({
            "from": peer.to_string(),
            "ras_address": reply_to.map(|a| a.to_string()),
            "endpoint": h225::endpoint_summary(body.get("endpointType")),
            "aliases": h225::aliases_text(body.get("endpointAlias")),
            "requested_gatekeeper": body.get("gatekeeperIdentifier").and_then(|g| g.as_str()).map(crate::utils::sanitize::strip_controls),
            "this_gatekeeper": shared.config.gatekeeper_id,
        }),
    );
    let consulted = consult(shared, id, (peer, seq), event).await;
    let v = verdict(shared, "GRQ", peer, consulted, |c| match c {
        GkCommand::ConfirmGatekeeper => Some(Ok(())),
        GkCommand::RejectGatekeeper(r) => Some(Err(r)),
        _ => None,
    });
    let base = json!({
        "requestSeqNum": seq,
        "protocolIdentifier": h225::PROTOCOL_ID,
        "gatekeeperIdentifier": shared.config.gatekeeper_id,
    });
    match v {
        Verdict::Confirm(()) => {
            shared.log().info(format!(
                "H.323 gatekeeper: GRQ from {peer} decision=model_answer; GCF"
            ));
            let mut b = base;
            b["rasAddress"] = h225::transport(shared.ras_address_for(peer));
            Some(("gatekeeperConfirm", b))
        }
        Verdict::Reject(reason) => {
            shared.log().info(format!(
                "H.323 gatekeeper: GRQ from {peer} decision=model_reject; GRJ {reason}"
            ));
            let mut b = base;
            b["rejectReason"] = json!({ reason: null });
            Some(("gatekeeperReject", b))
        }
        Verdict::Refuse(reason) => {
            let mut b = base;
            b["rejectReason"] = json!({ reason: null });
            Some(("gatekeeperReject", b))
        }
    }
}

fn reject_registration(
    seq: u16,
    gk: &str,
    reason: &str,
    duplicates: Option<Vec<Value>>,
) -> (&'static str, Value) {
    let reason_value = match duplicates {
        Some(d) if reason == "duplicateAlias" => json!({"duplicateAlias": d}),
        _ if reason == "duplicateAlias" => json!({"duplicateAlias": []}),
        _ => json!({ reason: null }),
    };
    (
        "registrationReject",
        json!({
            "requestSeqNum": seq,
            "protocolIdentifier": h225::PROTOCOL_ID,
            "rejectReason": reason_value,
            "gatekeeperIdentifier": gk,
        }),
    )
}

async fn registration_request(
    shared: &Shared,
    id: ConnectionId,
    peer: SocketAddr,
    seq: u16,
    body: &Value,
) -> Option<(&'static str, Value)> {
    let gk = shared.config.gatekeeper_id.clone();
    let call_signal: Vec<Value> = body
        .get("callSignalAddress")
        .and_then(|a| a.as_array())
        .cloned()
        .unwrap_or_default();
    let ras: Vec<Value> = body
        .get("rasAddress")
        .and_then(|a| a.as_array())
        .cloned()
        .unwrap_or_default();
    let keep_alive = body
        .get("keepAlive")
        .and_then(|k| k.as_bool())
        .unwrap_or(false);
    let requested_ttl = body.get("timeToLive").and_then(|t| t.as_u64());

    if keep_alive {
        let endpoint_id = body
            .get("endpointIdentifier")
            .and_then(|e| e.as_str())
            .unwrap_or("");
        let mut st = shared.state();
        let Some(reg) = st.registrations.get_mut(endpoint_id) else {
            drop(st);
            shared.log().info(format!(
                "H.323 gatekeeper: keep-alive RRQ from {peer} for unknown endpoint {endpoint_id:?} decision=protocol_reject; RRJ fullRegistrationRequired"
            ));
            return Some(reject_registration(
                seq,
                &gk,
                "fullRegistrationRequired",
                None,
            ));
        };
        reg.expires = Instant::now() + Duration::from_secs(reg.ttl);
        let answer = json!({
            "requestSeqNum": seq,
            "protocolIdentifier": h225::PROTOCOL_ID,
            "callSignalAddress": [],
            "gatekeeperIdentifier": gk,
            "endpointIdentifier": reg.endpoint_id,
            "timeToLive": reg.ttl,
            "willRespondToIRR": false,
            "maintainConnection": false,
        });
        shared.log().debug(format!(
            "H.323 gatekeeper: keep-alive RRQ from {peer} refreshed {} for {}s",
            reg.endpoint_id, reg.ttl
        ));
        return Some(("registrationConfirm", answer));
    }

    if call_signal.is_empty() {
        shared.log().info(format!("H.323 gatekeeper: RRQ from {peer} with no call signalling address decision=protocol_reject"));
        return Some(reject_registration(
            seq,
            &gk,
            "invalidCallSignalAddress",
            None,
        ));
    }
    if ras.is_empty() {
        shared.log().info(format!(
            "H.323 gatekeeper: RRQ from {peer} with no RAS address decision=protocol_reject"
        ));
        return Some(reject_registration(seq, &gk, "invalidRASAddress", None));
    }
    let requested: Vec<Value> = body
        .get("terminalAlias")
        .and_then(|a| a.as_array())
        .cloned()
        .unwrap_or_default();
    let (existing, conflicts, full) = {
        let mut st = shared.state();
        st.expire();
        let existing = st.by_call_signal(&call_signal);
        let conflicts: Vec<String> = requested
            .iter()
            .filter(|a| {
                st.holder_of(a)
                    .is_some_and(|r| Some(&r.endpoint_id) != existing.as_ref())
            })
            .map(h225::alias_text)
            .collect();
        let full = existing.is_none() && st.registrations.len() >= MAX_REGISTRATIONS;
        (existing, conflicts, full)
    };
    if full {
        shared.log().warn(format!(
            "H.323 gatekeeper: RRQ from {peer} refused decision=fail_closed_registration_cap ({MAX_REGISTRATIONS} endpoints registered)"
        ));
        return Some(reject_registration(seq, &gk, "resourceUnavailable", None));
    }
    let event = Event::new(
        &act::RRQ_EVENT,
        json!({
            "from": peer.to_string(),
            "aliases": requested.iter().map(h225::alias_text).collect::<Vec<_>>(),
            "call_signal_addresses": h225::addresses_text(Some(&Value::Array(call_signal.clone()))),
            "ras_addresses": h225::addresses_text(Some(&Value::Array(ras.clone()))),
            "endpoint": h225::endpoint_summary(body.get("terminalType")),
            "vendor": h225::endpoint_summary(Some(&json!({"vendor": body.get("endpointVendor"), "terminal": {}}))),
            "requested_time_to_live": requested_ttl,
            "already_registered_as": existing,
            "aliases_held_by_other_endpoints": conflicts,
            "registered_endpoints": shared.state().registrations.len(),
        }),
    );
    let consulted = consult(shared, id, (peer, seq), event).await;
    let v = verdict(shared, "RRQ", peer, consulted, |c| match c {
        GkCommand::ConfirmRegistration { aliases, ttl } => Some(Ok((aliases, ttl))),
        GkCommand::RejectRegistration { reason, duplicates } => Some(Err((reason, duplicates))),
        _ => None,
    });
    match v {
        Verdict::Confirm((aliases, ttl)) => {
            let aliases = aliases.unwrap_or(requested);
            let ttl = ttl
                .or(requested_ttl)
                .unwrap_or(shared.config.default_ttl)
                .clamp(1, MAX_TTL_SECS);
            let mut st = shared.state();
            let endpoint_id = match &existing {
                Some(e) => e.clone(),
                None => {
                    st.next_endpoint += 1;
                    format!("ep{}-{:04x}", st.next_endpoint, rand::random::<u16>())
                }
            };
            let taken: Vec<Value> = aliases
                .iter()
                .filter(|a| {
                    st.holder_of(a)
                        .is_some_and(|r| r.endpoint_id != endpoint_id)
                })
                .cloned()
                .collect();
            if !taken.is_empty() {
                drop(st);
                shared.log().warn(format!(
                    "H.323 gatekeeper: RRQ from {peer}: the model confirmed aliases another endpoint holds ({}) decision=fail_closed_bad_action; RRJ duplicateAlias",
                    taken.iter().map(h225::alias_text).collect::<Vec<_>>().join(", ")
                ));
                return Some(reject_registration(seq, &gk, "duplicateAlias", Some(taken)));
            }
            if existing.is_none() && st.registrations.len() >= MAX_REGISTRATIONS {
                drop(st);
                return Some(reject_registration(seq, &gk, "resourceUnavailable", None));
            }
            st.registrations.insert(
                endpoint_id.clone(),
                Registration {
                    endpoint_id: endpoint_id.clone(),
                    aliases: aliases.clone(),
                    call_signal,
                    ras,
                    ttl,
                    expires: Instant::now() + Duration::from_secs(ttl),
                    endpoint: h225::endpoint_summary(body.get("terminalType")),
                },
            );
            drop(st);
            shared.log().info(format!(
                "H.323 gatekeeper: RRQ from {peer} decision=model_answer; RCF {endpoint_id} as [{}] for {ttl}s",
                aliases.iter().map(h225::alias_text).collect::<Vec<_>>().join(", ")
            ));
            let mut answer = json!({
                "requestSeqNum": seq,
                "protocolIdentifier": h225::PROTOCOL_ID,
                "callSignalAddress": [],
                "gatekeeperIdentifier": gk,
                "endpointIdentifier": endpoint_id,
                "timeToLive": ttl,
                "willRespondToIRR": false,
                "maintainConnection": false,
            });
            if !aliases.is_empty() {
                answer["terminalAlias"] = Value::Array(aliases);
            }
            Some(("registrationConfirm", answer))
        }
        Verdict::Reject((reason, duplicates)) => {
            shared.log().info(format!(
                "H.323 gatekeeper: RRQ from {peer} decision=model_reject; RRJ {reason}"
            ));
            Some(reject_registration(seq, &gk, &reason, duplicates))
        }
        Verdict::Refuse(reason) => Some(reject_registration(seq, &gk, reason, None)),
    }
}

fn unregistration_request(
    shared: &Shared,
    seq: u16,
    body: &Value,
) -> Option<(&'static str, Value)> {
    let call_signal: Vec<Value> = body
        .get("callSignalAddress")
        .and_then(|a| a.as_array())
        .cloned()
        .unwrap_or_default();
    let mut st = shared.state();
    let endpoint_id = body
        .get("endpointIdentifier")
        .and_then(|e| e.as_str())
        .map(str::to_string)
        .filter(|e| st.registrations.contains_key(e))
        .or_else(|| st.by_call_signal(&call_signal));
    match endpoint_id {
        Some(e) => {
            st.registrations.remove(&e);
            st.calls.retain(|_, c| c.endpoint_id != e);
            drop(st);
            shared
                .log()
                .info(format!("H.323 gatekeeper: URQ: {e} unregistered; UCF"));
            Some(("unregistrationConfirm", json!({"requestSeqNum": seq})))
        }
        None => Some((
            "unregistrationReject",
            json!({"requestSeqNum": seq, "rejectReason": {"notCurrentlyRegistered": null}}),
        )),
    }
}

fn disengage_request(shared: &Shared, seq: u16, body: &Value) -> Option<(&'static str, Value)> {
    let endpoint_id = body
        .get("endpointIdentifier")
        .and_then(|e| e.as_str())
        .unwrap_or("");
    let mut st = shared.state();
    if !st.registrations.contains_key(endpoint_id) {
        return Some((
            "disengageReject",
            json!({"requestSeqNum": seq, "rejectReason": {"notRegistered": null}}),
        ));
    }
    if let Some(guid) = body
        .get("callIdentifier")
        .and_then(|c| c.get("guid"))
        .and_then(|g| g.as_str())
    {
        if let Some(call) = st.calls.remove(&format!("{endpoint_id}/{guid}")) {
            shared.log().debug(format!(
                "H.323 gatekeeper: call {guid} of {} released {} × 100 bit/s",
                call.endpoint_id, call.bandwidth
            ));
        }
    }
    drop(st);
    shared
        .log()
        .info(format!("H.323 gatekeeper: DRQ from {endpoint_id}; DCF"));
    Some(("disengageConfirm", json!({"requestSeqNum": seq})))
}

/// Resolve the model's destination: a registered alias (to that endpoint's call signalling
/// address), or a literal `ip:port`.
/// A resolved destination: its call signalling address, its registered aliases, and its RAS
/// addresses when it is a registered endpoint.
type Resolved = (SocketAddr, Vec<Value>, Option<Vec<Value>>);

fn resolve_destination(st: &State, destination: &str) -> Result<Resolved, String> {
    if let Ok(addr) = destination.parse::<SocketAddr>() {
        return Ok((addr, Vec::new(), None));
    }
    let alias = h225::alias(destination).map_err(|e| e.to_string())?;
    let reg = st
        .holder_of(&alias)
        .ok_or_else(|| format!("no registered endpoint holds {destination}"))?;
    let addr = reg
        .call_signal
        .iter()
        .find_map(h225::socket_addr)
        .ok_or_else(|| {
            format!(
                "{} registered no IP call signalling address",
                reg.endpoint_id
            )
        })?;
    Ok((addr, reg.aliases.clone(), Some(reg.ras.clone())))
}

async fn admission_request(
    shared: &Shared,
    id: ConnectionId,
    peer: SocketAddr,
    seq: u16,
    body: &Value,
) -> Option<(&'static str, Value)> {
    let endpoint_id = body
        .get("endpointIdentifier")
        .and_then(|e| e.as_str())
        .unwrap_or("")
        .to_string();
    let reject = |reason: &str| {
        Some((
            "admissionReject",
            json!({"requestSeqNum": seq, "rejectReason": { reason: null }}),
        ))
    };
    let answer_call = body
        .get("answerCall")
        .and_then(|a| a.as_bool())
        .unwrap_or(false);
    let destinations: Vec<Value> = body
        .get("destinationInfo")
        .and_then(|d| d.as_array())
        .cloned()
        .unwrap_or_default();
    let (caller, candidates, calls_open) = {
        let mut st = shared.state();
        st.expire();
        let caller = st.registrations.get(&endpoint_id).cloned();
        let candidates: Vec<Value> = destinations
            .iter()
            .filter_map(|a| {
                st.holder_of(a).map(|r| {
                    json!({
                        "alias": h225::alias_text(a),
                        "endpoint_id": r.endpoint_id,
                        "call_signal_address": r.call_signal.iter().find_map(h225::socket_addr).map(|s| s.to_string()),
                        "endpoint": r.endpoint,
                    })
                })
            })
            .collect();
        (caller, candidates, st.calls.len())
    };
    let Some(caller) = caller else {
        shared.log().info(format!(
            "H.323 gatekeeper: ARQ from {peer} for unregistered endpoint {endpoint_id:?} decision=protocol_reject; ARJ callerNotRegistered"
        ));
        return reject("callerNotRegistered");
    };
    if calls_open >= MAX_CALLS {
        shared.log().warn(format!(
            "H.323 gatekeeper: ARQ from {peer} refused decision=fail_closed_call_cap ({MAX_CALLS} calls admitted)"
        ));
        return reject("resourceUnavailable");
    }
    let requested_bw = body.get("bandWidth").and_then(|b| b.as_u64()).unwrap_or(0);
    let call_id = body
        .get("callIdentifier")
        .and_then(|c| c.get("guid"))
        .and_then(|g| g.as_str())
        .unwrap_or("")
        .to_string();
    let event = Event::new(
        &act::ARQ_EVENT,
        json!({
            "from": peer.to_string(),
            "endpoint_id": endpoint_id,
            "caller_aliases": caller.aliases.iter().map(h225::alias_text).collect::<Vec<_>>(),
            "source_info": h225::aliases_text(body.get("srcInfo")),
            "destination_aliases": h225::aliases_text(body.get("destinationInfo")),
            "destination_address": body.get("destCallSignalAddress").map(h225::transport_text),
            "registered_destinations": candidates,
            "answer_call": answer_call,
            "bandwidth": requested_bw,
            "call_reference": body.get("callReferenceValue"),
            "call_id": call_id,
            "conference_id": body.get("conferenceID"),
        }),
    );
    let consulted = consult(shared, id, (peer, seq), event).await;
    let v = verdict(shared, "ARQ", peer, consulted, |c| match c {
        GkCommand::ConfirmAdmission {
            destination,
            bandwidth,
        } => Some(Ok((destination, bandwidth))),
        GkCommand::RejectAdmission(r) => Some(Err(r)),
        _ => None,
    });
    match v {
        Verdict::Confirm((destination, bandwidth)) => {
            let resolved = {
                let st = shared.state();
                match destination.as_deref() {
                    Some(d) => resolve_destination(&st, d),
                    None if answer_call => caller
                        .call_signal
                        .iter()
                        .find_map(h225::socket_addr)
                        .map(|a| (a, caller.aliases.clone(), None))
                        .ok_or_else(|| {
                            "the answering endpoint registered no IP address".to_string()
                        }),
                    None => destinations
                        .iter()
                        .find_map(|a| {
                            let r = st.holder_of(a)?;
                            let addr = r.call_signal.iter().find_map(h225::socket_addr)?;
                            Some((addr, r.aliases.clone(), None))
                        })
                        .or_else(|| {
                            body.get("destCallSignalAddress")
                                .and_then(h225::socket_addr)
                                .map(|a| (a, Vec::new(), None))
                        })
                        .ok_or_else(|| {
                            "no destination is registered and the ARQ named no address".to_string()
                        }),
                }
            };
            let (addr, dest_aliases, _) = match resolved {
                Ok(r) => r,
                Err(why) => {
                    shared.log().warn(format!(
                        "H.323 gatekeeper: ARQ from {peer}: cannot admit ({why}) decision=fail_closed_bad_action; ARJ calledPartyNotRegistered"
                    ));
                    return reject("calledPartyNotRegistered");
                }
            };
            let bw = bandwidth
                .unwrap_or(requested_bw)
                .min(shared.config.max_bandwidth);
            {
                let mut st = shared.state();
                if st.calls.len() < MAX_CALLS && !call_id.is_empty() {
                    st.calls.insert(
                        format!("{endpoint_id}/{call_id}"),
                        AdmittedCall {
                            endpoint_id: endpoint_id.clone(),
                            bandwidth: bw,
                        },
                    );
                }
            }
            shared.log().info(format!(
                "H.323 gatekeeper: ARQ from {endpoint_id} decision=model_answer; ACF to {addr}, {bw} × 100 bit/s"
            ));
            let mut answer = json!({
                "requestSeqNum": seq,
                "bandWidth": bw,
                "callModel": {"direct": null},
                "destCallSignalAddress": h225::transport(addr),
                "willRespondToIRR": false,
                "uuiesRequested": {
                    "setup": false, "callProceeding": false, "connect": false, "alerting": false,
                    "information": false, "releaseComplete": false, "facility": false,
                    "progress": false, "empty": false,
                },
            });
            if !dest_aliases.is_empty() {
                answer["destinationInfo"] = Value::Array(dest_aliases);
            }
            Some(("admissionConfirm", answer))
        }
        Verdict::Reject(reason) => {
            shared.log().info(format!(
                "H.323 gatekeeper: ARQ from {endpoint_id} decision=model_reject; ARJ {reason}"
            ));
            reject(&reason)
        }
        Verdict::Refuse(reason) => reject(reason),
    }
}

async fn location_request(
    shared: &Shared,
    id: ConnectionId,
    peer: SocketAddr,
    seq: u16,
    body: &Value,
) -> Option<(&'static str, Value)> {
    let reject = |reason: &str| {
        Some((
            "locationReject",
            json!({"requestSeqNum": seq, "rejectReason": { reason: null }}),
        ))
    };
    let destinations: Vec<Value> = body
        .get("destinationInfo")
        .and_then(|d| d.as_array())
        .cloned()
        .unwrap_or_default();
    let candidates: Vec<Value> = {
        let st = shared.state();
        destinations
            .iter()
            .filter_map(|a| {
                st.holder_of(a).map(|r| json!({
                    "alias": h225::alias_text(a),
                    "endpoint_id": r.endpoint_id,
                    "call_signal_address": r.call_signal.iter().find_map(h225::socket_addr).map(|s| s.to_string()),
                }))
            })
            .collect()
    };
    let event = Event::new(
        &act::LRQ_EVENT,
        json!({
            "from": peer.to_string(),
            "destination_aliases": h225::aliases_text(body.get("destinationInfo")),
            "source_info": h225::aliases_text(body.get("sourceInfo")),
            "reply_address": body.get("replyAddress").map(h225::transport_text),
            "registered_destinations": candidates,
        }),
    );
    let consulted = consult(shared, id, (peer, seq), event).await;
    let v = verdict(shared, "LRQ", peer, consulted, |c| match c {
        GkCommand::ConfirmLocation { destination } => Some(Ok(destination)),
        GkCommand::RejectLocation(r) => Some(Err(r)),
        _ => None,
    });
    match v {
        Verdict::Confirm(destination) => {
            let resolved = {
                let st = shared.state();
                match destination.as_deref() {
                    Some(d) => resolve_destination(&st, d),
                    None => destinations
                        .iter()
                        .find_map(|a| {
                            let r = st.holder_of(a)?;
                            let addr = r.call_signal.iter().find_map(h225::socket_addr)?;
                            Some((addr, r.aliases.clone(), Some(r.ras.clone())))
                        })
                        .ok_or_else(|| "no destination alias is registered".to_string()),
                }
            };
            match resolved {
                Ok((addr, aliases, ras)) => {
                    let ras = ras
                        .and_then(|r| r.into_iter().next())
                        .unwrap_or_else(|| h225::transport(shared.ras_address_for(peer)));
                    shared.log().info(format!(
                        "H.323 gatekeeper: LRQ from {peer} decision=model_answer; LCF {addr}"
                    ));
                    let mut answer = json!({
                        "requestSeqNum": seq,
                        "callSignalAddress": h225::transport(addr),
                        "rasAddress": ras,
                    });
                    if !aliases.is_empty() {
                        answer["destinationInfo"] = Value::Array(aliases);
                    }
                    Some(("locationConfirm", answer))
                }
                Err(why) => {
                    shared.log().warn(format!(
                        "H.323 gatekeeper: LRQ from {peer}: cannot locate ({why}) decision=fail_closed_bad_action; LRJ notRegistered"
                    ));
                    reject("notRegistered")
                }
            }
        }
        Verdict::Reject(reason) => {
            shared.log().info(format!(
                "H.323 gatekeeper: LRQ from {peer} decision=model_reject; LRJ {reason}"
            ));
            reject(&reason)
        }
        Verdict::Refuse(reason) => {
            // LRJ has resourceUnavailable only as an extension; undefinedReason is root.
            reject(if reason == "resourceUnavailable" {
                "resourceUnavailable"
            } else {
                "undefinedReason"
            })
        }
    }
}

pub fn validate_gatekeeper_id(s: &str) -> Result<()> {
    anyhow::ensure!(
        gk_identifier_ok(s),
        "gatekeeper_id is 1 to 128 characters with no control characters"
    );
    Ok(())
}
