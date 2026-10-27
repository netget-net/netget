//! ONVIF device (server role): Device, Media, Media2, PTZ, Events (pull point and Basic
//! Notification push), Imaging, Recording, Search and Replay over SOAP 1.2 on HTTP/1.1.
//!
//! Rust owns the envelopes, WS-Security, the clock, the service addresses, every fault the
//! specification defines, and the device's volatile state — its clock settings, configurable
//! scopes and hostname, PTZ position and presets, imaging settings and focus, event
//! subscriptions, the recordings the model described and the searches over them. That state
//! lives in memory for the life of the server, as it does in a camera; nothing is stored, and no
//! media is recorded. A push subscription is the one thing that makes the device connect out,
//! and `notify.rs` bounds it. The model decides what the device says about itself and its media, and
//! allows or refuses every change and every move (`handlers.rs` says which operation is which).
//! Every request is one of:
//!
//! - answered by Rust: GetSystemDateAndTime (never authenticated, so a client can learn the
//!   clock before it signs anything), GetCapabilities, GetServices, the service capabilities,
//!   PTZ nodes/configurations/status/presets/stop, event properties and pull-point traffic,
//!   imaging reads, every recording read, search and replay URI once the recordings are
//!   described;
//! - asked of the model: device information, scopes, interfaces, hostname, profiles, sources,
//!   URIs, every Set*, every PTZ and focus move, every new subscription, the recordings (once),
//!   every CreateRecording and DeleteRecording;
//! - refused: anything else is env:Receiver/ter:ActionNotSupported, a request that fails
//!   authentication is env:Sender/ter:NotAuthorized, and a model that gives no usable answer is
//!   env:Receiver with a category.
pub mod actions;
pub mod events;
mod handlers;
pub mod imaging;
pub mod media2;
pub mod notify;
pub mod ptz;
pub mod recording;
pub mod wire;

use crate::llm::action_helper::call_llm;
use crate::llm::actions::protocol_trait::ActionResult;
use crate::logging::emit::{Log, Sink};
use crate::protocol::{Event, EventType, SpawnContext};
use crate::server::accept_bounded::{accept_bounded, ConnectionLimiter, DEFAULT_MAX_CONNECTIONS};
use crate::server::connection::ConnectionId;
use crate::state::server::{ConnectionState, ConnectionStatus, ProtocolConnectionInfo};
use crate::state::AccessLogOwner;
use crate::utils::WireFailure;
use anyhow::Result;
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::{
    body::Incoming, server::conn::http1, service::service_fn, Request, Response, StatusCode,
};
use hyper_util::rt::{TokioIo, TokioTimer};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;
use wire::FaultCode;

/// How far a UsernameToken's Created may be from the device's clock, by default.
pub const MAX_CLOCK_SKEW: Duration = Duration::from_secs(300);
pub const MAX_CLOCK_SKEW_SECS: u64 = 86_400;
pub const HEADER_TIMEOUT: Duration = Duration::from_secs(30);
/// Nonces remembered at most; past it the oldest is forgotten.
pub const MAX_NONCES: usize = 4096;
/// Configurable scopes (SetScopes/AddScopes) at most.
pub const MAX_SCOPES: usize = 16;

type Resp = Response<Full<Bytes>>;

/// The clock a SetSystemDateAndTime sets: an offset from the host clock and how the device
/// describes its time.
struct Clock {
    offset: chrono::Duration,
    date_time_type: String,
    tz: String,
    daylight_savings: bool,
}

#[derive(Default)]
struct ScopeState {
    configurable: Vec<String>,
    /// The fixed scopes the model last named, to tell a fixed scope from a missing one.
    fixed: Vec<String>,
}

/// What the device has said about its profiles and video sources, so PTZ and Imaging requests
/// can be checked against it; refreshed from the model when a request names one it has not.
#[derive(Default)]
struct Catalog {
    /// (token, has PTZ, video source token)
    profiles: Vec<(String, bool, String)>,
    sources: Vec<String>,
}

impl Catalog {
    fn learn_profiles(&mut self, v: &Value) {
        self.profiles = wire::items(v, "profiles")
            .map(|p| {
                let source = match wire::s(p, "video_source_token") {
                    "" => "video_source",
                    t => t,
                };
                (
                    wire::s(p, "token").to_string(),
                    wire::b(p, "ptz", false),
                    source.to_string(),
                )
            })
            .collect();
    }
    fn learn_sources(&mut self, v: &Value) {
        self.sources = wire::items(v, "sources")
            .map(|s| wire::s(s, "token").to_string())
            .collect();
    }
    fn profile(&self, token: &str) -> Option<bool> {
        self.profiles
            .iter()
            .find(|(t, _, _)| t == token)
            .map(|(_, ptz, _)| *ptz)
    }
    fn has_source(&self, token: &str) -> bool {
        self.sources.iter().any(|s| s == token) || self.profiles.iter().any(|(_, _, s)| s == token)
    }
}

/// One running device: its credentials and every piece of its volatile state.
pub struct Device {
    credentials: Option<(String, String)>,
    max_skew: Duration,
    max_pull_timeout: Duration,
    /// Nonces of accepted tokens, with when they were seen: a token is accepted once.
    nonces: Mutex<HashMap<Vec<u8>, crate::utils::clock::Instant>>,
    clock: Mutex<Clock>,
    scopes: Mutex<ScopeState>,
    hostname: Mutex<Option<String>>,
    catalog: Mutex<Catalog>,
    ptz: Mutex<ptz::PtzState>,
    imaging: Mutex<imaging::ImagingState>,
    events: events::Broker,
    /// Basic Notification: who may be a consumer, and the bounds on each delivery.
    notify: notify::Config,
    /// The recordings, once the model has described them.
    archive: Mutex<Option<recording::Archive>>,
    searches: Mutex<recording::Searches>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl Device {
    /// Remember a nonce; false when it was already used inside the freshness window.
    fn fresh_nonce(&self, nonce: Vec<u8>) -> bool {
        let now = crate::utils::clock::Instant::now();
        let mut seen = lock(&self.nonces);
        // A nonce older than twice the skew can no longer arrive with an acceptable Created.
        seen.retain(|_, at| now.duration_since(*at) <= self.max_skew * 2);
        if seen.contains_key(&nonce) {
            return false;
        }
        if seen.len() >= MAX_NONCES {
            if let Some(oldest) = seen
                .iter()
                .min_by_key(|(_, at)| **at)
                .map(|(k, _)| k.clone())
            {
                seen.remove(&oldest);
            }
        }
        seen.insert(nonce, now);
        true
    }

    /// The device's clock: the host's, shifted by any SetSystemDateAndTime it accepted.
    pub fn now(&self) -> chrono::DateTime<chrono::Utc> {
        chrono::Utc::now() + lock(&self.clock).offset
    }

    /// Raise the event an `onvif_raise_event` action describes; returns how many subscriptions
    /// it was queued on.
    pub fn raise(&self, action: &Value) -> Result<usize> {
        let now = self.now();
        let n = events::notification_from_action(action, now)?;
        Ok(self.events.publish(n, now))
    }

    /// Live subscriptions, pull point and push alike.
    pub fn subscriptions(&self) -> usize {
        self.events.count()
    }

    /// Live Basic Notification (push) subscriptions.
    pub fn push_subscriptions(&self) -> usize {
        self.events.push_count(self.now())
    }

    /// Live searches.
    pub fn searches(&self) -> usize {
        lock(&self.searches).count(self.now())
    }

    /// The recordings, if the model has described them.
    pub fn recording_tokens(&self) -> Option<Vec<String>> {
        lock(&self.archive)
            .as_ref()
            .map(|a| a.recordings.iter().map(|r| r.token.clone()).collect())
    }
}

pub async fn spawn(ctx: SpawnContext) -> Result<SocketAddr> {
    let params = ctx.startup_params.as_ref();
    let username = params
        .map(|p| p.get_optional_string("username"))
        .transpose()?
        .flatten();
    let password = params
        .map(|p| p.get_optional_string("password"))
        .transpose()?
        .flatten();
    let credentials = match (username, password) {
        (Some(u), Some(p)) => {
            anyhow::ensure!(!u.is_empty(), "username must not be empty");
            Some((u, p))
        }
        (None, None) => None,
        _ => anyhow::bail!("username and password are given together, or neither"),
    };
    let skew = params
        .map(|p| p.get_optional_u64("max_clock_skew_secs"))
        .transpose()?
        .flatten()
        .unwrap_or(MAX_CLOCK_SKEW.as_secs());
    anyhow::ensure!(
        (1..=MAX_CLOCK_SKEW_SECS).contains(&skew),
        "max_clock_skew_secs must be between 1 and {MAX_CLOCK_SKEW_SECS}"
    );
    let pull = params
        .map(|p| p.get_optional_u64("max_pull_timeout_secs"))
        .transpose()?
        .flatten()
        .unwrap_or(events::MAX_PULL_TIMEOUT.as_secs());
    anyhow::ensure!(
        (1..=events::MAX_PULL_TIMEOUT.as_secs()).contains(&pull),
        "max_pull_timeout_secs must be between 1 and {}",
        events::MAX_PULL_TIMEOUT.as_secs()
    );
    let consumers: Option<Vec<String>> = params
        .map(|p| p.get_optional_array("notify_consumers"))
        .transpose()?
        .flatten()
        .map(|a| {
            a.iter()
                .map(|v| {
                    v.as_str().map(str::to_string).ok_or_else(|| {
                        anyhow::anyhow!(
                            "notify_consumers holds addresses, CIDR blocks and {}",
                            notify::SUBSCRIBER
                        )
                    })
                })
                .collect::<Result<Vec<_>>>()
        })
        .transpose()?;
    let allowlist = match consumers {
        Some(c) => notify::Allowlist::parse(&c)?,
        None => notify::Allowlist::default_list(),
    };
    let allow_https = params
        .map(|p| p.get_optional_bool("notify_allow_https"))
        .transpose()?
        .flatten()
        .unwrap_or(notify::ALLOW_HTTPS);
    let notify_timeout = params
        .map(|p| p.get_optional_u64("notify_timeout_secs"))
        .transpose()?
        .flatten()
        .unwrap_or(notify::NOTIFY_TIMEOUT.as_secs());
    anyhow::ensure!(
        (1..=notify::MAX_NOTIFY_TIMEOUT_SECS).contains(&notify_timeout),
        "notify_timeout_secs must be between 1 and {}",
        notify::MAX_NOTIFY_TIMEOUT_SECS
    );
    let notify_retries = params
        .map(|p| p.get_optional_u64("notify_retries"))
        .transpose()?
        .flatten()
        .unwrap_or(notify::NOTIFY_RETRIES);
    anyhow::ensure!(
        notify_retries <= notify::MAX_NOTIFY_RETRIES,
        "notify_retries must be between 0 and {}",
        notify::MAX_NOTIFY_RETRIES
    );
    let notify = notify::Config::new(
        allowlist,
        allow_https,
        Duration::from_secs(notify_timeout),
        notify_retries,
    )?;
    let listener = tokio::net::TcpListener::bind(ctx.legacy_listen_addr()).await?;
    let local = listener.local_addr()?;
    Log::new(Some(&ctx.status_tx)).info(format!(
        "ONVIF device listening on {local} ({})",
        if credentials.is_some() {
            "WS-Security digest required"
        } else {
            "no credentials configured: every operation is open"
        }
    ));
    let device = Arc::new(Device {
        credentials,
        max_skew: Duration::from_secs(skew),
        max_pull_timeout: Duration::from_secs(pull),
        nonces: Mutex::new(HashMap::new()),
        clock: Mutex::new(Clock {
            offset: chrono::Duration::zero(),
            date_time_type: "Manual".into(),
            tz: "UTC0".into(),
            daylight_savings: false,
        }),
        scopes: Mutex::new(ScopeState::default()),
        hostname: Mutex::new(None),
        catalog: Mutex::new(Catalog::default()),
        ptz: Mutex::new(ptz::PtzState::default()),
        imaging: Mutex::new(imaging::ImagingState::default()),
        events: events::Broker::default(),
        notify,
        archive: Mutex::new(None),
        searches: Mutex::new(recording::Searches::default()),
    });
    let state = ctx.state.clone();
    let server_id = ctx.server_id;
    // onvif_raise_event finds the running device through this handle.
    state
        .register_server_handle(server_id, device.clone())
        .await;
    let accept = tokio::spawn(async move {
        let limiter = ConnectionLimiter::new(DEFAULT_MAX_CONNECTIONS);
        loop {
            let (stream, peer, permit) = match accept_bounded(
                &listener,
                &limiter,
                b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                "ONVIF",
                Some(&ctx.status_tx),
            )
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
            let child = ctx.clone();
            let device = device.clone();
            ctx.state
                .spawn_server_task(server_id, async move {
                    let _permit = permit;
                    let svc_ctx = child.clone();
                    let service = service_fn(move |request| {
                        let ctx = svc_ctx.clone();
                        let device = device.clone();
                        async move {
                            Ok::<_, Infallible>(
                                handle(&ctx, &device, id, peer, local, request).await,
                            )
                        }
                    });
                    let _ = http1::Builder::new()
                        .timer(TokioTimer::new())
                        .header_read_timeout(HEADER_TIMEOUT)
                        .max_buf_size(64 * 1024)
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                    child
                        .state
                        .update_connection_status(child.server_id, id, ConnectionStatus::Closed)
                        .await;
                    let _ = child.status_tx.send("__UPDATE_UI__".into());
                })
                .await;
        }
    });
    state.register_server_task(server_id, accept).await;
    Ok(local)
}

fn soap(status: StatusCode, body: &str) -> Resp {
    let mut r = Response::new(Full::new(Bytes::from(wire::envelope(body))));
    *r.status_mut() = status;
    r.headers_mut().insert(
        hyper::header::CONTENT_TYPE,
        hyper::header::HeaderValue::from_static("application/soap+xml; charset=utf-8"),
    );
    r
}

fn ok(body: &str) -> Resp {
    soap(StatusCode::OK, body)
}

fn status_of(code: FaultCode) -> StatusCode {
    match code {
        FaultCode::Receiver => StatusCode::INTERNAL_SERVER_ERROR,
        FaultCode::Sender | FaultCode::VersionMismatch => StatusCode::BAD_REQUEST,
    }
}

/// A fault with the HTTP status the SOAP 1.2 binding gives it: 400 for the sender's fault,
/// 500 for ours.
fn fault(code: FaultCode, subcodes: &[&str], reason: &str) -> Resp {
    soap(status_of(code), &wire::fault(code, subcodes, reason))
}

fn fault_detail(code: FaultCode, subcodes: &[&str], reason: &str, detail: &str) -> Resp {
    soap(
        status_of(code),
        &wire::fault_with_detail(code, subcodes, reason, detail),
    )
}

/// env:Sender / ter:InvalidArgVal / ter:<detail>: the request named something wrong.
fn invalid(detail: &str, reason: &str) -> Resp {
    fault(FaultCode::Sender, &["InvalidArgVal", detail], reason)
}

fn bare(code: StatusCode) -> Resp {
    let mut r = Response::new(Full::new(Bytes::new()));
    *r.status_mut() = code;
    r
}

fn outcome(ctx: &SpawnContext, id: ConnectionId, operation: &str, decision: &str) {
    let summary = format!("ONVIF connection {id} operation={operation} decision={decision}");
    let log = Log::new(Some(&ctx.status_tx));
    if decision.starts_with("fail_closed_") || decision == "model_silent" {
        log.error(summary);
    } else {
        log.info(summary);
    }
}

/// The scheme and authority clients reached this server by: the Host header when it is a
/// plain host[:port], else the listening address.
fn base_url(req: &Request<Incoming>, local: SocketAddr) -> String {
    let host = req
        .headers()
        .get(hyper::header::HOST)
        .and_then(|h| h.to_str().ok())
        .filter(|h| {
            !h.is_empty()
                && h.len() <= 255
                && h.chars()
                    .all(|c| c.is_ascii_alphanumeric() || ".-:[]_".contains(c))
        })
        .map(str::to_string)
        .unwrap_or_else(|| local.to_string());
    format!("http://{host}")
}

/// The Receiver fault for a model that gave no usable answer: a category, never the error.
fn unavailable(failure: WireFailure) -> Resp {
    let mut r = fault(FaultCode::Receiver, &[], failure.text());
    if failure.is_overloaded() {
        *r.status_mut() = StatusCode::SERVICE_UNAVAILABLE;
        r.headers_mut().insert(
            hyper::header::RETRY_AFTER,
            hyper::header::HeaderValue::from_static("5"),
        );
    }
    r
}

/// The fault the model chose to refuse with.
fn model_fault(reply: &Value) -> Resp {
    let mut subcodes = vec![reply["subcode"].as_str().unwrap_or("InvalidArgVal")];
    if let Some(d) = reply["detail"].as_str() {
        subcodes.push(d);
    }
    let code = if subcodes[0] == "ActionNotSupported" || subcodes[0] == "Action" {
        FaultCode::Receiver
    } else {
        FaultCode::Sender
    };
    fault(
        code,
        &subcodes,
        reply["reason"].as_str().unwrap_or_default(),
    )
}

/// The model's answer to one request: the first result that is the expected answer or a fault.
/// Events it raised along the way (`onvif_raise_event`) have already gone out and are neither.
async fn ask(
    ctx: &SpawnContext,
    id: ConnectionId,
    event: Event,
    operation: &str,
    answer: &str,
) -> std::result::Result<Value, WireFailure> {
    match call_llm(
        &ctx.llm_client,
        &ctx.state,
        ctx.server_id,
        Some(id),
        &event,
        &actions::OnvifProtocol,
    )
    .await
    {
        Ok(r) => {
            let mut stack = r.protocol_results;
            stack.reverse();
            let mut chosen = None;
            // An answer meant for another operation is a wrong answer, not silence.
            let mut wrong = false;
            while let Some(r) = stack.pop() {
                match r {
                    ActionResult::Custom { name, data }
                        if name == answer || name == actions::FAULT =>
                    {
                        chosen = Some(data);
                        break;
                    }
                    ActionResult::Custom { name, .. } if name == actions::RAISE_EVENT => {}
                    ActionResult::Custom { .. } => wrong = true,
                    ActionResult::Multiple(items) => stack.extend(items.into_iter().rev()),
                    _ => {}
                }
            }
            match chosen {
                Some(data) => {
                    outcome(
                        ctx,
                        id,
                        operation,
                        if data["type"] == actions::FAULT {
                            "model_reject"
                        } else {
                            "model_answer"
                        },
                    );
                    Ok(data)
                }
                None if r.failures.is_empty() && !wrong => {
                    outcome(ctx, id, operation, "model_silent");
                    Err(WireFailure::Unavailable)
                }
                None => {
                    outcome(ctx, id, operation, "fail_closed_invalid_reply");
                    Err(WireFailure::Unavailable)
                }
            }
        }
        Err(e) => {
            outcome(ctx, id, operation, "fail_closed_llm_error");
            Err(WireFailure::classify(&e))
        }
    }
}

/// One authenticated request being answered.
pub(crate) struct Call<'a> {
    ctx: &'a SpawnContext,
    device: &'a Arc<Device>,
    id: ConnectionId,
    peer: SocketAddr,
    /// `http://host:port` as the client reached us.
    base: String,
    /// The request's path, which names a pull-point subscription.
    path: String,
    req: wire::Request,
    username: Value,
}

impl Call<'_> {
    fn op(&self) -> &str {
        &self.req.operation
    }

    fn body(&self) -> &wire::Element {
        &self.req.body
    }

    /// Ask the model `event_type` about this request with `extra` facts; Ok is the answer named
    /// `answer`, Err the response to send instead (the model's fault, or a fail-closed one).
    async fn ask(
        &self,
        event_type: &'static EventType,
        extra: Value,
        answer: &str,
    ) -> std::result::Result<Value, Resp> {
        let mut data = if extra.is_object() { extra } else { json!({}) };
        data["operation"] = json!(self.op());
        data["username"] = self.username.clone();
        data["remote_addr"] = json!(self.peer.to_string());
        match ask(
            self.ctx,
            self.id,
            Event::new(event_type, data),
            self.op(),
            answer,
        )
        .await
        {
            Err(failure) => Err(unavailable(failure)),
            Ok(reply) if reply["type"] == actions::FAULT => Err(model_fault(&reply)),
            Ok(reply) => Ok(reply),
        }
    }
}

/// The short name of the service an operation's namespace belongs to, for the request log.
fn service_name(ns: &str) -> &'static str {
    match ns {
        wire::TDS => "device",
        wire::TRT => "media",
        wire::TR2 => "media2",
        wire::TPTZ => "ptz",
        wire::TEV | wire::WSNT => "events",
        wire::TIMG => "imaging",
        wire::TRC => "recording",
        wire::TSE => "search",
        wire::TRP => "replay",
        _ => "other",
    }
}

async fn handle(
    ctx: &SpawnContext,
    device: &Arc<Device>,
    id: ConnectionId,
    peer: SocketAddr,
    local: SocketAddr,
    req: Request<Incoming>,
) -> Resp {
    let log = Log::new(Some(&ctx.status_tx));
    if req.method() != hyper::Method::POST {
        let mut r = bare(StatusCode::METHOD_NOT_ALLOWED);
        r.headers_mut().insert(
            hyper::header::ALLOW,
            hyper::header::HeaderValue::from_static("POST"),
        );
        return r;
    }
    let base = base_url(&req, local);
    let path = req.uri().path().to_string();
    let body = match Limited::new(req.into_body(), wire::MAX_REQUEST)
        .collect()
        .await
    {
        Ok(b) => b.to_bytes(),
        Err(_) => {
            log.warn(format!(
                "ONVIF connection {id}: request larger than {} bytes refused",
                wire::MAX_REQUEST
            ));
            return bare(StatusCode::PAYLOAD_TOO_LARGE);
        }
    };
    ctx.state
        .update_connection_stats(
            ctx.server_id,
            id,
            Some(body.len() as u64),
            None,
            Some(1),
            None,
        )
        .await;
    let request = match wire::parse_request(&body) {
        Ok(r) => r,
        Err(e) => {
            log.warn(format!("ONVIF connection {id}: unreadable request: {e:#}"));
            return fault(
                FaultCode::Sender,
                &["WellFormed"],
                "The request is not a well-formed SOAP envelope",
            );
        }
    };
    if !request.soap12 {
        return fault(FaultCode::VersionMismatch, &[], "ONVIF speaks SOAP 1.2");
    }
    let operation = request.operation.clone();
    // One line per request, naming its service: what each client actually sends is read
    // from here.
    log.debug_to(
        Sink::Both,
        format!(
            "ONVIF connection {id} request {}:{operation}",
            service_name(&request.ns)
        ),
    );
    let Some(op) = handlers::Op::of(&request.ns, &operation) else {
        outcome(ctx, id, &operation, "action_not_supported");
        return fault(
            FaultCode::Receiver,
            &["ActionNotSupported"],
            "Optional Action Not Implemented",
        );
    };
    // Authentication: everything but GetSystemDateAndTime, when credentials are configured,
    // checked against the device's own clock.
    let mut username = Value::Null;
    if op != handlers::Op::SystemDateAndTime {
        if let Some((user, password)) = &device.credentials {
            let verdict = wire::verify_token(
                request.token.as_ref(),
                user,
                password,
                device.now(),
                chrono::Duration::from_std(device.max_skew).unwrap_or(chrono::Duration::MAX),
            )
            .and_then(|nonce| {
                if device.fresh_nonce(nonce) {
                    Ok(())
                } else {
                    Err("replayed_nonce")
                }
            });
            if let Err(reason) = verdict {
                outcome(
                    ctx,
                    id,
                    &operation,
                    &format!("fail_closed_not_authorized reason={reason}"),
                );
                ctx.state
                    .record_access_log(
                        AccessLogOwner::Server(ctx.server_id.as_u32()),
                        "ONVIF",
                        Some(id.as_u32()),
                        "onvif_not_authorized",
                        json!({"operation": operation, "reason": reason, "remote_addr": peer.to_string()}),
                        vec![],
                    )
                    .await;
                return fault(
                    FaultCode::Sender,
                    &["NotAuthorized"],
                    "Sender not Authorized",
                );
            }
            username = json!(user);
        }
    }
    let call = Call {
        ctx,
        device,
        id,
        peer,
        base,
        path,
        req: request,
        username,
    };
    handlers::dispatch(&call, op).await
}
