//! ONVIF device (server role): the Device and Media services over SOAP 1.2 on HTTP/1.1.
//!
//! Rust owns the envelopes, WS-Security, the clock, the service addresses and every fault the
//! specification defines; the model decides what the device says about itself and its media.
//! Each request is one of three kinds:
//!
//! - answered by Rust: GetSystemDateAndTime (never authenticated, so a client can learn the
//!   clock before it signs anything), GetCapabilities and GetServices (they name this server);
//! - asked of the model: GetDeviceInformation, GetScopes, GetNetworkInterfaces, GetProfiles,
//!   GetVideoSources, GetStreamUri, GetSnapshotUri;
//! - refused: anything else is env:Receiver/ter:ActionNotSupported, a request that fails
//!   authentication is env:Sender/ter:NotAuthorized, and a model that gives no usable answer is
//!   env:Receiver with a category.
pub mod actions;
pub mod wire;

use crate::llm::action_helper::call_llm;
use crate::llm::actions::protocol_trait::ActionResult;
use crate::logging::emit::Log;
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
use std::sync::{Arc, Mutex};
use std::time::Duration;
use wire::FaultCode;

/// How far a UsernameToken's Created may be from the device's clock, by default.
pub const MAX_CLOCK_SKEW: Duration = Duration::from_secs(300);
pub const MAX_CLOCK_SKEW_SECS: u64 = 86_400;
pub const HEADER_TIMEOUT: Duration = Duration::from_secs(30);
/// Nonces remembered at most; past it the oldest is forgotten.
pub const MAX_NONCES: usize = 4096;

struct Device {
    credentials: Option<(String, String)>,
    max_skew: Duration,
    /// Nonces of accepted tokens, with when they were seen: a token is accepted once.
    nonces: Mutex<HashMap<Vec<u8>, crate::utils::clock::Instant>>,
}

impl Device {
    /// Remember a nonce; false when it was already used inside the freshness window.
    fn fresh_nonce(&self, nonce: Vec<u8>) -> bool {
        let now = crate::utils::clock::Instant::now();
        let mut seen = self.nonces.lock().unwrap_or_else(|e| e.into_inner());
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
}

/// The operations NetGet serves, by namespace and name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    SystemDateAndTime,
    Capabilities,
    Services,
    DeviceInformation,
    Scopes,
    NetworkInterfaces,
    Profiles,
    VideoSources,
    StreamUri,
    SnapshotUri,
}

impl Op {
    fn of(ns: &str, name: &str) -> Option<Op> {
        Some(match (ns, name) {
            (wire::TDS, "GetSystemDateAndTime") => Op::SystemDateAndTime,
            (wire::TDS, "GetCapabilities") => Op::Capabilities,
            (wire::TDS, "GetServices") => Op::Services,
            (wire::TDS, "GetDeviceInformation") => Op::DeviceInformation,
            (wire::TDS, "GetScopes") => Op::Scopes,
            (wire::TDS, "GetNetworkInterfaces") => Op::NetworkInterfaces,
            (wire::TRT, "GetProfiles") => Op::Profiles,
            (wire::TRT, "GetVideoSources") => Op::VideoSources,
            (wire::TRT, "GetStreamUri") => Op::StreamUri,
            (wire::TRT, "GetSnapshotUri") => Op::SnapshotUri,
            _ => return None,
        })
    }

    /// The event the model is asked with, and the action that answers it.
    fn event(self) -> Option<(&'static EventType, &'static str)> {
        Some(match self {
            Op::DeviceInformation => (
                &actions::DEVICE_INFORMATION_EVENT,
                actions::DEVICE_INFORMATION,
            ),
            Op::Scopes => (&actions::SCOPES_EVENT, actions::SCOPES),
            Op::NetworkInterfaces => (
                &actions::NETWORK_INTERFACES_EVENT,
                actions::NETWORK_INTERFACES,
            ),
            Op::Profiles => (&actions::PROFILES_EVENT, actions::PROFILES),
            Op::VideoSources => (&actions::VIDEO_SOURCES_EVENT, actions::VIDEO_SOURCES),
            Op::StreamUri => (&actions::STREAM_URI_EVENT, actions::STREAM_URI),
            Op::SnapshotUri => (&actions::SNAPSHOT_URI_EVENT, actions::SNAPSHOT_URI),
            Op::SystemDateAndTime | Op::Capabilities | Op::Services => return None,
        })
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
        nonces: Mutex::new(HashMap::new()),
    });
    let state = ctx.state.clone();
    let server_id = ctx.server_id;
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

fn soap(status: StatusCode, body: &str) -> Response<Full<Bytes>> {
    let mut r = Response::new(Full::new(Bytes::from(wire::envelope(body))));
    *r.status_mut() = status;
    r.headers_mut().insert(
        hyper::header::CONTENT_TYPE,
        hyper::header::HeaderValue::from_static("application/soap+xml; charset=utf-8"),
    );
    r
}

/// A fault with the HTTP status the SOAP 1.2 binding gives it: 400 for the sender's fault,
/// 500 for ours.
fn fault(code: FaultCode, subcodes: &[&str], reason: &str) -> Response<Full<Bytes>> {
    let status = match code {
        FaultCode::Receiver => StatusCode::INTERNAL_SERVER_ERROR,
        FaultCode::Sender | FaultCode::VersionMismatch => StatusCode::BAD_REQUEST,
    };
    soap(status, &wire::fault(code, subcodes, reason))
}

fn bare(code: StatusCode) -> Response<Full<Bytes>> {
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
fn unavailable(failure: WireFailure) -> Response<Full<Bytes>> {
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

/// The model's answer to one request: the first result that is the expected answer or a fault.
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

/// What an operation's request says, for the model.
fn arguments(op: Op, body: &wire::Element) -> Value {
    match op {
        Op::StreamUri => json!({
            "profile_token": body.text_of("ProfileToken").unwrap_or_default(),
            "stream": body.path(&["StreamSetup", "Stream"]).unwrap_or_default(),
            "protocol": body.path(&["StreamSetup", "Transport", "Protocol"]).unwrap_or_default(),
        }),
        Op::SnapshotUri => {
            json!({"profile_token": body.text_of("ProfileToken").unwrap_or_default()})
        }
        _ => json!({}),
    }
}

async fn handle(
    ctx: &SpawnContext,
    device: &Arc<Device>,
    id: ConnectionId,
    peer: SocketAddr,
    local: SocketAddr,
    req: Request<Incoming>,
) -> Response<Full<Bytes>> {
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
    let Some(op) = Op::of(&request.ns, &operation) else {
        outcome(ctx, id, &operation, "action_not_supported");
        return fault(
            FaultCode::Receiver,
            &["ActionNotSupported"],
            "Optional Action Not Implemented",
        );
    };
    // Authentication: everything but GetSystemDateAndTime, when credentials are configured.
    let mut username = Value::Null;
    if op != Op::SystemDateAndTime {
        if let Some((user, password)) = &device.credentials {
            let verdict = wire::verify_token(
                request.token.as_ref(),
                user,
                password,
                chrono::Utc::now(),
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
    match op {
        Op::SystemDateAndTime => soap(
            StatusCode::OK,
            &wire::system_date_and_time(chrono::Utc::now()),
        ),
        Op::Services => soap(StatusCode::OK, &wire::services(&base)),
        Op::Capabilities => {
            let categories: Vec<String> = request
                .body
                .children_named("Category")
                .map(|c| c.text.trim().to_string())
                .collect();
            let wants =
                |c: &str| categories.is_empty() || categories.iter().any(|x| x == "All" || x == c);
            if !categories
                .iter()
                .all(|c| matches!(c.as_str(), "All" | "Device" | "Media"))
            {
                return fault(
                    FaultCode::Receiver,
                    &["ActionNotSupported", "NoSuchService"],
                    "The device does not have that service",
                );
            }
            soap(
                StatusCode::OK,
                &wire::capabilities(&base, wants("Device"), wants("Media")),
            )
        }
        _ => {
            let Some((event_type, answer)) = op.event() else {
                return fault(
                    FaultCode::Receiver,
                    &["ActionNotSupported"],
                    "Optional Action Not Implemented",
                );
            };
            let mut data = arguments(op, &request.body);
            data["operation"] = json!(operation);
            data["username"] = username;
            data["remote_addr"] = json!(peer.to_string());
            let reply = match ask(ctx, id, Event::new(event_type, data), &operation, answer).await {
                Ok(v) => v,
                Err(failure) => return unavailable(failure),
            };
            if reply["type"] == actions::FAULT {
                let mut subcodes = vec![reply["subcode"].as_str().unwrap_or("InvalidArgVal")];
                if let Some(d) = reply["detail"].as_str() {
                    subcodes.push(d);
                }
                let code = if subcodes[0] == "ActionNotSupported" || subcodes[0] == "Action" {
                    FaultCode::Receiver
                } else {
                    FaultCode::Sender
                };
                return fault(
                    code,
                    &subcodes,
                    reply["reason"].as_str().unwrap_or_default(),
                );
            }
            let body = match op {
                Op::DeviceInformation => wire::device_information(&reply),
                Op::Scopes => wire::scopes(&reply),
                Op::NetworkInterfaces => wire::network_interfaces(&reply),
                Op::Profiles => wire::profiles(&reply),
                Op::VideoSources => wire::video_sources(&reply),
                Op::StreamUri => wire::media_uri("GetStreamUri", &reply),
                Op::SnapshotUri => wire::media_uri("GetSnapshotUri", &reply),
                Op::SystemDateAndTime | Op::Capabilities | Op::Services => String::new(),
            };
            soap(StatusCode::OK, &body)
        }
    }
}
