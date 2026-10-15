//! YARN client: NetGet reads a Hadoop YARN ResourceManager's REST API (`/ws/v1/cluster`) and
//! the model decides what to read. See `AGENTS.md` beside this file.
//!
//! Rust owns the URL, the HTTP exchange, every bound and the decoding: an action names a
//! resource by structured values (`actions::request` validates them), the path is assembled
//! here one percent-encoded segment at a time on the base URL fixed at connect, and the response
//! is measured, parsed, unwrapped and projected (`decode`) before the model sees it.
//!
//! Two tasks per client, both registered so `stop_client` ends them:
//!
//! * the **session** runs one request at a time — the model's, or one injected from the
//!   dashboard or MCP — and turns the answer into an event.
//! * the **turns** task asks the model about each event and hands its actions back. Each event
//!   carries the number of model turns that led to it; past [`MAX_FOLLOWUP_DEPTH`] the model is
//!   not asked again.
//!
//! **The target is mandatory.** The client talks to `endpoint_url` exactly as given, or to its
//! `remote_addr`; without one it refuses to start. **Redirects are not followed**, not even to
//! the same host: a standby ResourceManager in an HA pair redirects to the active one, which is
//! a different machine, and following it would change the target behind the operator's back.
//! `connect` reads `GET /ws/v1/cluster/info` first — the one resource a standby answers itself
//! — so a target that is not a ResourceManager fails the client before the model is asked
//! anything, and the model is told the ResourceManager's HA state.
//!
//! **Read-only unless told otherwise.** The one write, `kill_application`, is refused before
//! anything is sent unless the client was opened with `allow_kill: true`. Application
//! submission is not implemented at all: its body carries the shell command YARN runs.
//!
//! Fail closed: an unreachable or non-YARN target fails `connect`; an LLM failure sends
//! nothing; an error status, a redirect or an answer that cannot be read becomes a `yarn_error`
//! naming why, never an invented result.
pub mod actions;
pub mod decode;

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{anyhow, ensure, Context, Result};
use serde_json::{json, Value};
use tokio::sync::mpsc;

use crate::client::http_fetch::FetchClient;
use crate::client::llm_budget::call_llm_for_client;
use crate::llm::actions::client_trait::{Client, ClientActionResult};
use crate::logging::emit::Log;
use crate::protocol::{ConnectContext, Event, EventType};
use crate::state::client_handles::{ClientCommand, ClientSendOutcome};
use crate::state::{AccessLogOwner, ClientStatus};
pub use actions::{ApiCall, YarnClientProtocol};
use decode::Resource;

/// How many model turns may follow from one another before the chain stops.
pub const MAX_FOLLOWUP_DEPTH: u32 = 8;
/// How long one request may take.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_REQUEST_TIMEOUT_SECS: u64 = 600;
/// The largest response body read. An unfiltered application list on a busy cluster is the
/// largest answer the ResourceManager gives (~1.5 KiB per application, 10000 retained by
/// default); past this the model is told to filter or use `limit`.
pub const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
/// Entries delivered when the action names no `max_items`.
pub const DEFAULT_MAX_ITEMS: usize = 50;
/// The most entries one event carries.
pub const MAX_ITEMS_LIMIT: usize = 500;
/// The most of a server's own error text kept.
pub const MAX_ERROR_BYTES: usize = 1024;
/// Events waiting for the model.
const TURNS: usize = 64;

fn user_agent() -> String {
    format!("NetGet/{}", env!("CARGO_PKG_VERSION"))
}

/// The base URL this client talks to: `endpoint_url` as given, else `remote_addr` (a bare
/// `host:port` meaning `http://host:port`). There is no third option. A path is allowed, for a
/// ResourceManager behind a gateway; a query, a fragment or credentials are not.
pub fn resolve_endpoint(remote_addr: &str, endpoint_url: Option<&str>) -> Result<url::Url> {
    let given = match endpoint_url.map(str::trim).filter(|u| !u.is_empty()) {
        Some(url) => url.to_string(),
        None => {
            let raw = remote_addr.trim();
            ensure!(
                !raw.is_empty(),
                "the YARN client needs a target: a remote_addr (host:port) or an endpoint_url. \
                 Refusing to start without one"
            );
            if raw.contains("://") {
                raw.to_string()
            } else {
                format!("http://{raw}")
            }
        }
    };
    let parsed = url::Url::parse(&given).with_context(|| format!("{given:?} is not a URL"))?;
    ensure!(
        matches!(parsed.scheme(), "http" | "https") && parsed.host_str().is_some(),
        "{given:?} is not an http(s) URL with a host"
    );
    ensure!(
        parsed.query().is_none() && parsed.fragment().is_none(),
        "{given:?}: the endpoint is a base URL, without a query or fragment"
    );
    ensure!(
        parsed.username().is_empty() && parsed.password().is_none(),
        "{given:?}: credentials in the URL are not accepted"
    );
    let path = parsed.path().trim_end_matches('/');
    ensure!(
        !path.ends_with("/ws/v1") && !path.ends_with("/ws/v1/cluster"),
        "{given:?}: give the ResourceManager's base URL; the client adds /ws/v1/cluster itself"
    );
    Ok(parsed)
}

/// `base` + `/ws/v1/cluster/` + each segment, percent-encoded as one segment, + the query. The
/// host, port and scheme are the base's; nothing in `segments` or `query` can change them.
pub fn api_url(base: &url::Url, segments: &[String], query: &[(String, String)]) -> Result<String> {
    let mut url = base.clone();
    {
        let mut path = url
            .path_segments_mut()
            .map_err(|_| anyhow!("{base} cannot carry a path"))?;
        path.pop_if_empty().push("ws").push("v1").push("cluster");
        for segment in segments {
            ensure!(
                !segment.is_empty() && segment != "." && segment != "..",
                "an empty or dot path segment is never sent"
            );
            path.push(segment);
        }
    }
    if !query.is_empty() {
        url.query_pairs_mut().extend_pairs(query);
    }
    ensure!(
        url.origin() == base.origin(),
        "{url} is not on the client's target {base}"
    );
    Ok(url.to_string())
}

#[cfg(not(target_arch = "wasm32"))]
fn http_client(base: &str, timeout: Duration) -> Result<FetchClient> {
    let builder = reqwest::Client::builder()
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(user_agent());
    let client = crate::llm::ollama_client::configured_for_endpoint(builder, base)
        .build()
        .context("building the HTTP client")?;
    Ok(FetchClient::from_reqwest(client).with_max_body(MAX_RESPONSE_BYTES))
}

#[cfg(target_arch = "wasm32")]
fn http_client(_base: &str, timeout: Duration) -> Result<FetchClient> {
    Ok(FetchClient::transport(timeout)
        .with_max_body(MAX_RESPONSE_BYTES)
        .with_user_agent(&user_agent()))
}

/// What one request produced: the event to raise.
pub type Done = (&'static EventType, Value);

/// The event a resource is answered with.
fn event_for(resource: Resource) -> &'static EventType {
    match resource {
        Resource::ClusterInfo => &actions::CLUSTER_INFO_EVENT,
        Resource::Metrics => &actions::METRICS_EVENT,
        Resource::Scheduler => &actions::SCHEDULER_EVENT,
        Resource::Applications => &actions::APPLICATIONS_EVENT,
        Resource::Attempts => &actions::ATTEMPTS_EVENT,
        Resource::AppState => &actions::APP_STATE_EVENT,
        Resource::AppQueue => &actions::APP_QUEUE_EVENT,
        Resource::Nodes => &actions::NODES_EVENT,
    }
}

fn error_event(
    call: &ApiCall,
    status: Option<u16>,
    exception: Option<String>,
    message: String,
) -> Done {
    let mut data = json!({"operation": call.operation, "message": message});
    for key in ["app_id", "node_id"] {
        if let Some(v) = call.context.get(key) {
            data[key] = v.clone();
        }
    }
    if let Some(status) = status {
        data["http_status"] = json!(status);
    }
    if let Some(e) = exception.filter(|e| !e.is_empty()) {
        data["exception"] = json!(e);
    }
    (&actions::ERROR_EVENT, data)
}

/// The server's own words for an error: YARN's RemoteException, its plain-text body, or the
/// title of an HTML page.
fn error_text(body: &[u8]) -> (Option<String>, String) {
    if let Some((exception, message)) = decode::remote_exception(body) {
        return (
            Some(exception),
            crate::utils::truncate::truncate_with_suffix(&message, MAX_ERROR_BYTES, "..."),
        );
    }
    let text = String::from_utf8_lossy(body);
    let trimmed = text.trim();
    let message = if trimmed.starts_with('<') {
        let lower = trimmed.to_ascii_lowercase();
        match (lower.find("<title>"), lower.find("</title>")) {
            (Some(a), Some(b)) if b > a + 7 => trimmed[a + 7..b].to_string(),
            _ => "an HTML error page".to_string(),
        }
    } else if trimmed.is_empty() {
        "the server sent no error text".to_string()
    } else {
        trimmed.to_string()
    };
    (
        None,
        crate::utils::truncate::truncate_with_suffix(
            &crate::utils::sanitize::line_field(&message),
            MAX_ERROR_BYTES,
            "...",
        ),
    )
}

/// The REST API this client reads.
pub struct Api {
    http: FetchClient,
    pub base: url::Url,
    timeout: Duration,
    /// Whether `kill_application` may be sent.
    pub allow_kill: bool,
}

impl Api {
    pub fn new(base: url::Url, timeout: Duration, allow_kill: bool) -> Result<Api> {
        Ok(Api {
            http: http_client(base.as_str(), timeout)?,
            base,
            timeout,
            allow_kill,
        })
    }

    /// One request, bounded in time and size: `(status, Location, body)`, or why there was no
    /// answer.
    async fn send(&self, call: &ApiCall, url: &str) -> Result<(u16, Option<String>, bytes::Bytes)> {
        let send = async {
            let request = match (call.method.as_str(), &call.body) {
                ("GET", None) => self.http.get(url),
                ("PUT", Some(body)) => self.http.put(url).json(body),
                (m, _) => return Err(anyhow!("{m} with this body is never sent")),
            };
            let resp = request
                .header("Accept", "application/json")
                .send()
                .await
                .map_err(|e| anyhow!("no answer from {}: {e:#}", self.base))?;
            let status = resp.status().as_u16();
            let location = resp
                .headers()
                .get("location")
                .and_then(|v| v.to_str().ok())
                .map(str::to_string);
            // The one size bound: `FetchClient::with_max_body` stops reading past
            // MAX_RESPONSE_BYTES, so an oversized answer is never buffered whole.
            let body = resp.bytes().await.map_err(|e| {
                anyhow!(
                    "reading the answer (at most {MAX_RESPONSE_BYTES} bytes are read — narrow \
                     the request with a filter, limit or max_items): {e:#}"
                )
            })?;
            Ok((status, location, body))
        };
        tokio::time::timeout(self.timeout, send)
            .await
            .map_err(|_| anyhow!("no answer within {}s", self.timeout.as_secs()))?
    }

    /// Run one validated request. Always an event: the resource's, or `yarn_error`.
    pub async fn run(&self, call: &ApiCall) -> Done {
        let Some(resource) = Resource::of(&call.operation) else {
            return error_event(
                call,
                None,
                None,
                format!("{} reads nothing", call.operation),
            );
        };
        if call.operation == "kill_application" && !self.allow_kill {
            return error_event(
                call,
                None,
                None,
                "kill_application is refused: this client was opened without allow_kill, so it \
                 is read-only. Nothing was sent"
                    .into(),
            );
        }
        let url = match api_url(&self.base, &call.segments, &call.query) {
            Ok(u) => u,
            Err(e) => return error_event(call, None, None, format!("{e:#}")),
        };
        let (status, location, body) = match self.send(call, &url).await {
            Ok(r) => r,
            Err(e) => return error_event(call, None, None, format!("{e:#}")),
        };
        if (300..400).contains(&status) {
            let to = location
                .map(|l| {
                    crate::utils::truncate::truncate_with_suffix(
                        &crate::utils::sanitize::line_field(&l),
                        MAX_ERROR_BYTES,
                        "...",
                    )
                })
                .unwrap_or_else(|| "nowhere".into());
            return error_event(
                call,
                Some(status),
                None,
                format!(
                    "the server redirected to {to}; redirects are not followed (a standby \
                     ResourceManager redirects to the active one) — open a client on that \
                     address if it is the one meant"
                ),
            );
        }
        if !(200..300).contains(&status) {
            let (exception, message) = error_text(&body);
            return error_event(call, Some(status), exception, message);
        }
        let value = match decode::parse(&body) {
            Ok(v) => v,
            Err(e) => return error_event(call, Some(status), None, format!("{e:#}")),
        };
        match decode::decode(
            resource,
            &call.operation,
            &value,
            call.max_items,
            &call.context,
        ) {
            Ok(mut payload) => {
                if call.method != "GET" {
                    payload["http_status"] = json!(status);
                }
                (event_for(resource), payload)
            }
            Err(e) => error_event(
                call,
                Some(status),
                None,
                format!("the answer is not what YARN sends: {e:#}"),
            ),
        }
    }

    /// `GET /ws/v1/cluster/info`: the ResourceManager's identity, or why this is not one.
    pub async fn cluster_info(&self) -> Result<Value> {
        let call = actions::request(&json!({"type": "get_cluster_info"}))?;
        match self.run(&call).await {
            (event, payload) if event.id == actions::CLUSTER_INFO_EVENT.id => {
                Ok(payload["cluster_info"].clone())
            }
            (_, payload) => Err(anyhow!(
                "{} did not answer GET /ws/v1/cluster/info as a YARN ResourceManager does: {}",
                self.base,
                payload["message"].as_str().unwrap_or("no reason given")
            )),
        }
    }
}

pub async fn connect(ctx: ConnectContext) -> Result<SocketAddr> {
    let params = ctx.startup_params.as_ref();
    let endpoint_url = params
        .map(|p| p.get_optional_string("endpoint_url"))
        .transpose()?
        .flatten();
    let base = resolve_endpoint(&ctx.remote_addr, endpoint_url.as_deref())?;
    crate::client::http_fetch::check_url(base.as_str())?;
    let timeout_secs = params
        .map(|p| p.get_optional_u64("request_timeout_secs"))
        .transpose()?
        .flatten()
        .unwrap_or(REQUEST_TIMEOUT.as_secs());
    ensure!(
        (1..=MAX_REQUEST_TIMEOUT_SECS).contains(&timeout_secs),
        "request_timeout_secs is 1..={MAX_REQUEST_TIMEOUT_SECS}"
    );
    let allow_kill = params
        .map(|p| p.get_optional_bool("allow_kill"))
        .transpose()?
        .flatten()
        .unwrap_or(false);
    let log = Log::new(Some(&ctx.status_tx));
    let api = Api::new(base.clone(), Duration::from_secs(timeout_secs), allow_kill)?;
    let info = match api.cluster_info().await {
        Ok(v) => v,
        Err(e) => {
            log.warn(format!(
                "YARN client {}: {e:#} decision=fail_closed_connect",
                ctx.client_id
            ));
            return Err(e);
        }
    };
    let version = info["resourceManagerVersion"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    ctx.state
        .update_client_status(ctx.client_id, ClientStatus::Connected)
        .await;
    log.info(format!(
        "YARN client {} reached ResourceManager {version} ({}) at {base}{}",
        ctx.client_id,
        info["haState"].as_str().unwrap_or("no HA state"),
        if allow_kill { ", kill allowed" } else { "" }
    ));
    let _ = ctx.status_tx.send("__UPDATE_UI__".into());

    // Registered before the connected turn can run, so the operator can reach the client
    // while that turn is parked on a manual rule.
    let external =
        crate::client::command_support::register_command_channel(&ctx.state, ctx.client_id).await;
    let (event_tx, event_rx) = mpsc::channel::<(Event, u32)>(TURNS);
    let (internal_tx, internal) = mpsc::channel::<(Value, u32)>(TURNS);
    let mut connected = json!({
        "endpoint": base.as_str(),
        "resource_manager_version": version,
        "kill_allowed": allow_kill,
    });
    for (from, to) in [
        ("id", "cluster_id"),
        ("state", "state"),
        ("haState", "ha_state"),
    ] {
        if let Some(v) = info.get(from) {
            connected[to] = v.clone();
        }
    }
    let _ = event_tx.try_send((Event::new(&actions::CONNECTED_EVENT, connected), 0));
    let dispatcher = tokio::spawn(run_turns(ctx.clone(), event_rx, internal_tx));
    let dispatcher_abort = dispatcher.abort_handle();
    ctx.state
        .register_client_task(ctx.client_id, dispatcher)
        .await;
    let session_ctx = ctx.clone();
    let task = tokio::spawn(async move {
        run_session(&api, &session_ctx, external, internal, event_tx).await;
        dispatcher_abort.abort();
        session_ctx
            .state
            .update_client_status(session_ctx.client_id, ClientStatus::Disconnected)
            .await;
        session_ctx
            .state
            .remove_client_handle(session_ctx.client_id)
            .await;
        let _ = session_ctx.status_tx.send("__UPDATE_UI__".into());
    });
    ctx.state.register_client_task(ctx.client_id, task).await;
    // HTTP holds no one socket for the session; there is no local address to report.
    Ok(SocketAddr::from(([0, 0, 0, 0], 0)))
}

fn reply(command: Option<ClientCommand>, outcome: ClientSendOutcome) {
    if let Some(c) = command {
        crate::client::command_support::reply(c, Ok(outcome));
    }
}

/// Run requests one at a time until the client disconnects or is stopped.
async fn run_session(
    api: &Api,
    ctx: &ConnectContext,
    mut external: mpsc::Receiver<ClientCommand>,
    mut internal: mpsc::Receiver<(Value, u32)>,
    events: mpsc::Sender<(Event, u32)>,
) {
    let protocol = YarnClientProtocol;
    loop {
        let (action, depth, command) = tokio::select! {
            c = external.recv() => match c {
                Some(c) => {
                    ctx.state.record_access_log(AccessLogOwner::Client(ctx.client_id.as_u32()), "YARN",
                        None, "injected_action", c.action.clone(), vec![]).await;
                    (c.action.clone(), 0, Some(c))
                }
                None => return,
            },
            a = internal.recv() => match a {
                Some((a, d)) => (a, d, None),
                None => return,
            },
        };
        let call = match protocol.execute_action(action) {
            Ok(ClientActionResult::Custom { data, .. }) => {
                match serde_json::from_value::<ApiCall>(data) {
                    Ok(call) => call,
                    Err(e) => {
                        reply(
                            command,
                            ClientSendOutcome::Rejected {
                                error: e.to_string(),
                            },
                        );
                        continue;
                    }
                }
            }
            Ok(ClientActionResult::Disconnect) => {
                Log::new(Some(&ctx.status_tx)).info(format!(
                    "YARN client {} disconnecting from {}",
                    ctx.client_id, api.base
                ));
                reply(command, ClientSendOutcome::Disconnected);
                return;
            }
            Ok(_) => {
                reply(
                    command,
                    ClientSendOutcome::Executed {
                        detail: "nothing to send".into(),
                    },
                );
                continue;
            }
            Err(e) => {
                Log::new(Some(&ctx.status_tx)).warn(format!(
                    "YARN client {}: action refused: {e:#}",
                    ctx.client_id
                ));
                reply(
                    command,
                    ClientSendOutcome::Rejected {
                        error: e.to_string(),
                    },
                );
                continue;
            }
        };
        if call.operation == "kill_application" && !api.allow_kill {
            Log::new(Some(&ctx.status_tx)).warn(format!(
                "YARN client {}: kill_application refused without allow_kill \
                 decision=refused_kill_not_allowed",
                ctx.client_id
            ));
        }
        let (event_type, payload) = api.run(&call).await;
        let request_bytes = api_url(&api.base, &call.segments, &call.query)
            .map(|u| u.len())
            .unwrap_or(0);
        reply(
            command,
            ClientSendOutcome::Sent {
                bytes_sent: request_bytes,
            },
        );
        tracing::info!(
            "YARN client {} {} -> {} (depth {depth})",
            ctx.client_id,
            call.operation,
            event_type.id
        );
        if events
            .try_send((Event::new(event_type, payload), depth))
            .is_err()
        {
            Log::new(Some(&ctx.status_tx)).warn(format!(
                "YARN client {}: {} events are waiting for the model; this one is dropped \
                 decision=turn_queue_full",
                ctx.client_id, TURNS
            ));
        }
        let _ = ctx.status_tx.send("__UPDATE_UI__".into());
    }
}

/// Ask the model about each event, in order, and hand its actions to the session.
async fn run_turns(
    ctx: ConnectContext,
    mut events: mpsc::Receiver<(Event, u32)>,
    internal: mpsc::Sender<(Value, u32)>,
) {
    let protocol = YarnClientProtocol;
    while let Some((event, depth)) = events.recv().await {
        if depth >= MAX_FOLLOWUP_DEPTH {
            Log::new(Some(&ctx.status_tx)).warn(format!(
                "YARN client {} not asking the model about {}: {depth} turns deep \
                 decision=followup_depth",
                ctx.client_id,
                event.id()
            ));
            continue;
        }
        let instruction = ctx
            .state
            .get_instruction_for_client(ctx.client_id)
            .await
            .unwrap_or_default();
        let memory = ctx
            .state
            .get_memory_for_client(ctx.client_id)
            .await
            .unwrap_or_default();
        match call_llm_for_client(
            &ctx.llm_client,
            &ctx.state,
            ctx.client_id.to_string(),
            &instruction,
            &memory,
            Some(&event),
            &protocol,
            &ctx.status_tx,
        )
        .await
        {
            Ok(result) => {
                if let Some(memory) = result.memory_updates {
                    ctx.state.set_memory_for_client(ctx.client_id, memory).await;
                }
                tracing::info!(
                    "YARN client {} {} decision={} actions={}",
                    ctx.client_id,
                    event.id(),
                    if result.actions.is_empty() {
                        "model_silent"
                    } else {
                        "model_actions"
                    },
                    result.actions.len()
                );
                for action in result.actions {
                    if internal.send((action, depth + 1)).await.is_err() {
                        return;
                    }
                }
            }
            // Fail closed: nothing is read on the model's behalf when it cannot be asked.
            Err(e) => Log::new(Some(&ctx.status_tx)).warn(format!(
                "YARN client {} {}: {e:#} decision=fail_closed_llm_error",
                ctx.client_id,
                event.id()
            )),
        }
    }
}
