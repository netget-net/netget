//! ONVIF client: SOAP 1.2 requests to a device's Device, Media, Media2, PTZ, Events and Imaging
//! services, each signed with a WS-Security PasswordDigest UsernameToken whose Created follows
//! the device's clock.
//!
//! `connect` reads the device's clock (unauthenticated, as ONVIF allows), its capabilities
//! (authenticated: a device that refuses the credentials refuses the connection) and its services
//! (best effort: older devices have no GetServices), then the model asks it things. Three tasks:
//! the session (sends, one request at a time), the dispatcher (model turns), and the connect
//! handshake that starts them.
pub mod actions;
pub mod ops;

use crate::client::http_fetch::FetchClient;
use crate::client::llm_budget::call_llm_for_client;
use crate::llm::actions::client_trait::{Client, ClientActionResult};
use crate::logging::emit::Log;
use crate::protocol::{ConnectContext, Event};
use crate::server::onvif::wire::{self, Reply};
use crate::state::client_handles::{ClientCommand, ClientSendOutcome};
use crate::state::{AccessLogOwner, ClientStatus};
pub use actions::OnvifClientProtocol;
use anyhow::{bail, ensure, Context, Result};
use hyper::Method;
use ops::Service;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::Duration;
use tokio::sync::mpsc;

/// How many model turns may follow from one another before the chain stops.
pub const MAX_FOLLOWUP_DEPTH: u32 = 8;
const TIMEOUT: Duration = Duration::from_secs(30);
const TURN_QUEUE: usize = 64;

struct Conn {
    fetch: FetchClient,
    base: String,
    device_path: String,
    /// Each service's path on `base`, from GetCapabilities and GetServices.
    paths: HashMap<Service, String>,
    /// The path of the pull-point subscription onvif_create_pull_point made, if any.
    subscription: Mutex<Option<String>>,
    credentials: Option<(String, String)>,
    /// Device clock minus ours.
    offset: chrono::Duration,
}

impl Conn {
    fn security(&self) -> Option<String> {
        let (user, password) = self.credentials.as_ref()?;
        let nonce: [u8; 16] = rand::random();
        let created =
            (chrono::Utc::now() + self.offset).to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        Some(wire::security_header(user, password, &nonce, &created))
    }

    fn path(&self, service: Service) -> Result<String> {
        match service {
            Service::Device => Ok(self.device_path.clone()),
            Service::Subscription => self
                .subscription
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone()
                .context("no pull-point subscription: call onvif_create_pull_point first"),
            s => self.paths.get(&s).cloned().with_context(|| {
                format!(
                    "the device advertises no {} service",
                    actions::service_name(s)
                )
            }),
        }
    }

    /// One operation: the device's answer, or the fault it refused with.
    async fn call(&self, spec: &ops::Spec, args: &Value, authenticate: bool) -> Result<Reply> {
        let operation = spec.operation;
        let path = self.path(spec.service)?;
        let security = if authenticate { self.security() } else { None };
        let url = format!("{}{path}", self.base);
        let addressing = ops::action_uri(spec).map(|action| wire::addressing(&url, action));
        let envelope = wire::request_envelope_with(
            security.as_deref(),
            addressing.as_deref(),
            &ops::request_body(spec, args)?,
        );
        let mut request = self
            .fetch
            .request(Method::POST, &url)
            .header("Content-Type", "application/soap+xml; charset=utf-8")
            .body(envelope);
        if operation == "PullMessages" {
            // A long poll: the device may hold the request for the whole Timeout.
            request = request.timeout(Duration::from_secs(ops::pull_secs(args)?) + TIMEOUT);
        }
        let response = request
            .send()
            .await
            .with_context(|| format!("{operation}: the device could not be reached"))?;
        let status = response.status().as_u16();
        let bytes = response
            .bytes()
            .await
            .with_context(|| format!("{operation}: reading the reply"))?;
        let reply = wire::parse_reply(&bytes)
            .with_context(|| format!("{operation}: HTTP {status} with no readable SOAP reply"))?;
        if let Reply::Ok(_) = &reply {
            ensure!(
                (200..300).contains(&status),
                "{operation}: HTTP {status} without a fault"
            );
        }
        Ok(reply)
    }

    /// A device operation by name (the connect handshake's).
    async fn device_call(&self, operation: &str, authenticate: bool) -> Result<Reply> {
        let spec = ops::SPECS
            .iter()
            .find(|s| s.service == Service::Device && s.operation == operation)
            .context("no such device operation")?;
        self.call(spec, &json!({}), authenticate).await
    }
}

fn fault_text(f: &Value) -> String {
    format!(
        "{}/{}: {}",
        f["code"].as_str().unwrap_or_default(),
        f["subcodes"]
            .as_array()
            .map(|a| a
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join("/"))
            .unwrap_or_default(),
        f["reason"].as_str().unwrap_or_default()
    )
}

/// The service a GetCapabilities category or a GetServices namespace names.
fn service_of(name: &str) -> Option<Service> {
    Some(match name {
        "Media" | wire::TRT => Service::Media,
        wire::TR2 => Service::Media2,
        "PTZ" | wire::TPTZ => Service::Ptz,
        "Events" | wire::TEV => Service::Events,
        "Imaging" | wire::TIMG => Service::Imaging,
        _ => return None,
    })
}

pub async fn connect(ctx: ConnectContext) -> Result<SocketAddr> {
    let p = ctx.startup_params.as_ref();
    let opt = |k: &str| -> Result<Option<String>> {
        Ok(p.map(|p| p.get_optional_string(k)).transpose()?.flatten())
    };
    let credentials = match (opt("username")?, opt("password")?) {
        (Some(u), password) => Some((u, password.unwrap_or_default())),
        (None, None) => None,
        (None, Some(_)) => bail!("a password needs a username"),
    };
    let device_path = opt("device_path")?.unwrap_or_else(|| wire::DEVICE_PATH.to_string());
    ensure!(
        device_path.starts_with('/') && !device_path.chars().any(char::is_whitespace),
        "device_path is a path such as /onvif/device_service"
    );
    ensure!(
        !ctx.remote_addr.trim().is_empty() && !ctx.remote_addr.contains('/'),
        "remote_addr is the device's host:port"
    );
    let base = format!("http://{}", ctx.remote_addr.trim());
    crate::client::http_fetch::check_url(&base)?;
    #[cfg(not(target_arch = "wasm32"))]
    let fetch = FetchClient::from_reqwest(
        crate::llm::ollama_client::configured_for_endpoint(
            reqwest::Client::builder()
                .timeout(TIMEOUT)
                .redirect(reqwest::redirect::Policy::none()),
            &base,
        )
        .build()?,
    );
    #[cfg(target_arch = "wasm32")]
    let fetch = FetchClient::transport(TIMEOUT);
    let mut conn = Conn {
        fetch: fetch
            .with_max_body(wire::MAX_RESPONSE)
            .with_user_agent("netget-onvif"),
        base,
        device_path,
        paths: HashMap::new(),
        subscription: Mutex::new(None),
        credentials,
        offset: chrono::Duration::zero(),
    };

    // The clock first, unauthenticated: digests carry the device's time, not ours.
    let device_time = match conn.device_call("GetSystemDateAndTime", false).await? {
        Reply::Ok(el) => el.child("SystemDateAndTime").and_then(wire::utc_of),
        Reply::Fault(f) => {
            Log::new(Some(&ctx.status_tx)).warn(format!(
                "ONVIF client {}: the device would not tell its time ({}); signing with ours",
                ctx.client_id,
                fault_text(&f)
            ));
            None
        }
    };
    if let Some(t) = device_time {
        conn.offset = t - chrono::Utc::now();
    }
    let mut services = match conn.device_call("GetCapabilities", true).await? {
        Reply::Ok(el) => wire::result_json("GetCapabilities", &el)["services"].clone(),
        Reply::Fault(f) => bail!("the device refused GetCapabilities: {}", fault_text(&f)),
    };
    // Every XAddr is followed by path only, on the host the client was given.
    if let Some(map) = services.as_object() {
        for (name, xaddr) in map {
            if let (Some(s), Some(path)) =
                (service_of(name), xaddr.as_str().and_then(wire::xaddr_path))
            {
                conn.paths.insert(s, path);
            }
        }
    }
    // GetServices names Media2 (GetCapabilities predates it); older devices do not have it.
    match conn.device_call("GetServices", true).await {
        Ok(Reply::Ok(el)) => {
            for s in wire::result_json("GetServices", &el)["services"]
                .as_array()
                .into_iter()
                .flatten()
            {
                let (Some(ns), Some(xaddr)) = (s["namespace"].as_str(), s["xaddr"].as_str()) else {
                    continue;
                };
                if let (Some(service), Some(path)) = (service_of(ns), wire::xaddr_path(xaddr)) {
                    if service == Service::Media2 {
                        services["Media2"] = json!(xaddr);
                    }
                    conn.paths.entry(service).or_insert(path);
                }
            }
        }
        Ok(Reply::Fault(f)) => tracing::debug!(
            "ONVIF client {}: no GetServices ({})",
            ctx.client_id,
            fault_text(&f)
        ),
        Err(e) => tracing::debug!("ONVIF client {}: no GetServices ({e:#})", ctx.client_id),
    }

    ctx.state
        .update_client_status(ctx.client_id, ClientStatus::Connected)
        .await;
    Log::new(Some(&ctx.status_tx)).info(format!(
        "ONVIF client {} connected to {}",
        ctx.client_id, conn.base
    ));
    let external =
        crate::client::command_support::register_command_channel(&ctx.state, ctx.client_id).await;
    let (event_tx, event_rx) = mpsc::channel::<(Event, u32)>(TURN_QUEUE);
    let (internal_tx, internal) = mpsc::channel::<(Value, u32)>(64);
    let _ = event_tx.try_send((
        Event::new(
            &actions::CONNECTED_EVENT,
            json!({
                "device_time": device_time.map(|t| t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)),
                "clock_offset_secs": conn.offset.num_seconds(),
                "services": services,
                "authenticated": conn.credentials.is_some(),
            }),
        ),
        0,
    ));
    let dispatcher = tokio::spawn(run_turns(ctx.clone(), event_rx, internal_tx));
    let dispatcher_abort = dispatcher.abort_handle();
    ctx.state
        .register_client_task(ctx.client_id, dispatcher)
        .await;
    let session_ctx = ctx.clone();
    let task = tokio::spawn(async move {
        let result = session(&session_ctx, &conn, external, internal, event_tx).await;
        dispatcher_abort.abort();
        let status = match result {
            Ok(()) => ClientStatus::Disconnected,
            Err(e) => {
                Log::new(Some(&session_ctx.status_tx)).warn(format!("ONVIF client ended: {e:#}"));
                ClientStatus::Error(e.to_string())
            }
        };
        session_ctx
            .state
            .update_client_status(session_ctx.client_id, status)
            .await;
        session_ctx
            .state
            .remove_client_handle(session_ctx.client_id)
            .await;
        let _ = session_ctx.status_tx.send("__UPDATE_UI__".into());
    });
    ctx.state.register_client_task(ctx.client_id, task).await;
    Ok("0.0.0.0:0".parse()?)
}

async fn run_turns(
    ctx: ConnectContext,
    mut events: mpsc::Receiver<(Event, u32)>,
    internal: mpsc::Sender<(Value, u32)>,
) {
    let protocol = OnvifClientProtocol;
    while let Some((event, depth)) = events.recv().await {
        if depth >= MAX_FOLLOWUP_DEPTH {
            tracing::warn!(
                "ONVIF client {} not asking the model about {}: {depth} turns deep decision=followup_depth",
                ctx.client_id,
                event.id()
            );
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
                for action in result.actions {
                    if internal.send((action, depth + 1)).await.is_err() {
                        return;
                    }
                }
            }
            Err(e) => Log::new(Some(&ctx.status_tx)).warn(format!("ONVIF client handler: {e}")),
        }
    }
}

fn reply(command: Option<ClientCommand>, outcome: ClientSendOutcome) {
    if let Some(c) = command {
        crate::client::command_support::reply(c, Ok(outcome));
    }
}

async fn session(
    ctx: &ConnectContext,
    conn: &Conn,
    mut external: mpsc::Receiver<ClientCommand>,
    mut internal: mpsc::Receiver<(Value, u32)>,
    events: mpsc::Sender<(Event, u32)>,
) -> Result<()> {
    loop {
        let (action, depth, command) = tokio::select! {
            c = external.recv() => match c {
                Some(c) => (c.action.clone(), 0, Some(c)),
                None => return Ok(()),
            },
            a = internal.recv() => match a {
                Some((a, d)) => (a, d, None),
                None => return Ok(()),
            },
        };
        match OnvifClientProtocol.execute_action(action.clone()) {
            Ok(ClientActionResult::Disconnect) => {
                reply(command, ClientSendOutcome::Disconnected);
                return Ok(());
            }
            Ok(_) => {}
            Err(e) => {
                tracing::warn!("ONVIF client {} refused an action: {e}", ctx.client_id);
                reply(
                    command,
                    ClientSendOutcome::Rejected {
                        error: e.to_string(),
                    },
                );
                continue;
            }
        }
        let Some(spec) = actions::spec(&action) else {
            continue;
        };
        let operation = spec.operation;
        // GetSystemDateAndTime is the one operation ONVIF lets a client ask anonymously.
        let outcome = conn
            .call(spec, &action, operation != "GetSystemDateAndTime")
            .await;
        let mut data = json!({
            "operation": operation,
            "service": actions::service_name(spec.service),
            "request": ops::request_echo(&action),
        });
        match outcome {
            Ok(Reply::Ok(el)) => {
                data["ok"] = json!(true);
                let result = ops::result_json(spec, &el);
                match operation {
                    // The subscription is followed by path on the host the client was given.
                    "CreatePullPointSubscription" => {
                        *conn.subscription.lock().unwrap_or_else(|e| e.into_inner()) =
                            result["address"].as_str().and_then(wire::xaddr_path);
                    }
                    "Unsubscribe" => {
                        *conn.subscription.lock().unwrap_or_else(|e| e.into_inner()) = None;
                    }
                    _ => {}
                }
                data["result"] = result;
            }
            Ok(Reply::Fault(f)) => {
                data["ok"] = json!(false);
                data["fault"] = f;
            }
            Err(e) => {
                Log::new(Some(&ctx.status_tx)).warn(format!("ONVIF request failed: {e:#}"));
                data["ok"] = json!(false);
                data["error"] = json!(format!("{e:#}"));
            }
        }
        if command.is_some() {
            ctx.state
                .record_access_log(
                    AccessLogOwner::Client(ctx.client_id.as_u32()),
                    "ONVIF",
                    None,
                    "injected_action",
                    action.clone(),
                    vec![data.clone()],
                )
                .await;
        }
        reply(
            command,
            ClientSendOutcome::Executed {
                detail: data.to_string(),
            },
        );
        if events
            .try_send((Event::new(&actions::RESPONSE_EVENT, data), depth))
            .is_err()
        {
            tracing::warn!(
                "ONVIF client {} dropped an event: the model is {TURN_QUEUE} events behind decision=turn_queue_full",
                ctx.client_id
            );
        }
    }
}
