//! ONVIF client: SOAP 1.2 requests to a device's Device and Media services, each signed with a
//! WS-Security PasswordDigest UsernameToken whose Created follows the device's clock.
//!
//! `connect` reads the device's clock (unauthenticated, as ONVIF allows) and its capabilities
//! (authenticated: a device that refuses the credentials refuses the connection), then the
//! model asks it things. Three tasks: the session (sends, one request at a time), the
//! dispatcher (model turns), and the connect handshake that starts them.
pub mod actions;

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
use serde_json::{json, Value};
use std::net::SocketAddr;
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
    media_path: Option<String>,
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

    /// One operation: the device's answer, or the fault it refused with.
    async fn call(&self, operation: &str, args: &Value, authenticate: bool) -> Result<Reply> {
        let path = if actions::is_media(operation) {
            self.media_path
                .as_deref()
                .context("the device advertises no media service")?
        } else {
            &self.device_path
        };
        let security = if authenticate { self.security() } else { None };
        let envelope =
            wire::request_envelope(security.as_deref(), &wire::request_body(operation, args)?);
        let response = self
            .fetch
            .request(Method::POST, &format!("{}{path}", self.base))
            .header("Content-Type", "application/soap+xml; charset=utf-8")
            .body(envelope)
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
        media_path: None,
        credentials,
        offset: chrono::Duration::zero(),
    };

    // The clock first, unauthenticated: digests carry the device's time, not ours.
    let device_time = match conn.call("GetSystemDateAndTime", &json!({}), false).await? {
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
    let services = match conn.call("GetCapabilities", &json!({}), true).await? {
        Reply::Ok(el) => wire::result_json("GetCapabilities", &el)["services"].clone(),
        Reply::Fault(f) => bail!("the device refused GetCapabilities: {}", fault_text(&f)),
    };
    conn.media_path = services["Media"].as_str().and_then(wire::xaddr_path);

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
        let Some(operation) = actions::operation(&action) else {
            continue;
        };
        let mut request = json!({});
        for k in ["profile_token", "stream", "protocol"] {
            if let Some(v) = action.get(k).filter(|v| !v.is_null()) {
                request[k] = v.clone();
            }
        }
        // GetSystemDateAndTime is the one operation ONVIF lets a client ask anonymously.
        let outcome = conn
            .call(operation, &action, operation != "GetSystemDateAndTime")
            .await;
        let mut data = json!({"operation": operation, "request": request});
        match outcome {
            Ok(Reply::Ok(el)) => {
                data["ok"] = json!(true);
                data["result"] = wire::result_json(operation, &el);
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
