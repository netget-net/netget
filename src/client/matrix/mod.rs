//! Matrix client (client-server API v3). Logs in with a password, then one task follows
//! `/sync` and raises what other people did (messages, invites, membership), while the
//! session task performs the handler's actions, one HTTP/1.1 connection per request.
pub mod actions;
use crate::client::llm_budget::call_llm_for_client_batch;
use crate::llm::actions::client_trait::{Client, ClientActionResult};
use crate::logging::emit::Log;
use crate::protocol::{ConnectContext, Event};
use crate::state::client_handles::{ClientCommand, ClientSendOutcome};
use crate::state::{AccessLogOwner, ClientStatus};
pub use actions::MatrixClientProtocol;
use anyhow::{bail, ensure, Context, Result};
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::{
    client::conn::http1,
    header::{AUTHORIZATION, CONNECTION, CONTENT_LENGTH, CONTENT_TYPE, HOST},
    Request, Uri,
};
use hyper_util::rt::TokioIo;
use serde_json::{json, Value};
use std::time::Duration;
use tokio::sync::mpsc;

/// Largest answer read (a first `/sync` on a busy account is the big one).
pub const MAX_ANSWER_BYTES: usize = 4 * 1024 * 1024;
/// One ordinary request, connect to last byte.
pub const IO_TIMEOUT: Duration = Duration::from_secs(15);
/// How long each `/sync` asks the server to wait for something new.
pub const SYNC_WAIT: Duration = Duration::from_secs(25);
/// After a failed `/sync`, wait this long before the next.
pub const SYNC_BACKOFF: Duration = Duration::from_secs(2);
/// A handler chain (answer → event → answer …) stops after this many follow-ups.
pub const MAX_FOLLOWUP_DEPTH: usize = 8;

#[derive(Clone)]
struct Origin {
    authority: String,
    connect_addr: String,
}

fn origin(value: &str) -> Result<Origin> {
    let value = if value.starts_with("http://") {
        value.to_string()
    } else {
        format!("http://{value}")
    };
    let uri: Uri = value.parse().context("invalid homeserver address")?;
    ensure!(
        matches!(uri.path(), "" | "/") && uri.query().is_none(),
        "give the homeserver as host:port or http://host:port, without a path"
    );
    let authority = uri.authority().context("homeserver host required")?;
    Ok(Origin {
        authority: authority.as_str().to_string(),
        connect_addr: format!(
            "{}:{}",
            authority.host(),
            authority.port_u16().unwrap_or(8008)
        ),
    })
}

struct Answer {
    status: u16,
    body: Value,
}

/// One request under `/_matrix/client/v3/`.
async fn exchange(
    origin: &Origin,
    token: Option<&str>,
    method: &str,
    path: &str,
    body: Option<&Value>,
    deadline: Duration,
) -> Result<Answer> {
    tokio::time::timeout(deadline, async {
        let socket = tokio::net::TcpStream::connect(&origin.connect_addr).await?;
        let (mut sender, connection) = http1::Builder::new()
            .max_headers(64)
            .max_buf_size(64 * 1024)
            .handshake(TokioIo::new(socket))
            .await?;
        let payload = body.map(|b| b.to_string()).unwrap_or_default();
        let mut request = Request::builder()
            .method(method)
            .uri(format!("/_matrix/client/v3/{path}"))
            .header(HOST, &origin.authority)
            .header(CONNECTION, "close")
            .header(CONTENT_LENGTH, payload.len());
        if body.is_some() {
            request = request.header(CONTENT_TYPE, "application/json");
        }
        if let Some(t) = token {
            request = request.header(AUTHORIZATION, format!("Bearer {t}"));
        }
        let request = request.body(Full::new(Bytes::from(payload)))?;
        let exchange = async {
            let response = sender.send_request(request).await?;
            let (parts, body) = response.into_parts();
            let bytes = Limited::new(body, MAX_ANSWER_BYTES)
                .collect()
                .await
                .map_err(|_| anyhow::anyhow!("response body exceeds 4 MiB or is incomplete"))?
                .to_bytes();
            Ok::<_, anyhow::Error>(Answer {
                status: parts.status.as_u16(),
                body: serde_json::from_slice(&bytes).unwrap_or(Value::Null),
            })
        };
        tokio::pin!(connection);
        tokio::pin!(exchange);
        tokio::select! {
            r = &mut exchange => r,
            r = &mut connection => {
                r.context("HTTP connection failed")?;
                exchange.await
            }
        }
    })
    .await
    .context("Matrix request deadline exceeded")?
}

fn matrix_error(answer: &Answer) -> (String, String) {
    (
        answer.body["errcode"]
            .as_str()
            .unwrap_or("M_UNKNOWN")
            .to_string(),
        crate::utils::truncate::truncate_for_log(
            answer.body["error"].as_str().unwrap_or_default(),
            512,
        )
        .to_string(),
    )
}

struct Login {
    user_id: String,
    device_id: String,
    token: String,
}

async fn login(origin: &Origin, ctx: &ConnectContext) -> Result<Login> {
    let params = ctx
        .startup_params
        .as_ref()
        .context("startup_params user and password are required")?;
    let user = params.get_string("user")?;
    let password = params.get_string("password")?;
    let device = params.get_optional_string("device_id")?;
    let mut body = json!({"type": "m.login.password", "identifier": {"type": "m.id.user", "user": user},
                          "password": password, "initial_device_display_name": "NetGet"});
    if let Some(d) = device {
        body["device_id"] = json!(d);
    }
    let answer = exchange(origin, None, "POST", "login", Some(&body), IO_TIMEOUT).await?;
    if answer.status != 200 {
        let (code, error) = matrix_error(&answer);
        bail!("login refused: {} {code} {error}", answer.status);
    }
    let field = |k: &str| -> Result<String> {
        answer.body[k]
            .as_str()
            .map(str::to_string)
            .with_context(|| format!("login answer has no {k}"))
    };
    Ok(Login {
        user_id: field("user_id")?,
        device_id: field("device_id")?,
        token: field("access_token")?,
    })
}

/// The events one `/sync` answer raises for the handler; `first` skips the timeline (what
/// happened before login is not news).
fn sync_events(body: &Value, me: &str, first: bool) -> Vec<Event> {
    let mut out = Vec::new();
    if let Some(invites) = body["rooms"]["invite"].as_object() {
        for (room, data) in invites {
            let state = data["invite_state"]["events"]
                .as_array()
                .cloned()
                .unwrap_or_default();
            let sender = state
                .iter()
                .find(|e| e["type"] == "m.room.member" && e["state_key"] == me)
                .and_then(|e| e["sender"].as_str())
                .map(str::to_string);
            let name = state
                .iter()
                .find(|e| e["type"] == "m.room.name")
                .and_then(|e| e["content"]["name"].as_str())
                .map(str::to_string);
            out.push(Event::new(
                &actions::INVITE_EVENT,
                json!({"room_id": room, "sender": sender, "room_name": name}),
            ));
        }
    }
    if first {
        return out;
    }
    if let Some(joined) = body["rooms"]["join"].as_object() {
        for (room, data) in joined {
            for e in data["timeline"]["events"].as_array().into_iter().flatten() {
                let kind = e["type"].as_str().unwrap_or_default();
                if kind == "m.room.member" {
                    let user = e["state_key"].as_str().unwrap_or_default();
                    if user != me {
                        out.push(Event::new(
                            &actions::MEMBER_EVENT,
                            json!({"room_id": room, "user_id": user,
                                   "membership": e["content"]["membership"]}),
                        ));
                    }
                    continue;
                }
                if e.get("state_key").is_some() || e["sender"] == me {
                    continue;
                }
                out.push(Event::new(
                    &actions::MESSAGE_EVENT,
                    json!({"room_id": room, "sender": e["sender"], "event_type": kind,
                           "content": e["content"], "event_id": e["event_id"]}),
                ));
            }
        }
    }
    out
}

pub async fn connect(ctx: ConnectContext) -> Result<std::net::SocketAddr> {
    let origin = origin(&ctx.remote_addr)?;
    let login = login(&origin, &ctx).await?;
    let first = exchange(
        &origin,
        Some(&login.token),
        "GET",
        "sync?timeout=0",
        None,
        IO_TIMEOUT,
    )
    .await?;
    ensure!(
        first.status == 200,
        "first /sync failed: {} {:?}",
        first.status,
        matrix_error(&first)
    );
    let mut since = first.body["next_batch"]
        .as_str()
        .context("/sync answer has no next_batch")?
        .to_string();
    let joined: Vec<String> = first.body["rooms"]["join"]
        .as_object()
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default();
    Log::new(Some(&ctx.status_tx)).info(format!(
        "Matrix client logged in as {} ({}) at {}",
        login.user_id, login.device_id, origin.authority
    ));
    ctx.state
        .update_client_status(ctx.client_id, ClientStatus::Connected)
        .await;
    let external =
        crate::client::command_support::register_command_channel(&ctx.state, ctx.client_id).await;
    let (internal_tx, internal_rx) = mpsc::channel::<(Value, usize)>(32);
    let (event_tx, mut event_rx) = mpsc::channel::<(Event, usize)>(64);
    event_tx.try_send((
        Event::new(
            &actions::CONNECTED_EVENT,
            json!({"user_id": login.user_id, "device_id": login.device_id, "joined_rooms": joined}),
        ),
        0,
    ))?;
    for e in sync_events(&first.body, &login.user_id, true) {
        event_tx.try_send((e, 0))?;
    }

    let events_ctx = ctx.clone();
    let dispatcher = tokio::spawn(async move {
        // An event that would not have joined the previous batch starts the next one.
        let mut carried = None;
        while let Some(first) = match carried.take() {
            Some(item) => Some(item),
            None => event_rx.recv().await,
        } {
            // With batching on, everything raised while the model was answering is answered
            // in this one call; with it off, one event per call. Only events the model itself
            // will answer together are drained: one a script, static or manual rule answers
            // stays in the bounded queue, as it would without batching.
            let mut batch = vec![first];
            while batch.len() < crate::protocol::metadata::MAX_BATCH_EVENTS {
                let mut ids: Vec<&str> = batch.iter().map(|item| item.0.id()).collect();
                if ids.len() == 1
                    && !crate::llm::action_helper::client_batch_goes_to_the_model(
                        &events_ctx.state,
                        events_ctx.client_id,
                        &ids,
                    )
                    .await
                {
                    break;
                }
                let Ok(next) = event_rx.try_recv() else {
                    break;
                };
                ids.push(next.0.id());
                if !crate::llm::action_helper::client_batch_goes_to_the_model(
                    &events_ctx.state,
                    events_ctx.client_id,
                    &ids,
                )
                .await
                {
                    carried = Some(next);
                    break;
                }
                drop(ids);
                batch.push(next);
            }
            // A follow-up is as deep as the deepest event it answers.
            let depth = batch.iter().map(|(_, d)| *d).max().unwrap_or(0);
            let events: Vec<Event> = batch.into_iter().map(|(e, _)| e).collect();
            for event in &events {
                events_ctx
                    .state
                    .record_access_log(
                        AccessLogOwner::Client(events_ctx.client_id.as_u32()),
                        "Matrix",
                        None,
                        event.id(),
                        event.data.clone(),
                        vec![],
                    )
                    .await;
            }
            let instruction = events_ctx
                .state
                .get_instruction_for_client(events_ctx.client_id)
                .await
                .unwrap_or_default();
            let memory = events_ctx
                .state
                .get_memory_for_client(events_ctx.client_id)
                .await
                .unwrap_or_default();
            match call_llm_for_client_batch(
                &events_ctx.llm_client,
                &events_ctx.state,
                events_ctx.client_id.to_string(),
                &instruction,
                &memory,
                &events,
                &MatrixClientProtocol,
                &events_ctx.status_tx,
            )
            .await
            {
                Ok(result) => {
                    if let Some(memory) = result.memory_updates {
                        events_ctx
                            .state
                            .set_memory_for_client(events_ctx.client_id, memory)
                            .await;
                    }
                    for action in result.actions {
                        if internal_tx.send((action, depth + 1)).await.is_err() {
                            return;
                        }
                    }
                }
                Err(e) => Log::new(Some(&events_ctx.status_tx))
                    .warn(format!("Matrix client handler: {e}")),
            }
        }
    });
    let dispatcher_abort = dispatcher.abort_handle();
    ctx.state
        .register_client_task(ctx.client_id, dispatcher)
        .await;

    let sync_ctx = ctx.clone();
    let sync_origin = origin.clone();
    let sync_token = login.token.clone();
    let me = login.user_id.clone();
    let sync_events_tx = event_tx.clone();
    let syncer = tokio::spawn(async move {
        let log = Log::new(Some(&sync_ctx.status_tx));
        loop {
            let path = format!(
                "sync?timeout={}&since={}",
                SYNC_WAIT.as_millis(),
                urlencoding::encode(&since)
            );
            match exchange(
                &sync_origin,
                Some(&sync_token),
                "GET",
                &path,
                None,
                SYNC_WAIT + IO_TIMEOUT,
            )
            .await
            {
                Ok(a) if a.status == 200 => {
                    if let Some(next) = a.body["next_batch"].as_str() {
                        since = next.to_string();
                    }
                    for e in sync_events(&a.body, &me, false) {
                        if sync_events_tx.send((e, 0)).await.is_err() {
                            return;
                        }
                    }
                }
                Ok(a) => {
                    let (code, error) = matrix_error(&a);
                    log.warn(format!("Matrix /sync answered {} {code} {error}", a.status));
                    if a.status == 401 {
                        return;
                    }
                    tokio::time::sleep(SYNC_BACKOFF).await;
                }
                Err(e) => {
                    log.warn(format!("Matrix /sync failed: {e:#}"));
                    tokio::time::sleep(SYNC_BACKOFF).await;
                }
            }
        }
    });
    let syncer_abort = syncer.abort_handle();
    ctx.state.register_client_task(ctx.client_id, syncer).await;

    let session_ctx = ctx.clone();
    let task = tokio::spawn(async move {
        let result = session(
            &session_ctx,
            &origin,
            &login,
            external,
            internal_rx,
            event_tx,
        )
        .await;
        syncer_abort.abort();
        dispatcher_abort.abort();
        let _ = exchange(
            &origin,
            Some(&login.token),
            "POST",
            "logout",
            Some(&json!({})),
            IO_TIMEOUT,
        )
        .await;
        let status = match result {
            Ok(()) => ClientStatus::Disconnected,
            Err(e) => {
                Log::new(Some(&session_ctx.status_tx)).warn(format!("Matrix client ended: {e}"));
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

async fn session(
    ctx: &ConnectContext,
    origin: &Origin,
    login: &Login,
    mut external: mpsc::Receiver<ClientCommand>,
    mut internal: mpsc::Receiver<(Value, usize)>,
    events: mpsc::Sender<(Event, usize)>,
) -> Result<()> {
    let log = Log::new(Some(&ctx.status_tx));
    let txn_prefix = format!("ng{}", crate::server::matrix::hub::random_id(8));
    let mut txn = 0u64;
    loop {
        let (action, depth, mut injected) = tokio::select! {
            command = external.recv() => match command {
                Some(c) => (c.action.clone(), 0, Some(c)),
                None => return Ok(()),
            },
            action = internal.recv() => match action {
                Some((a, depth)) => (a, depth, None),
                None => return Ok(()),
            },
        };
        let reply = |injected: &mut Option<ClientCommand>, outcome: ClientSendOutcome| {
            if let Some(command) = injected.take() {
                crate::client::command_support::reply(command, Ok(outcome));
            }
        };
        match MatrixClientProtocol.execute_action(action.clone()) {
            Ok(ClientActionResult::Disconnect) => {
                reply(&mut injected, ClientSendOutcome::Disconnected);
                return Ok(());
            }
            Ok(_) => {}
            Err(e) => {
                log.warn(format!("Matrix client action refused: {e:#}"));
                reply(
                    &mut injected,
                    ClientSendOutcome::Rejected {
                        error: e.to_string(),
                    },
                );
                continue;
            }
        }
        if depth > MAX_FOLLOWUP_DEPTH {
            log.warn(format!(
                "Matrix client: handler chain stopped after {MAX_FOLLOWUP_DEPTH} follow-ups"
            ));
            continue;
        }
        if injected.is_some() {
            ctx.state
                .record_access_log(
                    AccessLogOwner::Client(ctx.client_id.as_u32()),
                    "Matrix",
                    None,
                    "injected_action",
                    action.clone(),
                    vec![],
                )
                .await;
        }
        txn += 1;
        let (method, path, body) = actions::request(&action, &format!("{txn_prefix}.{txn}"))?;
        let operation = action["type"].as_str().unwrap_or_default().to_string();
        match exchange(
            origin,
            Some(&login.token),
            method,
            &path,
            body.as_ref(),
            IO_TIMEOUT,
        )
        .await
        {
            Ok(answer) => {
                let ok = answer.status == 200;
                let mut data = json!({"operation": operation, "status": answer.status});
                if ok {
                    data["result"] = match operation.as_str() {
                        "matrix_messages" => json!({"events": answer.body["chunk"]}),
                        _ => answer.body.clone(),
                    };
                } else {
                    let (code, error) = matrix_error(&answer);
                    data["result"] = json!({});
                    data["errcode"] = json!(code);
                    data["error"] = json!(error);
                }
                reply(
                    &mut injected,
                    ClientSendOutcome::Executed {
                        detail: data.to_string(),
                    },
                );
                // A successful send needs no answer from the handler; everything else does.
                if ok && operation == "matrix_send" {
                    ctx.state
                        .record_access_log(
                            AccessLogOwner::Client(ctx.client_id.as_u32()),
                            "Matrix",
                            None,
                            "matrix_sent",
                            data,
                            vec![],
                        )
                        .await;
                    continue;
                }
                events
                    .try_send((Event::new(&actions::RESPONSE_EVENT, data), depth))
                    .context("Matrix event queue full; consumer stalled")?;
            }
            Err(e) => {
                log.warn(format!("Matrix request failed: {e:#}"));
                reply(
                    &mut injected,
                    ClientSendOutcome::Rejected {
                        error: format!("{e:#}"),
                    },
                );
            }
        }
    }
}
