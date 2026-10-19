//! WAMP v2 client, JSON over WebSocket, in all four roles.
pub mod actions;
use crate::client::llm_budget::call_llm_for_client_batch;
use crate::llm::actions::client_trait::{Client, ClientActionResult};
use crate::logging::emit::Log;
use crate::protocol::{ConnectContext, Event};
use crate::server::wamp::uri::*;
use crate::state::client_handles::{ClientCommand, ClientSendOutcome};
use crate::state::{AccessLogOwner, ClientStatus};
pub use actions::WampClientProtocol;
use anyhow::{bail, ensure, Context, Result};
use futures::{SinkExt, StreamExt};
use serde_json::{json, Value};
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::{
    client::IntoClientRequest, http::HeaderValue, Message as WsMessage,
};

pub const DEFAULT_REALM: &str = "realm1";
pub const DEFAULT_PATH: &str = "/";
const TIMEOUT: Duration = Duration::from_secs(15);
const MAX_PENDING: usize = 1024;

type Ws =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

#[derive(Default)]
struct Session {
    next_request: u64,
    /// request ID → (operation, target)
    pending: HashMap<u64, (&'static str, String)>,
    /// topic → subscription ID, and back
    subscriptions: HashMap<String, u64>,
    topics: HashMap<u64, String>,
    /// procedure → registration ID, and back
    registrations: HashMap<String, u64>,
    procedures: HashMap<u64, String>,
    /// unanswered invocations, oldest first
    invocations: VecDeque<u64>,
}

impl Session {
    fn request(&mut self, op: &'static str, target: &str) -> Result<u64> {
        ensure!(
            self.pending.len() < MAX_PENDING,
            "too many requests awaiting the router"
        );
        self.next_request += 1;
        self.pending
            .insert(self.next_request, (op, target.to_owned()));
        Ok(self.next_request)
    }
}

async fn send(ws: &mut Ws, msg: Value) -> Result<usize> {
    let text = msg.to_string();
    let n = text.len();
    ws.send(WsMessage::Text(text)).await?;
    Ok(n)
}

async fn recv(ws: &mut Ws) -> Result<Option<Vec<Value>>> {
    loop {
        match ws.next().await {
            None => return Ok(None),
            Some(Err(e)) => bail!("WebSocket: {e}"),
            Some(Ok(WsMessage::Text(t))) => {
                let v: Value = serde_json::from_str(&t).context("the router sent invalid JSON")?;
                ensure!(
                    crate::utils::json_budget::within_budget(
                        &v,
                        crate::server::wamp::MAX_MESSAGE,
                        200_000,
                        64
                    ),
                    "the router's message exceeds the client's bounds"
                );
                let a = v
                    .as_array()
                    .filter(|a| !a.is_empty() && a[0].is_u64())
                    .cloned()
                    .context("the router sent something that is not a WAMP message")?;
                return Ok(Some(a));
            }
            Some(Ok(WsMessage::Close(_))) => return Ok(None),
            Some(Ok(WsMessage::Binary(_))) => {
                bail!("the router sent a binary frame on wamp.2.json")
            }
            Some(Ok(_)) => continue,
        }
    }
}

pub async fn connect(ctx: ConnectContext) -> Result<SocketAddr> {
    let p = ctx.startup_params.as_ref();
    let s = |k: &str| -> Result<Option<String>> {
        Ok(p.map(|p| p.get_optional_string(k)).transpose()?.flatten())
    };
    let realm = s("realm")?.unwrap_or_else(|| DEFAULT_REALM.to_owned());
    ensure!(uri_ok(&realm, false), "realm is a URI");
    let path = s("path")?.unwrap_or_else(|| DEFAULT_PATH.to_owned());
    ensure!(
        path.starts_with('/')
            && path.len() <= 256
            && !path.chars().any(|c| c.is_control() || c == ' '),
        "path is an absolute path"
    );
    let authid = s("authid")?;
    if let Some(a) = &authid {
        ensure!(
            !a.is_empty() && a.len() <= 128 && !crate::utils::sanitize::has_controls(&a),
            "authid is 1 to 128 printable characters"
        );
    }
    let mut request = format!("ws://{}{path}", ctx.remote_addr).into_client_request()?;
    request.headers_mut().insert(
        "sec-websocket-protocol",
        HeaderValue::from_static(SUBPROTOCOL),
    );
    let (mut ws, response) =
        tokio::time::timeout(TIMEOUT, tokio_tungstenite::connect_async(request))
            .await
            .context("WebSocket connect timed out")??;
    let negotiated = response
        .headers()
        .get("sec-websocket-protocol")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    ensure!(
        negotiated == SUBPROTOCOL,
        "the router did not agree to {SUBPROTOCOL} (it answered {negotiated:?})"
    );
    let local = match ws.get_ref() {
        tokio_tungstenite::MaybeTlsStream::Plain(t) => t.local_addr()?,
        _ => "0.0.0.0:0".parse()?,
    };
    let mut details = json!({"roles": {"caller": {"features": {}}, "callee": {"features": {}}, "publisher": {"features": {}}, "subscriber": {"features": {}}}, "authmethods": ["anonymous"]});
    if let Some(a) = &authid {
        details["authid"] = json!(a);
    }
    send(&mut ws, json!([HELLO, realm, details])).await?;
    let first = tokio::time::timeout(TIMEOUT, recv(&mut ws))
        .await
        .context("no WELCOME in time")??
        .context("the router closed before WELCOME")?;
    let session_id = match first[0].as_u64() {
        Some(WELCOME) => first
            .get(1)
            .and_then(id_of)
            .context("WELCOME without a session ID")?,
        Some(ABORT) => bail!(
            "the router refused the session: {} ({})",
            first.get(2).and_then(Value::as_str).unwrap_or("no reason"),
            first
                .get(1)
                .and_then(|d| d["message"].as_str())
                .unwrap_or("")
        ),
        _ => bail!("the router answered HELLO with message type {}", first[0]),
    };
    let roles: Vec<String> = first
        .get(2)
        .and_then(|d| d["roles"].as_object())
        .map(|r| r.keys().cloned().collect())
        .unwrap_or_default();
    ctx.state
        .update_client_status(ctx.client_id, ClientStatus::Connected)
        .await;
    let external =
        crate::client::command_support::register_command_channel(&ctx.state, ctx.client_id).await;
    let (internal_tx, internal_rx) = mpsc::channel::<Value>(64);
    let (event_tx, mut event_rx) = mpsc::channel::<Event>(256);
    event_tx.try_send(Event::new(
        &actions::WELCOME_EVENT,
        json!({"session": session_id, "realm": realm, "roles": roles}),
    ))?;
    let events_ctx = ctx.clone();
    let dispatcher = tokio::spawn(async move {
        let protocol = WampClientProtocol;
        while let Some(event) = event_rx.recv().await {
            // This event, plus - with batching on - every event already waiting: what the
            // router delivered while the model answered the previous one.
            let mut events = vec![event];
            if events_ctx
                .state
                .client_conversation_settings(events_ctx.client_id)
                .await
                .is_some_and(|(_, batching)| batching)
            {
                while events.len() < crate::protocol::metadata::MAX_BATCH_EVENTS {
                    match event_rx.try_recv() {
                        Ok(more) => events.push(more),
                        Err(_) => break,
                    }
                }
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
            let mut produced = match call_llm_for_client_batch(
                &events_ctx.llm_client,
                &events_ctx.state,
                events_ctx.client_id.to_string(),
                &instruction,
                &memory,
                &events,
                &protocol,
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
                    result.actions
                }
                Err(e) => {
                    Log::new(Some(&events_ctx.status_tx)).warn(format!("WAMP client handler: {e}"));
                    vec![]
                }
            };
            // An invocation the handler did not answer is answered for it: a caller must never
            // hang. In a batch an answer naming its invocation answers that one, and each
            // answer naming none answers the oldest still unanswered, as `perform` does.
            let answers =
                |a: &&Value| matches!(a["type"].as_str(), Some("wamp_yield" | "wamp_error"));
            let mut unnamed = produced
                .iter()
                .filter(answers)
                .filter(|a| a["invocation"].is_null())
                .count();
            let mut unanswered = Vec::new();
            for event in events
                .iter()
                .filter(|e| e.event_type.id == "wamp_invocation")
            {
                let inv = event.data["invocation"].clone();
                if produced
                    .iter()
                    .filter(answers)
                    .any(|a| a["invocation"] == inv)
                {
                    continue;
                }
                if unnamed > 0 {
                    unnamed -= 1;
                    continue;
                }
                unanswered.push(inv);
            }
            for inv in unanswered {
                produced.push(json!({"type": "wamp_error", "invocation": inv, "error": "wamp.error.unavailable", "args": ["the callee could not answer"]}));
            }
            for action in produced {
                if internal_tx.send(action).await.is_err() {
                    return;
                }
            }
        }
    });
    ctx.state
        .register_client_task(ctx.client_id, dispatcher)
        .await;
    let session_ctx = ctx.clone();
    let task = tokio::spawn(async move {
        let reason = match run(&session_ctx, &mut ws, external, internal_rx, &event_tx).await {
            Ok(r) => r,
            Err(e) => format!("{e:#}"),
        };
        let _ = event_tx
            .send(Event::new(&actions::LEFT_EVENT, json!({"reason": reason})))
            .await;
        let _ = ws.close(None).await;
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
    Ok(local)
}

enum Wake {
    Message(Option<Vec<Value>>),
    Action(Value, Option<ClientCommand>),
    Idle,
}

async fn run(
    ctx: &ConnectContext,
    ws: &mut Ws,
    mut external: mpsc::Receiver<ClientCommand>,
    mut internal: mpsc::Receiver<Value>,
    events: &mpsc::Sender<Event>,
) -> Result<String> {
    let mut s = Session::default();
    loop {
        let wake = tokio::select! {
            m = recv(ws) => Wake::Message(m?),
            c = external.recv() => match c { Some(c) => Wake::Action(c.action.clone(), Some(c)), None => Wake::Idle },
            a = internal.recv() => match a { Some(a) => Wake::Action(a, None), None => Wake::Idle },
        };
        match wake {
            Wake::Idle => {}
            Wake::Message(None) => return Ok("the router closed the connection".into()),
            Wake::Message(Some(m)) => {
                if let Some(reason) = on_message(&mut s, &m, events).await? {
                    if m[0] == GOODBYE {
                        let _ = send(ws, json!([GOODBYE, {}, "wamp.close.goodbye_and_out"])).await;
                    }
                    return Ok(reason);
                }
            }
            Wake::Action(action, command) => {
                let outcome = match WampClientProtocol.execute_action(action.clone()) {
                    Err(e) => Ok(ClientSendOutcome::Rejected {
                        error: e.to_string(),
                    }),
                    Ok(ClientActionResult::Disconnect) => {
                        if let Some(c) = command {
                            crate::client::command_support::reply(
                                c,
                                Ok(ClientSendOutcome::Disconnected),
                            );
                        }
                        return Ok("disconnected".into());
                    }
                    Ok(_) => perform(&mut s, ws, &action).await,
                };
                let goodbye = action["type"] == "wamp_goodbye"
                    && matches!(outcome, Ok(ClientSendOutcome::Sent { .. }));
                if let Some(c) = command {
                    let logged = outcome
                        .as_ref()
                        .map(|o| serde_json::to_value(o).unwrap_or(Value::Null))
                        .unwrap_or_else(|e| json!({"error": e.to_string()}));
                    ctx.state
                        .record_access_log(
                            AccessLogOwner::Client(ctx.client_id.as_u32()),
                            "WAMP",
                            None,
                            "injected_action",
                            json!({"type": action["type"]}),
                            vec![logged],
                        )
                        .await;
                    crate::client::command_support::reply(c, outcome);
                } else if let Err(e) = outcome {
                    Log::new(Some(&ctx.status_tx)).warn(format!("WAMP action failed: {e:#}"));
                }
                if goodbye {
                    // The router answers GOODBYE; wait briefly for it.
                    let _ = tokio::time::timeout(Duration::from_secs(5), recv(ws)).await;
                    return Ok("wamp.close.goodbye_and_out".into());
                }
            }
        }
    }
}

fn payload_of(m: &[Value], i: usize) -> (Value, Value) {
    (
        m.get(i)
            .cloned()
            .filter(Value::is_array)
            .unwrap_or_else(|| json!([])),
        m.get(i + 1)
            .cloned()
            .filter(Value::is_object)
            .unwrap_or_else(|| json!({})),
    )
}

/// Handle a router message; Some(reason) when the session ended.
async fn on_message(
    s: &mut Session,
    m: &[Value],
    events: &mpsc::Sender<Event>,
) -> Result<Option<String>> {
    let kind = m[0].as_u64().unwrap_or(0);
    let emit = |e: Event| async move {
        events
            .send(e)
            .await
            .map_err(|_| anyhow::anyhow!("event consumer stopped"))
    };
    match kind {
        GOODBYE | ABORT => {
            return Ok(Some(
                m.get(2)
                    .and_then(Value::as_str)
                    .unwrap_or("closed")
                    .to_owned(),
            ))
        }
        EVENT => {
            let sub = m.get(1).and_then(id_of).unwrap_or(0);
            let topic = m
                .get(3)
                .and_then(|d| d["topic"].as_str())
                .map(str::to_owned)
                .or_else(|| s.topics.get(&sub).cloned())
                .unwrap_or_default();
            let (args, kwargs) = payload_of(m, 4);
            emit(Event::new(
                &actions::EVENT_EVENT,
                json!({"topic": topic, "args": args, "kwargs": kwargs, "publication": m.get(2)}),
            ))
            .await?;
        }
        INVOCATION => {
            let inv = m
                .get(1)
                .and_then(id_of)
                .context("INVOCATION without a request ID")?;
            let reg = m.get(2).and_then(id_of).unwrap_or(0);
            let (args, kwargs) = payload_of(m, 4);
            s.invocations.push_back(inv);
            emit(Event::new(&actions::INVOCATION_EVENT, json!({"invocation": inv, "procedure": s.procedures.get(&reg), "args": args, "kwargs": kwargs}))).await?;
        }
        SUBSCRIBED | UNSUBSCRIBED | PUBLISHED | REGISTERED | UNREGISTERED | RESULT | ERROR => {
            let req_index = if kind == ERROR { 2 } else { 1 };
            let Some((op, target)) = m
                .get(req_index)
                .and_then(id_of)
                .and_then(|r| s.pending.remove(&r))
            else {
                return Ok(None);
            };
            let mut data = json!({"operation": op, "target": target, "ok": kind != ERROR});
            match kind {
                SUBSCRIBED => {
                    let id = m.get(2).and_then(id_of).unwrap_or(0);
                    s.subscriptions.insert(target.clone(), id);
                    s.topics.insert(id, target);
                }
                UNSUBSCRIBED => {
                    if let Some(id) = s.subscriptions.remove(&target) {
                        s.topics.remove(&id);
                    }
                }
                REGISTERED => {
                    let id = m.get(2).and_then(id_of).unwrap_or(0);
                    s.registrations.insert(target.clone(), id);
                    s.procedures.insert(id, target);
                }
                UNREGISTERED => {
                    if let Some(id) = s.registrations.remove(&target) {
                        s.procedures.remove(&id);
                    }
                }
                RESULT => {
                    let (args, kwargs) = payload_of(m, 3);
                    data["args"] = args;
                    data["kwargs"] = kwargs;
                }
                ERROR => {
                    data["error"] = m.get(4).cloned().unwrap_or(Value::Null);
                    let (args, kwargs) = payload_of(m, 5);
                    data["args"] = args;
                    data["kwargs"] = kwargs;
                }
                _ => {}
            }
            emit(Event::new(&actions::REPLY_EVENT, data)).await?;
        }
        _ => {}
    }
    Ok(None)
}

async fn perform(s: &mut Session, ws: &mut Ws, a: &Value) -> Result<ClientSendOutcome> {
    let text = |k: &str| a[k].as_str().unwrap_or_default().to_owned();
    let msg = match a["type"].as_str().unwrap_or_default() {
        "wamp_subscribe" => {
            let topic = text("topic");
            let req = s.request("subscribe", &topic)?;
            let mut opts = json!({});
            if let Some(m) = a["match"].as_str().filter(|m| *m != "exact") {
                opts["match"] = json!(m);
            }
            json!([SUBSCRIBE, req, opts, topic])
        }
        "wamp_unsubscribe" => {
            let topic = text("topic");
            let Some(id) = s.subscriptions.get(&topic).copied() else {
                return Ok(ClientSendOutcome::Rejected {
                    error: format!("not subscribed to {topic}"),
                });
            };
            let req = s.request("unsubscribe", &topic)?;
            json!([UNSUBSCRIBE, req, id])
        }
        "wamp_publish" => {
            let topic = text("topic");
            let ack = a["acknowledge"].as_bool().unwrap_or(true);
            let req = if ack {
                s.request("publish", &topic)?
            } else {
                random_id()
            };
            let opts = json!({"acknowledge": ack, "exclude_me": a["exclude_me"].as_bool().unwrap_or(true)});
            with_payload(
                vec![json!(PUBLISH), json!(req), opts, json!(topic)],
                a.get("args"),
                a.get("kwargs"),
            )
        }
        "wamp_call" => {
            let procedure = text("procedure");
            let req = s.request("call", &procedure)?;
            with_payload(
                vec![json!(CALL), json!(req), json!({}), json!(procedure)],
                a.get("args"),
                a.get("kwargs"),
            )
        }
        "wamp_register" => {
            let procedure = text("procedure");
            let req = s.request("register", &procedure)?;
            json!([REGISTER, req, {}, procedure])
        }
        "wamp_unregister" => {
            let procedure = text("procedure");
            let Some(id) = s.registrations.get(&procedure).copied() else {
                return Ok(ClientSendOutcome::Rejected {
                    error: format!("{procedure} is not registered by this session"),
                });
            };
            let req = s.request("unregister", &procedure)?;
            json!([UNREGISTER, req, id])
        }
        kind @ ("wamp_yield" | "wamp_error") => {
            let inv = match a["invocation"].as_u64() {
                Some(i) => {
                    let Some(pos) = s.invocations.iter().position(|x| *x == i) else {
                        return Ok(ClientSendOutcome::Rejected {
                            error: format!("no unanswered invocation {i}"),
                        });
                    };
                    s.invocations.remove(pos);
                    i
                }
                None => match s.invocations.pop_front() {
                    Some(i) => i,
                    None => {
                        return Ok(ClientSendOutcome::Rejected {
                            error: "no invocation is waiting for an answer".into(),
                        })
                    }
                },
            };
            if kind == "wamp_yield" {
                with_payload(
                    vec![json!(YIELD), json!(inv), json!({})],
                    a.get("args"),
                    a.get("kwargs"),
                )
            } else {
                with_payload(
                    vec![
                        json!(ERROR),
                        json!(INVOCATION),
                        json!(inv),
                        json!({}),
                        json!(text("error")),
                    ],
                    a.get("args"),
                    a.get("kwargs"),
                )
            }
        }
        _ => json!([GOODBYE, {}, "wamp.close.close_realm"]),
    };
    let n = send(ws, msg).await?;
    Ok(ClientSendOutcome::Sent { bytes_sent: n })
}
