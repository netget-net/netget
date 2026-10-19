//! Socket.IO v5 client over Engine.IO v4 (direct WebSocket or HTTP long-polling).
pub mod actions;
use crate::client::http_fetch::FetchClient;
use crate::client::llm_budget::call_llm_for_client_batch;
use crate::llm::actions::client_trait::{Client, ClientActionResult};
use crate::logging::emit::Log;
use crate::protocol::{ConnectContext, Event};
use crate::server::socketio::packet::{self, Eio, Kind, Sio};
use crate::state::client_handles::{ClientCommand, ClientSendOutcome};
use crate::state::{AccessLogOwner, ClientStatus};
pub use actions::SocketIoClientProtocol;
use anyhow::{bail, ensure, Context, Result};
use futures::{SinkExt, StreamExt};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, Mutex};
use tokio_tungstenite::tungstenite::Message;

pub const DEFAULT_TRANSPORT: &str = "websocket";
const TIMEOUT: Duration = Duration::from_secs(30);

type WsStream =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

enum Transport {
    Ws(Mutex<futures::stream::SplitSink<WsStream, Message>>),
    Polling { fetch: FetchClient, url: String },
}

impl Transport {
    fn name(&self) -> &'static str {
        match self {
            Transport::Ws(_) => "websocket",
            Transport::Polling { .. } => "polling",
        }
    }

    async fn send(&self, packets: Vec<String>) -> Result<()> {
        match self {
            Transport::Ws(sink) => {
                let mut s = sink.lock().await;
                for p in packets {
                    s.send(Message::Text(p)).await?;
                }
            }
            Transport::Polling { fetch, url } => {
                let r = fetch
                    .post(url)
                    .header("Content-Type", "text/plain;charset=UTF-8")
                    .body(packet::join_payload(&packets))
                    .send()
                    .await?;
                ensure!(
                    r.status().as_u16() == 200,
                    "polling POST answered HTTP {}",
                    r.status()
                );
            }
        }
        Ok(())
    }
}

fn open_info(open: &str) -> Result<String> {
    let v: Value = serde_json::from_str(open).context("open packet is not JSON")?;
    let sid = v["sid"]
        .as_str()
        .filter(|s| !s.is_empty() && s.len() <= 128)
        .context("open packet has no sid")?;
    Ok(sid.to_owned())
}

pub async fn connect(ctx: ConnectContext) -> Result<SocketAddr> {
    let p = ctx.startup_params.as_ref();
    let path = p
        .map(|p| p.get_optional_string("path"))
        .transpose()?
        .flatten()
        .unwrap_or_else(|| crate::server::socketio::DEFAULT_PATH.to_owned());
    ensure!(
        path.starts_with('/') && path.len() <= 128 && !path.contains(['?', '#', ' ']),
        "path must be an absolute path"
    );
    let path = format!("{}/", path.trim_end_matches('/'));
    let transport = p
        .map(|p| p.get_optional_string("transport"))
        .transpose()?
        .flatten()
        .unwrap_or_else(|| DEFAULT_TRANSPORT.to_owned());
    ensure!(
        transport == "websocket" || transport == "polling",
        "transport must be websocket or polling"
    );
    let namespaces: Vec<String> = match p
        .map(|p| p.get_optional_array("namespaces"))
        .transpose()?
        .flatten()
    {
        None => vec!["/".into()],
        Some(list) => list
            .iter()
            .map(|n| {
                n.as_str()
                    .filter(|n| packet::namespace_ok(n))
                    .map(str::to_owned)
                    .ok_or_else(|| anyhow::anyhow!("namespaces look like /name"))
            })
            .collect::<Result<_>>()?,
    };
    let auth = p
        .map(|p| p.get_optional_object("auth"))
        .transpose()?
        .flatten()
        .map(|m| Value::Object(m.clone()));
    let (incoming_tx, incoming_rx) = mpsc::channel::<Result<Eio>>(256);
    let local: SocketAddr = "0.0.0.0:0".parse()?;
    let transport: Arc<Transport> = if transport == "websocket" {
        let url = format!("ws://{}{path}?EIO=4&transport=websocket", ctx.remote_addr);
        let mut cfg = tokio_tungstenite::tungstenite::protocol::WebSocketConfig::default();
        cfg.max_message_size = Some(packet::MAX_PAYLOAD);
        let (ws, _) = tokio::time::timeout(
            TIMEOUT,
            tokio_tungstenite::connect_async_with_config(url.as_str(), Some(cfg), false),
        )
        .await
        .context("WebSocket connect timed out")??;
        let (sink, mut stream) = ws.split();
        let first = tokio::time::timeout(TIMEOUT, stream.next())
            .await
            .context("no Engine.IO open packet")?;
        let Some(Ok(Message::Text(t))) = first else {
            bail!("the server did not open an Engine.IO session")
        };
        let Eio::Open(info) = Eio::decode(&t)? else {
            bail!("expected the Engine.IO open packet")
        };
        open_info(&info)?;
        let reader = tokio::spawn(async move {
            while let Some(m) = stream.next().await {
                let item = match m {
                    Ok(Message::Text(t)) => Eio::decode(&t),
                    Ok(Message::Close(_)) | Err(_) => break,
                    Ok(_) => continue,
                };
                if incoming_tx.send(item).await.is_err() {
                    break;
                }
            }
        });
        ctx.state.register_client_task(ctx.client_id, reader).await;
        Arc::new(Transport::Ws(Mutex::new(sink)))
    } else {
        let base = format!("http://{}{path}?EIO=4&transport=polling", ctx.remote_addr);
        crate::client::http_fetch::check_url(&base)?;
        #[cfg(not(target_arch = "wasm32"))]
        let fetch = FetchClient::from_reqwest(
            crate::llm::ollama_client::configured_for_endpoint(
                reqwest::Client::builder().timeout(Duration::from_secs(120)),
                &base,
            )
            .build()?,
        );
        #[cfg(target_arch = "wasm32")]
        let fetch = FetchClient::transport(Duration::from_secs(120));
        let fetch = fetch
            .with_max_body(packet::MAX_PAYLOAD)
            .with_user_agent("netget-socketio");
        let r = fetch
            .get(&base)
            .send()
            .await
            .context("Engine.IO handshake")?;
        ensure!(
            r.status().as_u16() == 200,
            "Engine.IO handshake answered HTTP {}",
            r.status()
        );
        let body = String::from_utf8(r.bytes().await?.to_vec()).context("handshake is not text")?;
        let packets = packet::split_payload(&body)?;
        let Some(Eio::Open(info)) = packets.first().cloned() else {
            bail!("expected the Engine.IO open packet")
        };
        let sid = open_info(&info)?;
        let url = format!("{base}&sid={sid}");
        for p in packets.into_iter().skip(1) {
            incoming_tx.try_send(Ok(p))?;
        }
        let poll_fetch = fetch.clone();
        let poll_url = url.clone();
        let reader = tokio::spawn(async move {
            loop {
                let r = match poll_fetch.get(&poll_url).send().await {
                    Ok(r) if r.status().as_u16() == 200 => r,
                    _ => break,
                };
                let Ok(body) = r.bytes().await else { break };
                let Ok(text) = String::from_utf8(body.to_vec()) else {
                    break;
                };
                let items: Vec<Result<Eio>> = match packet::split_payload(&text) {
                    Ok(list) => list.into_iter().map(Ok).collect(),
                    Err(e) => vec![Err(e)],
                };
                for item in items {
                    let closing = matches!(item, Ok(Eio::Close));
                    if incoming_tx.send(item).await.is_err() || closing {
                        return;
                    }
                }
            }
        });
        ctx.state.register_client_task(ctx.client_id, reader).await;
        Arc::new(Transport::Polling { fetch, url })
    };
    let connects: Vec<String> = namespaces
        .iter()
        .map(|n| Eio::Message(Sio::new(Kind::Connect, n, None, auth.clone()).encode()).encode())
        .collect();
    transport
        .send(connects)
        .await
        .context("sending namespace CONNECT")?;
    ctx.state
        .update_client_status(ctx.client_id, ClientStatus::Connected)
        .await;
    let external =
        crate::client::command_support::register_command_channel(&ctx.state, ctx.client_id).await;
    let (internal_tx, internal_rx) = mpsc::channel::<Value>(16);
    let (event_tx, mut event_rx) = mpsc::channel::<Event>(64);
    let events_ctx = ctx.clone();
    let dispatcher = tokio::spawn(async move {
        let protocol = SocketIoClientProtocol;
        while let Some(event) = event_rx.recv().await {
            // This event, plus - with batching on - every event already waiting: what the
            // server pushed while the model answered the previous one. Each keeps its own
            // `ack_id`, so the model can still acknowledge every one of them.
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
            match call_llm_for_client_batch(
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
                    for action in result.actions {
                        if internal_tx.send(action).await.is_err() {
                            return;
                        }
                    }
                }
                Err(e) => Log::new(Some(&events_ctx.status_tx))
                    .warn(format!("Socket.IO client handler: {e}")),
            }
        }
    });
    ctx.state
        .register_client_task(ctx.client_id, dispatcher)
        .await;
    let session_ctx = ctx.clone();
    let task = tokio::spawn(async move {
        let result = session(
            &session_ctx,
            &transport,
            auth,
            external,
            internal_rx,
            incoming_rx,
            event_tx,
        )
        .await;
        let _ = transport.send(vec![Eio::Close.encode()]).await;
        let status = match result {
            Ok(()) => ClientStatus::Disconnected,
            Err(e) => {
                Log::new(Some(&session_ctx.status_tx)).warn(format!("Socket.IO client ended: {e}"));
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
    Ok(local)
}

fn reply(command: Option<ClientCommand>, outcome: Result<ClientSendOutcome>) {
    if let Some(c) = command {
        crate::client::command_support::reply(c, outcome);
    }
}

#[allow(clippy::too_many_arguments)]
async fn session(
    ctx: &ConnectContext,
    transport: &Transport,
    auth: Option<Value>,
    mut external: mpsc::Receiver<ClientCommand>,
    mut internal: mpsc::Receiver<Value>,
    mut incoming: mpsc::Receiver<Result<Eio>>,
    events: mpsc::Sender<Event>,
) -> Result<()> {
    let mut connected: HashSet<String> = HashSet::new();
    let mut pending: HashMap<u64, (String, String)> = HashMap::new();
    let mut next_ack: u64 = 1;
    loop {
        let (action, command) = tokio::select! {
            c = external.recv() => match c { Some(c) => (c.action.clone(), Some(c)), None => return Ok(()) },
            a = internal.recv() => match a { Some(a) => (a, None), None => return Ok(()) },
            m = incoming.recv() => {
                let p = match m {
                    Some(Ok(p)) => p,
                    Some(Err(e)) => bail!("protocol error from the server: {e}"),
                    None => {
                        events.send(Event::new(&actions::DISCONNECTED_EVENT, json!({"namespace": "*", "reason": "transport close"}))).await.ok();
                        return Ok(());
                    }
                };
                match p {
                    Eio::Ping(d) => transport.send(vec![Eio::Pong(d).encode()]).await?,
                    Eio::Close => {
                        events.send(Event::new(&actions::DISCONNECTED_EVENT, json!({"namespace": "*", "reason": "io server disconnect"}))).await.ok();
                        return Ok(());
                    }
                    Eio::Message(m) => {
                        let sio = match Sio::decode(&m) {
                            Ok(s) => s,
                            Err(e) => {
                                Log::new(Some(&ctx.status_tx)).warn(format!("Socket.IO client: {e}"));
                                continue;
                            }
                        };
                        let event = match sio.kind {
                            Kind::Connect => {
                                connected.insert(sio.nsp.clone());
                                let sid = sio.data.as_ref().and_then(|d| d["sid"].as_str()).unwrap_or_default().to_owned();
                                Event::new(&actions::CONNECTED_EVENT, json!({"namespace": sio.nsp, "socket_id": sid, "transport": transport.name()}))
                            }
                            Kind::ConnectError => {
                                let d = sio.data.clone().unwrap_or(Value::Null);
                                let message = d["message"].as_str().or(d.as_str()).unwrap_or("refused").to_owned();
                                Event::new(&actions::CONNECT_ERROR_EVENT, json!({"namespace": sio.nsp, "message": message, "data": d.get("data")}))
                            }
                            Kind::Disconnect => {
                                connected.remove(&sio.nsp);
                                Event::new(&actions::DISCONNECTED_EVENT, json!({"namespace": sio.nsp, "reason": "io server disconnect"}))
                            }
                            Kind::Event => match sio.event() {
                                Ok((name, args)) => Event::new(&actions::EVENT_EVENT, json!({"namespace": sio.nsp, "event": name, "args": args, "ack_id": sio.id})),
                                Err(e) => {
                                    Log::new(Some(&ctx.status_tx)).warn(format!("Socket.IO client: {e}"));
                                    continue;
                                }
                            },
                            Kind::Ack => {
                                let Some((nsp, event)) = sio.id.and_then(|id| pending.remove(&id)) else { continue };
                                Event::new(&actions::ACK_EVENT, json!({"namespace": nsp, "event": event, "args": sio.data.and_then(|d| d.as_array().cloned()).unwrap_or_default()}))
                            }
                            Kind::BinaryEvent | Kind::BinaryAck => continue,
                        };
                        events.send(event).await.context("Socket.IO event consumer stopped")?;
                    }
                    Eio::Open(_) | Eio::Pong(_) | Eio::Upgrade | Eio::Noop => {}
                }
                continue;
            }
        };
        match SocketIoClientProtocol.execute_action(action.clone()) {
            Ok(ClientActionResult::Disconnect) => {
                reply(command, Ok(ClientSendOutcome::Disconnected));
                return Ok(());
            }
            Ok(_) => {}
            Err(e) => {
                reply(
                    command,
                    Ok(ClientSendOutcome::Rejected {
                        error: e.to_string(),
                    }),
                );
                continue;
            }
        }
        let nsp = action["namespace"].as_str().unwrap_or("/").to_owned();
        let built: Result<Sio> = match action["type"].as_str().unwrap_or_default() {
            "socketio_emit" => {
                if !connected.contains(&nsp) {
                    Err(anyhow::anyhow!("not connected to {nsp}"))
                } else {
                    let id = action["ack"].as_bool().unwrap_or(false).then(|| {
                        let id = next_ack;
                        next_ack += 1;
                        pending.insert(
                            id,
                            (
                                nsp.clone(),
                                action["event"].as_str().unwrap_or_default().to_owned(),
                            ),
                        );
                        id
                    });
                    let mut payload = vec![action["event"].clone()];
                    payload.extend(action["args"].as_array().cloned().unwrap_or_default());
                    Ok(Sio::new(Kind::Event, &nsp, id, Some(Value::Array(payload))))
                }
            }
            "socketio_ack" => Ok(Sio::new(
                Kind::Ack,
                &nsp,
                action["ack_id"].as_u64(),
                Some(Value::Array(
                    action["args"].as_array().cloned().unwrap_or_default(),
                )),
            )),
            "socketio_connect_namespace" => Ok(Sio::new(
                Kind::Connect,
                &nsp,
                None,
                action
                    .get("auth")
                    .filter(|a| a.is_object())
                    .cloned()
                    .or_else(|| auth.clone()),
            )),
            _ => {
                connected.remove(&nsp);
                Ok(Sio::new(Kind::Disconnect, &nsp, None, None))
            }
        };
        let packet = match built {
            Ok(p) => Eio::Message(p.encode()).encode(),
            Err(e) => {
                reply(
                    command,
                    Ok(ClientSendOutcome::Rejected {
                        error: e.to_string(),
                    }),
                );
                continue;
            }
        };
        let n = packet.len();
        let sent = transport.send(vec![packet]).await;
        if command.is_some() {
            ctx.state
                .record_access_log(
                    AccessLogOwner::Client(ctx.client_id.as_u32()),
                    "Socket.IO",
                    None,
                    "injected_action",
                    json!({"type": action["type"], "event": action["event"]}),
                    vec![json!({"ok": sent.is_ok()})],
                )
                .await;
        }
        match sent {
            Ok(()) => reply(command, Ok(ClientSendOutcome::Sent { bytes_sent: n })),
            Err(e) => {
                reply(command, Err(anyhow::anyhow!("{e}")));
                return Err(e);
            }
        }
    }
}
