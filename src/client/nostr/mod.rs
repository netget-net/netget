pub mod actions;
pub mod api;
use crate::{
    client::{command_support, llm_budget::call_llm_for_client_batch},
    logging::emit::Log,
    protocol::{ConnectContext, Event},
    server::nostr::wire::{self, Filter, RelayKey},
    state::{
        client_handles::{ClientCommand, ClientSendOutcome},
        AccessLogOwner, ClientStatus,
    },
};
pub use actions::NostrClientProtocol;
use anyhow::{ensure, Context, Result};
use futures::{SinkExt, StreamExt};
use serde_json::{json, Value};
use std::{collections::HashMap, net::SocketAddr, pin::Pin, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::mpsc,
    time::Instant,
};
use tokio_tungstenite::{
    tungstenite::{protocol::WebSocketConfig, Message},
    WebSocketStream,
};
pub const DEFAULT_TIMEOUT_SECS: u64 = 15;
pub const MAX_FOLLOWUPS: u8 = 4;
pub const QUEUE_CAPACITY: usize = 8;
pub const MAX_PENDING_PUBLISHES: usize = 16;
trait Socket: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Socket for T {}
type Ws = WebSocketStream<Box<dyn Socket>>;
type HandlerEvent = (Event, u8);
type HandlerAction = (Value, u8);
type InfoFuture = Pin<Box<dyn std::future::Future<Output = Result<Value>> + Send>>;
#[derive(Debug)]
struct WriteFailure;
impl std::fmt::Display for WriteFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Nostr bounded write failure")
    }
}
impl std::error::Error for WriteFailure {}
struct Publication {
    deadline: Instant,
    depth: u8,
}
struct Subscription {
    filters: Vec<Filter>,
    eose: bool,
    depth: u8,
}

pub fn endpoint(address: &str) -> Result<url::Url> {
    let address = if address.contains("://") {
        address.to_owned()
    } else {
        format!("ws://{address}")
    };
    let url = url::Url::parse(&address).context("invalid Nostr relay URL")?;
    ensure!(
        ["ws", "wss"].contains(&url.scheme()) && url.host_str().is_some(),
        "Nostr relay URL must use WS or WSS"
    );
    ensure!(
        url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none(),
        "Nostr URL credentials/query/fragment refused"
    );
    ensure!(url.as_str().len() <= 4096, "Nostr URL length limit");
    #[cfg(target_arch = "wasm32")]
    ensure!(
        url.scheme() == "ws",
        "Nostr browser transport supports WS only"
    );
    Ok(url)
}
async fn websocket(url: &url::Url) -> Result<(Ws, SocketAddr)> {
    let host = url.host_str().unwrap().trim_matches(['[', ']']);
    let stream = tokio::net::TcpStream::connect((host, url.port_or_known_default().unwrap()))
        .await
        .context("Nostr TCP connection failed")?;
    let remote = stream.peer_addr()?;
    let stream: Box<dyn Socket> = if url.scheme() == "wss" {
        #[cfg(not(target_arch = "wasm32"))]
        {
            let roots = rustls::RootCertStore {
                roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
            };
            let config = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()?
            .with_root_certificates(roots)
            .with_no_client_auth();
            let server_name = rustls::pki_types::ServerName::try_from(host.to_owned())
                .context("invalid Nostr TLS server name")?;
            Box::new(
                tokio_rustls::TlsConnector::from(std::sync::Arc::new(config))
                    .connect(server_name, stream)
                    .await
                    .context("Nostr TLS verification failed")?,
            )
        }
        #[cfg(target_arch = "wasm32")]
        {
            anyhow::bail!("Nostr browser transport supports WS only")
        }
    } else {
        Box::new(stream)
    };
    let config = WebSocketConfig {
        max_message_size: Some(wire::MAX_MESSAGE_BYTES),
        max_frame_size: Some(wire::MAX_MESSAGE_BYTES),
        write_buffer_size: 0,
        max_write_buffer_size: wire::MAX_MESSAGE_BYTES * 2,
        ..Default::default()
    };
    let (ws, response) =
        tokio_tungstenite::client_async_with_config(url.as_str(), stream, Some(config))
            .await
            .context("Nostr WebSocket upgrade failed")?;
    ensure!(
        response.headers().get("sec-websocket-protocol").is_none(),
        "Nostr relay selected unoffered WebSocket subprotocol"
    );
    Ok((ws, remote))
}
#[cfg(not(target_arch = "wasm32"))]
async fn information(url: url::Url, timeout: Duration) -> Result<Value> {
    let client = reqwest::Client::builder()
        .use_rustls_tls()
        .no_proxy()
        .no_gzip()
        .no_brotli()
        .no_deflate()
        .no_zstd()
        .redirect(reqwest::redirect::Policy::none())
        .pool_max_idle_per_host(0)
        .timeout(timeout)
        .http1_only()
        .build()?;
    let mut url = url;
    url.set_scheme(if url.scheme() == "wss" {
        "https"
    } else {
        "http"
    })
    .map_err(|_| anyhow::anyhow!("invalid Nostr information URL"))?;
    let mut response = client
        .get(url)
        .header("Accept", "application/nostr+json")
        .header("Accept-Encoding", "identity")
        .header("Connection", "close")
        .send()
        .await?;
    ensure!(response.status() == 200, "NIP-11 requires HTTP200");
    let mime = response
        .headers()
        .get("content-type")
        .context("NIP-11 Content-Type required")?
        .to_str()?
        .split(';')
        .next()
        .unwrap()
        .trim();
    ensure!(
        mime.eq_ignore_ascii_case("application/nostr+json")
            || mime.eq_ignore_ascii_case("application/json"),
        "NIP-11 JSON Content-Type required"
    );
    for encoding in response.headers().get_all("content-encoding") {
        ensure!(
            encoding.to_str()?.eq_ignore_ascii_case("identity"),
            "NIP-11 encoded body refused"
        );
    }
    if let Some(length) = response.content_length() {
        ensure!(
            length <= wire::MAX_MESSAGE_BYTES as u64,
            "NIP-11 body limit"
        );
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        ensure!(
            body.len().saturating_add(chunk.len()) <= wire::MAX_MESSAGE_BYTES,
            "NIP-11 body limit"
        );
        body.extend_from_slice(&chunk);
    }
    api::relay_info(&api::json(&body)?)
}
#[cfg(target_arch = "wasm32")]
async fn information(mut url: url::Url, _timeout: Duration) -> Result<Value> {
    use http_body_util::{BodyExt, Full, Limited};
    url.set_scheme("http")
        .map_err(|_| anyhow::anyhow!("invalid Nostr information URL"))?;
    let target = crate::client::http_fetch::transport::parse_http_url(url.as_str())?;
    let stream = tokio::net::TcpStream::connect((target.host.as_str(), target.port)).await?;
    let (mut sender, connection) =
        hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream)).await?;
    let exchange = async {
        let request = hyper::Request::builder()
            .method("GET")
            .uri(target.path_and_query)
            .header("Host", target.authority)
            .header("Accept", "application/nostr+json")
            .header("Accept-Encoding", "identity")
            .header("Connection", "close")
            .body(Full::new(bytes::Bytes::new()))?;
        let response = sender.send_request(request).await?;
        ensure!(response.status() == 200, "NIP-11 requires HTTP200");
        let mime = response
            .headers()
            .get("content-type")
            .context("NIP-11 Content-Type required")?
            .to_str()?
            .split(';')
            .next()
            .unwrap()
            .trim();
        ensure!(
            mime.eq_ignore_ascii_case("application/nostr+json")
                || mime.eq_ignore_ascii_case("application/json"),
            "NIP-11 JSON Content-Type required"
        );
        for encoding in response.headers().get_all("content-encoding") {
            ensure!(
                encoding.to_str()?.eq_ignore_ascii_case("identity"),
                "NIP-11 encoded body refused"
            );
        }
        let body = Limited::new(response.into_body(), wire::MAX_MESSAGE_BYTES)
            .collect()
            .await?
            .to_bytes();
        api::relay_info(&api::json(&body)?)
    };
    tokio::pin!(exchange, connection);
    tokio::select! {result=&mut exchange=>result,result=&mut connection=>{let _=result;exchange.await}}
}
pub async fn connect(mut ctx: ConnectContext) -> Result<SocketAddr> {
    let url = endpoint(&ctx.remote_addr)?;
    let mut timeout_secs = DEFAULT_TIMEOUT_SECS;
    let mut key = RelayKey::generate();
    if let Some(params) = &ctx.startup_params {
        timeout_secs = params
            .get_optional_u64("request_timeout_secs")?
            .unwrap_or(timeout_secs);
        if let Some(secret) = params
            .get_optional_string("secret_key")
            .map_err(|_| anyhow::anyhow!("Nostr secret_key must be string"))?
        {
            ensure!(
                secret.len() == 64,
                "Nostr secret_key must be64 hex characters"
            );
            key = RelayKey::from_hex(&secret)
                .map_err(|_| anyhow::anyhow!("invalid Nostr secret_key"))?;
        }
    }
    ensure!(
        (1..=30).contains(&timeout_secs),
        "request_timeout_secs must be1..30"
    );
    // The owned tasks need the signer, never a copy of private startup parameters.
    ctx.startup_params = None;
    let timeout = Duration::from_secs(timeout_secs);
    let (ws, remote) = tokio::time::timeout(timeout, websocket(&url))
        .await
        .context("Nostr connect/upgrade deadline")??;
    let external = command_support::register_command_channel(&ctx.state, ctx.client_id).await;
    let (actions_tx, actions_rx) = mpsc::channel::<HandlerAction>(QUEUE_CAPACITY);
    let (events_tx, mut events_rx) = mpsc::channel::<HandlerEvent>(QUEUE_CAPACITY);
    let handler_ctx = ctx.clone();
    let handler = tokio::spawn(async move {
        // An event that would not have joined the previous batch starts the next one.
        let mut carried = None;
        while let Some(first) = match carried.take() {
            Some(item) => Some(item),
            None => events_rx.recv().await,
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
                        &handler_ctx.state,
                        handler_ctx.client_id,
                        &ids,
                    )
                    .await
                {
                    break;
                }
                let Ok(next) = events_rx.try_recv() else {
                    break;
                };
                ids.push(next.0.id());
                if !crate::llm::action_helper::client_batch_goes_to_the_model(
                    &handler_ctx.state,
                    handler_ctx.client_id,
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
            let instruction = handler_ctx
                .state
                .get_instruction_for_client(handler_ctx.client_id)
                .await
                .unwrap_or_default();
            let memory = handler_ctx
                .state
                .get_memory_for_client(handler_ctx.client_id)
                .await
                .unwrap_or_default();
            match call_llm_for_client_batch(
                &handler_ctx.llm_client,
                &handler_ctx.state,
                handler_ctx.client_id.to_string(),
                &instruction,
                &memory,
                &events,
                &NostrClientProtocol,
                &handler_ctx.status_tx,
            )
            .await
            {
                Ok(result) => {
                    if let Some(memory) = result.memory_updates {
                        handler_ctx
                            .state
                            .set_memory_for_client(handler_ctx.client_id, memory)
                            .await;
                    }
                    for action in result.actions {
                        if depth >= MAX_FOLLOWUPS && action["type"] != "disconnect" {
                            crate::utils::json_budget::drop_iteratively(action);
                            Log::new(Some(&handler_ctx.status_tx))
                                .warn("Nostr handler followup limit reached");
                            continue;
                        }
                        if actions_tx.send((action, depth + 1)).await.is_err() {
                            return;
                        }
                    }
                }
                Err(_) => Log::new(Some(&handler_ctx.status_tx)).warn("Nostr event handler failed"),
            }
        }
    });
    let handler_abort = handler.abort_handle();
    ctx.state.register_client_task(ctx.client_id, handler).await;
    let task_ctx = ctx.clone();
    let task = tokio::spawn(async move {
        let result = session(
            &task_ctx, ws, url, key, timeout, external, actions_rx, events_tx,
        )
        .await;
        handler_abort.abort();
        let status = if result.is_ok() {
            ClientStatus::Disconnected
        } else {
            Log::new(Some(&task_ctx.status_tx)).warn("Nostr bounded session failure");
            ClientStatus::Error("Nostr bounded session failure".into())
        };
        task_ctx
            .state
            .update_client_status(task_ctx.client_id, status)
            .await;
        task_ctx
            .state
            .remove_client_handle(task_ctx.client_id)
            .await;
        let _ = task_ctx.status_tx.send("__UPDATE_UI__".into());
    });
    ctx.state.register_client_task(ctx.client_id, task).await;
    Ok(remote)
}
fn emit(
    events: &mpsc::Sender<HandlerEvent>,
    event: &'static crate::protocol::EventType,
    data: Value,
    depth: u8,
) -> Result<()> {
    events
        .try_send((Event::new(event, data), depth))
        .context("Nostr event queue full")
}
// Writes are owned by the session. A queued disconnect cancels the pending
// write; other commands refuse without copying their programmatically-built JSON.
async fn send(
    ws: &mut Ws,
    frame: Message,
    timeout: Duration,
    external: &mut mpsc::Receiver<ClientCommand>,
) -> Result<bool> {
    let write = tokio::time::timeout(timeout, ws.send(frame));
    tokio::pin!(write);
    loop {
        tokio::select! {biased;
            command=external.recv()=>{
                let Some(mut command)=command else {return Ok(true)};
                let value=std::mem::take(&mut command.action);
                let bounded=api::within_budget(&value);
                let disconnect=bounded && matches!(api::action(&value),Ok(api::Action::Disconnect));
                crate::utils::json_budget::drop_iteratively(value);
                if disconnect {command_support::reply(command,Ok(ClientSendOutcome::Disconnected));return Ok(true)}
                command_support::reply(command,Ok(ClientSendOutcome::Rejected{error:if bounded {"Nostr write pending; retry after its receipt"} else {"Nostr action depth/node/retained-content limit"}.into()}));
            }
            result=&mut write=>{result.map_err(|_|WriteFailure)?.map_err(|_|WriteFailure)?;return Ok(false)}
        }
    }
}
#[allow(clippy::too_many_arguments)]
async fn session(
    ctx: &ConnectContext,
    mut ws: Ws,
    url: url::Url,
    key: RelayKey,
    timeout: Duration,
    mut external: mpsc::Receiver<ClientCommand>,
    mut internal: mpsc::Receiver<HandlerAction>,
    events: mpsc::Sender<HandlerEvent>,
) -> Result<()> {
    let mut publications = HashMap::<String, Publication>::new();
    let mut subscriptions = HashMap::<String, Subscription>::new();
    let mut info: Option<(InfoFuture, u8)> = None;
    let mut unsolicited_depth = 0;
    emit(
        &events,
        &actions::CONNECTED_EVENT,
        json!({"relay_url":url.as_str(),"pubkey":key.pubkey_hex()}),
        0,
    )?;
    loop {
        let next_deadline = publications.values().map(|p| p.deadline).min();
        let deadline = async {
            match next_deadline {
                Some(d) => tokio::time::sleep_until(d).await,
                None => std::future::pending::<()>().await,
            }
        };
        let info_result = async {
            match &mut info {
                Some((future, depth)) => Some((future.await, *depth)),
                None => std::future::pending().await,
            }
        };
        let input = tokio::select! {
            command=external.recv()=>{let Some(mut c)=command else{return Ok(())};Some((std::mem::take(&mut c.action),0,Some(c)))},
            action=internal.recv()=>{let Some((a,d))=action else{return Ok(())};Some((a,d,None))},
            result=info_result=>{
                let (result,depth)=result.unwrap();info=None;
                match result {Ok(value)=>emit(&events,&actions::INFO_EVENT,json!({"information":value}),depth)?,Err(_)=>emit(&events,&actions::ERROR_EVENT,json!({"category":"relay_info","error":"NIP-11 transport/status/schema/deadline refusal"}),depth)?};
                None
            },
            _=deadline=>{
                let expired=publications.iter().filter(|(_,p)|p.deadline<=Instant::now()).map(|(id,_)|id.clone()).collect::<Vec<_>>();
                for id in expired {let p=publications.remove(&id).unwrap();emit(&events,&actions::RESULT_EVENT,json!({"id":id,"status":"timeout","accepted":null,"message":"no OK before publish deadline","reason_prefix":null}),p.depth)?;}
                None
            },
            frame=ws.next()=>{
                let Some(frame)=frame else{return Ok(())};
                match frame? {
                    Message::Text(text)=>{
                        let message=match api::relay(&text) {Ok(m)=>m,Err(_)=>{emit(&events,&actions::ERROR_EVENT,json!({"category":"relay_schema","error":"Nostr relay message/id/signature/schema refusal"}),0)?;return Err(anyhow::anyhow!("invalid Nostr relay message"))}};
                        match message {
                            api::RelayMessage::Event{id,event}=>if let Some(sub)=subscriptions.get(&id) {
                                let matches=sub.filters.iter().any(|filter|filter.matches(&event));
                                emit(&events,&actions::EVENT_EVENT,json!({"subscription_id":id,"event":event.to_json(),"stored_phase":!sub.eose,"matches_current_filters":matches}),sub.depth)?;
                            },
                            api::RelayMessage::Ok{id,accepted,message}=>if let Some(p)=publications.remove(&id) {
                                emit(&events,&actions::RESULT_EVENT,json!({"id":id,"status":"ok","accepted":accepted,"reason_prefix":api::reason_prefix(&message),"message":message}),p.depth)?;
                            },
                            api::RelayMessage::Eose(id)=>if let Some(sub)=subscriptions.get_mut(&id) {sub.eose=true;emit(&events,&actions::SUBSCRIPTION_EVENT,json!({"subscription_id":id,"status":"eose","message":"","reason_prefix":null}),sub.depth)?;},
                            api::RelayMessage::Closed{id,message}=>if let Some(sub)=subscriptions.remove(&id) {emit(&events,&actions::SUBSCRIPTION_EVENT,json!({"subscription_id":id,"status":"closed","reason_prefix":api::reason_prefix(&message),"message":message}),sub.depth)?;},
                            api::RelayMessage::Notice(message)=>emit(&events,&actions::NOTICE_EVENT,json!({"message":message,"message_type":"NOTICE","supported":true}),unsolicited_depth)?,
                            api::RelayMessage::Unsupported(kind)=>emit(&events,&actions::NOTICE_EVENT,json!({"message":"unsupported relay extension; no automatic signing or request","message_type":kind,"supported":false}),unsolicited_depth)?,
                        }
                    }
                    Message::Ping(payload)=>if send(&mut ws,Message::Pong(payload),timeout,&mut external).await? {return Ok(())},
                    Message::Pong(_)=>{},
                    Message::Close(_)=>return Ok(()),
                    _=>anyhow::bail!("Nostr requires text WebSocket messages"),
                }
                None
            }
        };
        let Some((value, depth, command)) = input else {
            continue;
        };
        if !api::within_budget(&value) {
            crate::utils::json_budget::drop_iteratively(value);
            if let Some(command) = command {
                command_support::reply(
                    command,
                    Ok(ClientSendOutcome::Rejected {
                        error: "Nostr action depth/node/retained-content limit".into(),
                    }),
                );
            } else {
                emit(
                    &events,
                    &actions::ERROR_EVENT,
                    json!({"category":"action","error":"Nostr action depth/node/retained-content limit"}),
                    depth,
                )?;
            }
            continue;
        }
        let outcome=async {
            let action=api::action(&value)?;
            unsolicited_depth=depth;
            let (text,receipt)=match action {
                api::Action::Disconnect=>return Ok((ClientSendOutcome::Disconnected,true)),
                api::Action::RelayInfo=>{
                    ensure!(info.is_none(),"NIP-11 request already pending");
                    let info_url=url.clone();
                    info=Some((Box::pin(async move {tokio::time::timeout(timeout,information(info_url,timeout)).await.context("NIP-11 deadline")?}),depth));
                    return Ok((ClientSendOutcome::Executed{detail:json!({"request":"relay_info","pending":true}).to_string()},false));
                }
                api::Action::Publish{kind,content,tags,created_at}=>{
                    ensure!(publications.len()<MAX_PENDING_PUBLISHES,"Nostr pending publish limit");
                    let event=key.sign(created_at,kind,tags,content);
                    ensure!(!publications.contains_key(&event.id),"Nostr duplicate pending event id");
                    let text=api::frame_text(json!(["EVENT",event.to_json()]))?;
                    let receipt=json!({"id":event.id,"bytes_sent":text.len()});
                    if send(&mut ws,Message::Text(text),timeout,&mut external).await? {return Ok((ClientSendOutcome::Disconnected,true))}
                    publications.insert(event.id,Publication{deadline:Instant::now()+timeout,depth});
                    return Ok((ClientSendOutcome::Executed{detail:receipt.to_string()},false));
                }
                api::Action::Subscribe{id,filters}=>{
                    ensure!(subscriptions.contains_key(&id) || subscriptions.len()<wire::MAX_SUBSCRIPTIONS,"Nostr subscription limit");
                    let mut frame=vec![json!("REQ"),json!(id)];frame.extend(filters.iter().map(|f|f.raw.clone()));
                    let text=api::frame_text(Value::Array(frame))?;
                    let receipt=json!({"subscription_id":id,"bytes_sent":text.len()});
                    subscriptions.insert(id,Subscription{filters,eose:false,depth});
                    (text,receipt)
                }
                api::Action::Close(id)=>{
                    ensure!(subscriptions.contains_key(&id),"Nostr subscription is not open");
                    let text=api::frame_text(json!(["CLOSE",id]))?;
                    let receipt=json!({"subscription_id":id,"bytes_sent":text.len(),"relay_acknowledged":false});
                    subscriptions.remove(&id);
                    emit(&events,&actions::SUBSCRIPTION_EVENT,json!({"subscription_id":id,"status":"local_close","message":"","reason_prefix":null}),depth)?;
                    (text,receipt)
                }
            };
            let disconnected=send(&mut ws,Message::Text(text),timeout,&mut external).await?;
            Ok::<_,anyhow::Error>((if disconnected {ClientSendOutcome::Disconnected} else {ClientSendOutcome::Executed{detail:receipt.to_string()}},disconnected))
        }.await;
        let (result, disconnect) = match outcome {
            Ok((result, disconnect)) => (result, disconnect),
            Err(error) => {
                if error.is::<WriteFailure>() {
                    return Err(error);
                }
                emit(
                    &events,
                    &actions::ERROR_EVENT,
                    json!({"category":"action","error":error.to_string()}),
                    depth,
                )?;
                (
                    ClientSendOutcome::Rejected {
                        error: error.to_string(),
                    },
                    false,
                )
            }
        };
        if let Some(command) = command {
            ctx.state
                .record_access_log(
                    AccessLogOwner::Client(ctx.client_id.as_u32()),
                    "Nostr",
                    None,
                    "injected_action",
                    if matches!(result, ClientSendOutcome::Rejected { .. }) {
                        json!({})
                    } else {
                        value
                    },
                    vec![serde_json::to_value(&result)?],
                )
                .await;
            command_support::reply(command, Ok(result));
        }
        if disconnect {
            return Ok(());
        }
    }
}
