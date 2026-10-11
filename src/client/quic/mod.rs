//! An authenticated reusable QUIC connection, with independent bounded streams.
//! The registered owner polls all query and handler futures; no detached tasks
//! survive client removal and a parked handler never prevents command injection.
pub mod actions;
use crate::client::{command_support, llm_budget::call_llm_for_client};
use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
};
use crate::logging::emit::Log;
use crate::protocol::{ConnectContext, Event};
use crate::state::{
    client_handles::{ClientCommand, ClientSendOutcome},
    AccessLogOwner, ClientStatus,
};
use crate::utils::quic::*;
use actions::{
    QuicClientProtocol, QUIC_CONNECTED_EVENT, QUIC_DATAGRAM_EVENT, QUIC_ERROR_EVENT,
    QUIC_RESPONSE_EVENT,
};
use anyhow::{ensure, Context, Result};
use futures::{future::BoxFuture, stream::FuturesUnordered, FutureExt, StreamExt};
use serde_json::{json, Value};
use std::{net::SocketAddr, time::Duration};

const MAX_FOLLOWUP_DEPTH: u8 = 4;
/// Marks a handler turn a received DATAGRAM started, in the depth byte it carries.
const FROM_DATAGRAM: u8 = 0x80;
type HandlerFuture = BoxFuture<'static, (u8, Result<Vec<Value>>)>;
type QueryFuture = BoxFuture<'static, (u8, Event)>;

pub struct QuicClient;
impl QuicClient {
    pub async fn connect(ctx: ConnectContext) -> Result<SocketAddr> {
        let params = ctx.startup_params.as_ref();
        let exchange =
            Duration::from_secs(bounded_parameter(params, "exchange_timeout_secs", 30, 300)?);
        let alpn = params
            .map(|p| p.get_optional_string("alpn"))
            .transpose()?
            .flatten()
            .unwrap_or_else(|| "netget-quic".into());
        let (endpoint, connection) =
            crate::utils::quic::connect(&ctx.remote_addr, params, alpn.as_bytes(), 0).await?;
        let local_addr = endpoint.0.local_addr()?;
        ctx.state
            .update_client_status(ctx.client_id, ClientStatus::Connected)
            .await;
        let command_rx = command_support::register_command_channel(&ctx.state, ctx.client_id).await;
        let state = ctx.state.clone();
        let id = ctx.client_id;
        let task = tokio::spawn(Self::run(ctx, endpoint, connection, command_rx, exchange));
        state.register_client_task(id, task).await;
        Ok(local_addr)
    }

    async fn run(
        ctx: ConnectContext,
        _endpoint: EndpointGuard,
        connection: ConnectionGuard,
        mut commands: tokio::sync::mpsc::Receiver<ClientCommand>,
        exchange: Duration,
    ) {
        let mut handlers: FuturesUnordered<HandlerFuture> = FuturesUnordered::new();
        let mut queries: FuturesUnordered<QueryFuture> = FuturesUnordered::new();
        handlers.push(handle_event(
            ctx.clone(),
            Event::new(
                &QUIC_CONNECTED_EVENT,
                json!({
                    "remote_addr": ctx.remote_addr,
                    "max_datagram_size": connection.0.max_datagram_size(),
                }),
            ),
            0,
        ));
        let mut disconnect = false;
        // Consecutive datagrams sent in answer to a received datagram. An echoing peer and a
        // model that answers every datagram would otherwise trade them for as long as the LLM
        // budget lasts; past MAX_FOLLOWUP_DEPTH such answers are dropped until the operator or
        // a non-datagram event sends something.
        let mut datagram_replies: u8 = 0;
        while !disconnect {
            tokio::select! {
                command = commands.recv() => {
                    let Some(command) = command else { break; };
                    datagram_replies = 0;
                    disconnect = enqueue(&ctx,&connection.0,exchange,&mut queries,command.action.clone(),Some(command),0).await;
                }
                Some((depth,event)) = queries.next(), if !queries.is_empty() => {
                    // The final response still reaches the handler; only subsequent actions
                    // are stopped at the depth boundary. A returned disconnect is honoured.
                    if handlers.len() < MAX_STREAMS {
                        handlers.push(handle_event(ctx.clone(),event,depth));
                    } else { Log::new(Some(&ctx.status_tx)).warn("QUIC response handler limit reached"); }
                }
                Some((tagged,result)) = handlers.next(), if !handlers.is_empty() => {
                    let from_datagram = tagged & FROM_DATAGRAM != 0;
                    let depth = tagged & !FROM_DATAGRAM;
                    match result {
                        Ok(actions) if actions.len() <= MAX_STREAMS => {
                            for action in actions {
                                if action["type"] == "send_quic_datagram" {
                                    if !from_datagram {
                                        datagram_replies = 0;
                                    } else if datagram_replies >= MAX_FOLLOWUP_DEPTH {
                                        Log::new(Some(&ctx.status_tx)).warn("QUIC datagram reply limit reached");
                                        continue;
                                    } else {
                                        datagram_replies += 1;
                                    }
                                }
                                if depth >= MAX_FOLLOWUP_DEPTH && action["type"] != "disconnect" {
                                    if action["type"] == "send_quic_data" || action["type"] == "send_quic_datagram" { Log::new(Some(&ctx.status_tx)).warn("QUIC follow-up limit reached"); }
                                    continue;
                                }
                                if enqueue(&ctx,&connection.0,exchange,&mut queries,action,None,depth).await { disconnect = true; break; }
                            }
                        }
                        Ok(_) => Log::new(Some(&ctx.status_tx)).warn("QUIC handler returned more than 32 actions"),
                        Err(e) => Log::new(Some(&ctx.status_tx)).warn(format!("QUIC event handler failed: {e}")),
                    }
                }
                // An RFC 9221 DATAGRAM: one more handler turn. While the handler set is full,
                // datagrams wait in Quinn's bounded buffer and the oldest are dropped there.
                datagram = connection.0.read_datagram(), if handlers.len() < MAX_STREAMS => {
                    let Ok(datagram) = datagram else { break; };
                    let (data, encoding) = crate::server::quic::actions::encode_quic_payload(&datagram);
                    handlers.push(handle_event(
                        ctx.clone(),
                        Event::new(
                            &QUIC_DATAGRAM_EVENT,
                            json!({"data":data,"encoding":encoding,"bytes":datagram.len()}),
                        ),
                        FROM_DATAGRAM,
                    ));
                }
                _ = connection.0.closed() => break,
            }
        }
        drop(queries);
        drop(handlers);
        connection.0.close(0u32.into(), b"client disconnected");
        ctx.state.remove_client_handle(ctx.client_id).await;
        ctx.state
            .update_client_status(ctx.client_id, ClientStatus::Disconnected)
            .await;
        let _ = ctx.status_tx.send("__UPDATE_UI__".into());
    }
}

pub fn payload(data: &Value) -> Result<Vec<u8>> {
    let text = data["data"].as_str().context("Missing data")?;
    let bytes = crate::server::quic::actions::decode_quic_payload(text, data["encoding"].as_str())?;
    ensure!(bytes.len() <= MAX_BYTES, "QUIC payload exceeds 1 MiB");
    Ok(bytes)
}

fn handle_event(ctx: ConnectContext, event: Event, depth: u8) -> HandlerFuture {
    async move {
        let result = async {
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
            let result = call_llm_for_client(
                &ctx.llm_client,
                &ctx.state,
                ctx.client_id.to_string(),
                &instruction,
                &memory,
                Some(&event),
                &QuicClientProtocol::new(),
                &ctx.status_tx,
            )
            .await?;
            if let Some(memory) = result.memory_updates {
                ctx.state.set_memory_for_client(ctx.client_id, memory).await;
            }
            Ok(result.actions)
        }
        .await;
        (depth, result)
    }
    .boxed()
}

async fn enqueue(
    ctx: &ConnectContext,
    connection: &quinn::Connection,
    deadline: Duration,
    queries: &mut FuturesUnordered<QueryFuture>,
    action: Value,
    command: Option<ClientCommand>,
    depth: u8,
) -> bool {
    let outcome = match QuicClientProtocol::new().execute_action(action.clone()) {
        Ok(ClientActionResult::Disconnect) => Ok(ClientSendOutcome::Disconnected),
        Ok(ClientActionResult::WaitForMore | ClientActionResult::NoAction) => {
            Ok(ClientSendOutcome::Executed {
                detail: "Waiting for more queries".into(),
            })
        }
        Ok(ClientActionResult::Custom { name, data })
            if name == crate::server::quic::actions::DATAGRAM_RESULT =>
        {
            match data.as_str().and_then(|h| hex::decode(h).ok()) {
                Some(bytes) => {
                    let n = bytes.len();
                    connection
                        .send_datagram(bytes::Bytes::from(bytes))
                        .map(|()| ClientSendOutcome::Executed {
                            detail: format!("QUIC datagram of {n} bytes sent"),
                        })
                        .map_err(|e| {
                            anyhow::anyhow!(
                                "QUIC datagram of {n} bytes not sent (peer limit {:?}): {e}",
                                connection.max_datagram_size()
                            )
                        })
                }
                None => Err(anyhow::anyhow!("QUIC datagram payload was not hex")),
            }
        }
        Ok(ClientActionResult::Custom { name, data }) if name == "quic_exchange" => {
            if queries.len() >= MAX_STREAMS {
                Err(anyhow::anyhow!("QUIC client busy: 32 active transactions"))
            } else {
                queries.push(query_future(
                    ctx.clone(),
                    connection.clone(),
                    deadline,
                    data,
                    action,
                    command,
                    depth + 1,
                ));
                return false;
            }
        }
        Ok(_) => Err(anyhow::anyhow!("Unsupported QUIC client action")),
        Err(e) => Err(e),
    };
    let disconnect = matches!(outcome, Ok(ClientSendOutcome::Disconnected));
    record_action(ctx, &action, &outcome).await;
    if let Some(command) = command {
        command_support::reply(command, outcome);
    }
    disconnect
}

async fn record_action(ctx: &ConnectContext, action: &Value, outcome: &Result<ClientSendOutcome>) {
    let result = match outcome {
        Ok(v) => serde_json::to_value(v).unwrap_or(Value::Null),
        Err(e) => json!({"error":e.to_string()}),
    };
    ctx.state
        .record_access_log(
            AccessLogOwner::Client(ctx.client_id.as_u32()),
            QuicClientProtocol::new().protocol_name(),
            None,
            "client_action",
            action.clone(),
            vec![result],
        )
        .await;
}

fn query_future(
    ctx: ConnectContext,
    connection: quinn::Connection,
    deadline: Duration,
    data: Value,
    action: Value,
    command: Option<ClientCommand>,
    depth: u8,
) -> QueryFuture {
    async move {
        let result = async {
            let query = payload(&data)?;
            exchange(&connection, &query, deadline).await
        }
        .await;
        let (outcome, event) = match result {
            Ok((bytes, stream)) => {
                let (data, encoding) = crate::server::quic::actions::encode_quic_payload(&bytes);
                let event = Event::new(
                    &QUIC_RESPONSE_EVENT,
                    json!({"stream_id":stream,"data":data,"encoding":encoding,"bytes":bytes.len()}),
                );
                (
                    Ok(ClientSendOutcome::Executed {
                        detail: format!("QUIC stream {stream}: {} response bytes", bytes.len()),
                    }),
                    event,
                )
            }
            Err(e) => {
                Log::new(Some(&ctx.status_tx)).warn(format!("QUIC stream failed: {e:#}"));
                let event = Event::new(&QUIC_ERROR_EVENT, json!({"error":format!("{e:#}")}));
                (Err(e), event)
            }
        };
        record_action(&ctx, &action, &outcome).await;
        if let Some(command) = command {
            command_support::reply(command, outcome);
        }
        (depth, event)
    }
    .boxed()
}

/// One raw bidirectional exchange: write payload and FIN, then read until peer FIN.
pub async fn exchange(
    connection: &quinn::Connection,
    payload: &[u8],
    deadline: Duration,
) -> Result<(Vec<u8>, u64)> {
    ensure!(payload.len() <= MAX_BYTES, "QUIC payload exceeds 1 MiB");
    let end = tokio::time::Instant::now() + deadline;
    let (send, recv) = tokio::time::timeout_at(end, connection.open_bi())
        .await
        .context("QUIC stream-open deadline")??;
    let mut streams = CancelStreams {
        send,
        recv,
        done: false,
    };
    let result = tokio::time::timeout_at(end, async {
        streams.send.write_all(payload).await?;
        streams.send.finish()?;
        let response = streams.recv.read_to_end(MAX_BYTES).await?;
        Ok((response, u64::from(streams.recv.id())))
    })
    .await
    .context("QUIC stream deadline exceeded")?;
    if result.is_ok() {
        streams.done = true;
    }
    result
}
struct CancelStreams {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    done: bool,
}
impl Drop for CancelStreams {
    fn drop(&mut self) {
        if !self.done {
            let _ = self.recv.stop(quinn::VarInt::from_u32(3));
            let _ = self.send.reset(quinn::VarInt::from_u32(3));
        }
    }
}
