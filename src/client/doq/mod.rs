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
use crate::server::doq::wire::*;
use crate::state::{
    client_handles::{ClientCommand, ClientSendOutcome},
    AccessLogOwner, ClientStatus,
};
use actions::{DoqClientProtocol, DOQ_CONNECTED_EVENT, DOQ_ERROR_EVENT, DOQ_RESPONSE_EVENT};
use anyhow::{bail, ensure, Context, Result};
use futures::{future::BoxFuture, stream::FuturesUnordered, FutureExt, StreamExt};
use hickory_proto::{
    op::{Message, MessageType, Query},
    rr::{Name, RecordType},
};
use serde_json::{json, Value};
use std::{net::SocketAddr, str::FromStr, sync::Arc, time::Duration};

const MAX_FOLLOWUP_DEPTH: u8 = 4;
type HandlerFuture = BoxFuture<'static, (u8, Result<Vec<Value>>)>;
type QueryFuture = BoxFuture<'static, (u8, Event)>;

pub struct DoqClient;
impl DoqClient {
    pub async fn connect(ctx: ConnectContext) -> Result<SocketAddr> {
        let params = ctx.startup_params.as_ref();
        let handshake = Duration::from_secs(bounded_parameter(
            params,
            "handshake_timeout_secs",
            HANDSHAKE_TIMEOUT.as_secs(),
            60,
        )?);
        let exchange = Duration::from_secs(bounded_parameter(
            params,
            "exchange_timeout_secs",
            EXCHANGE_TIMEOUT.as_secs(),
            300,
        )?);
        let idle = Duration::from_secs(bounded_parameter(
            params,
            "idle_timeout_secs",
            IDLE_TIMEOUT.as_secs(),
            3600,
        )?);
        let auth_name = params
            .map(|p| p.get_optional_string("server_name"))
            .transpose()?
            .flatten();
        let ca = params
            .map(|p| p.get_optional_string("ca_cert_path"))
            .transpose()?
            .flatten();
        let (_, port) = ctx
            .remote_addr
            .rsplit_once(':')
            .context("DoQ remote address must be hostname:port or [IPv6]:port")?;
        ensure!(
            port.parse::<u16>()? != 53,
            "RFC 9250 forbids DoQ on UDP port 53"
        );
        let default_name = ctx
            .remote_addr
            .rsplit_once(':')
            .unwrap()
            .0
            .trim_start_matches('[')
            .trim_end_matches(']');
        let server_name = auth_name.unwrap_or_else(|| default_name.to_string());
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        if let Some(path) = ca {
            let pem = std::fs::read(path).context("Read DoQ trust certificate")?;
            let certs = rustls_pemfile::certs(&mut pem.as_slice())
                .collect::<std::result::Result<Vec<_>, _>>()?;
            ensure!(!certs.is_empty(), "DoQ trust file contains no certificates");
            for cert in certs {
                roots.add(cert)?;
            }
        }
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut tls = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        tls.alpn_protocols = vec![b"doq".to_vec()];
        tls.enable_early_data = false;
        let mut config = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(tls)?,
        ));
        // A DoQ server never opens streams. Quinn enforces zero credit in both directions.
        config.transport_config(transport(idle, 0));
        let (endpoint, connection) = tokio::time::timeout(handshake, async {
            let remote = tokio::net::lookup_host(&ctx.remote_addr)
                .await?
                .next()
                .context("No addresses for DoQ server")?;
            let bind = if remote.is_ipv6() {
                "[::]:0"
            } else {
                "0.0.0.0:0"
            };
            let mut endpoint = quinn::Endpoint::client(bind.parse()?)?;
            endpoint.set_default_client_config(config);
            let endpoint = EndpointGuard(endpoint);
            let connection = endpoint
                .0
                .connect(remote, &server_name)?
                .await
                .context("DoQ TLS handshake (check ca_cert_path and server_name)")?;
            Ok::<_, anyhow::Error>((endpoint, ConnectionGuard(connection)))
        })
        .await
        .context("DoQ connection deadline exceeded")??;
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
            Event::new(&DOQ_CONNECTED_EVENT, json!({"remote_addr":ctx.remote_addr})),
            0,
        ));
        let mut disconnect = false;
        while !disconnect {
            tokio::select! {
                command = commands.recv() => {
                    let Some(command) = command else { break; };
                    disconnect = enqueue(&ctx,&connection.0,exchange,&mut queries,command.action.clone(),Some(command),0).await;
                }
                Some((depth,event)) = queries.next(), if !queries.is_empty() => {
                    // The final response still reaches the handler; only subsequent actions
                    // are stopped at the depth boundary. A returned disconnect is honoured.
                    if handlers.len() < MAX_STREAMS {
                        handlers.push(handle_event(ctx.clone(),event,depth));
                    } else { Log::new(Some(&ctx.status_tx)).warn("DoQ response handler limit reached"); }
                }
                Some((depth,result)) = handlers.next(), if !handlers.is_empty() => {
                    match result {
                        Ok(actions) if actions.len() <= MAX_STREAMS => {
                            for action in actions {
                                if depth >= MAX_FOLLOWUP_DEPTH && action["type"] != "disconnect" {
                                    if action["type"] == "send_dns_query" { Log::new(Some(&ctx.status_tx)).warn("DoQ follow-up limit reached"); }
                                    continue;
                                }
                                if enqueue(&ctx,&connection.0,exchange,&mut queries,action,None,depth).await { disconnect = true; break; }
                            }
                        }
                        Ok(_) => Log::new(Some(&ctx.status_tx)).warn("DoQ handler returned more than 32 actions"),
                        Err(e) => Log::new(Some(&ctx.status_tx)).warn(format!("DoQ event handler failed: {e}")),
                    }
                }
                _ = connection.0.closed() => break,
            }
        }
        drop(queries);
        drop(handlers);
        connection.0.close(NO_ERROR, b"client disconnected");
        ctx.state.remove_client_handle(ctx.client_id).await;
        ctx.state
            .update_client_status(ctx.client_id, ClientStatus::Disconnected)
            .await;
        let _ = ctx.status_tx.send("__UPDATE_UI__".into());
    }
}

pub fn build_query(data: &Value) -> Result<Message> {
    let domain = data["domain"].as_str().context("Missing domain")?;
    let kind = RecordType::from_str(data["query_type"].as_str().context("Missing query_type")?)?;
    ensure!(
        !matches!(kind, RecordType::AXFR | RecordType::IXFR),
        "DoQ zone transfers are not implemented"
    );
    let mut message = Message::new();
    message
        .set_id(0)
        .set_recursion_desired(data["recursion_desired"].as_bool().unwrap_or(true))
        .add_query(Query::query(Name::from_str(domain)?, kind));
    Ok(message)
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
                &DoqClientProtocol::new(),
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
    let outcome = match DoqClientProtocol::new().execute_action(action.clone()) {
        Ok(ClientActionResult::Disconnect) => Ok(ClientSendOutcome::Disconnected),
        Ok(ClientActionResult::WaitForMore | ClientActionResult::NoAction) => {
            Ok(ClientSendOutcome::Executed {
                detail: "Waiting for more queries".into(),
            })
        }
        Ok(ClientActionResult::Custom { name, data }) if name == "dns_query" => {
            if queries.len() >= MAX_STREAMS {
                Err(anyhow::anyhow!("DoQ client busy: 32 active transactions"))
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
        Ok(_) => Err(anyhow::anyhow!("Unsupported DoQ client action")),
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
            DoqClientProtocol::new().protocol_name(),
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
            let query = build_query(&data)?;
            exchange(&connection,&query,deadline).await
        }.await;
        let (outcome,event) = match result {
            Ok((message,stream)) => {
                let records = |records: &[hickory_proto::rr::Record]| records.iter().map(|r|json!({"name":r.name().to_utf8(),"type":r.record_type().to_string(),"class":r.dns_class().to_string(),"ttl":r.ttl(),"data":r.data().and_then(crate::utils::display::try_display)})).collect::<Vec<_>>();
                let event = Event::new(&DOQ_RESPONSE_EVENT,json!({"query_id":0,"stream_id":stream,"domain":data["domain"],"query_type":data["query_type"],"response_code":message.response_code().to_string(),"answers":records(message.answers()),"authorities":records(message.name_servers()),"additionals":records(message.additionals())}));
                (Ok(ClientSendOutcome::Executed{detail:format!("DNS {} ({} answers)",message.response_code(),message.answers().len())}),event)
            }
            Err(e) => {
                Log::new(Some(&ctx.status_tx)).warn(format!("DoQ query failed: {e:#}"));
                let event = Event::new(&DOQ_ERROR_EVENT,json!({"domain":data["domain"],"query_type":data["query_type"],"error":format!("{e:#}")}));
                (Err(e),event)
            }
        };
        record_action(&ctx,&action,&outcome).await;
        if let Some(command) = command { command_support::reply(command,outcome); }
        (depth,event)
    }.boxed()
}

/// Execute one ordinary DNS exchange. Deadline and cancellation cover open/write/read/FIN.
/// Public for transport validation and embedding; CLI actions use the same path.
pub async fn exchange(
    connection: &quinn::Connection,
    query: &Message,
    deadline: Duration,
) -> Result<(Message, u64)> {
    let frame = encode(query)?;
    let end = tokio::time::Instant::now() + deadline;
    let (send, recv) = tokio::time::timeout_at(end, connection.open_bi())
        .await
        .context("DoQ stream-open timeout")??;
    let mut streams = CancelStreams {
        send,
        recv,
        done: false,
    };
    let result = tokio::time::timeout_at(end, async {
        streams.send.write_all(&frame).await?;
        streams.send.finish()?;
        let frame = match streams.recv.read_to_end(MAX_FRAME_BYTES).await {
            Ok(frame) => frame,
            Err(quinn::ReadToEndError::TooLong) => {
                connection.close(PROTOCOL_ERROR, b"DoQ response too large");
                bail!("DoQ response exceeds the DNS message limit");
            }
            Err(e) => return Err(e.into()),
        };
        let response = match decode(&frame, MessageType::Response) {
            Ok(response) => response,
            Err(e) => {
                connection.close(PROTOCOL_ERROR, b"invalid DoQ response");
                return Err(e);
            }
        };
        if response.queries() != query.queries() || response.op_code() != query.op_code() {
            connection.close(PROTOCOL_ERROR, b"DoQ question or opcode mismatch");
            bail!("DoQ response question or opcode does not match the query");
        }
        Ok((response, u64::from(streams.recv.id())))
    })
    .await
    .context("DoQ query deadline exceeded")?;
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
            let _ = self.recv.stop(REQUEST_CANCELLED);
            let _ = self.send.reset(REQUEST_CANCELLED);
        }
    }
}
