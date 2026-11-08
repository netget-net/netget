//! DNS over QUIC. All connection and stream futures are owned by the registered
//! accept task; aborting it drops them and closes the endpoint, with no detached I/O.
pub mod actions;
pub mod wire;

use crate::llm::action_helper::call_llm;
use crate::llm::ActionResult;
use crate::logging::emit::Log;
use crate::protocol::{Event, SpawnContext};
use crate::server::connection::ConnectionId;
use crate::state::server::{ConnectionState, ConnectionStatus, ProtocolConnectionInfo};
use actions::{DoqProtocol, DOQ_QUERY_EVENT};
use anyhow::{bail, Context, Result};
use futures::{stream::FuturesUnordered, StreamExt};
use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::{DNSClass, RecordType};
use serde_json::json;
use std::{net::SocketAddr, sync::Arc, time::Duration};
use wire::*;

#[derive(Clone)]
struct Settings {
    handshake: Duration,
    exchange: Duration,
    idle: Duration,
    connections: usize,
    streams: usize,
}
impl Settings {
    fn read(params: Option<&crate::protocol::StartupParams>) -> Result<Self> {
        Ok(Self {
            handshake: Duration::from_secs(bounded_parameter(
                params,
                "handshake_timeout_secs",
                HANDSHAKE_TIMEOUT.as_secs(),
                60,
            )?),
            exchange: Duration::from_secs(bounded_parameter(
                params,
                "exchange_timeout_secs",
                EXCHANGE_TIMEOUT.as_secs(),
                300,
            )?),
            idle: Duration::from_secs(bounded_parameter(
                params,
                "idle_timeout_secs",
                IDLE_TIMEOUT.as_secs(),
                3600,
            )?),
            connections: bounded_parameter(params, "max_connections", MAX_CONNECTIONS as u64, 256)?
                as usize,
            streams: bounded_parameter(
                params,
                "max_streams",
                MAX_STREAMS as u64,
                MAX_STREAMS as u64,
            )? as usize,
        })
    }
}

pub struct DoqServer;
impl DoqServer {
    pub async fn spawn(ctx: SpawnContext) -> Result<SocketAddr> {
        let bind = ctx.legacy_listen_addr();
        if bind.port() == 53 {
            bail!("RFC 9250 forbids DoQ on UDP port 53");
        }
        let settings = Settings::read(ctx.startup_params.as_ref())?;
        let cert = ctx
            .startup_params
            .as_ref()
            .map(|p| p.get_optional_string("cert_path"))
            .transpose()?
            .flatten();
        let key = ctx
            .startup_params
            .as_ref()
            .map(|p| p.get_optional_string("key_path"))
            .transpose()?
            .flatten();
        let _ = rustls::crypto::ring::default_provider().install_default();
        let tls = match (cert, key) {
            (Some(cert), Some(key)) => {
                crate::server::tls_cert_manager::load_tls_config_from_files(&cert, &key)?
            }
            (None, None) => crate::server::tls_cert_manager::generate_default_tls_config()?,
            _ => bail!("DoQ cert_path and key_path must be supplied together"),
        };
        let mut crypto = (*tls).clone();
        crypto.alpn_protocols = vec![b"doq".to_vec()];
        crypto.max_early_data_size = 0;
        let mut config = quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(crypto)?,
        ));
        config.transport_config(transport(settings.idle, settings.streams as u32));
        // Disable migration: this endpoint is a simulator, not a mobile resolver session.
        config.migration(false);
        let endpoint =
            EndpointGuard(quinn::Endpoint::server(config, bind).context("Bind DoQ UDP endpoint")?);
        let local = endpoint.0.local_addr()?;
        Log::new(Some(&ctx.status_tx)).info(format!("DoQ listening on {local}"));
        let state = ctx.state.clone();
        let id = ctx.server_id;
        let task = tokio::spawn(async move {
            let mut sessions = FuturesUnordered::new();
            loop {
                tokio::select! {
                    incoming = endpoint.0.accept() => {
                        let Some(incoming) = incoming else { break; };
                        if sessions.len() >= settings.connections {
                            incoming.refuse();
                            Log::new(Some(&ctx.status_tx)).warn("DoQ connection limit reached");
                            continue;
                        }
                        sessions.push(Self::session(incoming, ctx.clone(), settings.clone(), local));
                    }
                    _ = sessions.next(), if !sessions.is_empty() => {}
                }
            }
        });
        state.register_server_task(id, task).await;
        Ok(local)
    }

    async fn session(
        incoming: quinn::Incoming,
        ctx: SpawnContext,
        settings: Settings,
        local: SocketAddr,
    ) {
        let connection = match tokio::time::timeout(settings.handshake, incoming).await {
            Ok(Ok(c)) => ConnectionGuard(c),
            _ => return,
        };
        let id = ConnectionId::new(ctx.state.get_next_unified_id().await);
        let now = crate::utils::clock::Instant::now();
        ctx.state
            .add_connection_to_server(
                ctx.server_id,
                ConnectionState {
                    id,
                    remote_addr: connection.0.remote_address(),
                    local_addr: local,
                    bytes_sent: 0,
                    bytes_received: 0,
                    packets_sent: 0,
                    packets_received: 0,
                    last_activity: now,
                    status: ConnectionStatus::Active,
                    status_changed_at: now,
                    protocol_info: ProtocolConnectionInfo::new(json!({"alpn":"doq"})),
                },
            )
            .await;
        let _ = ctx.status_tx.send("__UPDATE_UI__".into());
        let mut streams = FuturesUnordered::new();
        loop {
            tokio::select! {
                result = connection.0.accept_bi(), if streams.len() < settings.streams => {
                    match result {
                        Ok((send,recv)) => streams.push(Self::transaction(send,recv,&connection.0,&ctx,id,settings.exchange)),
                        Err(_) => break,
                    }
                }
                _ = connection.0.closed() => break,
                _ = streams.next(), if !streams.is_empty() => {}
            }
        }
        // Dropping these futures cancels handlers and resets any unfinished responses.
        drop(streams);
        ctx.state
            .close_connection_on_server(ctx.server_id, id)
            .await;
        let _ = ctx.status_tx.send("__UPDATE_UI__".into());
    }

    async fn transaction(
        mut send: quinn::SendStream,
        mut recv: quinn::RecvStream,
        connection: &quinn::Connection,
        ctx: &SpawnContext,
        id: ConnectionId,
        deadline: Duration,
    ) {
        let end = tokio::time::Instant::now() + deadline;
        let exchange = async {
            let frame = match recv.read_to_end(MAX_FRAME_BYTES).await {
                Ok(frame) => frame,
                // Reset by the client is cancellation, not malformed input. Other
                // streams continue on the same connection.
                Err(quinn::ReadToEndError::Read(quinn::ReadError::Reset(_))) => return Ok(None),
                Err(quinn::ReadToEndError::TooLong) => {
                    connection.close(PROTOCOL_ERROR, b"DoQ frame too large");
                    return Ok(None);
                }
                Err(e) => return Err(anyhow::Error::from(e)),
            };
            let query = match decode(&frame, MessageType::Query) {
                Ok(message) => message,
                Err(_) => {
                    connection.close(PROTOCOL_ERROR, b"invalid DoQ query");
                    return Ok(None);
                }
            };
            ctx.state
                .update_connection_stats(
                    ctx.server_id,
                    id,
                    Some(frame.len() as u64),
                    None,
                    Some(1),
                    None,
                )
                .await;
            let response = if query.queries.len() != 1 {
                error_response(&query, ResponseCode::FormErr)
            } else if query.op_code != OpCode::Query
                || query.queries[0].query_class() != DNSClass::IN
                || !matches!(
                    query.queries[0].query_type(),
                    RecordType::A
                        | RecordType::AAAA
                        | RecordType::MX
                        | RecordType::TXT
                        | RecordType::CNAME
                        | RecordType::ANY
                )
            {
                error_response(&query, ResponseCode::NotImp)
            } else {
                let q = &query.queries[0];
                let event = Event::new(
                    &DOQ_QUERY_EVENT,
                    json!({
                        "query_id":0,"domain":q.name().to_utf8(),"query_type":q.query_type().to_string(),
                        "query_class":q.query_class().to_string(),"recursion_desired":query.recursion_desired,
                        "stream_id":u64::from(recv.id()),"peer_addr":connection.remote_address().to_string(),
                    }),
                );
                Log::new(Some(&ctx.status_tx)).debug(format!(
                    "DoQ {} {} stream {}",
                    q.query_type(),
                    q.name(),
                    recv.id()
                ));
                Log::new(Some(&ctx.status_tx)).trace(format!("DoQ query: {}", event.data));
                match call_llm(
                    &ctx.llm_client,
                    &ctx.state,
                    ctx.server_id,
                    Some(id),
                    &event,
                    &DoqProtocol::new(),
                )
                .await
                {
                    Ok(result) => {
                        if !result.failures.is_empty() {
                            Log::new(Some(&ctx.status_tx)).error(format!(
                                "DoQ stream {} decision=fail_closed_action_error: {} action(s) failed; answering SERVFAIL",
                                recv.id(), result.failures.len()
                            ));
                            return Ok(Some(encode(&error_response(
                                &query,
                                ResponseCode::ServFail,
                            ))?));
                        }
                        for message in result.messages {
                            Log::new(Some(&ctx.status_tx)).info(message);
                        }
                        let mut messages = Vec::new();
                        for result in result.protocol_results {
                            if let ActionResult::Output(bytes) = result {
                                messages.push(Message::from_vec(&bytes)?);
                            }
                        }
                        if messages.is_empty() {
                            Log::new(Some(&ctx.status_tx)).info(format!(
                                "DoQ stream {} decision=model_silent; cancelling query with DOQ_NO_ERROR",
                                recv.id()
                            ));
                            // A dropped query is an explicit transaction cancellation, not an
                            // empty DNS stream or an indefinitely dangling request.
                            return Ok(None);
                        }
                        let mut response = messages.remove(0);
                        for message in messages {
                            response.add_answers(message.answers.iter().cloned());
                        }
                        response.metadata.id = 0;
                        response.metadata.message_type = MessageType::Response;
                        response.metadata.op_code = query.op_code;
                        response.metadata.recursion_desired = query.recursion_desired;
                        response.queries = query.queries.to_vec();
                        let decision = if matches!(
                            response.response_code,
                            ResponseCode::NXDomain | ResponseCode::Refused
                        ) {
                            "model_reject"
                        } else {
                            "model_answer"
                        };
                        Log::new(Some(&ctx.status_tx)).info(format!(
                            "DoQ stream {} decision={decision} rcode={}",
                            recv.id(),
                            response.response_code
                        ));
                        response
                    }
                    Err(e) => {
                        let category = if crate::utils::WireFailure::classify(&e).is_overloaded() {
                            "overloaded"
                        } else {
                            "unavailable"
                        };
                        Log::new(Some(&ctx.status_tx)).error(format!(
                            "DoQ stream {} decision=fail_closed_llm_error category={category}; answering SERVFAIL: {e}", recv.id()
                        ));
                        error_response(&query, ResponseCode::ServFail)
                    }
                }
            };
            Ok::<_, anyhow::Error>(Some(encode(&response)?))
        };
        // While a handler runs, STOP_SENDING promptly drops the work rather than
        // retaining its LLM request until the exchange deadline.
        let result = tokio::select! {
            _ = send.stopped() => {
                Log::new(Some(&ctx.status_tx)).info(format!("DoQ decision=peer_cancelled stream {}", send.id()));
                let _ = recv.stop(REQUEST_CANCELLED); return;
            }
            result = tokio::time::timeout_at(end, exchange) => result,
        };
        match result {
            Ok(Ok(Some(frame))) => {
                let sent = tokio::time::timeout_at(end, async {
                    send.write_all(&frame).await?;
                    send.finish()?;
                    Ok::<_, anyhow::Error>(())
                })
                .await;
                if matches!(sent, Ok(Ok(()))) {
                    ctx.state
                        .update_connection_stats(
                            ctx.server_id,
                            id,
                            None,
                            Some(frame.len() as u64),
                            None,
                            Some(1),
                        )
                        .await;
                } else {
                    Log::new(Some(&ctx.status_tx)).error(format!(
                        "DoQ stream {} decision=fail_closed_send_error; resetting stream",
                        send.id()
                    ));
                    let _ = send.reset(INTERNAL_ERROR);
                }
            }
            Ok(Ok(None)) => {
                let _ = send.reset(NO_ERROR);
            }
            Ok(Err(e)) => {
                Log::new(Some(&ctx.status_tx)).error(format!(
                    "DoQ stream {} decision=fail_closed_response_error: {e}",
                    send.id()
                ));
                let _ = send.reset(INTERNAL_ERROR);
            }
            Err(_) => {
                Log::new(Some(&ctx.status_tx)).error(format!(
                    "DoQ stream {} decision=fail_closed_timeout; resetting stream",
                    send.id()
                ));
                let _ = recv.stop(UNSPECIFIED_ERROR);
                let _ = send.reset(UNSPECIFIED_ERROR);
            }
        }
    }
}

fn error_response(query: &Message, code: ResponseCode) -> Message {
    let mut response = Message::new(0, MessageType::Response, query.op_code);
    response.metadata.recursion_desired = query.recursion_desired;
    response.metadata.response_code = code;
    response.add_queries(query.queries.iter().cloned());
    response
}
