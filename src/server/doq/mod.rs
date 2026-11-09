//! DNS over QUIC. All connection and stream futures are owned by the registered
//! accept task; aborting it drops them and closes the endpoint, with no detached I/O.
pub mod actions;
pub mod wire;

use crate::llm::action_helper::call_llm;
use crate::llm::actions::executor::ExecutionResult;
use crate::llm::ActionResult;
use crate::logging::emit::Log;
use crate::protocol::{Event, SpawnContext};
use crate::server::connection::ConnectionId;
use crate::server::dns::StreamQuery;
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

    /// One DNS transaction on one client-initiated bidirectional stream (RFC 9250 §4.2): read
    /// the query up to its FIN, answer it, send the answer and FIN. A STOP_SENDING from the
    /// client at any point before the answer goes out abandons the work (§4.3.1).
    async fn transaction(
        mut send: quinn::SendStream,
        mut recv: quinn::RecvStream,
        connection: &quinn::Connection,
        ctx: &SpawnContext,
        id: ConnectionId,
        exchange: Duration,
    ) {
        let log = Log::new(Some(&ctx.status_tx));
        let stream = recv.id();
        let end = tokio::time::Instant::now() + exchange;
        let ending = tokio::select! {
            _ = send.stopped() => {
                log.info(format!("DoQ stream {stream} decision=peer_cancelled"));
                // Dropping `send` after STOP_SENDING resets it with the client's own code.
                let _ = recv.stop(REQUEST_CANCELLED);
                return;
            }
            ending = Self::exchange(&mut recv, connection, ctx, id, end) => ending,
        };
        match ending {
            Ending::Reply(message) => {
                let frame = match frame(&message) {
                    Ok(frame) => frame,
                    Err(e) => {
                        log.error(format!(
                            "DoQ stream {stream} answer cannot be framed ({e}); resetting \
                             with DOQ_INTERNAL_ERROR decision=fail_closed_send_error"
                        ));
                        let _ = send.reset(INTERNAL_ERROR);
                        return;
                    }
                };
                // The answer is ready; the peer's flow control decides when it can go. A peer
                // that grants no credit does not keep the stream past this.
                let sent = tokio::time::timeout(RESPONSE_WRITE_TIMEOUT, async {
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
                    log.error(format!(
                        "DoQ stream {stream} answer not accepted by the peer within \
                         {RESPONSE_WRITE_TIMEOUT:?}; resetting with DOQ_INTERNAL_ERROR \
                         decision=fail_closed_send_error"
                    ));
                    let _ = send.reset(INTERNAL_ERROR);
                }
            }
            Ending::Reset(code) => {
                let _ = recv.stop(code);
                let _ = send.reset(code);
            }
            Ending::Closed => {}
        }
    }

    /// Read the query and decide what the stream ends with.
    async fn exchange(
        recv: &mut quinn::RecvStream,
        connection: &quinn::Connection,
        ctx: &SpawnContext,
        id: ConnectionId,
        end: tokio::time::Instant,
    ) -> Ending {
        let log = Log::new(Some(&ctx.status_tx));
        let stream = recv.id();
        let peer = connection.remote_address();
        let frame = match tokio::time::timeout_at(end, recv.read_to_end(MAX_FRAME_BYTES)).await {
            Ok(Ok(frame)) => frame,
            // RFC 9250 §4.3.1: a RESET_STREAM before the FIN abandons the transaction, and the
            // server answers it with a RESET_STREAM of its own. Other streams go on.
            Ok(Err(quinn::ReadToEndError::Read(quinn::ReadError::Reset(_)))) => {
                log.debug(format!(
                    "DoQ stream {stream} reset by {peer} before its query ended \
                     decision=peer_cancelled"
                ));
                return Ending::Reset(NO_ERROR);
            }
            // More bytes than one frame: a second message, or a length that lies (§4.3.3).
            // Flow control does not prevent it — quinn extends credit as the stream is read.
            Ok(Err(quinn::ReadToEndError::TooLong)) => {
                log.warn(format!(
                    "DoQ stream {stream} from {peer} carries more than one \
                     {MAX_FRAME_BYTES}-byte frame; closing with DOQ_PROTOCOL_ERROR \
                     decision=fail_closed_protocol_error"
                ));
                connection.close(PROTOCOL_ERROR, b"DoQ frame too large");
                return Ending::Closed;
            }
            Ok(Err(e)) => {
                log.debug(format!("DoQ stream {stream} from {peer} read failed: {e}"));
                return Ending::Reset(INTERNAL_ERROR);
            }
            Err(_) => {
                log.warn(format!(
                    "DoQ stream {stream} from {peer}: no complete query and FIN within the \
                     exchange deadline; resetting with DOQ_UNSPECIFIED_ERROR \
                     decision=fail_closed_read_timeout"
                ));
                return Ending::Reset(UNSPECIFIED_ERROR);
            }
        };
        // RFC 9250 §4.3.3: a non-zero id, a length that disagrees with the stream, a second
        // message and EDNS TCP keepalive are protocol errors, which close the connection.
        let query = match decode(&frame, MessageType::Query) {
            Ok(message) => message,
            Err(e) => {
                log.warn(format!(
                    "DoQ stream {stream} from {peer}: {e:#}; closing with DOQ_PROTOCOL_ERROR \
                     decision=fail_closed_protocol_error"
                ));
                connection.close(PROTOCOL_ERROR, b"invalid DoQ query");
                return Ending::Closed;
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
        let reply = StreamQuery::new(&query, "DoQ");
        match tokio::time::timeout_at(end, Self::answer(&query, &reply, ctx, id, stream, peer))
            .await
        {
            Ok(ending) => ending,
            // RFC 9250 §4.3.2: a server failure is a SERVFAIL on the stream, not a reset.
            Err(_) => {
                log.error(format!(
                    "DoQ stream {stream} from {peer}: not answered within the exchange \
                     deadline; answering SERVFAIL decision=fail_closed_timeout"
                ));
                reply
                    .servfail()
                    .map_or(Ending::Reset(INTERNAL_ERROR), Ending::Reply)
            }
        }
    }

    /// Answer a decoded query through the DNS server's own rules ([`StreamQuery`]).
    async fn answer(
        query: &Message,
        reply: &StreamQuery<'_>,
        ctx: &SpawnContext,
        id: ConnectionId,
        stream: quinn::StreamId,
        peer: SocketAddr,
    ) -> Ending {
        let log = Log::new(Some(&ctx.status_tx));
        let spec = |rcode, why: String| {
            reply
                .spec_reply(rcode, &why, peer, &log)
                .map_or(Ending::Reset(INTERNAL_ERROR), Ending::Reply)
        };
        if query.queries.is_empty() {
            return reply
                .formerr_without_question(peer, &log)
                .map_or(Ending::Reset(INTERNAL_ERROR), Ending::Reply);
        }
        if query.queries.len() > 1 {
            return spec(
                ResponseCode::FormErr,
                format!(
                    "{} questions in one query, and a DoQ stream answers one",
                    query.queries.len()
                ),
            );
        }
        let q = &query.queries[0];
        if query.op_code != OpCode::Query {
            return spec(
                ResponseCode::NotImp,
                format!("opcode {:?} is not implemented", query.op_code),
            );
        }
        if q.query_class() != DNSClass::IN {
            return spec(
                ResponseCode::NotImp,
                format!("class {} is not served", q.query_class()),
            );
        }
        if matches!(q.query_type(), RecordType::AXFR | RecordType::IXFR) {
            return spec(
                ResponseCode::NotImp,
                format!(
                    "{} zone transfer is not implemented over DoQ",
                    q.query_type()
                ),
            );
        }
        let event = Event::new(
            &DOQ_QUERY_EVENT,
            json!({
                "query_id": 0,
                "domain": q.name().to_string(),
                "query_type": q.query_type().to_string(),
                "query_class": q.query_class().to_string(),
                "recursion_desired": query.recursion_desired,
                "stream_id": u64::from(stream),
                "peer_addr": peer.to_string(),
            }),
        );
        log.debug(format!(
            "DoQ {} {} stream {stream} from {peer}",
            q.query_type(),
            q.name()
        ));
        log.trace(format!("DoQ query: {}", event.data));
        let result = call_llm(
            &ctx.llm_client,
            &ctx.state,
            ctx.server_id,
            Some(id),
            &event,
            &DoqProtocol::new(),
        )
        .await
        .map(|mut execution| {
            bind_to_query(&mut execution, query);
            execution
        });
        // The DNS server's rules decide what goes back: the first message an action produced,
        // finished (the OPT echoed for an EDNS query, SERVFAIL for an answer past 65535
        // octets); nothing for `ignore_query`, which on DoQ resets the stream with
        // DOQ_NO_ERROR so the transaction ends rather than dangles; SERVFAIL for a backend
        // failure and for an answer with nothing sendable in it. The id is zero because every
        // action's `query_id` is (`DoqProtocol::execute_action`), and `frame` refuses any other.
        match reply.answer(result, peer, id, &log) {
            Some(message) => Ending::Reply(message),
            None => {
                log.info(format!(
                    "DoQ stream {stream} answered with ignore_query; resetting with DOQ_NO_ERROR"
                ));
                Ending::Reset(NO_ERROR)
            }
        }
    }
}

/// Make every DNS message an action produced answer *this* stream's query: its question,
/// opcode and RD flag copied from the query (RFC 1035 §4.1.1), its id the query's zero
/// (RFC 9250 §4.2.1). An action builds its question from the `domain` and type the model
/// wrote, so without this an A action answering an ANY query carries an A question, which a
/// client that checks the question — NetGet's own DoQ client does — refuses as a protocol
/// error. Bytes that are not a DNS message are left alone for [`StreamQuery`] to refuse.
fn bind_to_query(execution: &mut ExecutionResult, query: &Message) {
    for result in &mut execution.protocol_results {
        let ActionResult::Output(bytes) = result else {
            continue;
        };
        let Ok(mut message) = crate::utils::dns_screen::decode_dns_message(bytes) else {
            continue;
        };
        message.metadata.id = 0;
        message.metadata.op_code = query.op_code;
        message.metadata.recursion_desired = query.recursion_desired;
        message.queries = query.queries.clone();
        if let Ok(bound) = message.to_vec() {
            *bytes = bound;
        }
    }
}

/// How a transaction's stream ends.
enum Ending {
    /// A DNS message to frame, send and FIN.
    Reply(Vec<u8>),
    /// STOP_SENDING and RESET_STREAM with this DoQ error code.
    Reset(quinn::VarInt),
    /// The connection is closed (a protocol error); there is no stream left to end.
    Closed,
}
