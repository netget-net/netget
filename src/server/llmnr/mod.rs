//! LLMNR (RFC 4795) responder.
//!
//! LLMNR is DNS's message format on a link-local multicast group, with one rule that inverts
//! everything the DNS server in this repo does: **a responder answers only for the names it
//! owns, and says nothing at all for anything else.** RFC 4795 §2.1.1 spells out why NXDOMAIN
//! is not available — "LLMNR responders MUST NOT respond with an RCODE of 3; instead, they
//! should not respond at all" — because on a shared link the host that *does* own the name
//! still has to be able to answer, and a negative answer from a bystander would race it.
//!
//! That makes this protocol a member of the deliberately-silent class the root `CLAUDE.md`
//! catalogues, and its case is the strongest of them. An LLMNR response is not a message the
//! peer reads and discards: it is a name-to-address binding written straight into the
//! querier's resolver cache. **A fabricated answer is cache poisoning.** So when the model
//! cannot be reached, or answers with nothing usable, this server writes zero bytes — and puts
//! the distinction in the log instead, exactly as `src/server/radius/` does, so an operator can
//! tell a refusal from an outage after the fact.
//!
//! See `src/server/llmnr/CLAUDE.md` for the design notes, the RFC deviations and what is
//! unverified.

pub mod actions;

use crate::llm::action_helper::call_llm;
use crate::llm::ollama_client::OllamaClient;
use crate::logging::emit::Log;
use crate::protocol::{Event, SpawnContext};
use crate::server::connection::ConnectionId;
use crate::state::app_state::AppState;
use crate::state::ServerId;
use actions::{LlmnrProtocol, LLMNR_IPV4_GROUP, LLMNR_IPV6_GROUP, LLMNR_QUERY_EVENT};
use anyhow::{Context, Result};
use hickory_proto::op::{MessageType, OpCode};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tracing::{debug, error, info, trace, warn};

/// Largest LLMNR message this server will read.
///
/// LLMNR has no EDNS0 negotiation, but the DNS message format allows up to 64 KiB over TCP.
/// 4 KiB covers every query a name resolver produces and bounds a hostile datagram.
pub const MAX_MESSAGE_LEN: usize = 4096;

/// How long a TCP querier may hold a connection open without sending anything.
///
/// RFC 4795 §2.4's TCP path is a single question and a single answer; there is no session to
/// keep alive. Without a deadline, a peer that connects and then says nothing parks a task
/// that `register_server_task` can never prune, because it never finishes — so N idle
/// connections cost N permanent tasks and N file descriptors for a protocol that has no
/// concept of an idle connection. Thirty seconds is far longer than any real querier waits
/// and short enough that the cost of a stalled peer is bounded.
const TCP_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Concurrent TCP connections this responder admits before it starts refusing.
///
/// [`crate::server::accept_bounded::DEFAULT_MAX_CONNECTIONS`]. [`TCP_IDLE_TIMEOUT`] bounds how
/// long one silent querier holds a slot; only a cap bounds how many of them there can be at
/// once, and thirty seconds times an unbounded arrival rate is still unbounded.
///
/// The house default is *generous* here rather than tight, and deliberately so. LLMNR's TCP
/// path is the rare one — RFC 4795 §2.4 reaches for it only for a unicast query or a response
/// that would not fit a datagram — so this listener should normally have a handful of
/// connections at most, and a number like 16 would be defensible on traffic alone. It is not
/// defensible on *failure*: the cap's job is to bound what a stranger can pin, and a low cap
/// on a rarely-used side channel is a cheap way for that stranger to deny the TCP path to the
/// legitimate querier who actually needed it. 256 bounded connections is still bounded, and it
/// does not turn the cap into the outage.
const MAX_CONNECTIONS: usize = crate::server::accept_bounded::DEFAULT_MAX_CONNECTIONS;

/// A peer over [`MAX_CONNECTIONS`] gets a **plain close**, with nothing written.
///
/// LLMNR's only server message is a DNS response, and every DNS response is an answer to a
/// question it must echo back: RFC 4795 §2.4 requires the responder to copy the query's ID and
/// its question section, and §2.1 has the querier silently discard anything whose ID and
/// question do not match one it has outstanding. A peer refused at the accept has sent no
/// query, so a fabricated response would be dropped as unmatched — the querier would learn
/// nothing and wait out its own timeout, which is strictly worse than the immediate EOF it
/// gets here.
///
/// Silence is also what this protocol does everywhere else: RFC 4795 has responders *silently*
/// discard queries they cannot or must not answer, so an LLMNR querier already treats "nothing
/// came back" as the normal negative outcome and falls back to its next resolution mechanism.
/// The refusal is logged with `decision=fail_closed_connection_cap`, which is the diagnosis.
const CONNECTION_CAP_REFUSAL: &[u8] = b"";

/// How this responder arrived at what it did (or did not) put on the wire.
///
/// The whole point of this enum is that **"the model said stay silent" and "the model could
/// not be reached" produce identical bytes on the wire — nothing — and must never be
/// identical in the log.** That collapse is the OAuth2 failure the root `CLAUDE.md` records,
/// and here it would hide a backend outage as protocol-correct silence forever.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// The model answered with a record. Bytes went out.
    ModelResponse,
    /// The model chose `no_response`: this host does not own the name. Correct silence.
    ModelSilent,
    /// The model chose `send_llmnr_error`, i.e. an explicit non-zero RCODE refusal.
    ModelReject,
    /// The model's `send_llmnr_error` could not be sent because the query arrived over UDP,
    /// where RFC 4795 §2.1.1 requires RCODE 0. Silence, and the model's intent recorded.
    ModelRejectSuppressed,
    /// The model returned no usable action at all. The server stays silent.
    FailClosedNoAction,
    /// The model produced actions but none of them encoded. The server stays silent.
    FailClosedActionError,
    /// The LLM call itself failed — outage, overload, unusable output. The server stays silent.
    FailClosedLlmError,
}

impl Decision {
    /// Stable, grep-able token. An operator looking for requests the model did not actually
    /// answer greps `decision=fail_closed_`.
    pub fn as_str(&self) -> &'static str {
        match self {
            Decision::ModelResponse => "model_response",
            Decision::ModelSilent => "model_silent",
            Decision::ModelReject => "model_reject",
            Decision::ModelRejectSuppressed => "model_reject_suppressed_udp",
            Decision::FailClosedNoAction => "fail_closed_no_action",
            Decision::FailClosedActionError => "fail_closed_action_error",
            Decision::FailClosedLlmError => "fail_closed_llm_error",
        }
    }

    /// True when the *server*, not the model, chose to say nothing.
    pub fn is_fail_closed(&self) -> bool {
        matches!(
            self,
            Decision::FailClosedNoAction
                | Decision::FailClosedActionError
                | Decision::FailClosedLlmError
        )
    }
}

/// Which transport a query arrived on. It decides whether a non-zero RCODE may be returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Transport {
    Udp,
    Tcp,
}

impl Transport {
    fn as_str(self) -> &'static str {
        match self {
            Transport::Udp => "udp",
            Transport::Tcp => "tcp",
        }
    }
}

/// Everything a query handler needs, gathered so the handler is not an eight-argument
/// function repeated on two code paths.
#[derive(Clone)]
struct Responder {
    llm_client: OllamaClient,
    state: Arc<AppState>,
    status_tx: mpsc::UnboundedSender<String>,
    server_id: ServerId,
    local_addr: SocketAddr,
}

pub struct LlmnrServer;

impl LlmnrServer {
    /// Bind the responder and start serving.
    ///
    /// Returns `Err` if the UDP socket cannot be bound, so `server_startup` marks the instance
    /// `ServerStatus::Error` rather than showing a responder that is not listening. The two
    /// optional extras — the multicast group join and the TCP listener — are best-effort and
    /// logged: neither is required to answer a query sent straight to this port, and on macOS
    /// a loopback multicast join routinely fails for reasons that have nothing to do with
    /// whether the server works.
    pub async fn spawn_with_llm_actions(ctx: SpawnContext) -> Result<SocketAddr> {
        let listen_addr = ctx.legacy_listen_addr();
        let SpawnContext {
            llm_client,
            state,
            status_tx,
            server_id,
            startup_params,
            ..
        } = ctx;

        // Startup parameters. Every accessor is fallible because the values come from the
        // model or an MCP client; propagate with `?` so an undeclared key or a wrong type
        // produces a clean startup error instead of a panic in the spawning task.
        let (join_multicast, multicast_interface, enable_tcp) = match startup_params {
            Some(params) => (
                params.get_optional_bool("join_multicast")?.unwrap_or(true),
                params.get_optional_string("multicast_interface")?,
                params.get_optional_bool("enable_tcp")?.unwrap_or(true),
            ),
            None => (true, None, true),
        };

        let socket = Arc::new(
            UdpSocket::bind(listen_addr)
                .await
                .with_context(|| format!("LLMNR failed to bind UDP {}", listen_addr))?,
        );
        let local_addr = socket
            .local_addr()
            .context("LLMNR could not read its own UDP address")?;

        let log = Log::new(Some(&status_tx));
        log.info(format!("LLMNR responder listening on {}", local_addr));
        info!("LLMNR responder listening on UDP {}", local_addr);

        if join_multicast {
            join_llmnr_group(
                &socket,
                local_addr,
                multicast_interface.as_deref(),
                &status_tx,
            );
        } else {
            debug!("LLMNR multicast join skipped (join_multicast=false)");
        }

        let responder = Responder {
            llm_client,
            state: state.clone(),
            status_tx: status_tx.clone(),
            server_id,
            local_addr,
        };

        // UDP receive loop.
        let udp_responder = responder.clone();
        let udp_socket = socket.clone();
        let udp_handle = tokio::spawn(async move {
            let mut buffer = vec![0u8; MAX_MESSAGE_LEN];
            loop {
                let (n, peer_addr) = match udp_socket.recv_from(&mut buffer).await {
                    Ok(pair) => pair,
                    Err(e) => {
                        Log::new(Some(&udp_responder.status_tx))
                            .error(format!("LLMNR UDP receive error: {}", e));
                        break;
                    }
                };

                let data = buffer[..n].to_vec();
                let sink = UdpSink {
                    socket: udp_socket.clone(),
                    peer: peer_addr,
                };
                let r = udp_responder.clone();
                let task = tokio::spawn(async move {
                    r.handle_query(data, peer_addr, Transport::Udp, Some(sink))
                        .await;
                });
                // Register even these short-lived tasks: `register_server_task` prunes the
                // finished ones on every call, so the list stays bounded, and `stop_server`
                // cancels an in-flight LLM call instead of letting it answer after the socket
                // is gone. Aborting the accept loop alone does not abort what it spawned.
                udp_responder
                    .state
                    .register_server_task(server_id, task)
                    .await;
            }
        });
        state.register_server_task(server_id, udp_handle).await;

        // TCP listener. RFC 4795 §2.4 requires responders to support TCP queries, and it is
        // the only transport on which a non-zero RCODE may be returned. Best-effort: the UDP
        // responder is the protocol's main path and must not be lost to a port collision on
        // the TCP side (the ephemeral port UDP was given may already be held by a TCP socket).
        if enable_tcp {
            match TcpListener::bind(SocketAddr::new(local_addr.ip(), local_addr.port())).await {
                Ok(listener) => {
                    info!("LLMNR also listening on TCP {}", local_addr);
                    let tcp_responder = responder.clone();
                    let limiter =
                        crate::server::accept_bounded::ConnectionLimiter::new(MAX_CONNECTIONS);
                    let tcp_handle = tokio::spawn(async move {
                        loop {
                            let (stream, peer_addr, permit) =
                                match crate::server::accept_bounded::accept_bounded(
                                    &listener,
                                    &limiter,
                                    CONNECTION_CAP_REFUSAL,
                                    "LLMNR",
                                    Some(&tcp_responder.status_tx),
                                )
                                .await
                                {
                                    Ok(triple) => triple,
                                    Err(e) => {
                                        Log::new(Some(&tcp_responder.status_tx))
                                            .error(format!("LLMNR TCP accept error: {}", e));
                                        break;
                                    }
                                };
                            let r = tcp_responder.clone();
                            let task = tokio::spawn(async move {
                                // Released when this task ends, and this task is the whole of
                                // the connection — `serve_tcp_connection` spawns nothing — so
                                // `MAX_CONNECTIONS` caps live connections rather than accepts.
                                let _permit = permit;
                                r.serve_tcp_connection(stream, peer_addr).await;
                            });
                            tcp_responder
                                .state
                                .register_server_task(server_id, task)
                                .await;
                        }
                    });
                    state.register_server_task(server_id, tcp_handle).await;
                }
                Err(e) => {
                    // Not fatal, but not hidden either: a responder that silently lacks TCP
                    // cannot serve the queries RFC 4795 §2.4 sends over TCP, and the operator
                    // should know which half is missing.
                    warn!(
                        "LLMNR could not bind TCP {}: {}; UDP queries are still answered, \
                         TCP queries are not",
                        local_addr, e
                    );
                    log.warn(format!(
                        "LLMNR TCP listener unavailable on {} ({}); UDP only",
                        local_addr, e
                    ));
                }
            }
        } else {
            debug!("LLMNR TCP listener disabled (enable_tcp=false)");
        }

        Ok(local_addr)
    }
}

/// Where a UDP response goes back to. `None` means TCP, whose reply is written by the
/// connection loop because that is what owns the stream.
struct UdpSink {
    socket: Arc<UdpSocket>,
    peer: SocketAddr,
}

impl Responder {
    /// Serve one TCP connection.
    ///
    /// RFC 4795 §2.4 carries unicast queries over TCP with the RFC 1035 §4.2.2 two-byte
    /// length prefix, and requires the response to go back on the same connection.
    async fn serve_tcp_connection(&self, mut stream: TcpStream, peer_addr: SocketAddr) {
        loop {
            let mut len_buf = [0u8; 2];
            // Every read is bounded. A peer that opens a connection and then goes quiet —
            // between frames, or half way through one — must not hold this task forever; see
            // TCP_IDLE_TIMEOUT.
            match tokio::time::timeout(TCP_IDLE_TIMEOUT, stream.read_exact(&mut len_buf)).await {
                Ok(Ok(_)) => {}
                // EOF or a half-written frame: the querier is done. Not an error.
                Ok(Err(_)) => break,
                Err(_) => {
                    debug!(
                        "LLMNR closing an idle TCP connection from {} after {:?}",
                        peer_addr, TCP_IDLE_TIMEOUT
                    );
                    break;
                }
            }
            let len = u16::from_be_bytes(len_buf) as usize;
            if len == 0 || len > MAX_MESSAGE_LEN {
                warn!(
                    "LLMNR dropping TCP query from {}: length prefix {} is out of range",
                    peer_addr, len
                );
                break;
            }

            let mut data = vec![0u8; len];
            match tokio::time::timeout(TCP_IDLE_TIMEOUT, stream.read_exact(&mut data)).await {
                Ok(Ok(_)) => {}
                Ok(Err(_)) => break,
                Err(_) => {
                    warn!(
                        "LLMNR closing a TCP connection from {}: {} octets were announced but \
                         did not arrive within {:?}",
                        peer_addr, len, TCP_IDLE_TIMEOUT
                    );
                    break;
                }
            }

            let outcome = self
                .handle_query(data, peer_addr, Transport::Tcp, None)
                .await;

            let Some((reply, connection_id)) = outcome else {
                continue;
            };
            let mut framed = Vec::with_capacity(reply.len() + 2);
            // A message longer than u16::MAX cannot be framed; the encoder never produces
            // one from a single answer record, but truncating the prefix would desynchronise
            // the connection permanently rather than fail visibly.
            let Ok(prefix) = u16::try_from(reply.len()) else {
                error!(
                    "LLMNR TCP response to {} is {} bytes, too long to frame",
                    peer_addr,
                    reply.len()
                );
                break;
            };
            framed.extend_from_slice(&prefix.to_be_bytes());
            framed.extend_from_slice(&reply);

            if let Err(e) = stream.write_all(&framed).await {
                Log::new(Some(&self.status_tx)).error(format!(
                    "LLMNR failed to reply over TCP to {}: {}",
                    peer_addr, e
                ));
                break;
            }
            trace!(
                "LLMNR sent {} framed bytes to {} over TCP",
                framed.len(),
                peer_addr
            );
            self.count_sent_for(connection_id, framed.len()).await;
        }
    }

    /// Parse, validate, ask the model, decide, and — when `sink` is a UDP peer — send.
    ///
    /// Returns the bytes to write, plus the connection entry to count them against, for the
    /// TCP path, which owns its stream.
    async fn handle_query(
        &self,
        data: Vec<u8>,
        peer_addr: SocketAddr,
        transport: Transport,
        sink: Option<UdpSink>,
    ) -> Option<(Vec<u8>, ConnectionId)> {
        let log = Log::new(Some(&self.status_tx));
        trace!(
            "LLMNR {} bytes from {} over {}: {}",
            data.len(),
            peer_addr,
            transport.as_str(),
            hex::encode(&data)
        );

        let query = match crate::utils::dns_screen::decode_dns_message(&data) {
            Ok(m) => m,
            Err(e) => {
                // A malformed datagram on a multicast group is normal background noise, not
                // an error worth the status stream.
                debug!(
                    "LLMNR dropped unparseable message from {}: {}",
                    peer_addr, e
                );
                return None;
            }
        };

        // RFC 4795 §2.1.1 discard rules. Each of these is "silently discard", so none of them
        // reaches the model and none of them produces a packet.
        if query.message_type() != MessageType::Query {
            debug!("LLMNR dropped a response (not a query) from {}", peer_addr);
            return None;
        }
        if query.op_code() != OpCode::Query {
            debug!(
                "LLMNR dropped query from {}: unsupported OPCODE {:?}",
                peer_addr,
                query.op_code()
            );
            return None;
        }
        if query.queries().len() != 1 {
            debug!(
                "LLMNR dropped query from {}: QDCOUNT is {}, must be 1",
                peer_addr,
                query.queries().len()
            );
            return None;
        }

        let question = &query.queries()[0];
        let name = question.name().to_string();
        let query_type = question.query_type().to_string();
        let query_class = question.query_class().to_string();
        let transaction_id = query.id();

        let connection_id = self.record_connection(peer_addr, data.len()).await;
        let _ = self.status_tx.send("__UPDATE_UI__".to_string());

        debug!(
            "LLMNR query id={} {} {} {} from {} over {}",
            transaction_id,
            name,
            query_class,
            query_type,
            peer_addr,
            transport.as_str()
        );

        let event = Event::new(
            &LLMNR_QUERY_EVENT,
            serde_json::json!({
                "transaction_id": transaction_id,
                "name": name,
                "query_type": query_type,
                "query_class": query_class,
                "source_address": peer_addr.to_string(),
                "transport": transport.as_str(),
                "conflict": actions::conflict_bit(&query),
                "tentative": actions::tentative_bit(&query),
            }),
        );

        let protocol = LlmnrProtocol::new();
        let llm_outcome = call_llm(
            &self.llm_client,
            &self.state,
            self.server_id,
            None,
            &event,
            &protocol,
        )
        .await;

        let (decision, reply) = self.decide(llm_outcome, transport, peer_addr);

        // Log the decision before acting on it. `model_silent` and every `fail_closed_*`
        // produce the same zero bytes on the wire, so this line is the only place the
        // difference survives.
        let summary = format!(
            "LLMNR {} {} from {} decision={}",
            query_type,
            name,
            peer_addr,
            decision.as_str()
        );
        if decision.is_fail_closed() {
            // Loud: nothing was written, and the reason was ours, not the protocol's.
            error!(
                "{} (nothing sent: no usable answer was produced; a guessed LLMNR record \
                 would poison the querier's name cache)",
                summary
            );
            log.error(format!(
                "{} - staying silent rather than guessing a name binding",
                summary
            ));
        } else {
            log.info(&summary);
        }

        let reply = reply?;

        let Some(udp) = sink else {
            // TCP: the connection loop writes it, framed, on the same connection.
            return Some((reply, connection_id));
        };

        match udp.socket.send_to(&reply, udp.peer).await {
            Ok(sent) => {
                trace!(
                    "LLMNR sent {} bytes to {}: {}",
                    sent,
                    udp.peer,
                    hex::encode(&reply)
                );
                self.count_sent_for(connection_id, sent).await;
                log.debug(format!("LLMNR sent {} bytes to {}", sent, udp.peer));
            }
            Err(e) => {
                Log::new(Some(&self.status_tx))
                    .error(format!("LLMNR failed to reply to {}: {}", udp.peer, e));
            }
        }
        None
    }

    /// **The fail-closed rule: nothing usable means nothing on the wire.**
    ///
    /// Every other UDP protocol in this repo answers a failure with an error frame, because
    /// silence costs the client its own timeout. LLMNR is the case where that trade inverts.
    /// Its only error frame is a non-zero RCODE, which RFC 4795 forbids in response to a
    /// multicast query — and its success frame is a cache entry, so inventing one on a backend
    /// outage would hand every querier on the link a binding that no host actually claims.
    /// A querier that hears nothing simply asks the next responder, which is exactly what the
    /// protocol is designed for.
    fn decide(
        &self,
        llm_outcome: Result<crate::llm::ExecutionResult>,
        transport: Transport,
        peer_addr: SocketAddr,
    ) -> (Decision, Option<Vec<u8>>) {
        let log = Log::new(Some(&self.status_tx));

        let execution = match llm_outcome {
            Ok(result) => {
                for message in &result.messages {
                    log.info(message);
                }
                result
            }
            Err(e) => {
                // The error is classified for the log and never rendered onto the wire —
                // there is no wire text here at all, but the category is still what tells an
                // operator whether to wait or to look.
                let category = match crate::utils::wire_failure::WireFailure::classify(&e) {
                    crate::utils::wire_failure::WireFailure::Overloaded => "overloaded",
                    crate::utils::wire_failure::WireFailure::Unavailable => "unavailable",
                };
                error!(
                    "LLMNR LLM call failed for {} (category={}): {}",
                    peer_addr, category, e
                );
                return (Decision::FailClosedLlmError, None);
            }
        };

        // Take the first output that parses as an LLMNR response. Extra outputs are a model
        // error: one query gets one response, and a second datagram would look to the querier
        // like a second responder claiming the same name (which sets its C bit).
        let mut chosen: Option<Vec<u8>> = None;
        let mut extra = 0usize;
        for protocol_result in &execution.protocol_results {
            for output in protocol_result.get_all_output() {
                if chosen.is_none() {
                    chosen = Some(output);
                } else {
                    extra += 1;
                }
            }
        }
        if extra > 0 {
            warn!(
                "LLMNR ignored {} extra output(s) for the query from {}; one query gets one \
                 response",
                extra, peer_addr
            );
        }

        if let Some(bytes) = chosen {
            // Classify by what is actually in the packet rather than by which action name the
            // model used: the bytes are what the querier will act on.
            let rcode = bytes.get(3).map(|b| b & 0x0F).unwrap_or(0);
            if rcode == 0 {
                return (Decision::ModelResponse, Some(bytes));
            }
            // RFC 4795 §2.1.1: "The response to a multicast LLMNR query MUST have RCODE set
            // to zero." This server cannot distinguish a unicast UDP datagram from a
            // multicast one without IP_PKTINFO, so it applies the stricter rule to all UDP
            // and drops the error rather than risk an illegal response.
            if transport == Transport::Udp {
                warn!(
                    "LLMNR suppressed an RCODE {} response to {}: a response to a UDP query \
                     must carry RCODE 0 (RFC 4795 2.1.1); use no_response instead",
                    rcode, peer_addr
                );
                return (Decision::ModelRejectSuppressed, None);
            }
            return (Decision::ModelReject, Some(bytes));
        }

        // No bytes. Three different reasons, and they must stay apart.
        if execution.raw_actions.is_empty() {
            return (Decision::FailClosedNoAction, None);
        }
        if execution
            .raw_actions
            .iter()
            .any(|a| a.get("type").and_then(|t| t.as_str()) == Some("no_response"))
        {
            // The model looked at the name and decided this host does not own it. This is the
            // protocol working, not failing.
            return (Decision::ModelSilent, None);
        }
        (Decision::FailClosedActionError, None)
    }

    /// Record the query as a connection entry so the dashboard shows it.
    ///
    /// Nothing ever closes these — LLMNR has no connection — which is why `metadata()`
    /// declares `.connectionless()`: the 10-second idle sweep is what reaps them.
    async fn record_connection(&self, peer_addr: SocketAddr, bytes: usize) -> ConnectionId {
        use crate::state::server::{
            ConnectionState as ServerConnectionState, ConnectionStatus, ProtocolConnectionInfo,
        };
        let connection_id = ConnectionId::new(self.state.get_next_unified_id().await);
        let now = crate::utils::clock::Instant::now();
        let conn_state = ServerConnectionState {
            id: connection_id,
            remote_addr: peer_addr,
            local_addr: self.local_addr,
            bytes_sent: 0,
            bytes_received: bytes as u64,
            packets_sent: 0,
            packets_received: 1,
            last_activity: now,
            status: ConnectionStatus::Active,
            status_changed_at: now,
            protocol_info: ProtocolConnectionInfo::empty(),
        };
        self.state
            .add_connection_to_server(self.server_id, conn_state)
            .await;
        connection_id
    }

    /// Keep the rail's `↑` counter in step with what actually went out. Each query — each TCP
    /// frame included — got its own entry in `record_connection`, so the write is counted
    /// against the entry the query created.
    async fn count_sent_for(&self, connection_id: ConnectionId, bytes: usize) {
        self.state
            .update_connection_stats(
                self.server_id,
                connection_id,
                None,
                Some(bytes as u64),
                None,
                Some(1),
            )
            .await;
    }
}

/// Join the LLMNR multicast group, non-fatally.
///
/// Deliberately best-effort. On macOS a join on loopback fails routinely, and a responder
/// that refused to start because of it would be unusable for exactly the local testing this
/// repo does — while still being perfectly able to answer a query sent to its port. The
/// failure is logged on both channels so it is never *silently* absent.
fn join_llmnr_group(
    socket: &UdpSocket,
    local_addr: SocketAddr,
    multicast_interface: Option<&str>,
    status_tx: &mpsc::UnboundedSender<String>,
) {
    let log = Log::new(Some(status_tx));

    match local_addr.ip() {
        IpAddr::V4(_) => {
            let interface = match multicast_interface {
                Some(value) => match value.parse::<Ipv4Addr>() {
                    Ok(ip) => ip,
                    Err(e) => {
                        warn!(
                            "LLMNR multicast_interface '{}' is not an IPv4 address ({}); \
                             letting the host choose",
                            value, e
                        );
                        Ipv4Addr::UNSPECIFIED
                    }
                },
                None => Ipv4Addr::UNSPECIFIED,
            };
            match socket.join_multicast_v4(LLMNR_IPV4_GROUP, interface) {
                Ok(()) => {
                    info!(
                        "LLMNR joined {} on interface {}",
                        LLMNR_IPV4_GROUP, interface
                    );
                    log.info(format!("LLMNR joined multicast group {}", LLMNR_IPV4_GROUP));
                }
                Err(e) => {
                    warn!(
                        "LLMNR could not join {} on interface {}: {}; queries sent directly to \
                         this port are still answered",
                        LLMNR_IPV4_GROUP, interface, e
                    );
                    log.warn(format!(
                        "LLMNR multicast join failed ({}); answering direct queries only",
                        e
                    ));
                }
            }
        }
        IpAddr::V6(_) => {
            // Interface index 0 lets the kernel pick. There is no address-based selector for
            // IPv6 joins, so `multicast_interface` (an IPv4 address) has no meaning here.
            match socket.join_multicast_v6(&LLMNR_IPV6_GROUP, 0) {
                Ok(()) => {
                    info!("LLMNR joined {}", LLMNR_IPV6_GROUP);
                    log.info(format!("LLMNR joined multicast group {}", LLMNR_IPV6_GROUP));
                }
                Err(e) => {
                    warn!(
                        "LLMNR could not join {}: {}; queries sent directly to this port are \
                         still answered",
                        LLMNR_IPV6_GROUP, e
                    );
                    log.warn(format!(
                        "LLMNR multicast join failed ({}); answering direct queries only",
                        e
                    ));
                }
            }
        }
    }
}
