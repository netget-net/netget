//! LLMNR (RFC 4795) querier.
//!
//! LLMNR is DNS's message format on a link-local multicast group, and as a *client* it has
//! three properties that DNS does not, all of which are load-bearing here:
//!
//! 1. **A query has no single answer.** It is multicast to the link, and *every* host that
//!    claims the name replies unicast. Two hosts answering the same name with different
//!    addresses is not an edge case — LLMNR is unauthenticated, so it is precisely what name
//!    spoofing looks like on the wire. This client therefore collects for a whole window,
//!    raises one `llmnr_response_received` per responder, and raises
//!    `llmnr_conflicting_responses` loudly when they disagree. It never silently takes the
//!    first answer.
//! 2. **Nobody answering is the normal outcome.** RFC 4795 §2.1.1 has a responder stay silent
//!    for a name it does not own rather than return NXDOMAIN, so an unanswered query is how
//!    the link says "no host here claims that name". It is modelled as its own event
//!    (`llmnr_query_timeout`), not as an error.
//! 3. **The querier is the only thing that can reject a forged answer.** There is no
//!    authentication, so the transaction ID and the echoed question are the entire defence.
//!    Every datagram is matched on both and anything else is discarded with a recorded reason,
//!    which then reaches the model in the timeout event's `discard_reasons`.
//!
//! See `src/client/llmnr/CLAUDE.md` for the design notes and what is unverified.

pub mod actions;

pub use actions::LlmnrClientProtocol;

use anyhow::{Context, Result};
use hickory_proto::op::{Header, Message as DnsMessage, MessageType, OpCode, Query};
use hickory_proto::rr::{DNSClass, Name, RData, RecordType};
use std::collections::{BTreeSet, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex};
use tokio::time::{Duration, Instant};
use tracing::{debug, error, info, trace, warn};

use crate::client::llm_budget::call_llm_for_client;
use crate::llm::actions::client_trait::{Client, ClientActionResult};
use crate::llm::ollama_client::OllamaClient;
use crate::llm::ClientLlmResult;
use crate::logging::emit::Log;
use crate::protocol::{Event, StartupParams};
use crate::state::app_state::AppState;
use crate::state::{ClientId, ClientStatus};

use actions::{
    conflict_bit, parse_record_type, tentative_bit, LLMNR_CLIENT_CONNECTED_EVENT,
    LLMNR_CONFLICTING_RESPONSES_EVENT, LLMNR_IPV4_GROUP, LLMNR_PORT, LLMNR_QUERY_TIMEOUT_EVENT,
    LLMNR_RESPONSE_RECEIVED_EVENT,
};

/// Largest LLMNR datagram this querier will read.
///
/// LLMNR has no EDNS0 negotiation and a link-local answer is a handful of records; 4 KiB bounds
/// a hostile datagram while covering everything legitimate.
const MAX_MESSAGE_LEN: usize = 4096;

/// Seconds each query keeps collecting responses, unless `response_wait_secs` overrides it.
///
/// RFC 4795 §2.7's `LLMNR_TIMEOUT` is one second per transmission; two gives a slow responder a
/// second chance to be *counted* rather than missed, which matters because a responder that
/// arrives after the window closes is invisible — and an invisible second answer is exactly the
/// conflict this client exists to surface.
const DEFAULT_RESPONSE_WAIT_SECS: u64 = 2;

/// How many action → event → action rounds one initial batch may drive.
///
/// The work queue below is iterative, so depth here is not stack depth (the DNS client
/// overflowed the stack by recursing; that shape is deliberately not reproduced). This is a
/// semantic bound: a model that answers every response by resolving another name would
/// otherwise run until the per-client LLM budget stopped it, having flooded the link.
const MAX_FOLLOWUP_DEPTH: usize = 6;

/// How many rejection reasons one query keeps.
///
/// Rejecting a datagram costs no LLM call, so the collection loop will process as many as
/// arrive — and an LLMNR querier sits on an ephemeral port on a *multicast* link, where the
/// query it just sent is visible to everyone. Without a cap, one flood inside the response
/// window allocates a `String` per datagram, sends one unbounded status message per datagram,
/// and then puts the whole list into the model's prompt as `discard_reasons`. Ten is enough
/// to see the pattern (they repeat); `discarded_count` still reports the true total, so
/// nothing about the *count* is softened — only the transcript is.
const MAX_RECORDED_DISCARDS: usize = 10;

pub struct LlmnrClient;

/// One host's answer to one query.
#[derive(Debug, Clone)]
struct ResponderAnswer {
    responder_address: String,
    /// Every matching record in this response, rendered as text (address or PTR name).
    addresses: Vec<String>,
    ttl: u32,
    /// The responder's own C bit: it has seen the name claimed more than once.
    conflict: bool,
    /// The responder's T bit: authoritative, uniqueness unverified.
    tentative: bool,
}

impl ResponderAnswer {
    fn primary(&self) -> &str {
        self.addresses.first().map(String::as_str).unwrap_or("")
    }
}

/// Everything one completed query produced. Deliberately data-only: the socket work and the
/// model work are separate steps, so an injected command can be answered before the model is
/// ever involved.
#[derive(Debug)]
struct QueryOutcome {
    transaction_id: u16,
    name: String,
    record_type: String,
    target: SocketAddr,
    bytes_sent: usize,
    waited_secs: u64,
    responses: Vec<ResponderAnswer>,
    /// One plain-language reason per rejected datagram, **capped at
    /// [`MAX_RECORDED_DISCARDS`]**. `discarded_total` is the honest count.
    discarded: Vec<String>,
    /// How many datagrams were rejected in all, whether or not a reason was kept for them.
    discarded_total: usize,
}

impl QueryOutcome {
    /// Distinct answers across responders. More than one is a conflict.
    fn distinct_answers(&self) -> usize {
        self.responses
            .iter()
            .map(|r| r.addresses.join(","))
            .collect::<BTreeSet<_>>()
            .len()
    }

    fn summary(&self) -> String {
        if self.responses.is_empty() {
            format!(
                "llmnr_query {} {} -> no responder ({} datagram(s) discarded), {} bytes sent",
                self.name, self.record_type, self.discarded_total, self.bytes_sent
            )
        } else {
            format!(
                "llmnr_query {} {} -> {} responder(s): {}, {} discarded, {} bytes sent",
                self.name,
                self.record_type,
                self.responses.len(),
                self.responses
                    .iter()
                    .map(|r| format!("{}={}", r.responder_address, r.primary()))
                    .collect::<Vec<_>>()
                    .join(", "),
                self.discarded_total,
                self.bytes_sent
            )
        }
    }
}

/// What [`LlmnrClient::apply_action`] did with one action.
enum Applied {
    /// A query completed. The model still has to be shown what came back.
    Queried(Box<QueryOutcome>),
    /// The action ran but sent no query; the string says why.
    Other(String),
}

/// Shared handles the query path and the command path both need.
#[derive(Clone)]
struct Wire {
    socket: Arc<UdpSocket>,
    /// Serialises send-then-collect over the one socket.
    ///
    /// Two queries running at once on a shared datagram socket would steal each other's
    /// responses, and "the other query ate my answer" is indistinguishable from "nobody
    /// answered" — the failure this client is least able to detect. The guard is held **only**
    /// across bounded socket I/O (send plus a `response_wait_secs` collection window) and never
    /// across an LLM call: reporting happens after `run_query` has returned and dropped it.
    lock: Arc<Mutex<()>>,
    default_target: SocketAddr,
    response_wait_secs: u64,
}

impl LlmnrClient {
    /// Bind the querier's socket and start driving it.
    ///
    /// Returns the socket's real local address, which is where responders will reply: LLMNR
    /// answers are unicast back to the query's source address and port (RFC 4795 §2.5), so this
    /// is the one address that matters.
    pub async fn connect_with_llm_actions(
        remote_addr: String,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        client_id: ClientId,
        startup_params: Option<StartupParams>,
    ) -> Result<SocketAddr> {
        // Startup parameters come from the model or an MCP caller, so every accessor is
        // fallible and propagated with `?` — never unwrapped, which over MCP would kill the
        // request task before it could report the error.
        let (bind_address, response_wait_secs) = match &startup_params {
            Some(params) => (
                params.get_optional_string("bind_address")?,
                params
                    .get_optional_u64("response_wait_secs")?
                    .unwrap_or(DEFAULT_RESPONSE_WAIT_SECS),
            ),
            None => (None, DEFAULT_RESPONSE_WAIT_SECS),
        };

        let default_target = parse_target(&remote_addr)?;

        // The default bind follows the target's family. 0.0.0.0 rather than 127.0.0.1 is
        // deliberate and measured: bound to 127.0.0.1 a socket can JOIN a multicast group but
        // cannot SEND to one — sendto() fails with EADDRNOTAVAIL (49), because loopback carries
        // no multicast route. Bound to 0.0.0.0 both work.
        let bind_ip: IpAddr = match &bind_address {
            Some(value) => IpAddr::from_str(value).with_context(|| {
                format!("Invalid 'bind_address' for the LLMNR querier: '{value}'")
            })?,
            None if default_target.is_ipv4() => IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            None => IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
        };

        let socket = Arc::new(
            UdpSocket::bind(SocketAddr::new(bind_ip, 0))
                .await
                .with_context(|| format!("LLMNR querier failed to bind {bind_ip}:0"))?,
        );

        // RFC 4795 §2.5: an LLMNR query is link-scoped, so its multicast TTL / hop limit is 1.
        // Best-effort — on some platforms this is refused for an unbound family, and a failure
        // here does not stop a unicast query from working.
        if bind_ip.is_ipv4() {
            if let Err(e) = socket.set_multicast_ttl_v4(1) {
                debug!("LLMNR querier could not set multicast TTL to 1: {}", e);
            }
        }

        let local_addr = socket
            .local_addr()
            .context("LLMNR querier could not read its own address")?;

        let log = Log::new(Some(&status_tx));
        info!(
            "LLMNR querier {} bound to {}, default target {}",
            client_id, local_addr, default_target
        );
        log.info(format!(
            "[CLIENT] LLMNR querier {} ready on {} (target {})",
            client_id, local_addr, default_target
        ));

        app_state
            .update_client_status(client_id, ClientStatus::Connected)
            .await;
        let _ = status_tx.send("__UPDATE_UI__".to_string());

        let wire = Wire {
            socket,
            lock: Arc::new(Mutex::new(())),
            default_target,
            response_wait_secs,
        };
        let protocol = Arc::new(LlmnrClientProtocol::new());

        // Registered BEFORE the connected-event LLM call below. A dashboard-created client
        // defaults to a `*` -> manual routing rule, so that call can park for minutes waiting
        // for a human, and [ send ] must work for the whole park.
        let command_rx =
            crate::client::command_support::register_command_channel(&app_state, client_id).await;

        let cmd_task = tokio::spawn(Self::command_loop(
            command_rx,
            wire.clone(),
            protocol.clone(),
            client_id,
            app_state.clone(),
            llm_client.clone(),
            status_tx.clone(),
        ));
        app_state.register_client_task(client_id, cmd_task).await;

        // The conversation runs as a registered background task rather than inline, so
        // `connect()` returns as soon as the socket is up and `stop_client` can abort it.
        let conversation_state = app_state.clone();
        let conversation_llm = llm_client.clone();
        let conversation_tx = status_tx.clone();
        let conversation_wire = wire.clone();
        let conversation_protocol = protocol.clone();
        let handle = tokio::spawn(async move {
            let app_state = conversation_state;
            let llm_client = conversation_llm;
            let status_tx = conversation_tx;
            let wire = conversation_wire;
            let protocol = conversation_protocol;

            let Some(instruction) = app_state.get_instruction_for_client(client_id).await else {
                debug!(
                    "LLMNR querier {} has no instruction; nothing to drive",
                    client_id
                );
                return;
            };

            let event = Event::new(
                &LLMNR_CLIENT_CONNECTED_EVENT,
                serde_json::json!({
                    "target": default_target.to_string(),
                    "local_addr": local_addr.to_string(),
                    "response_wait_secs": response_wait_secs,
                }),
            );

            let memory = app_state
                .get_memory_for_client(client_id)
                .await
                .unwrap_or_default();

            match call_llm_for_client(
                &llm_client,
                &app_state,
                client_id.to_string(),
                &instruction,
                &memory,
                Some(&event),
                protocol.as_ref(),
                &status_tx,
            )
            .await
            {
                Ok(ClientLlmResult {
                    actions,
                    memory_updates,
                }) => {
                    if let Some(mem) = memory_updates {
                        app_state.set_memory_for_client(client_id, mem).await;
                    }
                    // The model's answer is executed, not counted and logged. That discard is
                    // the single most common client defect in this repo.
                    Self::run_actions(
                        &wire,
                        &protocol,
                        actions,
                        0,
                        client_id,
                        &app_state,
                        &llm_client,
                        &status_tx,
                    )
                    .await;
                }
                Err(e) => {
                    error!("LLM error for LLMNR querier {}: {}", client_id, e);
                    let _ = status_tx.send(format!(
                        "[CLIENT] ✖ LLMNR querier {} could not reach the model: {}",
                        client_id, e
                    ));
                }
            }

            debug!("LLMNR querier {} conversation task finished", client_id);
        });
        app_state.register_client_task(client_id, handle).await;

        Ok(local_addr)
    }

    /// Drain a batch of actions and every follow-up they produce.
    ///
    /// An explicit work queue, not recursion: the DNS client used to await the model and then
    /// call itself per follow-up action, and because each level is a separately polled boxed
    /// future, a non-converging model overflowed the stack and took the whole process down
    /// (`IMPROVEMENTS.md` item 49). Here stack depth is constant however many rounds occur, and
    /// `depth` bounds the *number* of rounds at [`MAX_FOLLOWUP_DEPTH`] so a model that answers
    /// every response with another query cannot flood the link either.
    #[allow(clippy::too_many_arguments)]
    async fn run_actions(
        wire: &Wire,
        protocol: &Arc<LlmnrClientProtocol>,
        initial_actions: Vec<serde_json::Value>,
        initial_depth: usize,
        client_id: ClientId,
        app_state: &Arc<AppState>,
        llm_client: &OllamaClient,
        status_tx: &mpsc::UnboundedSender<String>,
    ) {
        let mut pending: VecDeque<(usize, serde_json::Value)> = initial_actions
            .into_iter()
            .map(|a| (initial_depth, a))
            .collect();

        while let Some((depth, action)) = pending.pop_front() {
            match Self::apply_action(wire, protocol, action, client_id, app_state, status_tx).await
            {
                Ok(Applied::Queried(outcome)) => {
                    if depth >= MAX_FOLLOWUP_DEPTH {
                        warn!(
                            "LLMNR querier {} stopped at follow-up depth {}: {} — the model is \
                             not converging, so its answer is not being asked for again",
                            client_id,
                            depth,
                            outcome.summary()
                        );
                        let _ = status_tx.send(format!(
                            "[CLIENT] ⚠ LLMNR querier {} reached the follow-up depth cap ({})",
                            client_id, MAX_FOLLOWUP_DEPTH
                        ));
                        continue;
                    }
                    let follow_ups = Self::report_outcome(
                        &outcome, protocol, client_id, app_state, llm_client, status_tx,
                    )
                    .await;
                    pending.extend(follow_ups.into_iter().map(|a| (depth + 1, a)));
                }
                Ok(Applied::Other(_)) => {}
                Err(e) => error!("LLMNR querier {} action error: {}", client_id, e),
            }
        }
    }

    /// Run one action against the live socket, without involving the model.
    ///
    /// Split from the reporting so an injected command can be answered as soon as the wire work
    /// is done: a manual routing rule parked on `llmnr_response_received` would otherwise hold
    /// the dashboard's \[send\] open for its whole timeout.
    async fn apply_action(
        wire: &Wire,
        protocol: &Arc<LlmnrClientProtocol>,
        action: serde_json::Value,
        client_id: ClientId,
        app_state: &Arc<AppState>,
        status_tx: &mpsc::UnboundedSender<String>,
    ) -> Result<Applied> {
        match protocol.execute_action(action)? {
            ClientActionResult::Custom { name, data } if name == "llmnr_query" => {
                let query_name = data
                    .get("name")
                    .and_then(|v| v.as_str())
                    .context("Missing name in llmnr_query")?;
                let record_type_str = data
                    .get("record_type")
                    .and_then(|v| v.as_str())
                    .context("Missing record_type in llmnr_query")?;
                let target = match data.get("target").and_then(|v| v.as_str()) {
                    Some(value) => parse_target(value)?,
                    None => wire.default_target,
                };

                let outcome = Self::run_query(
                    wire,
                    query_name,
                    record_type_str,
                    target,
                    client_id,
                    status_tx,
                )
                .await?;
                Ok(Applied::Queried(Box::new(outcome)))
            }
            ClientActionResult::Disconnect => {
                info!("LLMNR querier {} disconnecting", client_id);
                app_state
                    .update_client_status(client_id, ClientStatus::Disconnected)
                    .await;
                let _ = status_tx.send("__UPDATE_UI__".to_string());
                Ok(Applied::Other("disconnect".to_string()))
            }
            ClientActionResult::WaitForMore => {
                debug!("LLMNR querier {} waiting; no query sent", client_id);
                Ok(Applied::Other("wait_for_more: no query sent".to_string()))
            }
            other => Ok(Applied::Other(format!(
                "{other:?} is not an LLMNR client verb; no query sent"
            ))),
        }
    }

    /// Send one query and collect every response that belongs to it.
    ///
    /// **This function is the client's correctness property.** LLMNR has no authentication of
    /// any kind, so the only thing separating a real answer from a forged one is that the real
    /// one carries the random transaction ID this querier just chose *and* echoes the exact
    /// question. Both are checked; anything failing either is discarded with a recorded reason
    /// rather than dropped silently, so a spoofing attempt shows up in the timeout event
    /// instead of looking like an unanswered query.
    async fn run_query(
        wire: &Wire,
        name: &str,
        record_type: &str,
        target: SocketAddr,
        client_id: ClientId,
        status_tx: &mpsc::UnboundedSender<String>,
    ) -> Result<QueryOutcome> {
        // Canonicalised to a lowercase FQDN before anything else happens to it. Two reasons,
        // and both bit once already: a name parsed from the wire is always fully qualified, so
        // comparing it against `Name::from_str("printer.local")` (which is *relative*) is
        // comparing two different things; and the `name` field the model sees must match the
        // responder half's event field exactly, which is the trailing-dot form.
        let mut question_name = Name::from_str(name)
            .with_context(|| format!("Invalid LLMNR name: '{name}'"))?
            .to_lowercase();
        question_name.set_fqdn(true);
        let question_type = parse_record_type(record_type)?;

        // Random per query, and the whole defence: a responder echoes it, an off-path forger
        // has to guess it.
        let transaction_id: u16 = rand::random();

        let mut message = DnsMessage::new();
        let mut header = Header::new();
        header.set_id(transaction_id);
        header.set_message_type(MessageType::Query);
        header.set_op_code(OpCode::Query);
        // C = 0: this querier is not reporting a conflict. (DNS's AA bit — do not set it: every
        // other DNS builder in this repo sets AA on an authoritative message, and that line
        // copied to here would change what the packet means.)
        header.set_authoritative(false);
        header.set_truncated(false);
        // T = 0: tentative is a responder's flag. (DNS's RD bit — a DNS client would set it.)
        header.set_recursion_desired(false);
        // RA is part of LLMNR's Z field and MUST be zero.
        header.set_recursion_available(false);
        message.set_header(header);

        let mut question = Query::query(question_name.clone(), question_type);
        question.set_query_class(DNSClass::IN);
        message.add_query(question);

        let bytes = message
            .to_vec()
            .context("Failed to serialize the LLMNR query")?;

        let mut responses: Vec<ResponderAnswer> = Vec::new();
        let mut discarded: Vec<String> = Vec::new();
        let mut discarded_total = 0usize;
        let bytes_sent;

        {
            // Held across socket I/O only, and bounded by the collection deadline below. No LLM
            // call happens inside this scope.
            let _guard = wire.lock.lock().await;

            bytes_sent = wire
                .socket
                .send_to(&bytes, target)
                .await
                .with_context(|| format!("LLMNR query to {target} could not be sent"))?;
            trace!(
                "LLMNR querier {} sent {} bytes to {}: {}",
                client_id,
                bytes_sent,
                target,
                hex::encode(&bytes)
            );
            debug!(
                "LLMNR querier {} asked {} for {} {} (id={})",
                client_id, target, question_name, question_type, transaction_id
            );

            let deadline = Instant::now() + Duration::from_secs(wire.response_wait_secs);
            let mut buffer = vec![0u8; MAX_MESSAGE_LEN];

            loop {
                let now = Instant::now();
                if now >= deadline {
                    break;
                }
                let (n, from) =
                    match tokio::time::timeout(deadline - now, wire.socket.recv_from(&mut buffer))
                        .await
                    {
                        // The window closed. For LLMNR that is not a failure; see the module docs.
                        Err(_) => break,
                        Ok(Ok(pair)) => pair,
                        Ok(Err(e)) => {
                            warn!(
                                "LLMNR querier {} socket error while collecting responses: {}",
                                client_id, e
                            );
                            break;
                        }
                    };

                match Self::classify(
                    &buffer[..n],
                    transaction_id,
                    &question_name,
                    question_type,
                    from,
                ) {
                    Ok(answer) => {
                        // A retransmission from a host already counted is one responder, not
                        // two — counting it twice would manufacture a conflict.
                        if responses.iter().any(|existing| {
                            existing.responder_address == answer.responder_address
                                && existing.addresses == answer.addresses
                        }) {
                            trace!(
                                "LLMNR querier {} ignored a duplicate answer from {}",
                                client_id,
                                answer.responder_address
                            );
                        } else {
                            responses.push(answer);
                        }
                    }
                    Err(reason) => {
                        discarded_total += 1;
                        // Loud on both channels for the first few: an unmatched datagram
                        // addressed to this querier's ephemeral port is either a stale answer
                        // or somebody guessing, and both are worth seeing. Past the cap the
                        // reasons repeat, and *that* is when a flood is in progress — the one
                        // situation in which a message per datagram on an unbounded channel
                        // is the wrong thing to do. The total is still counted.
                        if discarded.len() < MAX_RECORDED_DISCARDS {
                            warn!(
                                "LLMNR querier {} discarded a datagram from {}: {}",
                                client_id, from, reason
                            );
                            Log::new(Some(status_tx)).warn(format!(
                                "[CLIENT] LLMNR querier {} discarded a response from {}: {}",
                                client_id, from, reason
                            ));
                            discarded.push(format!("{from}: {reason}"));
                        } else {
                            trace!(
                                "LLMNR querier {} discarded a datagram from {}: {} \
                                 (past the first {} — reporting the count only)",
                                client_id,
                                from,
                                reason,
                                MAX_RECORDED_DISCARDS
                            );
                        }
                    }
                }
            }
        }

        Ok(QueryOutcome {
            transaction_id,
            name: question_name.to_string(),
            record_type: question_type.to_string(),
            target,
            bytes_sent,
            waited_secs: wire.response_wait_secs,
            responses,
            discarded,
            discarded_total,
        })
    }

    /// Decide whether one received datagram is an answer to *this* query.
    ///
    /// `Err(reason)` is a rejection with a human-readable reason; the reason reaches the model
    /// in `llmnr_query_timeout.discard_reasons`.
    fn classify(
        data: &[u8],
        transaction_id: u16,
        question_name: &Name,
        question_type: RecordType,
        from: SocketAddr,
    ) -> std::result::Result<ResponderAnswer, String> {
        let message = crate::utils::dns_screen::decode_dns_message(data)
            .map_err(|e| format!("not a parseable DNS/LLMNR message ({e})"))?;

        if message.message_type() != MessageType::Response {
            return Err("not a response (QR=0)".to_string());
        }
        if message.id() != transaction_id {
            return Err(format!(
                "transaction ID mismatch: carried {}, this query used {} — a response with the \
                 wrong ID answers somebody else's question, or nobody's",
                message.id(),
                transaction_id
            ));
        }
        if message.queries().len() != 1 {
            return Err(format!(
                "question section not echoed (QDCOUNT={}, must be 1)",
                message.queries().len()
            ));
        }

        let echoed = &message.queries()[0];
        if &echoed.name().to_lowercase() != question_name {
            return Err(format!(
                "echoed question is for '{}', this query asked for '{}'",
                echoed.name(),
                question_name
            ));
        }
        if echoed.query_type() != question_type {
            return Err(format!(
                "echoed question type is {}, this query asked for {}",
                echoed.query_type(),
                question_type
            ));
        }
        if echoed.query_class() != DNSClass::IN {
            return Err(format!(
                "echoed question class is {}, expected IN",
                echoed.query_class()
            ));
        }

        let mut addresses = Vec::new();
        let mut ttl = 0u32;
        for record in message.answers() {
            if record.record_type() != question_type {
                continue;
            }
            let rendered = match record.data() {
                Some(RData::A(a)) => a.0.to_string(),
                Some(RData::AAAA(a)) => a.0.to_string(),
                Some(RData::PTR(ptr)) => ptr.to_string(),
                _ => continue,
            };
            if addresses.is_empty() {
                ttl = record.ttl();
            }
            addresses.push(rendered);
        }

        if addresses.is_empty() {
            // A responder answers only for names it owns, so an answer-less response is not a
            // "no": it is a malformed claim, and treating it as an answer would let an empty
            // packet count as a responder.
            return Err(format!(
                "response carries no {question_type} record for the question it echoed"
            ));
        }

        Ok(ResponderAnswer {
            responder_address: from.to_string(),
            addresses,
            ttl,
            conflict: conflict_bit(&message),
            tentative: tentative_bit(&message),
        })
    }

    /// Hand one completed query to the model and return whatever it asked for next.
    ///
    /// One event per responder, then — if they disagreed — the conflict event, so the
    /// multiplicity is visible whichever event a handler is keyed on. Zero responders is its own
    /// event and is described to the model as the expected outcome it is.
    async fn report_outcome(
        outcome: &QueryOutcome,
        protocol: &Arc<LlmnrClientProtocol>,
        client_id: ClientId,
        app_state: &Arc<AppState>,
        llm_client: &OllamaClient,
        status_tx: &mpsc::UnboundedSender<String>,
    ) -> Vec<serde_json::Value> {
        let mut events: Vec<Event> = Vec::new();
        let log = Log::new(Some(status_tx));

        if outcome.responses.is_empty() {
            info!(
                "LLMNR querier {} got no answer for {} {} from {} after {}s ({} discarded) — \
                 expected when no host on the link claims the name",
                client_id,
                outcome.name,
                outcome.record_type,
                outcome.target,
                outcome.waited_secs,
                outcome.discarded_total
            );
            log.info(format!(
                "[CLIENT] LLMNR {} {}: no host claims this name ({} datagram(s) discarded)",
                outcome.record_type, outcome.name, outcome.discarded_total
            ));
            events.push(Event::new(
                &LLMNR_QUERY_TIMEOUT_EVENT,
                serde_json::json!({
                    "transaction_id": outcome.transaction_id,
                    "name": outcome.name,
                    "record_type": outcome.record_type,
                    "target": outcome.target.to_string(),
                    "waited_secs": outcome.waited_secs,
                    "discarded_count": outcome.discarded_total,
                    "discard_reasons": outcome.discarded,
                }),
            ));
        } else {
            let responder_count = outcome.responses.len();
            for (index, answer) in outcome.responses.iter().enumerate() {
                info!(
                    "LLMNR querier {} accepted {} {} = {} from {} ({}/{}, ttl={}, tentative={})",
                    client_id,
                    outcome.record_type,
                    outcome.name,
                    answer.primary(),
                    answer.responder_address,
                    index + 1,
                    responder_count,
                    answer.ttl,
                    answer.tentative
                );
                log.info(format!(
                    "[CLIENT] LLMNR {} {} = {} from {} ({}/{})",
                    outcome.record_type,
                    outcome.name,
                    answer.primary(),
                    answer.responder_address,
                    index + 1,
                    responder_count
                ));
                events.push(Event::new(
                    &LLMNR_RESPONSE_RECEIVED_EVENT,
                    serde_json::json!({
                        "transaction_id": outcome.transaction_id,
                        "name": outcome.name,
                        "record_type": outcome.record_type,
                        "address": answer.primary(),
                        "addresses": answer.addresses,
                        "ttl": answer.ttl,
                        "responder_address": answer.responder_address,
                        "responder_index": index + 1,
                        "responder_count": responder_count,
                        "conflict": answer.conflict,
                        "tentative": answer.tentative,
                    }),
                ));
            }

            let distinct = outcome.distinct_answers();
            if distinct > 1 {
                // The one thing in this protocol that deserves to be shouted. LLMNR is
                // unauthenticated, so two different answers to one query means some host is
                // claiming a name it may not own — and whichever answer a resolver takes first
                // wins.
                warn!(
                    "LLMNR querier {}: {} hosts answered '{}' ({}) with {} DIFFERENT answers — \
                     LLMNR is unauthenticated, so this is what name spoofing looks like on the \
                     wire: {}",
                    client_id,
                    outcome.responses.len(),
                    outcome.name,
                    outcome.record_type,
                    distinct,
                    outcome
                        .responses
                        .iter()
                        .map(|r| format!("{} says {}", r.responder_address, r.primary()))
                        .collect::<Vec<_>>()
                        .join("; ")
                );
                log.warn(format!(
                    "[CLIENT] ⚠ LLMNR CONFLICT: '{}' ({}) answered differently by {} hosts",
                    outcome.name,
                    outcome.record_type,
                    outcome.responses.len()
                ));

                let answers: Vec<serde_json::Value> = outcome
                    .responses
                    .iter()
                    .map(|r| {
                        serde_json::json!({
                            "responder_address": r.responder_address,
                            "address": r.primary(),
                            "addresses": r.addresses,
                            "ttl": r.ttl,
                            "tentative": r.tentative,
                        })
                    })
                    .collect();

                events.push(Event::new(
                    &LLMNR_CONFLICTING_RESPONSES_EVENT,
                    serde_json::json!({
                        "transaction_id": outcome.transaction_id,
                        "name": outcome.name,
                        "record_type": outcome.record_type,
                        "responder_count": outcome.responses.len(),
                        "distinct_answers": distinct,
                        "answers": answers,
                    }),
                ));
            }
        }

        let mut follow_ups = Vec::new();
        for event in events {
            let Some(instruction) = app_state.get_instruction_for_client(client_id).await else {
                return follow_ups;
            };
            let memory = app_state
                .get_memory_for_client(client_id)
                .await
                .unwrap_or_default();

            match call_llm_for_client(
                llm_client,
                app_state,
                client_id.to_string(),
                &instruction,
                &memory,
                Some(&event),
                protocol.as_ref(),
                status_tx,
            )
            .await
            {
                Ok(ClientLlmResult {
                    actions,
                    memory_updates,
                }) => {
                    if let Some(mem) = memory_updates {
                        app_state.set_memory_for_client(client_id, mem).await;
                    }
                    // Returned to the caller's work queue rather than executed here: recursing
                    // is what overflowed the stack in the DNS client.
                    follow_ups.extend(actions);
                }
                Err(e) => {
                    error!(
                        "LLM error for LLMNR querier {} on '{}': {}",
                        client_id,
                        event.id(),
                        e
                    );
                }
            }
        }
        follow_ups
    }

    /// Drain injected commands until the channel closes or an injected `disconnect` ends the
    /// session.
    ///
    /// A query reports `Executed { detail }` rather than `Sent { bytes_sent }`: the byte count
    /// is truthful but useless — what the caller wants to know is who answered and whether they
    /// agreed, which is what the detail string carries.
    async fn command_loop(
        mut command_rx: mpsc::Receiver<crate::state::client_handles::ClientCommand>,
        wire: Wire,
        protocol: Arc<LlmnrClientProtocol>,
        client_id: ClientId,
        app_state: Arc<AppState>,
        llm_client: OllamaClient,
        status_tx: mpsc::UnboundedSender<String>,
    ) {
        use crate::llm::actions::protocol_trait::Protocol;
        use crate::state::client_handles::ClientSendOutcome;
        use crate::state::AccessLogOwner;

        while let Some(command) = command_rx.recv().await {
            let action = command.action.clone();
            let is_disconnect = action.get("type").and_then(|v| v.as_str()) == Some("disconnect");

            // The model is shown the result only after the caller has been answered.
            let mut queried: Option<Box<QueryOutcome>> = None;
            let outcome = match Self::apply_action(
                &wire,
                &protocol,
                action.clone(),
                client_id,
                &app_state,
                &status_tx,
            )
            .await
            {
                Ok(Applied::Queried(result)) => {
                    let detail = result.summary();
                    queried = Some(result);
                    Ok(ClientSendOutcome::Executed { detail })
                }
                Ok(Applied::Other(_)) if is_disconnect => Ok(ClientSendOutcome::Disconnected),
                Ok(Applied::Other(detail)) => Ok(ClientSendOutcome::Executed { detail }),
                // The model naming a verb this client does not have is a rejection; a socket
                // fault is an error. They are different things and must not collapse.
                Err(e) if e.to_string().starts_with("Unknown LLMNR client action") => {
                    Ok(ClientSendOutcome::Rejected {
                        error: e.to_string(),
                    })
                }
                Err(e) => Err(e),
            };

            let outcome_json = match &outcome {
                Ok(outcome) => serde_json::to_value(outcome).unwrap_or(serde_json::Value::Null),
                Err(e) => serde_json::json!({"error": e.to_string()}),
            };
            app_state
                .record_access_log(
                    AccessLogOwner::Client(client_id.as_u32()),
                    protocol.protocol_name(),
                    None,
                    "injected_action",
                    action,
                    vec![outcome_json],
                )
                .await;

            let disconnect = matches!(outcome, Ok(ClientSendOutcome::Disconnected));
            if let Err(e) = &outcome {
                error!("LLMNR querier {} injected action failed: {}", client_id, e);
                let _ = status_tx.send(format!(
                    "[WARN] Client {} injected action failed: {}",
                    client_id, e
                ));
            }
            let _ = status_tx.send("__UPDATE_UI__".to_string());
            crate::client::command_support::reply(command, outcome);

            if disconnect {
                break;
            }

            if let Some(result) = queried {
                let follow_ups = Self::report_outcome(
                    &result,
                    &protocol,
                    client_id,
                    &app_state,
                    &llm_client,
                    &status_tx,
                )
                .await;
                Self::run_actions(
                    &wire,
                    &protocol,
                    follow_ups,
                    1,
                    client_id,
                    &app_state,
                    &llm_client,
                    &status_tx,
                )
                .await;
            }
        }

        app_state.remove_client_handle(client_id).await;
        let _ = status_tx.send("__UPDATE_UI__".to_string());
    }
}

/// Parse a query destination.
///
/// Accepts `address:port`, a bare address (port 5355 is assumed, which is what an operator
/// typing `224.0.0.252` means), and the two group names spelled out so `open_client` does not
/// require remembering them.
fn parse_target(value: &str) -> Result<SocketAddr> {
    let trimmed = value.trim();
    match trimmed.to_ascii_lowercase().as_str() {
        "llmnr" | "multicast" | "default" => {
            return Ok(SocketAddr::from((LLMNR_IPV4_GROUP, LLMNR_PORT)))
        }
        "llmnr6" | "multicast6" => {
            return Ok(SocketAddr::new(
                actions::LLMNR_IPV6_GROUP.into(),
                LLMNR_PORT,
            ))
        }
        _ => {}
    }

    if let Ok(addr) = SocketAddr::from_str(trimmed) {
        return Ok(addr);
    }
    if let Ok(ip) = IpAddr::from_str(trimmed) {
        return Ok(SocketAddr::new(ip, LLMNR_PORT));
    }
    Err(anyhow::anyhow!(
        "Invalid LLMNR target '{value}'. Use 'address:port' (e.g. '127.0.0.1:5355'), a bare \
         address (port {LLMNR_PORT} is assumed), or 'llmnr' for the multicast group {}:{}.",
        LLMNR_IPV4_GROUP,
        LLMNR_PORT
    ))
}
