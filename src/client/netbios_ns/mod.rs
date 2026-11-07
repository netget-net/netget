//! NetBIOS Name Service client (RFC 1001 / RFC 1002) — the `nbtstat` equivalent.
//!
//! One UDP socket on an **ephemeral** source port. Querying NBNS needs no privilege of any
//! kind: only *binding* 137 does, and that is the server's problem. The destination port is a
//! declared startup parameter (`port`, default 137) so a test can point the client at a high
//! port.
//!
//! # Shape of the loop, and why it is not a free-running receiver
//!
//! NBNS is a question/answer protocol with no session, and an answer is matched to its
//! question by the 16-bit `NAME_TRN_ID`. So a query *is* a transaction: send, then read
//! datagrams until one carries the matching id or the deadline passes, discarding everything
//! else. That is [`NetbiosNsClient::run_query`], and it makes the two rules the protocol
//! actually requires structural rather than aspirational:
//!
//! * **A reply whose transaction id does not match is discarded**, counted, and logged. UDP
//!   source addresses are trivially spoofed and NBNS answers are cached by the querier, so
//!   accepting a stray datagram means caching a name nobody asked about.
//! * **Silence is a normal answer.** A node that does not hold the queried name says nothing;
//!   there is no refusal to send. The deadline therefore raises `netbios_query_timeout`, which
//!   is an ordinary event and not an error path.
//!
//! Because both the LLM path and injected commands run transactions on the same socket, the
//! socket is held behind a `Mutex` that is taken for the whole send-then-receive transaction.
//! Two concurrent transactions on one socket would steal each other's replies. The guard
//! covers **socket I/O only** and is bounded by `query_timeout_secs`; no LLM call and no
//! `AppState` access happens under it.
//!
//! # Follow-ups are bounded twice over
//!
//! An answer is handed to the model, which may ask another question — a node status reply
//! lists names the model will want to resolve next, so this chain is the point of the client
//! rather than an accident. Two independent bounds keep it finite:
//!
//! 1. **A depth cap** (`MAX_FOLLOWUP_DEPTH`): the model is asked about an answer only while
//!    the chain that produced it is shallower than the cap.
//! 2. **An explicit work queue instead of recursion.** `run_actions` drains a `VecDeque`, so
//!    stack depth is constant regardless of how many rounds occur. The DNS client recursed
//!    here and a non-converging model overflowed the stack after ~200 rounds, taking the whole
//!    process down (`IMPROVEMENTS.md` item 49). The queue carries the depth alongside each
//!    action, so the cap is enforced without a boxed self-call.
//!
//! The per-client LLM budget (`crate::client::llm_budget`) is the third backstop and applies
//! to every client.

pub mod actions;
pub mod wire;

pub use actions::NetbiosNsClientProtocol;

use crate::logging::emit::Log;
use crate::utils::clock::Instant;
use std::collections::VecDeque;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, error, info, trace, warn};

use crate::client::llm_budget::call_llm_for_client;
use crate::llm::actions::client_trait::{Client, ClientActionResult};
use crate::llm::actions::protocol_trait::Protocol;
use crate::llm::ollama_client::OllamaClient;
use crate::llm::ClientLlmResult;
use crate::protocol::{ConnectContext, Event, EventType};
use crate::server::netbios_ns::packet as pkt;
use crate::state::app_state::AppState;
use crate::state::client_handles::{ClientCommand, ClientSendOutcome};
use crate::state::{AccessLogOwner, ClientId, ClientStatus};

use self::actions::{
    NETBIOS_NAME_RESPONSE_EVENT, NETBIOS_NEGATIVE_RESPONSE_EVENT,
    NETBIOS_NODE_STATUS_RESPONSE_EVENT, NETBIOS_NS_CONNECTED_EVENT, NETBIOS_QUERY_TIMEOUT_EVENT,
};

/// The well-known NetBIOS Name Service port. Only *binding* it needs privilege; sending to it
/// from an ephemeral port does not.
const DEFAULT_NBNS_PORT: u16 = 137;

/// Seconds to wait for a reply carrying the matching transaction id.
const DEFAULT_QUERY_TIMEOUT_SECS: u64 = 3;

/// How deep an answer→question→answer chain may go before this client stops asking the model
/// about the result. Deliberately small: NBNS enumeration converges in a handful of steps
/// (node status, then resolve the names it listed), and anything longer is a loop.
const MAX_FOLLOWUP_DEPTH: usize = 6;

/// Everything one running client needs to put a query on the wire.
struct Transport {
    /// Held for a whole send-then-receive transaction so two queries cannot steal each other's
    /// replies. Nothing but socket I/O happens under this guard.
    socket: Mutex<UdpSocket>,
    default_target: SocketAddr,
    query_timeout: Duration,
}

/// What one executed action did.
enum Applied {
    /// A query completed (with an answer, a refusal, or a timeout). `event_type`/`event_data`
    /// are what the model still has to be shown; `detail` summarises it for an injecting
    /// caller that has already been answered.
    Answered {
        event_type: &'static EventType,
        event_data: serde_json::Value,
        detail: String,
    },
    /// Ran, but sent nothing; the string says why.
    Nothing(String),
    /// The session should end.
    Disconnect,
}

/// Outcome of one transaction on the wire.
enum QueryOutcome {
    Reply {
        response: wire::NbnsResponse,
        from: SocketAddr,
    },
    /// Nothing matching arrived in time. Carries how many datagrams were seen and thrown away,
    /// which is the difference between "nobody is there" and "something answered and it was
    /// not for us".
    TimedOut { ignored: usize },
}

pub struct NetbiosNsClient;

impl NetbiosNsClient {
    /// Bind the querying socket, register everything that can be aborted, and start the
    /// conversation.
    pub async fn connect_with_llm_actions(ctx: ConnectContext) -> Result<SocketAddr> {
        let ConnectContext {
            remote_addr,
            llm_client,
            state: app_state,
            status_tx,
            client_id,
            startup_params,
        } = ctx;

        // --- startup parameters, both read, neither unwrapped -------------------------------
        let port_override = match &startup_params {
            Some(params) => params.get_optional_u32("port")?,
            None => None,
        };
        let port_override = match port_override {
            Some(p) => Some(u16::try_from(p).map_err(|_| {
                anyhow::anyhow!("startup parameter 'port' must be between 0 and 65535, got {p}")
            })?),
            None => None,
        };
        let query_timeout_secs = match &startup_params {
            Some(params) => params
                .get_optional_u64("query_timeout_secs")?
                .unwrap_or(DEFAULT_QUERY_TIMEOUT_SECS),
            None => DEFAULT_QUERY_TIMEOUT_SECS,
        };
        if query_timeout_secs == 0 {
            anyhow::bail!(
                "startup parameter 'query_timeout_secs' must be at least 1: a zero deadline \
                 discards every reply before it can arrive"
            );
        }

        let default_target = resolve_target(&remote_addr, port_override).await?;

        // Source port 0: the querier is not the name service, so nothing here needs 137.
        let socket = UdpSocket::bind(("0.0.0.0", 0))
            .await
            .context("failed to bind the NetBIOS-NS client's UDP socket")?;
        let local_addr = socket
            .local_addr()
            .context("bound NetBIOS-NS socket has no local address")?;

        info!(
            "NetBIOS-NS client {} querying from {} to {}",
            client_id, local_addr, default_target
        );
        app_state
            .update_client_status(client_id, ClientStatus::Connected)
            .await;
        let _ = status_tx.send(format!(
            "[CLIENT] NetBIOS-NS client {} ready ({} -> {})",
            client_id, local_addr, default_target
        ));
        let _ = status_tx.send("__UPDATE_UI__".to_string());

        let transport = Arc::new(Transport {
            socket: Mutex::new(socket),
            default_target,
            query_timeout: Duration::from_secs(query_timeout_secs),
        });
        let protocol = Arc::new(NetbiosNsClientProtocol::new());

        // The command channel is registered BEFORE anything that can park. A client created
        // from the dashboard gets a `*` -> manual routing rule, so the connected-event call
        // below can wait minutes for a human, and [ send ] has to work for the whole wait.
        let command_rx =
            crate::client::command_support::register_command_channel(&app_state, client_id).await;
        let cmd_task = tokio::spawn(Self::command_loop(
            command_rx,
            protocol.clone(),
            transport.clone(),
            client_id,
            app_state.clone(),
            llm_client.clone(),
            status_tx.clone(),
        ));
        app_state.register_client_task(client_id, cmd_task).await;

        // The conversation runs as its own registered task so `connect()` returns as soon as
        // the socket is up, rather than blocking until the model stops asking questions.
        let conversation = tokio::spawn(Self::conversation(
            protocol.clone(),
            transport.clone(),
            client_id,
            app_state.clone(),
            llm_client,
            status_tx,
            default_target,
            local_addr,
        ));
        app_state
            .register_client_task(client_id, conversation)
            .await;

        Ok(local_addr)
    }

    /// Raise `netbios_ns_connected` and drain everything the model asks for in reply.
    #[allow(clippy::too_many_arguments)]
    async fn conversation(
        protocol: Arc<NetbiosNsClientProtocol>,
        transport: Arc<Transport>,
        client_id: ClientId,
        app_state: Arc<AppState>,
        llm_client: OllamaClient,
        status_tx: mpsc::UnboundedSender<String>,
        default_target: SocketAddr,
        local_addr: SocketAddr,
    ) {
        let Some(instruction) = app_state.get_instruction_for_client(client_id).await else {
            debug!(
                "NetBIOS-NS client {} has no instruction; nothing to drive",
                client_id
            );
            return;
        };

        let event = Event::new(
            &NETBIOS_NS_CONNECTED_EVENT,
            serde_json::json!({
                "remote_addr": default_target.to_string(),
                "local_addr": local_addr.to_string(),
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
                Self::run_actions(
                    &protocol,
                    &transport,
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
                error!("LLM error for NetBIOS-NS client {}: {}", client_id, e);
                let _ = status_tx.send(format!(
                    "[CLIENT] ✖ NetBIOS-NS client {} could not start: {}",
                    client_id, e
                ));
            }
        }

        debug!("NetBIOS-NS client {} conversation task finished", client_id);
    }

    /// Drain a batch of actions and every follow-up they produce.
    ///
    /// An explicit queue, never a self-call: stack depth stays constant however many
    /// question/answer rounds the model asks for. `depth` rides along with each action so
    /// [`MAX_FOLLOWUP_DEPTH`] can be enforced without recursion.
    #[allow(clippy::too_many_arguments)]
    async fn run_actions(
        protocol: &Arc<NetbiosNsClientProtocol>,
        transport: &Arc<Transport>,
        initial_actions: Vec<serde_json::Value>,
        depth: usize,
        client_id: ClientId,
        app_state: &Arc<AppState>,
        llm_client: &OllamaClient,
        status_tx: &mpsc::UnboundedSender<String>,
    ) {
        let mut pending: VecDeque<(serde_json::Value, usize)> =
            initial_actions.into_iter().map(|a| (a, depth)).collect();

        while let Some((action, depth)) = pending.pop_front() {
            let applied =
                match Self::apply_action(protocol, transport, action, client_id, status_tx).await {
                    Ok(applied) => applied,
                    Err(e) => {
                        Log::to(status_tx).warn(format!(
                            "NetBIOS-NS client {} action failed: {}",
                            client_id, e
                        ));
                        continue;
                    }
                };

            match applied {
                Applied::Disconnect => {
                    Self::finish(client_id, app_state, status_tx).await;
                    return;
                }
                Applied::Nothing(detail) => {
                    debug!("NetBIOS-NS client {}: {}", client_id, detail);
                }
                Applied::Answered {
                    event_type,
                    event_data,
                    ..
                } => {
                    if depth >= MAX_FOLLOWUP_DEPTH {
                        warn!(
                            "NetBIOS-NS client {} reached the follow-up depth cap ({}); the \
                             '{}' answer is not being handed back to the model",
                            client_id, MAX_FOLLOWUP_DEPTH, event_type.id
                        );
                        let _ = status_tx.send(format!(
                            "[CLIENT] ⚠ NetBIOS-NS client {} stopped following up at depth {}",
                            client_id, MAX_FOLLOWUP_DEPTH
                        ));
                        continue;
                    }
                    let follow_ups = Self::report(
                        event_type, event_data, protocol, client_id, app_state, llm_client,
                        status_tx,
                    )
                    .await;
                    pending.extend(follow_ups.into_iter().map(|a| (a, depth + 1)));
                }
            }
        }
    }

    /// Hand one completed transaction to the model and return whatever it asks for next.
    ///
    /// The returned actions go back onto the caller's queue. They are never executed here and
    /// never discarded — a client that asks the model what to do and then drops the answer is
    /// the most common client defect in this repository.
    async fn report(
        event_type: &'static EventType,
        event_data: serde_json::Value,
        protocol: &Arc<NetbiosNsClientProtocol>,
        client_id: ClientId,
        app_state: &Arc<AppState>,
        llm_client: &OllamaClient,
        status_tx: &mpsc::UnboundedSender<String>,
    ) -> Vec<serde_json::Value> {
        let Some(instruction) = app_state.get_instruction_for_client(client_id).await else {
            return Vec::new();
        };
        let event = Event::new(event_type, event_data);
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
                actions
            }
            Err(e) => {
                error!("LLM error for NetBIOS-NS client {}: {}", client_id, e);
                Vec::new()
            }
        }
    }

    /// Execute one action against the wire. No LLM call happens here, which is what lets the
    /// injected-command path answer its caller as soon as the datagram round trip is done.
    async fn apply_action(
        protocol: &Arc<NetbiosNsClientProtocol>,
        transport: &Arc<Transport>,
        action: serde_json::Value,
        client_id: ClientId,
        status_tx: &mpsc::UnboundedSender<String>,
    ) -> Result<Applied> {
        match protocol.execute_action(action)? {
            ClientActionResult::Custom { name, data } if name == "netbios_name_query" => {
                Self::query(transport, &data, pkt::QTYPE_NB, client_id, status_tx).await
            }
            ClientActionResult::Custom { name, data } if name == "netbios_node_status_query" => {
                Self::query(transport, &data, pkt::QTYPE_NBSTAT, client_id, status_tx).await
            }
            ClientActionResult::Disconnect => Ok(Applied::Disconnect),
            ClientActionResult::WaitForMore => {
                Ok(Applied::Nothing("wait_for_more: no query sent".to_string()))
            }
            ClientActionResult::Custom { name, .. } => Ok(Applied::Nothing(format!(
                "custom result '{name}' is not a NetBIOS-NS query; nothing sent"
            ))),
            other => Ok(Applied::Nothing(format!(
                "action result {other:?} produced no datagram"
            ))),
        }
    }

    /// Build, send and await one query, then turn the outcome into the event the model sees.
    async fn query(
        transport: &Arc<Transport>,
        data: &serde_json::Value,
        qtype: u16,
        client_id: ClientId,
        status_tx: &mpsc::UnboundedSender<String>,
    ) -> Result<Applied> {
        let name = data
            .get("name")
            .and_then(|v| v.as_str())
            .context("query is missing 'name'")?
            .to_string();
        let suffix = u8::try_from(data.get("suffix").and_then(|v| v.as_u64()).unwrap_or(0))
            .context("'suffix' must be between 0 and 255")?;
        let broadcast = data
            .get("broadcast")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let target = target_for(transport.default_target, data)?;

        // A random transaction id, because it is the only thing tying a reply to this
        // question: a predictable one lets anything on the path answer for the real responder.
        let trn_id: u16 = rand::random();

        let datagram = if qtype == pkt::QTYPE_NBSTAT {
            wire::encode_node_status_query(trn_id, &name, suffix)?
        } else {
            wire::encode_name_query(trn_id, &name, suffix, broadcast)?
        };
        let question_type = pkt::qtype_name(qtype);

        debug!(
            "NetBIOS-NS client {} sending {} query for {}<0x{:02x}> to {} (trn_id 0x{:04x}, \
             {} octets)",
            client_id,
            question_type,
            name,
            suffix,
            target,
            trn_id,
            datagram.len()
        );

        let outcome = Self::run_query(transport, &datagram, target, trn_id, client_id).await?;

        match outcome {
            QueryOutcome::TimedOut { ignored } => {
                info!(
                    "NetBIOS-NS client {} got no matching answer for {}<0x{:02x}> from {} in {}s \
                     ({} datagram(s) discarded)",
                    client_id,
                    name,
                    suffix,
                    target,
                    transport.query_timeout.as_secs(),
                    ignored
                );
                let _ = status_tx.send(format!(
                    "[CLIENT] NetBIOS-NS {} query for {} timed out (normal when the node does \
                     not hold the name)",
                    question_type, name
                ));
                Ok(Applied::Answered {
                    event_type: &NETBIOS_QUERY_TIMEOUT_EVENT,
                    event_data: serde_json::json!({
                        "name": name,
                        "suffix": suffix,
                        "suffix_label": wire::suffix_label(suffix),
                        "question_type": question_type,
                        "target": target.to_string(),
                        "timeout_secs": transport.query_timeout.as_secs(),
                        "ignored_datagrams": ignored,
                    }),
                    detail: format!(
                        "{question_type} query for {name} timed out after {}s ({ignored} \
                         datagram(s) discarded)",
                        transport.query_timeout.as_secs()
                    ),
                })
            }
            QueryOutcome::Reply { response, from } => {
                Ok(Self::describe_reply(response, from, client_id, status_tx))
            }
        }
    }

    /// Turn a matched response into the event the model is shown.
    fn describe_reply(
        response: wire::NbnsResponse,
        from: SocketAddr,
        client_id: ClientId,
        status_tx: &mpsc::UnboundedSender<String>,
    ) -> Applied {
        let responder = from.to_string();
        match response.answer {
            wire::NbnsAnswer::Name(answer) => {
                let addresses: Vec<String> =
                    answer.addresses.iter().map(|a| a.to_string()).collect();
                info!(
                    "NetBIOS-NS client {} resolved {}<0x{:02x}> to {} (ttl {}, group {})",
                    client_id,
                    answer.name,
                    answer.suffix,
                    addresses.join(", "),
                    answer.ttl,
                    answer.group
                );
                let _ = status_tx.send(format!(
                    "[CLIENT] NetBIOS-NS {}<0x{:02x}> = {}",
                    answer.name,
                    answer.suffix,
                    addresses.join(", ")
                ));
                let detail = format!(
                    "{}<0x{:02x}> resolved to {}",
                    answer.name,
                    answer.suffix,
                    addresses.join(", ")
                );
                Applied::Answered {
                    event_type: &NETBIOS_NAME_RESPONSE_EVENT,
                    event_data: serde_json::json!({
                        "name": answer.name,
                        "suffix": answer.suffix,
                        "suffix_label": wire::suffix_label(answer.suffix),
                        "addresses": addresses,
                        "ttl": answer.ttl,
                        "group": answer.group,
                        "node_type": answer.node_type,
                        "responder": responder,
                    }),
                    detail,
                }
            }
            wire::NbnsAnswer::NodeStatus(answer) => {
                let names: Vec<serde_json::Value> = answer
                    .names
                    .iter()
                    .map(|entry| {
                        serde_json::json!({
                            "name": entry.name,
                            "suffix": entry.suffix,
                            "suffix_label": wire::suffix_label(entry.suffix),
                            "group": entry.group,
                            "active": entry.active,
                        })
                    })
                    .collect();
                info!(
                    "NetBIOS-NS client {} node status from {}: {} name(s), adapter {}",
                    client_id,
                    responder,
                    names.len(),
                    answer.mac_address
                );
                let _ = status_tx.send(format!(
                    "[CLIENT] NetBIOS-NS node status: {} name(s), adapter {}",
                    names.len(),
                    answer.mac_address
                ));
                let detail = format!(
                    "node status listed {} name(s), adapter {}",
                    names.len(),
                    answer.mac_address
                );
                Applied::Answered {
                    event_type: &NETBIOS_NODE_STATUS_RESPONSE_EVENT,
                    event_data: serde_json::json!({
                        "name": answer.name,
                        "suffix": answer.suffix,
                        "suffix_label": wire::suffix_label(answer.suffix),
                        "names": names,
                        "mac_address": answer.mac_address,
                        "responder": responder,
                    }),
                    detail,
                }
            }
            wire::NbnsAnswer::Negative(answer) => {
                info!(
                    "NetBIOS-NS client {} refused for {}<0x{:02x}>: rcode {} ({})",
                    client_id, answer.name, answer.suffix, answer.rcode, answer.rcode_name
                );
                let _ = status_tx.send(format!(
                    "[CLIENT] NetBIOS-NS {} -> {}",
                    answer.name, answer.rcode_name
                ));
                let detail = format!(
                    "{}<0x{:02x}> refused: {}",
                    answer.name, answer.suffix, answer.rcode_name
                );
                Applied::Answered {
                    event_type: &NETBIOS_NEGATIVE_RESPONSE_EVENT,
                    event_data: serde_json::json!({
                        "name": answer.name,
                        "suffix": answer.suffix,
                        "suffix_label": wire::suffix_label(answer.suffix),
                        "rcode": answer.rcode,
                        "rcode_name": answer.rcode_name,
                        "responder": responder,
                    }),
                    detail,
                }
            }
        }
    }

    /// One transaction: send, then read until the matching transaction id arrives or the
    /// deadline passes.
    ///
    /// **Everything that is not this transaction's answer is discarded**, counted and logged
    /// at DEBUG. Three things get thrown away here and each is a real case: a datagram from an
    /// unrelated NBNS conversation, a datagram that does not decode as a response at all, and
    /// a *request* (`R=0`) — treating any of them as an answer means caching a name nobody
    /// asked about, which on NBNS redirects that host's traffic for the answer's TTL.
    async fn run_query(
        transport: &Arc<Transport>,
        datagram: &[u8],
        target: SocketAddr,
        trn_id: u16,
        client_id: ClientId,
    ) -> Result<QueryOutcome> {
        let deadline = Instant::now() + transport.query_timeout;
        let mut ignored = 0usize;
        let mut buffer = vec![0u8; wire::RECV_BUFFER];

        // Held across the send and every read of this transaction: two overlapping queries on
        // one socket would race for each other's replies. Socket I/O only, bounded by the
        // query deadline; no LLM call and no AppState access happens under this guard.
        let socket = transport.socket.lock().await;

        socket
            .send_to(datagram, target)
            .await
            .with_context(|| format!("failed to send a NetBIOS-NS query to {target}"))?;

        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok(QueryOutcome::TimedOut { ignored });
            }

            let received =
                match tokio::time::timeout(remaining, socket.recv_from(&mut buffer)).await {
                    Err(_) => return Ok(QueryOutcome::TimedOut { ignored }),
                    Ok(Ok(received)) => received,
                    Ok(Err(e)) => {
                        return Err(anyhow::anyhow!(
                            "NetBIOS-NS client {client_id} socket read failed: {e}"
                        ))
                    }
                };
            let (n, from) = received;
            trace!(
                "NetBIOS-NS client {} read {} octets from {}",
                client_id,
                n,
                from
            );

            match wire::parse_response(&buffer[..n]) {
                Ok(response) if response.trn_id == trn_id => {
                    return Ok(QueryOutcome::Reply { response, from })
                }
                Ok(response) => {
                    ignored += 1;
                    // WARN rather than DEBUG on purpose: a well-formed NBNS answer to a
                    // question this client did not ask is either a stray late reply or
                    // somebody trying to get a name into our cache, and it is rare enough
                    // that logging every one costs nothing.
                    warn!(
                        "NetBIOS-NS client {} discarded a datagram from {}: transaction id \
                         0x{:04x} does not match the outstanding 0x{:04x}",
                        client_id, from, response.trn_id, trn_id
                    );
                }
                Err(e) => {
                    ignored += 1;
                    debug!(
                        "NetBIOS-NS client {} discarded a datagram from {}: {}",
                        client_id, from, e
                    );
                }
            }
        }
    }

    /// Drain injected commands (the dashboard's \[send\]) until the channel closes or an
    /// injected `disconnect` ends the session.
    ///
    /// The generic `command_support::handle_stream_client_command` cannot serve this client:
    /// its actions yield `Custom` results and the transport is a datagram socket, not an
    /// `AsyncWrite`. Commands go through [`Self::apply_action`] — the same function the LLM
    /// path uses — so the query encoding exists exactly once.
    ///
    /// The caller is answered as soon as the datagram round trip finishes; the model is shown
    /// the answer *afterwards*, so a manual routing rule parked on `netbios_name_response`
    /// cannot hold \[send\] open for its whole timeout.
    #[allow(clippy::too_many_arguments)]
    async fn command_loop(
        mut command_rx: mpsc::Receiver<ClientCommand>,
        protocol: Arc<NetbiosNsClientProtocol>,
        transport: Arc<Transport>,
        client_id: ClientId,
        app_state: Arc<AppState>,
        llm_client: OllamaClient,
        status_tx: mpsc::UnboundedSender<String>,
    ) {
        while let Some(command) = command_rx.recv().await {
            let action = command.action.clone();

            let mut answered: Option<(&'static EventType, serde_json::Value)> = None;
            let outcome = match Self::apply_action(
                &protocol,
                &transport,
                action.clone(),
                client_id,
                &status_tx,
            )
            .await
            {
                Ok(Applied::Answered {
                    event_type,
                    event_data,
                    detail,
                }) => {
                    answered = Some((event_type, event_data));
                    Ok(ClientSendOutcome::Executed { detail })
                }
                Ok(Applied::Nothing(detail)) => Ok(ClientSendOutcome::Executed { detail }),
                Ok(Applied::Disconnect) => Ok(ClientSendOutcome::Disconnected),
                // The model naming a verb this client does not have is a rejection; a socket
                // failure is an error. Conflating them makes a typo look like an outage.
                Err(e)
                    if e.to_string()
                        .starts_with("Unknown NetBIOS-NS client action") =>
                {
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
                Log::to(&status_tx).warn(format!(
                    "NetBIOS-NS client {} injected action failed: {}",
                    client_id, e
                ));
            }
            let _ = status_tx.send("__UPDATE_UI__".to_string());
            crate::client::command_support::reply(command, outcome);

            if disconnect {
                Self::finish(client_id, &app_state, &status_tx).await;
                break;
            }

            // The model still gets its turn on an injected query's answer, and whatever it
            // asks for next is executed rather than counted.
            if let Some((event_type, event_data)) = answered {
                let follow_ups = Self::report(
                    event_type,
                    event_data,
                    &protocol,
                    client_id,
                    &app_state,
                    &llm_client,
                    &status_tx,
                )
                .await;
                Self::run_actions(
                    &protocol,
                    &transport,
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
    }

    /// End the session. UDP has no wire close, so "disconnected" means: stop accepting
    /// commands, drop the handle so the dashboard greys out \[send\], and mark the client.
    async fn finish(
        client_id: ClientId,
        app_state: &Arc<AppState>,
        status_tx: &mpsc::UnboundedSender<String>,
    ) {
        info!("NetBIOS-NS client {} disconnecting", client_id);
        app_state.remove_client_handle(client_id).await;
        app_state
            .update_client_status(client_id, ClientStatus::Disconnected)
            .await;
        let _ = status_tx.send("__UPDATE_UI__".to_string());
    }
}

/// Work out where queries go by default.
///
/// A literal address is never handed to the system resolver: `getaddrinfo("127.0.0.1")` is a
/// real call that has been measured at 8.25 seconds under concurrency on macOS, and it can
/// only ever return what was already written down.
async fn resolve_target(remote_addr: &str, port_override: Option<u16>) -> Result<SocketAddr> {
    let remote_addr = remote_addr.trim();

    if let Ok(addr) = remote_addr.parse::<SocketAddr>() {
        return Ok(match port_override {
            Some(port) => SocketAddr::new(addr.ip(), port),
            None => addr,
        });
    }
    if let Ok(ip) = remote_addr.parse::<IpAddr>() {
        return Ok(SocketAddr::new(
            ip,
            port_override.unwrap_or(DEFAULT_NBNS_PORT),
        ));
    }

    // A hostname genuinely needs the resolver. Split off an explicit port if there is one.
    let (host, port) = match remote_addr.rsplit_once(':') {
        Some((host, port)) if port.chars().all(|c| c.is_ascii_digit()) && !port.is_empty() => (
            host,
            port.parse::<u16>()
                .with_context(|| format!("'{port}' is not a port number"))?,
        ),
        _ => (remote_addr, DEFAULT_NBNS_PORT),
    };
    let port = port_override.unwrap_or(port);

    tokio::net::lookup_host((host, port))
        .await
        .with_context(|| format!("could not resolve NetBIOS-NS target '{remote_addr}'"))?
        // NBNS is IPv4 by construction: its resource records carry four-octet addresses.
        .find(|addr| addr.is_ipv4())
        .with_context(|| format!("'{remote_addr}' has no IPv4 address; NetBIOS-NS is IPv4 only"))
}

/// Per-action target override, falling back to the address the client was opened against.
fn target_for(default_target: SocketAddr, data: &serde_json::Value) -> Result<SocketAddr> {
    let ip = match data.get("target_address").and_then(|v| v.as_str()) {
        Some(text) => text.trim().parse::<IpAddr>().with_context(|| {
            format!("'target_address' must be a dotted-quad IPv4 address, got '{text}'")
        })?,
        None => default_target.ip(),
    };
    let port = match data.get("target_port").and_then(|v| v.as_u64()) {
        Some(port) => u16::try_from(port)
            .with_context(|| format!("'target_port' must be between 0 and 65535, got {port}"))?,
        None => default_target.port(),
    };
    Ok(SocketAddr::new(ip, port))
}
