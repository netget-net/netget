//! Ethereum devp2p node: RLPx over TCP, the base protocol, and `eth/68` / `eth/69`.
//!
//! NetGet owns the transport and the encoding — the ECIES handshake, frame encryption and MACs,
//! Snappy, RLP, Hello, Ping/Pong — and computes every block hash. The model owns policy and
//! content: which peers to admit and with what Status (`eth_status`), what to answer when a peer
//! asks for headers, bodies or pooled transactions, and what to ask the peer for.
//!
//! A session runs: RLPx handshake and Hello (Rust, [`session::establish`]) → the peer's Status
//! → `eth_status` to the model → this node's Status or a Disconnect → requests both ways until
//! one side disconnects. The reader task answers the peer's Pings itself, so a slow model never
//! makes go-ethereum's 30-second read deadline fire.
//!
//! ## Failing closed
//!
//! Disconnect is the only refusal devp2p has, and it is what every failure here sends:
//!
//! - `eth_status` with no usable answer (backend down, nothing, a refused Status) →
//!   Disconnect `subprotocol_error`, `decision=fail_closed_*` / `model_silent`. An answer
//!   without `eth_send_status` is a refusal: Disconnect `useless_peer`, `decision=model_reject`.
//! - A peer request (headers, bodies, pooled transactions) still unanswered after the model's
//!   turn → Disconnect `subprotocol_error`. NetGet never invents an answer: a header the model
//!   did not write is never sent, and an empty answer is only ever the model's own.
//! - A frame that fails its MAC, a message past the bounds, a malformed message →
//!   Disconnect `breach_of_protocol`, `decision=protocol_error` /
//!   `fail_closed_message_too_large`, before any model call.
//!
//! Every outcome writes one `decision=` line.
pub mod actions;
pub mod crypto;
pub mod eth;
pub mod rlp;
pub mod rlpx;
pub mod session;

use crate::llm::action_helper::call_llm;
use crate::llm::actions::protocol_trait::ActionResult;
use crate::llm::ollama_client::OllamaClient;
use crate::logging::emit::Log;
use crate::protocol::{Event, EventType};
use crate::server::connection::ConnectionId;
use crate::state::app_state::AppState;
use crate::state::client_handles::{ClientCommand, ClientSendOutcome};
use crate::state::server::{ConnectionState, ConnectionStatus, ProtocolConnectionInfo};
use crate::state::ServerId;
use actions::{CommonConfig, Devp2pProtocol};
use anyhow::Result;
use serde_json::{json, Value};
use session::{Applied, Command, Inbound, PeerEvent, PeerEventKind, Session};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

/// How long a new connection has to send its first byte (the dialler speaks first in RLPx).
const FIRST_BYTE_TIMEOUT: Duration = Duration::from_secs(10);
/// How long after Hello the peer has to send its Status.
pub const STATUS_TIMEOUT: Duration = Duration::from_secs(10);
/// Concurrent connections.
const MAX_CONNECTIONS: usize = crate::server::accept_bounded::DEFAULT_MAX_CONNECTIONS;
/// How many model turns may follow from one another (a request whose answer prompts a request).
pub const MAX_FOLLOWUP_DEPTH: u32 = 8;
/// Decoded messages the reader may queue while a model call runs.
const INBOUND_QUEUE: usize = 32;

/// Disconnect reasons used here.
const BREACH: u64 = 0x02;
const USELESS_PEER: u64 = 0x03;
const SUBPROTOCOL_ERROR: u64 = 0x10;

pub struct Devp2pServer;

struct Shared {
    config: CommonConfig,
    app_state: Arc<AppState>,
    llm_client: OllamaClient,
    status_tx: mpsc::UnboundedSender<String>,
    server_id: ServerId,
}

/// The event type the model hears for a session event.
pub fn event_type_for(kind: PeerEventKind) -> &'static EventType {
    match kind {
        PeerEventKind::HeadersRequested => &actions::HEADERS_REQUESTED_EVENT,
        PeerEventKind::BodiesRequested => &actions::BODIES_REQUESTED_EVENT,
        PeerEventKind::PooledRequested => &actions::POOLED_REQUESTED_EVENT,
        PeerEventKind::Announced => &actions::ANNOUNCED_EVENT,
        PeerEventKind::HeadersReceived => &actions::HEADERS_RECEIVED_EVENT,
        PeerEventKind::BodiesReceived => &actions::BODIES_RECEIVED_EVENT,
        PeerEventKind::PooledReceived => &actions::POOLED_RECEIVED_EVENT,
        PeerEventKind::RequestTimedOut => &actions::REQUEST_TIMEOUT_EVENT,
    }
}

impl Devp2pServer {
    pub async fn spawn(
        listen_addr: SocketAddr,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        server_id: ServerId,
        config: CommonConfig,
    ) -> Result<SocketAddr> {
        let listener =
            crate::server::socket_helpers::create_reusable_tcp_listener(listen_addr).await?;
        let local_addr = listener.local_addr()?;
        let enode = eth::format_enode(&config.key.id(), local_addr);
        Log::new(Some(&status_tx)).info(format!("devp2p node {enode}"));
        // The E2E harness parses the port out of everything after the last "on ".
        Log::new(Some(&status_tx)).info(format!("devp2p server listening on {local_addr}"));
        let shared = Arc::new(Shared {
            config,
            app_state: app_state.clone(),
            llm_client,
            status_tx: status_tx.clone(),
            server_id,
        });
        let limiter = crate::server::accept_bounded::ConnectionLimiter::new(MAX_CONNECTIONS);
        let registrar = app_state.clone();
        let accept = tokio::spawn(async move {
            loop {
                // RLPx is dialler-speaks-first and nothing can be said before the handshake,
                // so a peer over the cap is refused with a plain close.
                match crate::server::accept_bounded::accept_bounded(
                    &listener,
                    &limiter,
                    b"",
                    "devp2p",
                    Some(&status_tx),
                )
                .await
                {
                    Ok((stream, remote, permit)) => {
                        let shared = shared.clone();
                        let local = stream.local_addr().unwrap_or(local_addr);
                        app_state
                            .spawn_server_task(server_id, async move {
                                let _permit = permit;
                                Self::handle_connection(shared, stream, remote, local).await;
                            })
                            .await;
                    }
                    Err(e) => {
                        Log::new(Some(&status_tx))
                            .error(format!("devp2p accept failed, stopping loop: {e}"));
                        break;
                    }
                }
            }
        });
        registrar.register_server_task(server_id, accept).await;
        Ok(local_addr)
    }

    async fn handle_connection(
        shared: Arc<Shared>,
        stream: tokio::net::TcpStream,
        remote: SocketAddr,
        local: SocketAddr,
    ) {
        let app_state = shared.app_state.clone();
        let server_id = shared.server_id;
        let log = Log::new(Some(&shared.status_tx));
        let connection_id = ConnectionId::new(app_state.get_next_unified_id().await);
        let _ = stream.set_nodelay(true);
        let now = crate::utils::clock::Instant::now();
        app_state
            .add_connection_to_server(
                server_id,
                ConnectionState {
                    id: connection_id,
                    remote_addr: remote,
                    local_addr: local,
                    bytes_sent: 0,
                    bytes_received: 0,
                    packets_sent: 0,
                    packets_received: 0,
                    last_activity: now,
                    status: ConnectionStatus::Active,
                    status_changed_at: now,
                    protocol_info: ProtocolConnectionInfo::empty(),
                },
            )
            .await;
        let _ = shared.status_tx.send("__UPDATE_UI__".to_string());

        let (read_half, write_half) = tokio::io::split(stream);
        let reader = crate::server::accept_bounded::IdleTimeoutReader::with_first(
            read_half,
            FIRST_BYTE_TIMEOUT,
            session::IDLE_TIMEOUT,
        );
        match session::establish(
            Box::new(reader),
            Box::new(write_half),
            &shared.config.key,
            session::Role::Listen,
            &shared.config.client_id,
            local.port(),
        )
        .await
        {
            Ok(est) => {
                log.info(format!(
                    "devp2p {connection_id}: peer {} ({}) at {remote}, eth/{}",
                    &hex::encode(est.remote_id)[..16],
                    est.hello.client_id,
                    est.eth_version
                ));
                let mut peer_rx = crate::server::peer_support::register_peer_channel(
                    &app_state,
                    server_id,
                    connection_id.as_u32(),
                )
                .await;
                let (tx, rx) = mpsc::channel(INBOUND_QUEUE);
                let reader_task = app_state
                    .spawn_server_task(
                        server_id,
                        session::read_loop(est.reader, est.read_half, est.writer.clone(), tx),
                    )
                    .await;
                let writer = est.writer.clone();
                let reason = run(
                    &shared,
                    Session::new(est.writer, est.eth_version),
                    &est.hello,
                    est.remote_id,
                    remote,
                    connection_id,
                    rx,
                    &mut peer_rx,
                )
                .await;
                reader_task.abort();
                session::close(&writer).await;
                log.info(format!("devp2p {connection_id}: session ended: {reason}"));
                app_state
                    .remove_peer_handle(server_id, connection_id.as_u32())
                    .await;
            }
            Err(session::EstablishError::Transport(e)) => {
                log.warn(format!(
                    "devp2p {connection_id} from {remote} refused decision=protocol_error: {e}"
                ));
            }
            Err(session::EstablishError::PeerDisconnected(r)) => {
                log.info(format!(
                    "devp2p {connection_id} from {remote}: the peer disconnected during Hello ({})",
                    eth::reason_name(r)
                ));
            }
            Err(e @ session::EstablishError::Refused { .. }) => {
                log.warn(format!(
                    "devp2p {connection_id} from {remote} decision=protocol_reject: {e}"
                ));
            }
        }
        app_state
            .remove_connection_from_server(server_id, connection_id)
            .await;
        let _ = shared.status_tx.send("__UPDATE_UI__".to_string());
    }
}

/// The session after Hello: Status, then events until it ends. Returns why it ended.
#[allow(clippy::too_many_arguments)]
async fn run(
    shared: &Shared,
    mut s: Session,
    hello: &eth::Hello,
    remote_id: [u8; 64],
    remote: SocketAddr,
    id: ConnectionId,
    mut rx: mpsc::Receiver<Inbound>,
    peer_rx: &mut mpsc::Receiver<ClientCommand>,
) -> String {
    let log = Log::new(Some(&shared.status_tx));
    // The peer's Status comes first: nothing else is valid before it.
    let status = match tokio::time::timeout(STATUS_TIMEOUT, rx.recv()).await {
        Err(_) => {
            log.warn(format!(
                "devp2p {id}: no Status within {}s decision=fail_closed_status_timeout",
                STATUS_TIMEOUT.as_secs()
            ));
            session::disconnect(&s.writer, 0x0b).await;
            return "no Status".into();
        }
        Ok(None) => return "the reader stopped".into(),
        Ok(Some(Inbound::Ended(end))) => return ended(&log, id, end),
        Ok(Some(Inbound::Message { code, payload })) => {
            if code == eth::code::DISCONNECT {
                return format!(
                    "the peer disconnected: {}",
                    eth::reason_name(eth::decode_disconnect(&payload))
                );
            }
            match s.take_status(code, &payload) {
                Ok(Some(status)) => status,
                Ok(None) => {
                    log.warn(format!(
                        "devp2p {id}: message {code:#04x} before Status decision=protocol_error"
                    ));
                    session::disconnect(&s.writer, BREACH).await;
                    return "no Status".into();
                }
                Err(e) => {
                    log.warn(format!(
                        "devp2p {id}: bad Status decision=protocol_error: {e:#}"
                    ));
                    session::disconnect(&s.writer, BREACH).await;
                    return format!("bad Status: {e:#}");
                }
            }
        }
    };
    let event = Event::new(
        &actions::STATUS_EVENT,
        json!({
            "remote": remote.to_string(),
            "client_id": hello.client_id,
            "node_id": hex::encode(remote_id),
            "capabilities": hello.caps_strings(),
            "eth_version": s.eth_version,
            "peer_status": status.to_json(),
            "configured": shared.config.defaults.to_json(),
        }),
    );
    let decision = consult(shared, id, &event).await;
    if decision.no_answer {
        session::disconnect(&s.writer, SUBPROTOCOL_ERROR).await;
        return "no usable answer to eth_status".into();
    }
    let admits = decision
        .commands
        .iter()
        .any(|c| matches!(c, Command::SendStatus(_)));
    let refuses = decision
        .commands
        .iter()
        .any(|c| matches!(c, Command::Disconnect(_)));
    if !admits && !refuses {
        log.info(format!(
            "devp2p {id}: eth_status answered without eth_send_status decision=model_reject"
        ));
        session::disconnect(&s.writer, USELESS_PEER).await;
        return "not admitted".into();
    }
    if let Some(reason) = carry_out(shared, &mut s, id, decision.commands, None, 0).await {
        return reason;
    }
    if !s.ready() {
        session::disconnect(&s.writer, SUBPROTOCOL_ERROR).await;
        return "the Status could not be sent".into();
    }
    if let (Some(ours), Some(theirs)) = (&s.our_status, &s.peer_status) {
        if let Err(why) = session::compatible(ours, theirs) {
            log.warn(format!(
                "devp2p {id}: this node's Status is not the peer's chain ({why}); the peer will likely disconnect"
            ));
        }
    }

    let mut ping = tokio::time::interval(session::PING_INTERVAL);
    ping.tick().await;
    let mut peer_open = true;
    loop {
        tokio::select! {
            m = rx.recv() => match m {
                None => return "the reader stopped".into(),
                Some(Inbound::Ended(end)) => return ended(&log, id, end),
                Some(Inbound::Message { code, payload }) => {
                    shared.app_state
                        .update_connection_stats(shared.server_id, id, Some(payload.len() as u64), None, Some(1), None)
                        .await;
                    if code == eth::code::DISCONNECT {
                        return format!("the peer disconnected: {}", eth::reason_name(eth::decode_disconnect(&payload)));
                    }
                    match s.on_message(code, &payload).await {
                        Ok(None) => {}
                        Ok(Some(ev)) => {
                            if let Some(reason) = handle(shared, &mut s, id, ev).await {
                                return reason;
                            }
                        }
                        Err(e) => {
                            log.warn(format!("devp2p {id}: decision=protocol_error: {e:#}"));
                            session::disconnect(&s.writer, BREACH).await;
                            return format!("protocol error: {e:#}");
                        }
                    }
                }
            },
            _ = ping.tick() => {
                if session::send(&s.writer, eth::code::PING, &eth::empty_payload()).await.is_err() {
                    return "the connection could not be written".into();
                }
                for ev in s.expire() {
                    if let Some(reason) = handle(shared, &mut s, id, ev).await {
                        return reason;
                    }
                }
            }
            c = peer_rx.recv(), if peer_open => {
                // A closed channel would otherwise be ready forever and spin this loop.
                let Some(c) = c else {
                    peer_open = false;
                    continue;
                };
                if let Some(reason) = inject(shared, &mut s, id, c).await {
                    return reason;
                }
            }
        }
    }
}

fn ended(log: &Log, id: ConnectionId, end: session::End) -> String {
    if let Some(tag) = end.decision {
        log.warn(format!("devp2p {id}: {} decision={tag}", end.reason));
    }
    end.reason
}

/// Raise one session event and carry out the answer. Returns `Some(reason)` when the session
/// is over.
async fn handle(
    shared: &Shared,
    s: &mut Session,
    id: ConnectionId,
    ev: PeerEvent,
) -> Option<String> {
    let log = Log::new(Some(&shared.status_tx));
    let event_type = event_type_for(ev.kind);
    if ev.depth >= MAX_FOLLOWUP_DEPTH {
        log.warn(format!(
            "devp2p {id}: not asking the model about {}: {} turns deep decision=followup_depth",
            event_type.id, ev.depth
        ));
        return None;
    }
    let event = Event::new(event_type, ev.data.clone());
    let decision = consult(shared, id, &event).await;
    if !decision.no_answer {
        if let Some(reason) =
            carry_out(shared, s, id, decision.commands, ev.request_id, ev.depth).await
        {
            return Some(reason);
        }
    }
    if let Some(request_id) = ev.request_id {
        if s.owes(request_id) {
            // The peer asked and nothing true can be said: close rather than invent an answer.
            log.warn(format!(
                "devp2p {id}: {} {request_id} left unanswered decision=fail_closed_unanswered",
                event_type.id
            ));
            session::disconnect(&s.writer, SUBPROTOCOL_ERROR).await;
            return Some(format!("{} {request_id} unanswered", event_type.id));
        }
    }
    None
}

/// Apply the model's commands in order. Returns `Some(reason)` when one ended the session.
async fn carry_out(
    shared: &Shared,
    s: &mut Session,
    id: ConnectionId,
    commands: Vec<Command>,
    answering: Option<u64>,
    depth: u32,
) -> Option<String> {
    let log = Log::new(Some(&shared.status_tx));
    for command in commands {
        let before = s.bytes_sent;
        match s
            .apply(command, answering, depth, &shared.config.defaults)
            .await
        {
            Ok(Applied::Disconnected(r)) => {
                return Some(format!("disconnected ({})", eth::reason_name(r)))
            }
            Ok(Applied::StatusSent(st)) => {
                log.info(format!("devp2p {id}: Status sent: {}", st.to_json()));
            }
            Ok(Applied::Sent(what)) => log.info(format!("devp2p {id}: {what}")),
            Err(e) => {
                log.error(format!(
                    "devp2p {id}: action refused decision=fail_closed_bad_action: {e:#}"
                ));
            }
        }
        if s.bytes_sent > before {
            shared
                .app_state
                .update_connection_stats(
                    shared.server_id,
                    id,
                    None,
                    Some(s.bytes_sent - before),
                    None,
                    Some(1),
                )
                .await;
        }
    }
    None
}

/// An action injected for this peer from the dashboard or MCP.
async fn inject(
    shared: &Shared,
    s: &mut Session,
    id: ConnectionId,
    command: ClientCommand,
) -> Option<String> {
    shared
        .app_state
        .record_access_log(
            crate::state::AccessLogOwner::Server(shared.server_id.as_u32()),
            "devp2p",
            None,
            "injected_action",
            command.action.clone(),
            vec![],
        )
        .await;
    let (outcome, end) = match session::parse_command(&command.action) {
        Err(e) => (
            ClientSendOutcome::Rejected {
                error: format!("{e:#}"),
            },
            None,
        ),
        Ok(cmd) => match s.apply(cmd, None, 0, &shared.config.defaults).await {
            Ok(Applied::Disconnected(r)) => (
                ClientSendOutcome::Disconnected,
                Some(format!(
                    "disconnected by the operator ({})",
                    eth::reason_name(r)
                )),
            ),
            Ok(Applied::StatusSent(st)) => (
                ClientSendOutcome::Executed {
                    detail: st.to_json().to_string(),
                },
                None,
            ),
            Ok(Applied::Sent(what)) => (ClientSendOutcome::Executed { detail: what }, None),
            Err(e) => (
                ClientSendOutcome::Rejected {
                    error: format!("{e:#}"),
                },
                None,
            ),
        },
    };
    Log::new(Some(&shared.status_tx)).info(format!("devp2p {id}: injected action: {outcome:?}"));
    let _ = command.reply_tx.send(Ok(outcome));
    end
}

/// What the model said about one event.
struct Decision {
    commands: Vec<Command>,
    /// No usable answer arrived; the reason is in the log.
    no_answer: bool,
}

/// Ask the model and validate its answer. Writes the event's `decision=` line.
async fn consult(shared: &Shared, id: ConnectionId, event: &Event) -> Decision {
    let log = Log::new(Some(&shared.status_tx));
    let name = &event.event_type.id;
    let execution = match call_llm(
        &shared.llm_client,
        &shared.app_state,
        shared.server_id,
        Some(id),
        event,
        &Devp2pProtocol::new(),
    )
    .await
    {
        Ok(x) => x,
        Err(e) => {
            let tag = match crate::utils::wire_failure::WireFailure::classify(&e) {
                crate::utils::wire_failure::WireFailure::Overloaded => "fail_closed_llm_overloaded",
                crate::utils::wire_failure::WireFailure::Unavailable => "fail_closed_llm_error",
            };
            log.error(format!(
                "devp2p {id}: {name} not answered decision={tag}: {e}"
            ));
            return Decision {
                commands: Vec::new(),
                no_answer: true,
            };
        }
    };
    for m in execution.messages {
        let _ = shared.status_tx.send(m);
    }
    let mut actions: Vec<Value> = Vec::new();
    let mut stack = execution.protocol_results;
    stack.reverse();
    while let Some(r) = stack.pop() {
        match r {
            ActionResult::Custom { data, .. } => actions.push(data),
            ActionResult::Multiple(inner) => stack.extend(inner.into_iter().rev()),
            _ => {}
        }
    }
    let commands: Vec<Command> = actions
        .iter()
        .filter_map(|a| session::parse_command(a).ok())
        .collect();
    let refused: Vec<String> = execution
        .failures
        .iter()
        .map(|f| format!("{}: {}", f.action, f.error))
        .collect();
    let no_answer = commands.is_empty();
    if commands.is_empty() && refused.is_empty() {
        log.warn(format!(
            "devp2p {id}: {name} produced no action decision=model_silent"
        ));
    } else if commands.is_empty() {
        log.error(format!(
            "devp2p {id}: {name} produced no usable action decision=fail_closed_bad_action ({})",
            refused.join("; ")
        ));
    } else if commands.iter().any(|c| matches!(c, Command::Disconnect(_))) {
        log.info(format!("devp2p {id}: {name} decision=model_reject"));
    } else {
        if !refused.is_empty() {
            log.warn(format!(
                "devp2p {id}: {name}: some actions refused: {}",
                refused.join("; ")
            ));
        }
        log.info(format!("devp2p {id}: {name} decision=model_answer"));
    }
    Decision {
        commands,
        no_answer,
    }
}
