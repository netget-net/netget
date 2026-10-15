//! devp2p dialler. Connects to a node named by its enode URL, runs the RLPx handshake as the
//! initiator and the Hello exchange (the server's `session::establish`), then hands the session
//! to a task that asks the model for this node's Status and carries out its requests.
//!
//! `connect()` returns once Hello is done; the model is never consulted inside it, so a parked
//! manual answer cannot stall the client's creation.
//!
//! The Status exchange: go-ethereum and reth send their Status as soon as Hello is done. The
//! session waits [`STATUS_WAIT`] for it, then raises `eth_status` either way — with the peer's
//! Status, or with `peer_status: null` when the peer is waiting for ours (another NetGet node
//! does). Requests the model gives alongside its Status go out once both are exchanged.
//!
//! Failing closed: no usable answer to `eth_status` → Disconnect `subprotocol_error`; an answer
//! without `eth_send_status` → Disconnect `useless_peer`; a peer request still unanswered after
//! the model's turn → Disconnect `subprotocol_error`. A follow-up chain (an answer prompting a
//! request whose answer prompts another) stops at [`MAX_FOLLOWUP_DEPTH`].
pub mod actions;

use crate::client::llm_budget::call_llm_for_client;
use crate::logging::emit::Log;
use crate::protocol::{ConnectContext, Event, EventType};
use crate::server::devp2p::actions::{common_config, CommonConfig};
use crate::server::devp2p::session::{
    self, Applied, Command, Inbound, PeerEvent, PeerEventKind, Session,
};
use crate::server::devp2p::{crypto, eth};
use crate::state::client_handles::{ClientCommand, ClientSendOutcome};
use crate::state::{AccessLogOwner, ClientStatus};
pub use actions::Devp2pClientProtocol;
use anyhow::{Context, Result};
use serde_json::json;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::sync::mpsc;

/// TCP connect.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// How long to wait for the peer's Status before asking the model to speak first.
pub const STATUS_WAIT: Duration = Duration::from_millis(1500);
/// How many model turns may follow from one another.
pub const MAX_FOLLOWUP_DEPTH: u32 = 8;
const INBOUND_QUEUE: usize = 32;

const USELESS_PEER: u64 = 0x03;
const BREACH: u64 = 0x02;
const SUBPROTOCOL_ERROR: u64 = 0x10;

fn event_type_for(kind: PeerEventKind) -> &'static EventType {
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

pub async fn connect(ctx: ConnectContext) -> Result<SocketAddr> {
    let config = common_config(ctx.startup_params.as_ref())?;
    let (node_id, target) = eth::parse_enode(&ctx.remote_addr)?;
    let remote_key = crypto::public_from_id(&node_id)?;
    let server = tokio::net::lookup_host(&target)
        .await
        .with_context(|| format!("cannot resolve {target}"))?
        .next()
        .with_context(|| format!("{target} resolved to no address"))?;
    let stream = tokio::time::timeout(CONNECT_TIMEOUT, tokio::net::TcpStream::connect(server))
        .await
        .with_context(|| format!("connecting to {server} timed out"))?
        .with_context(|| format!("cannot reach {server}"))?;
    let _ = stream.set_nodelay(true);
    let (r, w) = stream.into_split();
    let r = crate::server::accept_bounded::IdleTimeoutReader::new(r, session::IDLE_TIMEOUT);
    let est = session::establish(
        Box::new(r),
        Box::new(w),
        &config.key,
        session::Role::Dial(remote_key),
        &config.client_id,
        0,
    )
    .await
    .map_err(|e| anyhow::anyhow!("devp2p session with {server}: {e}"))?;
    ctx.state
        .update_client_status(ctx.client_id, ClientStatus::Connected)
        .await;
    Log::new(Some(&ctx.status_tx)).info(format!(
        "devp2p client {} connected to {} ({}) at {server}, eth/{}, as {}",
        ctx.client_id,
        &hex::encode(est.remote_id)[..16],
        est.hello.client_id,
        est.eth_version,
        eth::format_enode(&config.key.id(), server)
            .split('@')
            .next()
            .unwrap_or_default()
    ));
    let external =
        crate::client::command_support::register_command_channel(&ctx.state, ctx.client_id).await;
    let (tx, rx) = mpsc::channel(INBOUND_QUEUE);
    let reader = tokio::spawn(session::read_loop(
        est.reader,
        est.read_half,
        est.writer.clone(),
        tx,
    ));
    let reader_abort = reader.abort_handle();
    ctx.state.register_client_task(ctx.client_id, reader).await;
    let session_ctx = ctx.clone();
    let task = tokio::spawn(async move {
        let mut client = Devp2pClient {
            ctx: session_ctx.clone(),
            config,
            session: Session::new(est.writer, est.eth_version),
            server,
        };
        let reason = client.run(&est.hello, est.remote_id, rx, external).await;
        reader_abort.abort();
        session::close(&client.session.writer).await;
        Log::new(Some(&session_ctx.status_tx)).info(format!(
            "devp2p client {} disconnected: {reason}",
            session_ctx.client_id
        ));
        client
            .ask(
                &Event::new(&actions::DISCONNECTED_EVENT, json!({"reason": reason})),
                0,
            )
            .await;
        session_ctx
            .state
            .update_client_status(session_ctx.client_id, ClientStatus::Disconnected)
            .await;
        session_ctx
            .state
            .remove_client_handle(session_ctx.client_id)
            .await;
        let _ = session_ctx.status_tx.send("__UPDATE_UI__".into());
    });
    ctx.state.register_client_task(ctx.client_id, task).await;
    Ok(server)
}

struct Devp2pClient {
    ctx: ConnectContext,
    config: CommonConfig,
    session: Session,
    server: SocketAddr,
}

/// What the model answered: validated commands, or None when there was no answer at all.
type Answer = Option<Vec<(Command, String)>>;

impl Devp2pClient {
    fn log(&self) -> Log<'_> {
        Log::new(Some(&self.ctx.status_tx))
    }

    /// Ask the model about one event. `None` when the backend failed (logged
    /// `decision=fail_closed_*`); otherwise the actions it gave, validated, and the ones
    /// refused with why.
    async fn ask_raw(
        &mut self,
        event: &Event,
    ) -> Option<(Vec<(Command, String)>, Vec<(String, String)>)> {
        let instruction = self
            .ctx
            .state
            .get_instruction_for_client(self.ctx.client_id)
            .await
            .unwrap_or_default();
        let memory = self
            .ctx
            .state
            .get_memory_for_client(self.ctx.client_id)
            .await
            .unwrap_or_default();
        let name = event.id().to_string();
        let result = match call_llm_for_client(
            &self.ctx.llm_client,
            &self.ctx.state,
            self.ctx.client_id.to_string(),
            &instruction,
            &memory,
            Some(event),
            &Devp2pClientProtocol,
            &self.ctx.status_tx,
        )
        .await
        {
            Ok(r) => r,
            Err(e) => {
                let tag = match crate::utils::wire_failure::WireFailure::classify(&e) {
                    crate::utils::wire_failure::WireFailure::Overloaded => {
                        "fail_closed_llm_overloaded"
                    }
                    crate::utils::wire_failure::WireFailure::Unavailable => "fail_closed_llm_error",
                };
                self.log().error(format!(
                    "devp2p client {}: {name} not answered decision={tag}: {e}",
                    self.ctx.client_id
                ));
                return None;
            }
        };
        if let Some(memory) = result.memory_updates {
            self.ctx
                .state
                .set_memory_for_client(self.ctx.client_id, memory)
                .await;
        }
        let mut commands = Vec::new();
        let mut refused = Vec::new();
        for action in result.actions {
            let kind = action["type"].as_str().unwrap_or_default().to_string();
            match session::parse_command(&action) {
                Ok(c) => commands.push((c, kind)),
                Err(e) => {
                    self.log().error(format!(
                        "devp2p client {}: {kind} refused decision=fail_closed_bad_action: {e:#}",
                        self.ctx.client_id
                    ));
                    refused.push((kind, format!("{e:#}")));
                }
            }
        }
        Some((commands, refused))
    }

    /// [`Self::ask_raw`], telling the model about every refused action.
    async fn ask(&mut self, event: &Event, depth: u32) -> Answer {
        let (commands, refused) = self.ask_raw(event).await?;
        for (kind, message) in refused {
            self.error_event(&kind, &message, depth).await;
        }
        Some(commands)
    }

    /// Tell the model an action failed, unless the chain is already as deep as it may go. Its
    /// answer is carried out once; a failure there is only logged, so errors cannot loop.
    async fn error_event(&mut self, action: &str, message: &str, depth: u32) {
        if depth + 1 >= MAX_FOLLOWUP_DEPTH {
            return;
        }
        let event = Event::new(
            &actions::ERROR_EVENT,
            json!({"action": action, "message": message}),
        );
        let Some((commands, _)) = self.ask_raw(&event).await else {
            return;
        };
        for (c, kind) in commands {
            if let Err(e) = self.apply(c, None, depth + 1).await {
                self.log().warn(format!(
                    "devp2p client {}: {kind} after an error also failed: {e:#}",
                    self.ctx.client_id
                ));
            }
        }
    }

    async fn apply(
        &mut self,
        command: Command,
        answering: Option<u64>,
        depth: u32,
    ) -> Result<Applied> {
        let applied = self
            .session
            .apply(command, answering, depth, &self.config.defaults)
            .await?;
        match &applied {
            Applied::Sent(what) => self
                .log()
                .info(format!("devp2p client {}: {what}", self.ctx.client_id)),
            Applied::StatusSent(st) => self.log().info(format!(
                "devp2p client {}: Status sent: {}",
                self.ctx.client_id,
                st.to_json()
            )),
            Applied::Disconnected(_) => {}
        }
        Ok(applied)
    }

    /// Carry out the model's commands; deferred ones (sent before both Statuses were
    /// exchanged) are returned. `Err(reason)` when the session is over.
    async fn carry_out(
        &mut self,
        commands: Vec<(Command, String)>,
        answering: Option<u64>,
        depth: u32,
    ) -> std::result::Result<Vec<(Command, String)>, String> {
        let mut deferred = Vec::new();
        for (command, kind) in commands {
            let waits = !self.session.ready()
                && !matches!(command, Command::SendStatus(_) | Command::Disconnect(_));
            if waits {
                deferred.push((command, kind));
                continue;
            }
            match self.apply(command, answering, depth).await {
                Ok(Applied::Disconnected(r)) => {
                    return Err(format!("disconnected ({})", eth::reason_name(r)))
                }
                Ok(_) => {}
                Err(e) => {
                    self.log().error(format!(
                        "devp2p client {}: {kind} refused decision=fail_closed_bad_action: {e:#}",
                        self.ctx.client_id
                    ));
                    self.error_event(&kind, &format!("{e:#}"), depth).await;
                }
            }
        }
        Ok(deferred)
    }

    /// Wait for the peer's Status. `Ok(None)` on timeout.
    async fn read_status(
        &mut self,
        rx: &mut mpsc::Receiver<Inbound>,
        wait: Duration,
    ) -> std::result::Result<Option<eth::Status>, String> {
        let m = match tokio::time::timeout(wait, rx.recv()).await {
            Err(_) => return Ok(None),
            Ok(m) => m,
        };
        match m {
            None => Err("the reader stopped".into()),
            Some(Inbound::Ended(end)) => Err(self.ended(end)),
            Some(Inbound::Message { code, payload }) => {
                if code == eth::code::DISCONNECT {
                    return Err(format!(
                        "the peer disconnected: {}",
                        eth::reason_name(eth::decode_disconnect(&payload))
                    ));
                }
                match self.session.take_status(code, &payload) {
                    Ok(Some(s)) => Ok(Some(s)),
                    Ok(None) => {
                        self.log().warn(format!(
                            "devp2p client {}: message {code:#04x} before Status decision=protocol_error",
                            self.ctx.client_id
                        ));
                        session::disconnect(&self.session.writer, BREACH).await;
                        Err("the peer sent a message before its Status".into())
                    }
                    Err(e) => {
                        self.log().warn(format!(
                            "devp2p client {}: bad Status decision=protocol_error: {e:#}",
                            self.ctx.client_id
                        ));
                        session::disconnect(&self.session.writer, BREACH).await;
                        Err(format!("bad Status: {e:#}"))
                    }
                }
            }
        }
    }

    fn ended(&self, end: session::End) -> String {
        if let Some(tag) = end.decision {
            self.log().warn(format!(
                "devp2p client {}: {} decision={tag}",
                self.ctx.client_id, end.reason
            ));
        }
        end.reason
    }

    async fn run(
        &mut self,
        hello: &eth::Hello,
        remote_id: [u8; 64],
        mut rx: mpsc::Receiver<Inbound>,
        mut external: mpsc::Receiver<ClientCommand>,
    ) -> String {
        let id = self.ctx.client_id;
        let peer_status = match self.read_status(&mut rx, STATUS_WAIT).await {
            Ok(s) => s,
            Err(reason) => return reason,
        };
        let event = Event::new(
            &actions::STATUS_EVENT,
            json!({
                "remote": self.server.to_string(),
                "client_id": hello.client_id,
                "node_id": hex::encode(remote_id),
                "capabilities": hello.caps_strings(),
                "eth_version": self.session.eth_version,
                "peer_status": peer_status.as_ref().map(eth::Status::to_json),
                "configured": self.config.defaults.to_json(),
            }),
        );
        let Some(commands) = self.ask(&event, 0).await else {
            session::disconnect(&self.session.writer, SUBPROTOCOL_ERROR).await;
            return "no usable answer to eth_status".into();
        };
        let admits = commands
            .iter()
            .any(|(c, _)| matches!(c, Command::SendStatus(_)));
        let refuses = commands
            .iter()
            .any(|(c, _)| matches!(c, Command::Disconnect(_)));
        if commands.is_empty() {
            self.log().warn(format!(
                "devp2p client {id}: eth_status produced no action decision=model_silent"
            ));
            session::disconnect(&self.session.writer, SUBPROTOCOL_ERROR).await;
            return "no answer to eth_status".into();
        }
        if !admits && !refuses {
            self.log().info(format!(
                "devp2p client {id}: eth_status answered without eth_send_status decision=model_reject"
            ));
            session::disconnect(&self.session.writer, USELESS_PEER).await;
            return "the model did not send a Status".into();
        }
        self.log().info(format!(
            "devp2p client {id}: eth_status decision={}",
            if refuses {
                "model_reject"
            } else {
                "model_answer"
            }
        ));
        let deferred = match self.carry_out(commands, None, 0).await {
            Ok(d) => d,
            Err(reason) => return reason,
        };
        if self.session.our_status.is_none() {
            session::disconnect(&self.session.writer, SUBPROTOCOL_ERROR).await;
            return "the Status could not be sent".into();
        }
        if self.session.peer_status.is_none() {
            match self
                .read_status(&mut rx, crate::server::devp2p::STATUS_TIMEOUT)
                .await
            {
                Ok(Some(_)) => {}
                Ok(None) => {
                    self.log().warn(format!(
                        "devp2p client {id}: the peer sent no Status decision=fail_closed_status_timeout"
                    ));
                    session::disconnect(&self.session.writer, 0x0b).await;
                    return "the peer sent no Status".into();
                }
                Err(reason) => return reason,
            }
        }
        if let (Some(ours), Some(theirs)) = (&self.session.our_status, &self.session.peer_status) {
            match session::compatible(ours, theirs) {
                Ok(()) => self.log().info(format!(
                    "devp2p client {id}: eth handshake done with {}",
                    theirs.to_json()
                )),
                Err(why) => self.log().warn(format!(
                    "devp2p client {id}: this node's Status is not the peer's chain ({why}); the peer will likely disconnect"
                )),
            }
        }
        if let Err(reason) = self.carry_out(deferred, None, 0).await {
            return reason;
        }

        let mut ping = tokio::time::interval(session::PING_INTERVAL);
        ping.tick().await;
        loop {
            tokio::select! {
                m = rx.recv() => match m {
                    None => return "the reader stopped".into(),
                    Some(Inbound::Ended(end)) => return self.ended(end),
                    Some(Inbound::Message { code, payload }) => {
                        if code == eth::code::DISCONNECT {
                            return format!("the peer disconnected: {}", eth::reason_name(eth::decode_disconnect(&payload)));
                        }
                        match self.session.on_message(code, &payload).await {
                            Ok(None) => {}
                            Ok(Some(ev)) => {
                                if let Some(reason) = self.handle(ev).await {
                                    return reason;
                                }
                            }
                            Err(e) => {
                                self.log().warn(format!("devp2p client {id}: decision=protocol_error: {e:#}"));
                                session::disconnect(&self.session.writer, BREACH).await;
                                return format!("protocol error: {e:#}");
                            }
                        }
                    }
                },
                _ = ping.tick() => {
                    if session::send(&self.session.writer, eth::code::PING, &eth::empty_payload()).await.is_err() {
                        return "the connection could not be written".into();
                    }
                    for ev in self.session.expire() {
                        if let Some(reason) = self.handle(ev).await {
                            return reason;
                        }
                    }
                }
                c = external.recv() => match c {
                    None => {
                        session::disconnect(&self.session.writer, 0x08).await;
                        return "the client was stopped".into();
                    }
                    Some(c) => {
                        if let Some(reason) = self.inject(c).await {
                            return reason;
                        }
                    }
                },
            }
        }
    }

    /// Raise one session event and carry out the answer.
    async fn handle(&mut self, ev: PeerEvent) -> Option<String> {
        let event_type = event_type_for(ev.kind);
        if ev.depth >= MAX_FOLLOWUP_DEPTH {
            self.log().warn(format!(
                "devp2p client {}: not asking the model about {}: {} turns deep decision=followup_depth",
                self.ctx.client_id, event_type.id, ev.depth
            ));
        } else {
            let event = Event::new(event_type, ev.data.clone());
            if let Some(commands) = self.ask(&event, ev.depth).await {
                if commands.is_empty() {
                    self.log().info(format!(
                        "devp2p client {}: {} decision=model_silent",
                        self.ctx.client_id, event_type.id
                    ));
                }
                if let Err(reason) = self.carry_out(commands, ev.request_id, ev.depth).await {
                    return Some(reason);
                }
            }
        }
        if let Some(request_id) = ev.request_id {
            if self.session.owes(request_id) {
                self.log().warn(format!(
                    "devp2p client {}: {} {request_id} left unanswered decision=fail_closed_unanswered",
                    self.ctx.client_id, event_type.id
                ));
                session::disconnect(&self.session.writer, SUBPROTOCOL_ERROR).await;
                return Some(format!("{} {request_id} unanswered", event_type.id));
            }
        }
        None
    }

    /// An action sent to this client from the dashboard or MCP.
    async fn inject(&mut self, command: ClientCommand) -> Option<String> {
        self.ctx
            .state
            .record_access_log(
                AccessLogOwner::Client(self.ctx.client_id.as_u32()),
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
            Ok(cmd) => match self.apply(cmd, None, 0).await {
                Ok(Applied::Disconnected(r)) => (
                    ClientSendOutcome::Disconnected,
                    Some(format!("disconnected ({})", eth::reason_name(r))),
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
        crate::client::command_support::reply(command, Ok(outcome));
        end
    }
}
