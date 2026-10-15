//! H.323 endpoint: H.225.0 call signalling (Q.931 over TPKT) on TCP, the called side.
//!
//! One connection carries one call. The caller's Setup is decoded — numbers, aliases, display,
//! the caller's endpoint and vendor, its fastStart proposals and whether it tunnels H.245 — and
//! raised as `h323_setup`. The model answers with any of CallProceeding, Alerting, Connect,
//! Release Complete or a forward (Facility `callForwarded`, then Release Complete). NetGet
//! owns the rest: the call reference and its flag, the call and conference identifiers, the
//! fastStart answer, tunnelled H.245 (capability exchange, master-slave determination, logical
//! channels, end session) and the RTP/RTCP sockets the call advertises.
//!
//! ## Failing closed
//!
//! A Setup the model does not answer is never connected:
//!
//! - backend failure → Release Complete, cause 41 (temporary failure) or 42 (congestion) when
//!   overloaded, `decision=fail_closed_llm_*`;
//! - an answer with no call-control action → Release Complete cause 31, `decision=model_silent`;
//! - an answer that alerts but never connects → Release Complete cause 19 (no answer) after
//!   [`RING_TIMEOUT`];
//! - an action NetGet cannot carry out → logged `decision=fail_closed_bad_action`, and the call
//!   is released unless another action in the answer settled it.
//!
//! A malformed message, a message before Setup or a second Setup ends the call with Release
//! Complete cause 111 (protocol error) or `newConnectionNeeded`, before any model call.

use super::actions::{self as act, CallCommand};
use super::call::{self, cause, CallLeg, CallState, Incoming, MediaSockets, Role};
use super::q931::{self, ie, msg, Q931};
use super::{h225, h245};
use crate::llm::action_helper::call_llm;
use crate::llm::actions::protocol_trait::ActionResult;
use crate::llm::ollama_client::OllamaClient;
use crate::logging::emit::Log;
use crate::protocol::Event;
use crate::server::connection::ConnectionId;
use crate::state::app_state::AppState;
use crate::state::client_handles::{ClientCommand, ClientSendOutcome};
use crate::state::server::{ConnectionState, ConnectionStatus, ProtocolConnectionInfo};
use crate::state::ServerId;
use anyhow::Result;
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

/// How long a new connection has to send its Setup.
pub const FIRST_MESSAGE_TIMEOUT: Duration = Duration::from_secs(15);
/// Signalling silence a call may keep (a connected call is quiet on this connection while the
/// parties talk) before NetGet drops it.
pub const CALL_IDLE_TIMEOUT: Duration = Duration::from_secs(3600);
/// How long a call may ring (Alerting sent, no Connect) before it is released, cause 19.
pub const RING_TIMEOUT: Duration = Duration::from_secs(120);
/// Concurrent call-signalling connections.
pub const MAX_CONNECTIONS: usize = crate::server::accept_bounded::DEFAULT_MAX_CONNECTIONS;
/// Queued messages from the reader while the model decides.
const INBOUND_QUEUE: usize = 16;
/// User-input events raised per call.
const MAX_USER_INPUT_EVENTS: usize = 32;

#[derive(Clone, Debug)]
pub struct EndpointConfig {
    pub codecs: Vec<h245::Codec>,
}

struct Shared {
    config: EndpointConfig,
    app_state: Arc<AppState>,
    llm_client: OllamaClient,
    status_tx: mpsc::UnboundedSender<String>,
    server_id: ServerId,
}

pub async fn spawn(
    listen_addr: SocketAddr,
    llm_client: OllamaClient,
    app_state: Arc<AppState>,
    status_tx: mpsc::UnboundedSender<String>,
    server_id: ServerId,
    config: EndpointConfig,
) -> Result<SocketAddr> {
    let listener = crate::server::socket_helpers::create_reusable_tcp_listener(listen_addr).await?;
    let local_addr = listener.local_addr()?;
    Log::new(Some(&status_tx)).info(format!(
        "H.323 endpoint (H.225.0 call signalling) listening on {local_addr}"
    ));
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
            match crate::server::accept_bounded::accept_bounded(
                &listener,
                &limiter,
                b"",
                "H.323",
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
                            handle_connection(shared, stream, remote, local).await;
                        })
                        .await;
                }
                Err(e) => {
                    Log::new(Some(&status_tx))
                        .error(format!("H.323 accept failed, stopping loop: {e}"));
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
    let id = ConnectionId::new(app_state.get_next_unified_id().await);
    let now = crate::utils::clock::Instant::now();
    app_state
        .add_connection_to_server(
            server_id,
            ConnectionState {
                id,
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
    let _ = stream.set_nodelay(true);
    let (read_half, write_half) = stream.into_split();
    let reader = crate::server::accept_bounded::IdleTimeoutReader::with_first(
        read_half,
        FIRST_MESSAGE_TIMEOUT,
        CALL_IDLE_TIMEOUT,
    );
    let (tx, rx) = mpsc::channel(INBOUND_QUEUE);
    let reader_task = app_state
        .spawn_server_task(server_id, call::read_loop(reader, tx))
        .await;
    let reason = run(&shared, id, remote, local, write_half, rx).await;
    reader_task.abort();
    Log::new(Some(&shared.status_tx)).info(format!("H.323 {id} from {remote}: {reason}"));
    app_state.remove_peer_handle(server_id, id.as_u32()).await;
    app_state.remove_connection_from_server(server_id, id).await;
    let _ = shared.status_tx.send("__UPDATE_UI__".to_string());
}

/// Release Complete on a connection that has no call yet (no Setup, or a bad one).
async fn refuse_raw(writer: &mut tokio::net::tcp::OwnedWriteHalf, crv: u16, c: u8) {
    use tokio::io::AsyncWriteExt;
    let body = json!({"protocolIdentifier": h225::PROTOCOL_ID});
    if let Ok(uu) = h225::encode_user_information("releaseComplete", body, false, &[]) {
        let m = Q931::new(msg::RELEASE_COMPLETE, crv, true)
            .with_ie(ie::CAUSE, q931::cause_ie(c))
            .with_user_user(&uu);
        if let Ok(bytes) = m.encode().and_then(|b| q931::tpkt(&b)) {
            let _ = writer.write_all(&bytes).await;
        }
    }
    let _ = writer.shutdown().await;
}

async fn run(
    shared: &Shared,
    id: ConnectionId,
    remote: SocketAddr,
    local: SocketAddr,
    mut writer: tokio::net::tcp::OwnedWriteHalf,
    mut rx: mpsc::Receiver<Result<Q931>>,
) -> String {
    let log = Log::new(Some(&shared.status_tx));
    let setup = match rx.recv().await {
        None => return "closed before a Setup".into(),
        Some(Err(e)) => {
            log.warn(format!(
                "H.323 {id} from {remote}: no Setup decision=protocol_error: {e:#}"
            ));
            return format!("no Setup: {e:#}");
        }
        Some(Ok(m)) => m,
    };
    if setup.message_type != msg::SETUP {
        log.warn(format!(
            "H.323 {id} from {remote}: {} before Setup decision=protocol_error",
            q931::message_name(setup.message_type)
        ));
        refuse_raw(&mut writer, setup.crv, cause::PROTOCOL_ERROR).await;
        return "a message before Setup".into();
    }
    let ui = match setup
        .user_user()
        .and_then(|u| u.ok_or_else(|| anyhow::anyhow!("Setup without a User-user IE")))
        .and_then(h225::decode_user_information)
    {
        Ok(ui) if ui.kind == "setup" => ui,
        Ok(ui) => {
            log.warn(format!(
                "H.323 {id} from {remote}: Setup carries a {} UUIE decision=protocol_error",
                ui.kind
            ));
            refuse_raw(&mut writer, setup.crv, cause::PROTOCOL_ERROR).await;
            return "a Setup with the wrong UUIE".into();
        }
        Err(e) => {
            log.warn(format!(
                "H.323 {id} from {remote}: Setup not decodable decision=protocol_error: {e:#}"
            ));
            refuse_raw(&mut writer, setup.crv, cause::PROTOCOL_ERROR).await;
            return format!("an undecodable Setup: {e:#}");
        }
    };
    let setup_bytes = setup.encode().map(|b| b.len() as u64 + 4).unwrap_or(0);
    shared
        .app_state
        .update_connection_stats(shared.server_id, id, Some(setup_bytes), None, Some(1), None)
        .await;
    let media = match MediaSockets::bind(local.ip()).await {
        Ok(m) => m,
        Err(e) => {
            log.error(format!(
                "H.323 {id}: no RTP ports decision=fail_closed_media: {e:#}"
            ));
            refuse_raw(&mut writer, setup.crv, cause::TEMPORARY_FAILURE).await;
            return "no RTP ports".into();
        }
    };
    let call_id = ui.call_identifier().unwrap_or_else(h225::new_guid);
    let conference_id = ui
        .body
        .get("conferenceID")
        .and_then(|c| c.as_str())
        .map(str::to_string)
        .unwrap_or_else(h225::new_guid);
    let mut leg = CallLeg::new(
        writer,
        setup.crv,
        Role::Callee,
        call_id,
        conference_id,
        ui.h245_tunnelling(),
        media,
        shared.config.codecs.clone(),
    );
    leg.offered_fast_start = ui.fast_start();
    // Tunnelled H.245 may already ride in the Setup (H.245 in Setup / parallel).
    for t in ui.h245_control() {
        let _ = leg.h245.on_message(&t);
    }

    let proposals: Vec<Value> = leg
        .offered_fast_start
        .iter()
        .filter_map(|p| h245::decode_olc(p).ok())
        .map(|o| h245::describe_proposal(&o))
        .collect();
    let event_data = json!({
        "remote": remote.to_string(),
        "crv": setup.crv,
        "call_id": leg.call_id,
        "conference_id": leg.conference_id,
        "calling_number": setup.number(ie::CALLING_PARTY_NUMBER),
        "called_number": setup.number(ie::CALLED_PARTY_NUMBER),
        "display": setup.display(),
        "source_aliases": h225::aliases_text(ui.body.get("sourceAddress")),
        "destination_aliases": h225::aliases_text(ui.body.get("destinationAddress")),
        "source_endpoint": h225::endpoint_summary(ui.body.get("sourceInfo")),
        "source_call_signal_address": ui.body.get("sourceCallSignalAddress").map(h225::transport_text),
        "fast_start": proposals,
        "h245_tunnelling": ui.h245_tunnelling(),
        "h245_address": ui.body.get("h245Address").map(h225::transport_text),
        "endpoint_identifier": ui.body.get("endpointIdentifier"),
    });
    log.info(format!(
        "H.323 {id}: Setup from {remote} (crv {}, {} → {})",
        setup.crv,
        event_data["calling_number"].as_str().unwrap_or("-"),
        event_data["called_number"].as_str().unwrap_or("-")
    ));
    let mut peer_rx = crate::server::peer_support::register_peer_channel(
        &shared.app_state,
        shared.server_id,
        id.as_u32(),
    )
    .await;

    let decision = consult(shared, id, &Event::new(&act::SETUP_EVENT, event_data)).await;
    let mut ringing_since: Option<tokio::time::Instant> = None;
    match decision {
        Decision::Failed { overloaded } => {
            let c = if overloaded {
                cause::CONGESTION
            } else {
                cause::TEMPORARY_FAILURE
            };
            let _ = leg.release(c, Some("undefinedReason")).await;
            return "Setup not answered (backend failure)".into();
        }
        Decision::Answered { commands, refused } => {
            if commands.is_empty() {
                let tag = if refused.is_empty() {
                    "model_silent"
                } else {
                    "fail_closed_bad_action"
                };
                log.warn(format!(
                    "H.323 {id}: Setup answered with no call-control action decision={tag}{}; releasing, cause 31",
                    if refused.is_empty() { String::new() } else { format!(" ({})", refused.join("; ")) }
                ));
                let _ = leg
                    .release(cause::NORMAL_UNSPECIFIED, Some("undefinedReason"))
                    .await;
                return "Setup not answered".into();
            }
            let rejects = commands
                .iter()
                .any(|c| matches!(c, CallCommand::Release { .. } | CallCommand::Forward { .. }));
            log.info(format!(
                "H.323 {id}: Setup decision={}",
                if rejects {
                    "model_reject"
                } else {
                    "model_answer"
                }
            ));
            if let Some(end) = carry_out(shared, id, &mut leg, commands).await {
                return end;
            }
        }
    }
    if leg.state == CallState::Released {
        return "released".into();
    }
    if matches!(
        leg.state,
        CallState::Offered | CallState::Proceeding | CallState::Alerting
    ) {
        ringing_since = Some(tokio::time::Instant::now());
    }

    let mut peer_open = true;
    let mut user_input_seen = 0usize;
    loop {
        let ring_deadline = ringing_since.map(|t| t + RING_TIMEOUT);
        tokio::select! {
            m = rx.recv() => {
                let m = match m {
                    None => return format!("the caller closed the connection (call {})", leg.state.name()),
                    Some(Err(e)) => {
                        log.warn(format!("H.323 {id}: decision=protocol_error: {e:#}"));
                        let _ = leg.release(cause::PROTOCOL_ERROR, None).await;
                        return format!("protocol error: {e:#}");
                    }
                    Some(Ok(m)) => m,
                };
                let received = m.encode().map(|b| b.len() as u64 + 4).unwrap_or(0);
                let sent_before = leg.bytes_sent;
                let outcome = leg.on_incoming(&m).await;
                shared.app_state
                    .update_connection_stats(shared.server_id, id, Some(received), Some(leg.bytes_sent - sent_before), Some(1), None)
                    .await;
                match outcome {
                    Ok(Incoming::Released { cause: c, reason }) => {
                        log.info(format!("H.323 {id}: call ended by the caller: {}", json!({"cause": c, "reason": reason, "call": leg.summary()})));
                        return format!("the caller released (cause {c:?}, {reason:?})");
                    }
                    Ok(Incoming::WrongCallReference { crv, from_destination }) => {
                        log.warn(format!(
                            "H.323 {id}: {} for call reference {crv} (flag {from_destination}) on call {} decision=protocol_error; releasing, cause 81",
                            q931::message_name(m.message_type), leg.crv
                        ));
                        let _ = leg.release(cause::INVALID_CALL_REFERENCE, None).await;
                        return "a message for another call reference".into();
                    }
                    Ok(Incoming::UnexpectedSetup) => {
                        log.warn(format!("H.323 {id}: a second Setup on this connection decision=protocol_error"));
                        let _ = leg.release(cause::NORMAL_UNSPECIFIED, Some("newConnectionNeeded")).await;
                        return "a second Setup".into();
                    }
                    Ok(_) => {}
                    Err(e) => {
                        log.warn(format!("H.323 {id}: {} not decodable decision=protocol_error: {e:#}", q931::message_name(m.message_type)));
                    }
                }
                if leg.h245.ended && leg.state != CallState::Released {
                    let _ = leg.release(cause::NORMAL_CLEARING, None).await;
                    log.info(format!("H.323 {id}: call ended by the caller's endSessionCommand: {}", leg.summary()));
                    return "the caller ended the H.245 session".into();
                }
                while user_input_seen < leg.h245.user_input.len() && user_input_seen < MAX_USER_INPUT_EVENTS {
                    let input = leg.h245.user_input[user_input_seen].clone();
                    user_input_seen += 1;
                    let event = Event::new(&act::USER_INPUT_EVENT, json!({
                        "input": input,
                        "call_id": leg.call_id,
                        "state": leg.state.name(),
                    }));
                    if let Decision::Answered { commands, .. } = consult(shared, id, &event).await {
                        if let Some(end) = carry_out(shared, id, &mut leg, commands).await {
                            return end;
                        }
                    }
                }
                if leg.state == CallState::Connected {
                    ringing_since = None;
                }
            }
            _ = async { tokio::time::sleep_until(ring_deadline.expect("guarded")).await }, if ring_deadline.is_some() => {
                log.info(format!("H.323 {id}: rang for {}s without a Connect decision=fail_closed_ring_timeout; releasing, cause 19", RING_TIMEOUT.as_secs()));
                let _ = leg.release(cause::NO_ANSWER, None).await;
                return "rang without being answered".into();
            }
            c = peer_rx.recv(), if peer_open => {
                let Some(c) = c else {
                    peer_open = false;
                    continue;
                };
                if let Some(end) = inject(shared, id, &mut leg, c).await {
                    return end;
                }
                if leg.state == CallState::Connected {
                    ringing_since = None;
                } else if ringing_since.is_none() && leg.state != CallState::Released {
                    ringing_since = Some(tokio::time::Instant::now());
                }
            }
        }
    }
}

/// Carry out the model's call-control commands in order. `Some(reason)` when the call ended.
async fn carry_out(
    shared: &Shared,
    id: ConnectionId,
    leg: &mut CallLeg,
    commands: Vec<CallCommand>,
) -> Option<String> {
    let log = Log::new(Some(&shared.status_tx));
    for c in commands {
        let what = c.name();
        let before = leg.bytes_sent;
        let result = apply(leg, c).await;
        if leg.bytes_sent > before {
            shared
                .app_state
                .update_connection_stats(
                    shared.server_id,
                    id,
                    None,
                    Some(leg.bytes_sent - before),
                    None,
                    Some(1),
                )
                .await;
        }
        match result {
            Ok(()) if leg.state == CallState::Connected => log.info(format!(
                "H.323 {id}: {what} sent; media {}",
                leg.media_json()
            )),
            Ok(()) => log.info(format!("H.323 {id}: {what} sent")),
            Err(e) => {
                log.error(format!(
                    "H.323 {id}: {what} refused decision=fail_closed_bad_action: {e:#}"
                ));
                if leg.state != CallState::Connected && leg.state != CallState::Released {
                    let _ = leg
                        .release(cause::TEMPORARY_FAILURE, Some("undefinedReason"))
                        .await;
                }
            }
        }
        if leg.state == CallState::Released {
            log.info(format!(
                "H.323 {id}: call ended by the model: {}",
                leg.summary()
            ));
            return Some(format!("released by the model ({what})"));
        }
    }
    None
}

async fn apply(leg: &mut CallLeg, c: CallCommand) -> Result<()> {
    match c {
        CallCommand::Proceeding => leg.call_proceeding().await,
        CallCommand::Alerting => leg.alerting().await,
        CallCommand::Connect { codecs, display } => leg.connect(&codecs, display.as_deref()).await,
        CallCommand::Release { cause, reason } => leg.release(cause, reason.as_deref()).await,
        CallCommand::Forward { address, aliases } => leg.forward(address, aliases).await,
    }
}

async fn inject(
    shared: &Shared,
    id: ConnectionId,
    leg: &mut CallLeg,
    command: ClientCommand,
) -> Option<String> {
    shared
        .app_state
        .record_access_log(
            crate::state::AccessLogOwner::Server(shared.server_id.as_u32()),
            "h323",
            None,
            "injected_action",
            command.action.clone(),
            vec![],
        )
        .await;
    let (outcome, end) = match act::parse_call_command(&command.action) {
        Err(e) => (
            ClientSendOutcome::Rejected {
                error: format!("{e:#}"),
            },
            None,
        ),
        Ok(c) => {
            let what = c.name();
            match apply(leg, c).await {
                Ok(()) if leg.state == CallState::Released => {
                    Log::new(Some(&shared.status_tx)).info(format!(
                        "H.323 {id}: call ended by the operator: {}",
                        leg.summary()
                    ));
                    (
                        ClientSendOutcome::Disconnected,
                        Some(format!("released by the operator ({what})")),
                    )
                }
                Ok(()) => (
                    ClientSendOutcome::Executed {
                        detail: format!("{what} sent; call {}", leg.state.name()),
                    },
                    None,
                ),
                Err(e) => (
                    ClientSendOutcome::Rejected {
                        error: format!("{e:#}"),
                    },
                    None,
                ),
            }
        }
    };
    Log::new(Some(&shared.status_tx)).info(format!("H.323 {id}: injected action: {outcome:?}"));
    let _ = command.reply_tx.send(Ok(outcome));
    end
}

enum Decision {
    Failed {
        overloaded: bool,
    },
    Answered {
        commands: Vec<CallCommand>,
        refused: Vec<String>,
    },
}

async fn consult(shared: &Shared, id: ConnectionId, event: &Event) -> Decision {
    let log = Log::new(Some(&shared.status_tx));
    let execution = match call_llm(
        &shared.llm_client,
        &shared.app_state,
        shared.server_id,
        Some(id),
        event,
        &act::H323EndpointProtocol::new(),
    )
    .await
    {
        Ok(x) => x,
        Err(e) => {
            let overloaded = matches!(
                crate::utils::wire_failure::WireFailure::classify(&e),
                crate::utils::wire_failure::WireFailure::Overloaded
            );
            log.error(format!(
                "H.323 {id}: {} not answered decision={}: {e}",
                event.event_type.id,
                if overloaded {
                    "fail_closed_llm_overloaded"
                } else {
                    "fail_closed_llm_error"
                }
            ));
            return Decision::Failed { overloaded };
        }
    };
    for m in execution.messages {
        let _ = shared.status_tx.send(m);
    }
    let mut commands = Vec::new();
    let mut stack = execution.protocol_results;
    stack.reverse();
    while let Some(r) = stack.pop() {
        match r {
            ActionResult::Custom { data, .. } => {
                if let Ok(c) = act::parse_call_command(&data) {
                    commands.push(c);
                }
            }
            ActionResult::Multiple(inner) => stack.extend(inner.into_iter().rev()),
            _ => {}
        }
    }
    let refused = execution
        .failures
        .iter()
        .map(|f| format!("{}: {}", f.action, f.error))
        .collect();
    Decision::Answered { commands, refused }
}
