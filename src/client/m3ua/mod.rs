//! M3UA client: NetGet as an **ASP** on one association with an SGP (or an IPSP peer), carrying
//! the SS7 upper stack — SCCP, TCAP, MAP and CAMEL — that `src/server/m3ua` implements.
//!
//! On connect Rust opens the association (SCTP, or the labelled lab TCP transport), sends ASPUP
//! and ASPAC from the startup parameters and waits for both acknowledgements; an ERR fails the
//! connect with the SGP's error code. Then `m3ua_connected` is raised and the model opens MAP or
//! CAP dialogues. BEAT is answered in Rust; NTFY is logged.
//!
//! The dialogue engine is the server's ([`ss7::Engine`]): Rust owns transaction ids, invoke ids,
//! AARQ/AARE, SCCP addressing and the MTP routing label; the model names operations and fields.
//! Every answer from the far end is decoded before the model sees it. A dialogue the far end
//! opened towards this ASP is held to the server's rule: an invoke left unanswered after the
//! model's turn is aborted, and one the model could not be asked about is answered systemFailure.
//! A chain of model turns stops after [`MAX_FOLLOWUP_DEPTH`].
pub mod actions;

use crate::client::llm_budget::call_llm_for_client;
use crate::llm::actions::client_trait::{Client, ClientActionResult};
use crate::logging::emit::Log;
use crate::protocol::{ConnectContext, Event, EventType};
use crate::server::m3ua::sccp::{GlobalTitle, SccpAddress};
use crate::server::m3ua::{codec, read_message, sccp, ss7, transport, Incoming};
use crate::state::client_handles::{ClientCommand, ClientSendOutcome};
use crate::state::{AccessLogOwner, ClientStatus};
use crate::utils::clock::Instant;
pub use actions::M3uaClientProtocol;
use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;

/// How many model turns may follow from one another before the chain stops.
pub const MAX_FOLLOWUP_DEPTH: u32 = 8;
/// How long the SGP has to acknowledge ASPUP and ASPAC.
pub const ACTIVATION_TIMEOUT: Duration = Duration::from_secs(15);
/// How long an active association may be silent before the ASP gives up on it. A quiet
/// signalling link is normal; this is the server's idle bound.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(900);
/// CAP's SCCP subsystem number, used at both ends of a CAMEL dialogue with no called_address.
pub const CAP_SSN: u8 = 146;
const TURNS: usize = 64;

/// What the turn dispatcher hands back to the session.
enum TurnItem {
    Action(Value, u32),
    /// The model's turn about an event on `dialogue` is over; `failed` if it could not be asked.
    Done {
        dialogue: Option<u32>,
        failed: bool,
        depth_exceeded: bool,
    },
}

struct Asp {
    writer: transport::Writer,
    engine: ss7::Engine,
    route: ss7::Route,
    events: mpsc::Sender<(Event, u32, Option<u32>)>,
    client: crate::state::ClientId,
    next_sls: u8,
}

fn opt_u64(ctx: &ConnectContext, key: &str, max: u64) -> Result<Option<u64>> {
    let v = ctx
        .startup_params
        .as_ref()
        .map(|p| p.get_optional_u64(key))
        .transpose()?
        .flatten();
    if let Some(n) = v {
        if n > max {
            bail!("{key} {n} is above its maximum {max}");
        }
    }
    Ok(v)
}

fn opt_string(ctx: &ConnectContext, key: &str) -> Result<Option<String>> {
    Ok(ctx
        .startup_params
        .as_ref()
        .map(|p| p.get_optional_string(key))
        .transpose()?
        .flatten())
}

async fn resolve(raw: &str) -> Result<SocketAddr> {
    let raw = raw.trim();
    if let Ok(a) = raw.parse::<SocketAddr>() {
        return Ok(a);
    }
    if let Ok(ip) = raw.parse::<std::net::IpAddr>() {
        return Ok(SocketAddr::new(ip, 2905));
    }
    let with_port = if raw.contains(':') {
        raw.to_string()
    } else {
        format!("{raw}:2905")
    };
    let found = tokio::net::lookup_host(&with_port)
        .await
        .with_context(|| format!("cannot resolve {raw}"))?
        .next()
        .with_context(|| format!("{raw} resolved to no address"));
    found
}

fn address(pc: u32, ssn: u8, gt: &Option<String>) -> SccpAddress {
    SccpAddress {
        route_on_gt: false,
        point_code: Some(pc as u16),
        ssn: Some(ssn),
        global_title: gt.as_deref().map(GlobalTitle::e164),
        national: false,
    }
}

/// Wait for one ASPSM/ASPTM acknowledgement, collecting NTFYs and answering BEATs on the way.
async fn await_ack(
    reader: &mut transport::Reader,
    writer: &mut transport::Writer,
    class: u8,
    msg_type: u8,
    what: &str,
    notifications: &mut Vec<Value>,
) -> Result<codec::Message> {
    let deadline = tokio::time::Instant::now() + ACTIVATION_TIMEOUT;
    loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        if left.is_zero() {
            bail!(
                "the SGP did not send {what} within {}s",
                ACTIVATION_TIMEOUT.as_secs()
            );
        }
        let message = match read_message(reader, left).await.0 {
            Incoming::Message(m) => m,
            Incoming::HeaderError(e) | Incoming::BodyError(e) => {
                bail!("the SGP sent an unreadable message while NetGet waited for {what}: {e}")
            }
            Incoming::Eof => bail!("the SGP closed the association before {what}"),
        };
        match (message.class, message.msg_type) {
            (c, t) if c == class && t == msg_type => return Ok(message),
            (codec::CLASS_MGMT, codec::MGMT_ERR) => {
                let code = message.param_u32(codec::TAG_ERROR_CODE).unwrap_or(0);
                bail!(
                    "the SGP refused with ERR {} ({}) while NetGet waited for {what}",
                    code,
                    codec::error_code_name(code)
                )
            }
            (codec::CLASS_MGMT, codec::MGMT_NTFY) => notifications.push(ntfy_json(&message)),
            (codec::CLASS_ASPSM, codec::ASPSM_BEAT) => {
                let hb = message
                    .param(codec::TAG_HEARTBEAT_DATA)
                    .map(|p| p.value.clone());
                writer.write_all(&codec::beat_ack(hb.as_deref())?).await?;
            }
            _ => tracing::debug!("M3UA client: {} while waiting for {what}", message.name()),
        }
    }
}

fn ntfy_json(message: &codec::Message) -> Value {
    let status = message.param_u32(codec::TAG_STATUS).unwrap_or(0);
    let (t, i) = ((status >> 16) as u16, status as u16);
    let info = match (t, i) {
        (codec::STATUS_TYPE_AS_STATE_CHANGE, codec::STATUS_AS_INACTIVE) => "as_inactive",
        (codec::STATUS_TYPE_AS_STATE_CHANGE, codec::STATUS_AS_ACTIVE) => "as_active",
        (codec::STATUS_TYPE_AS_STATE_CHANGE, codec::STATUS_AS_PENDING) => "as_pending",
        (codec::STATUS_TYPE_OTHER, codec::STATUS_INSUFFICIENT_ASP_RESOURCES) => {
            "insufficient_asp_resources"
        }
        (codec::STATUS_TYPE_OTHER, codec::STATUS_ALTERNATE_ASP_ACTIVE) => "alternate_asp_active",
        (codec::STATUS_TYPE_OTHER, codec::STATUS_ASP_FAILURE) => "asp_failure",
        _ => "other",
    };
    json!({"status": info, "routing_context": message.param_u32(codec::TAG_ROUTING_CONTEXT)})
}

pub async fn connect(ctx: ConnectContext) -> Result<SocketAddr> {
    let sctp = match opt_string(&ctx, "transport")?.as_deref() {
        None | Some("sctp") => true,
        Some("tcp") => false,
        Some(other) => bail!("transport must be \"sctp\" or \"tcp\", got {other:?}"),
    };
    let label = if sctp {
        crate::server::m3ua::M3uaTransport::Sctp.label()
    } else {
        crate::server::m3ua::M3uaTransport::Tcp.label()
    };
    let routing_context = opt_u64(&ctx, "routing_context", u32::MAX as u64)?.map(|v| v as u32);
    let asp_identifier = opt_u64(&ctx, "asp_identifier", u32::MAX as u64)?.map(|v| v as u32);
    let local_port = opt_u64(&ctx, "local_port", 65535)?.map(|v| v as u16);
    let opc = opt_u64(&ctx, "opc", 0x3fff)?.unwrap_or(actions::DEFAULT_OPC) as u32;
    let dpc = opt_u64(&ctx, "dpc", 0x3fff)?.unwrap_or(actions::DEFAULT_DPC) as u32;
    let ni = opt_u64(&ctx, "network_indicator", 3)?.unwrap_or(actions::DEFAULT_NI) as u8;
    let local_ssn = opt_u64(&ctx, "local_ssn", 255)?.unwrap_or(actions::DEFAULT_LOCAL_SSN) as u8;
    let remote_ssn = opt_u64(&ctx, "remote_ssn", 255)?.unwrap_or(actions::DEFAULT_REMOTE_SSN) as u8;
    let local_gt = opt_string(&ctx, "local_gt")?;
    let remote_gt = opt_string(&ctx, "remote_gt")?;
    for gt in [&local_gt, &remote_gt].into_iter().flatten() {
        if gt.is_empty() || gt.len() > 32 || !gt.chars().all(|c| c.is_ascii_digit()) {
            bail!("a global title must be 1..32 decimal digits, got {gt:?}");
        }
    }
    let route = ss7::Route {
        opc,
        dpc,
        ni,
        mp: 0,
        sls: 0,
        remote: address(dpc, remote_ssn, &remote_gt),
        local: address(opc, local_ssn, &local_gt),
        message_type: sccp::MSG_UDT,
        protocol_class: 1,
        routing_context,
        network_appearance: None,
    };

    let sgp = resolve(&ctx.remote_addr).await?;
    let stream = transport::connect(sgp, sctp, local_port, ACTIVATION_TIMEOUT).await?;
    let local = stream.local_addr()?;
    let (mut reader, mut writer) = transport::split(stream, sctp);
    let log = Log::new(Some(&ctx.status_tx));
    log.info(format!(
        "M3UA ASP {} associated with {sgp} over {label}",
        ctx.client_id
    ));
    let mut notifications = Vec::new();
    writer
        .write_all(&codec::aspup(asp_identifier, None)?)
        .await
        .context("sending ASPUP")?;
    await_ack(
        &mut reader,
        &mut writer,
        codec::CLASS_ASPSM,
        codec::ASPSM_ASPUP_ACK,
        "ASPUP ACK",
        &mut notifications,
    )
    .await?;
    writer
        .write_all(&codec::aspac(
            Some(codec::TRAFFIC_MODE_LOADSHARE),
            routing_context,
        )?)
        .await
        .context("sending ASPAC")?;
    let ack = await_ack(
        &mut reader,
        &mut writer,
        codec::CLASS_ASPTM,
        codec::ASPTM_ASPAC_ACK,
        "ASPAC ACK",
        &mut notifications,
    )
    .await?;
    let traffic_mode = match ack.param_u32(codec::TAG_TRAFFIC_MODE_TYPE) {
        Some(codec::TRAFFIC_MODE_OVERRIDE) => "override",
        Some(codec::TRAFFIC_MODE_BROADCAST) => "broadcast",
        _ => "loadshare",
    };
    log.info(format!(
        "M3UA ASP {} is ACTIVE (rc={routing_context:?}, {traffic_mode})",
        ctx.client_id
    ));

    ctx.state
        .update_client_status(ctx.client_id, ClientStatus::Connected)
        .await;
    let external =
        crate::client::command_support::register_command_channel(&ctx.state, ctx.client_id).await;
    let (event_tx, event_rx) = mpsc::channel::<(Event, u32, Option<u32>)>(TURNS);
    let (internal_tx, internal) = mpsc::channel::<TurnItem>(64);
    let _ = event_tx.try_send((
        Event::new(
            &actions::CONNECTED_EVENT,
            json!({
                "routing_context": routing_context,
                "traffic_mode": traffic_mode,
                "notifications": notifications,
                "transport": label,
                "opc": opc,
                "dpc": dpc,
            }),
        ),
        0,
        None,
    ));
    let dispatcher = tokio::spawn(run_turns(ctx.clone(), event_rx, internal_tx));
    let dispatcher_abort = dispatcher.abort_handle();
    ctx.state
        .register_client_task(ctx.client_id, dispatcher)
        .await;

    let (msg_tx, msg_rx) = mpsc::channel::<Incoming>(16);
    let reader_task = tokio::spawn(async move {
        loop {
            let (item, _) = read_message(&mut reader, IDLE_TIMEOUT).await;
            let end = !matches!(item, Incoming::Message(_) | Incoming::BodyError(_));
            if msg_tx.send(item).await.is_err() || end {
                return;
            }
        }
    });
    ctx.state
        .register_client_task(ctx.client_id, reader_task)
        .await;

    let mut asp = Asp {
        writer,
        engine: ss7::Engine::new(),
        route,
        events: event_tx,
        client: ctx.client_id,
        next_sls: 0,
    };
    let session_ctx = ctx.clone();
    let task = tokio::spawn(async move {
        let result = asp.run(&session_ctx, msg_rx, external, internal).await;
        dispatcher_abort.abort();
        asp.writer.close();
        let status = match result {
            Ok(()) => ClientStatus::Disconnected,
            Err(e) => {
                Log::new(Some(&session_ctx.status_tx)).warn(format!("M3UA client ended: {e:#}"));
                ClientStatus::Error(e.to_string())
            }
        };
        session_ctx
            .state
            .update_client_status(session_ctx.client_id, status)
            .await;
        session_ctx
            .state
            .remove_client_handle(session_ctx.client_id)
            .await;
        let _ = session_ctx.status_tx.send("__UPDATE_UI__".into());
    });
    ctx.state.register_client_task(ctx.client_id, task).await;
    Ok(local)
}

fn reply(command: &mut Option<ClientCommand>, outcome: ClientSendOutcome) {
    if let Some(c) = command.take() {
        crate::client::command_support::reply(c, Ok(outcome));
    }
}

impl Asp {
    fn emit(&self, t: &'static EventType, data: Value, depth: u32, dialogue: Option<u32>) {
        if self
            .events
            .try_send((Event::new(t, data), depth, dialogue))
            .is_err()
        {
            tracing::warn!(
                "M3UA client {} dropped an event: the model is {TURNS} behind decision=turn_queue_full",
                self.client
            );
        }
    }

    async fn send_ss7(&mut self, out: ss7::Outgoing) -> Result<usize> {
        let bytes = codec::data(
            &out.protocol_data,
            out.network_appearance,
            out.routing_context,
            None,
        )?;
        self.writer
            .write_all(&bytes)
            .await
            .context("writing to the SGP")?;
        Ok(bytes.len())
    }

    fn event_for(family: ss7::Family) -> &'static EventType {
        match family {
            ss7::Family::Map => &actions::MAP_EVENT,
            ss7::Family::Cap => &actions::CAP_EVENT,
        }
    }

    async fn run(
        &mut self,
        ctx: &ConnectContext,
        mut messages: mpsc::Receiver<Incoming>,
        mut external: mpsc::Receiver<ClientCommand>,
        mut internal: mpsc::Receiver<TurnItem>,
    ) -> Result<()> {
        let log = Log::new(Some(&ctx.status_tx));
        loop {
            let expiry = self.engine.next_expiry();
            let (action, depth, mut command) = tokio::select! {
                m = messages.recv() => {
                    match m {
                        Some(Incoming::Message(message)) => self.incoming(message, &log).await?,
                        Some(Incoming::BodyError(e)) => {
                            log.warn(format!("M3UA client: unreadable message from the SGP: {e}"));
                            self.writer.write_all(&codec::error(e.error_code, self.route.routing_context)?).await?;
                        }
                        Some(Incoming::HeaderError(e)) => bail!("the SGP sent an unreadable header: {e}"),
                        Some(Incoming::Eof) | None => return Ok(()),
                    }
                    continue;
                }
                _ = async {
                    match expiry {
                        Some(at) => tokio::time::sleep(at.saturating_duration_since(Instant::now())).await,
                        None => std::future::pending::<()>().await,
                    }
                } => {
                    for (d, abort) in self.engine.expire(Instant::now()) {
                        log.info(format!(
                            "M3UA client: dialogue {} idle for {}s, abandoned (decision=dialogue_idle_timeout)",
                            d.id, ss7::DIALOGUE_IDLE_TIMEOUT.as_secs()
                        ));
                        if let Some(out) = abort {
                            self.send_ss7(out).await?;
                        }
                        self.emit(
                            Self::event_for(d.family),
                            json!({"dialogue_id": d.id, "tcap": "timeout",
                                   "note": "no answer arrived; NetGet abandoned the dialogue"}),
                            d.depth,
                            None,
                        );
                    }
                    continue;
                }
                c = external.recv() => match c {
                    Some(c) => {
                        ctx.state.record_access_log(AccessLogOwner::Client(ctx.client_id.as_u32()), "M3UA", None,
                            "injected_action", c.action.clone(), vec![]).await;
                        (c.action.clone(), 0, Some(c))
                    }
                    None => return Ok(()),
                },
                a = internal.recv() => match a {
                    Some(TurnItem::Action(a, d)) => (a, d, None),
                    Some(TurnItem::Done { dialogue, failed, depth_exceeded }) => {
                        self.turn_done(dialogue, failed, depth_exceeded, &log).await?;
                        continue;
                    }
                    None => return Ok(()),
                },
            };
            match M3uaClientProtocol.execute_action(action.clone()) {
                Ok(ClientActionResult::Disconnect) => {
                    let _ = self.writer.write_all(&codec::aspdn()?).await;
                    reply(&mut command, ClientSendOutcome::Disconnected);
                    return Ok(());
                }
                Ok(ClientActionResult::WaitForMore) | Ok(ClientActionResult::NoAction) => {
                    reply(&mut command, ClientSendOutcome::Sent { bytes_sent: 0 });
                    continue;
                }
                Ok(_) => {}
                Err(e) => {
                    log.warn(format!("M3UA client action refused: {e}"));
                    reply(
                        &mut command,
                        ClientSendOutcome::Rejected {
                            error: e.to_string(),
                        },
                    );
                    continue;
                }
            }
            match self.perform(&action, depth).await {
                Ok(bytes) => reply(&mut command, ClientSendOutcome::Sent { bytes_sent: bytes }),
                Err(e) => {
                    log.warn(format!("M3UA client: {e:#} (decision=action_refused)"));
                    reply(
                        &mut command,
                        ClientSendOutcome::Rejected {
                            error: format!("{e:#}"),
                        },
                    );
                }
            }
        }
    }

    /// Encode the model's intent and send it.
    async fn perform(&mut self, action: &Value, depth: u32) -> Result<usize> {
        let mut route = self.route.clone();
        // Spread new dialogues over the SLS values, as an MTP3 user does.
        route.sls = self.next_sls;
        self.next_sls = (self.next_sls + 1) & 0x0f;
        if action["type"] == "send_cap_operations" && action.get("called_address").is_none() {
            route.remote.ssn = Some(CAP_SSN);
            route.local.ssn = Some(CAP_SSN);
        }
        let (id, out) = self
            .engine
            .apply(action, Some(&route), depth, Instant::now())
            .map_err(|e| anyhow!(e))?;
        tracing::debug!("M3UA client {}: {} (dialogue {id})", self.client, out.label);
        self.send_ss7(out).await
    }

    /// A turn about an event on `dialogue` is over: hold the dialogue to an answer.
    async fn turn_done(
        &mut self,
        dialogue: Option<u32>,
        failed: bool,
        depth_exceeded: bool,
        log: &Log<'_>,
    ) -> Result<()> {
        let Some(id) = dialogue else {
            return Ok(());
        };
        if !self.engine.awaiting_answer(id) {
            return Ok(());
        }
        let decision = if failed {
            "fail_closed_llm_error"
        } else if depth_exceeded {
            "followup_depth"
        } else {
            "model_silent"
        };
        if let Some(out) = self.engine.close_unanswered(id, failed) {
            log.warn(format!(
                "M3UA client: dialogue {id} left unanswered (decision={decision}); sending {}",
                out.label
            ));
            self.send_ss7(out).await?;
        }
        Ok(())
    }

    async fn incoming(&mut self, message: codec::Message, log: &Log<'_>) -> Result<()> {
        match (message.class, message.msg_type) {
            (codec::CLASS_TRANSFER, codec::TRANSFER_DATA) => {
                let Some(param) = message.param(codec::TAG_PROTOCOL_DATA) else {
                    return Ok(());
                };
                let pd = match codec::ProtocolData::parse(&param.value) {
                    Ok(pd) => pd,
                    Err(e) => {
                        log.warn(format!("M3UA client: malformed Protocol Data: {e}"));
                        return Ok(());
                    }
                };
                let rc = message.param_u32(codec::TAG_ROUTING_CONTEXT);
                let na = message.param_u32(codec::TAG_NETWORK_APPEARANCE);
                match self.engine.on_data(&pd, rc, na, Instant::now()) {
                    ss7::Inbound::Handled { replies, note } => {
                        log.info(format!("M3UA client: {note}"));
                        for r in replies {
                            self.send_ss7(r).await?;
                        }
                    }
                    ss7::Inbound::Event(ev) => {
                        for r in ev.replies {
                            self.send_ss7(r).await?;
                        }
                        let dialogue = (!ev.ended).then_some(ev.dialogue_id);
                        self.emit(Self::event_for(ev.family), ev.data, ev.depth, dialogue);
                    }
                    ss7::Inbound::NotSccp | ss7::Inbound::Undecoded(_) => {
                        self.emit(
                            &actions::ERROR_EVENT,
                            json!({"message": format!("an MSU with service indicator {} ({}) NetGet does not decode", pd.si, codec::si_name(pd.si))}),
                            0,
                            None,
                        );
                    }
                }
            }
            (codec::CLASS_ASPSM, codec::ASPSM_BEAT) => {
                let hb = message
                    .param(codec::TAG_HEARTBEAT_DATA)
                    .map(|p| p.value.clone());
                self.writer
                    .write_all(&codec::beat_ack(hb.as_deref())?)
                    .await?;
            }
            (codec::CLASS_MGMT, codec::MGMT_NTFY) => {
                log.info(format!("M3UA client: NTFY {}", ntfy_json(&message)));
            }
            (codec::CLASS_MGMT, codec::MGMT_ERR) => {
                let code = message.param_u32(codec::TAG_ERROR_CODE).unwrap_or(0);
                log.warn(format!(
                    "M3UA client: ERR {code} ({}) from the SGP",
                    codec::error_code_name(code)
                ));
                self.emit(
                    &actions::ERROR_EVENT,
                    json!({"message": "err", "error_code": code, "error_name": codec::error_code_name(code)}),
                    0,
                    None,
                );
            }
            _ => tracing::debug!("M3UA client: {} from the SGP", message.name()),
        }
        Ok(())
    }
}

/// Ask the model about each event and feed its actions back to the session, bounded in depth.
async fn run_turns(
    ctx: ConnectContext,
    mut events: mpsc::Receiver<(Event, u32, Option<u32>)>,
    internal: mpsc::Sender<TurnItem>,
) {
    let protocol = M3uaClientProtocol;
    while let Some((event, depth, dialogue)) = events.recv().await {
        if depth >= MAX_FOLLOWUP_DEPTH {
            tracing::warn!(
                "M3UA client {} not asking the model about {}: {depth} turns deep decision=followup_depth",
                ctx.client_id,
                event.id()
            );
            let _ = internal
                .send(TurnItem::Done {
                    dialogue,
                    failed: false,
                    depth_exceeded: true,
                })
                .await;
            continue;
        }
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
        let failed = match call_llm_for_client(
            &ctx.llm_client,
            &ctx.state,
            ctx.client_id.to_string(),
            &instruction,
            &memory,
            Some(&event),
            &protocol,
            &ctx.status_tx,
        )
        .await
        {
            Ok(result) => {
                if let Some(memory) = result.memory_updates {
                    ctx.state.set_memory_for_client(ctx.client_id, memory).await;
                }
                for action in result.actions {
                    if internal
                        .send(TurnItem::Action(action, depth + 1))
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
                false
            }
            Err(e) => {
                Log::new(Some(&ctx.status_tx)).warn(format!("M3UA client handler: {e}"));
                true
            }
        };
        if internal
            .send(TurnItem::Done {
                dialogue,
                failed,
                depth_exceeded: false,
            })
            .await
            .is_err()
        {
            return;
        }
    }
}
