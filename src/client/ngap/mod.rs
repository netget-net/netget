//! NGAP client: NetGet as a **gNB** on one N2 association with one AMF.
//!
//! On connect Rust opens the association (SCTP, or the labelled lab TCP framing) and performs NG
//! Setup from the startup parameters — the gNB's PLMN, ID, tracking area and slice — the way a
//! real gNB does from its configuration. An NG Setup Failure fails the connect with the AMF's
//! cause; a Response raises `ngap_connected` and the model brings UEs in.
//!
//! Everything the AMF sends is decoded before the model sees it; a PDU that does not decode is
//! answered with an Error Indication (transfer-syntax-error) and never reaches the model. UE
//! Context Release Command and NG Reset are answered by Rust (the complete / acknowledge carry no
//! decision). The model's actions run in this task, so it owns the RAN UE NGAP IDs and the UE
//! table; a chain of model turns stops after [`MAX_FOLLOWUP_DEPTH`].
//!
//! Given a subscriber's credentials (`supi`, `subscriber_key`, `subscriber_opc`), the UE whose
//! SUCI names that subscriber is taken through 5G-AKA, NAS security, registration and PDU session
//! establishment by Rust ([`ue`]); the model brings it in and asks for sessions. Session release
//! and modification, CM-IDLE, the Service Request and the answer to paging are in
//! [`procedures`].
pub mod actions;
pub mod procedures;
pub mod ue;

use crate::client::llm_budget::call_llm_for_client;
use crate::llm::actions::client_trait::{Client, ClientActionResult};
use crate::logging::emit::Log;
use crate::protocol::{ConnectContext, Event, EventType};
use crate::server::ngap::codec::{self, Cause, PduKind};
use crate::server::ngap::nas;
use crate::server::ngap::transport::{self, MessageWriter, ReadOutcome, Transport};
use crate::state::client_handles::{ClientCommand, ClientSendOutcome};
use crate::state::{AccessLogOwner, ClientStatus};
pub use actions::NgapClientProtocol;
use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::debug;

/// How many model turns may follow from one another before the chain stops.
pub const MAX_FOLLOWUP_DEPTH: u32 = 8;
/// How long the AMF has to answer NG Setup.
pub const NG_SETUP_TIMEOUT: Duration = Duration::from_secs(15);
/// How long an established association may be silent before the gNB gives up on it. Generous:
/// an AMF with no UE traffic says nothing at all.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(3600);
/// UE contexts this gNB keeps; an Initial UE Message beyond it is refused locally.
pub const MAX_UES: usize = 1024;
const TURNS: usize = 64;

/// One UE on this gNB.
struct UeSlot {
    /// The AMF's id, once the AMF has named one.
    amf: Option<u64>,
    /// How many model turns deep the last action for this UE was; the AMF's next answer about
    /// it is raised at that depth, so a model and an AMF that keep answering each other stop at
    /// [`MAX_FOLLOWUP_DEPTH`].
    depth: u32,
    /// Present when the UE is the subscriber this gNB holds credentials for; see [`ue`].
    sec: Option<Box<ue::UeSec>>,
    /// Whether the AMF's K_gNB matched this UE's own, once an Initial Context Setup arrived.
    k_gnb_verified: Option<bool>,
    /// PDU session id → the UPF's uplink tunnel the AMF named.
    sessions: BTreeMap<u8, codec::GtpTunnel>,
}

impl UeSlot {
    fn new(amf: Option<u64>, depth: u32) -> Self {
        UeSlot {
            amf,
            depth,
            sec: None,
            k_gnb_verified: None,
            sessions: BTreeMap::new(),
        }
    }
}

struct Gnb {
    writer: MessageWriter,
    /// RAN UE NGAP ID → the UE.
    ues: BTreeMap<u64, UeSlot>,
    next_ran_id: u64,
    user_location: Value,
    setup: Vec<u8>,
    events: mpsc::Sender<(Event, u32)>,
    client: crate::state::ClientId,
    creds: Option<ue::Credentials>,
    /// The serving network name for this gNB's PLMN (TS 24.501 9.12.1).
    snn: String,
    /// The address this gNB puts in its downlink GTP-U tunnels: its N2 address.
    gtp_address: std::net::IpAddr,
    /// Registered UEs whose N2 context the AMF released, by SUPI digits; at most [`MAX_UES`].
    idle: BTreeMap<String, procedures::IdleUe>,
}

fn startup_u64(ctx: &ConnectContext, key: &str, default: u64, max: u64) -> Result<u64> {
    let v = ctx
        .startup_params
        .as_ref()
        .map(|p| p.get_optional_u64(key))
        .transpose()?
        .flatten()
        .unwrap_or(default);
    if v > max {
        bail!("{key} {v} is above its maximum {max}");
    }
    Ok(v)
}

fn startup_string(ctx: &ConnectContext, key: &str) -> Result<Option<String>> {
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
        return Ok(SocketAddr::new(ip, codec::SCTP_PORT));
    }
    let with_port = if raw.contains(':') {
        raw.to_string()
    } else {
        format!("{raw}:{}", codec::SCTP_PORT)
    };
    let found = tokio::net::lookup_host(&with_port)
        .await
        .with_context(|| format!("cannot resolve {raw}"))?
        .next()
        .with_context(|| format!("{raw} resolved to no address"));
    found
}

pub async fn connect(ctx: ConnectContext) -> Result<SocketAddr> {
    let transport = Transport::from_params(ctx.startup_params.as_ref())?;
    let plmn = actions::plmn(&ctx)?;
    let creds = ue::Credentials::from_ctx(&ctx)?;
    let snn = crate::server::ngap::security::serving_network_name(&plmn.mcc, &plmn.mnc);
    let gnb_id_bits = startup_u64(&ctx, "gnb_id_bits", actions::DEFAULT_GNB_ID_BITS, 32)?;
    anyhow::ensure!(gnb_id_bits >= 22, "gnb_id_bits must be 22..32");
    let gnb_id = startup_u64(
        &ctx,
        "gnb_id",
        actions::DEFAULT_GNB_ID,
        (1u64 << gnb_id_bits) - 1,
    )?;
    let tac = startup_u64(&ctx, "tac", actions::DEFAULT_TAC, 0xFF_FFFF)?;
    let sst = startup_u64(&ctx, "sst", actions::DEFAULT_SST, 255)?;
    let cell = startup_u64(
        &ctx,
        "nr_cell_id",
        actions::DEFAULT_NR_CELL_ID,
        (1 << 36) - 1,
    )?;
    let name = startup_string(&ctx, "ran_node_name")?
        .unwrap_or_else(|| actions::DEFAULT_RAN_NODE_NAME.to_string());
    let mut slice = json!({"sst": sst});
    if let Some(sd) = startup_string(&ctx, "sd")? {
        slice["sd"] = json!(sd);
    }
    let ta_list =
        vec![json!({"tac": tac, "broadcast_plmns": [{"plmn": plmn.to_json(), "slices": [slice]}]})];
    let setup = codec::ng_setup_request(
        &plmn,
        gnb_id,
        gnb_id_bits as u32,
        Some(&name),
        &ta_list,
        actions::DEFAULT_PAGING_DRX,
    )
    .map_err(|e| anyhow!("NG Setup Request from the startup parameters: {e}"))?;
    let user_location = json!({
        "cgi": {"plmn": plmn.to_json(), "cell_id": cell},
        "tai": {"plmn": plmn.to_json(), "tac": tac},
    });

    let amf = resolve(&ctx.remote_addr).await?;
    let conn = transport::connect(amf, transport, NG_SETUP_TIMEOUT).await?;
    let local = conn.local_addr()?;
    let mut reader = conn.reader();
    let mut writer = conn.writer();
    let log = Log::new(Some(&ctx.status_tx));
    log.info(format!(
        "NGAP gNB {} ({} {}-{}) associated with AMF {amf} over {}",
        ctx.client_id,
        name,
        plmn.mcc,
        plmn.mnc,
        transport.label()
    ));
    writer
        .send(&setup)
        .await
        .context("sending NG Setup Request")?;
    let answer = match reader.next(NG_SETUP_TIMEOUT).await {
        ReadOutcome::Message(m) => m,
        ReadOutcome::TimedOut => bail!(
            "the AMF did not answer NG Setup within {}s",
            NG_SETUP_TIMEOUT.as_secs()
        ),
        other => bail!("the AMF closed the association during NG Setup: {other:?}"),
    };
    let pdu = codec::decode_pdu(&answer)
        .map_err(|e| anyhow!("the AMF's NG Setup answer did not decode: {e}"))?;
    let info = match (pdu.kind, pdu.procedure_code) {
        (PduKind::Successful, codec::PROC_NG_SETUP) => codec::parse_ng_setup_response(&pdu)
            .map_err(|e| anyhow!("NG Setup Response did not decode: {e}"))?,
        (PduKind::Unsuccessful, codec::PROC_NG_SETUP) => {
            let f = codec::parse_cause_message(&pdu).unwrap_or(Value::Null);
            bail!(
                "the AMF refused NG Setup: cause {} time_to_wait {}",
                f.get("cause").map(Value::to_string).unwrap_or_default(),
                f.get("time_to_wait")
                    .map(Value::to_string)
                    .unwrap_or_else(|| "none".into())
            )
        }
        _ => bail!("the AMF answered NG Setup with {}", pdu.label()),
    };
    log.info(format!(
        "NGAP gNB {}: NG Setup accepted by {}",
        ctx.client_id,
        info["amf_name"].as_str().unwrap_or("?")
    ));

    ctx.state
        .update_client_status(ctx.client_id, ClientStatus::Connected)
        .await;
    let external =
        crate::client::command_support::register_command_channel(&ctx.state, ctx.client_id).await;
    let (event_tx, event_rx) = mpsc::channel::<(Event, u32)>(TURNS);
    let (internal_tx, internal) = mpsc::channel::<(Value, u32)>(64);
    let mut connected = info.clone();
    connected["transport"] = json!(transport.label());
    let _ = event_tx.try_send((Event::new(&actions::CONNECTED_EVENT, connected), 0));
    let dispatcher = tokio::spawn(run_turns(ctx.clone(), event_rx, internal_tx));
    let dispatcher_abort = dispatcher.abort_handle();
    ctx.state
        .register_client_task(ctx.client_id, dispatcher)
        .await;

    let (msg_tx, msg_rx) = mpsc::channel::<ReadOutcome>(16);
    let reader_task = tokio::spawn(async move {
        loop {
            let item = reader.next(IDLE_TIMEOUT).await;
            let end = !matches!(item, ReadOutcome::Message(_) | ReadOutcome::TooLarge(_))
                || (transport == Transport::Tcp && matches!(item, ReadOutcome::TooLarge(_)));
            if msg_tx.send(item).await.is_err() || end {
                return;
            }
        }
    });
    ctx.state
        .register_client_task(ctx.client_id, reader_task)
        .await;

    let mut gnb = Gnb {
        writer,
        ues: BTreeMap::new(),
        next_ran_id: 1,
        user_location,
        setup,
        events: event_tx,
        client: ctx.client_id,
        creds,
        snn,
        gtp_address: local.ip(),
        idle: BTreeMap::new(),
    };
    let session_ctx = ctx.clone();
    let task = tokio::spawn(async move {
        let result = gnb.run(&session_ctx, msg_rx, external, internal).await;
        dispatcher_abort.abort();
        gnb.writer.close();
        let status = match result {
            Ok(()) => ClientStatus::Disconnected,
            Err(e) => {
                Log::new(Some(&session_ctx.status_tx)).warn(format!("NGAP client ended: {e:#}"));
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

impl Gnb {
    fn emit(&self, t: &'static EventType, data: Value, depth: u32) {
        if self.events.try_send((Event::new(t, data), depth)).is_err() {
            tracing::warn!(
                "NGAP client {} dropped an event: the model is {TURNS} behind decision=turn_queue_full",
                self.client
            );
        }
    }

    async fn send(&mut self, pdu: &[u8]) -> Result<()> {
        self.writer.send(pdu).await.context("writing to the AMF")
    }

    async fn run(
        &mut self,
        ctx: &ConnectContext,
        mut messages: mpsc::Receiver<ReadOutcome>,
        mut external: mpsc::Receiver<ClientCommand>,
        mut internal: mpsc::Receiver<(Value, u32)>,
    ) -> Result<()> {
        let log = Log::new(Some(&ctx.status_tx));
        loop {
            let (action, depth, mut command) = tokio::select! {
                m = messages.recv() => {
                    match m {
                        Some(ReadOutcome::Message(bytes)) => self.incoming(&bytes, &log).await?,
                        Some(ReadOutcome::TooLarge(n)) => {
                            log.warn(format!("NGAP client: the AMF sent {n} octets, over {} (decision=refused_oversize)", codec::MAX_PDU_LEN));
                            let ei = codec::error_indication(None, None, Some(&Cause::protocol(codec::PROTOCOL_TRANSFER_SYNTAX_ERROR)))?;
                            self.send(&ei).await?;
                        }
                        Some(ReadOutcome::TimedOut) => bail!("the AMF was silent for {}s", IDLE_TIMEOUT.as_secs()),
                        Some(ReadOutcome::Error(e)) => bail!("reading from the AMF: {e}"),
                        Some(ReadOutcome::Eof) | None => return Ok(()),
                    }
                    continue;
                }
                c = external.recv() => match c {
                    Some(c) => {
                        ctx.state.record_access_log(AccessLogOwner::Client(ctx.client_id.as_u32()), "NGAP", None,
                            "injected_action", c.action.clone(), vec![]).await;
                        (c.action.clone(), 0, Some(c))
                    }
                    None => return Ok(()),
                },
                a = internal.recv() => match a {
                    Some((a, d)) => (a, d, None),
                    None => return Ok(()),
                },
            };
            match NgapClientProtocol.execute_action(action.clone()) {
                Ok(ClientActionResult::Disconnect) => {
                    reply(&mut command, ClientSendOutcome::Disconnected);
                    return Ok(());
                }
                Ok(_) => {}
                Err(e) => {
                    log.warn(format!("NGAP client action refused: {e}"));
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
                    log.warn(format!("NGAP client: {e:#}"));
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

    async fn perform(&mut self, action: &Value, depth: u32) -> Result<usize> {
        let pdu = match action["type"].as_str().unwrap_or_default() {
            actions::INITIAL_UE => {
                if self.ues.len() >= MAX_UES {
                    bail!("{MAX_UES} UEs are already on this gNB");
                }
                let ran =
                    match codec::json_opt_u64(action, "ran_ue_ngap_id", codec::MAX_RAN_UE_NGAP_ID)?
                    {
                        Some(r) => r,
                        None => {
                            while self.ues.contains_key(&self.next_ran_id) {
                                self.next_ran_id += 1;
                            }
                            self.next_ran_id
                        }
                    };
                if self.ues.contains_key(&ran) {
                    bail!("RAN UE NGAP ID {ran} is already in use");
                }
                let nas =
                    nas::encode(&action["nas"], nas::UPLINK_MESSAGES).map_err(|e| anyhow!(e))?;
                let cause = action["rrc_establishment_cause"]
                    .as_str()
                    .unwrap_or(actions::DEFAULT_RRC_CAUSE);
                let pdu = codec::initial_ue_message(ran, &nas, &self.user_location, cause)?;
                let mut slot = UeSlot::new(None, depth);
                slot.sec = self
                    .creds
                    .as_ref()
                    .and_then(|c| ue::UeSec::for_registration(c, &nas))
                    .map(Box::new);
                self.ues.insert(ran, slot);
                self.next_ran_id = ran + 1;
                pdu
            }
            actions::UPLINK_NAS => {
                let amf = codec::json_u64(action, "amf_ue_ngap_id", codec::MAX_AMF_UE_NGAP_ID)?;
                let ran = codec::json_u64(action, "ran_ue_ngap_id", codec::MAX_RAN_UE_NGAP_ID)?;
                let mut nas =
                    nas::encode(&action["nas"], nas::UPLINK_MESSAGES).map_err(|e| anyhow!(e))?;
                if let Some(slot) = self.ues.get_mut(&ran) {
                    slot.depth = depth;
                    // A UE under NAS security sends the model's message protected.
                    if let Some(sec) = slot.sec.as_deref_mut() {
                        nas = sec.protect(&nas);
                    }
                }
                codec::uplink_nas_transport(amf, ran, &nas, &self.user_location)?
            }
            actions::PDU_SESSION_REQUEST => self.request_pdu_session(action, depth).await?,
            actions::PDU_SESSION_RELEASE => self.release_pdu_session(action, depth)?,
            actions::PDU_SESSION_MODIFICATION => self.modify_pdu_session(action, depth)?,
            actions::UE_CONTEXT_RELEASE_REQUEST => self.request_context_release(action, depth)?,
            actions::SERVICE_REQUEST => self.service_request_action(action, depth)?,
            actions::ERROR_INDICATION => {
                let cause = match action.get("cause").filter(|c| !c.is_null()) {
                    Some(c) => Some(Cause::from_json(c)?),
                    None => None,
                };
                codec::error_indication(
                    codec::json_opt_u64(action, "amf_ue_ngap_id", codec::MAX_AMF_UE_NGAP_ID)?,
                    codec::json_opt_u64(action, "ran_ue_ngap_id", codec::MAX_RAN_UE_NGAP_ID)?,
                    cause.as_ref(),
                )?
            }
            actions::NG_SETUP => self.setup.clone(),
            other => bail!("unexpected action {other}"),
        };
        self.send(&pdu).await?;
        Ok(pdu.len())
    }

    async fn incoming(&mut self, bytes: &[u8], log: &Log<'_>) -> Result<()> {
        let pdu = match codec::decode_pdu(bytes) {
            Ok(p) => p,
            Err(e) => {
                // Refused before the model.
                log.warn(format!(
                    "NGAP client: AMF PDU refused: {e} (decision=refused_malformed)"
                ));
                let ei = codec::error_indication(None, None, Some(&e.cause))?;
                return self.send(&ei).await;
            }
        };
        match (pdu.kind, pdu.procedure_code) {
            (PduKind::Initiating, codec::PROC_DOWNLINK_NAS_TRANSPORT) => {
                let t = match codec::parse_nas_transport(&pdu) {
                    Ok(t) => t,
                    Err(e) => {
                        let ei = codec::error_indication(None, None, Some(&e.cause))?;
                        return self.send(&ei).await;
                    }
                };
                let depth = match self.ues.get_mut(&t.ran_ue_ngap_id) {
                    Some(slot) => {
                        slot.amf = Some(t.amf_ue_ngap_id);
                        slot.depth
                    }
                    None => {
                        log.warn(format!(
                            "NGAP client: Downlink NAS Transport for unknown RAN UE NGAP ID {}",
                            t.ran_ue_ngap_id
                        ));
                        let ei = codec::error_indication(
                            Some(t.amf_ue_ngap_id),
                            Some(t.ran_ue_ngap_id),
                            Some(&Cause::radio(codec::RADIO_UNKNOWN_LOCAL_UE_NGAP_ID)),
                        )?;
                        return self.send(&ei).await;
                    }
                };
                let has_sec = self
                    .ues
                    .get(&t.ran_ue_ngap_id)
                    .map(|s| s.sec.is_some())
                    .unwrap_or(false);
                if has_sec
                    && self
                        .ue_downlink(t.amf_ue_ngap_id, t.ran_ue_ngap_id, &t.nas, depth, log)
                        .await?
                {
                    return Ok(());
                }
                self.emit(
                    &actions::DOWNLINK_NAS_EVENT,
                    json!({
                        "amf_ue_ngap_id": t.amf_ue_ngap_id,
                        "ran_ue_ngap_id": t.ran_ue_ngap_id,
                        "nas": nas::decode(&t.nas),
                        "uninterpreted_ies": t.uninterpreted,
                    }),
                    depth,
                );
            }
            (PduKind::Initiating, codec::PROC_INITIAL_CONTEXT_SETUP) => {
                self.on_initial_context_setup(&pdu, log).await?;
            }
            (PduKind::Initiating, codec::PROC_PDU_SESSION_RESOURCE_SETUP) => {
                self.on_pdu_session_setup(&pdu, log).await?;
            }
            (PduKind::Initiating, codec::PROC_UE_CONTEXT_RELEASE) => {
                self.on_context_release(&pdu, log).await?;
            }
            (PduKind::Initiating, codec::PROC_PDU_SESSION_RESOURCE_RELEASE) => {
                self.on_resource_release(&pdu, log).await?;
            }
            (PduKind::Initiating, codec::PROC_PDU_SESSION_RESOURCE_MODIFY) => {
                self.on_resource_modify(&pdu, log).await?;
            }
            (PduKind::Initiating, codec::PROC_PAGING) => {
                self.on_paging(&pdu, log).await?;
            }
            (PduKind::Initiating, codec::PROC_NG_RESET) => {
                // Every UE context on the association is gone; a registered UE stays registered
                // with the network, idle (TS 38.413 8.7.4).
                let slots = std::mem::take(&mut self.ues);
                for (_, slot) in slots {
                    self.park(slot);
                }
                let ack = codec::ng_reset_acknowledge(None)?;
                self.send(&ack).await?;
                let data = codec::parse_cause_message(&pdu).unwrap_or(Value::Null);
                self.emit(
                    &actions::ERROR_EVENT,
                    json!({"message": "ng_reset", "cause": data.get("cause")}),
                    0,
                );
            }
            (PduKind::Initiating, codec::PROC_ERROR_INDICATION) => {
                let data = codec::parse_cause_message(&pdu).unwrap_or(Value::Null);
                log.warn(format!(
                    "NGAP client: Error Indication from the AMF: {data}"
                ));
                self.emit(&actions::ERROR_EVENT, json!({"message": "error_indication", "cause": data.get("cause"),
                    "amf_ue_ngap_id": data.get("amf_ue_ngap_id"), "ran_ue_ngap_id": data.get("ran_ue_ngap_id")}), 0);
            }
            (PduKind::Successful | PduKind::Unsuccessful, codec::PROC_NG_SETUP) => {
                // A repeated NG Setup's answer.
                log.info(format!("NGAP client: {}", pdu.label()));
            }
            _ => {
                if pdu.kind == PduKind::Initiating && pdu.criticality == codec::Criticality::Reject
                {
                    let ei = codec::error_indication(
                        None,
                        None,
                        Some(&Cause::protocol(
                            codec::PROTOCOL_ABSTRACT_SYNTAX_ERROR_REJECT,
                        )),
                    )?;
                    self.send(&ei).await?;
                }
                self.emit(&actions::ERROR_EVENT, json!({"message": pdu.label(), "uninterpreted_ies": pdu.uninterpreted_ies(&[])}), 0);
            }
        }
        Ok(())
    }
}

/// Ask the model about each event and feed its actions back to the session, bounded in depth.
async fn run_turns(
    ctx: ConnectContext,
    mut events: mpsc::Receiver<(Event, u32)>,
    internal: mpsc::Sender<(Value, u32)>,
) {
    let protocol = NgapClientProtocol;
    while let Some((event, depth)) = events.recv().await {
        if depth >= MAX_FOLLOWUP_DEPTH {
            tracing::warn!(
                "NGAP client {} not asking the model about {}: {depth} turns deep decision=followup_depth",
                ctx.client_id,
                event.id()
            );
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
        match call_llm_for_client(
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
                    if internal.send((action, depth + 1)).await.is_err() {
                        return;
                    }
                }
            }
            Err(e) => Log::new(Some(&ctx.status_tx)).warn(format!("NGAP client handler: {e}")),
        }
    }
}
