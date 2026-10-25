//! The rest of a registered UE's life on this gNB, after registration and its first sessions:
//! PDU session release and modification (TS 24.501 6.3.2-6.3.3, 6.4.2-6.4.3; TS 38.413 8.2.2,
//! 8.2.3), CM-IDLE and back with a Service Request (TS 24.501 5.6.1; TS 38.413 8.3.2-8.3.3),
//! and paging (TS 38.413 8.5.1).
//!
//! The model decides when a UE releases or modifies a session, when the gNB asks the AMF to
//! release a UE's context, and when an idle UE comes back. Rust does the protocol: the protected
//! 5GSM messages and their Completes, the NGAP resource procedures, the Service Request with its
//! ciphered NAS message container, the K_gNB comparison, and the answer to a Paging — a UE
//! answers paging without asking anyone. One event per outcome, never one per message.
//!
//! An idle UE keeps its NAS security context, its PDU sessions and its 5G-S-TMSI here, keyed by
//! SUPI and bounded by [`MAX_UES`]; the gNB itself keeps no RRC state for it.

use super::ue::{ServiceAttempt, UeSec};
use super::*;
use crate::server::ngap::security;
use crate::server::ngap::sm;

/// A registered UE with no N2 connection: what it needs to come back.
pub(super) struct IdleUe {
    pub(super) sec: Box<UeSec>,
    /// The depth of the model turn that last spoke for it; its next event is raised there.
    pub(super) depth: u32,
}

/// The default cause of `ngap_ue_context_release_request`.
pub const DEFAULT_CONTEXT_RELEASE_CAUSE: &str = "radioNetwork/user-inactivity";

/// UL NAS Transport carrying a 5GSM message for an existing session: payload container type N1
/// SM, the PDU session identity, and no request type, S-NSSAI or DNN (TS 24.501 8.2.10 — those
/// belong to establishment).
fn sm_transport(psi: u8, sm_msg: &[u8]) -> Vec<u8> {
    let mut out = vec![nas::EPD_5GMM, 0, nas::UL_NAS_TRANSPORT, nas::PAYLOAD_N1_SM];
    out.extend_from_slice(&(sm_msg.len() as u16).to_be_bytes());
    out.extend_from_slice(sm_msg);
    out.extend_from_slice(&[0x12, psi]);
    out
}

fn sm_cause_json(c: Option<u8>) -> Value {
    match c {
        Some(c) => json!({"value": c, "name": sm::cause_name(c)}),
        None => Value::Null,
    }
}

/// `service_type` of `ngap_service_request`.
pub(super) fn service_type_code(action: &Value) -> Result<u8> {
    match action
        .get("service_type")
        .filter(|v| !v.is_null())
        .map(|v| v.as_str().map(|s| s.trim().to_ascii_lowercase()))
    {
        None => Ok(nas::SERVICE_TYPE_DATA),
        Some(Some(s)) => match s.as_str() {
            "data" => Ok(nas::SERVICE_TYPE_DATA),
            "signalling" | "signaling" => Ok(nas::SERVICE_TYPE_SIGNALLING),
            "mobile_terminated" | "mobile_terminated_services" => {
                Ok(nas::SERVICE_TYPE_MOBILE_TERMINATED)
            }
            other => bail!(
                "service_type {other:?} must be \"data\", \"signalling\" or \"mobile_terminated\""
            ),
        },
        Some(None) => bail!("service_type must be a string"),
    }
}

/// `pdu_session_ids` of `ngap_service_request`: PSIs 1..15, at most 15.
pub(super) fn psi_array(action: &Value) -> Result<Option<Vec<u8>>> {
    let Some(v) = action.get("pdu_session_ids").filter(|v| !v.is_null()) else {
        return Ok(None);
    };
    let arr = v
        .as_array()
        .context("pdu_session_ids must be an array of PDU session ids")?;
    anyhow::ensure!(arr.len() <= 15, "pdu_session_ids holds at most 15 ids");
    arr.iter()
        .map(|p| match p.as_u64() {
            Some(p @ 1..=15) => Ok(p as u8),
            _ => bail!("each of pdu_session_ids must be 1..15"),
        })
        .collect::<Result<Vec<_>>>()
        .map(Some)
}

fn rrc_cause_for(service_type: u8) -> &'static str {
    match service_type {
        nas::SERVICE_TYPE_MOBILE_TERMINATED => "mt-Access",
        nas::SERVICE_TYPE_DATA => "mo-Data",
        _ => "mo-Signalling",
    }
}

fn service_type_label(t: u8) -> &'static str {
    match t {
        nas::SERVICE_TYPE_MOBILE_TERMINATED => "mobile_terminated",
        other => nas::service_type_name(other),
    }
}

impl Gnb {
    /// The registered UE `ran` with credentials, for an action: its AMF id and security state.
    fn registered_ue(&mut self, ran: u64, depth: u32) -> Result<(u64, &mut UeSec)> {
        let slot = self
            .ues
            .get_mut(&ran)
            .with_context(|| format!("no UE with RAN UE NGAP ID {ran}"))?;
        slot.depth = depth;
        let amf = slot.amf.context("the AMF has not named this UE yet")?;
        let sec = slot
            .sec
            .as_deref_mut()
            .context("this UE has no credentials on this gNB (give subscriber_key and supi)")?;
        anyhow::ensure!(sec.registered, "the UE is not registered");
        Ok((amf, sec))
    }

    /// `ngap_pdu_session_release`: a protected 5GSM PDU Session Release Request.
    pub(super) fn release_pdu_session(&mut self, action: &Value, depth: u32) -> Result<Vec<u8>> {
        let ran = codec::json_u64(action, "ran_ue_ngap_id", codec::MAX_RAN_UE_NGAP_ID)?;
        let psi = codec::json_u64(action, "pdu_session_id", 15)? as u8;
        let cause = match action.get("cause").filter(|c| !c.is_null()) {
            Some(c) => sm::parse_cause(c).map_err(|e| anyhow!(e))?,
            None => sm::CAUSE_REGULAR_DEACTIVATION,
        };
        let user_location = self.user_location.clone();
        let (amf, sec) = self.registered_ue(ran, depth)?;
        anyhow::ensure!(
            sec.sessions.contains_key(&psi),
            "the UE holds no PDU session {psi}"
        );
        let pti = sec.take_pti();
        sec.releasing.insert(psi, pti);
        let protected = sec.protect(&sm_transport(
            psi,
            &sm::release_request(psi, pti, Some(cause)),
        ));
        debug!("NGAP client UE {ran}: PDU Session Release Request {psi} PTI {pti}");
        Ok(codec::uplink_nas_transport(
            amf,
            ran,
            &protected,
            &user_location,
        )?)
    }

    /// `ngap_pdu_session_modification`: a protected 5GSM PDU Session Modification Request asking
    /// for a 5QI on the session's default flow.
    pub(super) fn modify_pdu_session(&mut self, action: &Value, depth: u32) -> Result<Vec<u8>> {
        let ran = codec::json_u64(action, "ran_ue_ngap_id", codec::MAX_RAN_UE_NGAP_ID)?;
        let psi = codec::json_u64(action, "pdu_session_id", 15)? as u8;
        let five_qi = codec::json_opt_u64(action, "five_qi", 255)?.map(|q| q as u8);
        let user_location = self.user_location.clone();
        let (amf, sec) = self.registered_ue(ran, depth)?;
        let qfi = sec
            .sessions
            .get(&psi)
            .with_context(|| format!("the UE holds no PDU session {psi}"))?
            .qfis
            .first()
            .copied()
            .unwrap_or(1);
        let pti = sec.take_pti();
        sec.modifying.insert(psi, (pti, five_qi));
        let protected = sec.protect(&sm_transport(
            psi,
            &sm::modification_request(psi, pti, qfi, five_qi),
        ));
        Ok(codec::uplink_nas_transport(
            amf,
            ran,
            &protected,
            &user_location,
        )?)
    }

    /// `ngap_ue_context_release_request`: the gNB asks the AMF to release a UE's N2 context.
    pub(super) fn request_context_release(
        &mut self,
        action: &Value,
        depth: u32,
    ) -> Result<Vec<u8>> {
        let ran = codec::json_u64(action, "ran_ue_ngap_id", codec::MAX_RAN_UE_NGAP_ID)?;
        let cause = Cause::from_json(
            action
                .get("cause")
                .filter(|c| !c.is_null())
                .unwrap_or(&json!(DEFAULT_CONTEXT_RELEASE_CAUSE)),
        )?;
        let slot = self
            .ues
            .get_mut(&ran)
            .with_context(|| format!("no UE with RAN UE NGAP ID {ran}"))?;
        slot.depth = depth;
        let amf = slot.amf.context("the AMF has not named this UE yet")?;
        Ok(codec::ue_context_release_request(amf, ran, &cause)?)
    }

    /// `ngap_service_request`: bring an idle UE back.
    pub(super) fn service_request_action(&mut self, action: &Value, depth: u32) -> Result<Vec<u8>> {
        let supi = crate::server::ngap::subscribers::supi_digits(
            action["supi"].as_str().context("supi is required")?,
        )
        .map_err(|e| anyhow!(e))?;
        let service_type = service_type_code(action)?;
        let idle = self.idle.get(&supi).with_context(|| {
            format!("imsi-{supi} is not idle on this gNB (a UE goes idle when the AMF releases its context)")
        })?;
        let held: Vec<u8> = idle.sec.sessions.keys().copied().collect();
        let uplink = match psi_array(action)? {
            Some(list) => {
                if let Some(p) = list.iter().find(|p| !held.contains(p)) {
                    bail!("imsi-{supi} holds no PDU session {p} (it holds {held:?})");
                }
                Some(list)
            }
            None if service_type == nas::SERVICE_TYPE_DATA => Some(held),
            None => None,
        };
        self.service_request(&supi, service_type, uplink, "ue", depth)
    }

    /// Move an idle UE onto a new RAN UE NGAP ID with an Initial UE Message carrying its Service
    /// Request (TS 24.501 4.4.6, as UERANSIM v3.2.7 sends it): the whole message, with the
    /// Uplink data status and PDU session status, ciphered with the current context at the
    /// COUNT of the outer message, in a NAS message container; the outer message keeps only the
    /// cleartext IEs and is integrity protected, not ciphered (security header type 1).
    pub(super) fn service_request(
        &mut self,
        supi: &str,
        service_type: u8,
        uplink: Option<Vec<u8>>,
        trigger: &'static str,
        depth: u32,
    ) -> Result<Vec<u8>> {
        if self.ues.len() >= MAX_UES {
            bail!("{MAX_UES} UEs are already on this gNB");
        }
        let mut idle = self
            .idle
            .remove(supi)
            .with_context(|| format!("imsi-{supi} is not idle on this gNB"))?;
        let sec = &mut idle.sec;
        let Some((set, pointer, tmsi)) = sec.s_tmsi else {
            bail!("imsi-{supi} has no 5G-S-TMSI");
        };
        let held = nas::psi_bits(sec.sessions.keys().copied());
        let Some(ctx) = sec.ctx.as_mut() else {
            bail!("imsi-{supi} has no NAS security context");
        };
        let mut request = nas::ServiceRequest {
            service_type,
            ngksi: ctx.ngksi & 0x07,
            amf_set_id: set,
            amf_pointer: pointer,
            tmsi,
            uplink_data_status: uplink.map(nas::psi_bits),
            pdu_session_status: Some(held),
            allowed_pdu_session_status: None,
            nas_container: None,
        };
        let mut container = nas::service_request(&request);
        let count = ctx.counts.tx;
        ctx.cipher_at(count, security::UPLINK, &mut container);
        request.uplink_data_status = None;
        request.pdu_session_status = None;
        request.nas_container = Some(container);
        let protected = ctx.protect(&nas::service_request(&request), security::SHT_INTEGRITY);
        // K_gNB from the Service Request's uplink COUNT (TS 33.501 6.8.1.2.1, A.9).
        sec.k_gnb = Some(ctx.k_gnb());
        sec.service = Some(ServiceAttempt {
            service_type,
            trigger,
        });
        while self.ues.contains_key(&self.next_ran_id) {
            self.next_ran_id += 1;
        }
        let ran = self.next_ran_id;
        let pdu = match codec::initial_ue_message_with_tmsi(
            ran,
            &protected,
            &self.user_location,
            rrc_cause_for(service_type),
            Some((set, pointer, tmsi)),
        ) {
            Ok(p) => p,
            Err(e) => {
                idle.sec.service = None;
                self.idle.insert(supi.to_string(), idle);
                return Err(e.into());
            }
        };
        let mut slot = UeSlot::new(None, depth);
        slot.sec = Some(idle.sec);
        self.ues.insert(ran, slot);
        self.next_ran_id = ran + 1;
        tracing::info!(
            "NGAP client UE {ran} imsi-{supi}: Service Request ({}, {trigger}) at uplink COUNT \
             {count} (decision=service_request)",
            service_type_label(service_type)
        );
        Ok(pdu)
    }

    /// A Service Accept, verified: release locally any session the network no longer has, and
    /// say what came back.
    pub(super) async fn on_service_accept(
        &mut self,
        amf: u64,
        ran: u64,
        plain: &[u8],
        depth: u32,
        log: &Log<'_>,
    ) -> Result<()> {
        let accept = match nas::parse_service_accept(plain) {
            Ok(a) => a,
            Err(e) => {
                log.warn(format!(
                    "NGAP client UE {ran}: Service Accept does not decode: {e} (decision=nas_malformed)"
                ));
                return Ok(());
            }
        };
        let Some(slot) = self.ues.get_mut(&ran) else {
            return Ok(());
        };
        let k_gnb_verified = slot.k_gnb_verified;
        let tunnels = &mut slot.sessions;
        let Some(sec) = slot.sec.as_deref_mut() else {
            return Ok(());
        };
        let Some(attempt) = sec.service.take() else {
            return Ok(());
        };
        let mut released_locally = Vec::new();
        if let Some(bits) = accept.pdu_session_status {
            let network = nas::psi_list(bits);
            let gone: Vec<u8> = sec
                .sessions
                .keys()
                .copied()
                .filter(|p| !network.contains(p))
                .collect();
            for psi in gone {
                sec.sessions.remove(&psi);
                tunnels.remove(&psi);
                released_locally.push(psi);
            }
        }
        let status: Vec<u8> = sec.sessions.keys().copied().collect();
        let user_plane: Vec<u8> = tunnels.keys().copied().collect();
        let supi = format!("imsi-{}", sec.supi);
        let nas_security = sec.nas_security();
        log.info(format!(
            "NGAP client UE {ran} {supi}: Service Accept ({}, {}), PDU sessions {status:?}, user \
             plane {user_plane:?}, K_gNB {} (decision=service_accepted)",
            service_type_label(attempt.service_type),
            attempt.trigger,
            match k_gnb_verified {
                Some(true) => "verified",
                Some(false) => "MISMATCH",
                None => "not received",
            }
        ));
        self.emit(
            &actions::SERVICE_ACCEPTED_EVENT,
            json!({
                "amf_ue_ngap_id": amf,
                "ran_ue_ngap_id": ran,
                "supi": supi,
                "service_type": service_type_label(attempt.service_type),
                "trigger": attempt.trigger,
                "pdu_session_status": status,
                "user_plane_sessions": user_plane,
                "released_locally": released_locally,
                "k_gnb_verified": k_gnb_verified,
                "nas_security": nas_security,
            }),
            depth,
        );
        Ok(())
    }

    /// A Service Reject. Causes #9 and #10 mean the network no longer knows the UE: it must
    /// register again, so it is not kept idle when the AMF releases it.
    pub(super) fn on_service_reject(
        &mut self,
        amf: u64,
        ran: u64,
        plain: &[u8],
        sht: u8,
        depth: u32,
        log: &Log<'_>,
    ) {
        let cause = plain.get(3).copied().unwrap_or(0);
        let Some(sec) = self.sec(ran) else {
            return;
        };
        let Some(attempt) = sec.service.take() else {
            return;
        };
        if matches!(cause, 9 | 10) {
            sec.registered = false;
        }
        let registered = sec.registered;
        let supi = format!("imsi-{}", sec.supi);
        log.warn(format!(
            "NGAP client UE {ran} {supi}: Service Reject {} ({}) (decision=service_rejected)",
            nas::cause_name(cause),
            if sht == security::SHT_PLAIN {
                "unprotected"
            } else {
                "protected"
            }
        ));
        self.emit(
            &actions::SERVICE_REJECTED_EVENT,
            json!({
                "amf_ue_ngap_id": amf,
                "ran_ue_ngap_id": ran,
                "supi": supi,
                "service_type": service_type_label(attempt.service_type),
                "trigger": attempt.trigger,
                "cause": {"value": cause, "name": nas::cause_name(cause)},
                "protected": sht != security::SHT_PLAIN,
                "still_registered": registered,
            }),
            depth,
        );
    }

    /// A 5GSM release or modification message for a UE with credentials. `Ok(true)` always: the
    /// message was this UE's, answered or reported.
    pub(super) async fn on_session_procedure(
        &mut self,
        amf: u64,
        ran: u64,
        payload: &[u8],
        depth: u32,
        log: &Log<'_>,
    ) -> Result<bool> {
        let p = match sm::parse_procedure(payload) {
            Ok(p) => p,
            Err(_) => {
                // A 5GSM Status or anything else this UE does not act on: the model reads it.
                self.emit(
                    &actions::DOWNLINK_NAS_EVENT,
                    json!({"amf_ue_ngap_id": amf, "ran_ue_ngap_id": ran, "nas": sm::decode(payload), "protected": true}),
                    depth,
                );
                return Ok(true);
            }
        };
        let psi = p.psi;
        let Some(slot) = self.ues.get_mut(&ran) else {
            return Ok(true);
        };
        let tunnels = &mut slot.sessions;
        let Some(sec) = slot.sec.as_deref_mut() else {
            return Ok(true);
        };
        match p.message_type {
            sm::PDU_SESSION_RELEASE_COMMAND => {
                let asked = sec.releasing.remove(&psi);
                let requested_by = if p.pti != 0 && asked == Some(p.pti) {
                    "ue"
                } else {
                    "network"
                };
                let held = sec.sessions.remove(&psi).is_some();
                sec.modifying.remove(&psi);
                tunnels.remove(&psi);
                self.send_ue_uplink(
                    amf,
                    ran,
                    &sm_transport(psi, &sm::release_complete(psi, p.pti)),
                    log,
                )
                .await?;
                log.info(format!(
                    "NGAP client UE {ran}: PDU session {psi} released ({requested_by}, {}){} \
                     (decision=pdu_session_released)",
                    p.cause.map(sm::cause_name).unwrap_or_default(),
                    if held { "" } else { "; it was not held" }
                ));
                self.emit(
                    &actions::PDU_RELEASED_EVENT,
                    json!({
                        "amf_ue_ngap_id": amf,
                        "ran_ue_ngap_id": ran,
                        "pdu_session_id": psi,
                        "result": "released",
                        "requested_by": requested_by,
                        "cause": sm_cause_json(p.cause),
                    }),
                    depth,
                );
            }
            sm::PDU_SESSION_RELEASE_REJECT => {
                sec.releasing.remove(&psi);
                log.warn(format!(
                    "NGAP client UE {ran}: release of PDU session {psi} refused: {} \
                     (decision=pdu_session_release_rejected)",
                    p.cause.map(sm::cause_name).unwrap_or_default()
                ));
                self.emit(
                    &actions::PDU_RELEASED_EVENT,
                    json!({
                        "amf_ue_ngap_id": amf,
                        "ran_ue_ngap_id": ran,
                        "pdu_session_id": psi,
                        "result": "rejected",
                        "requested_by": "ue",
                        "cause": sm_cause_json(p.cause),
                    }),
                    depth,
                );
            }
            sm::PDU_SESSION_MODIFICATION_COMMAND => {
                let asked = sec.modifying.remove(&psi);
                let requested_by = if p.pti != 0 && asked.map(|a| a.0) == Some(p.pti) {
                    "ue"
                } else {
                    "network"
                };
                if let (Some(s), Some((_, q))) = (sec.sessions.get_mut(&psi), p.flow_five_qi) {
                    s.five_qi = Some(q);
                }
                self.send_ue_uplink(
                    amf,
                    ran,
                    &sm_transport(psi, &sm::modification_complete(psi, p.pti)),
                    log,
                )
                .await?;
                let ambr = match (p.ambr_uplink_kbps, p.ambr_downlink_kbps) {
                    (Some(u), Some(d)) => json!({"uplink": u, "downlink": d}),
                    _ => Value::Null,
                };
                log.info(format!(
                    "NGAP client UE {ran}: PDU session {psi} modified ({requested_by}): 5QI {:?}, \
                     session AMBR {ambr} (decision=pdu_session_modified)",
                    p.flow_five_qi.map(|f| f.1)
                ));
                self.emit(
                    &actions::PDU_MODIFIED_EVENT,
                    json!({
                        "amf_ue_ngap_id": amf,
                        "ran_ue_ngap_id": ran,
                        "pdu_session_id": psi,
                        "result": "modified",
                        "requested_by": requested_by,
                        "requested_five_qi": asked.and_then(|a| a.1),
                        "five_qi": p.flow_five_qi.map(|f| f.1),
                        "qfi": p.flow_five_qi.map(|f| f.0),
                        "session_ambr_kbps": ambr,
                        "cause": sm_cause_json(p.cause),
                        "ies": p.optional_ies,
                    }),
                    depth,
                );
            }
            sm::PDU_SESSION_MODIFICATION_REJECT => {
                let asked = sec.modifying.remove(&psi);
                log.warn(format!(
                    "NGAP client UE {ran}: modification of PDU session {psi} refused: {} \
                     (decision=pdu_session_modification_rejected)",
                    p.cause.map(sm::cause_name).unwrap_or_default()
                ));
                self.emit(
                    &actions::PDU_MODIFIED_EVENT,
                    json!({
                        "amf_ue_ngap_id": amf,
                        "ran_ue_ngap_id": ran,
                        "pdu_session_id": psi,
                        "result": "rejected",
                        "requested_five_qi": asked.and_then(|a| a.1),
                        "cause": sm_cause_json(p.cause),
                    }),
                    depth,
                );
            }
            _ => {
                self.emit(
                    &actions::DOWNLINK_NAS_EVENT,
                    json!({"amf_ue_ngap_id": amf, "ran_ue_ngap_id": ran, "nas": sm::decode(payload), "protected": true}),
                    depth,
                );
            }
        }
        Ok(true)
    }

    /// Deliver a NAS-PDU that came inside an NGAP resource procedure to the UE.
    async fn deliver_nas(
        &mut self,
        amf: u64,
        ran: u64,
        nas_pdu: &[u8],
        via: &str,
        depth: u32,
        log: &Log<'_>,
    ) -> Result<()> {
        let handled = if self.sec(ran).is_some() {
            self.ue_downlink(amf, ran, nas_pdu, depth, log).await?
        } else {
            false
        };
        if !handled {
            self.emit(
                &actions::DOWNLINK_NAS_EVENT,
                json!({"amf_ue_ngap_id": amf, "ran_ue_ngap_id": ran, "nas": nas::decode(nas_pdu), "via": via}),
                depth,
            );
        }
        Ok(())
    }

    async fn unknown_ue(&mut self, amf: u64, ran: u64) -> Result<()> {
        let ei = codec::error_indication(
            Some(amf),
            Some(ran),
            Some(&Cause::radio(codec::RADIO_UNKNOWN_LOCAL_UE_NGAP_ID)),
        )?;
        self.send(&ei).await
    }

    /// PDU Session Resource Release Command: drop the sessions' tunnels, answer, then deliver
    /// the 5GSM Release Command it carries.
    pub(super) async fn on_resource_release(
        &mut self,
        pdu: &codec::Pdu,
        log: &Log<'_>,
    ) -> Result<()> {
        let rc = match codec::parse_pdu_session_resource_release_command(pdu) {
            Ok(r) => r,
            Err(e) => {
                log.warn(format!(
                    "NGAP client: PDU Session Resource Release Command: {e}"
                ));
                let ei = codec::error_indication(None, None, Some(&e.cause))?;
                return self.send(&ei).await;
            }
        };
        let (amf, ran) = (rc.amf_ue_ngap_id, rc.ran_ue_ngap_id);
        let Some(slot) = self.ues.get_mut(&ran) else {
            return self.unknown_ue(amf, ran).await;
        };
        slot.amf = Some(amf);
        let depth = slot.depth;
        let psis: Vec<u8> = rc.sessions.iter().map(|(p, _)| *p).collect();
        for p in &psis {
            slot.sessions.remove(p);
        }
        let response = codec::pdu_session_resource_release_response(amf, ran, &psis)?;
        self.send(&response).await?;
        log.info(format!(
            "NGAP client UE {ran}: PDU Session Resource Release {psis:?} ({}); tunnels dropped",
            rc.sessions
                .iter()
                .map(|(_, c)| c.label())
                .collect::<Vec<_>>()
                .join(", ")
        ));
        if let Some(nas_pdu) = rc.nas {
            self.deliver_nas(
                amf,
                ran,
                &nas_pdu,
                "pdu_session_resource_release",
                depth,
                log,
            )
            .await?;
        }
        Ok(())
    }

    /// PDU Session Resource Modify Request: answer with the QFIs of each session this gNB has,
    /// then deliver each session's NAS (normally a 5GSM Modification Command).
    pub(super) async fn on_resource_modify(
        &mut self,
        pdu: &codec::Pdu,
        log: &Log<'_>,
    ) -> Result<()> {
        let (amf, ran, items) = match codec::parse_pdu_session_resource_modify_request(pdu) {
            Ok(x) => x,
            Err(e) => {
                log.warn(format!(
                    "NGAP client: PDU Session Resource Modify Request: {e}"
                ));
                let ei = codec::error_indication(None, None, Some(&e.cause))?;
                return self.send(&ei).await;
            }
        };
        let Some(slot) = self.ues.get_mut(&ran) else {
            return self.unknown_ue(amf, ran).await;
        };
        slot.amf = Some(amf);
        let depth = slot.depth;
        let unknown = Cause::from_json(&json!("radioNetwork/unknown-PDU-session-ID"))?;
        let mut modified = Vec::new();
        let mut failed = Vec::new();
        for it in &items {
            if !slot.sessions.contains_key(&it.pdu_session_id) {
                failed.push((it.pdu_session_id, unknown));
                continue;
            }
            let known = slot
                .sec
                .as_deref()
                .and_then(|s| s.sessions.get(&it.pdu_session_id))
                .map(|s| s.qfis.clone())
                .unwrap_or_else(|| vec![1]);
            let qfis = match codec::decode_modify_request_transfer(&it.transfer) {
                Ok(t) if !t.qos_flows.is_empty() => t.qos_flows.iter().map(|f| f.qfi).collect(),
                Ok(_) => known,
                Err(e) => {
                    log.warn(format!(
                        "NGAP client UE {ran}: PDU session {} modify transfer does not decode \
                         ({e}); answering with its known QoS flows",
                        it.pdu_session_id
                    ));
                    known
                }
            };
            modified.push((it.pdu_session_id, codec::ModifyResponseTransfer { qfis }));
        }
        let response = codec::pdu_session_resource_modify_response(amf, ran, &modified, &failed)?;
        self.send(&response).await?;
        for it in items {
            if let Some(nas_pdu) = it.nas {
                self.deliver_nas(
                    amf,
                    ran,
                    &nas_pdu,
                    "pdu_session_resource_modify",
                    depth,
                    log,
                )
                .await?;
            }
        }
        Ok(())
    }

    /// A UE leaving this gNB's N2 association: a registered UE with credentials and a 5G-S-TMSI
    /// goes idle, keeping its NAS context and sessions; anything else is gone. Returns the SUPI
    /// it is kept under.
    pub(super) fn park(&mut self, slot: UeSlot) -> Option<String> {
        let mut sec = slot.sec?;
        if !sec.registered || sec.s_tmsi.is_none() || sec.ctx.is_none() {
            return None;
        }
        if self.idle.len() >= MAX_UES && !self.idle.contains_key(&sec.supi) {
            tracing::warn!(
                "NGAP client {}: {MAX_UES} idle UEs already held; imsi-{} is dropped \
                 (decision=idle_store_full)",
                self.client,
                sec.supi
            );
            return None;
        }
        sec.releasing.clear();
        sec.modifying.clear();
        sec.service = None;
        let supi = sec.supi.clone();
        self.idle.insert(
            supi.clone(),
            IdleUe {
                sec,
                depth: slot.depth,
            },
        );
        Some(supi)
    }

    /// UE Context Release Command: answer Release Complete; a registered UE goes idle.
    pub(super) async fn on_context_release(
        &mut self,
        pdu: &codec::Pdu,
        log: &Log<'_>,
    ) -> Result<()> {
        let mut budget = codec::Budget::default();
        let ids = pdu
            .require(codec::IE_UE_NGAP_IDS)
            .and_then(|ie| codec::decode_ue_ngap_ids(ie, &mut budget));
        let (amf, ran) = match ids {
            Ok(v) => v,
            Err(e) => {
                let ei = codec::error_indication(None, None, Some(&e.cause))?;
                return self.send(&ei).await;
            }
        };
        let ran = ran.or_else(|| {
            self.ues
                .iter()
                .find(|(_, u)| u.amf == Some(amf))
                .map(|(r, _)| *r)
        });
        let cause = pdu
            .ie(codec::IE_CAUSE)
            .and_then(|ie| codec::decode_cause(ie).ok())
            .map(|c| c.to_json());
        let mut depth = 0;
        let mut idle = None;
        if let Some(r) = ran {
            if let Some(slot) = self.ues.remove(&r) {
                depth = slot.depth;
                idle = self.park(slot);
            }
            let complete = codec::ue_context_release_complete(amf, r)?;
            self.send(&complete).await?;
        }
        let mut data = json!({"amf_ue_ngap_id": amf, "ran_ue_ngap_id": ran, "cause": cause,
            "cm_state": if idle.is_some() { "idle" } else { "released" }});
        if let Some(supi) = &idle {
            let held: Vec<u8> = self
                .idle
                .get(supi)
                .map(|u| u.sec.sessions.keys().copied().collect())
                .unwrap_or_default();
            log.info(format!(
                "NGAP client UE {}: imsi-{supi} is CM-IDLE, PDU sessions {held:?} kept \
                 (decision=ue_idle)",
                ran.unwrap_or_default()
            ));
            data["supi"] = json!(format!("imsi-{supi}"));
            data["pdu_sessions"] = json!(held);
        }
        self.emit(&actions::RELEASE_EVENT, data, depth);
        Ok(())
    }

    /// NGAP Paging: an idle UE whose 5G-S-TMSI it names, in a tracking area this gNB serves,
    /// answers with a Service Request (mobile terminated services) — Rust's, not the model's.
    pub(super) async fn on_paging(&mut self, pdu: &codec::Pdu, log: &Log<'_>) -> Result<()> {
        let paging = match codec::parse_paging(pdu) {
            Ok(p) => p,
            Err(e) => {
                log.warn(format!("NGAP client: Paging: {e}"));
                let ei = codec::error_indication(None, None, Some(&e.cause))?;
                return self.send(&ei).await;
            }
        };
        let my_tac = self.user_location["tai"]["tac"].as_u64().unwrap_or(0) as u32;
        let my_plmn = codec::Plmn::from_json(&self.user_location["tai"]["plmn"]).ok();
        let served = paging
            .tais
            .iter()
            .any(|(p, t)| *t == my_tac && Some(p) == my_plmn.as_ref());
        let target = (paging.amf_set_id, paging.amf_pointer, paging.tmsi);
        let found = self
            .idle
            .iter()
            .find(|(_, u)| u.sec.s_tmsi == Some(target))
            .map(|(s, u)| (s.clone(), u.depth));
        match (found, served) {
            (Some((supi, depth)), true) => {
                log.info(format!(
                    "NGAP client: Paging for 5G-S-TMSI {}/{}/{:#010x} is imsi-{supi}; answering \
                     with a Service Request (decision=paging_answered)",
                    target.0, target.1, target.2
                ));
                let pdu = self.service_request(
                    &supi,
                    nas::SERVICE_TYPE_MOBILE_TERMINATED,
                    None,
                    "paging",
                    depth,
                )?;
                self.send(&pdu).await
            }
            (Some((supi, _)), false) => {
                log.info(format!(
                    "NGAP client: Paging for imsi-{supi} names no tracking area this gNB serves \
                     (TAC {my_tac}); ignored (decision=paging_other_area)"
                ));
                Ok(())
            }
            (None, _) => {
                log.info(format!(
                    "NGAP client: Paging for 5G-S-TMSI {}/{}/{:#010x}, which no idle UE here \
                     holds; ignored (decision=paging_not_here)",
                    target.0, target.1, target.2
                ));
                Ok(())
            }
        }
    }
}
