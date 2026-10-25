//! PDU session release (TS 24.501 6.3.3 network-requested, 6.4.3 UE-requested; TS 38.413 8.2.2)
//! and modification (TS 24.501 6.3.2, 6.4.2; TS 38.413 8.2.3) for a registered UE with
//! credentials.
//!
//! The model decides: whether to release a session the UE asks to release
//! (`ngap_pdu_session_release_request` → `send_pdu_session_release` or
//! `send_pdu_session_release_reject`), what a UE-requested modification becomes
//! (`ngap_pdu_session_modification_request` → `send_pdu_session_modification` with the session
//! AMBR and the default flow's 5QI, or `send_pdu_session_modification_reject`), and — with the
//! same two actions, unprompted — network-requested releases and modifications. Everything else
//! is Rust's: the 5GSM messages, their protection, the NGAP resource procedures, the user plane,
//! and the UE's Complete or Command Reject.
//!
//! Fail closed. A UE's release request the model does not answer, or cannot evaluate, is
//! **released**: releasing keeps nothing open, so it is the closed direction, like NG Reset — a
//! session stays only if the model says so. A modification request the model does not answer is
//! **rejected** (#31, or #26 when the model was overloaded): nothing changes. Each is tagged
//! `decision=model_silent`, `fail_closed_llm_error` or `no_policy_configured`.
//!
//! A release frees the session's uplink TEID in the user plane when the command is sent, so its
//! G-PDUs are dropped as `up_no_session` from then on; the session itself is forgotten when the
//! UE's Release Complete arrives.

use super::*;
use amf::{supi_label, PendingSm, Phase, SmAsk};

/// A release or modification decision found its UE idle: it was queued and the UE paged.
const QUEUED_FOR_IDLE: &str = "queued for an idle UE";

impl Session {
    /// A 5GSM release or modification message from a registered UE, or a 5GSM Status.
    pub(super) async fn on_session_procedure(
        &mut self,
        amf: u64,
        ran: u64,
        psi: u8,
        payload: &[u8],
    ) -> bool {
        if sm::header(payload).map(|(_, _, t)| t) == Some(sm::FIVEGSM_STATUS) {
            Log::new(Some(&self.status_tx)).warn(format!(
                "NGAP UE {amf}: 5GSM Status for PDU session {psi}: {}",
                sm::decode(payload)["cause"]
            ));
            return true;
        }
        let p = match sm::parse_procedure(payload) {
            Ok(p) => p,
            Err(e) => {
                Log::new(Some(&self.status_tx)).warn(format!(
                    "NGAP UE {amf}: 5GSM message for PDU session {psi} does not decode: {e} \
                     (decision=nas_malformed)"
                ));
                return true;
            }
        };
        match p.message_type {
            sm::PDU_SESSION_RELEASE_REQUEST => self.on_ue_release_request(amf, ran, psi, &p).await,
            sm::PDU_SESSION_MODIFICATION_REQUEST => {
                self.on_ue_modification_request(amf, ran, psi, &p).await
            }
            sm::PDU_SESSION_RELEASE_COMPLETE => {
                let up = self.core.user_plane.clone();
                let status_tx = self.status_tx.clone();
                let Some(sec) = self.sec(amf) else {
                    return true;
                };
                let label = supi_label(&sec.supi);
                match sec.sessions.get(&psi).map(|s| s.releasing) {
                    Some(true) => {
                        if let (Some(s), Some(up)) = (sec.sessions.remove(&psi), &up) {
                            up.remove(s.ul_teid);
                        }
                        Log::new(Some(&status_tx)).info(format!(
                            "NGAP UE {amf} {label}: PDU session {psi} released \
                             (decision=pdu_session_released)"
                        ));
                    }
                    _ => Log::new(Some(&status_tx)).warn(format!(
                        "NGAP UE {amf} {label}: Release Complete for PDU session {psi}, which \
                         was not being released; ignored"
                    )),
                }
                true
            }
            sm::PDU_SESSION_MODIFICATION_COMPLETE | sm::PDU_SESSION_MODIFICATION_COMMAND_REJECT => {
                let status_tx = self.status_tx.clone();
                let Some(sec) = self.sec(amf) else {
                    return true;
                };
                let label = supi_label(&sec.supi);
                let Some(s) = sec.sessions.get_mut(&psi) else {
                    return true;
                };
                let Some(m) = s.modifying.take() else {
                    debug!("NGAP UE {amf}: no modification of PDU session {psi} was pending");
                    return true;
                };
                if p.message_type == sm::PDU_SESSION_MODIFICATION_COMPLETE {
                    if let (Some(ul), Some(dl)) = (m.ambr_uplink_kbps, m.ambr_downlink_kbps) {
                        s.ambr_ul_kbps = ul;
                        s.ambr_dl_kbps = dl;
                    }
                    if let Some((_, q)) = m.flow_five_qi {
                        s.five_qi = q;
                    }
                    Log::new(Some(&status_tx)).info(format!(
                        "NGAP UE {amf} {label}: PDU session {psi} modified (5QI {}, AMBR {}/{} \
                         kbps up/down) (decision=pdu_session_modified)",
                        s.five_qi, s.ambr_ul_kbps, s.ambr_dl_kbps
                    ));
                } else {
                    Log::new(Some(&status_tx)).warn(format!(
                        "NGAP UE {amf} {label}: the UE refused the modification of PDU session \
                         {psi} with 5GSM {} (decision=pdu_session_modification_refused_by_ue)",
                        sm::cause_name(p.cause.unwrap_or(0))
                    ));
                }
                true
            }
            _ => true,
        }
    }

    async fn on_ue_release_request(
        &mut self,
        amf: u64,
        ran: u64,
        psi: u8,
        p: &sm::SmProcedure,
    ) -> bool {
        let refuse = {
            let Some(sec) = self.sec(amf) else {
                return true;
            };
            match sec.sessions.get(&psi) {
                None => Some((43, "pdu_session_release_unknown")),
                Some(s) if s.releasing => Some((43, "pdu_session_release_unknown")),
                Some(_) if sec.pending_sm.contains_key(&psi) => {
                    Some((101, "pdu_session_procedure_in_progress"))
                }
                Some(_) => {
                    sec.pending_sm.insert(
                        psi,
                        PendingSm {
                            pti: p.pti,
                            kind: SmAsk::Release,
                        },
                    );
                    None
                }
            }
        };
        if let Some((cause, tag)) = refuse {
            Log::new(Some(&self.status_tx)).warn(format!(
                "NGAP UE {amf}: release of PDU session {psi} refused before the model \
                 (decision={tag})"
            ));
            let reject = sm::release_reject(psi, p.pti, cause);
            self.send_ue_nas(amf, ran, nas::dl_nas_transport_sm(psi, &reject))
                .await;
            return true;
        }
        let data = self.session_event_data(amf, ran, psi, p);
        let event = Event::new(&actions::NGAP_PDU_SESSION_RELEASE_EVENT, data);
        let event_id = event.event_type.id.clone();
        let outcome = self.call_llm_and_send(&event).await;
        let (closed, failure, tag) = match outcome {
            HandlerOutcome::Ran {
                ref pdu_answers,
                closed,
                ..
            } if pdu_answers.contains(&(amf, psi)) => return !closed,
            HandlerOutcome::Ran { closed, .. } => (closed, None, "model_silent"),
            HandlerOutcome::Failed(f) => (false, Some(f), "fail_closed_llm_error"),
            HandlerOutcome::NoPolicy => (false, None, "no_policy_configured"),
        };
        let _ = failure;
        Log::new(Some(&self.status_tx)).warn(format!(
            "NGAP {event_id} produced no decision for UE {amf} PDU session {psi} \
             (decision={tag}); releasing it as the UE asked: a release keeps nothing open"
        ));
        if let Err(e) = self
            .do_release(amf, psi, sm::CAUSE_REGULAR_DEACTIVATION)
            .await
        {
            warn!("NGAP UE {amf}: releasing PDU session {psi} failed: {e}");
        }
        !closed
    }

    async fn on_ue_modification_request(
        &mut self,
        amf: u64,
        ran: u64,
        psi: u8,
        p: &sm::SmProcedure,
    ) -> bool {
        let refuse = {
            let Some(sec) = self.sec(amf) else {
                return true;
            };
            match sec.sessions.get(&psi) {
                None => Some((43, "pdu_session_modification_unknown")),
                Some(s) if s.releasing || s.modifying.is_some() => {
                    Some((101, "pdu_session_procedure_in_progress"))
                }
                Some(_) if sec.pending_sm.contains_key(&psi) => {
                    Some((101, "pdu_session_procedure_in_progress"))
                }
                Some(_) => {
                    sec.pending_sm.insert(
                        psi,
                        PendingSm {
                            pti: p.pti,
                            kind: SmAsk::Modification,
                        },
                    );
                    None
                }
            }
        };
        if let Some((cause, tag)) = refuse {
            Log::new(Some(&self.status_tx)).warn(format!(
                "NGAP UE {amf}: modification of PDU session {psi} refused before the model \
                 (decision={tag})"
            ));
            let reject = sm::modification_reject(psi, p.pti, cause);
            self.send_ue_nas(amf, ran, nas::dl_nas_transport_sm(psi, &reject))
                .await;
            return true;
        }
        let data = self.session_event_data(amf, ran, psi, p);
        let event = Event::new(&actions::NGAP_PDU_SESSION_MODIFICATION_EVENT, data);
        let event_id = event.event_type.id.clone();
        let outcome = self.call_llm_and_send(&event).await;
        let (closed, failure, tag) = match outcome {
            HandlerOutcome::Ran {
                ref pdu_answers,
                closed,
                ..
            } if pdu_answers.contains(&(amf, psi)) => return !closed,
            HandlerOutcome::Ran { closed, .. } => (closed, None, "model_silent"),
            HandlerOutcome::Failed(f) => (false, Some(f), "fail_closed_llm_error"),
            HandlerOutcome::NoPolicy => (false, None, "no_policy_configured"),
        };
        let cause = if failure.map(|f| f.is_overloaded()).unwrap_or(false) {
            sm::CAUSE_INSUFFICIENT_RESOURCES
        } else {
            sm::CAUSE_REQUEST_REJECTED_UNSPECIFIED
        };
        Log::new(Some(&self.status_tx)).warn(format!(
            "NGAP {event_id} produced no decision for UE {amf} PDU session {psi} \
             (decision={tag}); rejecting the modification with 5GSM {}",
            sm::cause_name(cause)
        ));
        let pti = self
            .sec(amf)
            .and_then(|s| s.pending_sm.remove(&psi))
            .map(|x| x.pti)
            .unwrap_or(p.pti);
        let reject = sm::modification_reject(psi, pti, cause);
        self.send_ue_nas(amf, ran, nas::dl_nas_transport_sm(psi, &reject))
            .await;
        !closed
    }

    /// What the model is shown about a UE's release or modification request.
    fn session_event_data(&self, amf: u64, ran: u64, psi: u8, p: &sm::SmProcedure) -> Value {
        let ue = self.ues.get(&amf);
        let sec = ue.and_then(|u| u.sec.as_deref());
        let s = sec.and_then(|x| x.sessions.get(&psi));
        json!({
            "amf_ue_ngap_id": amf,
            "ran_ue_ngap_id": ran,
            "supi": sec.map(|x| supi_label(&x.supi)),
            "pdu_session_id": psi,
            "pti": p.pti,
            "cause": p.cause.map(|c| json!({"value": c, "name": sm::cause_name(c)})),
            "requested_five_qi": p.flow_five_qi.map(|(_, q)| q),
            "optional_ies": p.optional_ies,
            "session": s.map(|s| json!({
                "pdu_session_type": s.ngap_type(),
                "address": amf::address_label(&s.address, None),
                "dnn": s.dnn,
                "s_nssai": s.s_nssai.to_json(),
                "five_qi": s.five_qi,
                "session_ambr_kbps": {"uplink": s.ambr_ul_kbps, "downlink": s.ambr_dl_kbps},
            })),
            "user_location": ue.map(|u| u.user_location.clone()),
            "transport": self.transport.label(),
        })
    }

    /// The UE a release, modification or paging decision names: by `amf_ue_ngap_id` when it is
    /// connected here, or by `supi`, connected here or idle.
    pub(super) fn resolve_target(&self, data: &Value) -> Result<Target, String> {
        if let Some(amf) = data.get("amf_ue_ngap_id").and_then(Value::as_u64) {
            return match self.ues.get(&amf) {
                Some(u) if u.sec.is_some() => Ok(Target::Connected(amf)),
                Some(_) => Err(format!("UE {amf} was not authenticated by this AMF")),
                None => Err(format!("UE {amf} is not connected on this association")),
            };
        }
        let supi = data
            .get("supi")
            .and_then(Value::as_str)
            .ok_or("give amf_ue_ngap_id (a connected UE) or supi")?;
        let want = subscribers::supi_digits(supi)?;
        if let Some((amf, _)) = self.ues.iter().find(|(_, u)| {
            u.sec
                .as_deref()
                .map(|s| s.supi == want && s.active)
                .unwrap_or(false)
        }) {
            return Ok(Target::Connected(*amf));
        }
        match self.core.idle_find_supi(&want) {
            Some(tmsi) => Ok(Target::Idle(tmsi)),
            None => Err(format!(
                "{supi} is neither connected on this association nor idle"
            )),
        }
    }

    /// The model's release and modification decisions.
    pub(super) async fn do_session_decision(
        &mut self,
        name: &str,
        data: &Value,
        pdu_answers: &mut Vec<(u64, u8)>,
    ) -> Result<Sent, String> {
        let psi = data["pdu_session_id"]
            .as_u64()
            .filter(|p| (1..=15).contains(p))
            .ok_or("pdu_session_id must be 1..15")? as u8;
        let amf = match self.resolve_target(data)? {
            Target::Connected(a) => a,
            Target::Idle(tmsi) => {
                if matches!(
                    name,
                    actions::PDU_SESSION_RELEASE_REJECT | actions::PDU_SESSION_MODIFICATION_REJECT
                ) {
                    return Err("an idle UE has no request waiting for an answer".into());
                }
                return self.queue_for_idle(tmsi, data.clone()).await;
            }
        };
        let ran = self
            .ues
            .get(&amf)
            .map(|u| u.ran_ue_ngap_id)
            .ok_or(format!("UE {amf} is unknown"))?;
        let sent = match name {
            actions::PDU_SESSION_RELEASE => {
                let cause = match data.get("cause").filter(|c| !c.is_null()) {
                    Some(c) => sm::parse_cause(c)?,
                    None => sm::CAUSE_REGULAR_DEACTIVATION,
                };
                self.do_release(amf, psi, cause).await?
            }
            actions::PDU_SESSION_MODIFICATION => self.do_modification(amf, psi, data).await?,
            actions::PDU_SESSION_RELEASE_REJECT | actions::PDU_SESSION_MODIFICATION_REJECT => {
                let cause = sm::parse_cause(data.get("cause").unwrap_or(&Value::Null))?;
                let release = name == actions::PDU_SESSION_RELEASE_REJECT;
                let pending = {
                    let sec = self.sec(amf).ok_or("no security context")?;
                    let matches = sec
                        .pending_sm
                        .get(&psi)
                        .map(|p| matches!(p.kind, SmAsk::Release) == release)
                        .unwrap_or(false);
                    if !matches {
                        return Err(format!(
                            "UE {amf} has no {} request for PDU session {psi} waiting",
                            if release { "release" } else { "modification" }
                        ));
                    }
                    sec.pending_sm.remove(&psi).map(|p| p.pti).unwrap_or(0)
                };
                let reject = if release {
                    sm::release_reject(psi, pending, cause)
                } else {
                    sm::modification_reject(psi, pending, cause)
                };
                info!(
                    "NGAP UE {amf}: {} of PDU session {psi} refused by the model with 5GSM {} \
                     (decision=model_reject)",
                    if release { "release" } else { "modification" },
                    sm::cause_name(cause)
                );
                self.send_ue_nas(amf, ran, nas::dl_nas_transport_sm(psi, &reject))
                    .await;
                Sent {
                    kind: PduKind::Initiating,
                    code: codec::PROC_DOWNLINK_NAS_TRANSPORT,
                    amf_ue_ngap_id: Some(amf),
                }
            }
            other => return Err(format!("unknown session decision {other}")),
        };
        pdu_answers.push((amf, psi));
        Ok(sent)
    }

    /// Release one session: the 5GSM Release Command inside a PDU Session Resource Release
    /// Command, and its uplink TEID freed in the user plane now.
    pub(super) async fn do_release(
        &mut self,
        amf: u64,
        psi: u8,
        cause: u8,
    ) -> Result<Sent, String> {
        let up = self.core.user_plane.clone();
        let ran = self
            .ues
            .get(&amf)
            .map(|u| u.ran_ue_ngap_id)
            .ok_or(format!("UE {amf} is unknown"))?;
        let sec = self.sec(amf).ok_or("no security context")?;
        if !sec.active || !matches!(sec.phase, Phase::Accepted | Phase::Registered) {
            return Err(format!("UE {amf} is not registered"));
        }
        let pti = match sec.pending_sm.get(&psi).map(|p| &p.kind) {
            Some(SmAsk::Release) => sec.pending_sm.remove(&psi).map(|p| p.pti).unwrap_or(0),
            _ => 0,
        };
        let label = supi_label(&sec.supi);
        let s = sec
            .sessions
            .get_mut(&psi)
            .filter(|s| !s.releasing)
            .ok_or(format!("UE {amf} has no PDU session {psi} to release"))?;
        s.releasing = true;
        s.modifying = None;
        let teid = s.ul_teid;
        if let Some(up) = &up {
            up.remove(teid);
        }
        let command = sm::release_command(psi, pti, cause);
        let plain = nas::dl_nas_transport_sm(psi, &command);
        let ctx = sec.ctx.as_mut().ok_or("no NAS security context")?;
        let nas_pdu = ctx.protect(&plain, security::SHT_INTEGRITY_CIPHERED);
        let pdu = codec::pdu_session_resource_release_command(
            amf,
            ran,
            Some(&nas_pdu),
            &[(psi, Cause::nas(codec::NAS_NORMAL_RELEASE))],
        )
        .map_err(|e| e.to_string())?;
        Log::new(Some(&self.status_tx)).info(format!(
            "NGAP UE {amf} {label}: PDU session {psi} release command ({}, 5GSM {}); uplink \
             TEID {teid:#010x} freed (decision=pdu_session_release_command)",
            if pti == 0 {
                "network-requested"
            } else {
                "UE-requested"
            },
            sm::cause_name(cause)
        ));
        self.send(pdu).await;
        Ok(Sent {
            kind: PduKind::Initiating,
            code: codec::PROC_PDU_SESSION_RESOURCE_RELEASE,
            amf_ue_ngap_id: Some(amf),
        })
    }

    /// Modify one session: the 5GSM Modification Command inside a PDU Session Resource Modify
    /// Request whose transfer carries the new AMBR and the flow's new 5QI. Applied to the
    /// session when the UE's Complete arrives.
    async fn do_modification(&mut self, amf: u64, psi: u8, data: &Value) -> Result<Sent, String> {
        let ambr = match data.get("session_ambr").filter(|v| !v.is_null()) {
            Some(a) => Some((
                a["uplink_kbps"]
                    .as_u64()
                    .ok_or("session_ambr.uplink_kbps is required")?,
                a["downlink_kbps"]
                    .as_u64()
                    .ok_or("session_ambr.downlink_kbps is required")?,
            )),
            None => None,
        };
        let five_qi = match data.get("five_qi").filter(|v| !v.is_null()) {
            Some(q) => Some(
                q.as_u64()
                    .filter(|q| (1..=255).contains(q))
                    .ok_or("five_qi must be 1..255")? as u8,
            ),
            None => None,
        };
        if ambr.is_none() && five_qi.is_none() {
            return Err("a modification changes session_ambr, five_qi or both".into());
        }
        let ran = self
            .ues
            .get(&amf)
            .map(|u| u.ran_ue_ngap_id)
            .ok_or(format!("UE {amf} is unknown"))?;
        let sec = self.sec(amf).ok_or("no security context")?;
        if !sec.active || !matches!(sec.phase, Phase::Accepted | Phase::Registered) {
            return Err(format!("UE {amf} is not registered"));
        }
        let pti = match sec.pending_sm.get(&psi).map(|p| &p.kind) {
            Some(SmAsk::Modification) => sec.pending_sm.remove(&psi).map(|p| p.pti).unwrap_or(0),
            _ => 0,
        };
        let label = supi_label(&sec.supi);
        let s = sec
            .sessions
            .get_mut(&psi)
            .filter(|s| !s.releasing && s.modifying.is_none())
            .ok_or(format!(
                "UE {amf} has no PDU session {psi} that can be modified now"
            ))?;
        let m = sm::Modification {
            ambr_uplink_kbps: ambr.map(|a| a.0),
            ambr_downlink_kbps: ambr.map(|a| a.1),
            flow_five_qi: five_qi.map(|q| (amf::DEFAULT_QFI, q)),
            cause: None,
        };
        let command = sm::modification_command(psi, pti, &m)?;
        let transfer = codec::encode_modify_request_transfer(&codec::ModifyRequestTransfer {
            ambr_dl_bps: ambr.map(|a| a.1.saturating_mul(1000).min(codec::MAX_BIT_RATE)),
            ambr_ul_bps: ambr.map(|a| a.0.saturating_mul(1000).min(codec::MAX_BIT_RATE)),
            qos_flows: five_qi
                .map(|q| {
                    vec![codec::QosFlow {
                        qfi: amf::DEFAULT_QFI,
                        five_qi: q,
                        arp_priority: amf::DEFAULT_ARP_PRIORITY,
                    }]
                })
                .unwrap_or_default(),
        })
        .map_err(|e| e.to_string())?;
        s.modifying = Some(m);
        let plain = nas::dl_nas_transport_sm(psi, &command);
        let ctx = sec.ctx.as_mut().ok_or("no NAS security context")?;
        let nas_pdu = ctx.protect(&plain, security::SHT_INTEGRITY_CIPHERED);
        let pdu = codec::pdu_session_resource_modify_request(
            amf,
            ran,
            &[codec::ModifyItem {
                pdu_session_id: psi,
                nas: Some(nas_pdu),
                transfer,
            }],
        )
        .map_err(|e| e.to_string())?;
        Log::new(Some(&self.status_tx)).info(format!(
            "NGAP UE {amf} {label}: PDU session {psi} modification command ({}) \
             (decision=pdu_session_modification_command)",
            if pti == 0 {
                "network-requested"
            } else {
                "UE-requested"
            }
        ));
        self.send(pdu).await;
        Ok(Sent {
            kind: PduKind::Initiating,
            code: codec::PROC_PDU_SESSION_RESOURCE_MODIFY,
            amf_ue_ngap_id: Some(amf),
        })
    }

    /// The gNB's PDU Session Resource Release Response.
    pub(super) fn on_release_response(&mut self, pdu: &codec::Pdu) -> bool {
        match codec::parse_pdu_session_resource_release_response(pdu) {
            Ok(r) => info!(
                "NGAP UE {}: the gNB released the resources of PDU sessions {:?}",
                r.amf_ue_ngap_id, r.released
            ),
            Err(e) => warn!(
                "NGAP PDU Session Resource Release Response from {} does not decode: {e}",
                self.remote_addr
            ),
        }
        true
    }

    /// The gNB's PDU Session Resource Modify Response.
    pub(super) fn on_modify_response(&mut self, pdu: &codec::Pdu) -> bool {
        match codec::parse_pdu_session_resource_modify_response(pdu) {
            Ok(o) => {
                for (psi, cause) in &o.failed {
                    Log::new(Some(&self.status_tx)).warn(format!(
                        "NGAP UE {}: the gNB could not modify PDU session {psi}: {}",
                        o.amf_ue_ngap_id,
                        cause.label()
                    ));
                }
                info!(
                    "NGAP UE {}: the gNB modified PDU sessions {:?}",
                    o.amf_ue_ngap_id,
                    o.modified.iter().map(|(p, _)| *p).collect::<Vec<_>>()
                );
            }
            Err(e) => warn!(
                "NGAP PDU Session Resource Modify Response from {} does not decode: {e}",
                self.remote_addr
            ),
        }
        true
    }

    /// Hold a decision for an idle UE and page it; it runs when the UE's Service Request brings
    /// it back.
    pub(super) async fn queue_for_idle(
        &mut self,
        tmsi: u32,
        action: Value,
    ) -> Result<Sent, String> {
        self.core.idle_queue(tmsi, action)?;
        info!("NGAP: a decision for idle UE 5G-TMSI {tmsi:#010x} was {QUEUED_FOR_IDLE}; paging it");
        self.page(tmsi).await
    }
}

/// Who a decision names.
pub(super) enum Target {
    Connected(u64),
    Idle(u32),
}
