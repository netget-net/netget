//! CM-IDLE and back (TS 23.502 4.2.6, 4.2.3.2-4.2.3.3; TS 24.501 5.6.1, 5.6.2; TS 38.413 8.3.3,
//! 8.5.1): a registered UE whose N2 context is released keeps its registration, its NAS security
//! context and its PDU sessions here, and comes back with a Service Request, on its own or
//! because it was paged.
//!
//! - **Going idle.** A UE Context Release Command for a *registered* UE — the model's
//!   `send_ue_context_release_command`, the inactivity timer (`ue_inactivity_timeout_secs`,
//!   cause radioNetwork/user-inactivity), or the gNB's own UE Context Release Request — ends,
//!   on the gNB's Release Complete, in the UE moving to the server-wide idle store keyed by its
//!   5G-TMSI. The user plane forgets the gNB's downlink tunnels; the uplink TEIDs stay reserved.
//!   NG Reset and a closed association do the same for registered UEs.
//! - **Service Request.** An Initial UE Message whose NAS is an integrity-protected Service
//!   Request naming a 5G-S-TMSI in the store is verified with the UE's own context (MAC, and a
//!   COUNT above every one accepted before), its NAS message container deciphered at that
//!   COUNT, and answered by Rust — no model call: the subscriber was admitted when it
//!   registered. The answer is an Initial Context Setup with K_gNB from the Service Request's
//!   uplink COUNT (TS 33.501 A.9), the protected Service Accept, and the sessions whose user
//!   plane comes back (those in the Uplink data status; every session when paged). A Service
//!   Request that does not verify is refused with Service Reject #9 and the idle context kept,
//!   so a forged one cannot evict the real UE (`decision=nas_integrity_failure`); one naming a
//!   5G-S-TMSI nobody holds is Service Reject #9 (`decision=service_request_unknown_ue`).
//! - **Paging.** The model's `send_paging` for an idle UE, or any release or modification
//!   decision addressed (by `supi`) to an idle UE — that decision is queued and runs once the
//!   UE is back — sends NGAP Paging with the UE's 5G-S-TMSI and its last tracking area.

use super::*;
use crate::utils::clock::Instant;
use amf::{supi_label, Phase, UeSec};
use std::time::Duration;

/// radioNetwork/user-inactivity (TS 38.413 9.3.1.2, index 20 of CauseRadioNetwork's root).
pub const RADIO_USER_INACTIVITY: u8 = 20;
/// Idle UEs one AMF keeps across its associations.
pub const MAX_IDLE_UES: usize = 4096;
/// Decisions held for one idle UE until it answers its paging.
pub const MAX_QUEUED_PER_UE: usize = 8;
/// How long a paged UE has to come back before its queued decisions are dropped.
pub const PAGING_TIMEOUT: Duration = Duration::from_secs(30);
/// How soon an idle UE may be paged again.
const PAGING_REPEAT: Duration = Duration::from_secs(5);

/// A registered UE with no N2 connection.
pub(super) struct IdleUe {
    pub(super) sec: Box<UeSec>,
    /// Where it was last: the tracking area it is paged in.
    pub(super) user_location: Value,
    /// Decisions that wait for it, in order.
    pub(super) queued: Vec<Value>,
    pub(super) paged_at: Option<Instant>,
}

impl Core {
    fn idle(&self) -> std::sync::MutexGuard<'_, HashMap<u32, IdleUe>> {
        self.idle.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Whether a 5G-TMSI belongs to an idle UE.
    pub(super) fn tmsi_in_use(&self, tmsi: u32) -> bool {
        self.idle().contains_key(&tmsi)
    }

    pub(super) fn idle_find_supi(&self, supi: &str) -> Option<u32> {
        self.idle()
            .iter()
            .find(|(_, u)| u.sec.supi == supi)
            .map(|(t, _)| *t)
    }

    fn idle_put(&self, tmsi: u32, ue: IdleUe) -> Result<(), String> {
        let mut idle = self.idle();
        if idle.len() >= MAX_IDLE_UES && !idle.contains_key(&tmsi) {
            return Err(format!("{MAX_IDLE_UES} idle UEs are already held"));
        }
        idle.insert(tmsi, ue);
        Ok(())
    }

    fn idle_take(&self, tmsi: u32) -> Option<IdleUe> {
        self.idle().remove(&tmsi)
    }

    pub(super) fn idle_queue(&self, tmsi: u32, action: Value) -> Result<(), String> {
        let mut idle = self.idle();
        let ue = idle.get_mut(&tmsi).ok_or("the UE is no longer idle")?;
        if ue.queued.len() >= MAX_QUEUED_PER_UE {
            return Err(format!(
                "{MAX_QUEUED_PER_UE} decisions already wait for this idle UE"
            ));
        }
        ue.queued.push(action);
        Ok(())
    }

    /// Paged UEs that never came back lose what waited for them.
    fn expire_paging(&self, status_tx: &mpsc::UnboundedSender<String>) {
        let mut idle = self.idle();
        for u in idle.values_mut() {
            if let Some(at) = u.paged_at {
                if at.elapsed() >= PAGING_TIMEOUT {
                    Log::new(Some(status_tx)).warn(format!(
                        "NGAP {}: no Service Request within {}s of paging; {} queued decision(s) \
                         dropped (decision=paging_unanswered)",
                        supi_label(&u.sec.supi),
                        PAGING_TIMEOUT.as_secs(),
                        u.queued.len()
                    ));
                    u.paged_at = None;
                    u.queued.clear();
                }
            }
        }
    }
}

impl Session {
    /// A UE leaving this association: a registered one goes idle, keeping its context and
    /// sessions; anything else is dropped with its user plane.
    pub(super) fn retire_ue(&mut self, amf: u64, ue: Ue) {
        let registered = ue
            .sec
            .as_deref()
            .map(|s| s.active && matches!(s.phase, Phase::Registered) && s.s_tmsi.is_some())
            .unwrap_or(false);
        if !registered {
            self.release_user_plane(&ue);
            return;
        }
        let Ue {
            sec, user_location, ..
        } = ue;
        let Some(mut sec) = sec else {
            return;
        };
        let up = self.core.user_plane.clone();
        // What was mid-procedure ends with the connection: a release in flight completes
        // locally, a modification in flight is abandoned, requests wait for nothing now.
        let released: Vec<u8> = sec
            .sessions
            .iter()
            .filter(|(_, s)| s.releasing)
            .map(|(p, _)| *p)
            .collect();
        for psi in released {
            if let (Some(s), Some(up)) = (sec.sessions.remove(&psi), &up) {
                up.remove(s.ul_teid);
            }
        }
        for s in sec.sessions.values_mut() {
            s.modifying = None;
            s.established = false;
            if let Some(up) = &up {
                up.clear_downlink(s.ul_teid);
            }
        }
        sec.pending_sm.clear();
        let Some((_, _, tmsi)) = sec.s_tmsi else {
            return;
        };
        let label = sec.label();
        let sessions: Vec<u8> = sec.sessions.keys().copied().collect();
        match self.core.idle_put(
            tmsi,
            IdleUe {
                sec,
                user_location,
                queued: Vec::new(),
                paged_at: None,
            },
        ) {
            Ok(()) => Log::new(Some(&self.status_tx)).info(format!(
                "NGAP UE {amf} {label}: CM-IDLE, 5G-TMSI {tmsi:#010x}, PDU sessions {sessions:?} \
                 kept (decision=ue_idle)"
            )),
            Err(e) => {
                // Nowhere to keep it: its sessions go, and its next Service Request is refused.
                Log::new(Some(&self.status_tx)).warn(format!(
                    "NGAP UE {amf} {label}: cannot be kept idle ({e}); its context is dropped"
                ));
            }
        }
    }

    /// A Service Request in an Initial UE Message. `false` leaves the UE to the model (no
    /// credentials on this AMF).
    pub(super) async fn try_service_request(&mut self, amf: u64) -> bool {
        let Some(ue) = self.ues.get(&amf) else {
            return true;
        };
        let raw = ue.initial_nas_bytes.clone();
        let ran = ue.ran_ue_ngap_id;
        let sht = raw.get(1).map(|h| h & 0x0F).unwrap_or(0);
        // The cleartext part of the message: plain, or after a 7-octet security header.
        let outer = match sht {
            security::SHT_PLAIN => raw.as_slice(),
            security::SHT_INTEGRITY => raw.get(7..).unwrap_or_default(),
            _ => &[],
        };
        let tmsi = match nas::parse_service_request(outer) {
            Ok(r) => r.tmsi,
            Err(e) => {
                Log::new(Some(&self.status_tx)).warn(format!(
                    "NGAP UE {amf}: Service Request does not decode: {e} (decision=nas_malformed)"
                ));
                self.refuse_service(amf, ran).await;
                return true;
            }
        };
        let Some(mut idle) = self.core.idle_take(tmsi) else {
            Log::new(Some(&self.status_tx)).warn(format!(
                "NGAP UE {amf}: Service Request names 5G-TMSI {tmsi:#010x}, which this AMF holds \
                 no context for (decision=service_request_unknown_ue); Service Reject #9"
            ));
            self.refuse_service(amf, ran).await;
            return true;
        };
        let label = idle.sec.label();
        // TS 24.501 4.4.6: an initial NAS message from a UE with a security context is
        // integrity protected. Its MAC and COUNT are checked with the UE's own context; a
        // failure leaves that context, and the idle UE, as they were.
        let verified = if sht == security::SHT_INTEGRITY {
            match idle.sec.ctx.as_mut() {
                Some(ctx) => ctx.unprotect(&raw).map_err(|e| e.to_string()),
                None => Err("no security context".into()),
            }
        } else {
            Err(format!(
                "security header type {sht}, not integrity protected"
            ))
        };
        let (plain, count) = match verified {
            Ok((p, c, _)) => (p, c),
            Err(e) => {
                let _ = self.core.idle_put(tmsi, idle);
                Log::new(Some(&self.status_tx)).warn(format!(
                    "NGAP UE {amf} {label}: Service Request refused: {e} \
                     (decision=nas_integrity_failure); Service Reject #9, the idle context kept"
                ));
                self.refuse_service(amf, ran).await;
                return true;
            }
        };
        let mut request = match nas::parse_service_request(&plain) {
            Ok(r) => r,
            Err(e) => {
                let _ = self.core.idle_put(tmsi, idle);
                warn!("NGAP UE {amf}: verified Service Request does not decode: {e}");
                self.refuse_service(amf, ran).await;
                return true;
            }
        };
        // The non-cleartext IEs ride ciphered in the NAS message container, at the COUNT of
        // the message that carries it.
        if let (Some(mut container), Some(ctx)) =
            (request.nas_container.clone(), idle.sec.ctx.as_ref())
        {
            ctx.cipher_at(count, security::UPLINK, &mut container);
            match nas::parse_service_request(&container) {
                Ok(inner) if inner.tmsi == request.tmsi => request = inner,
                _ => warn!(
                    "NGAP UE {amf} {label}: the Service Request's NAS message container does not \
                     decipher to a Service Request; using the cleartext IEs"
                ),
            }
        }
        let paged = idle.paged_at.is_some();
        let queued = std::mem::take(&mut idle.queued);
        let up = self.core.user_plane.clone();
        let mut sec = idle.sec;
        sec.active = true;
        sec.k_gnb = sec.ctx.as_ref().map(|c| c.k_gnb());
        sec.last_activity = Instant::now();
        // Sessions the UE no longer holds are released locally (TS 24.501 5.6.1.4.1).
        if let Some(status) = request.pdu_session_status {
            let ue_has = nas::psi_list(status);
            let gone: Vec<u8> = sec
                .sessions
                .keys()
                .copied()
                .filter(|p| !ue_has.contains(p))
                .collect();
            for psi in gone {
                if let (Some(s), Some(up)) = (sec.sessions.remove(&psi), &up) {
                    up.remove(s.ul_teid);
                }
                info!("NGAP UE {amf} {label}: PDU session {psi} released locally: the UE no longer holds it");
            }
        }
        let reactivate: Vec<u8> = match request.uplink_data_status {
            Some(bits) => nas::psi_list(bits)
                .into_iter()
                .filter(|p| sec.sessions.contains_key(p))
                .collect(),
            None if request.service_type == nas::SERVICE_TYPE_MOBILE_TERMINATED
                || request.service_type == nas::SERVICE_TYPE_DATA =>
            {
                sec.sessions.keys().copied().collect()
            }
            None => Vec::new(),
        };
        let held = nas::psi_bits(sec.sessions.keys().copied());
        let accept = nas::service_accept(&nas::ServiceAccept {
            pdu_session_status: Some(held),
            reactivation_result: None,
        });
        let Some(ctx) = sec.ctx.as_mut() else {
            return true;
        };
        let nas_pdu = ctx.protect(&accept, security::SHT_INTEGRITY_CIPHERED);
        let mut items = Vec::new();
        if let Some(up) = &up {
            for psi in &reactivate {
                let Some(s) = sec.sessions.get(psi) else {
                    continue;
                };
                match amf::setup_transfer(s, up.advertised()) {
                    Ok(transfer) => items.push(codec::SetupItem {
                        pdu_session_id: *psi,
                        nas: None,
                        s_nssai: s.s_nssai.to_json(),
                        transfer,
                    }),
                    Err(e) => warn!("NGAP UE {amf}: PDU session {psi} transfer: {e}"),
                }
            }
        }
        let (Some(guami), Some(k_gnb)) = (self.guami.clone(), sec.k_gnb) else {
            let _ = self.core.idle_put(
                tmsi,
                IdleUe {
                    sec,
                    user_location: idle.user_location,
                    queued,
                    paged_at: None,
                },
            );
            self.refuse_service(amf, ran).await;
            return true;
        };
        let ics = codec::initial_context_setup_request(&codec::InitialContext {
            amf_ue_ngap_id: amf,
            ran_ue_ngap_id: ran,
            guami,
            allowed_nssai: sec.allowed_nssai.clone(),
            ue_security_capabilities: nas::ngap_security_capabilities(&sec.caps),
            security_key: k_gnb,
            ue_ambr: None,
            nas: Some(nas_pdu),
            pdu_sessions: items,
        });
        Log::new(Some(&self.status_tx)).info(format!(
            "NGAP UE {amf} {label}: Service Request ({}{}) verified at uplink COUNT {count}; \
             Service Accept, user plane of PDU sessions {reactivate:?} reactivated \
             (decision=service_accept)",
            nas::service_type_name(request.service_type),
            if paged { ", answering paging" } else { "" }
        ));
        if let Some(ue) = self.ues.get_mut(&amf) {
            ue.sec = Some(sec);
        }
        self.send_encoded("Initial Context Setup Request (Service Accept)", ics)
            .await;
        // What waited for the UE runs now, addressed to its new AMF UE NGAP ID.
        for mut action in queued {
            if let Some(o) = action.as_object_mut() {
                o.remove("supi");
                o.insert("amf_ue_ngap_id".into(), json!(amf));
            }
            info!("NGAP UE {amf} {label}: running a decision queued while it was idle");
            self.run_injected(action).await;
        }
        true
    }

    async fn refuse_service(&mut self, amf: u64, ran: u64) {
        self.send_encoded(
            "Downlink NAS Transport (Service Reject)",
            codec::downlink_nas_transport(
                amf,
                ran,
                &nas::service_reject(nas::CAUSE_UE_IDENTITY_CANNOT_BE_DERIVED),
            ),
        )
        .await;
        self.send_encoded(
            "UE Context Release Command",
            codec::ue_context_release_command(amf, Some(ran), &Cause::nas(codec::NAS_UNSPECIFIED)),
        )
        .await;
    }

    /// `send_ue_context_release_command` naming a subscriber rather than an AMF UE NGAP ID.
    pub(super) async fn do_context_release(&mut self, data: &Value) -> Result<Sent, String> {
        let amf = match self.resolve_target(data)? {
            sessions::Target::Connected(a) => a,
            sessions::Target::Idle(_) => return Err("the UE is already idle".into()),
        };
        let cause = match data.get("cause").filter(|c| !c.is_null()) {
            Some(c) => Cause::from_json(c).map_err(|e| e.to_string())?,
            None => Cause::nas(codec::NAS_NORMAL_RELEASE),
        };
        let ran = self.ues.get(&amf).map(|u| u.ran_ue_ngap_id);
        self.send_encoded(
            "UE Context Release Command",
            codec::ue_context_release_command(amf, ran, &cause),
        )
        .await;
        if let Some(ue) = self.ues.get_mut(&amf) {
            ue.releasing = true;
        }
        Ok(Sent {
            kind: PduKind::Initiating,
            code: codec::PROC_UE_CONTEXT_RELEASE,
            amf_ue_ngap_id: Some(amf),
        })
    }

    /// The model's `send_paging`: the UE must be idle.
    pub(super) async fn do_paging(&mut self, data: &Value) -> Result<Sent, String> {
        match self.resolve_target(data)? {
            sessions::Target::Idle(tmsi) => self.page(tmsi).await,
            sessions::Target::Connected(amf) => Err(format!(
                "the UE is connected (AMF UE NGAP ID {amf}); only an idle UE is paged"
            )),
        }
    }

    /// NGAP Paging for an idle UE on this association, at most every [`PAGING_REPEAT`].
    pub(super) async fn page(&mut self, tmsi: u32) -> Result<Sent, String> {
        let (paging, label) = {
            let mut idle = self.core.idle();
            let ue = idle.get_mut(&tmsi).ok_or("the UE is no longer idle")?;
            let (set, pointer, _) = ue.sec.s_tmsi.ok_or("the UE has no 5G-S-TMSI")?;
            let tai = &ue.user_location["tai"];
            let plmn = codec::Plmn::from_json(&tai["plmn"]).map_err(|e| e.to_string())?;
            let tac = tai["tac"].as_u64().unwrap_or(1) as u32;
            if ue
                .paged_at
                .map(|t| t.elapsed() < PAGING_REPEAT)
                .unwrap_or(false)
            {
                return Ok(Sent {
                    kind: PduKind::Initiating,
                    code: codec::PROC_PAGING,
                    amf_ue_ngap_id: None,
                });
            }
            ue.paged_at = Some(Instant::now());
            (
                codec::Paging {
                    amf_set_id: set,
                    amf_pointer: pointer,
                    tmsi,
                    tais: vec![(plmn, tac)],
                    paging_drx: None,
                },
                ue.sec.label(),
            )
        };
        let pdu = codec::paging(&paging).map_err(|e| e.to_string())?;
        Log::new(Some(&self.status_tx)).info(format!(
            "NGAP {label}: Paging 5G-S-TMSI {}/{}/{tmsi:#010x} in TAC {} (decision=paging)",
            paging.amf_set_id, paging.amf_pointer, paging.tais[0].1
        ));
        self.send(pdu).await;
        Ok(Sent {
            kind: PduKind::Initiating,
            code: codec::PROC_PAGING,
            amf_ue_ngap_id: None,
        })
    }

    /// Once a second: the inactivity timer, and paging that went unanswered.
    pub(super) async fn on_tick(&mut self) {
        self.core.expire_paging(&self.status_tx);
        let Some(limit) = self.core.inactivity else {
            return;
        };
        let up = self.core.user_plane.clone();
        let mut idle_now = Vec::new();
        for (amf, ue) in &self.ues {
            let Some(sec) = ue.sec.as_deref() else {
                continue;
            };
            if ue.releasing || !sec.active || !matches!(sec.phase, Phase::Registered) {
                continue;
            }
            if !sec.pending_sm.is_empty()
                || sec
                    .sessions
                    .values()
                    .any(|s| s.releasing || s.modifying.is_some())
            {
                continue;
            }
            let mut last = sec.last_activity;
            if let Some(up) = &up {
                for s in sec.sessions.values() {
                    if let Some(t) = up.last_uplink(s.ul_teid) {
                        last = last.max(t);
                    }
                }
            }
            if last.elapsed() >= limit {
                idle_now.push((*amf, ue.ran_ue_ngap_id, sec.label()));
            }
        }
        for (amf, ran, label) in idle_now {
            if let Some(ue) = self.ues.get_mut(&amf) {
                ue.releasing = true;
            }
            Log::new(Some(&self.status_tx)).info(format!(
                "NGAP UE {amf} {label}: no NAS or user-plane traffic for {}s; UE Context Release \
                 Command radioNetwork/user-inactivity (decision=ue_inactivity_release)",
                limit.as_secs()
            ));
            self.send_encoded(
                "UE Context Release Command",
                codec::ue_context_release_command(
                    amf,
                    Some(ran),
                    &Cause::radio(RADIO_USER_INACTIVITY),
                ),
            )
            .await;
        }
    }
}
