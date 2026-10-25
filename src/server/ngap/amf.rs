//! The AMF's side of a UE whose subscriber it holds credentials for: 5G-AKA (TS 33.501 6.1.3.2),
//! the security mode procedure (TS 24.501 5.4.2), registration with an Initial Context Setup
//! carrying K_gNB (TS 33.501 Annex A.9), PDU session establishment through the NAS transport
//! (TS 24.501 6.4.1) with a PDU Session Resource Setup and a user-plane tunnel, and UE-originating
//! deregistration. PDU session release and modification are in [`super::sessions`]; CM-IDLE,
//! Service Request and paging in [`super::idle`].
//!
//! Every NAS message here is Rust's. The model is asked once per decision — whether to admit the
//! authenticated subscriber, what to do with each PDU session request, release request and
//! modification request — and its answers are carried out by [`Session::apply_decision`], which
//! refuses an answer that does not fit the UE's state. Once a UE's NAS security is active, a plain message from it is discarded, and so is one
//! whose MAC does not verify or whose COUNT was already accepted; each is logged with its
//! `decision=` tag and never reaches the model.

use super::*;
use security::{AkaVector, NasContext};
use std::net::Ipv4Addr;
use subscribers::Identity;

/// SQN resynchronisations allowed per registration before the UE is rejected.
pub const MAX_RESYNCS: u8 = 1;
/// PDU sessions (established or being decided) per UE.
pub const MAX_PDU_SESSIONS_PER_UE: usize = 8;
/// QoS flow identifier of the one flow each session gets.
pub const DEFAULT_QFI: u8 = 1;
/// 5QI when the model names none: 9, the default non-GBR bearer for internet traffic.
pub const DEFAULT_FIVE_QI: u8 = 9;
/// ARP priority level of the session's flow.
pub const DEFAULT_ARP_PRIORITY: u8 = 8;
/// Session-AMBR when the model names none, each direction, in kbps.
pub const DEFAULT_SESSION_AMBR_KBPS: u64 = 1_000_000;
/// DNN when neither the UE nor the model names one.
pub const DEFAULT_DNN: &str = "internet";

pub(super) enum Phase {
    Authenticating {
        vector: AkaVector,
    },
    SecurityMode,
    /// Asking the model whether to register the authenticated subscriber.
    Deciding,
    /// Registration Accept sent in the Initial Context Setup; Registration Complete is next.
    Accepted,
    Registered,
    /// Rejected, released or deregistered: waiting for the gNB's release complete.
    Ending,
}

impl Phase {
    fn name(&self) -> &'static str {
        match self {
            Phase::Authenticating { .. } => "authenticating",
            Phase::SecurityMode => "security_mode",
            Phase::Deciding => "deciding",
            Phase::Accepted => "accepted",
            Phase::Registered => "registered",
            Phase::Ending => "ending",
        }
    }
}

pub(super) struct PendingPdu {
    pti: u8,
    dnn: Option<String>,
    s_nssai: Option<nas::Snssai>,
    pdu_session_type: Option<u8>,
}

/// One accepted PDU session, with what it takes to set its user plane up again after the UE was
/// idle.
pub(super) struct PduSession {
    pub(super) ul_teid: u32,
    pub(super) address: sm::PduAddress,
    pub(super) established: bool,
    pub(super) s_nssai: nas::Snssai,
    pub(super) dnn: String,
    pub(super) five_qi: u8,
    pub(super) ambr_ul_kbps: u64,
    pub(super) ambr_dl_kbps: u64,
    /// A release command was sent; the UE's Release Complete removes the session. Its TEID is
    /// already gone from the user plane.
    pub(super) releasing: bool,
    /// A modification command waiting for the UE's Complete or Command Reject.
    pub(super) modifying: Option<sm::Modification>,
}

impl PduSession {
    /// NGAP's name for the session's type.
    pub(super) fn ngap_type(&self) -> &'static str {
        match self.address {
            sm::PduAddress::V4(_) => "ipv4",
            sm::PduAddress::V6 { .. } => "ipv6",
            sm::PduAddress::V4V6 { .. } => "ipv4v6",
        }
    }
}

/// A UE's 5GSM request waiting for the model: a release or a modification.
pub(super) enum SmAsk {
    Release,
    Modification,
}

pub(super) struct PendingSm {
    pub(super) pti: u8,
    pub(super) kind: SmAsk,
}

/// One UE's security procedure state. Holds K_AMF and the NAS keys inside its [`NasContext`];
/// none of it is formatted anywhere.
pub(super) struct UeSec {
    pub(super) supi: String,
    protection_scheme: u8,
    snn: String,
    request: nas::RegistrationRequest,
    pub(super) caps: Vec<u8>,
    pub(super) phase: Phase,
    ngksi: u8,
    resyncs: u8,
    pub(super) ctx: Option<NasContext>,
    /// True once Security Mode Complete verified: from then on only verified NAS is processed.
    pub(super) active: bool,
    imeisv: Option<Value>,
    /// K_gNB, derived when Security Mode Complete verified, from its uplink NAS COUNT
    /// (TS 33.501 6.8.1.2, Annex A.9).
    pub(super) k_gnb: Option<security::Key256>,
    pub(super) allowed_nssai: Vec<Value>,
    pending_pdu: BTreeMap<u8, PendingPdu>,
    pub(super) pending_sm: BTreeMap<u8, PendingSm>,
    pub(super) sessions: BTreeMap<u8, PduSession>,
    /// The 5G-S-TMSI allocated with the Registration Accept: (AMF Set ID, AMF Pointer, 5G-TMSI).
    pub(super) s_tmsi: Option<(u16, u8, u32)>,
    /// The last NAS message from the UE, for the inactivity timer.
    pub(super) last_activity: crate::utils::clock::Instant,
}

impl UeSec {
    pub(super) fn label(&self) -> String {
        supi_label(&self.supi)
    }
}

pub(super) fn supi_label(supi: &str) -> String {
    format!("imsi-{supi}")
}

impl Session {
    fn tai_plmn(&self, amf: u64) -> Option<codec::Plmn> {
        let ue = self.ues.get(&amf)?;
        codec::Plmn::from_json(&ue.user_location["tai"]["plmn"]).ok()
    }

    /// Start 5G-AKA from the UE's initial Registration Request, when its identity resolves to a
    /// subscriber with credentials. `false` leaves the UE to the model.
    pub(super) async fn try_start_aka(&mut self, amf: u64) -> bool {
        if self.core.credentials_empty() {
            return false;
        }
        let Some(req) = self
            .ues
            .get(&amf)
            .and_then(|u| nas::parse_registration_request(&u.initial_nas_bytes).ok())
        else {
            return false;
        };
        self.start_aka(amf, req).await
    }

    /// A UE that opened with an identity this AMF cannot use answered the model's Identity
    /// Request with a SUCI: authenticate from it, keeping the rest of its Registration Request.
    pub(super) async fn try_start_aka_from_identity(&mut self, amf: u64, nas_pdu: &[u8]) -> bool {
        if self.core.credentials_empty() {
            return false;
        }
        // Identity Response: EPD, header, type, then the mobile identity LV-E.
        let Some(id) = nas_pdu.get(3..5).and_then(|l| {
            let n = u16::from_be_bytes([l[0], l[1]]) as usize;
            nas_pdu.get(5..5 + n).map(<[u8]>::to_vec)
        }) else {
            return false;
        };
        let Some(mut req) = self
            .ues
            .get(&amf)
            .and_then(|u| nas::parse_registration_request(&u.initial_nas_bytes).ok())
        else {
            return false;
        };
        req.mobile_identity = id;
        self.start_aka(amf, req).await
    }

    async fn start_aka(&mut self, amf: u64, req: nas::RegistrationRequest) -> bool {
        let identity = self.core.credentials().resolve(&req.mobile_identity);
        let (supi, protection_scheme) = match identity {
            Identity::Known {
                supi,
                protection_scheme,
            } => (supi, protection_scheme),
            Identity::Unknown { supi } => {
                Log::new(Some(&self.status_tx)).info(format!(
                    "NGAP UE {amf}: {} has no credentials on this AMF; the model decides \
                     (decision=no_credentials)",
                    supi_label(&supi)
                ));
                return false;
            }
            Identity::Unreadable(why) => {
                info!("NGAP UE {amf}: identity not usable for 5G-AKA ({why}); the model decides");
                return false;
            }
        };
        let Some(ran) = self.ues.get(&amf).map(|u| u.ran_ue_ngap_id) else {
            return true;
        };
        // The integrity algorithm is the first of the operator's preference the UE offers
        // (TS 24.501 9.11.3.54: bit 8 of the second octet is 5G-IA0, bit 7 5G-IA1, ...).
        let caps = req.ue_security_capability.clone().unwrap_or_default();
        if select_algorithm(&self.core.integrity, caps.get(1).copied()).is_none() {
            Log::new(Some(&self.status_tx)).warn(format!(
                "NGAP UE {amf} {}: offers none of this AMF's integrity algorithms ({}) \
                 (decision=ue_security_capabilities_mismatch); rejecting #23",
                supi_label(&supi),
                self.core
                    .integrity
                    .iter()
                    .map(|a| security::integrity_name(*a))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
            self.send_ue_nas(amf, ran, nas::registration_reject(23))
                .await;
            self.release_ue(amf, Cause::nas(codec::NAS_UNSPECIFIED))
                .await;
            return true;
        }
        let plmn = self
            .tai_plmn(amf)
            .or_else(|| nas::parse_suci(&req.mobile_identity).map(|s| s.plmn));
        let Some(plmn) = plmn else {
            return false;
        };
        let snn = security::serving_network_name(&plmn.mcc, &plmn.mnc);
        let Some(vector) = self.core.credentials().next_vector(&supi, &snn) else {
            return false;
        };
        // A key set identifier the UE is not already using (7 means it holds none).
        let ngksi = if req.ngksi == 0 { 1 } else { 0 };
        let auth = nas::authentication_request(ngksi, &[0, 0], &vector.rand, &vector.autn);
        Log::new(Some(&self.status_tx)).info(format!(
            "NGAP UE {amf} {}: 5G-AKA started (SUCI protection scheme {protection_scheme}), \
             serving network {snn}",
            supi_label(&supi)
        ));
        if let Some(ue) = self.ues.get_mut(&amf) {
            ue.sec = Some(Box::new(UeSec {
                supi,
                protection_scheme,
                snn,
                request: req,
                caps,
                phase: Phase::Authenticating { vector },
                ngksi,
                resyncs: 0,
                ctx: None,
                active: false,
                imeisv: None,
                k_gnb: None,
                allowed_nssai: Vec::new(),
                pending_pdu: BTreeMap::new(),
                pending_sm: BTreeMap::new(),
                sessions: BTreeMap::new(),
                s_tmsi: None,
                last_activity: crate::utils::clock::Instant::now(),
            }));
        }
        self.send_ue_nas(amf, ran, auth).await;
        true
    }

    pub(super) fn sec(&mut self, amf: u64) -> Option<&mut UeSec> {
        self.ues.get_mut(&amf).and_then(|u| u.sec.as_deref_mut())
    }

    /// Put a 5GMM message on the wire to a UE: protected (header type 2) once its NAS security
    /// is active, plain before.
    pub(super) async fn send_ue_nas(&mut self, amf: u64, ran: u64, plain: Vec<u8>) {
        let pdu = match self.sec(amf) {
            Some(sec) if sec.active => match sec.ctx.as_mut() {
                Some(ctx) => ctx.protect(&plain, security::SHT_INTEGRITY_CIPHERED),
                None => plain,
            },
            _ => plain,
        };
        self.send_encoded(
            "Downlink NAS Transport",
            codec::downlink_nas_transport(amf, ran, &pdu),
        )
        .await;
    }

    pub(super) async fn release_ue(&mut self, amf: u64, cause: Cause) {
        let Some(ran) = self.ues.get(&amf).map(|u| u.ran_ue_ngap_id) else {
            return;
        };
        if let Some(sec) = self.sec(amf) {
            sec.phase = Phase::Ending;
        }
        self.send_encoded(
            "UE Context Release Command",
            codec::ue_context_release_command(amf, Some(ran), &cause),
        )
        .await;
    }

    /// Drop a released UE's user-plane tunnels: it deregistered, was rejected, or was reset.
    pub(super) fn release_user_plane(&self, ue: &Ue) {
        if let (Some(sec), Some(up)) = (&ue.sec, &self.core.user_plane) {
            for s in sec.sessions.values() {
                up.remove(s.ul_teid);
            }
        }
    }

    /// The model writes plain 5GMM; a Downlink NAS Transport to a UE whose security is active is
    /// re-encoded with the NAS protected, so the model's reject or status reaches the UE as one
    /// it accepts. Anything else passes unchanged.
    pub(super) fn protect_model_downlink(&mut self, bytes: Vec<u8>) -> Vec<u8> {
        let Ok(p) = codec::decode_pdu(&bytes) else {
            return bytes;
        };
        if p.kind != PduKind::Initiating || p.procedure_code != codec::PROC_DOWNLINK_NAS_TRANSPORT {
            return bytes;
        }
        let Ok(t) = codec::parse_nas_transport(&p) else {
            return bytes;
        };
        if t.nas.get(1).map(|h| h & 0x0F) != Some(0) {
            return bytes;
        }
        let Some(sec) = self.sec(t.amf_ue_ngap_id) else {
            return bytes;
        };
        if !sec.active {
            return bytes;
        }
        let Some(ctx) = sec.ctx.as_mut() else {
            return bytes;
        };
        let protected = ctx.protect(&t.nas, security::SHT_INTEGRITY_CIPHERED);
        codec::downlink_nas_transport(t.amf_ue_ngap_id, t.ran_ue_ngap_id, &protected)
            .unwrap_or(bytes)
    }

    /// Everything a UE in the security procedure sends.
    pub(super) async fn on_secured_ue_nas(&mut self, amf: u64, raw: &[u8]) -> bool {
        let Some(ran) = self.ues.get(&amf).map(|u| u.ran_ue_ngap_id) else {
            return true;
        };
        if raw.first() != Some(&nas::EPD_5GMM) || raw.len() < 3 {
            Log::new(Some(&self.status_tx)).warn(format!(
                "NGAP UE {amf}: uplink NAS is not 5GMM; discarded (decision=nas_malformed)"
            ));
            return true;
        }
        let sht = raw[1] & 0x0F;
        let (plain, protected) = if sht == security::SHT_PLAIN {
            (raw.to_vec(), false)
        } else {
            let result = match self.sec(amf).and_then(|s| s.ctx.as_mut()) {
                Some(ctx) => ctx.unprotect(raw),
                None => Err(security::UnprotectError::HeaderType(sht)),
            };
            match result {
                Ok((p, _, _)) => (p, true),
                Err(e) => {
                    Log::new(Some(&self.status_tx)).warn(format!(
                        "NGAP UE {amf}: protected uplink NAS discarded: {e} (decision={})",
                        e.decision()
                    ));
                    return true;
                }
            }
        };
        let active = self.sec(amf).map(|s| s.active).unwrap_or(false);
        if active && !protected {
            Log::new(Some(&self.status_tx)).warn(format!(
                "NGAP UE {amf}: unprotected NAS after security was established; discarded \
                 (decision=nas_unprotected_refused)"
            ));
            return true;
        }
        let Some(&t) = plain.get(2) else {
            return true;
        };
        if plain.first() != Some(&nas::EPD_5GMM) || plain.get(1).map(|h| h & 0x0F) != Some(0) {
            Log::new(Some(&self.status_tx)).warn(format!(
                "NGAP UE {amf}: a protected message inside a protected message; discarded \
                 (decision=nas_malformed)"
            ));
            return true;
        }
        debug!(
            "NGAP UE {amf}: {} ({})",
            nas::message_name(t).unwrap_or("?"),
            if protected { "verified" } else { "plain" }
        );
        // What the inactivity timer measures: a verified message from the UE.
        if protected {
            if let Some(sec) = self.sec(amf) {
                sec.last_activity = crate::utils::clock::Instant::now();
            }
        }
        match t {
            nas::AUTHENTICATION_RESPONSE => self.on_auth_response(amf, ran, &plain).await,
            nas::AUTHENTICATION_FAILURE => self.on_auth_failure(amf, ran, &plain).await,
            nas::SECURITY_MODE_COMPLETE if protected => self.on_smc_complete(amf, &plain).await,
            nas::SECURITY_MODE_REJECT => {
                Log::new(Some(&self.status_tx)).warn(format!(
                    "NGAP UE {amf}: Security Mode Reject {} (decision=security_mode_rejected)",
                    nas::decode(&plain)["cause"]
                ));
                self.release_ue(amf, Cause::nas(codec::NAS_UNSPECIFIED))
                    .await;
                true
            }
            nas::REGISTRATION_COMPLETE if active => {
                if let Some(sec) = self.sec(amf) {
                    if matches!(sec.phase, Phase::Accepted) {
                        sec.phase = Phase::Registered;
                    }
                    let supi = supi_label(&sec.supi);
                    Log::new(Some(&self.status_tx)).info(format!(
                        "NGAP UE {amf} {supi}: registered (decision=ue_registered)"
                    ));
                }
                true
            }
            nas::UL_NAS_TRANSPORT if active => self.on_ul_nas_transport(amf, ran, &plain).await,
            nas::DEREGISTRATION_REQUEST_UE_ORIGINATING => {
                self.on_deregistration(amf, ran, &plain).await
            }
            nas::FIVEGMM_STATUS => {
                Log::new(Some(&self.status_tx)).warn(format!(
                    "NGAP UE {amf}: 5GMM Status {}",
                    nas::decode(&plain)["cause"]
                ));
                true
            }
            other => {
                Log::new(Some(&self.status_tx)).warn(format!(
                    "NGAP UE {amf}: {} is not handled in this state; answering 5GMM Status #98 \
                     (decision=nas_not_compatible)",
                    nas::message_name(other).unwrap_or("an unknown 5GMM message")
                ));
                self.send_ue_nas(amf, ran, nas::status(98)).await;
                true
            }
        }
    }

    async fn reject_authentication(&mut self, amf: u64, ran: u64) {
        self.send_ue_nas(amf, ran, nas::authentication_reject())
            .await;
        self.release_ue(amf, Cause::nas(1)).await;
    }

    async fn on_auth_response(&mut self, amf: u64, ran: u64, plain: &[u8]) -> bool {
        let res = nas::parse_authentication_response(plain).ok().flatten();
        let integrity = self.core.integrity.clone();
        let ciphering = self.core.ciphering.clone();
        let status_tx = self.status_tx.clone();
        let Some(sec) = self.sec(amf) else {
            return true;
        };
        let Phase::Authenticating { vector } = &sec.phase else {
            debug!("NGAP UE {amf}: Authentication Response outside authentication; ignored");
            return true;
        };
        // The SEAF compares HRES* with HXRES*, the AUSF RES* with XRES* (TS 33.501 6.1.3.2).
        let ok = match res {
            Some(r) => {
                security::constant_time_eq(
                    &security::hres_star(&vector.rand, &r),
                    &vector.hxres_star,
                ) && security::constant_time_eq(&r, &vector.xres_star)
            }
            None => false,
        };
        let supi = supi_label(&sec.supi);
        if !ok {
            Log::new(Some(&status_tx)).warn(format!(
                "NGAP UE {amf} {supi}: RES* does not match XRES* (decision=auth_res_mismatch); \
                 Authentication Reject"
            ));
            self.reject_authentication(amf, ran).await;
            return true;
        }
        let k_seaf = security::k_seaf(&vector.k_ausf, &sec.snn);
        let k_amf = security::k_amf(&k_seaf, &sec.supi, &[0, 0]);
        // Checked when 5G-AKA started: the UE offers one of the integrity algorithms.
        let ia = select_algorithm(&integrity, sec.caps.get(1).copied()).unwrap_or(security::NIA2);
        // NEA0 is mandatory for every UE, so ciphering always falls back to it.
        let ea = select_algorithm(&ciphering, sec.caps.first().copied()).unwrap_or(security::NEA0);
        let mut ctx = NasContext::new(sec.ngksi, k_amf, ia, ea, security::DOWNLINK);
        let smc = nas::security_mode_command(ia, ea, sec.ngksi, &sec.caps, true, true);
        let protected = ctx.protect(&smc, security::SHT_INTEGRITY_NEW_CONTEXT);
        sec.ctx = Some(ctx);
        sec.phase = Phase::SecurityMode;
        Log::new(Some(&status_tx)).info(format!(
            "NGAP UE {amf} {supi}: 5G-AKA succeeded; Security Mode Command ({}, {})",
            security::integrity_name(ia),
            security::ciphering_name(ea)
        ));
        self.send_encoded(
            "Downlink NAS Transport (Security Mode Command)",
            codec::downlink_nas_transport(amf, ran, &protected),
        )
        .await;
        true
    }

    async fn on_auth_failure(&mut self, amf: u64, ran: u64, plain: &[u8]) -> bool {
        let (cause, auts) = match nas::parse_authentication_failure(plain) {
            Ok(x) => x,
            Err(_) => (nas::CAUSE_PROTOCOL_ERROR_UNSPECIFIED, None),
        };
        let core = self.core.clone();
        let status_tx = self.status_tx.clone();
        let Some(sec) = self.sec(amf) else {
            return true;
        };
        let Phase::Authenticating { vector } = &sec.phase else {
            return true;
        };
        let supi = sec.supi.clone();
        let rand = vector.rand;
        let label = supi_label(&supi);
        if cause == 21 {
            if sec.resyncs >= MAX_RESYNCS {
                Log::new(Some(&status_tx)).warn(format!(
                    "NGAP UE {amf} {label}: synch failure after {MAX_RESYNCS} resynchronisation \
                     (decision=auth_resync_exhausted); Authentication Reject"
                ));
                self.reject_authentication(amf, ran).await;
                return true;
            }
            let ok = auts
                .as_deref()
                .map(|a| core.credentials().resync(&supi, &rand, a))
                .unwrap_or(false);
            if !ok {
                Log::new(Some(&status_tx)).warn(format!(
                    "NGAP UE {amf} {label}: synch failure with an AUTS whose MAC-S does not \
                     verify (decision=auth_auts_invalid); Authentication Reject"
                ));
                self.reject_authentication(amf, ran).await;
                return true;
            }
            let snn = sec.snn.clone();
            let Some(vector) = core.credentials().next_vector(&supi, &snn) else {
                return true;
            };
            sec.resyncs += 1;
            let auth = nas::authentication_request(sec.ngksi, &[0, 0], &vector.rand, &vector.autn);
            sec.phase = Phase::Authenticating { vector };
            Log::new(Some(&status_tx)).info(format!(
                "NGAP UE {amf} {label}: SQN resynchronised from AUTS (decision=auth_resync); \
                 new Authentication Request"
            ));
            self.send_ue_nas(amf, ran, auth).await;
            return true;
        }
        let tag = match cause {
            20 => "auth_mac_failure",
            26 => "auth_non_5g_unacceptable",
            71 => "auth_ngksi_in_use",
            _ => "auth_failure",
        };
        Log::new(Some(&status_tx)).warn(format!(
            "NGAP UE {amf} {label}: Authentication Failure {} — the UE did not accept this \
             network's AUTN (decision={tag}); Authentication Reject",
            nas::cause_name(cause)
        ));
        self.reject_authentication(amf, ran).await;
        true
    }

    async fn on_smc_complete(&mut self, amf: u64, plain: &[u8]) -> bool {
        let complete = match nas::parse_security_mode_complete(plain) {
            Ok(c) => c,
            Err(e) => {
                Log::new(Some(&self.status_tx)).warn(format!(
                    "NGAP UE {amf}: Security Mode Complete does not decode: {e} \
                     (decision=nas_malformed)"
                ));
                return true;
            }
        };
        let Some(sec) = self.sec(amf) else {
            return true;
        };
        if !matches!(sec.phase, Phase::SecurityMode) {
            return true;
        }
        sec.active = true;
        sec.k_gnb = sec.ctx.as_ref().map(|c| c.k_gnb());
        sec.imeisv = complete.imeisv;
        // The complete Registration Request the UE retransmits under protection (RINMR).
        if let Some(r) = complete
            .nas_container
            .as_deref()
            .and_then(|c| nas::parse_registration_request(c).ok())
        {
            if r.ue_security_capability.is_some()
                && r.ue_security_capability != Some(sec.caps.clone())
            {
                warn!(
                    "NGAP UE {amf}: the retransmitted Registration Request names different \
                     security capabilities than the plain one"
                );
            }
            if !r.requested_nssai.is_empty() {
                sec.request.requested_nssai = r.requested_nssai;
            }
        }
        sec.phase = Phase::Deciding;
        self.ask_registration(amf).await
    }

    /// The model's one registration decision for an authenticated subscriber.
    async fn ask_registration(&mut self, amf: u64) -> bool {
        let Some(ue) = self.ues.get(&amf) else {
            return true;
        };
        let Some(sec) = ue.sec.as_deref() else {
            return true;
        };
        let identity = nas::decode_mobile_identity(&sec.request.mobile_identity);
        let data = json!({
            "amf_ue_ngap_id": amf,
            "ran_ue_ngap_id": ue.ran_ue_ngap_id,
            "supi": supi_label(&sec.supi),
            "suci": {
                "plmn": identity.get("plmn"),
                "routing_indicator": identity.get("routing_indicator"),
                "protection_scheme": identity.get("protection_scheme"),
                "home_network_public_key_id": identity.get("home_network_public_key_id"),
            },
            "authenticated": true,
            "authentication": "5g_aka",
            "registration_type": match sec.request.registration_type {
                1 => "initial", 2 => "mobility_updating", 3 => "periodic_updating", 4 => "emergency", _ => "other"
            },
            "requested_nssai": sec.request.requested_nssai.iter().map(nas::Snssai::to_json).collect::<Vec<_>>(),
            "imeisv": sec.imeisv,
            "nas_security": {
                "integrity": security::integrity_name(sec.ctx.as_ref().map(|c| c.ia).unwrap_or(0)),
                "ciphering": security::ciphering_name(sec.ctx.as_ref().map(|c| c.ea).unwrap_or(0)),
            },
            "user_location": ue.user_location,
            "plmn_support": self.plmn_support,
            "transport": self.transport.label(),
        });
        let _ = sec.protection_scheme;
        let event = Event::new(&actions::NGAP_REGISTRATION_EVENT, data);
        let event_id = event.event_type.id.clone();
        let outcome = self.call_llm_and_send(&event).await;
        let accepted = self
            .sec(amf)
            .map(|s| !matches!(s.phase, Phase::Deciding | Phase::Ending))
            .unwrap_or(false);
        match outcome {
            HandlerOutcome::Ran {
                ref sent, closed, ..
            } if sent.iter().any(|s| s.amf_ue_ngap_id == Some(amf)) => {
                if !accepted {
                    info!("NGAP {event_id} decision=model_reject amf_ue_ngap_id={amf}");
                    if let Some(sec) = self.sec(amf) {
                        sec.phase = Phase::Ending;
                    }
                }
                !closed
            }
            HandlerOutcome::Ran { closed, .. } => {
                Log::new(Some(&self.status_tx)).warn(format!(
                    "NGAP {event_id} produced no answer for UE {amf} (decision=model_silent); \
                     rejecting"
                ));
                self.fail_closed_registration(amf, None).await;
                !closed
            }
            HandlerOutcome::Failed(f) => {
                Log::new(Some(&self.status_tx)).warn(format!(
                    "NGAP {event_id} could not be evaluated for UE {amf} \
                     (decision=fail_closed_llm_error, {}); rejecting",
                    failure_category(f)
                ));
                self.fail_closed_registration(amf, Some(f)).await;
                true
            }
            HandlerOutcome::NoPolicy => {
                Log::new(Some(&self.status_tx)).warn(format!(
                    "NGAP {event_id} for UE {amf} (decision=no_policy_configured): nothing \
                     decides who may register; rejecting"
                ));
                self.fail_closed_registration(amf, None).await;
                true
            }
        }
    }

    async fn fail_closed_registration(&mut self, amf: u64, failure: Option<WireFailure>) {
        let Some(ran) = self.ues.get(&amf).map(|u| u.ran_ue_ngap_id) else {
            return;
        };
        let overloaded = failure.map(|f| f.is_overloaded()).unwrap_or(false);
        let cause = if overloaded {
            nas::CAUSE_CONGESTION
        } else {
            nas::CAUSE_PROTOCOL_ERROR_UNSPECIFIED
        };
        self.send_ue_nas(amf, ran, nas::registration_reject(cause))
            .await;
        self.release_ue(
            amf,
            if overloaded {
                Cause::misc(codec::MISC_CONTROL_PROCESSING_OVERLOAD)
            } else {
                Cause::nas(codec::NAS_UNSPECIFIED)
            },
        )
        .await;
    }

    async fn on_deregistration(&mut self, amf: u64, ran: u64, plain: &[u8]) -> bool {
        let switch_off = nas::parse_deregistration_request(plain)
            .map(|(s, _)| s)
            .unwrap_or(false);
        let label = self
            .sec(amf)
            .map(|s| supi_label(&s.supi))
            .unwrap_or_default();
        if !switch_off {
            self.send_ue_nas(amf, ran, nas::deregistration_accept_ue_originating())
                .await;
        }
        Log::new(Some(&self.status_tx)).info(format!(
            "NGAP UE {amf} {label}: deregistered{} (decision=ue_deregistered)",
            if switch_off { " (switch-off)" } else { "" }
        ));
        // NAS cause value 2: deregister.
        self.release_ue(amf, Cause::nas(2)).await;
        true
    }

    async fn on_ul_nas_transport(&mut self, amf: u64, ran: u64, plain: &[u8]) -> bool {
        let t = match nas::parse_ul_nas_transport(plain) {
            Ok(t) => t,
            Err(e) => {
                Log::new(Some(&self.status_tx)).warn(format!(
                    "NGAP UE {amf}: UL NAS Transport does not decode: {e} (decision=nas_malformed)"
                ));
                self.send_ue_nas(amf, ran, nas::status(96)).await;
                return true;
            }
        };
        if t.payload_type != nas::PAYLOAD_N1_SM {
            Log::new(Some(&self.status_tx)).warn(format!(
                "NGAP UE {amf}: UL NAS Transport with payload type {} is not handled",
                t.payload_type
            ));
            return true;
        }
        let Some((psi_header, pti, mt)) = sm::header(&t.payload) else {
            return true;
        };
        match mt {
            sm::PDU_SESSION_RELEASE_REQUEST
            | sm::PDU_SESSION_RELEASE_COMPLETE
            | sm::PDU_SESSION_MODIFICATION_REQUEST
            | sm::PDU_SESSION_MODIFICATION_COMPLETE
            | sm::PDU_SESSION_MODIFICATION_COMMAND_REJECT
            | sm::FIVEGSM_STATUS => {
                let psi = t.pdu_session_id.unwrap_or(psi_header);
                return self.on_session_procedure(amf, ran, psi, &t.payload).await;
            }
            _ => {}
        }
        if mt != sm::PDU_SESSION_ESTABLISHMENT_REQUEST {
            Log::new(Some(&self.status_tx)).warn(format!(
                "NGAP UE {amf}: 5GSM {} is not built here; answering 5GSM Status #97",
                sm::message_name(mt).unwrap_or("message")
            ));
            let status = vec![sm::EPD_5GSM, psi_header, pti, sm::FIVEGSM_STATUS, 97];
            self.send_ue_nas(amf, ran, nas::dl_nas_transport_sm(psi_header, &status))
                .await;
            return true;
        }
        let psi = t.pdu_session_id.unwrap_or(psi_header);
        let req = match sm::parse_establishment_request(&t.payload) {
            Ok(r) => r,
            Err(e) => {
                warn!("NGAP UE {amf}: PDU Session Establishment Request: {e}");
                self.send_pdu_reject(amf, ran, psi, pti, 96).await;
                return true;
            }
        };
        let refuse = {
            let Some(sec) = self.sec(amf) else {
                return true;
            };
            if !(1..=15).contains(&psi) || sec.sessions.contains_key(&psi) {
                Some((43, "pdu_session_id_invalid_or_in_use"))
            } else if sec.sessions.len() + sec.pending_pdu.len() >= MAX_PDU_SESSIONS_PER_UE {
                Some((26, "pdu_session_cap"))
            } else {
                sec.pending_pdu.insert(
                    psi,
                    PendingPdu {
                        pti,
                        dnn: t.dnn.clone(),
                        s_nssai: t.s_nssai,
                        pdu_session_type: req.pdu_session_type,
                    },
                );
                None
            }
        };
        if let Some((cause, tag)) = refuse {
            Log::new(Some(&self.status_tx)).warn(format!(
                "NGAP UE {amf}: PDU session {psi} refused before the model (decision={tag})"
            ));
            self.send_pdu_reject(amf, ran, psi, pti, cause).await;
            return true;
        }
        self.ask_pdu_session(amf, ran, psi, &t, &req).await
    }

    pub(super) async fn send_pdu_reject(&mut self, amf: u64, ran: u64, psi: u8, pti: u8, cause: u8) {
        let sm = sm::establishment_reject(psi, pti, cause);
        self.send_ue_nas(amf, ran, nas::dl_nas_transport_sm(psi, &sm))
            .await;
    }

    async fn ask_pdu_session(
        &mut self,
        amf: u64,
        ran: u64,
        psi: u8,
        t: &nas::NasTransportSm,
        req: &sm::EstablishmentRequest,
    ) -> bool {
        let (supi, allowed) = match self.sec(amf) {
            Some(s) => (supi_label(&s.supi), s.allowed_nssai.clone()),
            None => return true,
        };
        let data = json!({
            "amf_ue_ngap_id": amf,
            "ran_ue_ngap_id": ran,
            "supi": supi,
            "pdu_session_id": psi,
            "pti": req.pti,
            "request_type": match t.request_type { Some(1) => "initial_request", Some(2) => "existing_pdu_session", Some(3) => "initial_emergency_request", Some(_) => "other", None => "not_given" },
            "dnn": t.dnn,
            "s_nssai": t.s_nssai.map(|s| s.to_json()),
            "pdu_session_type": req.pdu_session_type.map(sm::pdu_session_type_name),
            "ssc_mode": req.ssc_mode,
            "allowed_nssai": allowed,
            "user_plane_available": self.core.user_plane.is_some(),
            "transport": self.transport.label(),
        });
        let event = Event::new(&actions::NGAP_PDU_SESSION_EVENT, data);
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
             (decision={tag}); rejecting with 5GSM {}",
            sm::cause_name(cause)
        ));
        let pti = self
            .sec(amf)
            .and_then(|s| s.pending_pdu.remove(&psi))
            .map(|p| p.pti)
            .unwrap_or(req.pti);
        self.send_pdu_reject(amf, ran, psi, pti, cause).await;
        !closed
    }

    /// Carry out one of the model's stateful decisions. `None` when it was refused (logged).
    pub(super) async fn apply_decision(
        &mut self,
        name: &str,
        data: &Value,
        pdu_answers: &mut Vec<(u64, u8)>,
    ) -> Option<Sent> {
        let result = match name {
            actions::REGISTRATION_ACCEPT => self.do_registration_accept(data).await,
            actions::PDU_SESSION_ACCEPT => self.do_pdu_accept(data, pdu_answers).await,
            actions::PDU_SESSION_REJECT => self.do_pdu_reject(data, pdu_answers).await,
            actions::PDU_SESSION_RELEASE
            | actions::PDU_SESSION_RELEASE_REJECT
            | actions::PDU_SESSION_MODIFICATION
            | actions::PDU_SESSION_MODIFICATION_REJECT => {
                self.do_session_decision(name, data, pdu_answers).await
            }
            actions::PAGING => self.do_paging(data).await,
            actions::UE_CONTEXT_RELEASE => self.do_context_release(data).await,
            other => Err(format!("unknown decision {other}")),
        };
        match result {
            Ok(s) => Some(s),
            Err(e) => {
                Log::new(Some(&self.status_tx)).warn(format!(
                    "NGAP {name} refused: {e} (decision=refused_decision)"
                ));
                self.last_refusal = Some(e);
                None
            }
        }
    }

    async fn do_registration_accept(&mut self, data: &Value) -> Result<Sent, String> {
        let amf = data["amf_ue_ngap_id"]
            .as_u64()
            .ok_or("amf_ue_ngap_id is required")?;
        let guami = self
            .guami
            .clone()
            .ok_or("this association has no GUAMI (NG Setup has not succeeded)")?;
        let plmn = codec::Plmn::from_json(&guami["plmn"]).map_err(|e| e.to_string())?;
        let ue = self
            .ues
            .get_mut(&amf)
            .ok_or(format!("UE {amf} is unknown"))?;
        let ran = ue.ran_ue_ngap_id;
        let tai_plmn = codec::Plmn::from_json(&ue.user_location["tai"]["plmn"])
            .unwrap_or_else(|_| plmn.clone());
        let ue_tac = ue.user_location["tai"]["tac"].as_u64().unwrap_or(1) as u32;
        let sec = ue
            .sec
            .as_deref_mut()
            .ok_or(format!("UE {amf} was not authenticated by this AMF"))?;
        if !sec.active || !matches!(sec.phase, Phase::Deciding) {
            return Err(format!(
                "UE {amf} is not awaiting a registration decision (state {})",
                sec.phase.name()
            ));
        }
        let allowed = data["allowed_nssai"]
            .as_array()
            .ok_or("allowed_nssai must be a list")?;
        let allowed_nssai: Vec<nas::Snssai> = allowed
            .iter()
            .map(nas::Snssai::from_json)
            .collect::<Result<_, _>>()?;
        let tacs: Vec<u32> = match data.get("tac_list").and_then(Value::as_array) {
            Some(l) => l
                .iter()
                .map(|t| {
                    t.as_u64()
                        .filter(|x| *x <= 0xFF_FFFF)
                        .map(|x| x as u32)
                        .ok_or("tac_list entries are 24-bit numbers")
                })
                .collect::<Result<_, _>>()?,
            None => vec![ue_tac],
        };
        let tmsi = match data.get("tmsi").and_then(Value::as_u64) {
            Some(t) if t <= u32::MAX as u64 => t as u32,
            Some(_) => return Err("tmsi is 32 bits".into()),
            None => loop {
                let t: u32 = rand::random();
                if t != 0 && t != u32::MAX && !self.core.tmsi_in_use(t) {
                    break t;
                }
            },
        };
        if self.core.tmsi_in_use(tmsi) {
            return Err(format!(
                "5G-TMSI {tmsi:#010x} is already allocated to an idle UE"
            ));
        }
        let guti = nas::guti_octets(
            &plmn,
            guami["amf_region_id"].as_u64().unwrap_or(0) as u8,
            guami["amf_set_id"].as_u64().unwrap_or(0) as u16,
            guami["amf_pointer"].as_u64().unwrap_or(0) as u8,
            tmsi,
        );
        let accept = nas::registration_accept(&nas::RegistrationAccept {
            guti,
            tai_plmn,
            tacs,
            allowed_nssai: allowed_nssai.clone(),
            t3512: None,
        })?;
        let ue_ambr = match data.get("ue_ambr") {
            Some(a) if !a.is_null() => Some((
                a["downlink_kbps"].as_u64().ok_or("ue_ambr.downlink_kbps")? * 1000,
                a["uplink_kbps"].as_u64().ok_or("ue_ambr.uplink_kbps")? * 1000,
            )),
            _ => None,
        };
        let caps = nas::ngap_security_capabilities(&sec.caps);
        let ctx = sec.ctx.as_mut().ok_or("no NAS security context")?;
        let nas_pdu = ctx.protect(&accept, security::SHT_INTEGRITY_CIPHERED);
        let k_gnb = sec
            .k_gnb
            .ok_or("no K_gNB: Security Mode Complete never verified")?;
        let allowed_json: Vec<Value> = allowed_nssai.iter().map(nas::Snssai::to_json).collect();
        let s_tmsi = (
            guami["amf_set_id"].as_u64().unwrap_or(0) as u16,
            guami["amf_pointer"].as_u64().unwrap_or(0) as u8,
            tmsi,
        );
        let ics = codec::initial_context_setup_request(&codec::InitialContext {
            amf_ue_ngap_id: amf,
            ran_ue_ngap_id: ran,
            guami,
            allowed_nssai: allowed_json.clone(),
            ue_security_capabilities: caps,
            security_key: k_gnb,
            ue_ambr,
            nas: Some(nas_pdu),
            pdu_sessions: Vec::new(),
        })
        .map_err(|e| e.to_string())?;
        sec.phase = Phase::Accepted;
        sec.allowed_nssai = allowed_json;
        sec.s_tmsi = Some(s_tmsi);
        let supi = supi_label(&sec.supi);
        Log::new(Some(&self.status_tx)).info(format!(
            "NGAP UE {amf} {supi}: Registration Accept (5G-TMSI {tmsi:08x}) in Initial Context \
             Setup"
        ));
        self.send(ics).await;
        Ok(Sent {
            kind: PduKind::Initiating,
            code: codec::PROC_INITIAL_CONTEXT_SETUP,
            amf_ue_ngap_id: Some(amf),
        })
    }

    async fn do_pdu_accept(
        &mut self,
        data: &Value,
        pdu_answers: &mut Vec<(u64, u8)>,
    ) -> Result<Sent, String> {
        let amf = data["amf_ue_ngap_id"]
            .as_u64()
            .ok_or("amf_ue_ngap_id is required")?;
        let psi = data["pdu_session_id"]
            .as_u64()
            .filter(|p| (1..=15).contains(p))
            .ok_or("pdu_session_id must be 1..15")? as u8;
        let answers = parse_answering_addresses(data)?;
        let five_qi = data
            .get("five_qi")
            .and_then(Value::as_u64)
            .unwrap_or(DEFAULT_FIVE_QI as u64);
        if five_qi == 0 || five_qi > 255 {
            return Err("five_qi must be 1..255".into());
        }
        let ambr_ul = data["session_ambr"]["uplink_kbps"]
            .as_u64()
            .unwrap_or(DEFAULT_SESSION_AMBR_KBPS);
        let ambr_dl = data["session_ambr"]["downlink_kbps"]
            .as_u64()
            .unwrap_or(DEFAULT_SESSION_AMBR_KBPS);
        let up = self.core.user_plane.clone();
        let ue = self
            .ues
            .get_mut(&amf)
            .ok_or(format!("UE {amf} is unknown"))?;
        let ran = ue.ran_ue_ngap_id;
        let sec = ue
            .sec
            .as_deref_mut()
            .ok_or(format!("UE {amf} was not authenticated by this AMF"))?;
        if !sec.active || !matches!(sec.phase, Phase::Accepted | Phase::Registered) {
            return Err(format!("UE {amf} is not registered"));
        }
        let requested_type = sec
            .pending_pdu
            .get(&psi)
            .ok_or(format!(
                "UE {amf} has no PDU session {psi} waiting for a decision"
            ))?
            .pdu_session_type;
        // The address is checked before the pending request is consumed, so a refused decision
        // leaves the request for the fail-closed answer.
        let (address, ipv6_prefix) = session_address(data, requested_type)?;
        let pending = sec.pending_pdu.remove(&psi).ok_or(format!(
            "UE {amf} has no PDU session {psi} waiting for a decision"
        ))?;
        let supi = sec.supi.clone();
        let allowed_first = sec
            .allowed_nssai
            .first()
            .and_then(|s| nas::Snssai::from_json(s).ok());
        let reject = |cause: u8, sec: &mut UeSec| -> Vec<u8> {
            let sm = sm::establishment_reject(psi, pending.pti, cause);
            let plain = nas::dl_nas_transport_sm(psi, &sm);
            match sec.ctx.as_mut() {
                Some(ctx) => ctx.protect(&plain, security::SHT_INTEGRITY_CIPHERED),
                None => plain,
            }
        };
        let Some(up) = up else {
            let nas_pdu = reject(sm::CAUSE_INSUFFICIENT_RESOURCES, sec);
            pdu_answers.push((amf, psi));
            Log::new(Some(&self.status_tx)).warn(format!(
                "NGAP UE {amf}: the model accepted PDU session {psi} but this AMF has no user \
                 plane (set user_plane_address); rejecting #26 (decision=no_user_plane)"
            ));
            self.send_encoded(
                "Downlink NAS Transport",
                codec::downlink_nas_transport(amf, ran, &nas_pdu),
            )
            .await;
            return Ok(Sent {
                kind: PduKind::Initiating,
                code: codec::PROC_DOWNLINK_NAS_TRANSPORT,
                amf_ue_ngap_id: Some(amf),
            });
        };
        let dnn = data
            .get("dnn")
            .and_then(Value::as_str)
            .map(str::to_string)
            .or(pending.dnn.clone())
            .unwrap_or_else(|| DEFAULT_DNN.to_string());
        let s_nssai = match data.get("s_nssai") {
            Some(v) if !v.is_null() => nas::Snssai::from_json(v)?,
            _ => pending
                .s_nssai
                .or(allowed_first)
                .ok_or("no S-NSSAI: give s_nssai")?,
        };
        let teid = match up.add(upf::UpSession {
            supi: supi_label(&supi),
            pdu_session_id: psi,
            ue_ip: address.ipv4(),
            ue_ipv6: match (ipv6_prefix, address.iid()) {
                (Some(p), Some(i)) => Some((p, i)),
                _ => None,
            },
            qfi: DEFAULT_QFI,
            downlink: None,
            answers: answers.clone(),
            last_uplink: None,
        }) {
            Ok(t) => t,
            Err(e) => {
                let nas_pdu = reject(sm::CAUSE_INSUFFICIENT_RESOURCES, sec);
                pdu_answers.push((amf, psi));
                Log::new(Some(&self.status_tx)).warn(format!(
                    "NGAP UE {amf}: PDU session {psi} refused by the user plane: {e}; rejecting \
                     #26 (decision=up_refused)"
                ));
                self.send_encoded(
                    "Downlink NAS Transport",
                    codec::downlink_nas_transport(amf, ran, &nas_pdu),
                )
                .await;
                return Ok(Sent {
                    kind: PduKind::Initiating,
                    code: codec::PROC_DOWNLINK_NAS_TRANSPORT,
                    amf_ue_ngap_id: Some(amf),
                });
            }
        };
        let session = PduSession {
            ul_teid: teid,
            address,
            established: false,
            s_nssai,
            dnn: dnn.clone(),
            five_qi: five_qi as u8,
            ambr_ul_kbps: ambr_ul,
            ambr_dl_kbps: ambr_dl,
            releasing: false,
            modifying: None,
        };
        let accept = match sm::establishment_accept(&sm::Accept {
            psi,
            pti: pending.pti,
            ssc_mode: 1,
            qfi: DEFAULT_QFI,
            five_qi: five_qi as u8,
            ambr_uplink_kbps: ambr_ul,
            ambr_downlink_kbps: ambr_dl,
            address,
            s_nssai,
            dnn: dnn.clone(),
        }) {
            Ok(a) => a,
            Err(e) => {
                up.remove(teid);
                return Err(e);
            }
        };
        let transfer = setup_transfer(&session, up.advertised()).map_err(|e| {
            up.remove(teid);
            e
        })?;
        let plain = nas::dl_nas_transport_sm(psi, &accept);
        let ctx = sec.ctx.as_mut().ok_or("no NAS security context")?;
        let nas_pdu = ctx.protect(&plain, security::SHT_INTEGRITY_CIPHERED);
        let pdu = codec::pdu_session_resource_setup_request(
            amf,
            ran,
            &[codec::SetupItem {
                pdu_session_id: psi,
                nas: Some(nas_pdu),
                s_nssai: s_nssai.to_json(),
                transfer,
            }],
            None,
        )
        .map_err(|e| {
            up.remove(teid);
            e.to_string()
        })?;
        let shown = address_label(&address, ipv6_prefix.as_ref());
        sec.sessions.insert(psi, session);
        pdu_answers.push((amf, psi));
        Log::new(Some(&self.status_tx)).info(format!(
            "NGAP UE {amf} {}: PDU session {psi} accepted ({shown}, dnn {dnn}, uplink TEID \
             {teid:#010x} at {})",
            supi_label(&supi),
            up.advertised()
        ));
        self.send(pdu).await;
        Ok(Sent {
            kind: PduKind::Initiating,
            code: codec::PROC_PDU_SESSION_RESOURCE_SETUP,
            amf_ue_ngap_id: Some(amf),
        })
    }

    async fn do_pdu_reject(
        &mut self,
        data: &Value,
        pdu_answers: &mut Vec<(u64, u8)>,
    ) -> Result<Sent, String> {
        let amf = data["amf_ue_ngap_id"]
            .as_u64()
            .ok_or("amf_ue_ngap_id is required")?;
        let psi = data["pdu_session_id"]
            .as_u64()
            .filter(|p| (1..=15).contains(p))
            .ok_or("pdu_session_id must be 1..15")? as u8;
        let cause = sm::parse_cause(data.get("cause").unwrap_or(&Value::Null))?;
        let ran = self
            .ues
            .get(&amf)
            .map(|u| u.ran_ue_ngap_id)
            .ok_or(format!("UE {amf} is unknown"))?;
        let pending = self
            .sec(amf)
            .ok_or(format!("UE {amf} was not authenticated by this AMF"))?
            .pending_pdu
            .remove(&psi)
            .ok_or(format!(
                "UE {amf} has no PDU session {psi} waiting for a decision"
            ))?;
        info!(
            "NGAP UE {amf}: PDU session {psi} rejected by the model with 5GSM {} \
             (decision=model_reject)",
            sm::cause_name(cause)
        );
        self.send_pdu_reject(amf, ran, psi, pending.pti, cause)
            .await;
        pdu_answers.push((amf, psi));
        Ok(Sent {
            kind: PduKind::Initiating,
            code: codec::PROC_DOWNLINK_NAS_TRANSPORT,
            amf_ue_ngap_id: Some(amf),
        })
    }

    pub(super) async fn on_initial_context_setup_answer(&mut self, pdu: &codec::Pdu) -> bool {
        if pdu.kind == PduKind::Successful {
            // The answer may carry the downlink tunnels of sessions set up with the context (a
            // Service Request reactivating its user plane).
            match codec::parse_initial_context_setup_response(pdu) {
                Ok(outcome) => {
                    info!(
                        "NGAP UE {}: Initial Context Setup complete",
                        outcome.amf_ue_ngap_id
                    );
                    self.record_setup_outcome(&outcome);
                }
                Err(e) => warn!(
                    "NGAP Initial Context Setup Response from {} does not decode: {e}",
                    self.remote_addr
                ),
            }
            return true;
        }
        let amf = pdu
            .ie(codec::IE_AMF_UE_NGAP_ID)
            .and_then(|ie| codec::decode_amf_ue_ngap_id(ie).ok());
        let Some(amf) = amf else {
            return true;
        };
        let cause = pdu
            .ie(codec::IE_CAUSE)
            .and_then(|ie| codec::decode_cause(ie).ok())
            .map(|c| c.label())
            .unwrap_or_default();
        Log::new(Some(&self.status_tx)).warn(format!(
            "NGAP UE {amf}: Initial Context Setup failed ({cause}); releasing"
        ));
        self.release_ue(amf, Cause::nas(codec::NAS_UNSPECIFIED))
            .await;
        true
    }

    pub(super) async fn on_pdu_session_setup_response(&mut self, pdu: &codec::Pdu) -> bool {
        match codec::parse_pdu_session_resource_setup_response(pdu) {
            Ok(o) => self.record_setup_outcome(&o),
            Err(e) => {
                Log::new(Some(&self.status_tx)).warn(format!(
                    "NGAP PDU Session Resource Setup Response from {} does not decode: {e}",
                    self.remote_addr
                ));
            }
        }
        true
    }

    /// The gNB's downlink tunnels go to the user plane; a session it could not set up is dropped
    /// with its uplink TEID.
    fn record_setup_outcome(&mut self, outcome: &codec::SetupOutcome) {
        let amf = outcome.amf_ue_ngap_id;
        let up = self.core.user_plane.clone();
        let status_tx = self.status_tx.clone();
        let Some(sec) = self.sec(amf) else {
            return;
        };
        let label = supi_label(&sec.supi);
        for (psi, t) in &outcome.established {
            let Some(s) = sec.sessions.get_mut(psi) else {
                continue;
            };
            if let Some(up) = &up {
                up.set_downlink(s.ul_teid, t.dl_tunnel.address, t.dl_tunnel.teid);
            }
            s.established = true;
            Log::new(Some(&status_tx)).info(format!(
                "NGAP UE {amf} {label}: PDU session {psi} established, {} reachable through \
                 the gNB at {} TEID {:#010x} (decision=pdu_session_established)",
                address_label(&s.address, None),
                t.dl_tunnel.address,
                t.dl_tunnel.teid
            ));
        }
        for (psi, cause) in &outcome.failed {
            if let Some(s) = sec.sessions.remove(psi) {
                if let Some(up) = &up {
                    up.remove(s.ul_teid);
                }
            }
            Log::new(Some(&status_tx)).warn(format!(
                "NGAP UE {amf} {label}: the gNB could not set up PDU session {psi}: {}",
                cause.label()
            ));
        }
    }

    pub(super) async fn on_release_request(&mut self, pdu: &codec::Pdu) -> bool {
        let (amf, ran, cause) = match codec::parse_ue_context_release_request(pdu) {
            Ok(x) => x,
            Err(e) => {
                self.send_error_indication(None, None, e.cause).await;
                return true;
            }
        };
        if self.ues.get(&amf).map(|u| u.ran_ue_ngap_id) != Some(ran) {
            self.send_error_indication(
                Some(amf),
                Some(ran),
                Cause::radio(codec::RADIO_UNKNOWN_LOCAL_UE_NGAP_ID),
            )
            .await;
            return true;
        }
        info!(
            "NGAP UE {amf}: the gNB asks for release ({})",
            cause.map(|c| c.label()).unwrap_or_default()
        );
        // The gNB already knows why; the command carries its cause back (38.413 8.3.2). This is
        // not `release_ue`: a registered UE released at the gNB's request goes to CM-IDLE, so its
        // phase stays as it is.
        self.send_encoded(
            "UE Context Release Command",
            codec::ue_context_release_command(amf, Some(ran), &cause.unwrap_or(Cause::radio(0))),
        )
        .await;
        if let Some(ue) = self.ues.get_mut(&amf) {
            ue.releasing = true;
        }
        true
    }
}

/// The first algorithm of `preference` whose bit is set in the UE's capability octet (bit 8 is
/// algorithm 0, bit 7 algorithm 1, ...: TS 24.501 9.11.3.54).
pub(super) fn select_algorithm(preference: &[u8], offered: Option<u8>) -> Option<u8> {
    let offered = offered?;
    preference
        .iter()
        .copied()
        .find(|a| *a < 8 && offered & (0x80 >> a) != 0)
}

/// The model's `reachable_addresses`: IPv4 or IPv6, at most [`upf::MAX_ANSWERING_ADDRESSES`].
pub(super) fn parse_answering_addresses(data: &Value) -> Result<Vec<std::net::IpAddr>, String> {
    let answers: Vec<std::net::IpAddr> = match data.get("reachable_addresses") {
        Some(Value::Array(l)) => l
            .iter()
            .map(|a| a.as_str().and_then(|s| s.trim().parse().ok()))
            .collect::<Option<_>>()
            .ok_or("reachable_addresses must be IPv4 or IPv6 addresses")?,
        Some(Value::Null) | None => Vec::new(),
        Some(_) => return Err("reachable_addresses must be a list".into()),
    };
    if answers.len() > upf::MAX_ANSWERING_ADDRESSES {
        return Err(format!(
            "at most {} reachable_addresses",
            upf::MAX_ANSWERING_ADDRESSES
        ));
    }
    Ok(answers)
}

/// The session's PDU address and IPv6 prefix from the model's decision: `pdu_session_type`
/// (default: what the UE asked for, else ipv4), `ue_ipv4`, `ue_ipv6_prefix` (a /64) and
/// `ue_ipv6_interface_identifier` (default `::1`).
pub(super) fn session_address(
    data: &Value,
    requested: Option<u8>,
) -> Result<(sm::PduAddress, Option<[u8; 8]>), String> {
    let kind = match data.get("pdu_session_type").and_then(Value::as_str) {
        Some(t) => match t.trim().to_ascii_lowercase().as_str() {
            "ipv4" => 1,
            "ipv6" => 2,
            "ipv4v6" => 3,
            other => {
                return Err(format!(
                    "pdu_session_type {other:?} must be ipv4, ipv6 or ipv4v6"
                ))
            }
        },
        None => match requested {
            Some(t @ 1..=3) => t,
            _ => 1,
        },
    };
    let v4 = || -> Result<Ipv4Addr, String> {
        let ip: Ipv4Addr = data["ue_ipv4"]
            .as_str()
            .and_then(|s| s.trim().parse().ok())
            .ok_or("ue_ipv4 must be an IPv4 address")?;
        if ip.is_unspecified() || ip.is_broadcast() || ip.is_multicast() {
            return Err(format!("ue_ipv4 {ip} cannot be a UE's address"));
        }
        Ok(ip)
    };
    let v6 = || -> Result<([u8; 8], [u8; 8]), String> {
        let prefix = parse_prefix(
            data["ue_ipv6_prefix"]
                .as_str()
                .ok_or("ue_ipv6_prefix is required for an IPv6 session, e.g. 2001:db8:1:2::/64")?,
        )?;
        let iid = match data.get("ue_ipv6_interface_identifier").and_then(Value::as_str) {
            Some(s) => sm::parse_iid(s)?,
            None => [0, 0, 0, 0, 0, 0, 0, 1],
        };
        if iid == [0u8; 8] {
            return Err("the interface identifier cannot be zero".into());
        }
        Ok((prefix, iid))
    };
    Ok(match kind {
        1 => (sm::PduAddress::V4(v4()?), None),
        2 => {
            let (p, iid) = v6()?;
            (sm::PduAddress::V6 { iid }, Some(p))
        }
        _ => {
            let (p, iid) = v6()?;
            (sm::PduAddress::V4V6 { iid, v4: v4()? }, Some(p))
        }
    })
}

/// A /64 IPv6 prefix, written `2001:db8:1:2::/64` (the length may be omitted).
pub(super) fn parse_prefix(s: &str) -> Result<[u8; 8], String> {
    let (addr, len) = match s.trim().split_once('/') {
        Some((a, l)) => (a, Some(l)),
        None => (s.trim(), None),
    };
    if let Some(l) = len {
        if l.trim() != "64" {
            return Err(format!(
                "ue_ipv6_prefix {s:?}: a PDU session's prefix is a /64 (TS 23.501 5.8.2.2.3)"
            ));
        }
    }
    let a: std::net::Ipv6Addr = addr
        .parse()
        .map_err(|_| format!("ue_ipv6_prefix {s:?} is not an IPv6 prefix"))?;
    let o = a.octets();
    if o[8..] != [0u8; 8] {
        return Err(format!(
            "ue_ipv6_prefix {s:?} has bits set beyond /64"
        ));
    }
    if a.is_multicast() || a.is_unspecified() || o[0] == 0xfe && o[1] & 0xc0 == 0x80 {
        return Err(format!(
            "ue_ipv6_prefix {s:?} cannot be a UE's global prefix"
        ));
    }
    let mut p = [0u8; 8];
    p.copy_from_slice(&o[..8]);
    Ok(p)
}

/// `10.45.0.2`, `2001:db8::/64 iid ::1`, or both.
pub(super) fn address_label(address: &sm::PduAddress, prefix: Option<&[u8; 8]>) -> String {
    let v6 = |iid: &[u8; 8]| match prefix {
        Some(p) => format!("{} iid {}", upf::prefix_string(p), sm::iid_string(iid)),
        None => format!("iid {}", sm::iid_string(iid)),
    };
    match address {
        sm::PduAddress::V4(a) => a.to_string(),
        sm::PduAddress::V6 { iid } => v6(iid),
        sm::PduAddress::V4V6 { iid, v4 } => format!("{v4} and {}", v6(iid)),
    }
}

/// The PDU Session Resource Setup Request Transfer for a session on this user plane: its AMBR,
/// the uplink tunnel, its type and its one QoS flow. Built again, unchanged but for the 5QI a
/// modification set, when a Service Request reactivates the session.
pub(super) fn setup_transfer(
    s: &PduSession,
    upf_address: std::net::IpAddr,
) -> Result<Vec<u8>, String> {
    codec::encode_setup_request_transfer(&codec::SetupRequestTransfer {
        ambr_dl_bps: s.ambr_dl_kbps.saturating_mul(1000).min(codec::MAX_BIT_RATE),
        ambr_ul_bps: s.ambr_ul_kbps.saturating_mul(1000).min(codec::MAX_BIT_RATE),
        ul_tunnel: codec::GtpTunnel {
            address: upf_address,
            teid: s.ul_teid,
        },
        pdu_session_type: s.ngap_type().into(),
        qos_flows: vec![codec::QosFlow {
            qfi: DEFAULT_QFI,
            five_qi: s.five_qi,
            arp_priority: DEFAULT_ARP_PRIORITY,
        }],
    })
    .map_err(|e| e.to_string())
}
