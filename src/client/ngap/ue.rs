//! The UE behind NetGet's gNB, when it is given a subscriber's credentials: the UE side of 5G-AKA
//! (AUTN verified, RES* computed, SQN kept, AUTS on a stale SQN), the security mode procedure,
//! registration (Registration Complete, the Initial Context Setup answered), and PDU session
//! establishment with its NGAP resource setup — all in Rust, from `security`, the shared module.
//!
//! The model brings the UE in (`ngap_initial_ue_message`), learns that it registered
//! (`ngap_ue_registered`), asks for sessions (`ngap_pdu_session_request`) and learns of each
//! (`ngap_pdu_session_established`). It never handles a key, a MAC or a COUNT, and it is never
//! asked about an Authentication Request or a Security Mode Command.
//!
//! Every protected downlink message is verified before anything acts on it; one that fails is
//! discarded with its `decision=` tag. The K_gNB the AMF hands the gNB in the Initial Context
//! Setup is compared with the one this UE derives from its own K_AMF and uplink NAS COUNT
//! (TS 33.501 Annex A.9), which is the one place an independent AMF's key derivation becomes
//! checkable on the RAN side.

use super::*;
use crate::server::ngap::security::{self, Milenage, NasContext};
use crate::server::ngap::sm;

/// How far ahead of the USIM's SQN a fresh one may be (TS 33.102 Annex C.2.1's delta).
pub const SQN_DELTA: u64 = 1 << 28;
/// IMEISV this UE reports when the AMF asks and the operator named none.
pub const DEFAULT_IMEISV: &str = "4370816125816151";

/// A subscriber the operator gave this gNB. The SQN is the USIM's state.
pub struct Credentials {
    pub supi: String,
    milenage: Milenage,
    pub sqn_ms: u64,
    pub imeisv: String,
}

impl Credentials {
    /// From the startup parameters; `None` when no `subscriber_key` was given. Errors name the
    /// parameter, never its value.
    pub fn from_ctx(ctx: &ConnectContext) -> Result<Option<Credentials>> {
        let get = |k: &str| -> Result<Option<String>> { startup_string(ctx, k) };
        let Some(k) = get("subscriber_key")? else {
            return Ok(None);
        };
        let k = security::hex_key::<16>("subscriber_key", &k).map_err(|e| anyhow!(e))?;
        let milenage = match (get("subscriber_opc")?, get("subscriber_op")?) {
            (Some(opc), None) => Milenage::with_opc(
                k,
                security::hex_key::<16>("subscriber_opc", &opc).map_err(|e| anyhow!(e))?,
            ),
            (None, Some(op)) => Milenage::with_op(
                k,
                security::hex_key::<16>("subscriber_op", &op).map_err(|e| anyhow!(e))?,
            ),
            _ => bail!("give subscriber_opc or subscriber_op (one of them) with subscriber_key"),
        };
        let supi = crate::server::ngap::subscribers::supi_digits(
            &get("supi")?.context("supi is required with subscriber_key")?,
        )
        .map_err(|e| anyhow!(e))?;
        let sqn_ms = startup_u64(ctx, "sqn", 0, security::MAX_SQN)?;
        let imeisv = get("imeisv")?.unwrap_or_else(|| DEFAULT_IMEISV.to_string());
        anyhow::ensure!(
            imeisv.len() == 16 && imeisv.bytes().all(|b| b.is_ascii_digit()),
            "imeisv must be 16 digits"
        );
        Ok(Some(Credentials {
            supi,
            milenage,
            sqn_ms,
            imeisv,
        }))
    }
}

/// One UE's security state on this gNB.
pub struct UeSec {
    supi: String,
    /// The Registration Request as first sent, retransmitted inside Security Mode Complete.
    initial_nas: Vec<u8>,
    caps: Vec<u8>,
    k_amf: Option<security::Key256>,
    ctx: Option<NasContext>,
    active: bool,
    registered: bool,
    /// K_gNB from K_AMF and the uplink NAS COUNT of Security Mode Complete (TS 33.501 6.8.1.2,
    /// Annex A.9), to compare with the one the AMF hands the gNB.
    k_gnb: Option<security::Key256>,
    next_pti: u8,
    /// PDU session id → (PTI, the DNN asked for).
    pending: BTreeMap<u8, (u8, Option<String>)>,
}

impl UeSec {
    /// When `nas` is a Registration Request whose null-scheme SUCI names `creds`' subscriber,
    /// the UE that sends it is this subscriber.
    pub fn for_registration(creds: &Credentials, nas: &[u8]) -> Option<UeSec> {
        let req = nas::parse_registration_request(nas).ok()?;
        let suci = nas::parse_suci(&req.mobile_identity)?;
        if suci.protection_scheme != 0 {
            return None;
        }
        let msin = nas::msin_from_bcd(&suci.scheme_output)?;
        if format!("{}{}{}", suci.plmn.mcc, suci.plmn.mnc, msin) != creds.supi {
            return None;
        }
        Some(UeSec {
            supi: creds.supi.clone(),
            initial_nas: nas.to_vec(),
            caps: req.ue_security_capability.unwrap_or_default(),
            k_amf: None,
            ctx: None,
            active: false,
            registered: false,
            k_gnb: None,
            next_pti: 1,
            pending: BTreeMap::new(),
        })
    }

    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Protect an uplink 5GMM message once security is active; plain before.
    pub fn protect(&mut self, plain: &[u8]) -> Vec<u8> {
        match (self.active, self.ctx.as_mut()) {
            (true, Some(ctx)) => ctx.protect(plain, security::SHT_INTEGRITY_CIPHERED),
            _ => plain.to_vec(),
        }
    }
}

impl Gnb {
    fn sec(&mut self, ran: u64) -> Option<&mut UeSec> {
        self.ues.get_mut(&ran).and_then(|s| s.sec.as_deref_mut())
    }

    /// Answer the AMF for a UE in Rust: `nas` (as protected `nas_raw`) for UE `ran`.
    async fn send_ue_uplink(
        &mut self,
        amf: u64,
        ran: u64,
        plain: &[u8],
        log: &Log<'_>,
    ) -> Result<()> {
        let nas_pdu = match self.sec(ran) {
            Some(sec) => sec.protect(plain),
            None => plain.to_vec(),
        };
        let pdu = codec::uplink_nas_transport(amf, ran, &nas_pdu, &self.user_location)?;
        debug!(
            "NGAP client UE {ran}: -> {}",
            nas::message_name(plain.get(2).copied().unwrap_or(0)).unwrap_or("?")
        );
        let _ = log;
        self.send(&pdu).await
    }

    /// A Downlink NAS Transport (or an Initial Context Setup's NAS-PDU) for a UE with
    /// credentials. Returns `true` when Rust handled it; `false` hands it to the model.
    pub(super) async fn ue_downlink(
        &mut self,
        amf: u64,
        ran: u64,
        raw: &[u8],
        depth: u32,
        log: &Log<'_>,
    ) -> Result<bool> {
        let snn = self.snn.clone();
        let sht = raw.get(1).map(|h| h & 0x0F).unwrap_or(0);
        if raw.first() != Some(&nas::EPD_5GMM) {
            return Ok(false);
        }
        // A Security Mode Command is checked with the context it brings into use.
        if sht == security::SHT_INTEGRITY_NEW_CONTEXT {
            return self
                .on_security_mode_command(amf, ran, raw, depth, log)
                .await;
        }
        let plain = if sht == security::SHT_PLAIN {
            let active = self.sec(ran).map(|s| s.active).unwrap_or(false);
            if active {
                log.warn(format!(
                    "NGAP client UE {ran}: unprotected downlink NAS after security was \
                     established; discarded (decision=nas_unprotected_refused)"
                ));
                return Ok(true);
            }
            raw.to_vec()
        } else {
            let result = match self.sec(ran).and_then(|s| s.ctx.as_mut()) {
                Some(ctx) => ctx.unprotect(raw),
                None => Err(security::UnprotectError::HeaderType(sht)),
            };
            match result {
                Ok((p, _, _)) => p,
                Err(e) => {
                    log.warn(format!(
                        "NGAP client UE {ran}: protected downlink NAS discarded: {e} (decision={})",
                        e.decision()
                    ));
                    return Ok(true);
                }
            }
        };
        let t = plain.get(2).copied().unwrap_or(0);
        match t {
            nas::AUTHENTICATION_REQUEST => {
                let Ok(req) = nas::parse_authentication_request(&plain) else {
                    return Ok(false);
                };
                let Some(creds) = self.creds.as_mut() else {
                    return Ok(false);
                };
                let outcome = security::ue_check_autn(
                    &creds.milenage,
                    &req.rand,
                    &req.autn,
                    &snn,
                    creds.sqn_ms,
                    SQN_DELTA,
                );
                let reply = match outcome {
                    security::AutnOutcome::Ok {
                        res_star,
                        k_ausf,
                        sqn,
                    } => {
                        creds.sqn_ms = sqn;
                        let k_seaf = security::k_seaf(&k_ausf, &snn);
                        let supi = creds.supi.clone();
                        if let Some(sec) = self.sec(ran) {
                            sec.k_amf = Some(security::k_amf(&k_seaf, &supi, &req.abba));
                            sec.ctx = None;
                            sec.active = false;
                        }
                        log.info(format!(
                            "NGAP client UE {ran}: the network's AUTN verified (SQN {sqn:#x}); \
                             answering RES*"
                        ));
                        let _ = req.ngksi;
                        nas::authentication_response(&res_star)
                    }
                    security::AutnOutcome::MacFailure => {
                        log.warn(format!(
                            "NGAP client UE {ran}: the AUTN's MAC does not verify with this \
                             subscriber's key (decision=auth_mac_failure)"
                        ));
                        nas::authentication_failure(nas::CAUSE_MAC_FAILURE, None)
                    }
                    security::AutnOutcome::SynchFailure { auts } => {
                        log.info(format!(
                            "NGAP client UE {ran}: SQN not fresh; Authentication Failure with \
                             AUTS (decision=auth_synch_failure)"
                        ));
                        nas::authentication_failure(21, Some(&auts))
                    }
                    security::AutnOutcome::SeparationBit => nas::authentication_failure(26, None),
                };
                self.send_ue_uplink(amf, ran, &reply, log).await?;
                Ok(true)
            }
            nas::REGISTRATION_ACCEPT if self.sec(ran).map(|s| s.active).unwrap_or(false) => {
                let accept = match nas::parse_registration_accept(&plain) {
                    Ok(a) => a,
                    Err(e) => {
                        log.warn(format!("NGAP client UE {ran}: Registration Accept: {e}"));
                        return Ok(true);
                    }
                };
                self.send_ue_uplink(amf, ran, &nas::registration_complete(), log)
                    .await?;
                let k_gnb_verified = self.ues.get(&ran).and_then(|s| s.k_gnb_verified);
                let Some(sec) = self.sec(ran) else {
                    return Ok(true);
                };
                sec.registered = true;
                let (ia, ea) = sec.ctx.as_ref().map(|c| (c.ia, c.ea)).unwrap_or((0, 0));
                let supi = format!("imsi-{}", sec.supi);
                log.info(format!(
                    "NGAP client UE {ran} {supi}: registered (decision=ue_registered)"
                ));
                self.emit(
                    &actions::REGISTERED_EVENT,
                    json!({
                        "amf_ue_ngap_id": amf,
                        "ran_ue_ngap_id": ran,
                        "supi": supi,
                        "guti": accept.guti,
                        "allowed_nssai": accept.allowed_nssai.iter().map(nas::Snssai::to_json).collect::<Vec<_>>(),
                        "tai_list": accept.tai_list,
                        "nas_security": {"integrity": security::integrity_name(ia), "ciphering": security::ciphering_name(ea)},
                        "k_gnb_verified": k_gnb_verified,
                    }),
                    depth,
                );
                Ok(true)
            }
            nas::DL_NAS_TRANSPORT => {
                let Ok(t) = nas::parse_dl_nas_transport(&plain) else {
                    return Ok(false);
                };
                if t.payload_type != nas::PAYLOAD_N1_SM {
                    return Ok(false);
                }
                self.on_session_management(amf, ran, &t.payload, depth, log)
                    .await
            }
            0x54 => {
                // Configuration Update Command: acknowledge when it asks (IEI 0xD-, ACK bit).
                let ack = plain[3..].iter().any(|b| b >> 4 == 0xD && b & 0x01 != 0);
                if ack {
                    self.send_ue_uplink(amf, ran, &[nas::EPD_5GMM, 0, 0x55], log)
                        .await?;
                }
                Ok(true)
            }
            _ => {
                // Everything else — rejects, identity requests, a deregistration accept — goes
                // to the model, verified and deciphered.
                self.emit(
                    &actions::DOWNLINK_NAS_EVENT,
                    json!({
                        "amf_ue_ngap_id": amf,
                        "ran_ue_ngap_id": ran,
                        "nas": nas::decode(&plain),
                        "protected": sht != security::SHT_PLAIN,
                    }),
                    depth,
                );
                Ok(true)
            }
        }
    }

    async fn on_security_mode_command(
        &mut self,
        amf: u64,
        ran: u64,
        raw: &[u8],
        _depth: u32,
        log: &Log<'_>,
    ) -> Result<bool> {
        let imeisv = self
            .creds
            .as_ref()
            .map(|c| c.imeisv.clone())
            .unwrap_or_default();
        let Some(sec) = self.sec(ran) else {
            return Ok(false);
        };
        let Some(k_amf) = sec.k_amf else {
            log.warn(format!(
                "NGAP client UE {ran}: Security Mode Command before authentication; discarded \
                 (decision=nas_header_refused)"
            ));
            return Ok(true);
        };
        let Ok(smc) = raw
            .get(7..)
            .ok_or("short".to_string())
            .and_then(nas::parse_security_mode_command)
        else {
            log.warn(format!(
                "NGAP client UE {ran}: Security Mode Command does not decode (decision=nas_malformed)"
            ));
            return Ok(true);
        };
        let mut ctx = NasContext::new(smc.ngksi, k_amf, smc.ia, smc.ea, security::UPLINK);
        if let Err(e) = ctx.unprotect(raw) {
            log.warn(format!(
                "NGAP client UE {ran}: Security Mode Command discarded: {e} (decision={})",
                e.decision()
            ));
            return Ok(true);
        }
        let mismatch = smc.replayed_ue_security_capability != sec.caps;
        let unsupported =
            !matches!(smc.ia, security::NIA2) || !matches!(smc.ea, security::NEA0 | security::NEA2);
        if mismatch || unsupported {
            log.warn(format!(
                "NGAP client UE {ran}: Security Mode Command refused ({}) \
                 (decision=security_mode_rejected)",
                if mismatch {
                    "replayed UE security capabilities differ"
                } else {
                    "algorithms this UE does not implement"
                }
            ));
            let cause = if mismatch { 23 } else { 24 };
            let msg = vec![nas::EPD_5GMM, 0, nas::SECURITY_MODE_REJECT, cause];
            self.send_ue_uplink(amf, ran, &msg, log).await?;
            return Ok(true);
        }
        let digits = imeisv.clone();
        let imeisv_id = nas::encode_mobile_identity(&json!({"type": "imeisv", "digits": digits}))
            .map_err(|e| anyhow!(e))?;
        let complete = nas::security_mode_complete(
            smc.imeisv_request.then_some(imeisv_id.as_slice()),
            Some(&sec.initial_nas),
        );
        let protected = ctx.protect(&complete, security::SHT_INTEGRITY_CIPHERED_NEW_CONTEXT);
        log.info(format!(
            "NGAP client UE {ran}: Security Mode Command verified ({}, {}); Security Mode \
             Complete",
            security::integrity_name(smc.ia),
            security::ciphering_name(smc.ea)
        ));
        sec.k_gnb = Some(ctx.k_gnb());
        sec.ctx = Some(ctx);
        sec.active = true;
        let pdu = codec::uplink_nas_transport(amf, ran, &protected, &self.user_location)?;
        self.send(&pdu).await?;
        Ok(true)
    }

    async fn on_session_management(
        &mut self,
        amf: u64,
        ran: u64,
        payload: &[u8],
        depth: u32,
        log: &Log<'_>,
    ) -> Result<bool> {
        let Some((psi, _pti, mt)) = sm::header(payload) else {
            return Ok(false);
        };
        let Some(sec) = self.sec(ran) else {
            return Ok(false);
        };
        let dnn_asked = sec.pending.remove(&psi).and_then(|(_, d)| d);
        match mt {
            sm::PDU_SESSION_ESTABLISHMENT_ACCEPT => {
                let a = match sm::parse_establishment_accept(payload) {
                    Ok(a) => a,
                    Err(e) => {
                        log.warn(format!(
                            "NGAP client UE {ran}: PDU Session Establishment Accept: {e}"
                        ));
                        return Ok(true);
                    }
                };
                let tunnel = self
                    .ues
                    .get(&ran)
                    .and_then(|s| s.sessions.get(&psi))
                    .cloned();
                let k_gnb_verified = self.ues.get(&ran).and_then(|s| s.k_gnb_verified);
                log.info(format!(
                    "NGAP client UE {ran}: PDU session {psi} established, UE address {} \
                     (decision=pdu_session_established)",
                    a.address.map(|x| x.to_string()).unwrap_or_default()
                ));
                self.emit(
                    &actions::PDU_SESSION_EVENT,
                    json!({
                        "amf_ue_ngap_id": amf,
                        "ran_ue_ngap_id": ran,
                        "pdu_session_id": psi,
                        "result": "accepted",
                        "ue_ipv4": a.address.map(|x| x.to_string()),
                        "dnn": a.dnn.or(dnn_asked),
                        "s_nssai": a.s_nssai.map(|s| s.to_json()),
                        "qfis": a.qfis,
                        "session_ambr_kbps": {"uplink": a.ambr_uplink_kbps, "downlink": a.ambr_downlink_kbps},
                        "upf_tunnel": tunnel.map(|t| t.to_json()),
                        "k_gnb_verified": k_gnb_verified,
                    }),
                    depth,
                );
            }
            sm::PDU_SESSION_ESTABLISHMENT_REJECT => {
                let cause = payload.get(4).copied().unwrap_or(0);
                log.warn(format!(
                    "NGAP client UE {ran}: PDU session {psi} rejected: {}",
                    sm::cause_name(cause)
                ));
                self.emit(
                    &actions::PDU_SESSION_EVENT,
                    json!({
                        "amf_ue_ngap_id": amf,
                        "ran_ue_ngap_id": ran,
                        "pdu_session_id": psi,
                        "result": "rejected",
                        "cause": {"value": cause, "name": sm::cause_name(cause)},
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

    /// The model asks for a PDU session for a registered UE.
    pub(super) async fn request_pdu_session(
        &mut self,
        action: &Value,
        depth: u32,
    ) -> Result<Vec<u8>> {
        let ran = codec::json_u64(action, "ran_ue_ngap_id", codec::MAX_RAN_UE_NGAP_ID)?;
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
        anyhow::ensure!(sec.registered, "the UE is not registered yet");
        let psi = match codec::json_opt_u64(action, "pdu_session_id", 15)? {
            Some(p) if p >= 1 => p as u8,
            Some(_) => bail!("pdu_session_id must be 1..15"),
            None => (1..=15u8)
                .find(|p| !sec.pending.contains_key(p))
                .context("no free PDU session id")?,
        };
        let pti = sec.next_pti;
        sec.next_pti = if sec.next_pti >= 254 {
            1
        } else {
            sec.next_pti + 1
        };
        let dnn = action
            .get("dnn")
            .and_then(Value::as_str)
            .map(str::to_string);
        let s_nssai = match action.get("s_nssai") {
            Some(v) if !v.is_null() => Some(nas::Snssai::from_json(v).map_err(|e| anyhow!(e))?),
            _ => None,
        };
        let req = sm::establishment_request(psi, pti, 1, 1);
        let ul = nas::ul_nas_transport_sm(psi, 1, s_nssai.as_ref(), dnn.as_deref(), &req)
            .map_err(|e| anyhow!(e))?;
        sec.pending.insert(psi, (pti, dnn));
        let protected = sec.protect(&ul);
        Ok(codec::uplink_nas_transport(
            amf,
            ran,
            &protected,
            &self.user_location,
        )?)
    }

    /// Initial Context Setup Request: compare K_gNB with this UE's own, answer, then deliver
    /// the NAS-PDU (normally the Registration Accept).
    pub(super) async fn on_initial_context_setup(
        &mut self,
        pdu: &codec::Pdu,
        log: &Log<'_>,
    ) -> Result<()> {
        let ics = match codec::parse_initial_context_setup_request(pdu) {
            Ok(c) => c,
            Err(e) => {
                log.warn(format!("NGAP client: Initial Context Setup Request: {e}"));
                let ei = codec::error_indication(None, None, Some(&e.cause))?;
                return self.send(&ei).await;
            }
        };
        let ran = ics.ran_ue_ngap_id;
        let amf = ics.amf_ue_ngap_id;
        let depth = match self.ues.get_mut(&ran) {
            Some(slot) => {
                slot.amf = Some(amf);
                slot.depth
            }
            None => {
                let ei = codec::error_indication(
                    Some(amf),
                    Some(ran),
                    Some(&Cause::radio(codec::RADIO_UNKNOWN_LOCAL_UE_NGAP_ID)),
                )?;
                return self.send(&ei).await;
            }
        };
        // The UE's K_gNB uses the uplink NAS COUNT of its last protected message (Security Mode
        // Complete); compare before the Registration Complete moves it.
        let expected = self.sec(ran).and_then(|s| s.k_gnb);
        let verified = expected.map(|k| security::constant_time_eq(&k, &ics.security_key));
        if let Some(slot) = self.ues.get_mut(&ran) {
            slot.k_gnb_verified = verified;
        }
        match verified {
            Some(true) => log.info(format!(
                "NGAP client UE {ran}: the AMF's K_gNB equals the one this UE derived \
                 (decision=k_gnb_verified)"
            )),
            Some(false) => log.warn(format!(
                "NGAP client UE {ran}: the AMF's K_gNB differs from the one this UE derived \
                 (decision=k_gnb_mismatch)"
            )),
            None => {}
        }
        let (established, failed) = self.setup_sessions(ran, &ics.pdu_sessions, log);
        let response = codec::initial_context_setup_response(amf, ran, &established, &failed)?;
        self.send(&response).await?;
        let session_nas: Vec<Vec<u8>> =
            ics.pdu_sessions.into_iter().filter_map(|i| i.nas).collect();
        for nas_pdu in ics.nas.into_iter().chain(session_nas) {
            let handled = if self.sec(ran).is_some() {
                self.ue_downlink(amf, ran, &nas_pdu, depth, log).await?
            } else {
                false
            };
            if !handled {
                self.emit(
                    &actions::DOWNLINK_NAS_EVENT,
                    json!({"amf_ue_ngap_id": amf, "ran_ue_ngap_id": ran, "nas": nas::decode(&nas_pdu),
                           "via": "initial_context_setup"}),
                    depth,
                );
            }
        }
        Ok(())
    }

    /// Allocate a downlink tunnel for each requested session and record the UPF's uplink one.
    fn setup_sessions(
        &mut self,
        ran: u64,
        items: &[codec::SetupItem],
        log: &Log<'_>,
    ) -> (Vec<(u8, codec::SetupResponseTransfer)>, Vec<(u8, Cause)>) {
        let mut established = Vec::new();
        let mut failed = Vec::new();
        for it in items {
            match codec::decode_setup_request_transfer(&it.transfer) {
                Ok(t) => {
                    let dl_teid: u32 = loop {
                        let x: u32 = rand::random();
                        if x != 0 {
                            break x;
                        }
                    };
                    if let Some(slot) = self.ues.get_mut(&ran) {
                        slot.sessions.insert(it.pdu_session_id, t.ul_tunnel);
                    }
                    established.push((
                        it.pdu_session_id,
                        codec::SetupResponseTransfer {
                            dl_tunnel: codec::GtpTunnel {
                                address: self.gtp_address,
                                teid: dl_teid,
                            },
                            qfis: t.qos_flows.iter().map(|f| f.qfi).collect(),
                        },
                    ));
                }
                Err(e) => {
                    log.warn(format!(
                        "NGAP client: PDU session {} transfer: {e}",
                        it.pdu_session_id
                    ));
                    failed.push((it.pdu_session_id, e.cause));
                }
            }
        }
        (established, failed)
    }

    /// PDU Session Resource Setup Request: allocate a downlink tunnel per session, answer, then
    /// deliver each session's NAS-PDU.
    pub(super) async fn on_pdu_session_setup(
        &mut self,
        pdu: &codec::Pdu,
        log: &Log<'_>,
    ) -> Result<()> {
        let (amf, ran, items) = match codec::parse_pdu_session_resource_setup_request(pdu) {
            Ok(x) => x,
            Err(e) => {
                log.warn(format!(
                    "NGAP client: PDU Session Resource Setup Request: {e}"
                ));
                let ei = codec::error_indication(None, None, Some(&e.cause))?;
                return self.send(&ei).await;
            }
        };
        let Some(depth) = self.ues.get(&ran).map(|s| s.depth) else {
            let ei = codec::error_indication(
                Some(amf),
                Some(ran),
                Some(&Cause::radio(codec::RADIO_UNKNOWN_LOCAL_UE_NGAP_ID)),
            )?;
            return self.send(&ei).await;
        };
        let (established, failed) = self.setup_sessions(ran, &items, log);
        let response = codec::pdu_session_resource_setup_response(amf, ran, &established, &failed)?;
        self.send(&response).await?;
        for it in items {
            if let Some(nas_pdu) = it.nas {
                let handled = if self.sec(ran).is_some() {
                    self.ue_downlink(amf, ran, &nas_pdu, depth, log).await?
                } else {
                    false
                };
                if !handled {
                    self.emit(
                        &actions::DOWNLINK_NAS_EVENT,
                        json!({"amf_ue_ngap_id": amf, "ran_ue_ngap_id": ran, "nas": nas::decode(&nas_pdu),
                               "via": "pdu_session_resource_setup"}),
                        depth,
                    );
                }
            }
        }
        Ok(())
    }
}
