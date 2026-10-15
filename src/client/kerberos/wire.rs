//! What a Kerberos client builds and checks: AS-REQ (with or without PA-ENC-TIMESTAMP),
//! TGS-REQ (AP-REQ with an authenticator whose keyed checksum covers the request body, and a
//! subkey), and the verification of every reply before anything in it is believed.
//!
//! The KDC's codec (`src/server/kerberos/codec.rs`) supplies the bounded DER walk, the keys and
//! the vocabulary; nothing here is a second copy of it.

use anyhow::{anyhow, Context, Result};
use picky_asn1::wrapper::{
    Asn1SequenceOf, ExplicitContextTag0, ExplicitContextTag1, ExplicitContextTag2,
    ExplicitContextTag3, ExplicitContextTag4, ExplicitContextTag5, ExplicitContextTag6,
    ExplicitContextTag7, ExplicitContextTag8, ExplicitContextTag9, OctetStringAsn1, Optional,
};
use picky_krb::data_types::{
    Authenticator, AuthenticatorInner, Checksum, EtypeInfo2, HostAddress, PaData, PaEncTsEnc,
    Ticket,
};
use picky_krb::messages::{
    ApReq, ApReqInner, AsRep, AsReq, EncAsRepPart, EncKdcRepPart, EncTgsRepPart, KdcRep, KdcReq,
    KdcReqBody, KrbError, KrbErrorInner, TgsRep, TgsReq,
};

use crate::server::kerberos::codec::{
    self, decode, encode, flags, flags_u32, int, int_i64, kstring, kstring_text, now_secs, unix,
    Key, Principal, PA_ENC_TIMESTAMP, PA_ETYPE_INFO2, PA_TGS_REQ, SUPPORTED_ETYPES,
};

/// A ticket and its session key, as a client holds them. Not `Debug`: it carries the key.
#[derive(Clone)]
pub struct Credential {
    pub client: Principal,
    pub client_realm: String,
    pub service: Principal,
    pub service_realm: String,
    pub ticket: Ticket,
    pub session_key: Key,
    pub flags: u32,
    pub authtime: i64,
    pub starttime: i64,
    pub endtime: i64,
    pub renew_till: Option<i64>,
}

impl Credential {
    /// What the model is told about a credential. Never the key.
    pub fn summary(&self) -> serde_json::Value {
        let now = now_secs();
        let ticket_etype = int_i64(&self.ticket.0.enc_part.0.etype.0).unwrap_or(-1) as i32;
        serde_json::json!({
            "client": format!("{}@{}", self.client, self.client_realm),
            "service": format!("{}@{}", self.service, self.service_realm),
            "authtime": codec::rfc3339(self.authtime),
            "starttime": codec::rfc3339(self.starttime),
            "endtime": codec::rfc3339(self.endtime),
            "lifetime_secs": self.endtime - self.starttime,
            "expires_in_secs": self.endtime - now,
            "renew_till": self.renew_till.map(codec::rfc3339),
            "flags": codec::flag_names(self.flags, codec::ticket_flags::NAMES),
            "session_etype": codec::etype_name(self.session_key.etype()),
            "ticket_etype": codec::etype_name(ticket_etype),
        })
    }
}

/// What the client asks for, beyond who and which service.
#[derive(Debug, Clone, Default)]
pub struct Request {
    pub lifetime_secs: i64,
    pub renewable_lifetime_secs: Option<i64>,
    pub forwardable: bool,
    pub proxiable: bool,
    /// Client addresses to put in the request. The model cannot set these; the suites use them
    /// to make a reply too big for one datagram.
    pub addresses: Vec<std::net::IpAddr>,
}

impl Request {
    fn options(&self) -> u32 {
        let mut o = 0;
        if self.forwardable {
            o |= codec::kdc_options::FORWARDABLE;
        }
        if self.proxiable {
            o |= codec::kdc_options::PROXIABLE;
        }
        if self.renewable_lifetime_secs.is_some() {
            o |= codec::kdc_options::RENEWABLE;
        }
        o
    }
}

/// A random nonce in 31 bits, which every implementation encodes the same way.
pub fn nonce() -> u32 {
    rand::random::<u32>() & 0x7fff_ffff
}

fn body(
    client: Option<&Principal>,
    realm: &str,
    service: &Principal,
    request: &Request,
    nonce: u32,
) -> Result<KdcReqBody> {
    let now = now_secs();
    Ok(KdcReqBody {
        kdc_options: ExplicitContextTag0(flags(request.options())),
        cname: Optional(match client {
            Some(c) => Some(ExplicitContextTag1(c.to_asn1()?)),
            None => None,
        }),
        realm: ExplicitContextTag2(kstring(realm)?),
        sname: Optional(Some(ExplicitContextTag3(service.to_asn1()?))),
        from: Optional(None),
        till: ExplicitContextTag5(codec::ktime(now + request.lifetime_secs)),
        rtime: Optional(
            request
                .renewable_lifetime_secs
                .map(|r| ExplicitContextTag6(codec::ktime(now + r))),
        ),
        nonce: ExplicitContextTag7(int(nonce as i64)),
        etype: ExplicitContextTag8(Asn1SequenceOf(
            SUPPORTED_ETYPES.iter().map(|e| int(*e as i64)).collect(),
        )),
        addresses: Optional(if request.addresses.is_empty() {
            None
        } else {
            Some(ExplicitContextTag9(Asn1SequenceOf(
                request
                    .addresses
                    .iter()
                    .map(|a| {
                        let (kind, bytes) = match a {
                            std::net::IpAddr::V4(v4) => (2, v4.octets().to_vec()),
                            std::net::IpAddr::V6(v6) => (24, v6.octets().to_vec()),
                        };
                        HostAddress {
                            addr_type: ExplicitContextTag0(int(kind)),
                            address: ExplicitContextTag1(OctetStringAsn1(bytes)),
                        }
                    })
                    .collect(),
            )))
        }),
        enc_authorization_data: Optional(None),
        additional_tickets: Optional(None),
    })
}

/// PA-ENC-TIMESTAMP: the current time encrypted in the client's key (RFC 4120 §5.2.7.2).
pub fn pa_enc_timestamp(key: &Key) -> Result<PaData> {
    pa_enc_timestamp_at(key, now_secs())
}

/// PA-ENC-TIMESTAMP for an arbitrary time, for the suites that test the clock-skew bound.
pub fn pa_enc_timestamp_at(key: &Key, secs: i64) -> Result<PaData> {
    let ts = PaEncTsEnc {
        patimestamp: ExplicitContextTag0(codec::ktime(secs)),
        pausec: Optional(Some(ExplicitContextTag1(int(
            (rand::random::<u32>() % 1_000_000) as i64,
        )))),
    };
    let enc = key.encrypted_data(codec::KU_PA_ENC_TIMESTAMP, &encode(&ts)?, None)?;
    Ok(codec::padata(PA_ENC_TIMESTAMP, encode(&enc)?))
}

/// An AS-REQ for `client` to `service`, with `padata` (empty for the first, unauthenticated
/// attempt).
pub fn as_req(
    client: &Principal,
    realm: &str,
    service: &Principal,
    request: &Request,
    nonce: u32,
    padata: Vec<PaData>,
) -> Result<Vec<u8>> {
    let req = AsReq::from(KdcReq {
        pvno: ExplicitContextTag1(int(5)),
        msg_type: ExplicitContextTag2(int(10)),
        padata: Optional(if padata.is_empty() {
            None
        } else {
            Some(ExplicitContextTag3(Asn1SequenceOf(padata)))
        }),
        req_body: ExplicitContextTag4(body(Some(client), realm, service, request, nonce)?),
    });
    encode(&req)
}

/// A TGS-REQ for `service`, authenticated with `tgt`, carrying `subkey` for the reply.
pub fn tgs_req(
    tgt: &Credential,
    service: &Principal,
    request: &Request,
    nonce: u32,
    subkey: &Key,
) -> Result<Vec<u8>> {
    let req_body = body(None, &tgt.client_realm, service, request, nonce)?;
    let body_der = encode(&req_body)?;
    let session = &tgt.session_key;
    let checksum = Checksum {
        cksumtype: ExplicitContextTag0(int(session.checksum_type() as i64)),
        checksum: ExplicitContextTag1(OctetStringAsn1(
            session.checksum(codec::KU_TGS_REQ_AUTH_CKSUM, &body_der)?,
        )),
    };
    let authenticator = Authenticator::from(AuthenticatorInner {
        authenticator_vno: ExplicitContextTag0(int(5)),
        crealm: ExplicitContextTag1(kstring(&tgt.client_realm)?),
        cname: ExplicitContextTag2(tgt.client.to_asn1()?),
        cksum: Optional(Some(ExplicitContextTag3(checksum))),
        cusec: ExplicitContextTag4(int((rand::random::<u32>() % 1_000_000) as i64)),
        ctime: ExplicitContextTag5(codec::ktime(now_secs())),
        subkey: Optional(Some(ExplicitContextTag6(subkey.to_asn1()))),
        seq_number: Optional(None),
        authorization_data: Optional(None),
    });
    let ap_req = ApReq::from(ApReqInner {
        pvno: ExplicitContextTag0(int(5)),
        msg_type: ExplicitContextTag1(int(14)),
        ap_options: ExplicitContextTag2(flags(0)),
        ticket: ExplicitContextTag3(tgt.ticket.clone()),
        authenticator: ExplicitContextTag4(session.encrypted_data(
            codec::KU_TGS_REQ_AUTHENTICATOR,
            &encode(&authenticator)?,
            None,
        )?),
    });
    let req = TgsReq::from(KdcReq {
        pvno: ExplicitContextTag1(int(5)),
        msg_type: ExplicitContextTag2(int(12)),
        padata: Optional(Some(ExplicitContextTag3(Asn1SequenceOf(vec![
            codec::padata(PA_TGS_REQ, encode(&ap_req)?),
        ])))),
        req_body: ExplicitContextTag4(req_body),
    });
    let message = encode(&req)?;
    // The checksum covers the body as the KDC will find it in the message; DER is
    // deterministic, but this is the property the KDC checks, so check it here too.
    if codec::req_body_bytes(&message) != Some(body_der.as_slice()) {
        return Err(anyhow!(
            "the encoded request body differs from the checksummed one"
        ));
    }
    Ok(message)
}

/// A KDC reply, decoded but not yet trusted.
pub enum Reply {
    As(KdcRep),
    Tgs(KdcRep),
    Error(KrbErrorInner),
}

/// Decode a reply. Everything a KDC may send back is bounded by the same DER walk as requests.
pub fn parse_reply(bytes: &[u8]) -> Result<Reply> {
    match bytes.first() {
        Some(&codec::TAG_AS_REP) => Ok(Reply::As(decode::<AsRep>(bytes)?.0)),
        Some(&codec::TAG_TGS_REP) => Ok(Reply::Tgs(decode::<TgsRep>(bytes)?.0)),
        Some(&codec::TAG_KRB_ERROR) => Ok(Reply::Error(decode::<KrbError>(bytes)?.0)),
        Some(t) => Err(anyhow!(
            "reply tag 0x{t:02x} is not an AS-REP, TGS-REP or KRB-ERROR"
        )),
        None => Err(anyhow!("empty reply")),
    }
}

/// A KRB-ERROR as the model sees it.
pub fn error_summary(e: &KrbErrorInner) -> serde_json::Value {
    let code = e.error_code.0 as i32;
    serde_json::json!({
        "code": code,
        "error": codec::error_name(code),
        "text": e.e_text.0.as_ref().map(|t| crate::utils::sanitize::line_field(&kstring_text(&t.0))),
    })
}

/// The `(etype, salt)` pairs of a PREAUTH_REQUIRED error's METHOD-DATA.
pub fn etype_info_from_error(e: &KrbErrorInner) -> Vec<(i32, Option<String>)> {
    let Some(data) = e.e_data.0.as_ref() else {
        return Vec::new();
    };
    let Ok(method_data) = decode::<Asn1SequenceOf<PaData>>(&data.0 .0) else {
        return Vec::new();
    };
    etype_info_from_padata(&method_data.0)
}

/// The `(etype, salt)` pairs of a PA-ETYPE-INFO2 in `padata`, if there is one.
pub fn etype_info_from_padata(padata: &[PaData]) -> Vec<(i32, Option<String>)> {
    let Some(pa) = padata
        .iter()
        .find(|p| codec::padata_type(p) == PA_ETYPE_INFO2 as i64)
    else {
        return Vec::new();
    };
    let Ok(info) = decode::<EtypeInfo2>(&pa.padata_data.0 .0) else {
        return Vec::new();
    };
    info.0
        .iter()
        .filter_map(|e| {
            let etype = int_i64(&e.etype.0).and_then(|v| i32::try_from(v).ok())?;
            Some((etype, e.salt.0.as_ref().map(|s| kstring_text(&s.0))))
        })
        .collect()
}

/// What a verified reply must match.
pub struct Expect<'a> {
    pub client: &'a Principal,
    pub client_realm: &'a str,
    pub service: &'a Principal,
    pub service_realm: &'a str,
    pub nonce: u32,
}

/// Decrypt and verify a KDC-REP: the encrypted part must decrypt (its integrity check is the
/// proof the KDC holds our key, or the TGT session key), echo our nonce and name the client and
/// service we asked for. Only then is it a [`Credential`].
pub fn verify_rep(rep: &KdcRep, key: &Key, usage: i32, expect: &Expect) -> Result<Credential> {
    if int_i64(&rep.pvno.0) != Some(5) {
        return Err(anyhow!("reply protocol version is not 5"));
    }
    let plain = key
        .decrypt_data(usage, &rep.enc_part.0)
        .map_err(|e| anyhow!("the reply's encrypted part did not verify: {e}"))?;
    // RFC 4120 §5.4.2: accept either tag, as MIT and Heimdal both do.
    let part: EncKdcRepPart = match decode::<EncAsRepPart>(&plain) {
        Ok(p) => p.0,
        Err(_) => {
            decode::<EncTgsRepPart>(&plain)
                .context("decrypted reply is neither EncASRepPart nor EncTGSRepPart")?
                .0
        }
    };
    let nonce_ok = int_i64(&part.nonce.0) == Some(expect.nonce as i64);
    if !nonce_ok {
        return Err(anyhow!("the reply does not echo our nonce"));
    }
    let cname = Principal::from_asn1(&rep.cname.0)?;
    if !cname.same_name(expect.client) || kstring_text(&rep.crealm.0) != expect.client_realm {
        return Err(anyhow!("the reply is for {cname}, not {}", expect.client));
    }
    let sname = Principal::from_asn1(&part.sname.0)?;
    if !sname.same_name(expect.service) || kstring_text(&part.srealm.0) != expect.service_realm {
        return Err(anyhow!(
            "the reply is for service {sname}, not {}",
            expect.service
        ));
    }
    let tkt_sname = Principal::from_asn1(&rep.ticket.0 .0.sname.0)?;
    if !tkt_sname.same_name(expect.service) {
        return Err(anyhow!(
            "the ticket is for {tkt_sname}, not {}",
            expect.service
        ));
    }
    let authtime = unix(&part.auth_time.0).context("authtime is not a date")?;
    let endtime = unix(&part.end_time.0).context("endtime is not a date")?;
    Ok(Credential {
        client: expect.client.clone(),
        client_realm: expect.client_realm.to_string(),
        service: expect.service.clone(),
        service_realm: expect.service_realm.to_string(),
        ticket: rep.ticket.0.clone(),
        session_key: Key::from_asn1(&part.key.0)?,
        flags: flags_u32(&part.flags.0),
        authtime,
        starttime: part
            .start_time
            .0
            .as_ref()
            .and_then(|t| unix(&t.0))
            .unwrap_or(authtime),
        endtime,
        renew_till: part.renew_till.0.as_ref().and_then(|t| unix(&t.0)),
    })
}

/// Re-export for the test suites that inspect what NetGet's KDC put in a ticket's flags.
pub fn ticket_flag_names(value: u32) -> Vec<String> {
    codec::flag_names(value, codec::ticket_flags::NAMES)
}
