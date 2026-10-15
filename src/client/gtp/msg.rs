//! What the GTP client puts on the wire and how it reads the answers. Pure: no sockets, no
//! state, no model — `mod.rs` owns those — so `tests/client/gtp/msg_test.rs` can pin the
//! octets and the bounds without a peer.
//!
//! Every octet is built on the server's codec (`crate::server::gtp::codec`): the GTPv1
//! all-or-nothing optional block, the fixed-below-128 IE split, GTPv2 TLIV and the grouped
//! Bearer Context all come from there. This file adds the *request* side — Create Session /
//! Create PDP Context, Modify Bearer / Update PDP Context, Delete Session / Delete PDP Context,
//! Echo — and the inner IPv4 packet a G-PDU carries, which the model describes as fields and
//! never as bytes.

use crate::server::gtp::codec::{
    self, GtpV1Header, GtpV1Ie, GtpV1Message, GtpV2Header, GtpV2Ie, GtpV2Message, GtpVersion,
};
use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Value};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// The largest datagram this client reads. A read that fills the buffer past it is refused,
/// because it means the datagram was cut short.
pub const MAX_DATAGRAM: usize = 65_535;
/// Information elements one message may carry before it is refused unread. A real Create
/// Session Response has about fifteen; 64 KiB of four-octet IEs would be sixteen thousand.
pub const MAX_IES: usize = 256;
/// Payload octets of a received G-PDU that reach the model; the rest is counted, not shown.
pub const MAX_EVENT_PAYLOAD: usize = 1024;
/// Octets of transport payload one G-PDU may carry. An IPv4 + UDP inner packet inside a G-PDU
/// with a sequence number must fit one UDP datagram, which is what
/// [`codec::MAX_GPDU_PAYLOAD_LEN`] measures.
pub const MAX_INNER_PAYLOAD: usize = codec::MAX_GPDU_PAYLOAD_LEN - 28;

/// GTPv2 F-TEID interface types (TS 29.274 §8.22, Table 8.22-1) this client uses or names.
pub const IF_S1U_ENB_GTPU: u8 = 0;
pub const IF_S1U_SGW_GTPU: u8 = 1;
pub const IF_S5S8_SGW_GTPU: u8 = 4;
pub const IF_S5S8_PGW_GTPU: u8 = 5;
pub const IF_S5S8_SGW_GTPC: u8 = 6;
pub const IF_S5S8_PGW_GTPC: u8 = 7;
pub const IF_S11_MME_GTPC: u8 = 10;
pub const IF_S11S4_SGW_GTPC: u8 = 11;

pub const V2_IE_MEI: u8 = 75;
pub const V2_IE_AMBR: u8 = 72;
pub const V2_IE_BEARER_QOS: u8 = 80;
pub const V2_IE_SERVING_NETWORK: u8 = 83;
pub const V2_IE_PDN_TYPE: u8 = 99;
pub const V2_IE_SELECTION_MODE: u8 = 128;
pub const V2_IE_CHARGING_ID: u8 = 94;
pub const V1_IE_CHARGING_GATEWAY: u8 = 251;
/// GTP-U IE "GTP-U Peer Address" in an Error Indication (TS 29.281 §8.4) is IE 133.
pub const V1_IE_PEER_ADDRESS: u8 = 133;

pub const V1_ERROR_INDICATION: u8 = codec::V1_ERROR_INDICATION;
pub const V1_END_MARKER: u8 = codec::V1_END_MARKER;
pub const V1_G_PDU: u8 = codec::V1_G_PDU;
/// GTPv2 Version Not Supported Indication (TS 29.274 Table 6.1-1).
pub const V2_VERSION_NOT_SUPPORTED: u8 = 3;

pub fn interface_name(t: u8) -> &'static str {
    match t {
        IF_S1U_ENB_GTPU => "S1-U eNodeB GTP-U",
        IF_S1U_SGW_GTPU => "S1-U SGW GTP-U",
        2 => "S12 RNC GTP-U",
        3 => "S12 SGW GTP-U",
        IF_S5S8_SGW_GTPU => "S5/S8 SGW GTP-U",
        IF_S5S8_PGW_GTPU => "S5/S8 PGW GTP-U",
        IF_S5S8_SGW_GTPC => "S5/S8 SGW GTP-C",
        IF_S5S8_PGW_GTPC => "S5/S8 PGW GTP-C",
        IF_S11_MME_GTPC => "S11 MME GTP-C",
        IF_S11S4_SGW_GTPC => "S11/S4 SGW GTP-C",
        _ => "other",
    }
}

/// Which node this client is, which decides the interface types it advertises.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// GTPv1 Gn: an SGSN towards a GGSN.
    Gn,
    /// GTPv2 S5/S8: an SGW towards a PGW.
    S5,
    /// GTPv2 S11: an MME towards an SGW.
    S11,
}

impl Role {
    pub fn version(self) -> GtpVersion {
        match self {
            Role::Gn => GtpVersion::V1,
            _ => GtpVersion::V2,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Gn => "gn",
            Role::S5 => "s5",
            Role::S11 => "s11",
        }
    }
}

/// The request kinds this client issues; each one's answer is matched by sequence **and**
/// by message type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Request {
    Echo,
    Create,
    Modify,
    Delete,
}

impl Request {
    pub fn message_type(self, version: GtpVersion) -> u8 {
        match (version, self) {
            (_, Request::Echo) => 1,
            (GtpVersion::V1, Request::Create) => codec::V1_CREATE_PDP_CONTEXT_REQUEST,
            (GtpVersion::V1, Request::Modify) => codec::V1_UPDATE_PDP_CONTEXT_REQUEST,
            (GtpVersion::V1, Request::Delete) => codec::V1_DELETE_PDP_CONTEXT_REQUEST,
            (GtpVersion::V2, Request::Create) => codec::V2_CREATE_SESSION_REQUEST,
            (GtpVersion::V2, Request::Modify) => codec::V2_MODIFY_BEARER_REQUEST,
            (GtpVersion::V2, Request::Delete) => codec::V2_DELETE_SESSION_REQUEST,
        }
    }
    /// The message that answers it.
    pub fn response_type(self, version: GtpVersion) -> u8 {
        self.message_type(version) + 1
    }
    pub fn name(self, version: GtpVersion) -> &'static str {
        match version {
            GtpVersion::V1 => codec::v1_message_name(self.message_type(version)),
            GtpVersion::V2 => codec::v2_message_name(self.message_type(version)),
        }
    }
}

/// QoS for the default bearer, as the model gives it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BearerQos {
    pub qci: u8,
    pub arp_priority_level: u8,
    pub pre_emption_capability: bool,
    pub pre_emption_vulnerability: bool,
    pub mbr_uplink_kbps: u64,
    pub mbr_downlink_kbps: u64,
    pub gbr_uplink_kbps: u64,
    pub gbr_downlink_kbps: u64,
}

impl Default for BearerQos {
    fn default() -> Self {
        Self {
            qci: 9,
            arp_priority_level: 8,
            pre_emption_capability: false,
            pre_emption_vulnerability: true,
            mbr_uplink_kbps: 0,
            mbr_downlink_kbps: 0,
            gbr_uplink_kbps: 0,
            gbr_downlink_kbps: 0,
        }
    }
}

/// The 40-bit bit-rate fields of a Bearer QoS IE hold kilobits per second.
const MAX_BITRATE_KBPS: u64 = 0xFF_FFFF_FFFF;

impl BearerQos {
    pub fn from_json(v: Option<&Value>) -> Result<Self> {
        let mut q = Self::default();
        let Some(v) = v else { return Ok(q) };
        ensure!(v.is_object(), "qos is an object");
        if let Some(x) = v.get("qci") {
            q.qci = small(x, "qos.qci", 1, 254)? as u8;
        }
        if let Some(x) = v.get("arp_priority_level") {
            q.arp_priority_level = small(x, "qos.arp_priority_level", 1, 15)? as u8;
        }
        if let Some(x) = v.get("pre_emption_capability") {
            q.pre_emption_capability = x
                .as_bool()
                .context("qos.pre_emption_capability is true or false")?;
        }
        if let Some(x) = v.get("pre_emption_vulnerability") {
            q.pre_emption_vulnerability = x
                .as_bool()
                .context("qos.pre_emption_vulnerability is true or false")?;
        }
        for (key, slot) in [
            ("mbr_uplink_kbps", &mut q.mbr_uplink_kbps),
            ("mbr_downlink_kbps", &mut q.mbr_downlink_kbps),
            ("gbr_uplink_kbps", &mut q.gbr_uplink_kbps),
            ("gbr_downlink_kbps", &mut q.gbr_downlink_kbps),
        ] {
            if let Some(x) = v.get(key) {
                *slot = small(x, &format!("qos.{key}"), 0, MAX_BITRATE_KBPS)?;
            }
        }
        Ok(q)
    }

    /// TS 29.274 §8.15: `spare|PCI|PL(4)|spare|PVI`, QCI, then four 40-bit rates.
    /// PCI and PVI are *disable* bits: 0 means the capability/vulnerability is on.
    pub fn encode_v2(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(22);
        let pci = u8::from(!self.pre_emption_capability);
        let pvi = u8::from(!self.pre_emption_vulnerability);
        out.push((pci << 6) | ((self.arp_priority_level & 0x0F) << 2) | pvi);
        out.push(self.qci);
        for rate in [
            self.mbr_uplink_kbps,
            self.mbr_downlink_kbps,
            self.gbr_uplink_kbps,
            self.gbr_downlink_kbps,
        ] {
            out.extend_from_slice(&rate.to_be_bytes()[3..8]);
        }
        out
    }

    /// TS 29.060 §7.7.34: the Allocation/Retention Priority octet, then a TS 24.008 QoS
    /// profile. The profile is the R97 best-effort one (delay class 1, reliability class 3,
    /// peak throughput class 9, precedence 2, best-effort mean throughput) — the octets
    /// Osmocom's `sgsnemu` sends by default. Only the ARP comes from the model.
    pub fn encode_v1(&self) -> Vec<u8> {
        vec![self.arp_priority_level.clamp(1, 3), 0x0B, 0x92, 0x1F]
    }
}

fn small(v: &Value, name: &str, min: u64, max: u64) -> Result<u64> {
    let n = v
        .as_u64()
        .with_context(|| format!("{name} is a whole number"))?;
    ensure!(
        (min..=max).contains(&n),
        "{name} is {n}, outside {min}..={max}"
    );
    Ok(n)
}

/// Everything a Create Session / Create PDP Context Request needs, already validated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreateParams {
    pub imsi: String,
    pub msisdn: Option<String>,
    pub mei: Option<String>,
    pub apn: String,
    pub pdn_type: u8,
    pub ebi: u8,
    pub rat_type: u8,
    pub mcc: String,
    pub mnc: String,
    pub selection_mode: u8,
    pub qos: BearerQos,
    pub ambr_uplink_kbps: u32,
    pub ambr_downlink_kbps: u32,
    pub request_dns: bool,
    pub pgw_address: Option<IpAddr>,
}

/// Bounds on what the model may name. Each is a format limit, not a policy.
fn digits(v: &Value, name: &str, min: usize, max: usize) -> Result<String> {
    let s = v
        .as_str()
        .with_context(|| format!("{name} is a string of digits"))?;
    ensure!(
        s.chars().all(|c| c.is_ascii_digit()),
        "{name} must be decimal digits only"
    );
    ensure!(
        (min..=max).contains(&s.len()),
        "{name} has {} digits, outside {min}..={max}",
        s.len()
    );
    Ok(s.to_string())
}

/// Longest APN (TS 23.003 §9.1).
pub const MAX_APN_LEN: usize = 100;

pub fn rat_value(version: GtpVersion, name: &str) -> Result<u8> {
    let n = name
        .trim()
        .to_ascii_uppercase()
        .replace(['-', ' ', '_'], "");
    let pairs: &[(&str, u8)] = &[
        ("UTRAN", 1),
        ("GERAN", 2),
        ("WLAN", 3),
        ("GAN", 4),
        ("HSPAEVOLUTION", 5),
        ("EUTRAN", 6),
        ("EUTRANNBIOT", 8),
        ("LTEM", 9),
        ("NR", 10),
    ];
    let v = pairs
        .iter()
        .find(|(k, _)| *k == n)
        .map(|(_, v)| *v)
        .with_context(|| {
            format!("rat_type {name:?} is not one of UTRAN, GERAN, WLAN, GAN, HSPA Evolution, EUTRAN, EUTRAN-NB-IoT, LTE-M, NR")
        })?;
    ensure!(
        version == GtpVersion::V2 || v <= 6,
        "rat_type {name:?} has no GTPv1 code"
    );
    Ok(v)
}

impl CreateParams {
    pub fn from_action(role: Role, a: &Value) -> Result<Self> {
        let version = role.version();
        let imsi = digits(a.get("imsi").context("imsi is required")?, "imsi", 5, 15)?;
        let msisdn = a
            .get("msisdn")
            .map(|v| digits(v, "msisdn", 1, 15))
            .transpose()?;
        let mei = a.get("mei").map(|v| digits(v, "mei", 14, 16)).transpose()?;
        let apn = a
            .get("apn")
            .and_then(Value::as_str)
            .context("apn is required (a dotted name such as \"internet\")")?
            .to_string();
        ensure!(
            !apn.is_empty() && apn.len() <= MAX_APN_LEN,
            "apn is 1..={MAX_APN_LEN} characters"
        );
        codec::encode_apn(&apn)?;
        let pdn_type = match a
            .get("pdn_type")
            .and_then(Value::as_str)
            .unwrap_or("ipv4")
            .to_ascii_lowercase()
            .as_str()
        {
            "ipv4" => 1,
            "ipv6" => 2,
            "ipv4v6" => 3,
            other => bail!("pdn_type {other:?} is ipv4, ipv6 or ipv4v6"),
        };
        let ebi = match a.get("ebi") {
            Some(v) => small(v, "ebi", 5, 15)? as u8,
            None => 5,
        };
        let rat_type = match a.get("rat_type").and_then(Value::as_str) {
            Some(r) => rat_value(version, r)?,
            None if version == GtpVersion::V1 => 1,
            None => 6,
        };
        let mcc = match a.get("mcc") {
            Some(v) => digits(v, "mcc", 3, 3)?,
            None => "001".into(),
        };
        let mnc = match a.get("mnc") {
            Some(v) => digits(v, "mnc", 2, 3)?,
            None => "01".into(),
        };
        let selection_mode = match a.get("selection_mode") {
            Some(v) => small(v, "selection_mode", 0, 3)? as u8,
            None => 0,
        };
        let qos = BearerQos::from_json(a.get("qos"))?;
        let ambr = |k: &str| -> Result<u32> {
            match a.get(k) {
                Some(v) => Ok(small(v, k, 0, u32::MAX as u64)? as u32),
                None => Ok(DEFAULT_AMBR_KBPS),
            }
        };
        let ambr_uplink_kbps = ambr("ambr_uplink_kbps")?;
        let ambr_downlink_kbps = ambr("ambr_downlink_kbps")?;
        let request_dns = match a.get("request_dns") {
            Some(v) => v.as_bool().context("request_dns is true or false")?,
            None => true,
        };
        let pgw_address = match a.get("pgw_address").and_then(Value::as_str) {
            Some(s) => Some(
                s.parse::<IpAddr>()
                    .with_context(|| format!("pgw_address {s:?} is not an IP address"))?,
            ),
            None => None,
        };
        if role == Role::S11 {
            ensure!(
                pgw_address.is_some(),
                "on S11 the SGW needs the PGW to forward to: give pgw_address"
            );
        }
        Ok(Self {
            imsi,
            msisdn,
            mei,
            apn,
            pdn_type,
            ebi,
            rat_type,
            mcc,
            mnc,
            selection_mode,
            qos,
            ambr_uplink_kbps,
            ambr_downlink_kbps,
            request_dns,
            pgw_address,
        })
    }
}

pub const DEFAULT_AMBR_KBPS: u32 = 100_000;

/// The addresses and tunnel ids this client advertises for one session.
#[derive(Clone, Copy, Debug)]
pub struct Local {
    pub control_ip: IpAddr,
    pub user_ip: IpAddr,
    pub control_teid: u32,
    pub data_teid: u32,
}

/// TS 24.008 §10.5.1.13 PLMN: MCC2|MCC1, MNC3|MCC3, MNC2|MNC1; a two-digit MNC puts F in
/// MNC3.
pub fn encode_plmn(mcc: &str, mnc: &str) -> Vec<u8> {
    let d = |s: &str, i: usize| s.as_bytes().get(i).map(|b| b - b'0').unwrap_or(0x0F);
    vec![
        (d(mcc, 1) << 4) | d(mcc, 0),
        (d(mnc, 2) << 4) | d(mcc, 2),
        (d(mnc, 1) << 4) | d(mnc, 0),
    ]
}

/// A TBCD field padded with filler to a fixed length (GTPv1 IMSI and IMEI(SV) are TV, 8
/// octets).
fn tbcd_fixed(digits: &str, len: usize) -> Vec<u8> {
    let mut v = codec::encode_tbcd(digits);
    v.resize(len, 0xFF);
    v
}

/// PCO asking for DNS servers: container 0x000D (DNS Server IPv4 Address Request), and
/// 0x0003 for IPv6 when the PDN is v6.
fn pco_dns_request(pdn_type: u8) -> Vec<u8> {
    let mut out = vec![0x80];
    if pdn_type != 2 {
        out.extend_from_slice(&[0x00, 0x0D, 0x00]);
    }
    if pdn_type != 1 {
        out.extend_from_slice(&[0x00, 0x03, 0x00]);
    }
    out
}

fn ip_octets(ip: IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(a) => a.octets().to_vec(),
        IpAddr::V6(a) => a.octets().to_vec(),
    }
}

fn v1ie(ie_type: u8, value: Vec<u8>) -> GtpV1Ie {
    GtpV1Ie { ie_type, value }
}

fn v1_encode(message_type: u8, teid: u32, sequence: u32, ies: &[GtpV1Ie]) -> Vec<u8> {
    GtpV1Message {
        header: GtpV1Header::with_sequence(message_type, teid, sequence as u16),
        body: codec::encode_v1_ies(ies),
    }
    .encode()
}

fn v2_encode(header: GtpV2Header, ies: Vec<GtpV2Ie>) -> Vec<u8> {
    GtpV2Message { header, ies }.encode()
}

/// Echo Request on either plane. GTPv1 carries no IE (Recovery belongs to the response);
/// GTPv2 carries Recovery (TS 29.274 Table 7.1.1-1).
pub fn echo_request(version: GtpVersion, sequence: u32, recovery: u8) -> Vec<u8> {
    match version {
        GtpVersion::V1 => v1_encode(codec::V1_ECHO_REQUEST, 0, sequence, &[]),
        GtpVersion::V2 => v2_encode(
            GtpV2Header::without_teid(codec::V2_ECHO_REQUEST, sequence),
            vec![GtpV2Ie::new(codec::V2_IE_RECOVERY, 0, vec![recovery])],
        ),
    }
}

/// Echo Response to the peer's Echo Request, with this node's Recovery counter.
pub fn echo_response(version: GtpVersion, sequence: u32, recovery: u8) -> Vec<u8> {
    match version {
        GtpVersion::V1 => v1_encode(
            codec::V1_ECHO_RESPONSE,
            0,
            sequence,
            &[v1ie(codec::V1_IE_RECOVERY, vec![recovery])],
        ),
        GtpVersion::V2 => v2_encode(
            GtpV2Header::without_teid(codec::V2_ECHO_RESPONSE, sequence),
            vec![GtpV2Ie::new(codec::V2_IE_RECOVERY, 0, vec![recovery])],
        ),
    }
}

/// Create Session Request (GTPv2, TS 29.274 §7.2.1) or Create PDP Context Request (GTPv1,
/// TS 29.060 §7.3.1).
pub fn create_request(
    role: Role,
    p: &CreateParams,
    local: &Local,
    sequence: u32,
    recovery: u8,
) -> Result<Vec<u8>> {
    let apn = codec::encode_apn(&p.apn)?;
    Ok(match role {
        Role::Gn => {
            // TV IEs must appear in ascending type order; the TLV ones follow.
            let mut ies = vec![
                v1ie(codec::V1_IE_IMSI, tbcd_fixed(&p.imsi, 8)),
                v1ie(codec::V1_IE_RECOVERY, vec![recovery]),
                v1ie(codec::V1_IE_SELECTION_MODE, vec![0xFC | p.selection_mode]),
                v1ie(
                    codec::V1_IE_TEID_DATA_I,
                    local.data_teid.to_be_bytes().to_vec(),
                ),
                v1ie(
                    codec::V1_IE_TEID_CONTROL_PLANE,
                    local.control_teid.to_be_bytes().to_vec(),
                ),
                v1ie(codec::V1_IE_NSAPI, vec![p.ebi & 0x0F]),
                v1ie(
                    codec::V1_IE_END_USER_ADDRESS,
                    vec![
                        0xF1,
                        match p.pdn_type {
                            1 => 0x21,
                            2 => 0x57,
                            _ => 0x8D,
                        },
                    ],
                ),
                v1ie(codec::V1_IE_ACCESS_POINT_NAME, apn),
            ];
            if p.request_dns {
                ies.push(v1ie(
                    codec::V1_IE_PROTOCOL_CONFIG_OPTIONS,
                    pco_dns_request(p.pdn_type),
                ));
            }
            ies.push(v1ie(codec::V1_IE_GSN_ADDRESS, ip_octets(local.control_ip)));
            ies.push(v1ie(codec::V1_IE_GSN_ADDRESS, ip_octets(local.user_ip)));
            if let Some(m) = &p.msisdn {
                // Numbering plan octet: international number, ISDN/E.164.
                let mut v = vec![0x91];
                v.extend(codec::encode_tbcd(m));
                ies.push(v1ie(codec::V1_IE_MSISDN, v));
            }
            ies.push(v1ie(codec::V1_IE_QOS_PROFILE, p.qos.encode_v1()));
            ies.push(v1ie(codec::V1_IE_RAT_TYPE, vec![p.rat_type]));
            if let Some(m) = &p.mei {
                ies.push(v1ie(codec::V1_IE_IMEISV, tbcd_fixed(m, 8)));
            }
            v1_encode(codec::V1_CREATE_PDP_CONTEXT_REQUEST, 0, sequence, &ies)
        }
        Role::S5 | Role::S11 => {
            let sender_if = if role == Role::S5 {
                IF_S5S8_SGW_GTPC
            } else {
                IF_S11_MME_GTPC
            };
            let mut ies = vec![GtpV2Ie::new(
                codec::V2_IE_IMSI,
                0,
                codec::encode_tbcd(&p.imsi),
            )];
            if let Some(m) = &p.msisdn {
                ies.push(GtpV2Ie::new(codec::V2_IE_MSISDN, 0, codec::encode_tbcd(m)));
            }
            if let Some(m) = &p.mei {
                ies.push(GtpV2Ie::new(V2_IE_MEI, 0, codec::encode_tbcd(m)));
            }
            ies.push(GtpV2Ie::new(
                V2_IE_SERVING_NETWORK,
                0,
                encode_plmn(&p.mcc, &p.mnc),
            ));
            ies.push(GtpV2Ie::new(codec::V2_IE_RAT_TYPE, 0, vec![p.rat_type]));
            ies.push(GtpV2Ie::new(
                codec::V2_IE_FTEID,
                0,
                codec::encode_fteid(sender_if, local.control_teid, local.control_ip),
            ));
            if let (Role::S11, Some(pgw)) = (role, p.pgw_address) {
                ies.push(GtpV2Ie::new(
                    codec::V2_IE_FTEID,
                    1,
                    codec::encode_fteid(IF_S5S8_PGW_GTPC, 0, pgw),
                ));
            }
            ies.push(GtpV2Ie::new(codec::V2_IE_APN, 0, apn));
            // GTPv2 spare bits are zero (TS 29.274 §8.1); GTPv1's are one (TS 29.060
            // §7.7.12), which is why the two Selection Modes differ by 0xFC.
            ies.push(GtpV2Ie::new(
                V2_IE_SELECTION_MODE,
                0,
                vec![p.selection_mode],
            ));
            ies.push(GtpV2Ie::new(V2_IE_PDN_TYPE, 0, vec![p.pdn_type]));
            ies.push(GtpV2Ie::new(
                codec::V2_IE_PAA,
                0,
                match p.pdn_type {
                    1 => vec![1, 0, 0, 0, 0],
                    2 => {
                        let mut v = vec![2, 64];
                        v.extend([0u8; 16]);
                        v
                    }
                    _ => {
                        let mut v = vec![3, 64];
                        v.extend([0u8; 20]);
                        v
                    }
                },
            ));
            ies.push(GtpV2Ie::new(codec::V2_IE_APN_RESTRICTION, 0, vec![0]));
            let mut ambr = p.ambr_uplink_kbps.to_be_bytes().to_vec();
            ambr.extend(p.ambr_downlink_kbps.to_be_bytes());
            ies.push(GtpV2Ie::new(V2_IE_AMBR, 0, ambr));
            if p.request_dns {
                ies.push(GtpV2Ie::new(
                    codec::V2_IE_PCO,
                    0,
                    pco_dns_request(p.pdn_type),
                ));
            }
            let mut bearer = vec![GtpV2Ie::new(codec::V2_IE_EBI, 0, vec![p.ebi & 0x0F])];
            if role == Role::S5 {
                bearer.push(GtpV2Ie::new(
                    codec::V2_IE_FTEID,
                    2,
                    codec::encode_fteid(IF_S5S8_SGW_GTPU, local.data_teid, local.user_ip),
                ));
            }
            bearer.push(GtpV2Ie::new(V2_IE_BEARER_QOS, 0, p.qos.encode_v2()));
            ies.push(GtpV2Ie::new(
                codec::V2_IE_BEARER_CONTEXT,
                0,
                codec::encode_v2_grouped(&bearer),
            ));
            ies.push(GtpV2Ie::new(codec::V2_IE_RECOVERY, 0, vec![recovery]));
            v2_encode(
                GtpV2Header::new(codec::V2_CREATE_SESSION_REQUEST, 0, sequence),
                ies,
            )
        }
    })
}

/// Modify Bearer Request (GTPv2 §7.2.7) or Update PDP Context Request (GTPv1 §7.3.3),
/// addressed to the peer's control TEID. It tells the peer where this node's end of the user
/// plane is: on S11 as the eNodeB's S1-U F-TEID, on S5 as the SGW's S5/S8-U F-TEID.
pub fn modify_request(
    role: Role,
    peer_control_teid: u32,
    ebi: u8,
    qos: &BearerQos,
    local: &Local,
    sequence: u32,
) -> Vec<u8> {
    match role {
        Role::Gn => {
            let ies = vec![
                v1ie(
                    codec::V1_IE_TEID_DATA_I,
                    local.data_teid.to_be_bytes().to_vec(),
                ),
                v1ie(
                    codec::V1_IE_TEID_CONTROL_PLANE,
                    local.control_teid.to_be_bytes().to_vec(),
                ),
                v1ie(codec::V1_IE_NSAPI, vec![ebi & 0x0F]),
                v1ie(codec::V1_IE_GSN_ADDRESS, ip_octets(local.control_ip)),
                v1ie(codec::V1_IE_GSN_ADDRESS, ip_octets(local.user_ip)),
                v1ie(codec::V1_IE_QOS_PROFILE, qos.encode_v1()),
            ];
            v1_encode(
                codec::V1_UPDATE_PDP_CONTEXT_REQUEST,
                peer_control_teid,
                sequence,
                &ies,
            )
        }
        Role::S5 | Role::S11 => {
            let (instance, iface) = if role == Role::S11 {
                (0, IF_S1U_ENB_GTPU)
            } else {
                (1, IF_S5S8_SGW_GTPU)
            };
            let bearer = vec![
                GtpV2Ie::new(codec::V2_IE_EBI, 0, vec![ebi & 0x0F]),
                GtpV2Ie::new(
                    codec::V2_IE_FTEID,
                    instance,
                    codec::encode_fteid(iface, local.data_teid, local.user_ip),
                ),
            ];
            v2_encode(
                GtpV2Header::new(codec::V2_MODIFY_BEARER_REQUEST, peer_control_teid, sequence),
                vec![GtpV2Ie::new(
                    codec::V2_IE_BEARER_CONTEXT,
                    0,
                    codec::encode_v2_grouped(&bearer),
                )],
            )
        }
    }
}

/// Delete Session Request (GTPv2 §7.2.9, with the Linked EPS Bearer ID) or Delete PDP Context
/// Request (GTPv1 §7.3.5, with Teardown Ind set so the whole PDP address goes).
pub fn delete_request(role: Role, peer_control_teid: u32, ebi: u8, sequence: u32) -> Vec<u8> {
    match role {
        Role::Gn => v1_encode(
            codec::V1_DELETE_PDP_CONTEXT_REQUEST,
            peer_control_teid,
            sequence,
            &[
                v1ie(codec::V1_IE_TEARDOWN_IND, vec![0xFF]),
                v1ie(codec::V1_IE_NSAPI, vec![ebi & 0x0F]),
            ],
        ),
        Role::S5 | Role::S11 => v2_encode(
            GtpV2Header::new(
                codec::V2_DELETE_SESSION_REQUEST,
                peer_control_teid,
                sequence,
            ),
            vec![GtpV2Ie::new(codec::V2_IE_EBI, 0, vec![ebi & 0x0F])],
        ),
    }
}

/// A response to a request the peer sent, carrying only a Cause.
pub fn cause_response(
    version: GtpVersion,
    message_type: u8,
    teid: u32,
    sequence: u32,
    cause: u8,
) -> Vec<u8> {
    match version {
        GtpVersion::V1 => v1_encode(
            message_type,
            teid,
            sequence,
            &[v1ie(codec::V1_IE_CAUSE, vec![cause])],
        ),
        GtpVersion::V2 => v2_encode(
            GtpV2Header::new(message_type, teid, sequence),
            vec![GtpV2Ie::new(codec::V2_IE_CAUSE, 0, vec![cause, 0])],
        ),
    }
}

/// The cause's symbolic name in this version's numbering, or `cause_<n>`.
pub fn cause_name(version: GtpVersion, value: u8) -> String {
    codec::CAUSES
        .iter()
        .find(|c| match version {
            GtpVersion::V1 => c.v1 == value,
            GtpVersion::V2 => c.v2 == value,
        })
        .map(|c| c.name.to_string())
        .unwrap_or_else(|| match (version, value) {
            (GtpVersion::V2, 64) => "context_not_found".into(),
            (GtpVersion::V2, 96) => "imsi_imei_not_known".into(),
            _ => format!("cause_{value}"),
        })
}

/// Resolve a cause the model named (`request_accepted`) or numbered.
pub fn cause_value(version: GtpVersion, v: &Value) -> Result<u8> {
    if let Some(n) = v.as_u64() {
        ensure!(n <= 255, "cause {n} is one octet");
        return Ok(n as u8);
    }
    let name = v.as_str().context("cause is a name or a number")?;
    let c = codec::cause_by_name(name).with_context(|| {
        format!(
            "cause {name:?} is not one of {}",
            codec::cause_names().join(", ")
        )
    })?;
    Ok(match version {
        GtpVersion::V1 => c.v1,
        GtpVersion::V2 => c.v2,
    })
}

// ===========================================================================
// Reading answers
// ===========================================================================

/// One decoded control-plane datagram, version-neutral.
#[derive(Debug)]
pub struct Control {
    pub version: GtpVersion,
    pub message_type: u8,
    pub sequence: u32,
    pub teid: u32,
    pub v1: Vec<GtpV1Ie>,
    pub v2: Vec<GtpV2Ie>,
}

impl Control {
    pub fn name(&self) -> &'static str {
        message_name(self.version, self.message_type)
    }
    /// A request the peer may send this node that it answers with `type + 1` — other than
    /// Echo, which Rust answers. GTPv1 (TS 29.060 Table 1): Create/Update/Delete PDP Context,
    /// Initiate PDP Context Activation, PDU Notification. GTPv2 (TS 29.274 Table 6.1-1):
    /// Create/Modify/Delete Session, Create/Update/Delete Bearer, Delete PDN Connection Set.
    /// Parity is no guide: GTPv2's bearer requests are odd and GTPv1's PDU Notification is.
    pub fn is_peer_request(&self) -> bool {
        match self.version {
            GtpVersion::V1 => matches!(self.message_type, 16 | 18 | 20 | 22 | 27),
            GtpVersion::V2 => matches!(self.message_type, 32 | 34 | 36 | 95 | 97 | 99 | 101),
        }
    }
}

/// Message names, including the requests a peer may send that the server codec never needed.
pub fn message_name(version: GtpVersion, t: u8) -> &'static str {
    match (version, t) {
        (GtpVersion::V1, 22) => "Initiate PDP Context Activation Request",
        (GtpVersion::V1, 23) => "Initiate PDP Context Activation Response",
        (GtpVersion::V1, 27) => "PDU Notification Request",
        (GtpVersion::V1, 28) => "PDU Notification Response",
        (GtpVersion::V1, _) => codec::v1_message_name(t),
        (GtpVersion::V2, 3) => "Version Not Supported Indication",
        (GtpVersion::V2, 95) => "Create Bearer Request",
        (GtpVersion::V2, 96) => "Create Bearer Response",
        (GtpVersion::V2, 97) => "Update Bearer Request",
        (GtpVersion::V2, 98) => "Update Bearer Response",
        (GtpVersion::V2, 99) => "Delete Bearer Request",
        (GtpVersion::V2, 100) => "Delete Bearer Response",
        (GtpVersion::V2, 101) => "Delete PDN Connection Set Request",
        (GtpVersion::V2, 102) => "Delete PDN Connection Set Response",
        (GtpVersion::V2, _) => codec::v2_message_name(t),
    }
}

/// Decode a control-plane datagram, refusing anything malformed or past the IE bound.
pub fn decode_control(data: &[u8]) -> Result<Control> {
    ensure!(
        data.len() <= MAX_DATAGRAM,
        "datagram of {} octets is past {MAX_DATAGRAM}",
        data.len()
    );
    match codec::peek_version(data) {
        Some(1) => {
            let m = GtpV1Message::decode(data)?;
            ensure!(m.header.protocol_type, "GTP' (charging) is not spoken here");
            let ies = codec::parse_v1_ies(&m.body)?;
            ensure!(ies.len() <= MAX_IES, "{} IEs is past {MAX_IES}", ies.len());
            Ok(Control {
                version: GtpVersion::V1,
                message_type: m.header.message_type,
                sequence: m
                    .header
                    .sequence
                    .map(u32::from)
                    .context("a GTPv1-C message without a sequence number cannot be matched")?,
                teid: m.header.teid,
                v1: ies,
                v2: vec![],
            })
        }
        Some(2) => {
            let m = GtpV2Message::decode(data)?;
            ensure!(
                m.ies.len() <= MAX_IES,
                "{} IEs is past {MAX_IES}",
                m.ies.len()
            );
            Ok(Control {
                version: GtpVersion::V2,
                message_type: m.header.message_type,
                sequence: m.header.sequence,
                teid: m.header.teid.unwrap_or(0),
                v1: vec![],
                v2: m.ies,
            })
        }
        Some(v) => bail!("GTP version {v} is not spoken here"),
        None => bail!("empty datagram"),
    }
}

/// A bare 4- or 16-octet address.
pub fn addr(value: &[u8]) -> Option<IpAddr> {
    match value.len() {
        4 => Some(IpAddr::V4(Ipv4Addr::new(
            value[0], value[1], value[2], value[3],
        ))),
        16 => {
            let mut o = [0u8; 16];
            o.copy_from_slice(value);
            Some(IpAddr::V6(Ipv6Addr::from(o)))
        }
        _ => None,
    }
}

/// DNS servers out of a PCO: containers 0x000D / 0x0003, and the primary/secondary DNS
/// options inside an IPCP (0x8021) Configure-Nak/Ack, which is how many GGSNs answer.
pub fn pco_dns(value: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut pos = 1usize;
    while pos + 3 <= value.len() {
        let id = u16::from_be_bytes([value[pos], value[pos + 1]]);
        let len = value[pos + 2] as usize;
        let Some(c) = value.get(pos + 3..pos + 3 + len) else {
            break;
        };
        match id {
            0x000D | 0x0003 => {
                if let Some(a) = addr(c) {
                    out.push(a.to_string());
                }
            }
            0x8021 if c.len() >= 4 => {
                let total = (u16::from_be_bytes([c[2], c[3]]) as usize).min(c.len());
                let mut o = 4usize;
                while o + 2 <= total {
                    let (t, l) = (c[o], c[o + 1] as usize);
                    if l < 2 || o + l > total {
                        break;
                    }
                    if (t == 129 || t == 131) && l == 6 {
                        out.push(Ipv4Addr::new(c[o + 2], c[o + 3], c[o + 4], c[o + 5]).to_string());
                    }
                    o += l;
                }
            }
            _ => {}
        }
        pos += 3 + len;
    }
    out
}

fn fteid_json(instance: u8, value: &[u8]) -> Option<Value> {
    let (iface, teid, address) = codec::decode_fteid(value)?;
    Some(json!({
        "instance": instance,
        "interface": interface_name(iface),
        "interface_type": iface,
        "teid": teid,
        "address": address.map(|a| a.to_string()),
    }))
}

/// What the peer told this client in a response: the event data the model sees, plus the
/// tunnel endpoints Rust keeps for the session.
#[derive(Debug, Default)]
pub struct Answer {
    pub cause: Option<u8>,
    pub peer_control_teid: Option<u32>,
    pub peer_control_address: Option<IpAddr>,
    pub peer_data_teid: Option<u32>,
    pub peer_data_address: Option<IpAddr>,
    pub ue_address: Option<IpAddr>,
    pub data: Value,
}

/// Read a response into structured fields. `role` decides which F-TEID is the peer's
/// control plane and which bearer F-TEID is its user plane.
pub fn read_answer(role: Role, c: &Control) -> Answer {
    let mut a = Answer {
        data: json!({}),
        ..Default::default()
    };
    match c.version {
        GtpVersion::V1 => {
            let find = |t| codec::find_v1(&c.v1, t);
            a.cause = find(codec::V1_IE_CAUSE).and_then(|v| v.first().copied());
            if let Some(r) = find(codec::V1_IE_RECOVERY).and_then(|v| v.first()) {
                a.data["recovery"] = json!(r);
            }
            a.peer_data_teid = find(codec::V1_IE_TEID_DATA_I)
                .map(|v| u32::from_be_bytes([v[0], v[1], v[2], v[3]]));
            a.peer_control_teid = find(codec::V1_IE_TEID_CONTROL_PLANE)
                .map(|v| u32::from_be_bytes([v[0], v[1], v[2], v[3]]));
            if let Some(v) = find(codec::V1_IE_CHARGING_ID) {
                a.data["charging_id"] = json!(u32::from_be_bytes([v[0], v[1], v[2], v[3]]));
            }
            if let Some(v) = find(codec::V1_IE_END_USER_ADDRESS) {
                let (t, ip) = codec::decode_end_user_address(v);
                a.data["pdn_type"] = json!(t);
                a.ue_address = ip;
            }
            if let Some(v) = find(codec::V1_IE_PROTOCOL_CONFIG_OPTIONS) {
                a.data["dns_servers"] = json!(pco_dns(v));
            }
            let gsn = codec::find_all_v1(&c.v1, codec::V1_IE_GSN_ADDRESS);
            a.peer_control_address = gsn.first().and_then(|v| addr(v));
            a.peer_data_address = gsn.get(1).and_then(|v| addr(v));
        }
        GtpVersion::V2 => {
            let top = |t, i| {
                c.v2.iter()
                    .find(|ie| ie.ie_type == t && ie.instance == i)
                    .map(|ie| ie.value.as_slice())
            };
            a.cause = top(codec::V2_IE_CAUSE, 0).and_then(|v| v.first().copied());
            if let Some(r) = top(codec::V2_IE_RECOVERY, 0).and_then(|v| v.first()) {
                a.data["recovery"] = json!(r);
            }
            if let Some(v) = top(codec::V2_IE_PAA, 0) {
                let (t, ip) = codec::decode_paa(v);
                a.data["pdn_type"] = json!(t);
                a.ue_address = ip;
            }
            if let Some(v) = top(codec::V2_IE_PCO, 0) {
                a.data["dns_servers"] = json!(pco_dns(v));
            }
            if let Some(v) = top(V2_IE_AMBR, 0).filter(|v| v.len() == 8) {
                a.data["ambr_uplink_kbps"] = json!(u32::from_be_bytes([v[0], v[1], v[2], v[3]]));
                a.data["ambr_downlink_kbps"] = json!(u32::from_be_bytes([v[4], v[5], v[6], v[7]]));
            }
            if let Some(v) = top(codec::V2_IE_APN_RESTRICTION, 0).and_then(|v| v.first()) {
                a.data["apn_restriction"] = json!(v);
            }
            // Control F-TEIDs at the top level: the sender's own (instance 0) is the peer's
            // control plane; on S11 instance 1 is the PGW behind the SGW.
            let mut fteids = Vec::new();
            for ie in c.v2.iter().filter(|ie| ie.ie_type == codec::V2_IE_FTEID) {
                if let Some(j) = fteid_json(ie.instance, &ie.value) {
                    fteids.push(j);
                }
            }
            let ctl = top(codec::V2_IE_FTEID, 0)
                .or_else(|| top(codec::V2_IE_FTEID, 1))
                .and_then(codec::decode_fteid);
            if let Some((_, teid, address)) = ctl {
                a.peer_control_teid = Some(teid);
                a.peer_control_address = address;
            }
            a.data["control_fteids"] = Value::Array(fteids);
            // Bearer Context created / modified (instance 0).
            if let Some(inner) =
                top(codec::V2_IE_BEARER_CONTEXT, 0).and_then(|v| codec::parse_v2_grouped(v).ok())
            {
                let mut bearer = json!({});
                let mut data_fteids = Vec::new();
                for ie in &inner {
                    match ie.ie_type {
                        codec::V2_IE_EBI => {
                            bearer["ebi"] = json!(ie.value.first().map(|v| v & 0x0F))
                        }
                        codec::V2_IE_CAUSE => {
                            if let Some(v) = ie.value.first() {
                                bearer["cause"] = json!(cause_name(GtpVersion::V2, *v));
                                bearer["cause_value"] = json!(v);
                            }
                        }
                        V2_IE_CHARGING_ID if ie.value.len() == 4 => {
                            bearer["charging_id"] = json!(u32::from_be_bytes([
                                ie.value[0],
                                ie.value[1],
                                ie.value[2],
                                ie.value[3]
                            ]))
                        }
                        codec::V2_IE_FTEID => {
                            if let Some(j) = fteid_json(ie.instance, &ie.value) {
                                data_fteids.push(j);
                            }
                        }
                        _ => {}
                    }
                }
                let wanted = if role == Role::S11 {
                    IF_S1U_SGW_GTPU
                } else {
                    IF_S5S8_PGW_GTPU
                };
                let user = inner
                    .iter()
                    .filter(|ie| ie.ie_type == codec::V2_IE_FTEID)
                    .filter_map(|ie| codec::decode_fteid(&ie.value))
                    .find(|f| f.0 == wanted)
                    .or_else(|| {
                        inner
                            .iter()
                            .filter(|ie| ie.ie_type == codec::V2_IE_FTEID)
                            .find_map(|ie| codec::decode_fteid(&ie.value))
                    });
                if let Some((_, teid, address)) = user {
                    a.peer_data_teid = Some(teid);
                    a.peer_data_address = address;
                }
                bearer["fteids"] = Value::Array(data_fteids);
                a.data["bearer"] = bearer;
            }
        }
    }
    if let Some(c2) = a.cause {
        a.data["cause"] = json!(cause_name(c.version, c2));
        a.data["cause_value"] = json!(c2);
        a.data["accepted"] = json!(codec::cause_accepts(c.version, c2));
    }
    if let Some(ip) = a.ue_address {
        a.data["ue_address"] = json!(ip.to_string());
    }
    if let Some(t) = a.peer_control_teid {
        a.data["peer_control_teid"] = json!(t);
    }
    if let Some(t) = a.peer_data_teid {
        a.data["peer_data_teid"] = json!(t);
    }
    if let Some(ip) = a.peer_data_address {
        a.data["peer_data_address"] = json!(ip.to_string());
    }
    a
}

// ===========================================================================
// The user packet inside a G-PDU
// ===========================================================================

/// RFC 1071 one's-complement sum.
pub fn checksum(chunks: &[&[u8]]) -> u16 {
    let mut sum: u32 = 0;
    for chunk in chunks {
        let mut it = chunk.chunks_exact(2);
        for w in &mut it {
            sum += u16::from_be_bytes([w[0], w[1]]) as u32;
        }
        if let [b] = it.remainder() {
            sum += (*b as u32) << 8;
        }
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// The inner packet as the model describes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Inner {
    IcmpEcho {
        identifier: u16,
        sequence: u16,
    },
    Udp {
        source_port: u16,
        destination_port: u16,
    },
}

/// Build an IPv4 packet with correct header and transport checksums. Only IPv4: an IPv6
/// inner packet is refused by the action check before it gets here.
pub fn ipv4_packet(
    source: Ipv4Addr,
    destination: Ipv4Addr,
    ttl: u8,
    identification: u16,
    inner: &Inner,
    payload: &[u8],
) -> Result<Vec<u8>> {
    ensure!(
        payload.len() <= MAX_INNER_PAYLOAD,
        "payload of {} octets is past {MAX_INNER_PAYLOAD}",
        payload.len()
    );
    let (protocol, transport) = match inner {
        Inner::IcmpEcho {
            identifier,
            sequence,
        } => {
            let mut t = vec![8, 0, 0, 0];
            t.extend(identifier.to_be_bytes());
            t.extend(sequence.to_be_bytes());
            t.extend_from_slice(payload);
            let c = checksum(&[&t]);
            t[2..4].copy_from_slice(&c.to_be_bytes());
            (1u8, t)
        }
        Inner::Udp {
            source_port,
            destination_port,
        } => {
            let len = (8 + payload.len()) as u16;
            let mut t = Vec::with_capacity(len as usize);
            t.extend(source_port.to_be_bytes());
            t.extend(destination_port.to_be_bytes());
            t.extend(len.to_be_bytes());
            t.extend([0, 0]);
            t.extend_from_slice(payload);
            let mut pseudo = Vec::with_capacity(12);
            pseudo.extend(source.octets());
            pseudo.extend(destination.octets());
            pseudo.extend([0, 17]);
            pseudo.extend(len.to_be_bytes());
            let mut c = checksum(&[&pseudo, &t]);
            if c == 0 {
                c = 0xFFFF;
            }
            t[6..8].copy_from_slice(&c.to_be_bytes());
            (17u8, t)
        }
    };
    let total = (20 + transport.len()) as u16;
    let mut ip = vec![0x45, 0];
    ip.extend(total.to_be_bytes());
    ip.extend(identification.to_be_bytes());
    ip.extend([0x40, 0]); // Don't Fragment
    ip.push(ttl);
    ip.push(protocol);
    ip.extend([0, 0]);
    ip.extend(source.octets());
    ip.extend(destination.octets());
    let c = checksum(&[&ip]);
    ip[10..12].copy_from_slice(&c.to_be_bytes());
    ip.extend(transport);
    Ok(ip)
}

/// A G-PDU (TS 29.281 §5.1) carrying `packet` to `teid`, with a sequence number.
pub fn gpdu(teid: u32, sequence: u16, packet: &[u8]) -> Vec<u8> {
    GtpV1Message {
        header: GtpV1Header::with_sequence(codec::V1_G_PDU, teid, sequence),
        body: packet.to_vec(),
    }
    .encode()
}

/// End Marker (TS 29.281 §7.3.2): no payload, the tunnel's TEID.
pub fn end_marker(teid: u32) -> Vec<u8> {
    GtpV1Message {
        header: GtpV1Header::new(codec::V1_END_MARKER, teid),
        body: vec![],
    }
    .encode()
}

/// Error Indication (TS 29.281 §7.3.1): TEID Data I is the TEID the offending G-PDU carried,
/// GTP-U Peer Address is this node's user-plane address. Header TEID 0, sequence present.
pub fn error_indication(teid: u32, sequence: u16, own_user_ip: IpAddr) -> Vec<u8> {
    GtpV1Message {
        header: GtpV1Header::with_sequence(codec::V1_ERROR_INDICATION, 0, sequence),
        body: codec::encode_v1_ies(&[
            v1ie(codec::V1_IE_TEID_DATA_I, teid.to_be_bytes().to_vec()),
            v1ie(V1_IE_PEER_ADDRESS, ip_octets(own_user_ip)),
        ]),
    }
    .encode()
}

/// The inner packet of a received G-PDU, for the model: addresses, protocol, ports, ICMP
/// type, checksum verdicts and the payload as text (or hex when it is not text).
pub fn inner_json(packet: &[u8]) -> Value {
    let Some(ip) = codec::decode_inner_ip(packet) else {
        return json!({"decoded": false, "length": packet.len()});
    };
    let mut j = json!({
        "decoded": true,
        "version": ip.version,
        "source": ip.source.to_string(),
        "destination": ip.destination.to_string(),
        "protocol": ip.protocol_name,
        "protocol_number": ip.protocol,
        "ttl": ip.ttl,
        "length": ip.length,
    });
    let mut payload_at = ip.payload_offset;
    if ip.version == 4 {
        let ihl = (packet[0] & 0x0F) as usize * 4;
        if packet.len() >= ihl {
            j["ipv4_header_checksum_ok"] = json!(checksum(&[&packet[..ihl]]) == 0);
            let end = (ip.length as usize).clamp(ihl, packet.len());
            let transport = &packet[ihl..end];
            if ip.protocol == 1 && transport.len() >= 8 {
                j["icmp"] = json!({
                    "type": transport[0],
                    "type_name": match transport[0] { 0 => "echo_reply", 8 => "echo_request", 3 => "destination_unreachable", 11 => "time_exceeded", _ => "other" },
                    "code": transport[1],
                    "identifier": u16::from_be_bytes([transport[4], transport[5]]),
                    "sequence": u16::from_be_bytes([transport[6], transport[7]]),
                    "checksum_ok": checksum(&[transport]) == 0,
                });
                payload_at = Some(ihl + 8);
            }
            if ip.protocol == 17 && transport.len() >= 8 {
                j["source_port"] = json!(ip.source_port);
                j["destination_port"] = json!(ip.destination_port);
                let stored = u16::from_be_bytes([transport[6], transport[7]]);
                if stored != 0 {
                    let mut pseudo = Vec::with_capacity(12);
                    pseudo.extend(ip_octets(ip.source));
                    pseudo.extend(ip_octets(ip.destination));
                    pseudo.extend([0, 17]);
                    pseudo.extend((transport.len() as u16).to_be_bytes());
                    j["udp_checksum_ok"] = json!(checksum(&[&pseudo, transport]) == 0);
                }
            }
        }
    }
    if let Some(at) = payload_at.filter(|at| *at <= packet.len()) {
        let end = if ip.version == 4 {
            (ip.length as usize).clamp(at, packet.len())
        } else {
            packet.len()
        };
        let payload = &packet[at..end];
        let shown = &payload[..payload.len().min(MAX_EVENT_PAYLOAD)];
        let text = std::str::from_utf8(shown)
            .ok()
            .filter(|s| !crate::utils::sanitize::has_controls(&s.replace(char::is_whitespace, "")));
        match text {
            Some(t) => {
                j["payload"] = json!(t);
                j["payload_encoding"] = json!("utf8");
            }
            None => {
                j["payload"] = json!(hex::encode(shown));
                j["payload_encoding"] = json!("hex");
            }
        }
        j["payload_length"] = json!(payload.len());
        if payload.len() > shown.len() {
            j["payload_truncated"] = json!(true);
        }
    }
    j
}
