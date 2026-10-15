//! H.225.0 values: transport and alias addresses, endpoint types, identifiers, and the RAS and
//! call-signalling message envelopes, all as the JSON the PER codec reads and writes.
//!
//! Model-facing aliases are strings `"<kind>:<value>"`, with the kind named as H.225.0 names
//! the `AliasAddress` alternative (`h323-ID:alice`, `dialledDigits:1001`, `url-ID:h323:a@b`,
//! `email-ID:a@b`, `transportID:10.0.0.1:1720`). The model may also write a bare value: digits
//! (`0-9 # * ,`) become `dialledDigits`, anything else `h323-ID`.

use super::per;
use super::schema;
use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Value};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// H.225.0 version 4: what NetGet claims to speak.
pub const PROTOCOL_ID: &str = "0.0.8.2250.0.4";
/// The most aliases one registration may hold, and one message may carry from the model.
pub const MAX_ALIASES: usize = 16;
/// Longest alias value NetGet will put on the wire (h323-ID allows 256 characters).
pub const MAX_ALIAS_CHARS: usize = 128;

pub fn transport(addr: SocketAddr) -> Value {
    match addr.ip() {
        IpAddr::V4(ip) => {
            json!({"ipAddress": {"ip": hex::encode(ip.octets()), "port": addr.port()}})
        }
        IpAddr::V6(ip) => {
            json!({"ip6Address": {"ip": hex::encode(ip.octets()), "port": addr.port()}})
        }
    }
}

/// A `TransportAddress` as a socket address, when it is an IP one.
pub fn socket_addr(v: &Value) -> Option<SocketAddr> {
    if let Some(a) = v.get("ipAddress") {
        let ip: [u8; 4] = hex::decode(a.get("ip")?.as_str()?).ok()?.try_into().ok()?;
        let port = u16::try_from(a.get("port")?.as_u64()?).ok()?;
        return Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), port));
    }
    if let Some(a) = v.get("ip6Address") {
        let ip: [u8; 16] = hex::decode(a.get("ip")?.as_str()?).ok()?.try_into().ok()?;
        let port = u16::try_from(a.get("port")?.as_u64()?).ok()?;
        return Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip)), port));
    }
    None
}

/// A `TransportAddress` for display: `ip:port`, or the alternative's name.
pub fn transport_text(v: &Value) -> String {
    match socket_addr(v) {
        Some(a) => a.to_string(),
        None => v
            .as_object()
            .and_then(|o| o.keys().next().cloned())
            .unwrap_or_else(|| "unknown".into()),
    }
}

pub fn addresses_text(v: Option<&Value>) -> Vec<String> {
    v.and_then(|a| a.as_array())
        .map(|a| a.iter().map(transport_text).collect())
        .unwrap_or_default()
}

/// The first IP address in a SEQUENCE OF TransportAddress.
pub fn first_socket_addr(v: Option<&Value>) -> Option<SocketAddr> {
    v?.as_array()?.iter().find_map(socket_addr)
}

const DIALLED: &str = "0123456789#*,";

/// A model-written alias as an `AliasAddress`.
pub fn alias(s: &str) -> Result<Value> {
    if crate::utils::sanitize::has_controls(s) {
        bail!("alias {s:?} contains a control character");
    }
    let (kind, value) = match s.split_once(':') {
        Some((k, v))
            if matches!(
                k,
                "h323-ID"
                    | "h323_id"
                    | "dialledDigits"
                    | "e164"
                    | "url-ID"
                    | "url"
                    | "email-ID"
                    | "email"
                    | "transportID"
            ) =>
        {
            (k, v)
        }
        _ if !s.is_empty() && s.chars().all(|c| DIALLED.contains(c)) => ("dialledDigits", s),
        _ => ("h323-ID", s),
    };
    if value.is_empty() || value.chars().count() > MAX_ALIAS_CHARS {
        bail!("alias {s:?}: the value must be 1 to {MAX_ALIAS_CHARS} characters");
    }
    Ok(match kind {
        "dialledDigits" | "e164" => {
            if !value.chars().all(|c| DIALLED.contains(c)) {
                bail!("dialledDigits {value:?} may only hold 0-9 # * ,");
            }
            json!({"dialledDigits": value})
        }
        "url-ID" | "url" => {
            if !value.is_ascii() {
                bail!("url-ID {value:?} must be ASCII");
            }
            json!({"url-ID": value})
        }
        "email-ID" | "email" => {
            if !value.is_ascii() {
                bail!("email-ID {value:?} must be ASCII");
            }
            json!({"email-ID": value})
        }
        "transportID" => {
            let addr: SocketAddr = value
                .parse()
                .with_context(|| format!("transportID {value:?} is not ip:port"))?;
            json!({"transportID": transport(addr)})
        }
        _ => json!({"h323-ID": value}),
    })
}

/// A list of model-written aliases.
pub fn aliases(v: &Value) -> Result<Vec<Value>> {
    let list: Vec<&Value> = match v {
        Value::String(_) => vec![v],
        Value::Array(a) => a.iter().collect(),
        _ => bail!("aliases are a string or a list of strings"),
    };
    if list.len() > MAX_ALIASES {
        bail!("at most {MAX_ALIASES} aliases");
    }
    list.into_iter()
        .map(|a| {
            a.as_str()
                .ok_or_else(|| anyhow!("an alias is a string"))
                .and_then(alias)
        })
        .collect()
}

/// An `AliasAddress` for the model: `kind:value`, the value stripped of control characters.
pub fn alias_text(v: &Value) -> String {
    let Some((kind, value)) = v.as_object().and_then(|o| o.iter().next()) else {
        return "unknown".into();
    };
    let text = match (kind.as_str(), value) {
        ("transportID", t) => transport_text(t),
        ("partyNumber", p) => party_number_text(p),
        (_, Value::String(s)) => s.clone(),
        (_, other) => other.to_string(),
    };
    format!("{kind}:{}", crate::utils::sanitize::strip_controls(&text))
}

fn party_number_text(p: &Value) -> String {
    let Some((_, inner)) = p.as_object().and_then(|o| o.iter().next()) else {
        return String::new();
    };
    match inner {
        Value::String(s) => s.clone(),
        Value::Object(o) => o
            .values()
            .find_map(|v| v.as_str().map(str::to_string))
            .unwrap_or_default(),
        _ => String::new(),
    }
}

pub fn aliases_text(v: Option<&Value>) -> Vec<String> {
    v.and_then(|a| a.as_array())
        .map(|a| a.iter().map(alias_text).collect())
        .unwrap_or_default()
}

/// Whether two `AliasAddress` values name the same alias (h323-ID compared case-insensitively,
/// as gatekeepers do).
pub fn same_alias(a: &Value, b: &Value) -> bool {
    match (a.get("h323-ID"), b.get("h323-ID")) {
        (Some(x), Some(y)) => x
            .as_str()
            .zip(y.as_str())
            .is_some_and(|(x, y)| x.eq_ignore_ascii_case(y)),
        _ => a == b,
    }
}

/// This endpoint's `EndpointType`: a terminal, with NetGet as the vendor.
pub fn endpoint_type(kind: &str) -> Value {
    let mut v = json!({
        "vendor": vendor(),
        "mc": false,
        "undefinedNode": false,
    });
    v[kind] = json!({});
    v
}

pub fn vendor() -> Value {
    json!({
        // T.35 country code 181 (United States), manufacturer 0x4e47 ("NG"): an unassigned
        // code, which is what an implementation without a T.35 registration writes.
        "vendor": {"t35CountryCode": 181, "t35Extension": 0, "manufacturerCode": 0x4e47},
        "productId": hex::encode("NetGet"),
        "versionId": hex::encode(env!("CARGO_PKG_VERSION")),
    })
}

/// What kind of node an `EndpointType` describes, and its vendor strings, for the model.
pub fn endpoint_summary(v: Option<&Value>) -> Value {
    let Some(v) = v else {
        return Value::Null;
    };
    let kind = ["terminal", "gateway", "mcu", "gatekeeper"]
        .into_iter()
        .find(|k| v.get(*k).is_some())
        .unwrap_or("undefined");
    let text = |field: &str| {
        v.get("vendor")
            .and_then(|vd| vd.get(field))
            .and_then(|h| h.as_str())
            .and_then(|h| hex::decode(h).ok())
            .map(|raw| {
                let s = String::from_utf8_lossy(&raw);
                crate::utils::sanitize::strip_controls(s.trim_end_matches('\0'))
            })
    };
    json!({
        "kind": kind,
        "product": text("productId"),
        "version": text("versionId"),
    })
}

/// A fresh 16-octet GloballyUniqueID / ConferenceIdentifier, as hex.
pub fn new_guid() -> String {
    let raw: [u8; 16] = rand::random();
    hex::encode(raw)
}

// ---------------------------------------------------------------------------------------------
// RAS
// ---------------------------------------------------------------------------------------------

/// Decode one RAS datagram: the message's alternative name and its body.
pub fn decode_ras(datagram: &[u8]) -> Result<(String, Value)> {
    let v = per::decode(schema::H225_RASMESSAGE, datagram).map_err(|e| anyhow!("{e}"))?;
    split_choice(v)
}

pub fn encode_ras(kind: &str, body: Value) -> Result<Vec<u8>> {
    per::encode(schema::H225_RASMESSAGE, &json!({ kind: body })).map_err(|e| anyhow!("{e}"))
}

pub fn split_choice(v: Value) -> Result<(String, Value)> {
    match v {
        Value::Object(o) if o.len() == 1 => {
            let (k, v) = o.into_iter().next().expect("one key");
            Ok((k, v))
        }
        other => bail!("not a CHOICE value: {other}"),
    }
}

/// The request sequence number of any decoded RAS message.
pub fn seq_num(body: &Value) -> Option<u16> {
    body.get("requestSeqNum")?
        .as_u64()
        .and_then(|n| u16::try_from(n).ok())
}

/// The short names gatekeepers and analysers use (GRQ, RCF, ...).
pub fn ras_abbreviation(kind: &str) -> &'static str {
    match kind {
        "gatekeeperRequest" => "GRQ",
        "gatekeeperConfirm" => "GCF",
        "gatekeeperReject" => "GRJ",
        "registrationRequest" => "RRQ",
        "registrationConfirm" => "RCF",
        "registrationReject" => "RRJ",
        "unregistrationRequest" => "URQ",
        "unregistrationConfirm" => "UCF",
        "unregistrationReject" => "URJ",
        "admissionRequest" => "ARQ",
        "admissionConfirm" => "ACF",
        "admissionReject" => "ARJ",
        "bandwidthRequest" => "BRQ",
        "bandwidthConfirm" => "BCF",
        "bandwidthReject" => "BRJ",
        "disengageRequest" => "DRQ",
        "disengageConfirm" => "DCF",
        "disengageReject" => "DRJ",
        "locationRequest" => "LRQ",
        "locationConfirm" => "LCF",
        "locationReject" => "LRJ",
        "infoRequest" => "IRQ",
        "infoRequestResponse" => "IRR",
        "nonStandardMessage" => "NSM",
        "unknownMessageResponse" => "XRS",
        "requestInProgress" => "RIP",
        "resourcesAvailableIndicate" => "RAI",
        "resourcesAvailableConfirm" => "RAC",
        "infoRequestAck" => "IACK",
        "infoRequestNak" => "INAK",
        "serviceControlIndication" => "SCI",
        "serviceControlResponse" => "SCR",
        "admissionConfirmSequence" => "ACF-seq",
        _ => "RAS",
    }
}

/// The name of the single alternative of a reject-reason CHOICE.
pub fn choice_name(v: Option<&Value>) -> String {
    v.and_then(|r| r.as_object())
        .and_then(|o| o.keys().next().cloned())
        .unwrap_or_else(|| "unknown".into())
}

// ---------------------------------------------------------------------------------------------
// Call signalling
// ---------------------------------------------------------------------------------------------

/// A decoded `H323-UserInformation`: the body's alternative name, the body, and the PDU.
pub struct UserInformation {
    pub kind: String,
    pub body: Value,
    pub pdu: Value,
}

impl UserInformation {
    pub fn h245_tunnelling(&self) -> bool {
        self.pdu
            .get("h245Tunnelling")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
    }

    /// The tunnelled H.245 messages, each one PER encoding.
    pub fn h245_control(&self) -> Vec<Vec<u8>> {
        self.pdu
            .get("h245Control")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|m| m.as_str().and_then(|h| hex::decode(h).ok()))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The fastStart elements, each one PER-encoded OpenLogicalChannel.
    pub fn fast_start(&self) -> Vec<Vec<u8>> {
        self.body
            .get("fastStart")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|m| m.as_str().and_then(|h| hex::decode(h).ok()))
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn call_identifier(&self) -> Option<String> {
        self.body
            .get("callIdentifier")
            .and_then(|c| c.get("guid"))
            .and_then(|g| g.as_str())
            .map(str::to_string)
    }
}

pub fn decode_user_information(per_bytes: &[u8]) -> Result<UserInformation> {
    let v =
        per::decode(schema::H225_H323_USERINFORMATION, per_bytes).map_err(|e| anyhow!("{e}"))?;
    let pdu = v
        .get("h323-uu-pdu")
        .cloned()
        .ok_or_else(|| anyhow!("no h323-uu-pdu"))?;
    let (kind, body) = split_choice(
        pdu.get("h323-message-body")
            .cloned()
            .ok_or_else(|| anyhow!("no h323-message-body"))?,
    )?;
    Ok(UserInformation { kind, body, pdu })
}

/// Encode an `H323-UserInformation` with the given body, tunnelling flag and tunnelled H.245.
pub fn encode_user_information(
    kind: &str,
    body: Value,
    tunnelling: bool,
    h245: &[Vec<u8>],
) -> Result<Vec<u8>> {
    let mut pdu = json!({
        "h323-message-body": { kind: body },
        "h245Tunnelling": tunnelling,
    });
    if !h245.is_empty() {
        pdu["h245Control"] = Value::Array(h245.iter().map(|m| json!(hex::encode(m))).collect());
    }
    per::encode(
        schema::H225_H323_USERINFORMATION,
        &json!({ "h323-uu-pdu": pdu }),
    )
    .map_err(|e| anyhow!("{e}"))
}
