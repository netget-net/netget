//! DNS resource records as the model writes them: structured JSON, one object per record.
//!
//! ```json
//! {"name": "www.example.com.", "type": "A", "ttl": 300, "ip": "192.0.2.1"}
//! {"name": "@", "type": "SOA", "mname": "ns1.example.com.", "rname": "hostmaster.example.com.",
//!  "serial": 2026101101, "refresh": 3600, "retry": 600, "expire": 604800, "minimum": 300}
//! ```
//!
//! One shape for every type, shared by the multi-record answer (`send_dns_records`) and both
//! zone transfers, so the model learns it once. It is also what retires the hex escape hatch's
//! reason to exist: NS, SOA, PTR and SRV were reachable only through `send_dns_response`'s
//! hand-assembled wire bytes, which the project's rule against raw bytes in actions forbids.
//!
//! A name may be absolute (`www.example.com.`), relative to the zone (`www`, when a zone
//! origin is known), or `@` for the origin itself. Without an origin, a name without a
//! trailing dot is read as absolute — the reading a person means.

use anyhow::{bail, Context, Result};
use hickory_proto::rr::rdata::{self, SOA, SRV};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use serde_json::Value;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use super::actions::MAX_CHARACTER_STRING_LEN;

/// Default TTL when a record does not name one.
pub const DEFAULT_TTL: u32 = 300;

/// The record types the model can write, by name.
pub const SUPPORTED_TYPES: &[&str] =
    &["A", "AAAA", "CNAME", "NS", "PTR", "MX", "TXT", "SRV", "SOA"];

/// Read a name. `@` is `origin`; a name without a trailing dot is relative to `origin` when
/// there is one, and absolute when there is not.
pub fn parse_name(text: &str, origin: Option<&Name>) -> Result<Name> {
    let text = text.trim();
    if text == "@" {
        return origin
            .cloned()
            .context("'@' names the zone apex, and this answer has no zone");
    }
    let mut name = Name::from_str(text).with_context(|| format!("invalid domain name {text:?}"))?;
    if !name.is_fqdn() {
        name = match origin {
            Some(origin) => name
                .append_domain(origin)
                .with_context(|| format!("{text:?} relative to {origin} is too long"))?,
            None => {
                name.set_fqdn(true);
                name
            }
        };
    }
    Ok(name)
}

fn str_field<'a>(v: &'a Value, key: &str, rtype: &str) -> Result<&'a str> {
    v.get(key)
        .and_then(|x| x.as_str())
        .with_context(|| format!("a {rtype} record needs a string '{key}'"))
}

fn u32_field(v: &Value, key: &str, rtype: &str, default: Option<u32>) -> Result<u32> {
    match v.get(key) {
        None | Some(Value::Null) => {
            default.with_context(|| format!("a {rtype} record needs a number '{key}'"))
        }
        Some(x) => {
            let n = x.as_u64().with_context(|| {
                format!("{rtype} '{key}' must be a non-negative number, got {x}")
            })?;
            u32::try_from(n).map_err(|_| anyhow::anyhow!("{rtype} '{key}' {n} is over 2^32-1"))
        }
    }
}

fn u16_field(v: &Value, key: &str, rtype: &str, default: Option<u16>) -> Result<u16> {
    let n = u32_field(v, key, rtype, default.map(u32::from))?;
    u16::try_from(n).map_err(|_| anyhow::anyhow!("{rtype} '{key}' {n} is over 65535"))
}

/// One record. `default_name` is used when the record has no `name` (an answer to the
/// question's own name, the common case).
pub fn record_from_json(
    v: &Value,
    origin: Option<&Name>,
    default_name: Option<&Name>,
) -> Result<Record> {
    if !v.is_object() {
        bail!(
            "a record must be an object like {{\"type\": \"A\", \"ip\": \"192.0.2.1\"}}, got {v}"
        );
    }
    let rtype = v
        .get("type")
        .and_then(|t| t.as_str())
        .context("a record needs a 'type', e.g. \"A\", \"MX\", \"SOA\"")?
        .to_ascii_uppercase();
    let name = match v.get("name").and_then(|n| n.as_str()) {
        Some(n) => parse_name(n, origin)?,
        None => default_name
            .cloned()
            .context("a record needs a 'name' (or '@' for the zone apex)")?,
    };
    let ttl = u32_field(v, "ttl", &rtype, Some(DEFAULT_TTL))?;
    let target = |key: &str| -> Result<Name> { parse_name(str_field(v, key, &rtype)?, origin) };

    let (record_type, data) = match rtype.as_str() {
        "A" => {
            let ip = str_field(v, "ip", "A")?;
            let ip =
                Ipv4Addr::from_str(ip).with_context(|| format!("invalid IPv4 address {ip:?}"))?;
            (RecordType::A, RData::A(rdata::A(ip)))
        }
        "AAAA" => {
            let ip = str_field(v, "ip", "AAAA")?;
            let ip =
                Ipv6Addr::from_str(ip).with_context(|| format!("invalid IPv6 address {ip:?}"))?;
            (RecordType::AAAA, RData::AAAA(rdata::AAAA(ip)))
        }
        "CNAME" => (
            RecordType::CNAME,
            RData::CNAME(rdata::CNAME(target("target")?)),
        ),
        "NS" => (RecordType::NS, RData::NS(rdata::NS(target("target")?))),
        "PTR" => (RecordType::PTR, RData::PTR(rdata::PTR(target("target")?))),
        "MX" => (
            RecordType::MX,
            RData::MX(rdata::MX::new(
                u16_field(v, "preference", "MX", Some(10))?,
                target("exchange")?,
            )),
        ),
        "TXT" => {
            let strings: Vec<String> = match v.get("text") {
                Some(Value::String(s)) => vec![s.clone()],
                Some(Value::Array(items)) => items
                    .iter()
                    .map(|i| {
                        i.as_str()
                            .map(str::to_string)
                            .context("TXT 'text' array items must be strings")
                    })
                    .collect::<Result<_>>()?,
                _ => bail!("a TXT record needs 'text': a string, or an array of strings"),
            };
            if let Some(long) = strings.iter().find(|s| s.len() > MAX_CHARACTER_STRING_LEN) {
                bail!(
                    "a TXT string is {} octets, over the {MAX_CHARACTER_STRING_LEN}-octet \
                     <character-string> limit (RFC 1035 §3.3); split it into an array of \
                     strings",
                    long.len()
                );
            }
            (RecordType::TXT, RData::TXT(rdata::TXT::new(strings)))
        }
        "SRV" => (
            RecordType::SRV,
            RData::SRV(SRV::new(
                u16_field(v, "priority", "SRV", Some(0))?,
                u16_field(v, "weight", "SRV", Some(0))?,
                u16_field(v, "port", "SRV", None)?,
                target("target")?,
            )),
        ),
        "SOA" => (
            RecordType::SOA,
            RData::SOA(SOA::new(
                target("mname")?,
                target("rname")?,
                u32_field(v, "serial", "SOA", None)?,
                u32_field(v, "refresh", "SOA", Some(3600))? as i32,
                u32_field(v, "retry", "SOA", Some(600))? as i32,
                u32_field(v, "expire", "SOA", Some(604_800))? as i32,
                u32_field(v, "minimum", "SOA", Some(DEFAULT_TTL))?,
            )),
        ),
        other => bail!(
            "record type {other:?} is not one this server writes; use one of {}",
            SUPPORTED_TYPES.join(", ")
        ),
    };
    let mut record = Record::with(name, record_type, ttl);
    record.set_data(Some(data));
    Ok(record)
}

/// A list of records, at most `max` of them.
pub fn records_from_json(
    v: Option<&Value>,
    origin: Option<&Name>,
    default_name: Option<&Name>,
    what: &str,
    max: usize,
) -> Result<Vec<Record>> {
    let items = match v {
        None | Some(Value::Null) => return Ok(Vec::new()),
        Some(Value::Array(items)) => items,
        Some(other) => bail!("'{what}' must be an array of records, got {other}"),
    };
    if items.len() > max {
        bail!(
            "'{what}' holds {} records; this server takes at most {max}",
            items.len()
        );
    }
    items
        .iter()
        .enumerate()
        .map(|(i, item)| {
            record_from_json(item, origin, default_name).with_context(|| format!("{what}[{i}]"))
        })
        .collect()
}
