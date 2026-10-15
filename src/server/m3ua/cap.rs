//! CAMEL Application Part (3GPP TS 29.078) circuit-switched call control: the gsmSSF reports a
//! call with InitialDP, the gsmSCF (here, the model) instructs it with Connect, Continue,
//! ReleaseCall and RequestReportBCSMEvent, and armed detection points come back as
//! EventReportBCSM.
//!
//! Application contexts accepted: CAP v2 `{0 4 0 0 1 0 50 1}`, v3 `{0 4 0 0 1 21 3 4}` and v4
//! `{0 4 0 0 1 23 3 4}` gsmSSF-to-gsmSCF. The operations below have the same tags in all three;
//! fields that only exist in later phases are reported by tag. The CAP modules use IMPLICIT
//! TAGS; CHOICEs (bearerCapability, legID) are explicitly tagged.

use super::ber::{self, Tag, Tlv};
use super::gsm::{self, Address};
use serde_json::{json, Map, Value};

pub type CapResult<T> = Result<T, String>;

pub const OP_INITIAL_DP: i64 = 0;
pub const OP_CONNECT: i64 = 20;
pub const OP_RELEASE_CALL: i64 = 22;
pub const OP_REQUEST_REPORT_BCSM_EVENT: i64 = 23;
pub const OP_EVENT_REPORT_BCSM: i64 = 24;
pub const OP_CONTINUE: i64 = 31;
pub const OP_ACTIVITY_TEST: i64 = 55;

/// gsmSSF-to-gsmSCF application contexts by phase.
pub const CONTEXTS: &[(&str, u64, &[u64])] = &[
    ("capV2-gsmSSF-to-gsmSCF", 2, &[0, 4, 0, 0, 1, 0, 50, 1]),
    ("capV3-gsmSSF-scfGeneric", 3, &[0, 4, 0, 0, 1, 21, 3, 4]),
    ("capV4-gsmSSF-scfGeneric", 4, &[0, 4, 0, 0, 1, 23, 3, 4]),
];

pub fn context_of(oid: &[u64]) -> Option<(&'static str, u64)> {
    CONTEXTS
        .iter()
        .find(|(_, _, o)| *o == oid)
        .map(|(n, v, _)| (*n, *v))
}

pub fn context_for_phase(phase: u64) -> Option<&'static [u64]> {
    CONTEXTS
        .iter()
        .find(|(_, v, _)| *v == phase)
        .map(|(_, _, o)| *o)
}

pub const OPERATIONS: &[(&str, i64)] = &[
    ("initialDP", OP_INITIAL_DP),
    ("connect", OP_CONNECT),
    ("releaseCall", OP_RELEASE_CALL),
    ("requestReportBCSMEvent", OP_REQUEST_REPORT_BCSM_EVENT),
    ("eventReportBCSM", OP_EVENT_REPORT_BCSM),
    ("continue", OP_CONTINUE),
    ("activityTest", OP_ACTIVITY_TEST),
];

pub fn operation_name(code: i64) -> Option<&'static str> {
    OPERATIONS.iter().find(|(_, c)| *c == code).map(|(n, _)| *n)
}

pub fn operation_code(name: &str) -> Option<i64> {
    let norm = |s: &str| s.replace(['-', '_'], "").to_ascii_lowercase();
    OPERATIONS
        .iter()
        .find(|(n, _)| norm(n) == norm(name))
        .map(|(_, c)| *c)
}

/// EventTypeBCSM (TS 29.078 section 5.1).
pub const EVENT_TYPES: &[(&str, i64)] = &[
    ("collectedInfo", 2),
    ("analyzedInformation", 3),
    ("routeSelectFailure", 4),
    ("oCalledPartyBusy", 5),
    ("oNoAnswer", 6),
    ("oAnswer", 7),
    ("oMidCall", 8),
    ("oDisconnect", 9),
    ("oAbandon", 10),
    ("termAttemptAuthorized", 12),
    ("tBusy", 13),
    ("tNoAnswer", 14),
    ("tAnswer", 15),
    ("tMidCall", 16),
    ("tDisconnect", 17),
    ("tAbandon", 18),
    ("oTermSeized", 19),
    ("callAccepted", 27),
    ("oChangeOfPosition", 28),
    ("tChangeOfPosition", 29),
    ("oServiceChange", 30),
    ("tServiceChange", 31),
];

pub const MONITOR_MODES: &[&str] = &["interrupted", "notifyAndContinue", "transparent"];

pub const CAP_ERRORS: &[(&str, i64)] = &[
    ("canceled", 0),
    ("cancelFailed", 1),
    ("eTCFailed", 3),
    ("improperCallerResponse", 4),
    ("missingCustomerRecord", 6),
    ("missingParameter", 7),
    ("parameterOutOfRange", 8),
    ("requestedInfoError", 10),
    ("systemFailure", 11),
    ("taskRefused", 12),
    ("unavailableResource", 13),
    ("unexpectedComponentSequence", 14),
    ("unexpectedDataValue", 15),
    ("unexpectedParameter", 16),
    ("unknownLegID", 17),
];

pub fn error_name(code: i64) -> String {
    CAP_ERRORS
        .iter()
        .find(|(_, c)| *c == code)
        .map(|(n, _)| n.to_string())
        .unwrap_or_else(|| format!("error{code}"))
}

fn event_name(v: i64) -> Value {
    EVENT_TYPES
        .iter()
        .find(|(_, c)| *c == v)
        .map(|(n, _)| json!(n))
        .unwrap_or_else(|| json!(v))
}

fn event_value(v: &Value, field: &str) -> CapResult<i64> {
    if let Some(n) = v.as_i64() {
        if EVENT_TYPES.iter().any(|(_, c)| *c == n) {
            return Ok(n);
        }
    }
    let s = v.as_str().unwrap_or_default();
    EVENT_TYPES
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(s))
        .map(|(_, c)| *c)
        .ok_or_else(|| {
            format!(
                "{field} must be one of {}",
                EVENT_TYPES
                    .iter()
                    .map(|(n, _)| *n)
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        })
}

fn ctx(n: u32) -> Tag {
    Tag::context(n, false)
}

fn ctxc(n: u32) -> Tag {
    Tag::context(n, true)
}

fn find(kids: &[Tlv], tag: Tag) -> Option<&Tlv> {
    kids.iter().find(|c| c.tag == tag)
}

/// Decode an Invoke's argument.
pub fn decode_argument(code: i64, p: Option<&Tlv>) -> CapResult<Value> {
    match code {
        OP_CONTINUE | OP_ACTIVITY_TEST => return Ok(json!({})),
        OP_RELEASE_CALL => {
            let p = p.ok_or("releaseCall without a cause")?;
            return Ok(json!({"cause": gsm::cause_decode(&p.value)}));
        }
        _ => {}
    }
    let p = p.ok_or("the operation's argument is missing")?;
    let kids = &p.children;
    let mut out = Map::new();
    let used: Vec<Tag> = match code {
        OP_INITIAL_DP => {
            out.insert(
                "service_key".into(),
                json!(find(kids, ctx(0))
                    .ok_or("serviceKey [0] missing")?
                    .as_i64()
                    .map_err(|e| e.0)?),
            );
            let num = |n: u32| find(kids, ctx(n)).map(|t| gsm::isup_number_decode(&t.value));
            out.insert("called_party_number".into(), json!(num(2)));
            out.insert("calling_party_number".into(), json!(num(3)));
            out.insert(
                "calling_partys_category".into(),
                json!(find(kids, ctx(5)).and_then(|t| t.value.first().copied())),
            );
            out.insert("location_number".into(), json!(num(10)));
            out.insert(
                "event_type_bcsm".into(),
                find(kids, ctx(28))
                    .and_then(|t| t.as_i64().ok())
                    .map(event_name)
                    .unwrap_or(Value::Null),
            );
            out.insert(
                "imsi".into(),
                json!(find(kids, ctx(50)).map(|t| gsm::tbcd_decode(&t.value))),
            );
            out.insert(
                "call_reference_number".into(),
                json!(find(kids, ctx(54)).map(|t| ber::hex(&t.value))),
            );
            let addr = |n: u32| {
                find(kids, ctx(n))
                    .and_then(|t| Address::decode(&t.value).ok())
                    .map(|a| a.to_json())
            };
            out.insert("msc_address".into(), json!(addr(55)));
            out.insert("called_party_bcd_number".into(), json!(addr(56)));
            out.insert(
                "location_information_present".into(),
                json!(find(kids, ctxc(52)).is_some()),
            );
            vec![
                ctx(0),
                ctx(2),
                ctx(3),
                ctx(5),
                ctx(10),
                ctx(28),
                ctx(50),
                ctxc(52),
                ctx(54),
                ctx(55),
                ctx(56),
            ]
        }
        OP_CONNECT => {
            let dra = find(kids, ctxc(0)).ok_or("destinationRoutingAddress [0] missing")?;
            out.insert(
                "destination_routing_address".into(),
                json!(dra
                    .children
                    .iter()
                    .map(|n| gsm::isup_number_decode(&n.value))
                    .collect::<Vec<_>>()),
            );
            out.insert(
                "suppression_of_announcement".into(),
                json!(find(kids, ctx(55)).is_some()),
            );
            vec![ctxc(0), ctx(55)]
        }
        OP_REQUEST_REPORT_BCSM_EVENT => {
            let events = find(kids, ctxc(0)).ok_or("bcsmEvents [0] missing")?;
            if events.children.len() > 30 {
                return Err("more than 30 BCSM events".into());
            }
            let mut list = Vec::new();
            for e in &events.children {
                let ev = find(&e.children, ctx(0)).and_then(|t| t.as_i64().ok());
                let mode = find(&e.children, ctx(1)).and_then(|t| t.as_i64().ok());
                let leg = find(&e.children, ctxc(2))
                    .and_then(|l| l.children.first())
                    .map(|c| {
                        json!({
                            "side": if c.tag.number == 0 { "sending" } else { "receiving" },
                            "leg_type": c.value.first().copied(),
                        })
                    });
                list.push(json!({
                    "event_type_bcsm": ev.map(event_name),
                    "monitor_mode": mode.and_then(|m| MONITOR_MODES.get(m as usize).copied()),
                    "leg_id": leg,
                }));
            }
            out.insert("bcsm_events".into(), json!(list));
            vec![ctxc(0)]
        }
        OP_EVENT_REPORT_BCSM => {
            out.insert(
                "event_type_bcsm".into(),
                find(kids, ctx(0))
                    .and_then(|t| t.as_i64().ok())
                    .map(event_name)
                    .ok_or("eventTypeBCSM [0] missing")?,
            );
            out.insert(
                "leg_id".into(),
                json!(find(kids, ctxc(3))
                    .and_then(|l| l.children.first())
                    .and_then(|c| c.value.first().copied())),
            );
            out.insert(
                "message_type".into(),
                json!(match find(kids, ctxc(4))
                    .and_then(|m| m.ctx(0))
                    .and_then(|t| t.as_i64().ok())
                {
                    Some(1) => "notification",
                    _ => "request",
                }),
            );
            out.insert(
                "event_specific_information_present".into(),
                json!(find(kids, ctxc(2)).is_some()),
            );
            vec![ctx(0), ctxc(2), ctxc(3), ctxc(4)]
        }
        other => return Err(format!("CAP operation {other} is not implemented")),
    };
    let rest: Vec<String> = kids
        .iter()
        .filter(|c| !used.contains(&c.tag))
        .map(|c| c.tag.label())
        .collect();
    out.insert("uninterpreted".into(), json!(rest));
    Ok(Value::Object(out))
}

/// Encode an Invoke's argument. `None` for the operations that take none.
pub fn encode_argument(code: i64, v: &Value) -> CapResult<Option<Vec<u8>>> {
    Ok(Some(match code {
        OP_CONTINUE | OP_ACTIVITY_TEST => return Ok(None),
        OP_RELEASE_CALL => {
            let cause = v
                .get("cause")
                .cloned()
                .unwrap_or(json!("normal_unspecified"));
            ber::tlv(Tag::OCTET_STRING, &gsm::cause_encode(&cause)?)
        }
        OP_CONNECT => {
            let dra = v
                .get("destination_routing_address")
                .ok_or("destination_routing_address is required")?;
            let first = match dra {
                Value::Array(a) => {
                    if a.len() != 1 {
                        return Err(
                            "destination_routing_address holds exactly one number in CAP".into(),
                        );
                    }
                    a[0].clone()
                }
                other => other.clone(),
            };
            let mut parts = vec![ber::seq(
                ctxc(0),
                &[ber::tlv(
                    Tag::OCTET_STRING,
                    &gsm::isup_number_encode(&first, "destination_routing_address", false)?,
                )],
            )];
            if v.get("suppression_of_announcement")
                .and_then(Value::as_bool)
                == Some(true)
            {
                parts.push(ber::tlv(ctx(55), &[]));
            }
            ber::seq(Tag::SEQUENCE, &parts)
        }
        OP_REQUEST_REPORT_BCSM_EVENT => {
            let events = v
                .get("bcsm_events")
                .and_then(Value::as_array)
                .ok_or("bcsm_events is required (a list)")?;
            if events.is_empty() || events.len() > 30 {
                return Err("bcsm_events must hold 1..30 events".into());
            }
            let mut list = Vec::new();
            for (i, e) in events.iter().enumerate() {
                let field = format!("bcsm_events[{i}]");
                let ev = event_value(
                    e.get("event_type_bcsm").unwrap_or(&Value::Null),
                    &format!("{field}.event_type_bcsm"),
                )?;
                let mode = e
                    .get("monitor_mode")
                    .and_then(Value::as_str)
                    .unwrap_or("notifyAndContinue");
                let m = MONITOR_MODES
                    .iter()
                    .position(|x| *x == mode)
                    .ok_or_else(|| {
                        format!(
                            "{field}.monitor_mode must be one of {}",
                            MONITOR_MODES.join(", ")
                        )
                    })?;
                let mut parts = vec![ber::integer(ctx(0), ev), ber::integer(ctx(1), m as i64)];
                // Leg 2 (the called party) for the answer/busy/no-answer family; leg 1 otherwise,
                // unless the model names it.
                let leg = e.get("leg").and_then(Value::as_u64).unwrap_or(match ev {
                    5..=7 | 9 => 2,
                    _ => 1,
                });
                if !(1..=2).contains(&leg) {
                    return Err(format!("{field}.leg must be 1 or 2"));
                }
                // In a request the SCF names the leg as sendingSideID [0]; the gsmSSF reports
                // back with receivingSideID.
                if ev != 2 && ev != 3 {
                    parts.push(ber::seq(ctxc(2), &[ber::tlv(ctx(0), &[leg as u8])]));
                }
                list.push(ber::seq(Tag::SEQUENCE, &parts));
            }
            ber::seq(Tag::SEQUENCE, &[ber::seq(ctxc(0), &list)])
        }
        OP_EVENT_REPORT_BCSM => {
            let ev = event_value(
                v.get("event_type_bcsm").unwrap_or(&Value::Null),
                "event_type_bcsm",
            )?;
            let leg = v
                .get("leg")
                .and_then(Value::as_u64)
                .unwrap_or(2)
                .clamp(1, 2) as u8;
            let notification =
                v.get("message_type").and_then(Value::as_str) == Some("notification");
            ber::seq(
                Tag::SEQUENCE,
                &[
                    ber::integer(ctx(0), ev),
                    ber::seq(ctxc(3), &[ber::tlv(ctx(1), &[leg])]),
                    ber::seq(ctxc(4), &[ber::integer(ctx(0), notification as i64)]),
                ],
            )
        }
        OP_INITIAL_DP => {
            let sk = v
                .get("service_key")
                .and_then(Value::as_i64)
                .filter(|k| (0..=2147483647).contains(k))
                .ok_or("service_key is required (0..2147483647)")?;
            let mut parts = vec![ber::integer(ctx(0), sk)];
            if let Some(n) = v.get("called_party_number").filter(|x| !x.is_null()) {
                parts.push(ber::tlv(
                    ctx(2),
                    &gsm::isup_number_encode(n, "called_party_number", false)?,
                ));
            }
            if let Some(n) = v.get("calling_party_number").filter(|x| !x.is_null()) {
                parts.push(ber::tlv(
                    ctx(3),
                    &gsm::isup_number_encode(n, "calling_party_number", true)?,
                ));
            }
            parts.push(ber::tlv(
                ctx(5),
                &[v.get("calling_partys_category")
                    .and_then(Value::as_u64)
                    .unwrap_or(10)
                    .min(255) as u8],
            ));
            let ev = match v.get("event_type_bcsm") {
                Some(e) => event_value(e, "event_type_bcsm")?,
                None => 2,
            };
            parts.push(ber::integer(ctx(28), ev));
            if let Some(i) = v.get("imsi").and_then(Value::as_str) {
                parts.push(ber::tlv(ctx(50), &gsm::imsi_encode(i)?));
            }
            if let Some(a) = v.get("msc_address").filter(|x| !x.is_null()) {
                let a = Address::from_json(a, "msc_address")?;
                parts.push(ber::tlv(ctx(55), &a.encode(gsm::MAX_ISDN_ADDRESS_DIGITS)?));
            }
            if let Some(a) = v.get("called_party_bcd_number").filter(|x| !x.is_null()) {
                let a = Address::from_json(a, "called_party_bcd_number")?;
                parts.push(ber::tlv(ctx(56), &a.encode(40)?));
            }
            ber::seq(Tag::SEQUENCE, &parts)
        }
        other => return Err(format!("CAP operation {other} is not implemented")),
    }))
}
