//! MAP (3GPP TS 29.002) operations NetGet implements: their application contexts, operation
//! codes, and the mapping between each argument/result and the structured JSON the model reads
//! and writes. The model never sees BER: an `anyTimeInterrogation` arrives as
//! `{"subscriber": {"msisdn": {...}}, "requested_info": [...]}` and its answer leaves as
//! `{"subscriber_state": "assumedIdle", "location_information": {...}}`, encoded here.
//!
//! Implemented (MAP v3 syntax unless noted):
//!
//! | Operation | Code | Context | Typical answering node |
//! |---|---|---|---|
//! | updateLocation | 2 | networkLocUpContext v3 | HLR |
//! | sendRoutingInfo | 22 | locationInfoRetrievalContext v3 | HLR |
//! | mt-forwardSM | 44 | shortMsgMTRelayContext v3 | MSC |
//! | sendRoutingInfoForSM | 45 | shortMsgGatewayContext v3 | HLR |
//! | mo-forwardSM | 46 | shortMsgMORelayContext v3 | SMSC |
//! | processUnstructuredSS-Request | 59 | networkUnstructuredSsContext v2 | HLR / USSD gateway |
//! | unstructuredSS-Request | 60 | networkUnstructuredSsContext v2 | MSC (towards the handset) |
//! | unstructuredSS-Notify | 61 | networkUnstructuredSsContext v2 | MSC |
//! | anyTimeInterrogation | 71 | anyTimeEnquiryContext v3 | HLR |
//!
//! Every argument is decoded field by field with the tags TS 29.002 gives them (the module uses
//! IMPLICIT TAGS; CHOICEs are explicitly tagged). Extension containers and fields not listed
//! are reported by tag in `uninterpreted` rather than dropped silently.

use super::ber::{self, Tag, Tlv};
use super::gsm::{self, Address};
use serde_json::{json, Map, Value};

pub type MapResult<T> = Result<T, String>;

/// `{0 4 0 0 1 0 <ac> <version>}`.
pub fn acn(ac: u64, version: u64) -> Vec<u64> {
    vec![0, 4, 0, 0, 1, 0, ac, version]
}

/// MAP application contexts NetGet names.
pub const CONTEXTS: &[(&str, u64)] = &[
    ("networkLocUpContext", 1),
    ("locationInfoRetrievalContext", 5),
    ("infoRetrievalContext", 14),
    ("subscriberDataMngtContext", 16),
    ("networkUnstructuredSsContext", 19),
    ("shortMsgGatewayContext", 20),
    ("shortMsgMORelayContext", 21),
    ("shortMsgMTRelayContext", 25),
    ("anyTimeEnquiryContext", 29),
];

/// If `oid` is a MAP application context, its name and version.
pub fn context_of(oid: &[u64]) -> Option<(&'static str, u64)> {
    if oid.len() != 8 || oid[..6] != [0, 4, 0, 0, 1, 0] {
        return None;
    }
    // Only the contexts NetGet names: CAMEL v2's {0 4 0 0 1 0 50 1} shares this prefix, and an
    // unknown context must be refused rather than read as MAP.
    CONTEXTS
        .iter()
        .find(|(_, c)| *c == oid[6])
        .map(|(n, _)| (*n, oid[7]))
}

/// One implemented operation.
pub struct Operation {
    pub name: &'static str,
    pub code: i64,
    pub context: u64,
    pub version: u64,
    /// Whether the operation is answered by a result (class 1); the notify has none.
    pub has_result: bool,
}

pub const OPERATIONS: &[Operation] = &[
    Operation {
        name: "updateLocation",
        code: 2,
        context: 1,
        version: 3,
        has_result: true,
    },
    Operation {
        name: "sendRoutingInfo",
        code: 22,
        context: 5,
        version: 3,
        has_result: true,
    },
    Operation {
        name: "mt-forwardSM",
        code: 44,
        context: 25,
        version: 3,
        has_result: true,
    },
    Operation {
        name: "sendRoutingInfoForSM",
        code: 45,
        context: 20,
        version: 3,
        has_result: true,
    },
    Operation {
        name: "mo-forwardSM",
        code: 46,
        context: 21,
        version: 3,
        has_result: true,
    },
    Operation {
        name: "processUnstructuredSS-Request",
        code: 59,
        context: 19,
        version: 2,
        has_result: true,
    },
    Operation {
        name: "unstructuredSS-Request",
        code: 60,
        context: 19,
        version: 2,
        has_result: true,
    },
    Operation {
        name: "unstructuredSS-Notify",
        code: 61,
        context: 19,
        version: 2,
        has_result: true,
    },
    Operation {
        name: "anyTimeInterrogation",
        code: 71,
        context: 29,
        version: 3,
        has_result: true,
    },
];

pub fn operation_by_code(code: i64) -> Option<&'static Operation> {
    OPERATIONS.iter().find(|o| o.code == code)
}

pub fn operation_by_name(name: &str) -> Option<&'static Operation> {
    let norm = |s: &str| s.replace(['-', '_'], "").to_ascii_lowercase();
    OPERATIONS.iter().find(|o| norm(o.name) == norm(name))
}

pub fn operation_names() -> String {
    OPERATIONS
        .iter()
        .map(|o| o.name)
        .collect::<Vec<_>>()
        .join(", ")
}

/// MAP error codes (TS 29.002 section 17.6.6) by name.
pub const ERRORS: &[(&str, i64)] = &[
    ("unknownSubscriber", 1),
    ("unknownMSC", 3),
    ("unidentifiedSubscriber", 5),
    ("absentSubscriberSM", 6),
    ("unknownEquipment", 7),
    ("roamingNotAllowed", 8),
    ("illegalSubscriber", 9),
    ("bearerServiceNotProvisioned", 10),
    ("teleserviceNotProvisioned", 11),
    ("illegalEquipment", 12),
    ("callBarred", 13),
    ("forwardingViolation", 14),
    ("cug-Reject", 15),
    ("illegalSS-Operation", 16),
    ("ss-ErrorStatus", 17),
    ("ss-NotAvailable", 18),
    ("ss-SubscriptionViolation", 19),
    ("ss-Incompatibility", 20),
    ("facilityNotSupported", 21),
    ("absentSubscriber", 27),
    ("subscriberBusyForMT-SMS", 31),
    ("sm-DeliveryFailure", 32),
    ("messageWaitingListFull", 33),
    ("systemFailure", 34),
    ("dataMissing", 35),
    ("unexpectedDataValue", 36),
    ("noRoamingNumberAvailable", 39),
    ("busySubscriber", 45),
    ("noSubscriberReply", 46),
    ("ati-NotAllowed", 49),
    ("resourceLimitation", 51),
    ("unknownAlphabet", 71),
    ("ussd-Busy", 72),
];

pub const ERROR_SYSTEM_FAILURE: i64 = 34;

pub fn error_name(code: i64) -> String {
    ERRORS
        .iter()
        .find(|(_, c)| *c == code)
        .map(|(n, _)| n.to_string())
        .unwrap_or_else(|| format!("error{code}"))
}

/// An error by name (case and punctuation insensitive) or by code.
pub fn error_code(v: &Value) -> MapResult<i64> {
    if let Some(n) = v.as_i64() {
        if ERRORS.iter().any(|(_, c)| *c == n) {
            return Ok(n);
        }
        return Err(format!("MAP error code {n} is not one NetGet names"));
    }
    let s = v.as_str().ok_or("error must be a MAP error name or code")?;
    let norm = |x: &str| x.replace(['-', '_'], "").to_ascii_lowercase();
    ERRORS
        .iter()
        .find(|(n, _)| norm(n) == norm(s))
        .map(|(_, c)| *c)
        .ok_or_else(|| {
            format!(
                "{s:?} is not a MAP error; use one of {}",
                ERRORS
                    .iter()
                    .map(|(n, _)| *n)
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        })
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

fn addr(t: &Tlv) -> Value {
    Address::decode(&t.value)
        .map(|a| a.to_json())
        .unwrap_or_else(|e| json!({ "error": e }))
}

fn imsi(t: &Tlv) -> Value {
    json!(gsm::tbcd_decode(&t.value))
}

fn address_tlv(tag: Tag, v: &Value, field: &str, max_digits: usize) -> MapResult<Vec<u8>> {
    let a = Address::from_json(v, field)?;
    Ok(ber::tlv(tag, &a.encode(max_digits)?))
}

fn required<'a>(v: &'a Value, field: &str) -> MapResult<&'a Value> {
    v.get(field)
        .filter(|x| !x.is_null())
        .ok_or_else(|| format!("{field} is required"))
}

fn imsi_tlv(tag: Tag, v: &Value, field: &str) -> MapResult<Vec<u8>> {
    let s = v
        .as_str()
        .ok_or_else(|| format!("{field} must be a digit string"))?;
    Ok(ber::tlv(tag, &gsm::imsi_encode(s)?))
}

fn seq_children(t: &Tlv, what: &str) -> MapResult<Vec<Tlv>> {
    if t.tag != Tag::SEQUENCE && !(t.tag.constructed) {
        return Err(format!("{what} is {}, expected a SEQUENCE", t.tag.label()));
    }
    Ok(t.children.clone())
}

/// Tags present that the mapping below did not consume.
fn leftovers(children: &[Tlv], used: &[Tag]) -> Vec<String> {
    children
        .iter()
        .filter(|c| !used.contains(&c.tag))
        .map(|c| c.tag.label())
        .collect()
}

fn ctx(n: u32) -> Tag {
    Tag::context(n, false)
}

fn ctxc(n: u32) -> Tag {
    Tag::context(n, true)
}

// ---------------------------------------------------------------------------
// Arguments
// ---------------------------------------------------------------------------

/// Decode an Invoke's argument for `code`. `mobile_originated` matters only for forwardSM's
/// TPDU direction.
pub fn decode_argument(code: i64, p: Option<&Tlv>) -> MapResult<Value> {
    let Some(p) = p else {
        return Err("the operation's argument is missing".into());
    };
    let kids = seq_children(p, "argument")?;
    let find = |tag: Tag| kids.iter().find(|c| c.tag == tag);
    let mut out = Map::new();
    let used: Vec<Tag> = match code {
        45 => {
            out.insert(
                "msisdn".into(),
                find(ctx(0)).map(addr).ok_or("msisdn [0] missing")?,
            );
            out.insert(
                "sm_rp_pri".into(),
                json!(find(ctx(1))
                    .map(|b| b.as_bool())
                    .transpose()
                    .map_err(|e| e.0)?),
            );
            out.insert(
                "service_centre_address".into(),
                find(ctx(2))
                    .map(addr)
                    .ok_or("serviceCentreAddress [2] missing")?,
            );
            out.insert(
                "gprs_support_indicator".into(),
                json!(find(ctx(7)).is_some()),
            );
            vec![ctx(0), ctx(1), ctx(2), ctx(7)]
        }
        71 => {
            let ident = find(ctxc(0)).ok_or("subscriberIdentity [0] missing")?;
            let sub = match ident.children.first() {
                Some(c) if c.tag == ctx(0) => json!({"imsi": imsi(c)}),
                Some(c) if c.tag == ctx(1) => json!({"msisdn": addr(c)}),
                _ => return Err("subscriberIdentity is neither imsi [0] nor msisdn [1]".into()),
            };
            out.insert("subscriber".into(), sub);
            let mut requested = Vec::new();
            if let Some(ri) = find(ctxc(1)) {
                for (n, name) in [
                    (0, "location_information"),
                    (1, "subscriber_state"),
                    (3, "current_location"),
                    (5, "ms_classmark"),
                    (6, "imei"),
                    (7, "mnp_requested_info"),
                ] {
                    if ri.children.iter().any(|c| c.tag.is_context(n)) {
                        requested.push(json!(name));
                    }
                }
            }
            out.insert("requested_info".into(), json!(requested));
            out.insert(
                "gsm_scf_address".into(),
                find(ctx(3)).map(addr).unwrap_or(Value::Null),
            );
            vec![ctxc(0), ctxc(1), ctx(3)]
        }
        59..=61 => {
            let (dcs, text) = ussd_fields(&kids)?;
            out.insert("ussd_data_coding_scheme".into(), json!(dcs));
            out.insert("ussd_text".into(), text);
            out.insert(
                "msisdn".into(),
                find(ctx(0)).map(addr).unwrap_or(Value::Null),
            );
            vec![Tag::OCTET_STRING, ctx(0)]
        }
        44 | 46 => {
            let da = kids.first().ok_or("sm-RP-DA missing")?;
            let oa = kids.get(1).ok_or("sm-RP-OA missing")?;
            let ui = kids
                .get(2)
                .filter(|u| u.tag == Tag::OCTET_STRING)
                .ok_or("sm-RP-UI missing")?;
            out.insert("sm_rp_da".into(), sm_rp_da(da));
            out.insert("sm_rp_oa".into(), sm_rp_oa(oa));
            out.insert(
                "sms".into(),
                gsm::sms_tpdu_decode(&ui.value, code == 46)
                    .unwrap_or_else(|e| json!({ "error": e })),
            );
            if code == 44 {
                out.insert(
                    "more_messages_to_send".into(),
                    json!(kids.iter().skip(3).any(|c| c.tag == Tag::NULL)),
                );
            } else if let Some(i) = kids.iter().skip(3).find(|c| c.tag == Tag::OCTET_STRING) {
                out.insert("imsi".into(), imsi(i));
            }
            let mut u = vec![da.tag, oa.tag, Tag::OCTET_STRING, Tag::NULL];
            u.dedup();
            u
        }
        22 => {
            out.insert(
                "msisdn".into(),
                find(ctx(0)).map(addr).ok_or("msisdn [0] missing")?,
            );
            out.insert(
                "interrogation_type".into(),
                json!(match find(ctx(3))
                    .map(|t| t.as_i64())
                    .transpose()
                    .map_err(|e| e.0)?
                {
                    Some(0) => "basicCall",
                    Some(1) => "forwarding",
                    _ => "unknown",
                }),
            );
            out.insert(
                "gmsc_or_gsm_scf_address".into(),
                find(ctx(6)).map(addr).unwrap_or(Value::Null),
            );
            out.insert("or_interrogation".into(), json!(find(ctx(4)).is_some()));
            vec![ctx(0), ctx(3), ctx(6), ctx(4)]
        }
        2 => {
            out.insert(
                "imsi".into(),
                find(Tag::OCTET_STRING).map(imsi).ok_or("imsi missing")?,
            );
            out.insert(
                "msc_number".into(),
                find(ctx(1)).map(addr).ok_or("msc-Number [1] missing")?,
            );
            out.insert(
                "vlr_number".into(),
                kids.iter()
                    .filter(|c| c.tag == Tag::OCTET_STRING)
                    .nth(1)
                    .map(addr)
                    .ok_or("vlr-Number missing")?,
            );
            out.insert(
                "lmsi".into(),
                find(ctx(10))
                    .map(|l| json!(ber::hex(&l.value)))
                    .unwrap_or(Value::Null),
            );
            vec![Tag::OCTET_STRING, ctx(1), ctx(10)]
        }
        other => return Err(format!("operation {other} is not implemented")),
    };
    out.insert("uninterpreted".into(), json!(leftovers(&kids, &used)));
    Ok(Value::Object(out))
}

fn ussd_fields(kids: &[Tlv]) -> MapResult<(u8, Value)> {
    let mut octets = kids.iter().filter(|c| c.tag == Tag::OCTET_STRING);
    let dcs = octets
        .next()
        .and_then(|d| d.value.first().copied())
        .ok_or("ussd-DataCodingScheme missing")?;
    let s = octets.next().ok_or("ussd-String missing")?;
    if s.value.len() > gsm::MAX_USSD_OCTETS {
        return Err(format!(
            "ussd-String of {} octets (at most {})",
            s.value.len(),
            gsm::MAX_USSD_OCTETS
        ));
    }
    Ok((dcs, json!(gsm::ussd_decode(dcs, &s.value))))
}

fn sm_rp_da(t: &Tlv) -> Value {
    match t.tag.number {
        0 => json!({"imsi": imsi(t)}),
        1 => json!({"lmsi": ber::hex(&t.value)}),
        4 => json!({"service_centre_address": addr(t)}),
        5 => json!({"none": true}),
        n => json!({"unknown_choice": n}),
    }
}

fn sm_rp_oa(t: &Tlv) -> Value {
    match t.tag.number {
        2 => json!({"msisdn": addr(t)}),
        4 => json!({"service_centre_address": addr(t)}),
        5 => json!({"none": true}),
        n => json!({"unknown_choice": n}),
    }
}

/// Encode an Invoke's argument from the model's fields.
pub fn encode_argument(code: i64, v: &Value) -> MapResult<Vec<u8>> {
    let parts: Vec<Vec<u8>> = match code {
        45 => vec![
            address_tlv(
                ctx(0),
                required(v, "msisdn")?,
                "msisdn",
                gsm::MAX_ISDN_ADDRESS_DIGITS,
            )?,
            ber::tlv(
                ctx(1),
                &[
                    if v.get("sm_rp_pri").and_then(Value::as_bool).unwrap_or(true) {
                        0xff
                    } else {
                        0
                    },
                ],
            ),
            address_tlv(
                ctx(2),
                required(v, "service_centre_address")?,
                "service_centre_address",
                gsm::MAX_ADDRESS_DIGITS,
            )?,
        ],
        71 => {
            let sub = required(v, "subscriber")?;
            let ident = if let Some(i) = sub.get("imsi") {
                imsi_tlv(ctx(0), i, "subscriber.imsi")?
            } else if let Some(m) = sub.get("msisdn") {
                address_tlv(ctx(1), m, "subscriber.msisdn", gsm::MAX_ISDN_ADDRESS_DIGITS)?
            } else {
                return Err("subscriber must be {\"msisdn\": ...} or {\"imsi\": ...}".into());
            };
            let wanted: Vec<String> = match v.get("requested_info") {
                Some(Value::Array(a)) => a
                    .iter()
                    .filter_map(|x| x.as_str().map(str::to_string))
                    .collect(),
                _ => vec!["location_information".into(), "subscriber_state".into()],
            };
            let mut ri = Vec::new();
            for (n, name) in [
                (0u32, "location_information"),
                (1, "subscriber_state"),
                (3, "current_location"),
                (5, "ms_classmark"),
                (6, "imei"),
            ] {
                if wanted.iter().any(|w| w == name) {
                    ri.push(ber::tlv(ctx(n), &[]));
                }
            }
            if ri.is_empty() {
                return Err("requested_info names nothing NetGet can request".into());
            }
            vec![
                ber::seq(ctxc(0), &[ident]),
                ber::seq(ctxc(1), &ri),
                address_tlv(
                    ctx(3),
                    required(v, "gsm_scf_address")?,
                    "gsm_scf_address",
                    gsm::MAX_ISDN_ADDRESS_DIGITS,
                )?,
            ]
        }
        59..=61 => {
            let text = v
                .get("ussd_text")
                .or_else(|| v.get("text"))
                .and_then(Value::as_str)
                .ok_or("ussd_text is required")?;
            let (dcs, octets) = gsm::ussd_encode(text)?;
            let mut p = vec![
                ber::tlv(Tag::OCTET_STRING, &[dcs]),
                ber::tlv(Tag::OCTET_STRING, &octets),
            ];
            if let Some(m) = v.get("msisdn").filter(|m| !m.is_null()) {
                p.push(address_tlv(
                    ctx(0),
                    m,
                    "msisdn",
                    gsm::MAX_ISDN_ADDRESS_DIGITS,
                )?);
            }
            p
        }
        46 => {
            let da = required(v, "sm_rp_da")?;
            let oa = required(v, "sm_rp_oa")?;
            vec![
                encode_sm_rp_da(da)?,
                encode_sm_rp_oa(oa)?,
                ber::tlv(
                    Tag::OCTET_STRING,
                    &gsm::sms_submit_encode(required(v, "sms")?)?,
                ),
            ]
        }
        44 => {
            let mut p = vec![
                encode_sm_rp_da(required(v, "sm_rp_da")?)?,
                encode_sm_rp_oa(required(v, "sm_rp_oa")?)?,
                ber::tlv(
                    Tag::OCTET_STRING,
                    &gsm::sms_deliver_encode(required(v, "sms")?)?,
                ),
            ];
            if v.get("more_messages_to_send").and_then(Value::as_bool) == Some(true) {
                p.push(ber::tlv(Tag::NULL, &[]));
            }
            p
        }
        22 => {
            let it = match v.get("interrogation_type").and_then(Value::as_str) {
                None | Some("basicCall") => 0,
                Some("forwarding") => 1,
                Some(other) => {
                    return Err(format!(
                        "interrogation_type {other:?} is not basicCall or forwarding"
                    ))
                }
            };
            vec![
                address_tlv(
                    ctx(0),
                    required(v, "msisdn")?,
                    "msisdn",
                    gsm::MAX_ISDN_ADDRESS_DIGITS,
                )?,
                ber::integer(ctx(3), it),
                address_tlv(
                    ctx(6),
                    required(v, "gmsc_or_gsm_scf_address")?,
                    "gmsc_or_gsm_scf_address",
                    gsm::MAX_ISDN_ADDRESS_DIGITS,
                )?,
            ]
        }
        2 => vec![
            imsi_tlv(Tag::OCTET_STRING, required(v, "imsi")?, "imsi")?,
            address_tlv(
                ctx(1),
                required(v, "msc_number")?,
                "msc_number",
                gsm::MAX_ISDN_ADDRESS_DIGITS,
            )?,
            address_tlv(
                Tag::OCTET_STRING,
                required(v, "vlr_number")?,
                "vlr_number",
                gsm::MAX_ISDN_ADDRESS_DIGITS,
            )?,
        ],
        other => return Err(format!("operation {other} is not implemented")),
    };
    Ok(ber::seq(Tag::SEQUENCE, &parts))
}

fn encode_sm_rp_da(v: &Value) -> MapResult<Vec<u8>> {
    if let Some(i) = v.get("imsi") {
        imsi_tlv(ctx(0), i, "sm_rp_da.imsi")
    } else if let Some(l) = v.get("lmsi").and_then(Value::as_str) {
        let b = ber::unhex(l).map_err(|e| e.0)?;
        if b.len() != 4 {
            return Err("sm_rp_da.lmsi must be 4 octets (8 hex digits)".into());
        }
        Ok(ber::tlv(ctx(1), &b))
    } else if let Some(s) = v.get("service_centre_address") {
        address_tlv(
            ctx(4),
            s,
            "sm_rp_da.service_centre_address",
            gsm::MAX_ADDRESS_DIGITS,
        )
    } else {
        Err("sm_rp_da must be {\"imsi\"}, {\"lmsi\"} or {\"service_centre_address\"}".into())
    }
}

fn encode_sm_rp_oa(v: &Value) -> MapResult<Vec<u8>> {
    if let Some(m) = v.get("msisdn") {
        address_tlv(ctx(2), m, "sm_rp_oa.msisdn", gsm::MAX_ISDN_ADDRESS_DIGITS)
    } else if let Some(s) = v.get("service_centre_address") {
        address_tlv(
            ctx(4),
            s,
            "sm_rp_oa.service_centre_address",
            gsm::MAX_ADDRESS_DIGITS,
        )
    } else {
        Err("sm_rp_oa must be {\"msisdn\"} or {\"service_centre_address\"}".into())
    }
}

// ---------------------------------------------------------------------------
// Results
// ---------------------------------------------------------------------------

pub const SUBSCRIBER_STATES: &[&str] = &[
    "assumedIdle",
    "camelBusy",
    "notProvidedFromVLR",
    "netDetNotReachable",
];

pub const NOT_REACHABLE_REASONS: &[&str] = &[
    "msPurged",
    "imsiDetached",
    "restrictedArea",
    "notRegistered",
];

/// Encode a result from the model's fields. `None` for an operation answered with an empty
/// ReturnResultLast.
pub fn encode_result(code: i64, v: &Value) -> MapResult<Option<Vec<u8>>> {
    Ok(Some(match code {
        45 => {
            let mut loc = vec![address_tlv(
                ctx(1),
                required(v, "network_node_number")?,
                "network_node_number",
                gsm::MAX_ISDN_ADDRESS_DIGITS,
            )?];
            if let Some(l) = v.get("lmsi").and_then(Value::as_str) {
                let b = ber::unhex(l).map_err(|e| e.0)?;
                if b.len() != 4 {
                    return Err("lmsi must be 4 octets (8 hex digits)".into());
                }
                loc.push(ber::tlv(Tag::OCTET_STRING, &b));
            }
            if v.get("gprs_node_indicator").and_then(Value::as_bool) == Some(true) {
                loc.push(ber::tlv(ctx(5), &[]));
            }
            ber::seq(
                Tag::SEQUENCE,
                &[
                    imsi_tlv(Tag::OCTET_STRING, required(v, "imsi")?, "imsi")?,
                    ber::seq(ctxc(0), &loc),
                ],
            )
        }
        71 => {
            let mut info = Vec::new();
            if let Some(li) = v.get("location_information").filter(|x| !x.is_null()) {
                let mut l = Vec::new();
                if let Some(age) = li
                    .get("age_of_location_information")
                    .and_then(Value::as_i64)
                {
                    if !(0..=32767).contains(&age) {
                        return Err("age_of_location_information must be 0..32767".into());
                    }
                    l.push(ber::integer(Tag::INTEGER, age));
                }
                if let Some(vlr) = li.get("vlr_number").filter(|x| !x.is_null()) {
                    l.push(address_tlv(
                        ctx(1),
                        vlr,
                        "vlr_number",
                        gsm::MAX_ISDN_ADDRESS_DIGITS,
                    )?);
                }
                if let Some(cgi) = li.get("cell_global_id").filter(|x| !x.is_null()) {
                    l.push(ber::seq(
                        ctxc(3),
                        &[ber::tlv(ctx(0), &gsm::cgi_encode(cgi)?)],
                    ));
                }
                info.push(ber::seq(ctxc(0), &l));
            }
            if let Some(state) = v.get("subscriber_state").and_then(Value::as_str) {
                let inner = match state {
                    "assumedIdle" => ber::tlv(ctx(0), &[]),
                    "camelBusy" => ber::tlv(ctx(1), &[]),
                    "notProvidedFromVLR" => ber::tlv(ctx(2), &[]),
                    "netDetNotReachable" => {
                        let reason = v
                            .get("not_reachable_reason")
                            .and_then(Value::as_str)
                            .unwrap_or("imsiDetached");
                        let r = NOT_REACHABLE_REASONS
                            .iter()
                            .position(|n| *n == reason)
                            .ok_or_else(|| {
                                format!(
                                    "not_reachable_reason must be one of {}",
                                    NOT_REACHABLE_REASONS.join(", ")
                                )
                            })?;
                        ber::integer(Tag::ENUMERATED, r as i64)
                    }
                    other => {
                        return Err(format!(
                            "subscriber_state {other:?} must be one of {}",
                            SUBSCRIBER_STATES.join(", ")
                        ))
                    }
                };
                info.push(ber::seq(ctxc(1), &[inner]));
            }
            if let Some(imei) = v.get("imei").and_then(Value::as_str) {
                if imei.len() != 15 && imei.len() != 16 {
                    return Err("imei must be 15 or 16 digits".into());
                }
                info.push(ber::tlv(ctx(5), &gsm::tbcd_encode(imei)?));
            }
            ber::seq(Tag::SEQUENCE, &[ber::seq(Tag::SEQUENCE, &info)])
        }
        59 | 60 => {
            let text = v
                .get("ussd_text")
                .or_else(|| v.get("text"))
                .and_then(Value::as_str)
                .ok_or("ussd_text is required")?;
            let (dcs, octets) = gsm::ussd_encode(text)?;
            ber::seq(
                Tag::SEQUENCE,
                &[
                    ber::tlv(Tag::OCTET_STRING, &[dcs]),
                    ber::tlv(Tag::OCTET_STRING, &octets),
                ],
            )
        }
        61 | 44 | 46 => return Ok(None),
        22 => {
            let mut p = Vec::new();
            if let Some(i) = v.get("imsi").filter(|x| !x.is_null()) {
                p.push(imsi_tlv(ctx(9), i, "imsi")?);
            }
            p.push(address_tlv(
                Tag::OCTET_STRING,
                required(v, "roaming_number")?,
                "roaming_number",
                gsm::MAX_ISDN_ADDRESS_DIGITS,
            )?);
            ber::seq(ctxc(3), &p)
        }
        2 => ber::seq(
            Tag::SEQUENCE,
            &[address_tlv(
                Tag::OCTET_STRING,
                required(v, "hlr_number")?,
                "hlr_number",
                gsm::MAX_ISDN_ADDRESS_DIGITS,
            )?],
        ),
        other => return Err(format!("operation {other} is not implemented")),
    }))
}

/// Decode a ReturnResult's parameter for `code`.
pub fn decode_result(code: i64, p: Option<&Tlv>) -> MapResult<Value> {
    let Some(p) = p else {
        return Ok(json!({}));
    };
    let kids = p.children.clone();
    let find = |tag: Tag| kids.iter().find(|c| c.tag == tag);
    Ok(match code {
        45 => {
            let loc = find(ctxc(0));
            json!({
                "imsi": find(Tag::OCTET_STRING).map(imsi),
                "network_node_number": loc.and_then(|l| l.ctx(1)).map(addr),
                "lmsi": loc.and_then(|l| l.univ(ber::UNIV_OCTET_STRING)).map(|x| ber::hex(&x.value)),
                "gprs_node_indicator": loc.map(|l| l.ctx(5).is_some()).unwrap_or(false),
            })
        }
        71 => {
            let info = kids.first();
            let li = info.and_then(|i| i.ctx(0));
            let state = info.and_then(|i| i.ctx(1)).and_then(|s| s.children.first());
            json!({
                "location_information": li.map(|l| json!({
                    "age_of_location_information": l.univ(ber::UNIV_INTEGER).and_then(|a| a.as_i64().ok()),
                    "vlr_number": l.ctx(1).map(addr),
                    "cell_global_id": l.ctx(3).and_then(|c| c.children.first()).map(|c| gsm::cgi_decode(&c.value)),
                })),
                "subscriber_state": state.map(|s| match (s.tag.class, s.tag.number) {
                    (ber::CLASS_CONTEXT, 0) => json!("assumedIdle"),
                    (ber::CLASS_CONTEXT, 1) => json!("camelBusy"),
                    (ber::CLASS_CONTEXT, 2) => json!("notProvidedFromVLR"),
                    _ => json!(format!("netDetNotReachable:{}", s.as_i64().ok()
                        .and_then(|r| NOT_REACHABLE_REASONS.get(r as usize).copied())
                        .unwrap_or("unknown"))),
                }),
                "imei": info.and_then(|i| i.ctx(5)).map(|x| gsm::tbcd_decode(&x.value)),
            })
        }
        59 | 60 => {
            let (dcs, text) = ussd_fields(&kids)?;
            json!({"ussd_data_coding_scheme": dcs, "ussd_text": text})
        }
        44 | 46 => json!({
            "sm_rp_ui_present": find(Tag::OCTET_STRING).is_some(),
        }),
        22 => json!({
            "imsi": find(ctx(9)).map(imsi),
            "roaming_number": find(Tag::OCTET_STRING).map(addr),
            "uninterpreted": leftovers(&kids, &[ctx(9), Tag::OCTET_STRING]),
        }),
        2 => json!({
            "hlr_number": find(Tag::OCTET_STRING).map(addr),
        }),
        _ => json!({"uninterpreted": p.child_labels()}),
    })
}

/// SM-DeliveryFailureCause values.
pub const SM_DELIVERY_FAILURE_CAUSES: &[&str] = &[
    "memoryCapacityExceeded",
    "equipmentProtocolError",
    "equipmentNotSM-Equipped",
    "unknownServiceCentre",
    "sc-Congestion",
    "invalidSME-Address",
    "subscriberNotSC-Subscriber",
];

/// An error's parameter. Only sm-DeliveryFailure's is mandatory; absentSubscriberSM takes an
/// optional diagnostic. Every other error is sent without one (each is OPTIONAL in TS 29.002).
pub fn encode_error_parameter(code: i64, v: &Value) -> MapResult<Option<Vec<u8>>> {
    match code {
        32 => {
            let cause = v
                .get("delivery_failure_cause")
                .and_then(Value::as_str)
                .unwrap_or("memoryCapacityExceeded");
            let i = SM_DELIVERY_FAILURE_CAUSES
                .iter()
                .position(|c| *c == cause)
                .ok_or_else(|| {
                    format!(
                        "delivery_failure_cause must be one of {}",
                        SM_DELIVERY_FAILURE_CAUSES.join(", ")
                    )
                })?;
            Ok(Some(ber::seq(
                Tag::SEQUENCE,
                &[ber::integer(Tag::ENUMERATED, i as i64)],
            )))
        }
        6 => match v
            .get("absent_subscriber_diagnostic")
            .and_then(Value::as_i64)
        {
            Some(d) if (0..=255).contains(&d) => Ok(Some(ber::seq(
                Tag::SEQUENCE,
                &[ber::integer(Tag::INTEGER, d)],
            ))),
            Some(_) => Err("absent_subscriber_diagnostic must be 0..255".into()),
            None => Ok(None),
        },
        _ => Ok(None),
    }
}

pub fn decode_error_parameter(code: i64, p: Option<&Tlv>) -> Value {
    let Some(p) = p else {
        return Value::Null;
    };
    match code {
        32 => json!({
            "delivery_failure_cause": p.univ(ber::UNIV_ENUMERATED)
                .and_then(|e| e.as_i64().ok())
                .and_then(|i| SM_DELIVERY_FAILURE_CAUSES.get(i as usize).copied()),
        }),
        6 => json!({
            "absent_subscriber_diagnostic": p.univ(ber::UNIV_INTEGER).and_then(|e| e.as_i64().ok()),
        }),
        _ => json!({"present": p.tag.label()}),
    }
}
