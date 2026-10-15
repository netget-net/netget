//! ITU-T TCAP (Q.773): transaction messages, the dialogue portion (AARQ / AARE / ABRT carried in
//! an EXTERNAL under the dialogue-as-id) and the component portion (Invoke, ReturnResult,
//! ReturnError, Reject). MAP and CAP ride in the components; the application context name in the
//! dialogue portion says which.
//!
//! Decoding goes through the bounded [`super::ber`] reader. On top of its depth and element
//! bounds this layer caps the components in one message at [`MAX_COMPONENTS`] and transaction
//! ids at the four octets Q.773 allows.

use super::ber::{self, BerError, Tag, Tlv};
use serde_json::{json, Value};

/// Components accepted in one TCAP message. Real MAP and CAP messages carry one to three.
pub const MAX_COMPONENTS: usize = 16;

/// `dialogue-as-id` {itu-t recommendation q 773 as(1) dialogue-as(1) version1(1)}.
pub const DIALOGUE_AS_ID: &[u64] = &[0, 0, 17, 773, 1, 1, 1];
/// `uni-dialogue-as-id`.
pub const UNI_DIALOGUE_AS_ID: &[u64] = &[0, 0, 17, 773, 1, 2, 1];
/// MAP's `map-DialogueAS` {0 4 0 0 1 1 1 1}, under which MAP-OpenInfo travels.
pub const MAP_DIALOGUE_AS: &[u64] = &[0, 4, 0, 0, 1, 1, 1, 1];

/// P-Abort causes (Q.773 section 3.1).
pub const P_ABORT_UNRECOGNIZED_MESSAGE_TYPE: u8 = 0;
pub const P_ABORT_UNRECOGNIZED_TRANSACTION_ID: u8 = 1;
pub const P_ABORT_BADLY_FORMATTED_TRANSACTION_PORTION: u8 = 2;
pub const P_ABORT_INCORRECT_TRANSACTION_PORTION: u8 = 3;
pub const P_ABORT_RESOURCE_LIMITATION: u8 = 4;

/// Associate-source-diagnostic values for dialogue-service-user.
pub const DIAG_USER_NULL: u8 = 0;
pub const DIAG_USER_NO_REASON_GIVEN: u8 = 1;
pub const DIAG_USER_ACN_NOT_SUPPORTED: u8 = 2;

/// Reject problem types and the codes used here.
pub const PROBLEM_GENERAL: u8 = 0;
pub const PROBLEM_INVOKE: u8 = 1;
pub const PROBLEM_RETURN_RESULT: u8 = 2;
pub const PROBLEM_RETURN_ERROR: u8 = 3;
pub const GENERAL_MISTYPED_COMPONENT: u8 = 1;
pub const GENERAL_BADLY_STRUCTURED_COMPONENT: u8 = 2;
pub const INVOKE_UNRECOGNIZED_OPERATION: u8 = 1;
pub const INVOKE_MISTYPED_PARAMETER: u8 = 2;
pub const INVOKE_RESOURCE_LIMITATION: u8 = 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TcKind {
    Unidirectional,
    Begin,
    End,
    Continue,
    Abort,
}

impl TcKind {
    pub fn name(self) -> &'static str {
        match self {
            TcKind::Unidirectional => "unidirectional",
            TcKind::Begin => "begin",
            TcKind::End => "end",
            TcKind::Continue => "continue",
            TcKind::Abort => "abort",
        }
    }

    fn app_number(self) -> u32 {
        match self {
            TcKind::Unidirectional => 1,
            TcKind::Begin => 2,
            TcKind::End => 4,
            TcKind::Continue => 5,
            TcKind::Abort => 7,
        }
    }
}

/// An operation or error code: local (an INTEGER) or global (an OBJECT IDENTIFIER).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Code {
    Local(i64),
    Global(Vec<u64>),
}

impl Code {
    fn decode(t: &Tlv) -> Result<Code, BerError> {
        if t.tag == Tag::INTEGER {
            Ok(Code::Local(t.as_i64()?))
        } else if t.tag == Tag::OID {
            Ok(Code::Global(ber::decode_oid(&t.value)?))
        } else {
            Err(BerError(format!(
                "operation/error code is {}, expected INTEGER or OBJECT IDENTIFIER",
                t.tag.label()
            )))
        }
    }

    fn encode(&self) -> Vec<u8> {
        match self {
            Code::Local(v) => ber::integer(Tag::INTEGER, *v),
            Code::Global(arcs) => ber::tlv(Tag::OID, &ber::oid_contents(arcs)),
        }
    }

    pub fn local(&self) -> Option<i64> {
        match self {
            Code::Local(v) => Some(*v),
            Code::Global(_) => None,
        }
    }
}

/// A component.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Component {
    Invoke {
        invoke_id: i64,
        linked_id: Option<i64>,
        opcode: Code,
        parameter: Option<Tlv>,
    },
    ReturnResult {
        last: bool,
        invoke_id: i64,
        opcode: Option<Code>,
        parameter: Option<Tlv>,
    },
    ReturnError {
        invoke_id: i64,
        error: Code,
        parameter: Option<Tlv>,
    },
    Reject {
        invoke_id: Option<i64>,
        problem_type: u8,
        problem: u8,
    },
}

impl Component {
    pub fn invoke_id(&self) -> Option<i64> {
        match self {
            Component::Invoke { invoke_id, .. }
            | Component::ReturnResult { invoke_id, .. }
            | Component::ReturnError { invoke_id, .. } => Some(*invoke_id),
            Component::Reject { invoke_id, .. } => *invoke_id,
        }
    }

    fn decode(t: &Tlv) -> Result<Component, BerError> {
        if t.tag.class != ber::CLASS_CONTEXT || !t.tag.constructed {
            return Err(BerError(format!("component tag {}", t.tag.label())));
        }
        let kids = &t.children;
        let invoke_id = |i: usize| -> Result<i64, BerError> {
            let k = kids
                .get(i)
                .filter(|k| k.tag == Tag::INTEGER)
                .ok_or_else(|| BerError("component without an invokeID".into()))?;
            let v = k.as_i64()?;
            if !(-128..=127).contains(&v) {
                return Err(BerError(format!("invokeID {v} outside -128..127")));
            }
            Ok(v)
        };
        match t.tag.number {
            1 => {
                let id = invoke_id(0)?;
                let mut i = 1;
                let mut linked_id = None;
                if let Some(k) = kids.get(i).filter(|k| k.tag == Tag::context(0, false)) {
                    linked_id = Some(ber::decode_integer(&k.value)?);
                    i += 1;
                }
                let opcode = Code::decode(
                    kids.get(i)
                        .ok_or_else(|| BerError("Invoke without an operation code".into()))?,
                )?;
                Ok(Component::Invoke {
                    invoke_id: id,
                    linked_id,
                    opcode,
                    parameter: kids.get(i + 1).cloned(),
                })
            }
            2 | 7 => {
                let id = invoke_id(0)?;
                let (opcode, parameter) = match kids.get(1) {
                    Some(s) if s.tag == Tag::SEQUENCE => {
                        let op = s
                            .children
                            .first()
                            .ok_or_else(|| BerError("ReturnResult result without opcode".into()))?;
                        (Some(Code::decode(op)?), s.children.get(1).cloned())
                    }
                    Some(other) => {
                        return Err(BerError(format!(
                            "ReturnResult result is {}, expected SEQUENCE",
                            other.tag.label()
                        )))
                    }
                    None => (None, None),
                };
                Ok(Component::ReturnResult {
                    last: t.tag.number == 2,
                    invoke_id: id,
                    opcode,
                    parameter,
                })
            }
            3 => {
                let id = invoke_id(0)?;
                let error = Code::decode(
                    kids.get(1)
                        .ok_or_else(|| BerError("ReturnError without an error code".into()))?,
                )?;
                Ok(Component::ReturnError {
                    invoke_id: id,
                    error,
                    parameter: kids.get(2).cloned(),
                })
            }
            4 => {
                let first = kids
                    .first()
                    .ok_or_else(|| BerError("Reject without an invokeID".into()))?;
                let invoke_id = if first.tag == Tag::NULL {
                    None
                } else {
                    Some(invoke_id(0)?)
                };
                let p = kids
                    .get(1)
                    .ok_or_else(|| BerError("Reject without a problem".into()))?;
                if p.tag.class != ber::CLASS_CONTEXT || p.tag.number > 3 {
                    return Err(BerError(format!("Reject problem {}", p.tag.label())));
                }
                Ok(Component::Reject {
                    invoke_id,
                    problem_type: p.tag.number as u8,
                    problem: ber::decode_integer(&p.value)? as u8,
                })
            }
            n => Err(BerError(format!("unknown component type [{n}]"))),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        match self {
            Component::Invoke {
                invoke_id,
                linked_id,
                opcode,
                parameter,
            } => {
                let mut parts = vec![ber::integer(Tag::INTEGER, *invoke_id)];
                if let Some(l) = linked_id {
                    parts.push(ber::integer(Tag::context(0, false), *l));
                }
                parts.push(opcode.encode());
                if let Some(p) = parameter {
                    parts.push(p.encode());
                }
                ber::seq(Tag::context(1, true), &parts)
            }
            Component::ReturnResult {
                last,
                invoke_id,
                opcode,
                parameter,
            } => {
                let mut parts = vec![ber::integer(Tag::INTEGER, *invoke_id)];
                if let Some(op) = opcode {
                    let mut inner = vec![op.encode()];
                    if let Some(p) = parameter {
                        inner.push(p.encode());
                    }
                    parts.push(ber::seq(Tag::SEQUENCE, &inner));
                }
                ber::seq(Tag::context(if *last { 2 } else { 7 }, true), &parts)
            }
            Component::ReturnError {
                invoke_id,
                error,
                parameter,
            } => {
                let mut parts = vec![ber::integer(Tag::INTEGER, *invoke_id), error.encode()];
                if let Some(p) = parameter {
                    parts.push(p.encode());
                }
                ber::seq(Tag::context(3, true), &parts)
            }
            Component::Reject {
                invoke_id,
                problem_type,
                problem,
            } => {
                let id = match invoke_id {
                    Some(i) => ber::integer(Tag::INTEGER, *i),
                    None => ber::tlv(Tag::NULL, &[]),
                };
                let p = ber::integer(Tag::context(*problem_type as u32, false), *problem as i64);
                ber::seq(Tag::context(4, true), &[id, p])
            }
        }
    }

    pub fn kind_name(&self) -> &'static str {
        match self {
            Component::Invoke { .. } => "invoke",
            Component::ReturnResult { last: true, .. } => "return_result_last",
            Component::ReturnResult { last: false, .. } => "return_result_not_last",
            Component::ReturnError { .. } => "return_error",
            Component::Reject { .. } => "reject",
        }
    }
}

/// The dialogue PDU carried in the dialogue portion.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DialoguePdu {
    /// AARQ: the initiator proposes an application context.
    Request {
        acn: Vec<u64>,
        user_information: Vec<Tlv>,
    },
    /// AARE: the responder accepts (result 0) or rejects (1) it.
    Response {
        acn: Vec<u64>,
        result: u8,
        diagnostic_provider: bool,
        diagnostic: u8,
    },
    /// ABRT: a user (0) or provider (1) abort.
    Abort {
        source: u8,
        user_information: Vec<Tlv>,
    },
    /// AUDT on a unidirectional message.
    Unidirectional { acn: Vec<u64> },
}

impl DialoguePdu {
    pub fn acn(&self) -> Option<&[u64]> {
        match self {
            DialoguePdu::Request { acn, .. }
            | DialoguePdu::Response { acn, .. }
            | DialoguePdu::Unidirectional { acn } => Some(acn),
            DialoguePdu::Abort { .. } => None,
        }
    }

    fn decode(portion: &Tlv) -> Result<DialoguePdu, BerError> {
        let external = portion
            .children
            .first()
            .filter(|e| e.tag.is_universal(ber::UNIV_EXTERNAL))
            .ok_or_else(|| BerError("dialogue portion without an EXTERNAL".into()))?;
        let as_id = external
            .univ(ber::UNIV_OID)
            .map(|o| ber::decode_oid(&o.value))
            .transpose()?
            .unwrap_or_default();
        let single = external
            .ctx(0)
            .and_then(|s| s.children.first())
            .ok_or_else(|| BerError("dialogue EXTERNAL without single-ASN1-type".into()))?;
        let unidirectional = as_id == UNI_DIALOGUE_AS_ID;
        if as_id != DIALOGUE_AS_ID && !unidirectional {
            return Err(BerError(format!(
                "dialogue portion under {} rather than the dialogue-as-id",
                ber::oid_string(&as_id)
            )));
        }
        let acn = |pdu: &Tlv| -> Result<Vec<u64>, BerError> {
            let name = pdu
                .ctx(1)
                .and_then(|a| a.univ(ber::UNIV_OID))
                .ok_or_else(|| BerError("dialogue PDU without application-context-name".into()))?;
            ber::decode_oid(&name.value)
        };
        let user_info =
            |pdu: &Tlv| -> Vec<Tlv> { pdu.ctx(30).map(|u| u.children.clone()).unwrap_or_default() };
        if single.tag.class != ber::CLASS_APPLICATION {
            return Err(BerError(format!("dialogue PDU tag {}", single.tag.label())));
        }
        Ok(match (single.tag.number, unidirectional) {
            (0, true) => DialoguePdu::Unidirectional { acn: acn(single)? },
            (0, false) => DialoguePdu::Request {
                acn: acn(single)?,
                user_information: user_info(single),
            },
            (1, false) => {
                let result = single
                    .ctx(2)
                    .and_then(|r| r.univ(ber::UNIV_INTEGER))
                    .map(|i| i.as_i64())
                    .transpose()?
                    .unwrap_or(0) as u8;
                let (provider, diagnostic) = match single.ctx(3).and_then(|d| d.children.first()) {
                    Some(choice) => (
                        choice.tag.number == 2,
                        choice
                            .univ(ber::UNIV_INTEGER)
                            .map(|i| i.as_i64())
                            .transpose()?
                            .unwrap_or(0) as u8,
                    ),
                    None => (false, 0),
                };
                DialoguePdu::Response {
                    acn: acn(single)?,
                    result,
                    diagnostic_provider: provider,
                    diagnostic,
                }
            }
            (4, false) => DialoguePdu::Abort {
                source: single
                    .ctx(0)
                    .map(|s| ber::decode_integer(&s.value))
                    .transpose()?
                    .unwrap_or(0) as u8,
                user_information: user_info(single),
            },
            (n, _) => return Err(BerError(format!("unknown dialogue PDU [APPLICATION {n}]"))),
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let version = ber::tlv(Tag::context(0, false), &[0x07, 0x80]);
        let acn_field = |acn: &[u64]| {
            ber::seq(
                Tag::context(1, true),
                &[ber::tlv(Tag::OID, &ber::oid_contents(acn))],
            )
        };
        let (as_id, pdu) = match self {
            DialoguePdu::Request {
                acn,
                user_information,
            } => {
                let mut parts = vec![version, acn_field(acn)];
                if !user_information.is_empty() {
                    let ui: Vec<Vec<u8>> = user_information.iter().map(|u| u.encode()).collect();
                    parts.push(ber::seq(Tag::context(30, true), &ui));
                }
                (DIALOGUE_AS_ID, ber::seq(Tag::application(0, true), &parts))
            }
            DialoguePdu::Response {
                acn,
                result,
                diagnostic_provider,
                diagnostic,
            } => {
                let result_field = ber::seq(
                    Tag::context(2, true),
                    &[ber::integer(Tag::INTEGER, *result as i64)],
                );
                let diag = ber::seq(
                    Tag::context(3, true),
                    &[ber::seq(
                        Tag::context(if *diagnostic_provider { 2 } else { 1 }, true),
                        &[ber::integer(Tag::INTEGER, *diagnostic as i64)],
                    )],
                );
                (
                    DIALOGUE_AS_ID,
                    ber::seq(
                        Tag::application(1, true),
                        &[version, acn_field(acn), result_field, diag],
                    ),
                )
            }
            DialoguePdu::Abort {
                source,
                user_information,
            } => {
                let mut parts = vec![ber::integer(Tag::context(0, false), *source as i64)];
                if !user_information.is_empty() {
                    let ui: Vec<Vec<u8>> = user_information.iter().map(|u| u.encode()).collect();
                    parts.push(ber::seq(Tag::context(30, true), &ui));
                }
                (DIALOGUE_AS_ID, ber::seq(Tag::application(4, true), &parts))
            }
            DialoguePdu::Unidirectional { acn } => (
                UNI_DIALOGUE_AS_ID,
                ber::seq(Tag::application(0, true), &[version, acn_field(acn)]),
            ),
        };
        let external = ber::seq(
            Tag::universal(ber::UNIV_EXTERNAL, true),
            &[
                ber::tlv(Tag::OID, &ber::oid_contents(as_id)),
                ber::seq(Tag::context(0, true), &[pdu]),
            ],
        );
        ber::seq(Tag::application(11, true), &[external])
    }

    pub fn to_json(&self) -> Value {
        match self {
            DialoguePdu::Request {
                acn,
                user_information,
            } => json!({
                "pdu": "AARQ",
                "application_context": ber::oid_string(acn),
                "map_open": map_open_info(user_information),
            }),
            DialoguePdu::Response {
                acn,
                result,
                diagnostic_provider,
                diagnostic,
            } => json!({
                "pdu": "AARE",
                "application_context": ber::oid_string(acn),
                "result": if *result == 0 { "accepted" } else { "rejected" },
                "diagnostic_source": if *diagnostic_provider { "provider" } else { "user" },
                "diagnostic": diagnostic_name(*diagnostic_provider, *diagnostic),
            }),
            DialoguePdu::Abort { source, .. } => json!({
                "pdu": "ABRT",
                "abort_source": if *source == 0 { "dialogue_service_user" } else { "dialogue_service_provider" },
            }),
            DialoguePdu::Unidirectional { acn } => json!({
                "pdu": "AUDT",
                "application_context": ber::oid_string(acn),
            }),
        }
    }
}

fn diagnostic_name(provider: bool, v: u8) -> &'static str {
    match (provider, v) {
        (false, 0) => "null",
        (false, 1) => "no_reason_given",
        (false, 2) => "application_context_name_not_supported",
        (true, 0) => "null",
        (true, 1) => "no_reason_given",
        (true, 2) => "no_common_dialogue_portion",
        _ => "unknown",
    }
}

/// MAP-OpenInfo (TS 29.002 section 7.3) as the AARQ user information: an EXTERNAL under
/// map-DialogueAS carrying map-open with the destination and origination references.
pub fn map_open_user_information(
    destination: Option<&super::gsm::Address>,
    origination: Option<&super::gsm::Address>,
) -> Result<Tlv, String> {
    let mut refs = Vec::new();
    if let Some(d) = destination {
        refs.push(ber::tlv(
            Tag::context(0, false),
            &d.encode(super::gsm::MAX_ADDRESS_DIGITS)?,
        ));
    }
    if let Some(o) = origination {
        refs.push(ber::tlv(
            Tag::context(1, false),
            &o.encode(super::gsm::MAX_ADDRESS_DIGITS)?,
        ));
    }
    let external = ber::seq(
        Tag::universal(ber::UNIV_EXTERNAL, true),
        &[
            ber::tlv(Tag::OID, &ber::oid_contents(MAP_DIALOGUE_AS)),
            ber::seq(
                Tag::context(0, true),
                &[ber::seq(Tag::context(0, true), &refs)],
            ),
        ],
    );
    ber::decode(&external).map_err(|e| e.to_string())
}

/// MAP-OpenInfo (TS 29.002 section 7.3) from the AARQ's user information, when present:
/// destination and origination references.
fn map_open_info(user_information: &[Tlv]) -> Value {
    for ext in user_information {
        let is_map = ext
            .univ(ber::UNIV_OID)
            .and_then(|o| ber::decode_oid(&o.value).ok())
            .map(|o| o == MAP_DIALOGUE_AS)
            .unwrap_or(false);
        if !is_map {
            continue;
        }
        let Some(open) = ext
            .ctx(0)
            .and_then(|s| s.children.first())
            .filter(|p| p.tag.is_context(0))
        else {
            continue;
        };
        let reference = |n: u32| {
            open.ctx(n)
                .and_then(|a| super::gsm::Address::decode(&a.value).ok())
                .map(|a| a.to_json())
        };
        return json!({
            "destination_reference": reference(0),
            "origination_reference": reference(1),
        });
    }
    Value::Null
}

/// A decoded TCAP message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TcMessage {
    pub kind: TcKind,
    pub otid: Option<Vec<u8>>,
    pub dtid: Option<Vec<u8>>,
    pub dialogue: Option<DialoguePdu>,
    pub components: Vec<Component>,
    pub p_abort_cause: Option<u8>,
}

fn tid(t: &Tlv, which: &str) -> Result<Vec<u8>, BerError> {
    if t.value.is_empty() || t.value.len() > 4 {
        return Err(BerError(format!(
            "{which} transaction id of {} octets (1..4)",
            t.value.len()
        )));
    }
    Ok(t.value.clone())
}

impl TcMessage {
    /// Decode a TCAP message. Errors carry the best P-Abort cause for a reply.
    pub fn decode(o: &[u8]) -> Result<TcMessage, (u8, BerError)> {
        let top = ber::decode(o).map_err(|e| (P_ABORT_BADLY_FORMATTED_TRANSACTION_PORTION, e))?;
        if top.tag.class != ber::CLASS_APPLICATION || !top.tag.constructed {
            return Err((
                P_ABORT_UNRECOGNIZED_MESSAGE_TYPE,
                BerError(format!("TCAP message tag {}", top.tag.label())),
            ));
        }
        let kind = match top.tag.number {
            1 => TcKind::Unidirectional,
            2 => TcKind::Begin,
            4 => TcKind::End,
            5 => TcKind::Continue,
            7 => TcKind::Abort,
            n => {
                return Err((
                    P_ABORT_UNRECOGNIZED_MESSAGE_TYPE,
                    BerError(format!("TCAP message type [APPLICATION {n}]")),
                ))
            }
        };
        let bad = |e: BerError| (P_ABORT_BADLY_FORMATTED_TRANSACTION_PORTION, e);
        let app = |n: u32| top.child(ber::CLASS_APPLICATION, n);
        let otid = app(8)
            .map(|t| tid(t, "originating"))
            .transpose()
            .map_err(bad)?;
        let dtid = app(9)
            .map(|t| tid(t, "destination"))
            .transpose()
            .map_err(bad)?;
        let (need_o, need_d) = match kind {
            TcKind::Unidirectional => (false, false),
            TcKind::Begin => (true, false),
            TcKind::Continue => (true, true),
            TcKind::End | TcKind::Abort => (false, true),
        };
        if need_o != otid.is_some() || need_d != dtid.is_some() {
            return Err((
                P_ABORT_INCORRECT_TRANSACTION_PORTION,
                BerError(format!(
                    "TC-{} with otid {} and dtid {}",
                    kind.name(),
                    if otid.is_some() { "present" } else { "absent" },
                    if dtid.is_some() { "present" } else { "absent" }
                )),
            ));
        }
        let dialogue = app(11)
            .map(DialoguePdu::decode)
            .transpose()
            .map_err(|e| (P_ABORT_BADLY_FORMATTED_TRANSACTION_PORTION, e))?;
        let mut components = Vec::new();
        if let Some(portion) = app(12) {
            if portion.children.len() > MAX_COMPONENTS {
                return Err((
                    P_ABORT_RESOURCE_LIMITATION,
                    BerError(format!(
                        "{} components (at most {MAX_COMPONENTS})",
                        portion.children.len()
                    )),
                ));
            }
            for c in &portion.children {
                // A malformed component is a Reject, not a transaction-level abort; it is kept
                // as a general-problem Reject marker for the caller to answer.
                components.push(Component::decode(c).unwrap_or(Component::Reject {
                    invoke_id: None,
                    problem_type: PROBLEM_GENERAL,
                    problem: GENERAL_BADLY_STRUCTURED_COMPONENT,
                }));
            }
        }
        let p_abort_cause = app(10)
            .map(|c| ber::decode_integer(&c.value).map(|v| v as u8))
            .transpose()
            .map_err(bad)?;
        Ok(TcMessage {
            kind,
            otid,
            dtid,
            dialogue,
            components,
            p_abort_cause,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut parts = Vec::new();
        if let Some(o) = &self.otid {
            parts.push(ber::tlv(Tag::application(8, false), o));
        }
        if let Some(d) = &self.dtid {
            parts.push(ber::tlv(Tag::application(9, false), d));
        }
        if let Some(c) = self.p_abort_cause {
            parts.push(ber::integer(Tag::application(10, false), c as i64));
        }
        if let Some(d) = &self.dialogue {
            parts.push(d.encode());
        }
        if !self.components.is_empty() {
            let comps: Vec<Vec<u8>> = self.components.iter().map(|c| c.encode()).collect();
            parts.push(ber::seq(Tag::application(12, true), &comps));
        }
        ber::seq(Tag::application(self.kind.app_number(), true), &parts)
    }

    /// A P-Abort answering a message whose originating transaction id is `their_tid`.
    pub fn p_abort(their_tid: &[u8], cause: u8) -> TcMessage {
        TcMessage {
            kind: TcKind::Abort,
            otid: None,
            dtid: Some(their_tid.to_vec()),
            dialogue: None,
            components: Vec::new(),
            p_abort_cause: Some(cause),
        }
    }
}

pub fn p_abort_name(c: u8) -> &'static str {
    match c {
        P_ABORT_UNRECOGNIZED_MESSAGE_TYPE => "unrecognized_message_type",
        P_ABORT_UNRECOGNIZED_TRANSACTION_ID => "unrecognized_transaction_id",
        P_ABORT_BADLY_FORMATTED_TRANSACTION_PORTION => "badly_formatted_transaction_portion",
        P_ABORT_INCORRECT_TRANSACTION_PORTION => "incorrect_transaction_portion",
        P_ABORT_RESOURCE_LIMITATION => "resource_limitation",
        _ => "unknown",
    }
}

pub fn reject_problem_name(problem_type: u8, problem: u8) -> String {
    let (t, names): (&str, &[&str]) = match problem_type {
        PROBLEM_GENERAL => (
            "general",
            &[
                "unrecognized_component",
                "mistyped_component",
                "badly_structured_component",
            ],
        ),
        PROBLEM_INVOKE => (
            "invoke",
            &[
                "duplicate_invoke_id",
                "unrecognized_operation",
                "mistyped_parameter",
                "resource_limitation",
                "initiating_release",
                "unrecognized_linked_id",
                "linked_response_unexpected",
                "unexpected_linked_operation",
            ],
        ),
        PROBLEM_RETURN_RESULT => (
            "return_result",
            &[
                "unrecognized_invoke_id",
                "return_result_unexpected",
                "mistyped_parameter",
            ],
        ),
        PROBLEM_RETURN_ERROR => (
            "return_error",
            &[
                "unrecognized_invoke_id",
                "return_error_unexpected",
                "unrecognized_error",
                "unexpected_error",
                "mistyped_parameter",
            ],
        ),
        _ => ("unknown", &[]),
    };
    format!(
        "{t}/{}",
        names.get(problem as usize).copied().unwrap_or("unknown")
    )
}
