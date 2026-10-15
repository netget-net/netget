//! The SS7 upper stack over M3UA: SCCP → TCAP → MAP / CAP, as one dialogue engine shared by the
//! SGP (`mod.rs`) and the ASP client (`src/client/m3ua`).
//!
//! An M3UA DATA whose Service Indicator is 3 carries SCCP. [`Engine::on_data`] decodes the SCCP
//! unitdata, the TCAP message inside it and the MAP or CAP components inside that, keeps the
//! transaction table, and either answers in Rust (everything that follows from the protocol:
//! SCCP management, a P-Abort for an unknown transaction, a Reject for an operation NetGet does
//! not implement, a refused segmented message) or hands back one structured event for the model.
//!
//! The model's answer comes back as an intent (`send_map_result`, `send_cap_operations`, …,
//! carried as `ActionResult::Custom`) which [`Engine::apply`] turns into TCAP for that dialogue:
//! the right message type, the peer's transaction id, the AARE if the dialogue still needs one,
//! the invoke id it answers, the swapped SCCP addresses and MTP routing label.
//!
//! # Bounds
//!
//! | Bound | Value | On breach |
//! |---|---|---|
//! | Open dialogues | [`MAX_OPEN_DIALOGUES`] per association | TC-P-ABORT `resourceLimitation` |
//! | Dialogue idle | [`DIALOGUE_IDLE_TIMEOUT`] | TC-U-ABORT to the peer, dialogue dropped |
//! | Components per message | `tcap::MAX_COMPONENTS` | TC-P-ABORT `resourceLimitation` |
//! | BER depth / elements | `ber::MAX_BER_DEPTH` / `ber::MAX_BER_ELEMENTS` | TC-P-ABORT `badlyFormattedTransactionPortion` |
//! | SCCP data | 255 octets (UDT/XUDT) | outgoing: the action fails; incoming: cannot occur |
//! | Segmentation | refused | UDTS/XUDTS `segmentation not supported` when the sender asked for errors |

use super::ber;
use super::codec::ProtocolData;
use super::sccp::{self, SccpAddress, Scmg, Unitdata};
use super::tcap::{self, Code, Component, DialoguePdu, TcKind, TcMessage};
use super::{cap, gsm, map};
use crate::utils::clock::Instant;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::time::Duration;

/// Open TCAP dialogues kept per association.
pub const MAX_OPEN_DIALOGUES: usize = 1024;
/// A dialogue with no traffic for this long is aborted and forgotten.
pub const DIALOGUE_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
/// The M3UA Service Indicator for SCCP.
pub const SI_SCCP: u8 = 3;
/// `ActionResult::Custom` name for an SS7 intent.
pub const SS7_INTENT: &str = "ss7_intent";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Family {
    Map,
    Cap,
}

impl Family {
    pub fn name(self) -> &'static str {
        match self {
            Family::Map => "map",
            Family::Cap => "cap",
        }
    }
}

/// How to reach the far end of a dialogue: the MTP routing label, the SCCP addresses and the
/// M3UA parameters to put on the DATA.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Route {
    pub opc: u32,
    pub dpc: u32,
    pub ni: u8,
    pub mp: u8,
    pub sls: u8,
    /// The far end's address (our Called Party Address).
    pub remote: SccpAddress,
    /// Ours (our Calling Party Address).
    pub local: SccpAddress,
    /// UDT or XUDT, mirroring what the far end used.
    pub message_type: u8,
    pub protocol_class: u8,
    pub routing_context: Option<u32>,
    pub network_appearance: Option<u32>,
}

impl Route {
    /// The route back to whoever sent `pd`/`ud`.
    pub fn reply_to(
        pd: &ProtocolData,
        ud: &Unitdata,
        routing_context: Option<u32>,
        network_appearance: Option<u32>,
    ) -> Route {
        Route {
            opc: pd.dpc,
            dpc: pd.opc,
            ni: pd.ni,
            mp: pd.mp,
            sls: pd.sls,
            remote: ud.calling.clone(),
            local: ud.called.clone(),
            message_type: if ud.message_type == sccp::MSG_XUDT {
                sccp::MSG_XUDT
            } else {
                sccp::MSG_UDT
            },
            protocol_class: ud.protocol_class & 0x01,
            routing_context,
            network_appearance,
        }
    }

    fn to_json(&self) -> Value {
        json!({
            "opc": self.opc,
            "dpc": self.dpc,
            "sls": self.sls,
            "remote_address": self.remote.to_json(),
            "local_address": self.local.to_json(),
        })
    }
}

/// One message to put on the association.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outgoing {
    pub protocol_data: ProtocolData,
    pub routing_context: Option<u32>,
    pub network_appearance: Option<u32>,
    /// What it is, for the log.
    pub label: String,
}

fn wrap(route: &Route, sccp_bytes: Vec<u8>, label: String) -> Outgoing {
    Outgoing {
        protocol_data: ProtocolData {
            opc: route.opc,
            dpc: route.dpc,
            si: SI_SCCP,
            ni: route.ni,
            mp: route.mp,
            sls: route.sls,
            payload: sccp_bytes,
        },
        routing_context: route.routing_context,
        network_appearance: route.network_appearance,
        label,
    }
}

fn unitdata(route: &Route, tcap_bytes: &[u8]) -> Result<Vec<u8>, String> {
    if route.message_type == sccp::MSG_XUDT {
        sccp::encode_xudt(
            route.protocol_class,
            false,
            sccp::DEFAULT_HOP_COUNTER,
            &route.remote,
            &route.local,
            tcap_bytes,
        )
    } else {
        sccp::encode_udt(
            route.protocol_class,
            false,
            &route.remote,
            &route.local,
            tcap_bytes,
        )
    }
}

fn send_tcap(route: &Route, m: &TcMessage, label: String) -> Result<Outgoing, String> {
    Ok(wrap(route, unitdata(route, &m.encode())?, label))
}

/// One TCAP dialogue.
#[derive(Clone, Debug)]
pub struct Dialogue {
    pub id: u32,
    pub remote_tid: Option<Vec<u8>>,
    pub acn: Option<Vec<u64>>,
    pub family: Family,
    /// The peer opened with an AARQ that has not been answered with an AARE yet.
    pub aare_pending: bool,
    pub route: Route,
    pub last_activity: Instant,
    /// Invokes from the peer still awaiting a result or error: (invoke id, operation code).
    pub peer_invokes: Vec<(i64, i64)>,
    /// Invokes NetGet sent: (invoke id, operation code).
    pub own_invokes: Vec<(i64, i64)>,
    pub next_invoke_id: i64,
    /// The last thing the peer sent asked for an answer and none has gone out yet.
    pub awaiting_answer: bool,
    /// Follow-up depth (client): how many model turns led to this dialogue.
    pub depth: u32,
}

impl Dialogue {
    fn tid(&self) -> Vec<u8> {
        self.id.to_be_bytes().to_vec()
    }

    fn take_invoke_id(&mut self) -> i64 {
        let id = self.next_invoke_id;
        self.next_invoke_id = if id >= 127 { 1 } else { id + 1 };
        id
    }
}

/// The outcome of one inbound DATA.
#[derive(Debug)]
pub enum Inbound {
    /// Not SCCP; the raw M3UA path applies.
    NotSccp,
    /// SCCP NetGet could not decode as connectionless unitdata; the raw path applies, with why.
    Undecoded(String),
    /// Answered (or deliberately ignored) in Rust. `note` says what happened, for the log.
    Handled {
        replies: Vec<Outgoing>,
        note: String,
    },
    /// Raise this event.
    Event(Ss7Event),
}

#[derive(Debug)]
pub struct Ss7Event {
    pub family: Family,
    pub dialogue_id: u32,
    pub kind: TcKind,
    pub data: Value,
    /// Rust-side replies that go out before the model is asked (none today; kept for order).
    pub replies: Vec<Outgoing>,
    /// The dialogue ended with this message (End/Abort); nothing can be sent in it.
    pub ended: bool,
    pub depth: u32,
}

/// The transaction table and everything that reads or writes it.
pub struct Engine {
    dialogues: HashMap<u32, Dialogue>,
    next_tid: u32,
    /// Open dialogues allowed; [`MAX_OPEN_DIALOGUES`] unless a test lowers it.
    pub max_dialogues: usize,
    /// The route back to whoever sent the last SCCP message, for a dialogue NetGet opens.
    pub last_route: Option<Route>,
}

impl Default for Engine {
    fn default() -> Self {
        Self::new()
    }
}

impl Engine {
    pub fn new() -> Self {
        // Start the local transaction ids away from zero so they read as identifiers.
        let seed = crate::utils::clock::process_id().wrapping_mul(2654435761) & 0x00ff_ffff;
        Engine {
            dialogues: HashMap::new(),
            next_tid: 0x0100_0000 | seed,
            max_dialogues: MAX_OPEN_DIALOGUES,
            last_route: None,
        }
    }

    pub fn open_dialogues(&self) -> usize {
        self.dialogues.len()
    }

    pub fn dialogue(&self, id: u32) -> Option<&Dialogue> {
        self.dialogues.get(&id)
    }

    fn allocate(&mut self) -> u32 {
        loop {
            let id = self.next_tid;
            self.next_tid = self.next_tid.wrapping_add(1).max(1);
            if !self.dialogues.contains_key(&id) {
                return id;
            }
        }
    }

    fn find_by_local_tid(&mut self, tid: &[u8]) -> Option<&mut Dialogue> {
        if tid.len() != 4 {
            return None;
        }
        let id = u32::from_be_bytes([tid[0], tid[1], tid[2], tid[3]]);
        self.dialogues.get_mut(&id)
    }

    /// Decode one inbound DATA's user part.
    pub fn on_data(
        &mut self,
        pd: &ProtocolData,
        routing_context: Option<u32>,
        network_appearance: Option<u32>,
        now: Instant,
    ) -> Inbound {
        if pd.si != SI_SCCP {
            return Inbound::NotSccp;
        }
        let ud = match sccp::decode(&pd.payload) {
            Ok(u) => u,
            Err(e) => return Inbound::Undecoded(e),
        };
        let route = Route::reply_to(pd, &ud, routing_context, network_appearance);
        self.last_route = Some(route.clone());

        if ud.is_service_message() {
            return self.on_service_message(&ud);
        }
        if ud.called.ssn == Some(sccp::SSN_SCMG) {
            return on_scmg(&ud, &route);
        }
        if let Some(seg) = ud.segmentation {
            if !seg.is_whole_message() {
                let mut replies = Vec::new();
                if ud.return_on_error {
                    if let Ok(b) = sccp::encode_service(&ud, sccp::CAUSE_SEGMENTATION_NOT_SUPPORTED)
                    {
                        replies.push(wrap(&route, b, "XUDTS segmentation not supported".into()));
                    }
                }
                return Inbound::Handled {
                    replies,
                    note: format!(
                        "decision=refused_segmented: XUDT segment (first={}, remaining={}) — \
                         NetGet does not reassemble",
                        seg.first, seg.remaining
                    ),
                };
            }
        }
        let message = match TcMessage::decode(&ud.data) {
            Ok(m) => m,
            Err((cause, e)) => return refuse_undecodable(&ud.data, &route, cause, e),
        };
        match message.kind {
            TcKind::Begin => self.on_begin(message, route, now),
            TcKind::Continue => self.on_continue(message, route, now),
            TcKind::End | TcKind::Abort => self.on_end_or_abort(message, now),
            TcKind::Unidirectional => Inbound::Handled {
                replies: vec![],
                note: "TC-UNI ignored: NetGet answers dialogues, and a unidirectional message \
                       cannot be answered"
                    .into(),
            },
        }
    }

    fn on_service_message(&mut self, ud: &Unitdata) -> Inbound {
        let cause = ud.return_cause.unwrap_or(0);
        // The returned data is one of our own messages; its originating id names the dialogue.
        let ours = TcMessage::decode(&ud.data)
            .ok()
            .and_then(|m| m.otid.clone().or(m.dtid.clone()));
        let dialogue = ours.and_then(|tid| {
            if tid.len() == 4 {
                let id = u32::from_be_bytes([tid[0], tid[1], tid[2], tid[3]]);
                self.dialogues.remove(&id)
            } else {
                None
            }
        });
        match dialogue {
            Some(d) => Inbound::Event(Ss7Event {
                family: d.family,
                dialogue_id: d.id,
                kind: TcKind::Abort,
                data: json!({
                    "dialogue_id": d.id,
                    "tcap": "sccp_returned",
                    "sccp_return_cause": cause,
                    "note": "SCCP returned NetGet's message as undeliverable; the dialogue is closed",
                    "route": d.route.to_json(),
                }),
                replies: vec![],
                ended: true,
                depth: d.depth,
            }),
            None => Inbound::Handled {
                replies: vec![],
                note: format!(
                    "{} cause 0x{cause:02x} for no open dialogue; ignored",
                    ud.type_name()
                ),
            },
        }
    }

    fn on_begin(&mut self, m: TcMessage, route: Route, now: Instant) -> Inbound {
        let otid = m.otid.clone().unwrap_or_default();
        if self.dialogues.len() >= self.max_dialogues {
            return match send_tcap(
                &route,
                &TcMessage::p_abort(&otid, tcap::P_ABORT_RESOURCE_LIMITATION),
                "TC-P-ABORT resourceLimitation".into(),
            ) {
                Ok(o) => Inbound::Handled {
                    replies: vec![o],
                    note: format!(
                        "decision=refused_dialogue_cap: {} dialogues already open",
                        self.dialogues.len()
                    ),
                },
                Err(e) => Inbound::Handled {
                    replies: vec![],
                    note: e,
                },
            };
        }
        let acn = m
            .dialogue
            .as_ref()
            .and_then(|d| d.acn().map(|a| a.to_vec()));
        let family = match &acn {
            Some(a) if map::context_of(a).is_some() => Some(Family::Map),
            Some(a) if cap::context_of(a).is_some() => Some(Family::Cap),
            Some(_) => None,
            // No dialogue portion is MAP v1 (CAP always has one); its operations are checked one
            // by one below, and one NetGet does not implement is answered with a Reject.
            None => Some(Family::Map),
        };
        let Some(family) = family else {
            // An application context NetGet does not implement: refuse it the way TCAP users do,
            // with an AARE carrying application-context-name-not-supported in a TC-U-ABORT.
            let reply = TcMessage {
                kind: TcKind::Abort,
                otid: None,
                dtid: Some(otid),
                dialogue: acn.clone().map(|a| DialoguePdu::Response {
                    acn: a,
                    result: 1,
                    diagnostic_provider: false,
                    diagnostic: tcap::DIAG_USER_ACN_NOT_SUPPORTED,
                }),
                components: vec![],
                p_abort_cause: None,
            };
            let name = acn
                .as_deref()
                .map(ber::oid_string)
                .unwrap_or_else(|| "none".into());
            return match send_tcap(&route, &reply, "TC-U-ABORT ACN not supported".into()) {
                Ok(o) => Inbound::Handled {
                    replies: vec![o],
                    note: format!(
                        "decision=refused_application_context: {name} is neither a MAP context \
                         nor a CAP gsmSSF-to-gsmSCF context"
                    ),
                },
                Err(e) => Inbound::Handled {
                    replies: vec![],
                    note: e,
                },
            };
        };

        let id = self.allocate();
        let mut d = Dialogue {
            id,
            remote_tid: Some(otid),
            acn: acn.clone(),
            family,
            aare_pending: matches!(m.dialogue, Some(DialoguePdu::Request { .. })),
            route,
            last_activity: now,
            peer_invokes: vec![],
            own_invokes: vec![],
            next_invoke_id: 1,
            awaiting_answer: false,
            depth: 0,
        };
        let (components, rejects) = describe_components(&mut d, &m.components);
        if !rejects.is_empty() {
            // Rust answers an operation it cannot decode: TC-END with the AARE and a Reject per
            // bad invoke. The model is not consulted about a message it could not read.
            let reply = TcMessage {
                kind: TcKind::End,
                otid: None,
                dtid: d.remote_tid.clone(),
                dialogue: d.acn.clone().filter(|_| d.aare_pending).map(accept),
                components: rejects,
                p_abort_cause: None,
            };
            return match send_tcap(&d.route, &reply, "TC-END with Reject".into()) {
                Ok(o) => Inbound::Handled {
                    replies: vec![o],
                    note: "decision=rejected_operation: an invoke NetGet cannot decode was \
                           answered with Reject"
                        .into(),
                },
                Err(e) => Inbound::Handled {
                    replies: vec![],
                    note: e,
                },
            };
        }
        // activityTest needs no decision.
        if let Some(r) = self.rust_answers(&mut d) {
            return r;
        }
        d.awaiting_answer = needs_answer(&d, &components);
        let data = event_data(&d, &m, components);
        let ev = Ss7Event {
            family,
            dialogue_id: id,
            kind: TcKind::Begin,
            data,
            replies: vec![],
            ended: false,
            depth: 0,
        };
        self.dialogues.insert(id, d);
        Inbound::Event(ev)
    }

    fn rust_answers(&mut self, d: &mut Dialogue) -> Option<Inbound> {
        if d.family == Family::Cap
            && !d.peer_invokes.is_empty()
            && d.peer_invokes
                .iter()
                .all(|(_, op)| *op == cap::OP_ACTIVITY_TEST)
        {
            let comps = d
                .peer_invokes
                .drain(..)
                .map(|(id, _)| Component::ReturnResult {
                    last: true,
                    invoke_id: id,
                    opcode: None,
                    parameter: None,
                })
                .collect();
            let reply = TcMessage {
                kind: TcKind::End,
                otid: None,
                dtid: d.remote_tid.clone(),
                dialogue: d.acn.clone().filter(|_| d.aare_pending).map(accept),
                components: comps,
                p_abort_cause: None,
            };
            self.dialogues.remove(&d.id);
            return Some(
                match send_tcap(&d.route, &reply, "activityTest result".into()) {
                    Ok(o) => Inbound::Handled {
                        replies: vec![o],
                        note: "CAP activityTest answered in Rust".into(),
                    },
                    Err(e) => Inbound::Handled {
                        replies: vec![],
                        note: e,
                    },
                },
            );
        }
        None
    }

    fn on_continue(&mut self, m: TcMessage, route: Route, now: Instant) -> Inbound {
        let dtid = m.dtid.clone().unwrap_or_default();
        let otid = m.otid.clone().unwrap_or_default();
        let Some(d) = self.find_by_local_tid(&dtid) else {
            return p_abort_unknown(&route, &otid, &dtid);
        };
        match &d.remote_tid {
            // The first answer to a Begin NetGet sent: it names the peer's transaction.
            None => d.remote_tid = Some(otid.clone()),
            Some(known) if *known != otid => {
                let reply = TcMessage::p_abort(&otid, tcap::P_ABORT_INCORRECT_TRANSACTION_PORTION);
                return match send_tcap(
                    &route,
                    &reply,
                    "TC-P-ABORT incorrectTransactionPortion".into(),
                ) {
                    Ok(o) => Inbound::Handled {
                        replies: vec![o],
                        note: format!(
                            "decision=refused_transaction: TC-CONTINUE for dialogue {} from \
                             transaction {} (expected {})",
                            d.id,
                            ber::hex(&otid),
                            ber::hex(known)
                        ),
                    },
                    Err(e) => Inbound::Handled {
                        replies: vec![],
                        note: e,
                    },
                };
            }
            Some(_) => {}
        }
        d.last_activity = now;
        // Follow the peer's MTP/SCCP addressing from here on (its first Continue may come from a
        // different point code than the one the Begin was routed to).
        d.route.remote = route.remote.clone();
        d.route.dpc = route.dpc;
        d.route.sls = route.sls;
        let mut d = d.clone();
        if let Some(DialoguePdu::Response { result, .. }) = &m.dialogue {
            if *result != 0 {
                self.dialogues.remove(&d.id);
                return Inbound::Event(Ss7Event {
                    family: d.family,
                    dialogue_id: d.id,
                    kind: TcKind::Continue,
                    data: event_data(&d, &m, vec![]),
                    replies: vec![],
                    ended: true,
                    depth: d.depth,
                });
            }
        }
        let (components, rejects) = describe_components(&mut d, &m.components);
        if !rejects.is_empty() {
            let reply = TcMessage {
                kind: TcKind::Continue,
                otid: Some(d.tid()),
                dtid: d.remote_tid.clone(),
                dialogue: None,
                components: rejects,
                p_abort_cause: None,
            };
            if let Ok(o) = send_tcap(&d.route, &reply, "TC-CONTINUE with Reject".into()) {
                self.dialogues.insert(d.id, d.clone());
                return Inbound::Handled {
                    replies: vec![o],
                    note: "decision=rejected_operation: an invoke NetGet cannot decode was \
                           answered with Reject"
                        .into(),
                };
            }
        }
        if let Some(r) = self.rust_answers(&mut d) {
            return r;
        }
        d.awaiting_answer = needs_answer(&d, &components);
        let data = event_data(&d, &m, components);
        let ev = Ss7Event {
            family: d.family,
            dialogue_id: d.id,
            kind: TcKind::Continue,
            data,
            replies: vec![],
            ended: false,
            depth: d.depth,
        };
        self.dialogues.insert(d.id, d);
        Inbound::Event(ev)
    }

    fn on_end_or_abort(&mut self, m: TcMessage, _now: Instant) -> Inbound {
        let dtid = m.dtid.clone().unwrap_or_default();
        let id = match self.find_by_local_tid(&dtid) {
            Some(d) => d.id,
            None => {
                // Neither End nor Abort can be answered (Q.774: discard).
                return Inbound::Handled {
                    replies: vec![],
                    note: format!(
                        "decision=discarded_unknown_transaction: TC-{} for transaction {} which \
                         no dialogue here owns",
                        m.kind.name().to_uppercase(),
                        ber::hex(&dtid)
                    ),
                };
            }
        };
        let mut d = self.dialogues.remove(&id).expect("found above");
        let (components, _) = describe_components(&mut d, &m.components);
        Inbound::Event(Ss7Event {
            family: d.family,
            dialogue_id: d.id,
            kind: m.kind,
            data: event_data(&d, &m, components),
            replies: vec![],
            ended: true,
            depth: d.depth,
        })
    }

    /// Whether the model still owes `id` an answer.
    pub fn awaiting_answer(&self, id: u32) -> bool {
        self.dialogues
            .get(&id)
            .map(|d| d.awaiting_answer)
            .unwrap_or(false)
    }

    /// Close a dialogue the model left unanswered or could not be asked about.
    ///
    /// `fail_closed`: MAP answers each pending invoke with ReturnError systemFailure in a TC-END
    /// (with the AARE, so the error reaches the MAP user rather than a dialogue failure); CAP has
    /// no such answer for InitialDP that is not a decision, so it is a TC-U-ABORT. Without
    /// `fail_closed` (the model said nothing) both are a TC-U-ABORT.
    pub fn close_unanswered(&mut self, id: u32, fail_closed: bool) -> Option<Outgoing> {
        let d = self.dialogues.remove(&id)?;
        let reply = if fail_closed && d.family == Family::Map && !d.peer_invokes.is_empty() {
            TcMessage {
                kind: TcKind::End,
                otid: None,
                dtid: d.remote_tid.clone(),
                dialogue: d.acn.clone().filter(|_| d.aare_pending).map(accept),
                components: d
                    .peer_invokes
                    .iter()
                    .map(|(inv, _)| Component::ReturnError {
                        invoke_id: *inv,
                        error: Code::Local(map::ERROR_SYSTEM_FAILURE),
                        parameter: None,
                    })
                    .collect(),
                p_abort_cause: None,
            }
        } else {
            user_abort(&d, tcap::DIAG_USER_NO_REASON_GIVEN)
        };
        let label = if reply.kind == TcKind::End {
            "TC-END ReturnError systemFailure"
        } else {
            "TC-U-ABORT"
        };
        send_tcap(&d.route, &reply, label.into()).ok()
    }

    /// Abort and forget dialogues idle past [`DIALOGUE_IDLE_TIMEOUT`].
    pub fn expire(&mut self, now: Instant) -> Vec<(Dialogue, Option<Outgoing>)> {
        let stale: Vec<u32> = self
            .dialogues
            .values()
            .filter(|d| now.saturating_duration_since(d.last_activity) >= DIALOGUE_IDLE_TIMEOUT)
            .map(|d| d.id)
            .collect();
        stale
            .into_iter()
            .filter_map(|id| self.dialogues.remove(&id))
            .map(|d| {
                let out = d.remote_tid.as_ref().and_then(|_| {
                    send_tcap(
                        &d.route,
                        &user_abort(&d, tcap::DIAG_USER_NO_REASON_GIVEN),
                        "TC-U-ABORT idle".into(),
                    )
                    .ok()
                });
                (d, out)
            })
            .collect()
    }

    /// The soonest moment a dialogue will expire, if any are open.
    pub fn next_expiry(&self) -> Option<Instant> {
        self.dialogues
            .values()
            .map(|d| d.last_activity + DIALOGUE_IDLE_TIMEOUT)
            .min()
    }

    /// Turn the model's intent into TCAP for its dialogue. `default_route` is used when the intent
    /// opens a new dialogue (`send_map_request` / `send_cap_operations` without a `dialogue_id`).
    pub fn apply(
        &mut self,
        intent: &Value,
        default_route: Option<&Route>,
        depth: u32,
        now: Instant,
    ) -> Result<(u32, Outgoing), String> {
        let kind = intent["type"].as_str().unwrap_or_default();
        let dialogue_id = match intent.get("dialogue_id") {
            None | Some(Value::Null) => None,
            Some(v) => Some(
                v.as_u64()
                    .filter(|n| *n <= u32::MAX as u64)
                    .ok_or("dialogue_id must be the integer from the event")?
                    as u32,
            ),
        };
        match kind {
            "send_map_request" | "send_cap_operations" if dialogue_id.is_none() => {
                self.originate(kind, intent, default_route, depth, now)
            }
            _ => {
                let id = dialogue_id.ok_or_else(|| format!("{kind} needs a dialogue_id"))?;
                let mut d = self.dialogues.remove(&id).ok_or_else(|| {
                    format!("dialogue {id} is not open (it ended or never existed)")
                })?;
                let result = continue_dialogue(&mut d, kind, intent, depth, now);
                match result {
                    Ok((out, keep)) => {
                        if keep {
                            self.dialogues.insert(id, d);
                        }
                        Ok((id, out))
                    }
                    Err(e) => {
                        self.dialogues.insert(id, d);
                        Err(e)
                    }
                }
            }
        }
    }

    fn originate(
        &mut self,
        kind: &str,
        intent: &Value,
        default_route: Option<&Route>,
        depth: u32,
        now: Instant,
    ) -> Result<(u32, Outgoing), String> {
        if self.dialogues.len() >= self.max_dialogues {
            return Err(format!(
                "{} dialogues are already open; NetGet opens no more",
                self.dialogues.len()
            ));
        }
        let mut route = default_route
            .cloned()
            .ok_or("no route: this association has no peer address to open a dialogue towards")?;
        if let Some(called) = intent.get("called_address").filter(|v| !v.is_null()) {
            route.remote = SccpAddress::from_json(called, "called_address")?;
        }
        let mut user_information = Vec::new();
        let (family, acn, components) = if kind == "send_map_request" {
            let op = intent["operation"]
                .as_str()
                .and_then(map::operation_by_name)
                .ok_or_else(|| format!("operation must be one of {}", map::operation_names()))?;
            let version = intent
                .get("context_version")
                .and_then(Value::as_u64)
                .unwrap_or(op.version);
            let argument = intent.get("argument").unwrap_or(&Value::Null);
            let arg = map::encode_argument(op.code, argument)?;
            // MAP-OpenInfo. networkUnstructuredSsContext requires it (TS 29.002 section 7.3: the
            // USSD dialogue names the subscriber and the originator), so for USSD the references
            // default to the MSISDN and this end's global title.
            let reference = |field: &str| -> Result<Option<gsm::Address>, String> {
                intent
                    .get(field)
                    .filter(|v| !v.is_null())
                    .map(|v| gsm::Address::from_json(v, field))
                    .transpose()
            };
            let mut destination = reference("destination_reference")?;
            let mut origination = reference("origination_reference")?;
            if op.context == 19 {
                if destination.is_none() {
                    destination = argument
                        .get("msisdn")
                        .filter(|v| !v.is_null())
                        .map(|v| gsm::Address::from_json(v, "msisdn"))
                        .transpose()?;
                }
                if origination.is_none() {
                    origination = route
                        .local
                        .global_title
                        .as_ref()
                        .map(|g| gsm::Address::international(&g.digits));
                }
            }
            if destination.is_some() || origination.is_some() {
                user_information.push(tcap::map_open_user_information(
                    destination.as_ref(),
                    origination.as_ref(),
                )?);
            }
            (
                Family::Map,
                map::acn(op.context, version),
                vec![(op.code, Some(arg))],
            )
        } else {
            let phase = intent.get("cap_phase").and_then(Value::as_u64).unwrap_or(2);
            let acn = cap::context_for_phase(phase)
                .ok_or("cap_phase must be 2, 3 or 4")?
                .to_vec();
            (Family::Cap, acn, cap_invokes(intent)?)
        };
        let id = self.allocate();
        let mut d = Dialogue {
            id,
            remote_tid: None,
            acn: Some(acn.clone()),
            family,
            aare_pending: false,
            route,
            last_activity: now,
            peer_invokes: vec![],
            own_invokes: vec![],
            next_invoke_id: 1,
            awaiting_answer: false,
            depth,
        };
        let comps = invokes(&mut d, components)?;
        let m = TcMessage {
            kind: TcKind::Begin,
            otid: Some(d.tid()),
            dtid: None,
            dialogue: Some(DialoguePdu::Request {
                acn,
                user_information,
            }),
            components: comps,
            p_abort_cause: None,
        };
        let out = send_tcap(
            &d.route,
            &m,
            format!("TC-BEGIN {} dialogue {id}", family.name()),
        )?;
        self.dialogues.insert(id, d);
        Ok((id, out))
    }
}

fn accept(acn: Vec<u64>) -> DialoguePdu {
    DialoguePdu::Response {
        acn,
        result: 0,
        diagnostic_provider: false,
        diagnostic: tcap::DIAG_USER_NULL,
    }
}

fn user_abort(d: &Dialogue, diagnostic: u8) -> TcMessage {
    // Before the AARE has gone out, a refusal is an AARE with result reject-permanent;
    // afterwards it is an ABRT from the dialogue-service-user.
    let dialogue = match (&d.acn, d.aare_pending) {
        (Some(acn), true) => Some(DialoguePdu::Response {
            acn: acn.clone(),
            result: 1,
            diagnostic_provider: false,
            diagnostic,
        }),
        (Some(_), false) => Some(DialoguePdu::Abort {
            source: 0,
            user_information: vec![],
        }),
        (None, _) => None,
    };
    TcMessage {
        kind: TcKind::Abort,
        otid: None,
        dtid: d.remote_tid.clone(),
        dialogue,
        components: vec![],
        // MAP v1 has no dialogue portion: its user abort is an Abort carrying no reason at all,
        // which Q.774 reads as TC-U-ABORT.
        p_abort_cause: None,
    }
}

fn p_abort_unknown(route: &Route, otid: &[u8], dtid: &[u8]) -> Inbound {
    let reply = TcMessage::p_abort(otid, tcap::P_ABORT_UNRECOGNIZED_TRANSACTION_ID);
    match send_tcap(route, &reply, "TC-P-ABORT unrecognizedTransactionID".into()) {
        Ok(o) => Inbound::Handled {
            replies: vec![o],
            note: format!(
                "decision=refused_transaction: TC-CONTINUE for transaction {} which no dialogue \
                 here owns",
                ber::hex(dtid)
            ),
        },
        Err(e) => Inbound::Handled {
            replies: vec![],
            note: e,
        },
    }
}

fn refuse_undecodable(data: &[u8], route: &Route, cause: u8, e: ber::BerError) -> Inbound {
    // Find the originating transaction id leniently so the peer's transaction is told.
    let otid = ber::shallow_children(data).and_then(|kids| {
        kids.into_iter()
            .find(|(t, _)| t.same(ber::CLASS_APPLICATION, 8))
            .map(|(_, v)| v.to_vec())
            .filter(|v| (1..=4).contains(&v.len()))
    });
    let note = format!(
        "decision=refused_malformed: TCAP did not decode ({e}); P-Abort cause {}",
        tcap::p_abort_name(cause)
    );
    match otid {
        Some(otid) => match send_tcap(
            route,
            &TcMessage::p_abort(&otid, cause),
            format!("TC-P-ABORT {}", tcap::p_abort_name(cause)),
        ) {
            Ok(o) => Inbound::Handled {
                replies: vec![o],
                note,
            },
            Err(e) => Inbound::Handled {
                replies: vec![],
                note: e,
            },
        },
        None => Inbound::Handled {
            replies: vec![],
            note: format!("{note}; no transaction id to answer, discarded"),
        },
    }
}

fn on_scmg(ud: &Unitdata, route: &Route) -> Inbound {
    let m = match Scmg::decode(&ud.data) {
        Ok(m) => m,
        Err(e) => {
            return Inbound::Handled {
                replies: vec![],
                note: format!("SCMG message discarded: {e}"),
            }
        }
    };
    if m.format != sccp::SCMG_SST {
        return Inbound::Handled {
            replies: vec![],
            note: format!(
                "SCMG {} for SSN {} at PC {} noted",
                m.name(),
                m.affected_ssn,
                m.affected_pc
            ),
        };
    }
    // Subsystem Status Test: every subsystem here is answered by the model, so each is allowed.
    let ssa = Scmg {
        format: sccp::SCMG_SSA,
        ..m
    };
    let mut scmg_route = route.clone();
    scmg_route.message_type = sccp::MSG_UDT;
    scmg_route.protocol_class = 0;
    match sccp::encode_udt(0, false, &ud.calling, &ud.called, &ssa.encode()) {
        Ok(b) => Inbound::Handled {
            replies: vec![wrap(&scmg_route, b, "SCMG SSA".into())],
            note: format!("SCMG SST for SSN {} answered SSA in Rust", m.affected_ssn),
        },
        Err(e) => Inbound::Handled {
            replies: vec![],
            note: e,
        },
    }
}

/// Describe each component for the model, recording the peer's invokes on the dialogue and
/// matching results to NetGet's own. Returns (descriptions, Reject components to send).
fn describe_components(d: &mut Dialogue, comps: &[Component]) -> (Vec<Value>, Vec<Component>) {
    let mut out = Vec::new();
    let mut rejects = Vec::new();
    for c in comps {
        match c {
            Component::Invoke {
                invoke_id,
                linked_id,
                opcode,
                parameter,
            } => {
                let code = opcode.local();
                let decoded = match (d.family, code) {
                    (Family::Map, Some(code)) => match map::operation_by_code(code) {
                        Some(op) => map::decode_argument(code, parameter.as_ref())
                            .map(|a| (op.name.to_string(), a)),
                        None => Err(format!("MAP operation {code} is not implemented")),
                    },
                    (Family::Cap, Some(code)) => match cap::operation_name(code) {
                        Some(name) => cap::decode_argument(code, parameter.as_ref())
                            .map(|a| (name.to_string(), a)),
                        None => Err(format!("CAP operation {code} is not implemented")),
                    },
                    (_, None) => Err("global operation codes are not implemented".into()),
                };
                match decoded {
                    Ok((name, argument)) => {
                        d.peer_invokes.push((*invoke_id, code.unwrap_or(-1)));
                        out.push(json!({
                            "component": "invoke",
                            "invoke_id": invoke_id,
                            "linked_id": linked_id,
                            "operation": name,
                            "opcode": code,
                            "argument": argument,
                        }));
                    }
                    Err(e) => {
                        let unknown = e.contains("not implemented");
                        rejects.push(Component::Reject {
                            invoke_id: Some(*invoke_id),
                            problem_type: tcap::PROBLEM_INVOKE,
                            problem: if unknown {
                                tcap::INVOKE_UNRECOGNIZED_OPERATION
                            } else {
                                tcap::INVOKE_MISTYPED_PARAMETER
                            },
                        });
                        out.push(json!({
                            "component": "invoke",
                            "invoke_id": invoke_id,
                            "opcode": code,
                            "rejected": e,
                        }));
                    }
                }
            }
            Component::ReturnResult {
                last,
                invoke_id,
                opcode,
                parameter,
            } => {
                let own = d.own_invokes.iter().position(|(i, _)| i == invoke_id);
                let code = own
                    .map(|p| d.own_invokes[p].1)
                    .or_else(|| opcode.as_ref().and_then(Code::local));
                if *last {
                    if let Some(p) = own {
                        d.own_invokes.remove(p);
                    }
                }
                let result = match (d.family, code) {
                    (Family::Map, Some(code)) => map::decode_result(code, parameter.as_ref())
                        .unwrap_or_else(|e| json!({ "error": e })),
                    _ => json!({}),
                };
                out.push(json!({
                    "component": c.kind_name(),
                    "invoke_id": invoke_id,
                    "matched_own_invoke": own.is_some(),
                    "operation": code.and_then(|c| op_name(d.family, c)),
                    "result": result,
                }));
            }
            Component::ReturnError {
                invoke_id,
                error,
                parameter,
            } => {
                let own = d.own_invokes.iter().position(|(i, _)| i == invoke_id);
                let op = own.map(|p| d.own_invokes.remove(p).1);
                let code = error.local().unwrap_or(-1);
                out.push(json!({
                    "component": "return_error",
                    "invoke_id": invoke_id,
                    "matched_own_invoke": op.is_some(),
                    "operation": op.and_then(|c| op_name(d.family, c)),
                    "error": match d.family {
                        Family::Map => map::error_name(code),
                        Family::Cap => cap::error_name(code),
                    },
                    "error_code": code,
                    "parameter": match d.family {
                        Family::Map => map::decode_error_parameter(code, parameter.as_ref()),
                        Family::Cap => Value::Null,
                    },
                }));
            }
            Component::Reject {
                invoke_id,
                problem_type,
                problem,
            } => {
                if let Some(i) = invoke_id {
                    d.own_invokes.retain(|(x, _)| x != i);
                }
                out.push(json!({
                    "component": "reject",
                    "invoke_id": invoke_id,
                    "problem": tcap::reject_problem_name(*problem_type, *problem),
                }));
            }
        }
    }
    (out, rejects)
}

fn op_name(family: Family, code: i64) -> Option<String> {
    match family {
        Family::Map => map::operation_by_code(code).map(|o| o.name.to_string()),
        Family::Cap => cap::operation_name(code).map(str::to_string),
    }
}

fn needs_answer(d: &Dialogue, components: &[Value]) -> bool {
    match d.family {
        Family::Map => !d.peer_invokes.is_empty(),
        Family::Cap => components.iter().any(|c| {
            c["component"] == "invoke"
                && (c["opcode"] == cap::OP_INITIAL_DP
                    || (c["opcode"] == cap::OP_EVENT_REPORT_BCSM
                        && c["argument"]["message_type"] == "request"))
        }),
    }
}

fn event_data(d: &Dialogue, m: &TcMessage, components: Vec<Value>) -> Value {
    let context = d.acn.as_ref().map(|a| {
        let (name, version) = map::context_of(a)
            .or_else(|| cap::context_of(a))
            .unwrap_or(("unknown", 0));
        json!({"name": name, "version": version, "oid": ber::oid_string(a)})
    });
    let mut v = json!({
        "dialogue_id": d.id,
        "tcap": m.kind.name(),
        "family": d.family.name(),
        "application_context": context,
        "dialogue_portion": m.dialogue.as_ref().map(DialoguePdu::to_json),
        "components": components,
        "awaiting_answer_to": d.peer_invokes.iter().map(|(i, _)| *i).collect::<Vec<_>>(),
        "route": d.route.to_json(),
        "peer_transaction_id": d.remote_tid.as_deref().map(ber::hex),
    });
    if m.kind == TcKind::Abort {
        v["abort"] = json!({
            "p_abort_cause": m.p_abort_cause.map(tcap::p_abort_name),
            "user_abort": m.dialogue.as_ref().map(DialoguePdu::to_json),
        });
    }
    v
}

/// Encode a list of invokes on `d`, recording them as NetGet's own.
fn invokes(d: &mut Dialogue, list: Vec<(i64, Option<Vec<u8>>)>) -> Result<Vec<Component>, String> {
    let mut out = Vec::new();
    for (code, arg) in list {
        let id = d.take_invoke_id();
        let parameter = arg
            .map(|b| ber::decode(&b).map_err(|e| e.to_string()))
            .transpose()?;
        d.own_invokes.push((id, code));
        out.push(Component::Invoke {
            invoke_id: id,
            linked_id: None,
            opcode: Code::Local(code),
            parameter,
        });
    }
    Ok(out)
}

/// (operation code, encoded argument) pairs.
type Invokes = Vec<(i64, Option<Vec<u8>>)>;

fn cap_invokes(intent: &Value) -> Result<Invokes, String> {
    let ops = intent
        .get("operations")
        .and_then(Value::as_array)
        .ok_or("operations is required (a list)")?;
    if ops.is_empty() || ops.len() > tcap::MAX_COMPONENTS {
        return Err(format!(
            "operations must hold 1..{} entries",
            tcap::MAX_COMPONENTS
        ));
    }
    ops.iter()
        .enumerate()
        .map(|(i, op)| {
            let name = op["operation"]
                .as_str()
                .ok_or_else(|| format!("operations[{i}].operation is required"))?;
            let code = cap::operation_code(name).ok_or_else(|| {
                format!(
                    "operations[{i}].operation {name:?} is not one of {}",
                    cap::OPERATIONS
                        .iter()
                        .map(|(n, _)| *n)
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            })?;
            Ok((code, cap::encode_argument(code, op)?))
        })
        .collect()
}

/// Encode the model's intent for an open dialogue. Returns the message and whether the dialogue
/// stays open.
fn continue_dialogue(
    d: &mut Dialogue,
    kind: &str,
    intent: &Value,
    depth: u32,
    now: Instant,
) -> Result<(Outgoing, bool), String> {
    let pick_invoke = |d: &Dialogue| -> Result<(i64, i64), String> {
        match intent.get("invoke_id").and_then(Value::as_i64) {
            Some(i) => d
                .peer_invokes
                .iter()
                .find(|(x, _)| *x == i)
                .copied()
                .ok_or_else(|| {
                    format!("invoke {i} in dialogue {} is not awaiting an answer", d.id)
                }),
            None => d
                .peer_invokes
                .first()
                .copied()
                .ok_or_else(|| format!("dialogue {} has no invoke awaiting an answer", d.id)),
        }
    };
    let end_default;
    let mut components = Vec::new();
    let mut message_kind = None;
    match kind {
        "send_map_result" => {
            if d.family != Family::Map {
                return Err(format!("dialogue {} is CAP, not MAP", d.id));
            }
            let (inv, code) = pick_invoke(d)?;
            let result = map::encode_result(code, intent.get("result").unwrap_or(&json!({})))?;
            let parameter = result
                .map(|b| ber::decode(&b).map_err(|e| e.to_string()))
                .transpose()?;
            d.peer_invokes.retain(|(x, _)| *x != inv);
            components.push(Component::ReturnResult {
                last: true,
                invoke_id: inv,
                opcode: parameter.as_ref().map(|_| Code::Local(code)),
                parameter,
            });
            end_default = d.peer_invokes.is_empty();
        }
        "send_map_error" => {
            let (inv, _) = pick_invoke(d)?;
            let code = match d.family {
                Family::Map => map::error_code(intent.get("error").unwrap_or(&Value::Null))?,
                Family::Cap => {
                    let e = intent.get("error").unwrap_or(&Value::Null);
                    e.as_i64()
                        .or_else(|| {
                            cap::CAP_ERRORS
                                .iter()
                                .find(|(n, _)| Some(*n) == e.as_str())
                                .map(|(_, c)| *c)
                        })
                        .ok_or("error must be a CAP error name or code")?
                }
            };
            let parameter = match d.family {
                Family::Map => map::encode_error_parameter(code, intent)?
                    .map(|b| ber::decode(&b).map_err(|e| e.to_string()))
                    .transpose()?,
                Family::Cap => None,
            };
            d.peer_invokes.retain(|(x, _)| *x != inv);
            components.push(Component::ReturnError {
                invoke_id: inv,
                error: Code::Local(code),
                parameter,
            });
            end_default = d.peer_invokes.is_empty();
        }
        "send_map_request" => {
            if d.family != Family::Map {
                return Err(format!("dialogue {} is CAP, not MAP", d.id));
            }
            let op = intent["operation"]
                .as_str()
                .and_then(map::operation_by_name)
                .ok_or_else(|| format!("operation must be one of {}", map::operation_names()))?;
            let arg =
                map::encode_argument(op.code, intent.get("argument").unwrap_or(&Value::Null))?;
            components = invokes(d, vec![(op.code, Some(arg))])?;
            end_default = false;
        }
        "send_cap_operations" => {
            if d.family != Family::Cap {
                return Err(format!("dialogue {} is MAP, not CAP", d.id));
            }
            let list = cap_invokes(intent)?;
            // Arming detection points means the SCF expects to hear back on this dialogue.
            let arms = list
                .iter()
                .any(|(c, _)| *c == cap::OP_REQUEST_REPORT_BCSM_EVENT);
            components = invokes(d, list)?;
            // CAP invokes (Connect, Continue, ReleaseCall, RRBCSM) are class 2/4: nothing comes
            // back for them, so they are not awaited.
            d.own_invokes.clear();
            d.peer_invokes.clear();
            end_default = !arms;
        }
        "send_tcap_end" => {
            message_kind = Some(TcKind::End);
            end_default = true;
        }
        "send_tcap_abort" => {
            let diag = match intent.get("reason").and_then(Value::as_str) {
                Some("application_context_not_supported") => tcap::DIAG_USER_ACN_NOT_SUPPORTED,
                _ => tcap::DIAG_USER_NO_REASON_GIVEN,
            };
            let m = user_abort(d, diag);
            let out = send_tcap(&d.route, &m, format!("TC-U-ABORT dialogue {}", d.id))?;
            return Ok((out, false));
        }
        other => return Err(format!("{other} is not an SS7 dialogue action")),
    }
    let end = intent
        .get("end_dialogue")
        .and_then(Value::as_bool)
        .unwrap_or(end_default);
    let Some(remote) = d.remote_tid.clone() else {
        return Err(format!(
            "dialogue {} has not been answered by the peer yet; wait for its TC-CONTINUE",
            d.id
        ));
    };
    let kind = message_kind.unwrap_or(if end { TcKind::End } else { TcKind::Continue });
    let m = TcMessage {
        kind,
        otid: if kind == TcKind::Continue {
            Some(d.tid())
        } else {
            None
        },
        dtid: Some(remote),
        dialogue: d.acn.clone().filter(|_| d.aare_pending).map(accept),
        components,
        p_abort_cause: None,
    };
    let out = send_tcap(
        &d.route,
        &m,
        format!("TC-{} dialogue {}", kind.name().to_uppercase(), d.id),
    )?;
    d.aare_pending = false;
    d.awaiting_answer = false;
    d.last_activity = now;
    d.depth = depth;
    Ok((out, kind == TcKind::Continue))
}

/// The action names the engine accepts, for routing `ActionResult::Custom` intents.
pub const INTENTS: &[&str] = &[
    "send_map_request",
    "send_map_result",
    "send_map_error",
    "send_cap_operations",
    "send_tcap_end",
    "send_tcap_abort",
];

/// Validate an intent's static shape without a dialogue (for `execute_action`): every field the
/// encoders need is checked now so a malformed action fails where the model can see it.
pub fn check_intent(intent: &Value) -> Result<(), String> {
    let kind = intent["type"].as_str().unwrap_or_default();
    let needs_dialogue = !matches!(kind, "send_map_request" | "send_cap_operations");
    if needs_dialogue
        && !intent
            .get("dialogue_id")
            .map(|v| v.is_u64())
            .unwrap_or(false)
    {
        return Err(format!("{kind} needs the dialogue_id from the event"));
    }
    match kind {
        "send_map_request" => {
            let op = intent["operation"]
                .as_str()
                .and_then(map::operation_by_name)
                .ok_or_else(|| format!("operation must be one of {}", map::operation_names()))?;
            map::encode_argument(op.code, intent.get("argument").unwrap_or(&Value::Null))?;
        }
        "send_map_result" => {
            if let Some(op) = intent
                .get("operation")
                .and_then(Value::as_str)
                .and_then(map::operation_by_name)
            {
                map::encode_result(op.code, intent.get("result").unwrap_or(&json!({})))?;
            }
        }
        "send_map_error" => {
            if intent.get("error").is_none() {
                return Err(
                    "error is required (a MAP error name such as unknownSubscriber)".into(),
                );
            }
        }
        "send_cap_operations" => {
            cap_invokes(intent)?;
        }
        "send_tcap_end" | "send_tcap_abort" => {}
        other => return Err(format!("{other} is not an SS7 dialogue action")),
    }
    Ok(())
}
