//! LLMNR (RFC 4795) protocol actions.
//!
//! LLMNR reuses the DNS message format, so every packet here is built with `hickory-proto`.
//! What differs from DNS is the *header flag layout* and the *silence rule*; both are
//! encoded below and explained in `src/server/llmnr/CLAUDE.md`.

use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::EventType;
use crate::state::app_state::AppState;
use anyhow::{Context, Result};
use hickory_proto::op::{Header, Message as DnsMessage, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{rdata, DNSClass, Name, RData, Record, RecordType};
use serde_json::json;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::sync::LazyLock;

/// The port LLMNR queries are sent to and received on (RFC 4795 §2).
pub const LLMNR_PORT: u16 = 5355;

/// IPv4 link-scope multicast group for LLMNR (RFC 4795 §2).
pub const LLMNR_IPV4_GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 252);

/// IPv6 link-scope multicast group for LLMNR (RFC 4795 §2).
pub const LLMNR_IPV6_GROUP: Ipv6Addr = Ipv6Addr::new(0xFF02, 0, 0, 0, 0, 0, 0x0001, 0x0003);

/// Default TTL for a record this server hands out.
///
/// Deliberately short: a link-local name belongs to whichever host currently answers for it,
/// and that host can leave the link at any time. Nothing in this server tracks a name, so a
/// long TTL would leave a stale binding in the querier's cache with nobody to correct it.
const DEFAULT_TTL: u32 = 30;

// ---------------------------------------------------------------------------
// Header flag mapping — the one place LLMNR genuinely departs from DNS
// ---------------------------------------------------------------------------
//
// RFC 4795 §2.1.1:
//
//                                   1  1  1  1  1  1
//     0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
//   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//   |                      ID                       |
//   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//   |QR|   Opcode  | C|TC| T| Z| Z| Z| Z|   RCODE   |
//   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//
// Lined up against RFC 1035's `QR|Opcode|AA|TC|RD| RA| Z| Z| Z| RCODE`, the two 16-bit words
// are bit-for-bit identical except that LLMNR renames three flags:
//
//   * DNS `AA` (byte 2, bit 2) is LLMNR `C` — Conflict.
//   * DNS `TC` (byte 2, bit 1) is LLMNR `TC` — unchanged.
//   * DNS `RD` (byte 2, bit 0) is LLMNR `T` — Tentative.
//   * DNS `RA` joins the Z field, so it MUST be zero on the wire.
//
// `hickory-proto` has no LLMNR mode, so this file reads and writes those bits through their
// DNS names. The two helpers below are the *only* place that aliasing happens, so a reader
// never has to remember that `set_recursion_desired` means "tentative" here.

/// Read the LLMNR `C` (Conflict) bit out of a parsed message.
///
/// Set in a query when the sender has already received multiple responses to it — i.e. the
/// querier is reporting a name collision on the link, which is worth showing the model.
pub fn conflict_bit(message: &DnsMessage) -> bool {
    message.authoritative()
}

/// Read the LLMNR `T` (Tentative) bit out of a parsed message.
///
/// Defined by RFC 4795 for *responses* ("the responder is authoritative for the name, but has
/// not yet verified the uniqueness of the name"). It carries no defined meaning in a query;
/// it is surfaced anyway, because a querier that sets it is doing something worth seeing.
pub fn tentative_bit(message: &DnsMessage) -> bool {
    message.recursion_desired()
}

/// LLMNR protocol action handler.
pub struct LlmnrProtocol;

impl Default for LlmnrProtocol {
    fn default() -> Self {
        Self::new()
    }
}

impl LlmnrProtocol {
    pub fn new() -> Self {
        Self
    }
}

impl Protocol for LlmnrProtocol {
    fn get_startup_parameters(&self) -> Vec<crate::llm::actions::ParameterDefinition> {
        use crate::llm::actions::ParameterDefinition;
        vec![
            ParameterDefinition {
                name: "join_multicast".to_string(),
                type_hint: "boolean".to_string(),
                description: "Join the LLMNR multicast group (224.0.0.252 / FF02::1:3) so \
                              multicast queries from the link are received. Defaults to true. \
                              A failed join is logged and does not stop the server: queries \
                              sent straight to this port are still answered."
                    .to_string(),
                required: false,
                example: json!(true),
                default: None,
            },
            ParameterDefinition {
                name: "multicast_interface".to_string(),
                type_hint: "string".to_string(),
                description: "Local IPv4 address of the interface to join the group on \
                              (e.g. '192.168.1.10'). Omit to let the host pick. Ignored when \
                              join_multicast is false or the socket is IPv6."
                    .to_string(),
                required: false,
                example: json!("192.168.1.10"),
                default: None,
            },
            ParameterDefinition {
                name: "enable_tcp".to_string(),
                type_hint: "boolean".to_string(),
                description: "Also listen for TCP queries on the same port. RFC 4795 §2.4 \
                              requires responders to support TCP, and it is the only transport \
                              on which a non-zero RCODE may be returned. Defaults to true; a \
                              failed bind is logged and does not stop the UDP responder."
                    .to_string(),
                required: false,
                example: json!(true),
                default: None,
            },
        ]
    }

    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        // LLMNR is purely reactive: a responder says nothing until it is asked.
        Vec::new()
    }

    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            send_llmnr_response_action(),
            no_response_action(),
            send_llmnr_error_action(),
        ]
    }

    fn protocol_name(&self) -> &'static str {
        "LLMNR"
    }

    fn get_event_types(&self) -> Vec<EventType> {
        get_llmnr_event_types()
    }

    fn stack_name(&self) -> &'static str {
        "ETH>IP>UDP>LLMNR"
    }

    fn keywords(&self) -> Vec<&'static str> {
        vec!["llmnr", "link-local multicast name resolution", "rfc4795"]
    }

    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{
            DevelopmentState, PrivilegeRequirement, ProtocolMetadataV2,
        };

        ProtocolMetadataV2::builder()
            // Every query is its own "connection" entry, and nothing ever closes one. Without
            // this flag those entries would leak until the server stops; with it the 10-second
            // idle sweep reaps them. See the sweep note in the root CLAUDE.md.
            .connectionless()
            // Deliberately silent: an LLMNR answer is a name binding written into the querier's
            // cache, and RFC 4795 forbids the only error frame (a non-zero RCODE) on a multicast
            // query. A querier that hears nothing asks the next responder.
            .deliberately_silent()
            // Experimental, and it cannot honestly be more than that. See `notes`.
            .state(DevelopmentState::Experimental)
            // Port 5355 is unprivileged and joining a multicast group needs no elevation.
            .privilege_requirement(PrivilegeRequirement::None)
            .well_known_udp_port(5355)
            .implementation(
                "hickory-proto for the DNS message format; UDP on 5355 plus an optional TCP \
                 listener on the same port. The LLMNR C and T header bits are read and written \
                 through their DNS aliases (AA and RD), which occupy the same bit positions.",
            )
            .llm_control(
                "Every query. The model owns all names: it answers with A/AAAA/PTR, chooses \
                 silence for a name it does not own, or (TCP only) returns an RCODE.",
            )
            .e2e_testing(
                "tests/server/llmnr/e2e_test.rs builds queries with hickory-proto and asserts \
                 on the raw response bytes. hickory-proto is also what this server encodes \
                 with, so this is CIRCULAR evidence and proves only that the codec round-trips \
                 through itself - it is not a third-party client.",
            )
            .notes(
                "Experimental. No independent LLMNR client is runnable here: the real ones are \
                 the Windows resolver and systemd-resolved, neither of which exists on macOS, \
                 and no Rust crate issues LLMNR queries (the closest, llmnr-poison, is a \
                 responder like this one, not a querier). The test therefore builds its queries \
                 with hickory-proto, the same crate the server encodes with, which is the \
                 circular-evidence failure mode the root CLAUDE.md names. Also unverified: \
                 multicast reception on a real link (the test is unicast to loopback), \
                 interoperability with a Windows or systemd-resolved querier, and the TCP \
                 transport against anything but itself. An LLM failure produces SILENCE, never \
                 a fabricated answer - an LLMNR response writes a name-to-address binding into \
                 the querier's resolver, so a guess is cache poisoning.",
            )
            .max_inbound_bytes(crate::server::llmnr::MAX_MESSAGE_LEN)
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }

    fn description(&self) -> &'static str {
        "Link-local multicast name resolution responder (RFC 4795)"
    }

    fn example_prompt(&self) -> &'static str {
        "LLMNR responder on port 5355 that answers for printer.local with 192.168.1.42"
    }

    fn group_name(&self) -> &'static str {
        "Core"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;

        // Deterministic ownership check: answer for exactly one name, stay silent for
        // everything else. The script sees the event, so it can echo the querier's random
        // transaction id - the thing a static handler structurally cannot do.
        let script = r#"import json, sys
data = json.load(sys.stdin)
event = data["event"]
if data["event_type_id"] == "llmnr_query":
    name = event.get("name", "").rstrip(".").lower()
    if name == "printer.local" and event.get("query_type") == "A":
        actions = [{"type": "send_llmnr_response",
                    "transaction_id": event["transaction_id"],
                    "name": event["name"], "record_type": "A",
                    "address": "192.168.1.42", "ttl": 30}]
    else:
        # RFC 4795: a responder that is not authoritative for the name does not
        # answer at all. Silence is the correct wire behaviour, not a failure.
        actions = [{"type": "no_response"}]
else:
    actions = []
print(json.dumps({"actions": actions}))"#;

        StartupExamples::new(
            // LLM mode: deciding which names this host owns is a judgement call.
            json!({
                "type": "open_server",
                "port": 5355,
                "base_stack": "llmnr",
                "instruction": "Act as the LLMNR responder for a print server. Answer A queries for 'printer.local' with 192.168.1.42 and AAAA queries for it with fd00::42. For every other name, answer with no_response - never invent a binding for a name this host does not own."
            }),
            // Script mode: the only mode that can echo the transaction id deterministically.
            json!({
                "type": "open_server",
                "port": 5355,
                "base_stack": "llmnr",
                "event_handlers": [{
                    "event_pattern": "llmnr_query",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": script
                    }
                }]
            }),
            // Static mode: a static handler has no access to the event, so it cannot echo the
            // querier's random transaction id or the queried name - and a response carrying
            // neither is discarded by the querier, which is silence with extra steps. The one
            // thing static mode expresses correctly here is deliberate silence.
            json!({
                "type": "open_server",
                "port": 5355,
                "base_stack": "llmnr",
                "event_handlers": [{
                    "event_pattern": "llmnr_query",
                    "handler": {
                        "type": "static",
                        "actions": [{"type": "no_response"}]
                    }
                }]
            }),
        )
    }
}

impl Server for LlmnrProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(
            async move { crate::server::llmnr::LlmnrServer::spawn_with_llm_actions(ctx).await },
        )
    }

    fn execute_action(&self, action: serde_json::Value) -> Result<ActionResult> {
        let action_type = action
            .get("type")
            .and_then(|v| v.as_str())
            .context("Missing 'type' field in action")?;

        match action_type {
            "send_llmnr_response" => execute_send_llmnr_response(&action),
            "send_llmnr_error" => execute_send_llmnr_error(&action),
            // Explicit silence. This is a real answer, not a missing one: the caller
            // distinguishes it from "the model produced nothing" and logs it as
            // `decision=model_silent`.
            "no_response" => Ok(ActionResult::NoAction),
            _ => Err(anyhow::anyhow!("Unknown LLMNR action: {}", action_type)),
        }
    }
}

// ---------------------------------------------------------------------------
// Executors
// ---------------------------------------------------------------------------

/// Read the LLMNR transaction ID out of an action.
///
/// The querier picks it at random and discards any response carrying a different one, so an
/// out-of-range value is a hard error rather than a silent `as u16` truncation: truncating
/// would produce a packet the querier drops without a diagnostic, which is indistinguishable
/// from this server having said nothing.
fn parse_transaction_id(action: &serde_json::Value) -> Result<u16> {
    let raw = action
        .get("transaction_id")
        .and_then(|v| v.as_u64())
        .context(
            "Missing 'transaction_id' parameter (echo the transaction_id from the llmnr_query \
             event verbatim)",
        )?;

    u16::try_from(raw).map_err(|_| {
        anyhow::anyhow!(
            "'transaction_id' must be a 16-bit LLMNR transaction ID (0-65535), got {}. Echo the \
             transaction_id from the llmnr_query event verbatim.",
            raw
        )
    })
}

fn required_str<'a>(action: &'a serde_json::Value, key: &str) -> Result<&'a str> {
    action
        .get(key)
        .and_then(|v| v.as_str())
        .with_context(|| format!("Missing '{key}' parameter"))
}

fn parse_name(value: &str) -> Result<Name> {
    Name::from_str(value).with_context(|| format!("Invalid LLMNR name: '{value}'"))
}

/// The record types this responder will put on the wire.
///
/// RFC 4795 §2.2 has responders answer for the names they own; in practice that means the
/// host's own addresses (A/AAAA) and the reverse mapping (PTR). Anything else would be
/// asserting authority over a zone, which a link-local responder does not have.
fn parse_record_type(name: &str) -> Result<RecordType> {
    match name.to_ascii_uppercase().as_str() {
        "A" => Ok(RecordType::A),
        "AAAA" => Ok(RecordType::AAAA),
        "PTR" => Ok(RecordType::PTR),
        other => Err(anyhow::anyhow!(
            "Unsupported LLMNR record_type '{other}'. LLMNR answers for a host's own names: \
             use 'A', 'AAAA' or 'PTR'."
        )),
    }
}

/// Build the shell of an LLMNR response: header plus the echoed question.
///
/// Three things are non-negotiable and each of them, if dropped, turns the response into
/// silence as far as the querier is concerned:
///
/// * the transaction ID is copied from the query (RFC 4795 §2.3, "the ID field is copied");
/// * the question section is repeated, as in RFC 1035 §4.1.2;
/// * `C` is left clear. That bit is DNS's `AA`, and every other DNS builder in this repo sets
///   `AA` on an authoritative answer — doing so here would claim a name conflict on the link.
fn new_response(
    transaction_id: u16,
    name: &Name,
    query_type: RecordType,
    response_code: ResponseCode,
    tentative: bool,
) -> DnsMessage {
    let mut message = DnsMessage::new();
    let mut header = Header::new();
    header.set_id(transaction_id);
    header.set_message_type(MessageType::Response);
    header.set_op_code(OpCode::Query);
    header.set_response_code(response_code);
    // C = 0: no conflict detected. (This is DNS's AA bit — do not set it.)
    header.set_authoritative(false);
    header.set_truncated(false);
    // T: tentative, i.e. authoritative for the name but uniqueness not yet verified.
    header.set_recursion_desired(tentative);
    // RA is part of LLMNR's Z field and MUST be zero.
    header.set_recursion_available(false);
    message.set_header(header);

    let mut question = Query::query(name.clone(), query_type);
    question.set_query_class(DNSClass::IN);
    message.add_query(question);

    message
}

fn finish(message: DnsMessage) -> Result<ActionResult> {
    let bytes = message
        .to_vec()
        .context("Failed to serialize LLMNR message")?;
    Ok(ActionResult::Output(bytes))
}

fn execute_send_llmnr_response(action: &serde_json::Value) -> Result<ActionResult> {
    let transaction_id = parse_transaction_id(action)?;
    let name = parse_name(required_str(action, "name")?)?;
    let record_type = parse_record_type(required_str(action, "record_type")?)?;
    let address = required_str(action, "address")?;
    let ttl = action
        .get("ttl")
        .and_then(|v| v.as_u64())
        .unwrap_or(DEFAULT_TTL as u64)
        .min(u32::MAX as u64) as u32;
    let tentative = action
        .get("tentative")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let rdata = match record_type {
        RecordType::A => {
            let ip = Ipv4Addr::from_str(address).with_context(|| {
                format!("record_type 'A' needs an IPv4 address in 'address', got '{address}'")
            })?;
            RData::A(rdata::A(ip))
        }
        RecordType::AAAA => {
            let ip = Ipv6Addr::from_str(address).with_context(|| {
                format!("record_type 'AAAA' needs an IPv6 address in 'address', got '{address}'")
            })?;
            RData::AAAA(rdata::AAAA(ip))
        }
        RecordType::PTR => {
            let target = Name::from_str(address).with_context(|| {
                format!("record_type 'PTR' needs a host name in 'address', got '{address}'")
            })?;
            RData::PTR(rdata::PTR(target))
        }
        // parse_record_type admits nothing else.
        other => return Err(anyhow::anyhow!("Unsupported LLMNR record type: {other}")),
    };

    let mut message = new_response(
        transaction_id,
        &name,
        record_type,
        ResponseCode::NoError,
        tentative,
    );
    let mut record = Record::with(name, record_type, ttl);
    record.set_data(Some(rdata));
    message.add_answer(record);

    finish(message)
}

fn execute_send_llmnr_error(action: &serde_json::Value) -> Result<ActionResult> {
    let transaction_id = parse_transaction_id(action)?;
    let name = parse_name(required_str(action, "name")?)?;
    let query_type = parse_record_type(required_str(action, "query_type")?)?;

    let rcode = match required_str(action, "rcode")?.to_ascii_uppercase().as_str() {
        "SERVFAIL" => ResponseCode::ServFail,
        "NOTIMP" | "NOTIMPL" => ResponseCode::NotImp,
        "REFUSED" => ResponseCode::Refused,
        // RFC 4795 §2.1.1 is explicit: "Since LLMNR responders only respond to LLMNR queries
        // for names for which they are authoritative, LLMNR responders MUST NOT respond with
        // an RCODE of 3; instead, they should not respond at all." Offering NXDOMAIN as a
        // choice at all would be a trap, so it is refused with the alternative named.
        "NXDOMAIN" | "NAMEERROR" => {
            return Err(anyhow::anyhow!(
                "LLMNR responders MUST NOT return RCODE 3 (NXDOMAIN) - RFC 4795 §2.1.1 says to \
                 stay silent instead. Use the 'no_response' action."
            ))
        }
        "NOERROR" => {
            return Err(anyhow::anyhow!(
                "'send_llmnr_error' is for failures only; RCODE 0 belongs on a real answer. Use \
                 'send_llmnr_response', or 'no_response' to say nothing."
            ))
        }
        other => {
            return Err(anyhow::anyhow!(
                "Unsupported LLMNR rcode '{other}'. Use 'SERVFAIL', 'NOTIMP' or 'REFUSED'."
            ))
        }
    };

    // No `tentative` here: T asserts something about a name this responder is authoritative
    // for, and an error response is not an assertion about a name.
    let message = new_response(transaction_id, &name, query_type, rcode, false);
    finish(message)
}

// ---------------------------------------------------------------------------
// Action definitions
// ---------------------------------------------------------------------------

fn send_llmnr_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_llmnr_response".to_string(),
        description:
            "Answer an LLMNR query for a name this host owns. Sent unicast to the querier with \
             the query's transaction ID and question echoed. Only use this for a name you are \
             authoritative for - RFC 4795 forbids answering for anything else, and a wrong \
             answer is written straight into the querier's name cache."
                .to_string(),
        parameters: vec![
            Parameter {
                name: "transaction_id".to_string(),
                type_hint: "number".to_string(),
                description:
                    "The transaction_id from the llmnr_query event, echoed verbatim. A response \
                     carrying any other value is discarded by the querier."
                        .to_string(),
                required: true,
            },
            Parameter {
                name: "name".to_string(),
                type_hint: "string".to_string(),
                description: "The queried name, echoed verbatim from the event (e.g. \
                              'printer.local.')"
                    .to_string(),
                required: true,
            },
            Parameter {
                name: "record_type".to_string(),
                type_hint: "string".to_string(),
                description: "'A' (IPv4), 'AAAA' (IPv6) or 'PTR' (reverse lookup)".to_string(),
                required: true,
            },
            Parameter {
                name: "address".to_string(),
                type_hint: "string".to_string(),
                description:
                    "For 'A' an IPv4 address, for 'AAAA' an IPv6 address, for 'PTR' the host \
                     name the queried address maps to."
                        .to_string(),
                required: true,
            },
            Parameter {
                name: "ttl".to_string(),
                type_hint: "number".to_string(),
                description: "Seconds the querier may cache this binding. Defaults to 30; keep \
                              it short, link-local names move with their host."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "tentative".to_string(),
                type_hint: "boolean".to_string(),
                description:
                    "Set the LLMNR T bit: authoritative for the name, but its uniqueness on the \
                     link has not been verified. Defaults to false."
                        .to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "send_llmnr_response",
            "transaction_id": 4660,
            "name": "printer.local.",
            "record_type": "A",
            "address": "192.168.1.42",
            "ttl": 30
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> LLMNR {record_type} {name} = {address}")
                .with_debug(
                    "LLMNR send_llmnr_response: id={transaction_id}, name={name}, \
                     type={record_type}, address={address}, ttl={ttl}",
                ),
        ),
    }
}

fn no_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "no_response".to_string(),
        description:
            "Say nothing. This is the CORRECT and required answer whenever the queried name is \
             not one this host owns: RFC 4795 has a responder stay silent rather than return \
             NXDOMAIN, because on a shared link the host that does own the name still has to be \
             able to answer. It is a deliberate answer, not a failure, and is logged as one."
                .to_string(),
        parameters: vec![],
        example: json!({"type": "no_response"}),
        log_template: Some(
            LogTemplate::new()
                .with_info("LLMNR staying silent (name not owned)")
                .with_debug("LLMNR no_response: nothing will be written to the wire"),
        ),
    }
}

fn send_llmnr_error_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_llmnr_error".to_string(),
        description:
            "Return a non-zero RCODE. TCP QUERIES ONLY: RFC 4795 §2.1.1 requires the response to \
             a multicast query to carry RCODE 0, and this server cannot tell a unicast UDP \
             datagram from a multicast one, so an error produced for a UDP query is discarded \
             rather than sent. NXDOMAIN is not available - use 'no_response' for a name this \
             host does not own."
                .to_string(),
        parameters: vec![
            Parameter {
                name: "transaction_id".to_string(),
                type_hint: "number".to_string(),
                description: "The transaction_id from the llmnr_query event, echoed verbatim."
                    .to_string(),
                required: true,
            },
            Parameter {
                name: "name".to_string(),
                type_hint: "string".to_string(),
                description: "The queried name, echoed verbatim from the event.".to_string(),
                required: true,
            },
            Parameter {
                name: "query_type".to_string(),
                type_hint: "string".to_string(),
                description: "The query_type from the event ('A', 'AAAA' or 'PTR'), so the \
                              question section can be echoed."
                    .to_string(),
                required: true,
            },
            Parameter {
                name: "rcode".to_string(),
                type_hint: "string".to_string(),
                description: "'SERVFAIL', 'NOTIMP' or 'REFUSED'. 'NXDOMAIN' is rejected."
                    .to_string(),
                required: true,
            },
        ],
        example: json!({
            "type": "send_llmnr_error",
            "transaction_id": 4660,
            "name": "printer.local.",
            "query_type": "A",
            "rcode": "REFUSED"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> LLMNR {rcode} for {name}")
                .with_debug(
                    "LLMNR send_llmnr_error: id={transaction_id}, name={name}, rcode={rcode}",
                ),
        ),
    }
}

// ---------------------------------------------------------------------------
// Action & event constants
// ---------------------------------------------------------------------------

pub static SEND_LLMNR_RESPONSE_ACTION: LazyLock<ActionDefinition> =
    LazyLock::new(send_llmnr_response_action);
pub static NO_RESPONSE_ACTION: LazyLock<ActionDefinition> = LazyLock::new(no_response_action);
pub static SEND_LLMNR_ERROR_ACTION: LazyLock<ActionDefinition> =
    LazyLock::new(send_llmnr_error_action);

/// A querier asked this host to resolve a name.
pub static LLMNR_QUERY_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "llmnr_query",
        "An LLMNR querier asked this host to resolve a name. Answer ONLY if this host owns the \
         name; otherwise use no_response - staying silent is the protocol's required behaviour, \
         not a failure.",
        json!({
            "type": "send_llmnr_response",
            "transaction_id": 4660,
            "name": "printer.local.",
            "record_type": "A",
            "address": "192.168.1.42",
            "ttl": 30
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "transaction_id".to_string(),
            type_hint: "number".to_string(),
            description: "Transaction ID from the query header; echo it in any response."
                .to_string(),
            required: true,
        },
        Parameter {
            name: "name".to_string(),
            type_hint: "string".to_string(),
            description: "The name being queried (e.g. 'printer.local.')".to_string(),
            required: true,
        },
        Parameter {
            name: "query_type".to_string(),
            type_hint: "string".to_string(),
            description: "Query type: 'A', 'AAAA', 'PTR', or another DNS type name".to_string(),
            required: true,
        },
        Parameter {
            name: "query_class".to_string(),
            type_hint: "string".to_string(),
            description: "Query class, normally 'IN'".to_string(),
            required: true,
        },
        Parameter {
            name: "source_address".to_string(),
            type_hint: "string".to_string(),
            description: "Address and port the query came from".to_string(),
            required: true,
        },
        Parameter {
            name: "transport".to_string(),
            type_hint: "string".to_string(),
            description: "'udp' or 'tcp'. A non-zero RCODE may only be returned over 'tcp'."
                .to_string(),
            required: true,
        },
        Parameter {
            name: "conflict".to_string(),
            type_hint: "boolean".to_string(),
            description: "LLMNR C bit: the querier has already received multiple responses to \
                          this query, i.e. it is reporting a name collision on the link."
                .to_string(),
            required: true,
        },
        Parameter {
            name: "tentative".to_string(),
            type_hint: "boolean".to_string(),
            description: "LLMNR T bit as it arrived. Has no defined meaning in a query; \
                          reported for diagnostics."
                .to_string(),
            required: true,
        },
    ])
    // Without this the model is handed no vocabulary and cannot answer the event at all.
    .with_actions(vec![
        SEND_LLMNR_RESPONSE_ACTION.clone(),
        NO_RESPONSE_ACTION.clone(),
        SEND_LLMNR_ERROR_ACTION.clone(),
    ])
    .with_alternative_example(json!({"type": "no_response"}))
    .with_alternative_example(json!({
        "type": "send_llmnr_response",
        "transaction_id": 4660,
        "name": "printer.local.",
        "record_type": "AAAA",
        "address": "fd00::42",
        "ttl": 30
    }))
    .with_log_template(
        LogTemplate::new()
            .with_info("LLMNR {query_type} {name} from {source_address}")
            .with_debug(
                "LLMNR query id={transaction_id}, name={name}, type={query_type}, \
                 class={query_class}, transport={transport}, conflict={conflict}",
            )
            .with_trace("LLMNR query: {json_pretty(.)}"),
    )
});

/// Event types this protocol raises.
pub fn get_llmnr_event_types() -> Vec<EventType> {
    vec![LLMNR_QUERY_EVENT.clone()]
}
