//! LLMNR (RFC 4795) **querier** actions.
//!
//! LLMNR reuses the DNS message format, so every packet is built and parsed with
//! `hickory-proto`. What differs from DNS is the header flag layout, the fact that a name is
//! answered by *however many* hosts on the link claim it, and the fact that **no answer at all
//! is the normal outcome**. All three are encoded here and explained in
//! `src/client/llmnr/CLAUDE.md`.

use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, Parameter,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::EventType;
use crate::state::app_state::AppState;
use anyhow::{Context, Result};
use hickory_proto::op::Message as DnsMessage;
use hickory_proto::rr::RecordType;
use serde_json::json;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::LazyLock;

/// The port LLMNR queries are sent to (RFC 4795 §2).
pub const LLMNR_PORT: u16 = 5355;

/// IPv4 link-scope multicast group for LLMNR (RFC 4795 §2).
pub const LLMNR_IPV4_GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 252);

/// IPv6 link-scope multicast group for LLMNR (RFC 4795 §2).
pub const LLMNR_IPV6_GROUP: Ipv6Addr = Ipv6Addr::new(0xFF02, 0, 0, 0, 0, 0, 0x0001, 0x0003);

// ---------------------------------------------------------------------------
// Header flag mapping — the one place LLMNR genuinely departs from DNS
// ---------------------------------------------------------------------------
//
// RFC 4795 §2.1.1 lays the LLMNR header word out as
// `QR|Opcode|C|TC|T|Z|Z|Z|Z|RCODE`, which is bit-for-bit RFC 1035's
// `QR|Opcode|AA|TC|RD|RA|Z|Z|Z|RCODE` with three flags renamed:
//
//   * DNS `AA` (byte 2, bit 2, 0x04) is LLMNR `C` — Conflict.
//   * DNS `RD` (byte 2, bit 0, 0x01) is LLMNR `T` — Tentative.
//   * DNS `RA` joins the Z field and MUST be zero.
//
// `hickory-proto` has no LLMNR mode, so those bits are read and written through their DNS
// names. `src/server/llmnr/actions.rs` puts the aliasing in exactly two helpers so no reader
// has to remember that `set_recursion_desired` means "tentative"; this file does the same, and
// the two must stay consistent — they are the two halves of one protocol.

/// Read the LLMNR `C` (Conflict) bit out of a parsed message.
///
/// In a *response* it means the responder has seen this name claimed by more than one host.
/// That is the responder's own opinion and is reported to the model alongside this querier's
/// independent observation of how many hosts answered.
pub fn conflict_bit(message: &DnsMessage) -> bool {
    message.authoritative()
}

/// Read the LLMNR `T` (Tentative) bit out of a parsed message.
///
/// RFC 4795 defines it for responses: "the responder is authoritative for the name, but has not
/// yet verified the uniqueness of the name". A tentative answer is a weaker claim and the model
/// is told so rather than having it flattened away.
pub fn tentative_bit(message: &DnsMessage) -> bool {
    message.recursion_desired()
}

/// The record types this querier will ask for.
///
/// LLMNR resolves a *host's own* names: its addresses (A/AAAA) and the reverse mapping (PTR).
/// Anything else would be asking a link-local responder to act as a zone authority, which it is
/// not. Kept deliberately identical to the responder half's `parse_record_type`.
pub fn parse_record_type(name: &str) -> Result<RecordType> {
    match name.to_ascii_uppercase().as_str() {
        "A" => Ok(RecordType::A),
        "AAAA" => Ok(RecordType::AAAA),
        "PTR" => Ok(RecordType::PTR),
        other => Err(anyhow::anyhow!(
            "Unsupported LLMNR record_type '{other}'. LLMNR resolves a host's own names: use \
             'A', 'AAAA' or 'PTR'."
        )),
    }
}

/// LLMNR client protocol action handler.
pub struct LlmnrClientProtocol;

impl Default for LlmnrClientProtocol {
    fn default() -> Self {
        Self::new()
    }
}

impl LlmnrClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

impl Protocol for LlmnrClientProtocol {
    fn get_startup_parameters(&self) -> Vec<crate::llm::actions::ParameterDefinition> {
        use crate::llm::actions::ParameterDefinition;
        vec![
            ParameterDefinition {
                name: "bind_address".to_string(),
                type_hint: "string".to_string(),
                description:
                    "Local address to send queries from. Defaults to '0.0.0.0' ('::' for an IPv6 \
                     target). Binding to 0.0.0.0 is deliberate: on macOS a socket bound to \
                     127.0.0.1 can join a multicast group but cannot SEND to one - sendto() \
                     fails with EADDRNOTAVAIL, because loopback carries no multicast route."
                        .to_string(),
                required: false,
                example: json!("0.0.0.0"),
                default: None,
            },
            ParameterDefinition {
                name: "response_wait_secs".to_string(),
                type_hint: "number".to_string(),
                description: "How long to keep collecting responses after each query, in seconds \
                     (default 2). This is NOT a first-answer timeout: several hosts on a link \
                     may claim the same name, and the whole window is collected so the \
                     disagreement is visible instead of being decided by whichever packet \
                     arrived first."
                    .to_string(),
                required: false,
                example: json!(2),
                default: None,
            },
        ]
    }

    /// All three verbs live here. `get_sync_actions()` is empty on purpose: a client has one
    /// LLM entry point (`call_llm_for_client`), which advertises the **union** of async, sync
    /// and the firing event's own actions, so the async/sync split cannot express a narrowing
    /// and duplicating the list into both methods would only make it harder to keep in step.
    /// See `client_llm_action_set` in `src/llm/actions/client_trait.rs`.
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![
            send_llmnr_query_action(),
            wait_for_more_action(),
            disconnect_action(),
        ]
    }

    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        Vec::new()
    }

    fn protocol_name(&self) -> &'static str {
        "LLMNR"
    }

    fn get_event_types(&self) -> Vec<EventType> {
        get_llmnr_client_event_types()
    }

    fn stack_name(&self) -> &'static str {
        "ETH>IP>UDP>LLMNR"
    }

    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "llmnr",
            "llmnr client",
            "link-local multicast name resolution",
            "rfc4795",
            "resolve a link-local name",
        ]
    }

    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{
            DevelopmentState, PrivilegeRequirement, ProtocolMetadataV2,
        };

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            // Queries go out from an ephemeral port; nothing here binds 5355 or opens a raw
            // socket, and joining a group is not needed because responses are unicast.
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation(
                "hickory-proto for the DNS message format, one UDP socket bound to 0.0.0.0:0. \
                 Responses are matched on BOTH the random transaction ID and the echoed \
                 question, and anything else is discarded. The socket is deliberately not \
                 connect()ed: responses to one query legitimately arrive from several different \
                 hosts, and a connected socket would drop every one but the target's. The LLMNR \
                 C and T header bits are read through their DNS aliases (AA and RD), which \
                 occupy the same bit positions.",
            )
            .llm_control(
                "The model chooses the name and record type to resolve, and decides what to do \
                 with each responder's answer. It is shown one event per responder plus a \
                 conflict event when two responders answer differently; a query nobody answers \
                 is reported as its own expected outcome, not as an error.",
            )
            .e2e_testing(
                "tests/client/llmnr/e2e_test.rs drives this client against NetGet's own LLMNR \
                 SERVER, and both halves encode with hickory-proto. That is circular on two \
                 axes at once - same project and same codec - so it proves NetGet's own wiring \
                 and nothing about interoperability. See notes.",
            )
            .notes(
                "Experimental. The evidence is circular twice over: (1) the test peer is \
                 NetGet's own LLMNR responder, so both ends are this project's code, and (2) \
                 both ends frame with hickory-proto, so the test shows only that one codec \
                 round-trips through itself - the exact failure the root CLAUDE.md names for \
                 webrtc_signaling and websocket. The real LLMNR responders are Windows hosts \
                 and systemd-resolved, neither present on macOS. HOW TO BREAK THE CODEC AXIS: \
                 the crates.io crate `llmnr-poison` 0.1.0 IS a library (not, as the server half \
                 recorded, only a Responder-style tool) and depends on nothing but anyhow and \
                 tokio, so it hand-rolls the DNS wire format rather than using hickory. Its \
                 `llmnr_response(query: &[u8], spoof: Ipv4Addr) -> Option<(String, Vec<u8>)>` \
                 is a pure function - the test keeps its own ephemeral unicast socket and lets \
                 that crate own the encoding, which is a genuinely independent implementation. \
                 Its `poison(spoof)` entry point is NOT usable: it takes no bind address and \
                 claims the fixed port 5355 plus NBT-NS 137. Even with that wired up this stays \
                 Experimental, because an independent response ENCODER is not a running \
                 responder and nothing here has met a Windows or systemd-resolved peer. Also \
                 unverified: multicast on a real link (the tests are unicast to loopback, \
                 because loopback carries no multicast route), IPv6/FF02::1:3 entirely, and TCP \
                 queries (RFC 4795 2.4), which this querier does not implement.",
            )
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }

    fn description(&self) -> &'static str {
        "Link-local multicast name resolution querier (RFC 4795)"
    }

    fn example_prompt(&self) -> &'static str {
        "Resolve printer.local over LLMNR and report every host that answers"
    }

    fn group_name(&self) -> &'static str {
        "Core"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;

        // Deterministic: ask once on connect, then stop. The script sees the event, so it can
        // report the responder count - the thing that matters on a link where more than one
        // host may claim the name.
        let script = r#"import json, sys
data = json.load(sys.stdin)
event = data["event"]
if data["event_type_id"] == "llmnr_connected":
    actions = [{"type": "send_llmnr_query", "name": "printer.local", "record_type": "A"}]
else:
    # A response, a conflict report or a timeout: all three are terminal here.
    actions = [{"type": "wait_for_more"}]
print(json.dumps({"actions": actions}))"#;

        StartupExamples::new(
            // LLM mode: deciding what to make of several conflicting answers is a judgement
            // call, which is exactly what the model is for.
            json!({
                "type": "open_client",
                "remote_addr": "224.0.0.252:5355",
                "protocol": "LLMNR",
                "instruction": "Resolve 'printer.local' (A) over LLMNR. Report EVERY host that answers and the address each one gave. If two hosts answer with different addresses, say so explicitly - that is what name spoofing looks like on the wire. If nobody answers, report that no host on this link claims the name; that is a normal outcome, not an error."
            }),
            // Script mode.
            json!({
                "type": "open_client",
                "remote_addr": "224.0.0.252:5355",
                "protocol": "LLMNR",
                "event_handlers": [{
                    "event_pattern": "*",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": script
                    }
                }]
            }),
            // Static mode: a fixed query on connect, and nothing further. A static handler
            // cannot read the event, so it cannot react to what came back - which is fine for
            // the query itself (it carries no echoed value) and useless for the answers.
            json!({
                "type": "open_client",
                "remote_addr": "224.0.0.252:5355",
                "protocol": "LLMNR",
                "event_handlers": [
                    {
                        "event_pattern": "llmnr_connected",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "send_llmnr_query",
                                "name": "printer.local",
                                "record_type": "A"
                            }]
                        }
                    },
                    {
                        "event_pattern": "llmnr_query_timeout",
                        "handler": {
                            "type": "static",
                            "actions": [{"type": "wait_for_more"}]
                        }
                    }
                ]
            }),
        )
    }
}

impl Client for LlmnrClientProtocol {
    fn connect(
        &self,
        ctx: crate::protocol::ConnectContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            crate::client::llmnr::LlmnrClient::connect_with_llm_actions(
                ctx.remote_addr,
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.client_id,
                ctx.startup_params,
            )
            .await
        })
    }

    fn execute_action(&self, action: serde_json::Value) -> Result<ClientActionResult> {
        let action_type = action
            .get("type")
            .and_then(|v| v.as_str())
            .context("Missing 'type' field in action")?;

        match action_type {
            "send_llmnr_query" => {
                let name = action
                    .get("name")
                    .and_then(|v| v.as_str())
                    .context("Missing 'name' parameter (the link-local name to resolve)")?
                    .to_string();

                // Validated here, not deep in the socket loop, so a bad type is rejected as an
                // action error the model can see and correct rather than as a silent no-op.
                let record_type = action
                    .get("record_type")
                    .and_then(|v| v.as_str())
                    .context("Missing 'record_type' parameter ('A', 'AAAA' or 'PTR')")?;
                let record_type = parse_record_type(record_type)?.to_string();

                let target = action
                    .get("target")
                    .and_then(|v| v.as_str())
                    .map(str::to_string);

                Ok(ClientActionResult::Custom {
                    name: "llmnr_query".to_string(),
                    data: json!({
                        "name": name,
                        "record_type": record_type,
                        "target": target,
                    }),
                })
            }
            "wait_for_more" => Ok(ClientActionResult::WaitForMore),
            "disconnect" => Ok(ClientActionResult::Disconnect),
            other => Err(anyhow::anyhow!("Unknown LLMNR client action: {}", other)),
        }
    }
}

// ---------------------------------------------------------------------------
// Action definitions
// ---------------------------------------------------------------------------

fn send_llmnr_query_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_llmnr_query".to_string(),
        description:
            "Ask the link to resolve a name. A fresh random transaction ID is generated for you \
             and every response is matched against it AND against the echoed question before it \
             is accepted, so you never see an answer to somebody else's query. Several hosts may \
             answer - you get one llmnr_response_received event per responder - and NO host \
             answering is a normal outcome reported as llmnr_query_timeout, not an error."
                .to_string(),
        parameters: vec![
            Parameter {
                name: "name".to_string(),
                type_hint: "string".to_string(),
                description:
                    "The name to resolve, e.g. 'printer.local'. For a PTR query use the reverse \
                     form, e.g. '42.1.168.192.in-addr.arpa'."
                        .to_string(),
                required: true,
            },
            Parameter {
                name: "record_type".to_string(),
                type_hint: "string".to_string(),
                description: "'A' (IPv4), 'AAAA' (IPv6) or 'PTR' (reverse lookup).".to_string(),
                required: true,
            },
            Parameter {
                name: "target".to_string(),
                type_hint: "string".to_string(),
                description: "Optional 'address:port' override for THIS query only, e.g. \
                     '127.0.0.1:5355'. Omit it to use the multicast group (or whatever address \
                     this client was opened with). Its purpose is testing against one known \
                     responder: many hosts cannot send to a multicast group at all - on a \
                     loopback-only setup sendto() fails with EADDRNOTAVAIL because loopback \
                     carries no multicast route."
                    .to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "send_llmnr_query",
            "name": "printer.local",
            "record_type": "A"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> LLMNR query {record_type} {name}")
                .with_debug(
                    "LLMNR send_llmnr_query: name={name}, type={record_type}, target={target}",
                ),
        ),
    }
}

fn wait_for_more_action() -> ActionDefinition {
    ActionDefinition {
        name: "wait_for_more".to_string(),
        description:
            "Send nothing and wait. Use this to end a resolution without disconnecting - for \
             instance after reading an answer, or after a query nobody answered."
                .to_string(),
        parameters: vec![],
        example: json!({"type": "wait_for_more"}),
        log_template: Some(
            LogTemplate::new().with_debug("LLMNR wait_for_more: no query will be sent"),
        ),
    }
}

fn disconnect_action() -> ActionDefinition {
    ActionDefinition {
        name: "disconnect".to_string(),
        description: "Close this LLMNR querier's socket and stop.".to_string(),
        parameters: vec![],
        example: json!({"type": "disconnect"}),
        log_template: Some(LogTemplate::new().with_info("LLMNR querier disconnecting")),
    }
}

pub static SEND_LLMNR_QUERY_ACTION: LazyLock<ActionDefinition> =
    LazyLock::new(send_llmnr_query_action);
pub static WAIT_FOR_MORE_ACTION: LazyLock<ActionDefinition> = LazyLock::new(wait_for_more_action);
pub static DISCONNECT_ACTION: LazyLock<ActionDefinition> = LazyLock::new(disconnect_action);

/// The action list every event offers, so the model is never handed an event it has no
/// vocabulary to answer.
fn client_actions() -> Vec<ActionDefinition> {
    vec![
        SEND_LLMNR_QUERY_ACTION.clone(),
        WAIT_FOR_MORE_ACTION.clone(),
        DISCONNECT_ACTION.clone(),
    ]
}

// ---------------------------------------------------------------------------
// Event types
// ---------------------------------------------------------------------------

/// The querier's socket is up and the first query can be sent.
pub static LLMNR_CLIENT_CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "llmnr_connected",
        "The LLMNR querier is ready. LLMNR is connectionless - nothing was 'connected to'; a \
         UDP socket was bound and queries can now be sent to the link. Send a send_llmnr_query \
         to resolve a name.",
        json!({
            "type": "send_llmnr_query",
            "name": "printer.local",
            "record_type": "A"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "target".to_string(),
            type_hint: "string".to_string(),
            description: "Default destination for queries: the LLMNR multicast group, or the \
                          unicast address this client was opened with."
                .to_string(),
            required: true,
        },
        Parameter {
            name: "local_addr".to_string(),
            type_hint: "string".to_string(),
            description: "Local address and port queries are sent from. Responders reply \
                          unicast to exactly this."
                .to_string(),
            required: true,
        },
        Parameter {
            name: "response_wait_secs".to_string(),
            type_hint: "number".to_string(),
            description: "How long each query collects responses before it is reported."
                .to_string(),
            required: true,
        },
    ])
    .with_actions(client_actions())
    .with_log_template(
        LogTemplate::new()
            .with_info("LLMNR querier ready on {local_addr}, querying {target}")
            .with_debug(
                "LLMNR connected: local={local_addr}, target={target}, wait={response_wait_secs}s",
            ),
    )
});

/// One responder answered. **One event per responder** — on a real link several hosts may claim
/// the same name, and collapsing that into a single answer is how a spoofed binding gets
/// accepted silently.
pub static LLMNR_RESPONSE_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "llmnr_response_received",
        "One host answered the LLMNR query. If responder_count is greater than 1 you will \
         receive one of these per responder, followed by an llmnr_conflicting_responses event \
         if they disagreed - do NOT assume the first answer is authoritative.",
        json!({"type": "wait_for_more"}),
    )
    .with_parameters(vec![
        Parameter {
            name: "transaction_id".to_string(),
            type_hint: "number".to_string(),
            description: "The query's transaction ID. This response was accepted only because \
                          it carried this ID and echoed the question."
                .to_string(),
            required: true,
        },
        Parameter {
            name: "name".to_string(),
            type_hint: "string".to_string(),
            description: "The name that was resolved.".to_string(),
            required: true,
        },
        Parameter {
            name: "record_type".to_string(),
            type_hint: "string".to_string(),
            description: "'A', 'AAAA' or 'PTR'.".to_string(),
            required: true,
        },
        Parameter {
            name: "address".to_string(),
            type_hint: "string".to_string(),
            description: "The address (or, for PTR, the host name) this responder gave. The \
                          first record if it sent several; see 'addresses'."
                .to_string(),
            required: true,
        },
        Parameter {
            name: "addresses".to_string(),
            type_hint: "array".to_string(),
            description: "Every matching record in this one response.".to_string(),
            required: true,
        },
        Parameter {
            name: "ttl".to_string(),
            type_hint: "number".to_string(),
            description: "Seconds this binding may be cached.".to_string(),
            required: true,
        },
        Parameter {
            name: "responder_address".to_string(),
            type_hint: "string".to_string(),
            description: "Address and port the answer came from. On a multicast query this is \
                          NOT the address the query was sent to."
                .to_string(),
            required: true,
        },
        Parameter {
            name: "responder_index".to_string(),
            type_hint: "number".to_string(),
            description: "1-based position of this responder among the ones that answered."
                .to_string(),
            required: true,
        },
        Parameter {
            name: "responder_count".to_string(),
            type_hint: "number".to_string(),
            description: "How many distinct hosts answered this one query. Greater than 1 means \
                          the name is claimed by more than one host."
                .to_string(),
            required: true,
        },
        Parameter {
            name: "conflict".to_string(),
            type_hint: "boolean".to_string(),
            description: "The responder's own LLMNR C bit: it has itself seen this name claimed \
                          more than once."
                .to_string(),
            required: true,
        },
        Parameter {
            name: "tentative".to_string(),
            type_hint: "boolean".to_string(),
            description: "The responder's LLMNR T bit: authoritative for the name but its \
                          uniqueness on the link is not yet verified. A weaker claim."
                .to_string(),
            required: true,
        },
    ])
    .with_actions(client_actions())
    .with_log_template(
        LogTemplate::new()
            .with_info("LLMNR {record_type} {name} = {address} from {responder_address} ({responder_index}/{responder_count})")
            .with_debug(
                "LLMNR response: id={transaction_id}, name={name}, type={record_type}, \
                 address={address}, ttl={ttl}, from={responder_address}, \
                 conflict={conflict}, tentative={tentative}",
            )
            .with_trace("LLMNR response: {json_pretty(.)}"),
    )
});

/// Nobody answered — the **expected** outcome for a name no host on the link owns.
pub static LLMNR_QUERY_TIMEOUT_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "llmnr_query_timeout",
        "No host answered the LLMNR query within the collection window. THIS IS NORMAL, not an \
         error: RFC 4795 has a responder stay completely silent for a name it does not own, \
         rather than return NXDOMAIN, so silence is how the link says 'nobody here claims this \
         name'. Report it as a resolution failure, not as a fault.",
        json!({"type": "wait_for_more"}),
    )
    .with_parameters(vec![
        Parameter {
            name: "transaction_id".to_string(),
            type_hint: "number".to_string(),
            description: "The transaction ID that went unanswered.".to_string(),
            required: true,
        },
        Parameter {
            name: "name".to_string(),
            type_hint: "string".to_string(),
            description: "The name that was queried.".to_string(),
            required: true,
        },
        Parameter {
            name: "record_type".to_string(),
            type_hint: "string".to_string(),
            description: "'A', 'AAAA' or 'PTR'.".to_string(),
            required: true,
        },
        Parameter {
            name: "target".to_string(),
            type_hint: "string".to_string(),
            description: "Where the query was sent.".to_string(),
            required: true,
        },
        Parameter {
            name: "waited_secs".to_string(),
            type_hint: "number".to_string(),
            description: "How long responses were collected for.".to_string(),
            required: true,
        },
        Parameter {
            name: "discarded_count".to_string(),
            type_hint: "number".to_string(),
            description: "Datagrams that arrived and were REJECTED as not belonging to this \
                          query. Greater than 0 with no accepted response means something \
                          answered but its transaction ID or echoed question did not match - \
                          worth reporting, it is what an off-path spoofing attempt looks like."
                .to_string(),
            required: true,
        },
        Parameter {
            name: "discard_reasons".to_string(),
            type_hint: "array".to_string(),
            description: "One plain-language reason per discarded datagram, for the first ten \
                          only. When discarded_count is larger than this list, the rest were \
                          counted but not transcribed - the reasons repeat once a flood is \
                          under way, and discarded_count is the number to reason about."
                .to_string(),
            required: true,
        },
    ])
    .with_actions(client_actions())
    .with_log_template(
        LogTemplate::new()
            .with_info("LLMNR {record_type} {name}: no host on the link claims this name (expected outcome)")
            .with_debug(
                "LLMNR timeout: id={transaction_id}, name={name}, type={record_type}, \
                 target={target}, waited={waited_secs}s, discarded={discarded_count}",
            ),
    )
});

/// Two or more responders answered the same query with different data.
///
/// On LLMNR this is not a curiosity: the protocol has no authentication of any kind, so a host
/// that answers faster than the real owner wins the name. Raised loudly and separately so it
/// cannot be lost among the per-responder events.
pub static LLMNR_CONFLICTING_RESPONSES_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "llmnr_conflicting_responses",
        "SECURITY-RELEVANT: two or more hosts answered the SAME LLMNR query for the SAME name \
         with DIFFERENT data. LLMNR has no authentication, so whichever answer a resolver \
         accepts first wins the name - this is exactly what an LLMNR poisoning/spoofing attack \
         looks like on the wire. Report every answer and every responder address; do NOT pick \
         one and present it as the resolution.",
        json!({"type": "wait_for_more"}),
    )
    .with_parameters(vec![
        Parameter {
            name: "transaction_id".to_string(),
            type_hint: "number".to_string(),
            description: "The one query all of these answered.".to_string(),
            required: true,
        },
        Parameter {
            name: "name".to_string(),
            type_hint: "string".to_string(),
            description: "The contested name.".to_string(),
            required: true,
        },
        Parameter {
            name: "record_type".to_string(),
            type_hint: "string".to_string(),
            description: "'A', 'AAAA' or 'PTR'.".to_string(),
            required: true,
        },
        Parameter {
            name: "responder_count".to_string(),
            type_hint: "number".to_string(),
            description: "How many hosts answered.".to_string(),
            required: true,
        },
        Parameter {
            name: "distinct_answers".to_string(),
            type_hint: "number".to_string(),
            description: "How many different answers were given. Always at least 2 here."
                .to_string(),
            required: true,
        },
        Parameter {
            name: "answers".to_string(),
            type_hint: "array".to_string(),
            description: "One entry per responder: {responder_address, address, addresses, ttl, \
                          tentative}."
                .to_string(),
            required: true,
        },
    ])
    .with_actions(client_actions())
    .with_log_template(
        // The loud WARN is raised at the emit site in `mod.rs` (LogTemplate has no warn level);
        // this is the routing/diagnostic rendering of the same event.
        LogTemplate::new()
            .with_info(
                "LLMNR CONFLICT: {name} ({record_type}) answered differently by \
                 {responder_count} hosts - LLMNR is unauthenticated and this is what name \
                 spoofing looks like",
            )
            .with_debug(
                "LLMNR conflict: id={transaction_id}, name={name}, type={record_type}, \
                 responders={responder_count}, distinct={distinct_answers}",
            )
            .with_trace("LLMNR conflict: {json_pretty(.)}"),
    )
});

/// Event types this client raises.
pub fn get_llmnr_client_event_types() -> Vec<EventType> {
    vec![
        LLMNR_CLIENT_CONNECTED_EVENT.clone(),
        LLMNR_RESPONSE_RECEIVED_EVENT.clone(),
        LLMNR_QUERY_TIMEOUT_EVENT.clone(),
        LLMNR_CONFLICTING_RESPONSES_EVENT.clone(),
    ]
}
