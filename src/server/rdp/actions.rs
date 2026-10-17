//! RDP server actions — the connection-negotiation slice of [MS-RDPBCGR].
//!
//! This implements the very first exchange of the Remote Desktop Protocol: the TPKT-framed
//! X.224 Connection Request / Connection Confirm carrying the RDP negotiation
//! ([MS-RDPBCGR] 2.2.1.1 / 2.2.1.2). The LLM decides how the server negotiates — which security
//! protocol to select, or which failure code to reject with. See `src/server/rdp/CLAUDE.md` for
//! exactly where this slice stops (before MCS/GCC, security, capabilities and any bitmap).

use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::EventType;
use crate::state::app_state::AppState;
use anyhow::{Context, Result};
use serde_json::json;
use std::sync::LazyLock;

/// RDP protocol handler (stateless: describes actions/events, builds negotiation bytes).
#[derive(Default)]
pub struct RdpProtocol;

impl RdpProtocol {
    pub fn new() -> Self {
        Self
    }
}

impl Protocol for RdpProtocol {
    fn get_startup_parameters(&self) -> Vec<crate::llm::actions::ParameterDefinition> {
        // No startup parameters: the negotiation decision is made per connection by the model.
        Vec::new()
    }

    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        Vec::new()
    }

    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            send_negotiation_response_action(),
            reject_connection_action(),
        ]
    }

    fn protocol_name(&self) -> &'static str {
        "RDP"
    }

    fn get_event_types(&self) -> Vec<EventType> {
        get_rdp_event_types()
    }

    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>TPKT>X224>RDP"
    }

    fn keywords(&self) -> Vec<&'static str> {
        // Distinctive, never a bare "desktop" or "remote" (the Bluetooth "remote" profile
        // already claims that substring and broke resolution once).
        vec!["rdp", "mstsc", "ms-rdpbcgr", "freerdp"]
    }

    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{
            DevelopmentState, PrivilegeRequirement, ProtocolMetadataV2,
        };

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .well_known_port(3389)
            .implementation(
                "Hand-written TPKT + X.224 with the [MS-RDPBCGR] RDP negotiation (CR/CC); no crate",
            )
            .llm_control("The negotiation decision: which security protocol to select, or reject with which failure code")
            .e2e_testing("Raw TCP client sending a real X.224 Connection Request; asserts CC bytes vs MS-RDPBCGR literals")
            .notes(
                "SLICE: TPKT + X.224 connection negotiation ONLY ([MS-RDPBCGR] 2.2.1.1/2.2.1.2). \
                 The server parses the client's Connection Request (routing cookie / mstshash \
                 username, requestedProtocols) and answers a Connection Confirm the model chooses. \
                 It STOPS before MCS/GCC, the security exchange, the capability exchange and any \
                 bitmap output — so no desktop frame is rendered and a client does not reach a \
                 session. No real RDP client (xfreerdp/mstsc) was available in this environment to \
                 test past negotiation; correctness is pinned against RFC-derived literal bytes.",
            )
            .max_inbound_bytes(crate::server::rdp::MAX_X224_LEN)
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }

    fn description(&self) -> &'static str {
        "RDP server: the TPKT/X.224 connection-negotiation handshake (model picks the response)"
    }

    fn example_prompt(&self) -> &'static str {
        "Act as an RDP server on port 3389 that requires TLS security during negotiation"
    }

    fn group_name(&self) -> &'static str {
        "Network Services"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;

        // Deterministic: select TLS security for every connection request, no
        // LLM call.
        let script = r#"import json, sys
data = json.load(sys.stdin)
event = data["event"]
if data["event_type_id"] == "rdp_connection_request":
    actions = [{"type": "send_rdp_negotiation_response", "selected_protocol": "TLS"}]
else:
    actions = []
print(json.dumps({"actions": actions}))"#;

        StartupExamples::new(
            // LLM mode
            json!({
                "type": "open_server",
                "port": 3389,
                "base_stack": "rdp",
                "instruction": "RDP server that selects TLS security during negotiation"
            }),
            // Script mode
            json!({
                "type": "open_server",
                "port": 3389,
                "base_stack": "rdp",
                "event_handlers": [{
                    "event_pattern": "rdp_connection_request",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": script
                    }
                }]
            }),
            // Static mode
            json!({
                "type": "open_server",
                "port": 3389,
                "base_stack": "rdp",
                "event_handlers": [{
                    "event_pattern": "rdp_connection_request",
                    "handler": {
                        "type": "static",
                        "actions": [{
                            "type": "send_rdp_negotiation_response",
                            "selected_protocol": "TLS"
                        }]
                    }
                }]
            }),
        )
    }
}

impl Server for RdpProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            if let Some(params) = ctx.startup_params.as_ref() {
                let _ = params.allowed_parameters();
            }
            use crate::server::rdp::RdpServer;
            let listen_addr = ctx.legacy_listen_addr();
            RdpServer::spawn_with_llm_actions(
                listen_addr,
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.server_id,
            )
            .await
        })
    }

    fn execute_action(&self, action: serde_json::Value) -> Result<ActionResult> {
        let action_type = action
            .get("type")
            .and_then(|v| v.as_str())
            .context("Missing 'type' field in action")?;

        match action_type {
            "send_rdp_negotiation_response" => {
                let name = action
                    .get("selected_protocol")
                    .and_then(|v| v.as_str())
                    .context("Missing 'selected_protocol' parameter")?;
                let selected = protocol_name_to_value(name).ok_or_else(|| {
                    anyhow::anyhow!(
                        "Invalid 'selected_protocol' {name:?}. Valid values: RDP, TLS, HYBRID \
                         (CredSSP/NLA), RDSTLS, HYBRID_EX."
                    )
                })?;
                let extended = action
                    .get("extended_client_data")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let flags = if extended {
                    NEG_RSP_EXTENDED_CLIENT_DATA_SUPPORTED
                } else {
                    0
                };
                Ok(ActionResult::Output(build_negotiation_response(
                    selected, flags,
                )))
            }
            "reject_rdp_connection" => {
                let name = action
                    .get("failure_code")
                    .and_then(|v| v.as_str())
                    .context("Missing 'failure_code' parameter")?;
                let code = failure_name_to_value(name).ok_or_else(|| {
                    anyhow::anyhow!(
                        "Invalid 'failure_code' {name:?}. Valid values: SSL_REQUIRED_BY_SERVER, \
                         SSL_NOT_ALLOWED_BY_SERVER, SSL_CERT_NOT_ON_SERVER, INCONSISTENT_FLAGS, \
                         HYBRID_REQUIRED_BY_SERVER, SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER."
                    )
                })?;
                Ok(ActionResult::Output(build_negotiation_failure(code)))
            }
            // Not offered to the model (the negotiation slice always answers with a CC and then
            // half-closes on its own), but the dashboard's "disconnect this peer" injects this
            // through the peer command task, which half-closes the write side on this result.
            "close_connection" => Ok(ActionResult::CloseConnection),
            other => Err(anyhow::anyhow!("Unknown RDP action: {other}")),
        }
    }
}

// ============================================================================
// [MS-RDPBCGR] wire constants and byte builders
// ============================================================================

/// X.224 Connection Request TPDU code (CR, high nibble 0xE).
pub const X224_TPDU_CONNECTION_REQUEST: u8 = 0xE0;
/// X.224 Connection Confirm TPDU code (CC, high nibble 0xD).
pub const X224_TPDU_CONNECTION_CONFIRM: u8 = 0xD0;

/// RDP_NEG_REQ type octet ([MS-RDPBCGR] 2.2.1.1.1).
pub const TYPE_RDP_NEG_REQ: u8 = 0x01;
/// RDP_NEG_RSP type octet ([MS-RDPBCGR] 2.2.1.2.1).
pub const TYPE_RDP_NEG_RSP: u8 = 0x02;
/// RDP_NEG_FAILURE type octet ([MS-RDPBCGR] 2.2.1.2.2).
pub const TYPE_RDP_NEG_FAILURE: u8 = 0x03;

/// EXTENDED_CLIENT_DATA_SUPPORTED flag in RDP_NEG_RSP.
pub const NEG_RSP_EXTENDED_CLIENT_DATA_SUPPORTED: u8 = 0x01;

/// Map an RDP negotiation protocol name to its `requestedProtocols`/`selectedProtocol` value.
pub fn protocol_name_to_value(name: &str) -> Option<u32> {
    match name.trim().to_ascii_uppercase().as_str() {
        "RDP" | "PROTOCOL_RDP" | "STANDARD" => Some(0x0000_0000),
        "TLS" | "SSL" | "PROTOCOL_SSL" => Some(0x0000_0001),
        "HYBRID" | "CREDSSP" | "NLA" | "PROTOCOL_HYBRID" => Some(0x0000_0002),
        "RDSTLS" | "PROTOCOL_RDSTLS" => Some(0x0000_0004),
        "HYBRID_EX" | "PROTOCOL_HYBRID_EX" => Some(0x0000_0008),
        "RDSAAD" | "PROTOCOL_RDSAAD" => Some(0x0000_0010),
        _ => None,
    }
}

/// Names of every negotiation protocol bit set in a `requestedProtocols` bitmask.
///
/// A client that sends no RDP_NEG_REQ implicitly requests standard RDP security, which is why the
/// caller passes `0` and gets `["RDP"]`.
pub fn protocol_value_to_names(value: u32) -> Vec<&'static str> {
    if value == 0 {
        return vec!["RDP"];
    }
    let mut names = Vec::new();
    if value & 0x0000_0001 != 0 {
        names.push("TLS");
    }
    if value & 0x0000_0002 != 0 {
        names.push("HYBRID");
    }
    if value & 0x0000_0004 != 0 {
        names.push("RDSTLS");
    }
    if value & 0x0000_0008 != 0 {
        names.push("HYBRID_EX");
    }
    if value & 0x0000_0010 != 0 {
        names.push("RDSAAD");
    }
    if names.is_empty() {
        names.push("UNKNOWN");
    }
    names
}

/// Map an RDP negotiation failure name to its `failureCode` value ([MS-RDPBCGR] 2.2.1.2.2).
pub fn failure_name_to_value(name: &str) -> Option<u32> {
    match name.trim().to_ascii_uppercase().as_str() {
        "SSL_REQUIRED_BY_SERVER" => Some(0x0000_0001),
        "SSL_NOT_ALLOWED_BY_SERVER" => Some(0x0000_0002),
        "SSL_CERT_NOT_ON_SERVER" => Some(0x0000_0003),
        "INCONSISTENT_FLAGS" => Some(0x0000_0004),
        "HYBRID_REQUIRED_BY_SERVER" => Some(0x0000_0005),
        "SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER" => Some(0x0000_0006),
        _ => None,
    }
}

/// The `failureCode` used on the fail-closed path when the model gives no usable answer.
pub const DEFAULT_FAILURE_CODE: u32 = 0x0000_0001; // SSL_REQUIRED_BY_SERVER

/// Build a full TPKT + X.224 Connection Confirm carrying an RDP_NEG_RSP.
///
/// Layout ([MS-RDPBCGR] 2.2.1.2): TPKT(4) + X.224 CC header(7) + RDP_NEG_RSP(8) = 19 bytes.
pub fn build_negotiation_response(selected_protocol: u32, flags: u8) -> Vec<u8> {
    let nego = build_rdp_neg(TYPE_RDP_NEG_RSP, flags, selected_protocol);
    wrap_connection_confirm(&nego)
}

/// Build a full TPKT + X.224 Connection Confirm carrying an RDP_NEG_FAILURE.
pub fn build_negotiation_failure(failure_code: u32) -> Vec<u8> {
    // RDP_NEG_FAILURE has a reserved flags octet that is always 0.
    let nego = build_rdp_neg(TYPE_RDP_NEG_FAILURE, 0, failure_code);
    wrap_connection_confirm(&nego)
}

/// The 8-byte RDP_NEG_* structure: type(1), flags(1), length(2 LE = 0x0008), payload(4 LE).
fn build_rdp_neg(neg_type: u8, flags: u8, payload: u32) -> [u8; 8] {
    let mut buf = [0u8; 8];
    buf[0] = neg_type;
    buf[1] = flags;
    buf[2..4].copy_from_slice(&8u16.to_le_bytes());
    buf[4..8].copy_from_slice(&payload.to_le_bytes());
    buf
}

/// Wrap an 8-byte RDP_NEG_* structure in a TPKT + X.224 Connection Confirm.
fn wrap_connection_confirm(nego: &[u8]) -> Vec<u8> {
    debug_assert_eq!(nego.len(), 8);
    // X.224 CC header after the LI byte: code(1) + dstRef(2) + srcRef(2) + class(1) = 6 bytes.
    let li: u8 = 6 + nego.len() as u8; // = 14 (0x0E)
    let total_len: u16 = 4 + 1 + li as u16; // TPKT(4) + LI(1) + header+nego = 19

    let mut out = Vec::with_capacity(total_len as usize);
    // TPKT header (RFC 1006 / [MS-RDPBCGR] 2.2.1.2).
    out.push(0x03); // version
    out.push(0x00); // reserved
    out.extend_from_slice(&total_len.to_be_bytes());
    // X.224 Connection Confirm.
    out.push(li);
    out.push(X224_TPDU_CONNECTION_CONFIRM);
    out.extend_from_slice(&[0x00, 0x00]); // DST-REF
    out.extend_from_slice(&[0x00, 0x00]); // SRC-REF
    out.push(0x00); // class option
    out.extend_from_slice(nego);
    out
}

// ============================================================================
// Action definitions
// ============================================================================

fn send_negotiation_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_rdp_negotiation_response".to_string(),
        description: "Accept the RDP connection by sending an X.224 Connection Confirm with an \
            RDP_NEG_RSP that selects one security protocol. Choose from the protocols the client \
            offered in the event's requested_protocols."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "selected_protocol".to_string(),
                type_hint: "string".to_string(),
                description: "Security protocol to select: \"RDP\" (standard RDP security), \
                    \"TLS\" (SSL/TLS), \"HYBRID\" (CredSSP/NLA), \"RDSTLS\", or \"HYBRID_EX\"."
                    .to_string(),
                required: true,
            },
            Parameter {
                name: "extended_client_data".to_string(),
                type_hint: "boolean".to_string(),
                description: "Set the EXTENDED_CLIENT_DATA_SUPPORTED flag. Default false."
                    .to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "send_rdp_negotiation_response",
            "selected_protocol": "TLS"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> RDP NEG_RSP {selected_protocol}")
                .with_debug("RDP negotiation response: {selected_protocol}"),
        ),
    }
}

fn reject_connection_action() -> ActionDefinition {
    ActionDefinition {
        name: "reject_rdp_connection".to_string(),
        description: "Reject the RDP connection by sending an X.224 Connection Confirm with an \
            RDP_NEG_FAILURE. Use this to demand a protocol the client did not offer (e.g. reject \
            with SSL_REQUIRED_BY_SERVER when the client only offered standard RDP)."
            .to_string(),
        parameters: vec![Parameter {
            name: "failure_code".to_string(),
            type_hint: "string".to_string(),
            description: "One of: SSL_REQUIRED_BY_SERVER, SSL_NOT_ALLOWED_BY_SERVER, \
                SSL_CERT_NOT_ON_SERVER, INCONSISTENT_FLAGS, HYBRID_REQUIRED_BY_SERVER, \
                SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER."
                .to_string(),
            required: true,
        }],
        example: json!({
            "type": "reject_rdp_connection",
            "failure_code": "SSL_REQUIRED_BY_SERVER"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> RDP NEG_FAILURE {failure_code}")
                .with_debug("RDP negotiation failure: {failure_code}"),
        ),
    }
}

pub static SEND_NEGOTIATION_RESPONSE_ACTION: LazyLock<ActionDefinition> =
    LazyLock::new(send_negotiation_response_action);
pub static REJECT_CONNECTION_ACTION: LazyLock<ActionDefinition> =
    LazyLock::new(reject_connection_action);

// ============================================================================
// Event type — emitted once per connection by mod.rs, with actions attached.
// ============================================================================

/// Raised when a client's X.224 Connection Request (with RDP negotiation) arrives.
pub static RDP_CONNECTION_REQUEST_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "rdp_connection_request",
        "An RDP client sent its X.224 Connection Request. Decide how to negotiate: accept with \
         send_rdp_negotiation_response selecting one of the offered security protocols, or reject \
         with reject_rdp_connection.",
        json!({
            "type": "send_rdp_negotiation_response",
            "selected_protocol": "TLS"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "cookie_username".to_string(),
            type_hint: "string".to_string(),
            description: "The username from the client's `Cookie: mstshash=...` routing token, or \
                empty if none was sent."
                .to_string(),
            required: true,
        },
        Parameter {
            name: "requested_protocols".to_string(),
            type_hint: "array".to_string(),
            description: "Security protocols the client offered, as names (e.g. [\"RDP\"], \
                [\"TLS\",\"HYBRID\"]). \"RDP\" alone means standard RDP security (no RDP_NEG_REQ)."
                .to_string(),
            required: true,
        },
        Parameter {
            name: "requested_protocols_flags".to_string(),
            type_hint: "number".to_string(),
            description: "The raw flags octet from the client's RDP_NEG_REQ (0 if none)."
                .to_string(),
            required: true,
        },
    ])
    .with_actions(vec![
        SEND_NEGOTIATION_RESPONSE_ACTION.clone(),
        REJECT_CONNECTION_ACTION.clone(),
    ])
    .with_alternative_example(json!({
        "type": "reject_rdp_connection",
        "failure_code": "SSL_REQUIRED_BY_SERVER"
    }))
    .with_log_template(
        LogTemplate::new()
            .with_info("RDP CR from {client_ip}:{client_port} user='{cookie_username}'")
            .with_debug("RDP connection request: {json_pretty(.)}"),
    )
});

/// All event types this protocol can emit.
pub fn get_rdp_event_types() -> Vec<EventType> {
    vec![RDP_CONNECTION_REQUEST_EVENT.clone()]
}
