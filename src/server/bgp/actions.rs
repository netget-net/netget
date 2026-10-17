//! BGP protocol actions.
//!
//! Every `send_bgp_*` action validates and normalises its parameters here and returns
//! [`ActionResult::Custom`] carrying a structured *intent*, not wire bytes.
//!
//! The split exists because [`Protocol::execute_action`] is a pure function of the action JSON
//! with no access to the session, while the correct encoding of an UPDATE depends on whether
//! four-octet AS was negotiated with *this* peer (RFC 6793: a two-octet peer must be sent a
//! two-octet AS_PATH). So the session, which knows, does the encoding — see
//! [`super::wire::encode_intent`].
//!
//! Validating here rather than at encode time also means a malformed action is reported as a
//! failed action, with a message naming the field, instead of silently producing nothing.

use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::EventType;
use crate::state::app_state::AppState;
use anyhow::{bail, Context, Result};
use serde_json::json;
use std::net::Ipv4Addr;
use std::sync::LazyLock;

/// `ActionResult::Custom` name under which BGP hands a validated message intent to the session.
pub const BGP_MESSAGE_INTENT: &str = "bgp_message";

/// BGP protocol action handler
pub struct BgpProtocol;

impl Default for BgpProtocol {
    fn default() -> Self {
        Self::new()
    }
}

impl BgpProtocol {
    pub fn new() -> Self {
        Self
    }

    fn intent(data: serde_json::Value) -> ActionResult {
        ActionResult::Custom {
            name: BGP_MESSAGE_INTENT.to_string(),
            data,
        }
    }

    fn execute_send_bgp_open(&self, action: serde_json::Value) -> Result<ActionResult> {
        let my_as = action
            .get("my_as")
            .and_then(|v| v.as_u64())
            .context("send_bgp_open requires my_as")?;
        let my_as = u32::try_from(my_as)
            .with_context(|| format!("my_as {my_as} is outside the 1-4294967295 AS range"))?;
        if my_as == 0 {
            bail!("my_as must be between 1 and 4294967295");
        }

        let hold_time = action
            .get("hold_time")
            .and_then(|v| v.as_u64())
            .unwrap_or(180);
        let hold_time = u16::try_from(hold_time)
            .with_context(|| format!("hold_time {hold_time} is outside 0-65535"))?;
        if hold_time != 0 && hold_time < 3 {
            bail!("hold_time must be 0 (timers disabled) or at least 3 seconds (RFC 4271 6.2)");
        }

        let router_id = action
            .get("router_id")
            .and_then(|v| v.as_str())
            .context("send_bgp_open requires router_id")?;
        let router_id: Ipv4Addr = router_id
            .parse()
            .with_context(|| format!("router_id {router_id:?} is not an IPv4 address"))?;
        if router_id.is_unspecified() {
            bail!("router_id must not be 0.0.0.0 (RFC 4271 requires a valid BGP Identifier)");
        }

        Ok(Self::intent(json!({
            "kind": "open",
            "my_as": my_as,
            "hold_time": hold_time,
            "router_id": router_id.to_string(),
        })))
    }

    fn execute_send_bgp_keepalive(&self, _action: serde_json::Value) -> Result<ActionResult> {
        Ok(Self::intent(json!({ "kind": "keepalive" })))
    }

    fn execute_send_bgp_update(&self, action: serde_json::Value) -> Result<ActionResult> {
        let prefixes = |key: &str| -> Result<Vec<String>> {
            let Some(value) = action.get(key) else {
                return Ok(Vec::new());
            };
            if value.is_null() {
                return Ok(Vec::new());
            }
            let array = value
                .as_array()
                .with_context(|| format!("{key} must be an array of CIDR prefix strings"))?;
            array
                .iter()
                .map(|v| {
                    let s = v
                        .as_str()
                        .with_context(|| format!("{key} entries must be strings like 10.0.0.0/24"))?
                        .to_string();
                    // Parse now so a bad prefix is an action failure rather than a silent drop.
                    super::wire::ipv4_unicast(&s)?;
                    Ok(s)
                })
                .collect()
        };

        let withdrawn = prefixes("withdrawn_routes")?;
        let nlri = prefixes("nlri")?;
        if withdrawn.is_empty() && nlri.is_empty() {
            bail!("send_bgp_update needs at least one prefix in nlri or withdrawn_routes");
        }

        let next_hop = match action.get("next_hop").and_then(|v| v.as_str()) {
            Some(s) => Some(
                s.parse::<Ipv4Addr>()
                    .with_context(|| format!("next_hop {s:?} is not an IPv4 address"))?,
            ),
            None => None,
        };
        if !nlri.is_empty() && next_hop.is_none() {
            bail!(
                "send_bgp_update with nlri requires next_hop \
                 (RFC 4271 9.1 makes NEXT_HOP mandatory for an announcement)"
            );
        }

        let as_path: Vec<u32> = match action.get("as_path") {
            Some(v) if !v.is_null() => {
                let array = v
                    .as_array()
                    .context("as_path must be an array of AS numbers")?;
                array
                    .iter()
                    .map(|v| {
                        let n = v.as_u64().context("as_path entries must be AS numbers")?;
                        u32::try_from(n).with_context(|| format!("AS number {n} is out of range"))
                    })
                    .collect::<Result<_>>()?
            }
            _ => Vec::new(),
        };

        let origin = match action.get("origin").and_then(|v| v.as_str()) {
            None => "IGP",
            Some(o) => match o.to_ascii_uppercase().as_str() {
                "IGP" => "IGP",
                "EGP" => "EGP",
                "INCOMPLETE" => "INCOMPLETE",
                other => bail!("origin must be IGP, EGP or INCOMPLETE, got {other:?}"),
            },
        };

        let u32_field = |key: &str| -> Result<Option<u32>> {
            match action.get(key) {
                Some(v) if !v.is_null() => {
                    let n = v
                        .as_u64()
                        .with_context(|| format!("{key} must be a number"))?;
                    Ok(Some(u32::try_from(n).with_context(|| {
                        format!("{key} value {n} exceeds 4294967295")
                    })?))
                }
                _ => Ok(None),
            }
        };

        Ok(Self::intent(json!({
            "kind": "update",
            "withdrawn_routes": withdrawn,
            "nlri": nlri,
            "next_hop": next_hop.map(|h| h.to_string()),
            "as_path": as_path,
            "origin": origin,
            "med": u32_field("med")?,
            "local_pref": u32_field("local_pref")?,
        })))
    }

    fn execute_send_bgp_notification(&self, action: serde_json::Value) -> Result<ActionResult> {
        let error_code = action
            .get("error_code")
            .and_then(|v| v.as_u64())
            .context("send_bgp_notification requires error_code")?;
        let error_code = u8::try_from(error_code)
            .with_context(|| format!("error_code {error_code} must be 1-6"))?;
        if !(1..=6).contains(&error_code) {
            bail!("error_code must be 1-6 (see RFC 4271 section 6), got {error_code}");
        }

        let error_subcode = action
            .get("error_subcode")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let error_subcode = u8::try_from(error_subcode)
            .with_context(|| format!("error_subcode {error_subcode} must be 0-255"))?;

        // Documented as hex, and actually decoded as hex — the executor and the documentation
        // have to agree, or a model following the docs puts literal ASCII on the wire.
        let data = match action.get("data") {
            Some(v) if !v.is_null() => {
                let s = v
                    .as_str()
                    .context("data must be a hex-encoded string, e.g. \"00b4\"")?;
                if s.is_empty() {
                    String::new()
                } else {
                    hex::decode(s).with_context(|| format!("data {s:?} is not valid hex"))?;
                    s.to_string()
                }
            }
            _ => String::new(),
        };

        Ok(Self::intent(json!({
            "kind": "notification",
            "error_code": error_code,
            "error_subcode": error_subcode,
            "data": data,
        })))
    }
}

// ============================================================================
// Action Definitions (shared between get_sync_actions() and the event types).
// ============================================================================

fn send_bgp_open_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_bgp_open".to_string(),
        description: "Accept the peering request by sending our BGP OPEN. NetGet adds the \
                      four-octet AS capability and sends the follow-up KEEPALIVE itself."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "my_as".to_string(),
                type_hint: "number".to_string(),
                description: "Our AS number, 1-4294967295. Values above 65535 are carried in \
                              the four-octet AS capability with AS_TRANS in the legacy field."
                    .to_string(),
                required: true,
            },
            Parameter {
                name: "hold_time".to_string(),
                type_hint: "number".to_string(),
                description: "Proposed hold time in seconds (default 180). Must be 0 or >= 3. \
                              The session uses the smaller of this and the peer's."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "router_id".to_string(),
                type_hint: "string".to_string(),
                description: "BGP router identifier, IPv4 dotted quad, not 0.0.0.0".to_string(),
                required: true,
            },
        ],
        example: json!({
            "type": "send_bgp_open",
            "my_as": 65001,
            "hold_time": 180,
            "router_id": "192.168.1.1"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> BGP OPEN AS{my_as} hold={hold_time}s")
                .with_debug(
                    "BGP send_bgp_open: AS={my_as}, hold_time={hold_time}, router_id={router_id}",
                ),
        ),
    }
}

fn send_bgp_keepalive_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_bgp_keepalive".to_string(),
        description: "Send a BGP KEEPALIVE. Rarely needed: NetGet sends keepalives on its own \
                      at a third of the negotiated hold time for the life of the session."
            .to_string(),
        parameters: vec![],
        example: json!({ "type": "send_bgp_keepalive" }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> BGP KEEPALIVE")
                .with_debug("BGP send_bgp_keepalive"),
        ),
    }
}

fn send_bgp_update_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_bgp_update".to_string(),
        description: "Announce and/or withdraw routes with a BGP UPDATE. This is how routes \
                      reach the peer; NetGet keeps no routing table, so every announcement is \
                      exactly what this action says."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "nlri".to_string(),
                type_hint: "array".to_string(),
                description: "CIDR prefixes to announce, e.g. [\"192.168.0.0/16\"]".to_string(),
                required: false,
            },
            Parameter {
                name: "withdrawn_routes".to_string(),
                type_hint: "array".to_string(),
                description: "CIDR prefixes to withdraw, e.g. [\"10.0.0.0/24\"]".to_string(),
                required: false,
            },
            Parameter {
                name: "next_hop".to_string(),
                type_hint: "string".to_string(),
                description: "Next-hop IPv4 address. Required whenever nlri is non-empty."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "as_path".to_string(),
                type_hint: "array".to_string(),
                description: "AS numbers forming the AS_SEQUENCE, e.g. [65001]. An empty list \
                              is a locally originated route."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "origin".to_string(),
                type_hint: "string".to_string(),
                description: "ORIGIN attribute: IGP (default), EGP or INCOMPLETE".to_string(),
                required: false,
            },
            Parameter {
                name: "med".to_string(),
                type_hint: "number".to_string(),
                description: "Optional MULTI_EXIT_DISC metric".to_string(),
                required: false,
            },
            Parameter {
                name: "local_pref".to_string(),
                type_hint: "number".to_string(),
                description: "Optional LOCAL_PREF, meaningful to iBGP peers".to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "send_bgp_update",
            "nlri": ["10.0.0.0/24"],
            "next_hop": "192.168.1.1",
            "as_path": [65001],
            "origin": "IGP"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> BGP UPDATE")
                .with_debug("BGP send_bgp_update: withdrawn={withdrawn_routes} nlri={nlri}"),
        ),
    }
}

fn send_bgp_notification_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_bgp_notification".to_string(),
        description: "Refuse or tear down the session with a BGP NOTIFICATION. On a bgp_open \
                      event this is the explicit refusal to peer, and it is the only thing that \
                      counts as one."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "error_code".to_string(),
                type_hint: "number".to_string(),
                description: "RFC 4271 error code 1-6: 1 header, 2 OPEN, 3 UPDATE, \
                              4 hold timer expired, 5 FSM, 6 cease"
                    .to_string(),
                required: true,
            },
            Parameter {
                name: "error_subcode".to_string(),
                type_hint: "number".to_string(),
                description: "Error subcode, 0 if unspecified. With code 2: 2 bad peer AS, \
                              3 bad BGP identifier. With code 6: 2 administrative shutdown, \
                              5 connection rejected."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "data".to_string(),
                type_hint: "string".to_string(),
                description: "Optional diagnostic bytes as a hex string, e.g. \"00b4\". \
                              Decoded as hex; leave it out unless the subcode defines a payload."
                    .to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "send_bgp_notification",
            "error_code": 6,
            "error_subcode": 5
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> BGP NOTIFICATION code={error_code}")
                .with_debug(
                    "BGP send_bgp_notification: code={error_code}, subcode={error_subcode}",
                ),
        ),
    }
}

fn wait_for_more_action() -> ActionDefinition {
    ActionDefinition {
        name: "wait_for_more".to_string(),
        description: "Take no action and wait for the next BGP message.".to_string(),
        parameters: vec![],
        example: json!({ "type": "wait_for_more" }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> BGP wait for more")
                .with_debug("BGP wait_for_more: awaiting additional messages"),
        ),
    }
}

// ============================================================================
// Event Types
//
// `call_llm` builds the model's tool list from `EventType::actions`, not from
// get_sync_actions(), so every event carries its own action list.
// ============================================================================

/// Actions any BGP session event can respond with.
fn bgp_response_actions() -> Vec<ActionDefinition> {
    vec![
        send_bgp_open_action(),
        send_bgp_keepalive_action(),
        send_bgp_update_action(),
        send_bgp_notification_action(),
        wait_for_more_action(),
    ]
}

pub static BGP_OPEN_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "bgp_open",
        "BGP OPEN received. Decide whether to peer with this neighbour. Reply with \
         send_bgp_open to accept, or send_bgp_notification to refuse. If neither is returned, \
         NetGet sends the OPEN configured at startup.",
        json!({
            "type": "send_bgp_open",
            "my_as": 65001,
            "hold_time": 180,
            "router_id": "192.168.1.1"
        }),
    )
    .with_alternative_example(json!({
        "type": "send_bgp_notification",
        "error_code": 2,
        "error_subcode": 2
    }))
    .with_actions(bgp_response_actions())
    .with_log_template(
        LogTemplate::new()
            .with_info("BGP OPEN from AS{peer_as} router_id={peer_router_id}")
            .with_debug(
                "BGP OPEN: AS={peer_as} hold={peer_hold_time} asn4={peer_supports_four_octet_as}",
            )
            .with_trace("BGP OPEN: {json_pretty(.)}"),
    )
});

/// Raised once, when the session reaches Established.
///
/// This replaces a `bgp_keepalive` event that was declared and never emitted. Emitting one per
/// KEEPALIVE would have meant a model call every hold/3 seconds per peer, forever, to decide
/// nothing; this fires exactly when there is a decision to make, namely which routes to
/// advertise to a peer that is now willing to accept them.
pub static BGP_ESTABLISHED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "bgp_established",
        "BGP session reached Established. The peer will now accept UPDATEs. Reply with \
         send_bgp_update to advertise routes, or wait_for_more to advertise nothing.",
        json!({
            "type": "send_bgp_update",
            "nlri": ["10.0.0.0/24"],
            "next_hop": "192.168.1.1",
            "as_path": [65001],
            "origin": "IGP"
        }),
    )
    .with_alternative_example(json!({ "type": "wait_for_more" }))
    .with_actions(bgp_response_actions())
    .with_log_template(
        LogTemplate::new()
            .with_info("BGP established with AS{peer_as}")
            .with_debug("BGP established with AS{peer_as} on {connection_id}")
            .with_trace("BGP established: {json_pretty(.)}"),
    )
});

pub static BGP_UPDATE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "bgp_update",
        "BGP UPDATE received, decoded into withdrawn_routes, nlri, origin, next_hop, as_path \
         and the full path_attributes list. Reply with send_bgp_update to advertise routes back, \
         or wait_for_more.",
        json!({ "type": "wait_for_more" }),
    )
    .with_actions(bgp_response_actions())
    .with_log_template(
        LogTemplate::new()
            .with_info("BGP UPDATE from AS{peer_as}")
            .with_debug("BGP UPDATE from AS{peer_as} on {connection_id}")
            .with_trace("BGP UPDATE: {json_pretty(.)}"),
    )
});

pub static BGP_NOTIFICATION_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "bgp_notification",
        "BGP NOTIFICATION received. RFC 4271 forbids replying to one, so the session closes \
         regardless of what is returned and nothing is written to the socket. Record what \
         matters with set_memory or append_to_log.",
        json!({ "type": "wait_for_more" }),
    )
    // No wire verbs, deliberately. `on_notification` discards whatever the handler returns —
    // it has to, because RFC 4271 section 4.5 forbids answering a NOTIFICATION — so the four
    // `send_bgp_*` verbs this used to advertise could never reach the socket, which is the
    // "advertised but structurally inert" shape the root CLAUDE.md warns about.
    //
    // `wait_for_more` stays rather than `.with_no_actions()`, because a *server* narrows: its
    // tool list is built from this list alone, so dropping it would leave the declared response
    // example (`wait_for_more`) teaching an action the model was never offered. The common
    // actions (set_memory, append_to_log) are added by `call_llm` regardless, so a handler can
    // still record what it saw.
    .with_actions(vec![wait_for_more_action()])
    .with_log_template(
        LogTemplate::new()
            .with_info("BGP NOTIFICATION code={error_code} subcode={error_subcode}")
            .with_debug("BGP NOTIFICATION: {error_name} / {error_subcode_name} from AS{peer_as}")
            .with_trace("BGP NOTIFICATION: {json_pretty(.)}"),
    )
});

// Implement Protocol trait (common functionality)
impl Protocol for BgpProtocol {
    /// No user-triggered actions.
    ///
    /// There were three (`announce_route`, `withdraw_route`, `reset_peer`). All were dead: the
    /// first two logged their argument and returned `NoAction`, and none of the three could
    /// reach a peer, because an async action carries no connection and this server never
    /// consumed async action results. Routes are advertised from a `bgp_established` or
    /// `bgp_update` handler with `send_bgp_update`, which does reach the socket.
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![]
    }

    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        bgp_response_actions()
    }

    fn protocol_name(&self) -> &'static str {
        "BGP"
    }

    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            BGP_OPEN_EVENT.clone(),
            BGP_ESTABLISHED_EVENT.clone(),
            BGP_UPDATE_EVENT.clone(),
            BGP_NOTIFICATION_EVENT.clone(),
        ]
    }

    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>BGP"
    }

    fn keywords(&self) -> Vec<&'static str> {
        vec!["bgp", "border gateway"]
    }

    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{
            DevelopmentState, PrivilegeRequirement, ProtocolMetadataV2,
        };

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            // BGP's assigned port is TCP 179, below 1024. Any other port needs no privilege.
            .privilege_requirement(PrivilegeRequirement::PrivilegedPort(179))
            .well_known_port(179)
            .implementation(
                "RFC 4271 session over netgauze-bgp-pkt codec; four-octet AS (RFC 6793)",
            )
            .llm_control("Optional: the OPEN handshake is mechanical (configured OPEN, no LLM); whether to advertise routes is policy (LLM). With no policy configured the session handshakes on the configured OPEN and advertises nothing, all with no LLM call")
            .e2e_testing("Two-way wire conformance against netgauze, plus mocked session E2E")
            .notes(
                "Session is complete: OPEN validation, capability and hold-time negotiation, \
                 KEEPALIVE cadence, hold-timer expiry, NOTIFICATION on error. The OPEN handshake \
                 is mechanical (fully determined by the configured ASN/router-id/hold-time and a \
                 validated peer), so with no operator policy (no instruction, no handler) it \
                 completes on the configured OPEN with NO LLM round-trip; established/update then \
                 advertise nothing, which is correct with no routing policy. KEEPALIVE cadence \
                 never consulted the LLM. The model is consulted only when the operator opts in. \
                 No RIB by design - routes are whatever a handler advertises with send_bgp_update, \
                 nothing is stored or re-advertised, and there is no best-path selection or \
                 propagation between peers. IPv4 unicast only on the send path. Never peered \
                 against a live BGP daemon.",
            )
            .max_inbound_bytes(crate::server::bgp::wire::BGP_MAX_MESSAGE_LEN)
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }

    fn description(&self) -> &'static str {
        "BGP routing server"
    }

    fn example_prompt(&self) -> &'static str {
        "Start a BGP routing server on port 8179"
    }

    fn get_startup_parameters(&self) -> Vec<crate::llm::actions::ParameterDefinition> {
        use crate::llm::actions::ParameterDefinition;
        vec![
            ParameterDefinition {
                name: "as_number".to_string(),
                type_hint: "integer".to_string(),
                description: "Our Autonomous System Number (1-4294967295). Use private ASNs \
                              (64512-65534) for testing. Values above 65535 are advertised via \
                              the four-octet AS capability."
                    .to_string(),
                required: false,
                example: json!(65001),
                default: None,
            },
            ParameterDefinition {
                name: "router_id".to_string(),
                type_hint: "string".to_string(),
                description: "BGP router ID in IPv4 dotted-quad form, not 0.0.0.0".to_string(),
                required: false,
                example: json!("192.168.1.1"),
                default: None,
            },
            ParameterDefinition {
                name: "hold_time".to_string(),
                type_hint: "integer".to_string(),
                description: "Hold time we propose, in seconds (default 180). Must be 0 \
                              (timers disabled) or at least 3. Keepalives are sent at a third \
                              of the negotiated value."
                    .to_string(),
                required: false,
                example: json!(180),
                default: None,
            },
        ]
    }

    fn group_name(&self) -> &'static str {
        "VPN & Routing"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;

        // Deterministic: acknowledge every UPDATE with a KEEPALIVE, no LLM call.
        let script = r#"import json, sys
data = json.load(sys.stdin)
event = data["event"]
if data["event_type_id"] == "bgp_update":
    actions = [{"type": "send_bgp_keepalive"}]
else:
    actions = []
print(json.dumps({"actions": actions}))"#;

        StartupExamples::new(
            // LLM mode: the model decides who to peer with and what to advertise.
            json!({
                "type": "open_server",
                "port": 179,
                "base_stack": "bgp",
                "instruction": "Peer with anyone in AS 65000-65535 and advertise 10.0.0.0/24",
                "startup_params": {
                    "as_number": 65001,
                    "router_id": "192.168.1.1"
                }
            }),
            // Script mode.
            json!({
                "type": "open_server",
                "port": 179,
                "base_stack": "bgp",
                "startup_params": {
                    "as_number": 65001,
                    "router_id": "192.168.1.1"
                },
                "event_handlers": [{
                    "event_pattern": "bgp_update",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": script
                    }
                }]
            }),
            // Static mode: accept every peer and advertise one prefix once established.
            json!({
                "type": "open_server",
                "port": 179,
                "base_stack": "bgp",
                "startup_params": {
                    "as_number": 65001,
                    "router_id": "192.168.1.1"
                },
                "event_handlers": [
                    {
                        "event_pattern": "bgp_open",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "send_bgp_open",
                                "my_as": 65001,
                                "hold_time": 180,
                                "router_id": "192.168.1.1"
                            }]
                        }
                    },
                    {
                        "event_pattern": "bgp_established",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "send_bgp_update",
                                "nlri": ["10.0.0.0/24"],
                                "next_hop": "192.168.1.1",
                                "as_path": [65001],
                                "origin": "IGP"
                            }]
                        }
                    }
                ]
            }),
        )
    }
}

// Implement Server trait (server-specific functionality)
impl Server for BgpProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::server::bgp::BgpServer;
            BgpServer::spawn_with_llm_actions(
                ctx.legacy_listen_addr(),
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.server_id,
                ctx.startup_params,
            )
            .await
        })
    }

    fn execute_action(&self, action: serde_json::Value) -> Result<ActionResult> {
        let action_type = action
            .get("type")
            .and_then(|v| v.as_str())
            .context("Missing action type")?;

        match action_type {
            "send_bgp_open" => self.execute_send_bgp_open(action),
            "send_bgp_keepalive" => self.execute_send_bgp_keepalive(action),
            "send_bgp_update" => self.execute_send_bgp_update(action),
            "send_bgp_notification" => self.execute_send_bgp_notification(action),
            "wait_for_more" => Ok(ActionResult::WaitForMore),
            // Not offered to the model (refusing or ending a session is `send_bgp_notification`),
            // but the dashboard's "disconnect this peer" injects it through the session's peer
            // command task, which turns it into NOTIFICATION 6/2 followed by the close.
            "close_connection" => Ok(ActionResult::CloseConnection),
            _ => Err(anyhow::anyhow!("Unknown BGP action type: {}", action_type)),
        }
    }
}
