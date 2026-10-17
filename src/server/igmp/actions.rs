//! IGMP protocol actions implementation

use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::EventType;
use crate::state::app_state::AppState;
use anyhow::{Context, Result};
use serde_json::json;
use std::net::Ipv4Addr;
use std::sync::LazyLock;

/// IGMP protocol action handler
pub struct IgmpProtocol {
    _private: (),
}

impl IgmpProtocol {
    pub fn new() -> Self {
        Self { _private: () }
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for IgmpProtocol {
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![join_group_action(), leave_group_action()]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            send_membership_report_action(),
            send_leave_group_action(),
            ignore_message_action(),
        ]
    }
    fn protocol_name(&self) -> &'static str {
        "IGMP"
    }
    fn get_event_types(&self) -> Vec<EventType> {
        get_igmp_event_types()
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>IGMP"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["igmp", "multicast"]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{
            DevelopmentState, PrivilegeRequirement, ProtocolMetadataV2,
        };

        ProtocolMetadataV2::builder()
            .connectionless()
            .state(DevelopmentState::Experimental)
            // Deliberately silent: IGMP messages assert multicast group membership state;
            // there is no error message in the protocol.
            .deliberately_silent()
            .privilege_requirement(PrivilegeRequirement::RawSockets)
            .implementation("Raw AF_INET/SOCK_RAW/IPPROTO_IGMP socket (libc + socket2)")
            .llm_control("Optional: which groups to report membership in is a policy decision (LLM); with no policy configured the server stays silent with no LLM call")
            .e2e_testing("Manual IGMP packet construction")
            .notes(
                "IGMPv2 support, multicast group management. \
                 Requires root/CAP_NET_RAW; Unix only (no Windows raw-socket path). \
                 Handling is NOT wire-determined: which groups to report is membership policy \
                 (a general query names 0.0.0.0), and an observed report/leave needs no reply. \
                 So with no operator policy (no instruction, no handler) the server applies the \
                 spec-safe STATIC default of advertising no memberships and staying silent, with \
                 NO LLM round-trip; the LLM is consulted only when the operator supplies the \
                 membership policy. Evidence: the packet builders, the RFC 1071 checksum, the \
                 IP-header stripping and the RFC 2236/3376 response destinations are covered \
                 field-by-field by tests/server/igmp/packet_codec_test.rs, which needs no \
                 privilege. The raw socket itself is NOT: every e2e test is root-gated and \
                 `#[ignore]`d, so no ordinary test run has ever had this server receive a \
                 packet. Experimental for that reason - do not read the codec tests as \
                 validation against a real IGMP router.",
            )
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn description(&self) -> &'static str {
        "IGMP multicast group management server"
    }
    fn example_prompt(&self) -> &'static str {
        "Create an IGMP server that joins multicast group 239.255.255.250 and responds to membership queries"
    }
    fn group_name(&self) -> &'static str {
        "Network"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        use serde_json::json;

        // Deterministic: answer a membership query with a report for the group this
        // server is configured to be a member of, no LLM call.
        //
        // It does NOT echo the queried group back. A General Query names group 0.0.0.0,
        // so echoing would emit `send_membership_report` for 0.0.0.0 - a report in a
        // group that does not exist, which the executor refuses. Which groups to report
        // is membership policy and is never derivable from a general query; that is the
        // whole reason this protocol has a policy at all.
        let script = r#"import json, sys
GROUP = "239.255.255.250"
data = json.load(sys.stdin)
event = data["event"]
actions = []
if data["event_type_id"] == "igmp_query_received":
    queried = event.get("group_address", "0.0.0.0")
    if event.get("query_type") == "General" or queried == GROUP:
        actions = [{"type": "send_membership_report", "group_address": GROUP}]
print(json.dumps({"actions": actions}))"#;

        StartupExamples::new(
            // LLM mode: LLM handles all IGMP messages intelligently
            json!({
                "type": "open_server",
                "port": 0,
                "base_stack": "igmp",
                "instruction": "IGMP multicast group management server"
            }),
            // Script mode: Code-based deterministic responses
            json!({
                "type": "open_server",
                "port": 0,
                "base_stack": "igmp",
                "event_handlers": [{
                    "event_pattern": "igmp_query_received",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": script
                    }
                }]
            }),
            // Static mode: Fixed responses
            json!({
                "type": "open_server",
                "port": 0,
                "base_stack": "igmp",
                "event_handlers": [{
                    "event_pattern": "igmp_query_received",
                    "handler": {
                        "type": "static",
                        "actions": [{
                            "type": "send_membership_report",
                            "group_address": "239.255.255.250"
                        }]
                    }
                }]
            }),
        )
    }
}

// Implement Server trait (server-specific functionality)
impl Server for IgmpProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::server::igmp::IgmpServer;
            IgmpServer::spawn_with_llm_actions(
                ctx.legacy_listen_addr(),
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
            "join_group" => self.execute_join_group(action),
            "leave_group" => self.execute_leave_group(action),
            "send_membership_report" => self.execute_send_membership_report(action),
            "send_leave_group" => self.execute_send_leave_group_message(action),
            "ignore_message" => Ok(ActionResult::NoAction),
            _ => Err(anyhow::anyhow!("Unknown IGMP action: {}", action_type)),
        }
    }
}

impl IgmpProtocol {
    /// Read `group_address` and require it to be a real IPv4 multicast group.
    ///
    /// Every IGMP verb here names a group, and 224.0.0.0/4 is the only range any of them means
    /// anything in: `join_multicast_v4` refuses anything else with `EINVAL`, and a Membership
    /// Report or Leave for a unicast address is a claim no router can act on. Rejecting here
    /// names the offending field back to the model instead of failing later as a bare OS errno,
    /// or - worse - putting a nonsense group on the wire.
    ///
    /// It also catches the case the *general* query makes easy to get wrong: a general query
    /// carries group 0.0.0.0, so echoing the queried group straight back into a report produces
    /// `send_membership_report` for 0.0.0.0. Which groups to report is membership policy; it is
    /// never derivable from a general query.
    fn group_address(action: &serde_json::Value, verb: &str) -> Result<Ipv4Addr> {
        let group = action
            .get("group_address")
            .and_then(|v| v.as_str())
            .context("Missing 'group_address' parameter")?;

        let addr: Ipv4Addr = group.parse().context("Invalid IPv4 multicast address")?;

        if !addr.is_multicast() {
            return Err(anyhow::anyhow!(
                "{verb} needs an IPv4 multicast group in 224.0.0.0/4, got {addr}"
            ));
        }
        Ok(addr)
    }

    /// Execute join_group async action
    fn execute_join_group(&self, action: serde_json::Value) -> Result<ActionResult> {
        let addr = Self::group_address(&action, "join_group")?;

        // Return the group address as a custom result for async processing
        Ok(ActionResult::Custom {
            name: "igmp_join_group".to_string(),
            data: json!({"group_address": addr.to_string()}),
        })
    }

    /// Execute leave_group async action
    fn execute_leave_group(&self, action: serde_json::Value) -> Result<ActionResult> {
        let addr = Self::group_address(&action, "leave_group")?;

        // Return the group address as a custom result for async processing
        Ok(ActionResult::Custom {
            name: "igmp_leave_group".to_string(),
            data: json!({"group_address": addr.to_string()}),
        })
    }

    /// Execute send_membership_report sync action
    fn execute_send_membership_report(&self, action: serde_json::Value) -> Result<ActionResult> {
        let addr = Self::group_address(&action, "send_membership_report")?;

        // Build IGMPv2 Membership Report
        let packet = build_igmp_v2_report(addr)?;
        Ok(ActionResult::Output(packet))
    }

    /// Execute send_leave_group sync action
    fn execute_send_leave_group_message(&self, action: serde_json::Value) -> Result<ActionResult> {
        let addr = Self::group_address(&action, "send_leave_group")?;

        // Build IGMPv2 Leave Group message
        let packet = build_igmp_v2_leave(addr)?;
        Ok(ActionResult::Output(packet))
    }
}

/// Build an IGMPv2 Membership Report packet (RFC 2236 §2, type 0x16)
fn build_igmp_v2_report(group: Ipv4Addr) -> Result<Vec<u8>> {
    Ok(build_igmp_v2_message(0x16, group))
}

/// Build an IGMPv2 Leave Group packet (RFC 2236 §2, type 0x17)
fn build_igmp_v2_leave(group: Ipv4Addr) -> Result<Vec<u8>> {
    Ok(build_igmp_v2_message(0x17, group))
}

/// The RFC 2236 §2 message, which is the same eight octets for every type: one type byte, one
/// Max Response Time (unused and zero in everything but a Query), a two-byte checksum, and the
/// group. Written once so the checksum can never be computed over one layout and stamped into
/// another.
fn build_igmp_v2_message(msg_type: u8, group: Ipv4Addr) -> Vec<u8> {
    let g = group.octets();
    let mut packet = vec![msg_type, 0x00, 0x00, 0x00, g[0], g[1], g[2], g[3]];

    // Computed over the message with the checksum field zeroed, then written into it.
    let checksum = igmp_checksum(&packet);
    packet[2] = (checksum >> 8) as u8;
    packet[3] = (checksum & 0xFF) as u8;

    packet
}

/// The RFC 1071 Internet Checksum over an IGMP message.
///
/// Public because it is the one piece of IGMP the receive side and the send side must agree on:
/// `IgmpMessage::checksum_valid` folds a *received* message through this same function and
/// requires 0, which holds exactly when the checksum field equals the complement of everything
/// else. A second, separately written verifier would be a second chance to disagree.
pub fn igmp_checksum(data: &[u8]) -> u16 {
    // `data.len() - 1` below underflows for an empty slice, which would then index far out of
    // range and panic. Guard explicitly rather than relying on every caller.
    if data.is_empty() {
        return !0u16;
    }

    let mut sum: u32 = 0;
    let mut i = 0;

    // Sum 16-bit words
    while i < data.len() - 1 {
        sum += u32::from(u16::from_be_bytes([data[i], data[i + 1]]));
        i += 2;
    }

    // Add remaining byte if odd length
    if i < data.len() {
        sum += u32::from(data[i]) << 8;
    }

    // Fold 32-bit sum to 16 bits
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    // Return one's complement
    !sum as u16
}

// ============================================================================
// Action Definitions
// ============================================================================

fn join_group_action() -> ActionDefinition {
    ActionDefinition {
        name: "join_group".to_string(),
        description: "Join a multicast group (async action)".to_string(),
        parameters: vec![Parameter {
            name: "group_address".to_string(),
            type_hint: "string".to_string(),
            description: "IPv4 multicast group address (e.g., '239.255.255.250')".to_string(),
            required: true,
        }],
        example: json!({
            "type": "join_group",
            "group_address": "239.255.255.250"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> IGMP join {group_address}")
                .with_debug("IGMP join_group: group={group_address}"),
        ),
    }
}

fn leave_group_action() -> ActionDefinition {
    ActionDefinition {
        name: "leave_group".to_string(),
        description: "Leave a multicast group (async action)".to_string(),
        parameters: vec![Parameter {
            name: "group_address".to_string(),
            type_hint: "string".to_string(),
            description: "IPv4 multicast group address to leave".to_string(),
            required: true,
        }],
        example: json!({
            "type": "leave_group",
            "group_address": "239.255.255.250"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> IGMP leave {group_address}")
                .with_debug("IGMP leave_group: group={group_address}"),
        ),
    }
}

fn send_membership_report_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_membership_report".to_string(),
        description: "Send an IGMP Membership Report for a multicast group".to_string(),
        parameters: vec![Parameter {
            name: "group_address".to_string(),
            type_hint: "string".to_string(),
            description: "IPv4 multicast group address".to_string(),
            required: true,
        }],
        example: json!({
            "type": "send_membership_report",
            "group_address": "239.255.255.250"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> IGMP report {group_address}")
                .with_debug("IGMP send_membership_report: group={group_address}"),
        ),
    }
}

fn send_leave_group_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_leave_group".to_string(),
        description: "Send an IGMP Leave Group message".to_string(),
        parameters: vec![Parameter {
            name: "group_address".to_string(),
            type_hint: "string".to_string(),
            description: "IPv4 multicast group address to leave".to_string(),
            required: true,
        }],
        example: json!({
            "type": "send_leave_group",
            "group_address": "239.255.255.250"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> IGMP leave msg {group_address}")
                .with_debug("IGMP send_leave_group: group={group_address}"),
        ),
    }
}

fn ignore_message_action() -> ActionDefinition {
    ActionDefinition {
        name: "ignore_message".to_string(),
        description: "Ignore this IGMP message and don't send a response".to_string(),
        parameters: vec![],
        example: json!({
            "type": "ignore_message"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> IGMP ignore")
                .with_debug("IGMP ignore_message"),
        ),
    }
}

// ============================================================================
// IGMP Event Type Constants
// ============================================================================

pub static IGMP_QUERY_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "igmp_query_received",
        "IGMP Membership Query received",
        json!({
            "type": "send_membership_report",
            "group_address": "239.255.255.250"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "query_type".to_string(),
            type_hint: "string".to_string(),
            description: "Type of query (General or Group-Specific)".to_string(),
            required: true,
        },
        Parameter {
            name: "group_address".to_string(),
            type_hint: "string".to_string(),
            description: "Multicast group address (0.0.0.0 for general query)".to_string(),
            required: true,
        },
        Parameter {
            name: "max_response_time".to_string(),
            type_hint: "number".to_string(),
            description: "Maximum response time in deciseconds".to_string(),
            required: false,
        },
    ])
    .with_actions(vec![
        send_membership_report_action(),
        ignore_message_action(),
    ])
});

pub static IGMP_REPORT_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "igmp_report_received",
        "IGMP Membership Report received from another host",
        json!({
            "type": "ignore_message"
        }),
    )
    .with_parameters(vec![Parameter {
        name: "group_address".to_string(),
        type_hint: "string".to_string(),
        description: "Multicast group address being reported".to_string(),
        required: true,
    }])
    .with_actions(vec![ignore_message_action()])
});

pub static IGMP_LEAVE_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "igmp_leave_received",
        "IGMP Leave Group message received",
        json!({
            "type": "ignore_message"
        }),
    )
    .with_parameters(vec![Parameter {
        name: "group_address".to_string(),
        type_hint: "string".to_string(),
        description: "Multicast group address being left".to_string(),
        required: true,
    }])
    .with_actions(vec![ignore_message_action()])
});

pub fn get_igmp_event_types() -> Vec<EventType> {
    vec![
        IGMP_QUERY_RECEIVED_EVENT.clone(),
        IGMP_REPORT_RECEIVED_EVENT.clone(),
        IGMP_LEAVE_RECEIVED_EVENT.clone(),
    ]
}
