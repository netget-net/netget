//! DataLink protocol actions implementation

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

/// Name of the loopback interface on this platform.
///
/// Linux and Windows call it `lo`; macOS and the BSDs call it `lo0`. Hardcoding `lo` made the
/// default binding unresolvable on macOS ("Device 'lo' not found").
#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
))]
const DEFAULT_LOOPBACK_INTERFACE: &str = "lo0";
#[cfg(not(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
)))]
const DEFAULT_LOOPBACK_INTERFACE: &str = "lo";

/// DataLink protocol action handler
pub struct DataLinkProtocol;

impl DataLinkProtocol {
    pub fn new() -> Self {
        Self
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for DataLinkProtocol {
    fn default_binding(&self) -> Option<crate::protocol::BindingDefaults> {
        // DataLink uses interface-based binding (loopback by default)
        Some(crate::protocol::BindingDefaults::interface_based(
            DEFAULT_LOOPBACK_INTERFACE,
        ))
    }

    fn get_startup_parameters(&self) -> Vec<crate::llm::actions::ParameterDefinition> {
        // Interface is now provided via flexible binding system
        vec![
                crate::llm::actions::ParameterDefinition {
                    name: "filter".to_string(),
                    type_hint: "string".to_string(),
                    description: "Optional BPF (Berkeley Packet Filter) expression to filter captured packets (e.g., 'arp', 'tcp port 80')".to_string(),
                    required: false,
                    example: json!("arp"),
                    default: None,
                },
            ]
    }
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![show_message_action(), ignore_packet_action()]
    }
    fn protocol_name(&self) -> &'static str {
        "DataLink"
    }
    fn get_event_types(&self) -> Vec<EventType> {
        get_datalink_event_types()
    }
    fn stack_name(&self) -> &'static str {
        "ETH"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "datalink",
            "data link",
            "layer 2",
            "layer2",
            "l2",
            "ethernet",
            "pcap",
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{
            DevelopmentState, PrivilegeRequirement, ProtocolMetadataV2,
        };

        ProtocolMetadataV2::builder()
            // Demoted from Beta in August 2026 and still Experimental. The capture path is no
            // longer unproven — `datalink_captures_a_real_loopback_frame` was run on
            // 2026-09-08 and passed — but the test that proves it is `#[ignore]`d behind BPF
            // access, and this repo does not count an ignored test as evidence for a rating.
            // See notes.
            .state(DevelopmentState::Experimental)
            // Deliberately silent: A raw link-layer frame asserts whatever it contains; there
            // is no error frame to send instead.
            .deliberately_silent()
            .privilege_requirement(PrivilegeRequirement::PacketCapture)
            // Layer 2 capture has no sessions: each frame stands alone and this server
            // registers no connections at all. Declaring it keeps DataLink out of nothing it
            // needs, and puts it with its siblings (`arp`, `icmp`, `isis` all declare it).
            .connectionless()
            .implementation("libpcap (pcap crate) for Layer 2 packet capture")
            .llm_control("Observation only - no packet injection")
            .e2e_testing(
                "tests/server/datalink/e2e_test.rs drives DataLinkServer::spawn_with_llm in \
                 process. Unprivileged, it asserts an unknown device and a missing capture \
                 privilege both produce Err with the documented text, and that the event the \
                 model receives carries a real frame's fields (truncation, lengths). The \
                 real-capture test (a UDP datagram on loopback, asserted byte-for-byte in the \
                 captured hex) and the invalid-BPF-filter test are #[ignore]d because they \
                 need /dev/bpf* (macOS/BSD) or CAP_NET_RAW (Linux); both were run under \
                 --ignored on 2026-09-08 (macOS, access_bpf group) and passed.",
            )
            .notes(
                "Requires root/CAP_NET_RAW (or /dev/bpf* access) for promiscuous mode. \
                 Startup failure is reported: spawn_with_llm awaits the pcap handle and the \
                 BPF filter, so a privilege failure lands in ServerStatus::Error rather than \
                 Running. Capture has been observed end to end (a loopback UDP datagram \
                 reaching the event path byte-for-byte, 2026-09-08), but only through an \
                 #[ignore]d test, which is why this stays Experimental. Capture-only: there is \
                 no packet-injection action, so the model can analyse frames but cannot answer \
                 them, and on an LLM failure nothing is written anywhere - the outcome is in \
                 the log as decision=model_analysed / model_ignore / model_silent / \
                 fail_closed_llm_error. Frames arriving while 32 are already awaiting the \
                 model are dropped with a counted WARN rather than queued, and packet_hex is \
                 the first 2048 bytes of the frame (packet_length is the true length).",
            )
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn description(&self) -> &'static str {
        "Layer 2 Ethernet frame server"
    }
    fn example_prompt(&self) -> &'static str {
        "Listen on eth0 via Ethernet"
    }
    fn group_name(&self) -> &'static str {
        "Core"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;

        // Deterministic: log a note for every captured frame, no LLM call.
        let script = r#"import json, sys
data = json.load(sys.stdin)
event = data["event"]
if data["event_type_id"] == "datalink_packet_captured":
    actions = [{"type": "show_message", "message": "packet captured"}]
else:
    actions = []
print(json.dumps({"actions": actions}))"#;

        StartupExamples::new(
            json!({
                "type": "open_server",
                "interface": "eth0",
                "base_stack": "datalink",
                "instruction": "Capture and analyze Layer 2 Ethernet frames"
            }),
            json!({
                "type": "open_server",
                "interface": "eth0",
                "base_stack": "datalink",
                "filter": "arp",
                "event_handlers": [{
                    "event_pattern": "datalink_packet_captured",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": script
                    }
                }]
            }),
            json!({
                "type": "open_server",
                "interface": "eth0",
                "base_stack": "datalink",
                "filter": "arp",
                "event_handlers": [{
                    "event_pattern": "datalink_packet_captured",
                    "handler": {
                        "type": "static",
                        "actions": [{
                            "type": "show_message",
                            "message": "Packet captured"
                        }]
                    }
                }]
            }),
        )
    }
}

// Implement Server trait (server-specific functionality)
impl Server for DataLinkProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::server::datalink::DataLinkServer;

            // DataLink uses interface-based binding
            // Extract interface from context (defaults already applied)
            let interface = ctx
                .interface()
                .context("DataLink requires network interface")?
                .to_string();

            // Extract filter from startup_params (protocol-specific config)
            let filter = ctx
                .startup_params
                .as_ref()
                .map(|p| p.get_optional_string("filter"))
                .transpose()?
                .flatten();

            // Get listen address before moving ctx fields
            let listen_addr = ctx.legacy_listen_addr();

            // Spawn the datalink server
            let _interface_name = DataLinkServer::spawn_with_llm(
                interface,
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                filter,
                ctx.server_id,
            )
            .await?;

            // DataLink doesn't bind to a socket, so return a dummy address
            // The listen_addr from context is just a placeholder
            Ok(listen_addr)
        })
    }
    fn execute_action(&self, action: serde_json::Value) -> Result<ActionResult> {
        let action_type = action
            .get("type")
            .and_then(|v| v.as_str())
            .context("Missing 'type' field in action")?;

        match action_type {
            "show_message" => {
                // Message actions are handled by the LLM's text response
                // This action just acknowledges the intent
                Ok(ActionResult::NoAction)
            }
            "ignore_packet" => Ok(ActionResult::NoAction),
            _ => Err(anyhow::anyhow!("Unknown DataLink action: {}", action_type)),
        }
    }
}

/// Action definition for show_message
fn show_message_action() -> ActionDefinition {
    ActionDefinition {
        name: "show_message".to_string(),
        description: "Show a message about the packet analysis".to_string(),
        parameters: vec![Parameter {
            name: "message".to_string(),
            type_hint: "string".to_string(),
            description: "Message to display".to_string(),
            required: true,
        }],
        example: json!({
            "type": "show_message",
            "message": "ARP request detected for 192.168.1.1"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> L2 {message}")
                .with_debug("DataLink show_message: {message}"),
        ),
    }
}

/// Action definition for ignore_packet
fn ignore_packet_action() -> ActionDefinition {
    ActionDefinition {
        name: "ignore_packet".to_string(),
        description: "Ignore this packet (no action taken)".to_string(),
        parameters: vec![],
        example: json!({
            "type": "ignore_packet"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> L2 ignored")
                .with_debug("DataLink ignore_packet"),
        ),
    }
}

// ============================================================================
// DataLink Event Type Constants
// ============================================================================

pub static DATALINK_PACKET_CAPTURED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "datalink_packet_captured",
        "Layer 2 Ethernet packet captured from network interface",
        json!({
            "type": "show_message",
            "message": "ARP request detected"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "packet_length".to_string(),
            type_hint: "number".to_string(),
            description: "Full length of the captured frame in bytes, before any truncation"
                .to_string(),
            required: true,
        },
        Parameter {
            name: "packet_hex".to_string(),
            type_hint: "string".to_string(),
            description: format!(
                "Hex of the frame's first {} bytes (dst MAC, src MAC, EtherType, payload). \
                 A frame longer than that is cut here - see `truncated` - because the whole \
                 of a {}-byte frame would be {} characters of prompt.",
                crate::server::datalink::MAX_HEX_BYTES_TO_MODEL,
                65535,
                65535 * 2
            ),
            required: false,
        },
        Parameter {
            name: "captured_length".to_string(),
            type_hint: "number".to_string(),
            description: "Number of bytes actually encoded in packet_hex".to_string(),
            required: true,
        },
        Parameter {
            name: "truncated".to_string(),
            type_hint: "boolean".to_string(),
            description: "True when packet_hex is a prefix of the frame rather than all of it"
                .to_string(),
            required: true,
        },
    ])
    .with_actions(vec![show_message_action(), ignore_packet_action()])
});

pub fn get_datalink_event_types() -> Vec<EventType> {
    vec![DATALINK_PACKET_CAPTURED_EVENT.clone()]
}
