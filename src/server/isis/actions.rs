//! IS-IS protocol actions implementation

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
/// BSD-derived systems (macOS included) call it `lo0`; Linux calls it `lo`. IS-IS used
/// to hardcode `"lo"`, so on macOS its declared default named a device that does not
/// exist and a start with no explicit `interface` could only ever fail with
/// `no such capture device 'lo'` — a worse diagnosis than the truth, and one that would
/// mislead anyone who did have capture rights. ARP, DataLink and ICMP each carry this
/// same constant; IS-IS was missed, exactly as it was missed for the
/// startup-reports-failure fix (see this protocol's CLAUDE.md).
///
/// Loopback remains a poor place to actually run IS-IS — nothing speaks it there — but a
/// default that cannot resolve is not a useful way to say so.
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

pub struct IsisProtocol;

impl IsisProtocol {
    pub fn new() -> Self {
        Self
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for IsisProtocol {
    fn default_binding(&self) -> Option<crate::protocol::BindingDefaults> {
        // IS-IS uses interface-based binding (loopback by default)
        Some(crate::protocol::BindingDefaults::interface_based(
            DEFAULT_LOOPBACK_INTERFACE,
        ))
    }

    fn get_startup_parameters(&self) -> Vec<crate::llm::actions::ParameterDefinition> {
        // Interface is now provided via flexible binding system
        vec![
                crate::llm::actions::ParameterDefinition {
                    name: "system_id".to_string(),
                    type_hint: "string".to_string(),
                    description: "IS-IS System ID in format: 0000.0000.0001 (6 bytes in dotted hex notation)".to_string(),
                    required: false,
                    example: json!("0000.0000.0001"),
                    default: None,
                },
                crate::llm::actions::ParameterDefinition {
                    name: "area_id".to_string(),
                    type_hint: "string".to_string(),
                    description: "IS-IS Area ID in format: 49.0001 (NSAP format, 49 for private networks)".to_string(),
                    required: false,
                    example: json!("49.0001"),
                    default: None,
                },
                crate::llm::actions::ParameterDefinition {
                    name: "level".to_string(),
                    type_hint: "string".to_string(),
                    description: "IS-IS level: 'level-1' (intra-area), 'level-2' (inter-area backbone), or 'level-1+2' (both)".to_string(),
                    required: false,
                    example: json!("level-2"),
                    default: None,
                },
            ]
    }
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        Vec::new()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            send_isis_hello_action(),
            send_isis_lsp_action(),
            send_isis_pdu_action(),
            ignore_pdu_action(),
        ]
    }
    fn protocol_name(&self) -> &'static str {
        "ISIS"
    }
    fn get_event_types(&self) -> Vec<EventType> {
        get_isis_event_types()
    }
    fn stack_name(&self) -> &'static str {
        // Layer 2 only: Ethernet 802.3 + LLC (DSAP/SSAP 0xFE), never IP or UDP. The old
        // "ETH>IP>UDP>ISIS" here was a leftover from a UDP-encapsulated draft that no longer
        // exists in this module, and it told the model IS-IS rides on a transport it does not.
        "ETH>LLC>ISIS"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["isis", "is-is"]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{
            DevelopmentState, PrivilegeRequirement, ProtocolMetadataV2,
        };

        ProtocolMetadataV2::builder()
            .connectionless()
            .state(DevelopmentState::Experimental)
            // Deliberately silent: An IS-IS PDU asserts adjacency and topology; a fabricated
            // one is injected into a real routing domain.
            .deliberately_silent()
            .privilege_requirement(PrivilegeRequirement::PacketCapture)
            .implementation("Layer 2 IS-IS with pcap (ISO/IEC 10589, RFC 1195)")
            .llm_control("Optional: whether to engage with an IS-IS speaker (answer a Hello, form an adjacency, act as a honeypot) is a policy decision. With no operator policy (no instruction, no handler) the server observes passively and does NOT respond, with no LLM round-trip per PDU. When the operator opts in, the LLM decides the Hello/LSP responses")
            .e2e_testing(
                "tests/capture_startup_reports_failure_test.rs asserts spawn() returns Err for an \
                 unknown device and for missing capture privilege. PDU handling itself is \
                 untested: tests/server/isis/e2e_test.rs is #[ignore]d for root.",
            )
            .notes(
                "Layer 2 over Ethernet+LLC (DSAP/SSAP 0xFE), not UDP. Startup failure is \
                 reported: spawn() awaits the pcap handle and the BPF filter and returns Err, \
                 so a privilege failure lands in ServerStatus::Error rather than Running. \
                 NEVER validated against a real router (FRR/Cisco) or any IS-IS speaker - the \
                 earlier 'interoperable with real routers' claim was unfounded. Whether to \
                 respond is policy, so with no operator policy the server is a passive listener \
                 (no response, no LLM call); this passive default is compile-verified since the \
                 pcap path needs root and the E2E suite is #[ignore]d. LSP/CSNP/PSNP are parsed \
                 and logged but not handled; there is no LSP database or SPF.",
            )
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn description(&self) -> &'static str {
        "IS-IS (Intermediate System to Intermediate System) Layer 2 routing protocol server"
    }
    fn example_prompt(&self) -> &'static str {
        "start an is-is router on interface eth0 with system-id 0000.0000.0001 in area 49.0001 at level-2"
    }
    fn group_name(&self) -> &'static str {
        "Experimental"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;

        // Deterministic: answer every IS-IS hello with our own hello, no LLM
        // call.
        let script = r#"import json, sys
data = json.load(sys.stdin)
event = data["event"]
if data["event_type_id"] == "isis_hello":
    actions = [{"type": "send_isis_hello",
                "system_id": "0000.0000.0001", "area_id": "49.0001"}]
else:
    actions = []
print(json.dumps({"actions": actions}))"#;

        StartupExamples::new(
            // LLM mode: LLM handles IS-IS adjacency formation
            json!({
                "type": "open_server",
                "port": 0,
                "base_stack": "isis",
                "instruction": "IS-IS router with system-id 0000.0000.0001 in area 49.0001. Respond to Hello PDUs and form adjacencies with neighbors."
            }),
            // Script mode: Scripted IS-IS Hello response
            json!({
                "type": "open_server",
                "port": 0,
                "base_stack": "isis",
                "event_handlers": [{
                    "event_pattern": "isis_hello",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": script
                    }
                }]
            }),
            // Static mode: Fixed IS-IS Hello response
            json!({
                "type": "open_server",
                "port": 0,
                "base_stack": "isis",
                "event_handlers": [{
                    "event_pattern": "isis_hello",
                    "handler": {
                        "type": "static",
                        "actions": [{
                            "type": "send_isis_hello",
                            "pdu_type": "lan_hello_l2",
                            "system_id": "0000.0000.0001",
                            "area_id": "49.0001",
                            "holding_time": 30
                        }]
                    }
                }]
            }),
        )
    }
}

// Implement Server trait (server-specific functionality)
impl Server for IsisProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::server::isis::IsisServer;

            // IS-IS uses interface-based binding
            // Extract interface from context (defaults already applied)
            let interface = ctx
                .interface()
                .context("IS-IS requires network interface")?
                .to_string();

            // Get listen addr before consuming ctx fields
            let listen_addr = ctx.legacy_listen_addr();

            // Spawn the IS-IS server
            let _interface_name = IsisServer::spawn_with_llm_actions(
                interface,
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.server_id,
                ctx.startup_params,
            )
            .await?;

            // IS-IS doesn't bind to a socket, so return a dummy address
            Ok(listen_addr)
        })
    }
    fn execute_action(&self, action: serde_json::Value) -> Result<ActionResult> {
        let action_type = action
            .get("type")
            .and_then(|v| v.as_str())
            .context("Missing 'type' field in action")?;

        match action_type {
            "send_isis_hello" => self.execute_send_isis_hello(action),
            "send_isis_lsp" => self.execute_send_isis_lsp(action),
            "send_isis_pdu" => self.execute_send_isis_pdu(action),
            "ignore_pdu" => Ok(ActionResult::NoAction),
            _ => Err(anyhow::anyhow!("Unknown IS-IS action: {}", action_type)),
        }
    }
}

impl IsisProtocol {
    /// Execute send_isis_hello action - Send IS-IS Hello PDU
    fn execute_send_isis_hello(&self, action: serde_json::Value) -> Result<ActionResult> {
        // Extract parameters
        let pdu_type_str = action
            .get("pdu_type")
            .and_then(|v| v.as_str())
            .unwrap_or("lan_hello_l2");

        let pdu_type = match pdu_type_str {
            "lan_hello_l1" => 15,
            "lan_hello_l2" => 16,
            "p2p_hello" => 17,
            _ => 16, // Default to L2 LAN Hello
        };

        let system_id = action
            .get("system_id")
            .and_then(|v| v.as_str())
            .unwrap_or("0000.0000.0001");

        let area_id = action
            .get("area_id")
            .and_then(|v| v.as_str())
            .unwrap_or("49.0001");

        let holding_time = action
            .get("holding_time")
            .and_then(|v| v.as_u64())
            .unwrap_or(30) as u16;

        // Build IS-IS Hello PDU
        let packet = Self::build_isis_hello(pdu_type, system_id, area_id, holding_time)?;

        Ok(ActionResult::Output(packet))
    }

    /// Execute send_isis_lsp action - Send IS-IS Link State PDU
    fn execute_send_isis_lsp(&self, action: serde_json::Value) -> Result<ActionResult> {
        let level = action
            .get("level")
            .and_then(|v| v.as_str())
            .unwrap_or("level-2");

        let pdu_type = match level {
            "level-1" => 18,
            "level-2" => 20,
            _ => 20,
        };

        let system_id = action
            .get("system_id")
            .and_then(|v| v.as_str())
            .unwrap_or("0000.0000.0001");

        // Build simplified LSP (full implementation would require route information)
        let packet = Self::build_isis_lsp(pdu_type, system_id)?;

        Ok(ActionResult::Output(packet))
    }

    /// Execute send_isis_pdu action - Send raw IS-IS PDU from hex
    fn execute_send_isis_pdu(&self, action: serde_json::Value) -> Result<ActionResult> {
        let data = action
            .get("data")
            .and_then(|v| v.as_str())
            .context("Missing 'data' parameter")?;

        let bytes = hex::decode(data).context("Invalid hex data")?;

        Ok(ActionResult::Output(bytes))
    }

    /// Build IS-IS Hello PDU
    pub fn build_isis_hello(
        pdu_type: u8,
        system_id: &str,
        area_id: &str,
        holding_time: u16,
    ) -> Result<Vec<u8>> {
        let mut packet = Vec::new();

        // Common header (8 bytes)
        packet.push(0x83); // Intradomain Routing Protocol Discriminator
        packet.push(27); // Length Indicator (will update later)
        packet.push(1); // Version/Protocol ID Extension
        packet.push(0); // ID Length (0 = 6 bytes)
        packet.push(pdu_type); // PDU Type
        packet.push(1); // Version
        packet.push(0); // Reserved
        packet.push(0); // Max Area Addresses

        // PDU-specific header for Hello (variable, simplified here)
        // Circuit Type (1 byte)
        let circuit_type = match pdu_type {
            15 => 1, // Level 1
            16 => 2, // Level 2
            17 => 3, // Level 1+2 (P2P)
            _ => 2,
        };
        packet.push(circuit_type);

        // Source ID (6 bytes) - parse system_id
        let sys_id_bytes = Self::parse_system_id(system_id)?;
        packet.extend_from_slice(&sys_id_bytes);

        // Holding Time (2 bytes)
        packet.extend_from_slice(&holding_time.to_be_bytes());

        // PDU Length (2 bytes) - will update later
        packet.extend_from_slice(&[0, 0]);

        // For LAN Hello: Priority (1 byte), LAN ID (7 bytes)
        if pdu_type == 15 || pdu_type == 16 {
            packet.push(64); // Priority (default 64)
            packet.extend_from_slice(&sys_id_bytes); // LAN ID = Source ID
            packet.push(0); // Pseudonode ID
        }

        // TLVs
        let tlvs = Self::build_hello_tlvs(area_id, system_id)?;
        packet.extend_from_slice(&tlvs);

        // Update Length Indicator (points to start of TLVs)
        let header_len = if pdu_type == 15 || pdu_type == 16 {
            27 // LAN Hello header length
        } else {
            20 // P2P Hello header length
        };
        packet[1] = header_len;

        // Update PDU Length.
        //
        // Offset 17 for every Hello type, and this used to be 15 (LAN) / 11 (P2P). Count the
        // fields this function actually pushes, per ISO/IEC 10589 §9.5-9.7:
        //
        //   0..8   common header
        //   8      circuit type
        //   9..15  source ID (6)
        //   15..17 holding time (2)
        //   17..19 PDU length (2)      <- here
        //   19     priority        (LAN only)
        //   20..27 LAN ID (7)      (LAN only)
        //
        // Writing at 15 overwrote the **holding time** with the PDU length and left the real
        // PDU-length field as the zeros pushed above — so every Hello this server emitted
        // carried a corrupt holding time and a length of 0. A receiver reads holding time as
        // the adjacency hold timer, so the value it got was whatever the packet happened to
        // be long.
        const PDU_LEN_OFFSET: usize = 17;
        let pdu_len = packet.len() as u16;
        packet[PDU_LEN_OFFSET..PDU_LEN_OFFSET + 2].copy_from_slice(&pdu_len.to_be_bytes());

        Ok(packet)
    }

    /// Build IS-IS LSP
    fn build_isis_lsp(pdu_type: u8, system_id: &str) -> Result<Vec<u8>> {
        let mut packet = Vec::new();

        // Common header
        packet.push(0x83); // Intradomain Routing Protocol Discriminator
        packet.push(27); // Length Indicator
        packet.push(1); // Version/Protocol ID Extension
        packet.push(0); // ID Length (0 = 6 bytes)
        packet.push(pdu_type); // PDU Type (18 for L1, 20 for L2)
        packet.push(1); // Version
        packet.push(0); // Reserved
        packet.push(0); // Max Area Addresses

        // LSP-specific header (simplified)
        packet.extend_from_slice(&[0, 0]); // PDU Length (will update)
        packet.extend_from_slice(&[0, 0]); // Remaining Lifetime

        // LSP ID (8 bytes: 6 bytes system ID + 1 byte pseudonode + 1 byte fragment)
        let sys_id_bytes = Self::parse_system_id(system_id)?;
        packet.extend_from_slice(&sys_id_bytes);
        packet.push(0); // Pseudonode ID
        packet.push(0); // LSP Fragment Number

        packet.extend_from_slice(&[0, 0, 0, 0]); // Sequence Number
        packet.extend_from_slice(&[0, 0]); // Checksum (should calculate, but simplified)
        packet.push(0); // Type Block (P/ATT/OL/IS Type)

        // Update PDU Length
        let pdu_len = packet.len() as u16;
        packet[8..10].copy_from_slice(&pdu_len.to_be_bytes());

        Ok(packet)
    }

    /// Build Hello TLVs
    fn build_hello_tlvs(area_id: &str, _system_id: &str) -> Result<Vec<u8>> {
        let mut tlvs = Vec::new();

        // TLV 1: Area Addresses
        tlvs.push(1); // Type
        let area_bytes = Self::parse_area_id(area_id)?;
        tlvs.push(area_bytes.len() as u8 + 1); // Length (area length + 1-byte length prefix)
        tlvs.push(area_bytes.len() as u8); // Area address length
        tlvs.extend_from_slice(&area_bytes);

        // TLV 129: Protocols Supported
        tlvs.push(129); // Type
        tlvs.push(1); // Length
        tlvs.push(0xCC); // IPv4 (0xCC = NLPID for IPv4)

        Ok(tlvs)
    }

    /// Parse system ID from dotted format (e.g., "0000.0000.0001") to 6 bytes
    fn parse_system_id(system_id: &str) -> Result<[u8; 6]> {
        let parts: Vec<&str> = system_id.split('.').collect();
        if parts.len() != 3 {
            return Err(anyhow::anyhow!("Invalid system ID format: {}", system_id));
        }

        let mut bytes = [0u8; 6];
        for (i, part) in parts.iter().enumerate() {
            let val = u16::from_str_radix(part, 16)
                .context(format!("Invalid hex in system ID: {}", part))?;
            bytes[i * 2] = (val >> 8) as u8;
            bytes[i * 2 + 1] = val as u8;
        }

        Ok(bytes)
    }

    /// Parse area ID from dotted format (e.g., "49.0001") to bytes
    fn parse_area_id(area_id: &str) -> Result<Vec<u8>> {
        let parts: Vec<&str> = area_id.split('.').collect();
        let mut bytes = Vec::new();

        for part in parts {
            // Each part can be 2 or 4 hex digits
            if part.len() == 2 {
                let val = u8::from_str_radix(part, 16)
                    .context(format!("Invalid hex in area ID: {}", part))?;
                bytes.push(val);
            } else if part.len() == 4 {
                let val = u16::from_str_radix(part, 16)
                    .context(format!("Invalid hex in area ID: {}", part))?;
                bytes.push((val >> 8) as u8);
                bytes.push(val as u8);
            } else {
                return Err(anyhow::anyhow!("Invalid area ID part length: {}", part));
            }
        }

        Ok(bytes)
    }
}

// Event Types
pub static ISIS_HELLO_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "isis_hello",
        "An IS-IS Hello PDU arrived from a neighbour. Answer with send_isis_hello to adjacency \
         with it, send_isis_lsp to advertise link state, send_isis_pdu for any other PDU type, \
         or ignore_pdu to stay silent.",
        json!({
            "type": "send_isis_hello",
            "pdu_type": "lan_hello_l2",
            "system_id": "0000.0000.0001",
            "area_id": "49.0001"
        }),
    )
    // All four sync actions answer this event, which is the protocol's only one. `call_llm`
    // advertises the event's action list rather than get_sync_actions(), so leaving it empty
    // left the model unable to reply to a neighbour at all.
    .with_actions(vec![
        send_isis_hello_action(),
        send_isis_lsp_action(),
        send_isis_pdu_action(),
        ignore_pdu_action(),
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("IS-IS {pdu_type} from {peer_addr}")
            .with_debug("IS-IS Hello: type={pdu_type} peer={peer_addr} areas={area_addresses}")
            .with_trace("IS-IS Hello: {json_pretty(.)}"),
    )
});

fn get_isis_event_types() -> Vec<EventType> {
    vec![ISIS_HELLO_EVENT.clone()]
}

// Action Definitions
fn send_isis_hello_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_isis_hello".to_string(),
        description: "Send IS-IS Hello PDU for neighbor discovery".to_string(),
        parameters: vec![
            Parameter {
                name: "pdu_type".to_string(),
                type_hint: "string".to_string(),
                description: "Hello PDU type: lan_hello_l1, lan_hello_l2, or p2p_hello".to_string(),
                required: false,
            },
            Parameter {
                name: "system_id".to_string(),
                type_hint: "string".to_string(),
                description: "Local system ID in format: 0000.0000.0001".to_string(),
                required: false,
            },
            Parameter {
                name: "area_id".to_string(),
                type_hint: "string".to_string(),
                description: "Area ID in format: 49.0001".to_string(),
                required: false,
            },
            Parameter {
                name: "holding_time".to_string(),
                type_hint: "number".to_string(),
                description: "Holding time in seconds (default: 30)".to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "send_isis_hello",
            "pdu_type": "lan_hello_l2",
            "system_id": "0000.0000.0001",
            "area_id": "49.0001"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> IS-IS {pdu_type} Hello sys={system_id}")
                .with_debug(
                    "IS-IS send_isis_hello: type={pdu_type} sys_id={system_id} area={area_id}",
                ),
        ),
    }
}

fn send_isis_lsp_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_isis_lsp".to_string(),
        description: "Send IS-IS Link State PDU".to_string(),
        parameters: vec![
            Parameter {
                name: "level".to_string(),
                type_hint: "string".to_string(),
                description: "IS-IS level: level-1 or level-2".to_string(),
                required: false,
            },
            Parameter {
                name: "system_id".to_string(),
                type_hint: "string".to_string(),
                description: "Local system ID".to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "send_isis_lsp",
            "level": "level-2",
            "system_id": "0000.0000.0001"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> IS-IS LSP {level} sys={system_id}")
                .with_debug("IS-IS send_isis_lsp: level={level} sys_id={system_id}"),
        ),
    }
}

fn send_isis_pdu_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_isis_pdu".to_string(),
        description: "Send raw IS-IS PDU from hex data".to_string(),
        parameters: vec![Parameter {
            name: "data".to_string(),
            type_hint: "string".to_string(),
            description: "Hex-encoded IS-IS PDU".to_string(),
            required: true,
        }],
        // A complete ISO/IEC 10589 LAN Level-2 Hello: common header (0x83, header
        // length 27, version/ext 1, ID length 0, PDU type 16, version 1, reserved,
        // max area addresses 0), circuit type 2 (L2 only), source ID
        // 0000.0000.0001, holding time 30s, PDU length 36, priority 64, LAN ID
        // 0000.0000.0001-00, then TLV 1 (area 49.0001) and TLV 129 (NLPID 0xCC,
        // IPv4). The previous value ended in an ellipsis and did not decode.
        example: json!({
            "type": "send_isis_pdu",
            "data": "831b01001001000002000000000001001e00244000000000000100\
                     0104034900018101cc"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> IS-IS raw PDU ({data_len}B)")
                .with_debug("IS-IS send_isis_pdu: len={data_len}"),
        ),
    }
}

fn ignore_pdu_action() -> ActionDefinition {
    ActionDefinition {
        name: "ignore_pdu".to_string(),
        description: "Ignore the IS-IS PDU (no response)".to_string(),
        parameters: vec![],
        example: json!({
            "type": "ignore_pdu"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> IS-IS ignore PDU")
                .with_debug("IS-IS ignore_pdu"),
        ),
    }
}
