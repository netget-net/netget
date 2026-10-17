//! CDP protocol actions, events and metadata.
//!
//! The executor here is deliberately thin: it validates the model's answer through the pure
//! codec ([`super::codec::CdpAdvertisement::from_action`]) and hands the *structured* action
//! back as an [`ActionResult::Custom`]. The frame is built and put on the wire in
//! [`super`], which is the only place that knows the source MAC and which transport is in use.
//! That split is what lets `execute_action` be called on the stateless registry instance — the
//! shape `tests/executable_examples_test.rs` exercises for every advertised example.

use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter, ParameterDefinition,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::EventType;
use crate::state::app_state::AppState;
use anyhow::{Context, Result};
use serde_json::json;
use std::sync::LazyLock;

use super::codec::CdpAdvertisement;

/// The `ActionResult::Custom` name every CDP action returns under.
pub const CDP_ACTION_RESULT: &str = "cdp_action";

#[cfg(target_os = "macos")]
const DEFAULT_LOOPBACK_INTERFACE: &str = "lo0";
#[cfg(not(target_os = "macos"))]
const DEFAULT_LOOPBACK_INTERFACE: &str = "lo";

/// Which transport the server should use. Read in `super::CdpServer::spawn_with_llm_actions`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CdpTransport {
    /// Real 802.3 frames, captured and injected with libpcap. Needs packet-capture privilege.
    Raw,
    /// Each UDP datagram is one complete 802.3 CDP frame. Needs no privilege at all, and exists
    /// so the event -> LLM -> action -> frame path can be tested end to end.
    Udp,
}

impl CdpTransport {
    pub fn parse(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "raw" | "ethernet" | "pcap" => Ok(CdpTransport::Raw),
            "udp" | "test" => Ok(CdpTransport::Udp),
            other => Err(anyhow::anyhow!(
                "unknown CDP transport '{}': expected \"raw\" (real 802.3 frames via libpcap) \
                 or \"udp\" (one complete frame per datagram, for unprivileged testing)",
                other
            )),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            CdpTransport::Raw => "raw",
            CdpTransport::Udp => "udp",
        }
    }
}

pub struct CdpProtocol;

impl Default for CdpProtocol {
    fn default() -> Self {
        Self::new()
    }
}

impl CdpProtocol {
    pub fn new() -> Self {
        Self
    }
}

// =================================================================================================
// Actions
// =================================================================================================

fn send_cdp_advertisement_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_cdp_advertisement".to_string(),
        description:
            "Emit one CDP advertisement onto the link. This is an ASSERTION that a device with \
             this identity exists here: the neighbour writes every field into its CDP table and \
             an operator reads them back from `show cdp neighbors detail`. Every field is a \
             plain value - never bytes, never hex."
                .to_string(),
        parameters: vec![
            Parameter {
                name: "device_id".to_string(),
                type_hint: "string".to_string(),
                description:
                    "Device ID: the hostname the neighbour will key its CDP table on (e.g. \
                     \"SW-CORE-01\"). Required - an advertisement without one is not usable."
                        .to_string(),
                required: true,
            },
            Parameter {
                name: "port_id".to_string(),
                type_hint: "string".to_string(),
                description:
                    "Port ID: the interface name this advertisement is leaving by, in the \
                     device's own naming (e.g. \"GigabitEthernet0/1\")."
                        .to_string(),
                required: false,
            },
            Parameter {
                name: "platform".to_string(),
                type_hint: "string".to_string(),
                description: "Hardware platform string (e.g. \"cisco WS-C2960-24TT-L\")."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "software_version".to_string(),
                type_hint: "string".to_string(),
                description:
                    "Software version banner, exactly as the device would print it (e.g. a \
                     multi-line \"Cisco IOS Software, C2960 Software ... Version 15.0(2)SE11\")."
                        .to_string(),
                required: false,
            },
            Parameter {
                name: "capabilities".to_string(),
                type_hint: "array".to_string(),
                description: "Device capabilities as names: any of router, transparent_bridge, \
                     source_route_bridge, switch, host, igmp, repeater, voip_phone. A numeric \
                     bitmask is also accepted. An unknown name is rejected rather than ignored."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "native_vlan".to_string(),
                type_hint: "number".to_string(),
                description:
                    "Native VLAN of this port (0-4094). This is the field CDP is best known for \
                     leaking."
                        .to_string(),
                required: false,
            },
            Parameter {
                name: "duplex".to_string(),
                type_hint: "string".to_string(),
                description: "\"full\" or \"half\".".to_string(),
                required: false,
            },
            Parameter {
                name: "addresses".to_string(),
                type_hint: "array".to_string(),
                description:
                    "Interface addresses as plain IPv4/IPv6 strings, e.g. [\"192.168.1.1\"]."
                        .to_string(),
                required: false,
            },
            Parameter {
                name: "management_addresses".to_string(),
                type_hint: "array".to_string(),
                description: "Management addresses as plain IPv4/IPv6 strings. Often the same as \
                     'addresses' on a small switch."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "ttl".to_string(),
                type_hint: "number".to_string(),
                description:
                    "Hold time in seconds the neighbour should keep this entry (0-255, default \
                     180). A TTL of 0 withdraws the entry."
                        .to_string(),
                required: false,
            },
            Parameter {
                name: "version".to_string(),
                type_hint: "number".to_string(),
                description: "CDP version, 1 or 2 (default 2).".to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "send_cdp_advertisement",
            "device_id": "SW-CORE-01",
            "port_id": "GigabitEthernet0/1",
            "platform": "cisco WS-C2960-24TT-L",
            "software_version": "Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M), Version 15.0(2)SE11",
            "capabilities": ["switch", "igmp"],
            "native_vlan": 1,
            "duplex": "full",
            "addresses": ["192.168.1.1"],
            "management_addresses": ["192.168.1.1"],
            "ttl": 180,
            "version": 2
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> CDP advertisement device={device_id} port={port_id}")
                .with_debug(
                    "CDP send_cdp_advertisement: device={device_id} port={port_id} \
                     platform={platform} native_vlan={native_vlan} ttl={ttl}",
                ),
        ),
    }
}

fn no_advertisement_action() -> ActionDefinition {
    ActionDefinition {
        name: "no_advertisement".to_string(),
        description:
            "Say nothing. CDP has no negative or error message - every frame it defines asserts \
             that a device exists - so declining to advertise is the only way to refuse. Use \
             this when the neighbour should not learn anything about us. It is recorded in the \
             log as decision=model_reject, distinct from a backend failure."
                .to_string(),
        parameters: vec![Parameter {
            name: "reason".to_string(),
            type_hint: "string".to_string(),
            description: "Why nothing is being advertised. Logged; never put on the wire."
                .to_string(),
            required: false,
        }],
        example: json!({
            "type": "no_advertisement",
            "reason": "Unrecognised neighbour on an access port; do not disclose the switch identity"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> CDP silent (no advertisement)")
                .with_debug("CDP no_advertisement: reason={reason}"),
        ),
    }
}

/// The action set every CDP event accepts.
///
/// `call_llm` builds the model's tool list from `EventType::actions`, not from
/// `get_sync_actions()`, so this must be attached to each event with `.with_actions(...)` or
/// the model is offered nothing (root `CLAUDE.md`, and
/// `tests/event_action_declarations_test.rs` fails the build on it).
fn cdp_response_actions() -> Vec<ActionDefinition> {
    vec![send_cdp_advertisement_action(), no_advertisement_action()]
}

// =================================================================================================
// Events
// =================================================================================================

pub static CDP_NEIGHBOR_ADVERTISEMENT_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "cdp_neighbor_advertisement",
        "A CDP advertisement arrived on this link: a neighbouring device has just told us its \
         hostname, model, software version, port and native VLAN. Answer with \
         send_cdp_advertisement to introduce ourselves back - whatever identity you give is what \
         that neighbour will record and what its operator will see in `show cdp neighbors \
         detail`. Answer with no_advertisement to stay invisible. Describing an advertisement is \
         not sending one: only the action puts a frame on the link.",
        json!({
            "type": "send_cdp_advertisement",
            "device_id": "SW-CORE-01",
            "port_id": "GigabitEthernet0/1",
            "platform": "cisco WS-C2960-24TT-L",
            "software_version": "Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M), Version 15.0(2)SE11",
            "capabilities": ["switch", "igmp"],
            "native_vlan": 1,
            "duplex": "full",
            "addresses": ["192.168.1.1"],
            "ttl": 180
        }),
    )
    .with_actions(cdp_response_actions())
    .with_log_template(
        LogTemplate::new()
            .with_info("CDP advertisement from {device_id} ({platform}) on {port_id}")
            .with_debug(
                "CDP neighbor: device={device_id} port={port_id} platform={platform} \
                 native_vlan={native_vlan} ttl={ttl} src={source_mac}",
            )
            .with_trace("CDP neighbor advertisement: {json_pretty(.)}"),
    )
});

// =================================================================================================
// Protocol
// =================================================================================================

impl Protocol for CdpProtocol {
    fn default_binding(&self) -> Option<crate::protocol::BindingDefaults> {
        // CDP needs an interface for its real transport and a host/port for the UDP test
        // transport, so all four fields are supplied. A caller that names neither gets loopback
        // and an OS-assigned port, which is inert for the raw transport (loopback carries no
        // CDP) and correct for the UDP one.
        Some(crate::protocol::BindingDefaults {
            mac_address: None,
            interface: Some(DEFAULT_LOOPBACK_INTERFACE.to_string()),
            host: Some("127.0.0.1".to_string()),
            port: Some(0),
        })
    }

    /// Deliberately empty.
    ///
    /// CDP is one-way and unsolicited: there is nothing a user can ask a CDP *server* to do
    /// out-of-band that is not "advertise", and advertising is what the sync action already
    /// does in response to a neighbour. Declaring an async duplicate would advertise a verb
    /// with no executor state behind it.
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![]
    }

    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        cdp_response_actions()
    }

    fn protocol_name(&self) -> &'static str {
        "CDP"
    }

    fn get_event_types(&self) -> Vec<EventType> {
        vec![CDP_NEIGHBOR_ADVERTISEMENT_EVENT.clone()]
    }

    fn stack_name(&self) -> &'static str {
        "ETH(802.3)>LLC/SNAP>CDP"
    }

    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "cdp",
            "cisco discovery protocol",
            "cisco discovery",
            "neighbor discovery",
        ]
    }

    fn startup_privilege_requirement(
        &self,

        startup_params: Option<&serde_json::Value>,
    ) -> crate::protocol::metadata::PrivilegeRequirement {
        // The UDP test transport carries the same frames over an ordinary socket.

        crate::llm::actions::protocol_trait::unless_udp_transport(
            self.metadata().privilege_requirement,
            startup_params,
        )
    }

    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{
            DevelopmentState, PrivilegeRequirement, ProtocolMetadataV2,
        };

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            // libpcap, not SOCK_RAW: CDP is captured and injected at the link layer, exactly
            // like arp, datalink and isis, all three of which declare PacketCapture. Declaring
            // RawSockets would claim more than the protocol needs and refuse to start on a
            // machine with /dev/bpf* access but no root - the mistake root CLAUDE.md records
            // for ospf declaring Root when it wanted CAP_NET_RAW.
            .privilege_requirement(PrivilegeRequirement::PacketCapture)
            // Every advertisement is unsolicited and per-neighbour; nothing closes a "session",
            // so the 10-second idle sweep is the right owner of these entries.
            .connectionless()
            // Deliberately silent: CDP has no error message. Every CDP frame is an advertisement
            // asserting a device's identity, addresses and capabilities to every neighbour on the
            // segment, so a fabricated one is a false statement they all record.
            .deliberately_silent()
            .implementation(
                "Manual CDP v1/v2 over 802.3 with LLC/SNAP encapsulation (DSAP/SSAP 0xAA, \
                 control 0x03, OUI 00:00:0c, protocol 0x2000), destination 01:00:0c:cc:cc:cc. \
                 The frame codec is a pure module (src/server/cdp/codec.rs) with no I/O: TLV \
                 encode/decode for Device ID, Addresses, Port ID, Capabilities, Software \
                 Version, Platform, Native VLAN, Duplex and Management Address, plus the CDP \
                 checksum including Cisco's non-standard odd-length padding. Two transports sit \
                 over it: 'raw' (libpcap capture + injection on a named interface) and 'udp' \
                 (one complete 802.3 frame per datagram), selected by the 'transport' startup \
                 parameter.",
            )
            .llm_control(
                "The model authors the whole identity NetGet projects onto the link - hostname, \
                 hardware platform, IOS version string, port name, capabilities, native VLAN, \
                 duplex and addresses - as structured fields, never bytes. Whether to engage at \
                 all is policy: with no operator instruction and no event handler the server \
                 observes passively and makes no LLM call per captured advertisement. \
                 no_advertisement is the model's explicit refusal and is logged distinctly from \
                 silence and from a backend failure.",
            )
            .e2e_testing(
                "The codec is tested against literal specification bytes and against real \
                 captured CDP packets taken from scapy's regression vectors (a Catalyst 2950 \
                 and a Cisco 7960 phone): the checksum implementation reproduces the checksum \
                 those captures carry, and decoding them yields the device id, port id, \
                 platform, software version, capabilities, native VLAN, duplex and addresses \
                 the capture's own independent decoder reports. The event -> LLM -> action -> \
                 frame path is tested end to end over the UDP transport, including that an LLM \
                 failure emits no frame at all. The raw libpcap transport is NOT exercised by \
                 any test.",
            )
            .notes(
                "Experimental, and the split matters. PROVEN: the frame codec - TLV layout, the \
                 802.3 + LLC/SNAP header, and the checksum (including Cisco's odd-length \
                 padding quirk, which is where most CDP implementations go wrong) - against \
                 literal spec bytes and against two real captures decoded by an independent \
                 implementation. Also proven: the full event/LLM/action/frame path over the UDP \
                 test transport. NOT PROVEN: the raw 802.3 transport has never been executed. \
                 It needs packet-capture privilege, no test runs with it, and no real Cisco \
                 device or third-party CDP peer has ever seen a frame from this server. Do not \
                 read Experimental as 'works on a real switch'. CDP is in the \
                 deliberately-silent class: on an LLM failure the server emits nothing, because \
                 every CDP frame is a positive assertion that a device with a given identity \
                 exists on this link and a neighbour caches it - a fabricated one poisons that \
                 cache and there is no CDP error frame to send instead. The distinction lives in \
                 the log only, tagged decision=model_reject / model_silent / \
                 fail_closed_llm_error, and no LLM error text ever reaches the wire.",
            )
            .max_inbound_bytes(crate::server::cdp::codec::MAX_8023_LENGTH)
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }

    fn description(&self) -> &'static str {
        "Cisco Discovery Protocol (CDP) server - impersonate a Cisco device to its neighbours"
    }

    fn example_prompt(&self) -> &'static str {
        "Start a CDP server on en0 announcing itself as a Catalyst 2960 named SW-CORE-01 on \
         GigabitEthernet0/1 with native VLAN 42"
    }

    fn group_name(&self) -> &'static str {
        "Network Discovery"
    }

    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        // Both are read in `super::CdpServer::spawn_with_llm_actions`.
        vec![
            ParameterDefinition {
                name: "transport".to_string(),
                type_hint: "string".to_string(),
                description:
                    "\"raw\" (default) captures and injects real 802.3 CDP frames on the bound \
                     interface with libpcap. \"udp\" binds a UDP socket on the bound host/port \
                     and treats each datagram as one complete 802.3 CDP frame, replying to the \
                     datagram's sender; it needs no privilege and exists so the whole \
                     event/LLM/action/frame path can be exercised without root."
                        .to_string(),
                required: false,
                example: json!("raw"),
                default: None,
            },
            ParameterDefinition {
                name: "source_mac".to_string(),
                type_hint: "string".to_string(),
                description:
                    "Source MAC for advertisements we emit, e.g. \"00:1a:2b:3c:4d:5e\". On the \
                     raw transport this overrides the bound interface's own MAC; on the udp \
                     transport there is no interface, so it is the only way to choose one. \
                     Defaults to the interface MAC (raw) or the locally-administered address \
                     02:00:0c:cc:cc:01 (udp)."
                        .to_string(),
                required: false,
                example: json!("00:1a:2b:3c:4d:5e"),
                default: None,
            },
        ]
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;

        StartupExamples::new(
            // LLM mode: the model invents the whole device identity per neighbour.
            json!({
                "type": "open_server",
                "base_stack": "CDP",
                "interface": "en0",
                "instruction": "You are a Cisco Catalyst 2960 named SW-CORE-01. When a neighbour advertises itself, answer with our own advertisement on GigabitEthernet0/1, native VLAN 42, capabilities switch and igmp."
            }),
            // Script mode: mirror the neighbour's native VLAN back at it.
            json!({
                "type": "open_server",
                "base_stack": "CDP",
                "interface": "en0",
                "event_handlers": [{
                    "event_pattern": "cdp_neighbor_advertisement",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "return {'type': 'send_cdp_advertisement', 'device_id': 'SW-CORE-01', 'port_id': 'GigabitEthernet0/1', 'platform': 'cisco WS-C2960-24TT-L', 'capabilities': ['switch'], 'native_vlan': event.get('native_vlan', 1), 'duplex': 'full'}"
                    }
                }]
            }),
            // Static mode: one fixed identity, no LLM call at all.
            json!({
                "type": "open_server",
                "base_stack": "CDP",
                "interface": "en0",
                "event_handlers": [{
                    "event_pattern": "cdp_neighbor_advertisement",
                    "handler": {
                        "type": "static",
                        "actions": [{
                            "type": "send_cdp_advertisement",
                            "device_id": "SW-CORE-01",
                            "port_id": "GigabitEthernet0/1",
                            "platform": "cisco WS-C2960-24TT-L",
                            "capabilities": ["switch", "igmp"],
                            "native_vlan": 1,
                            "duplex": "full",
                            "ttl": 180
                        }]
                    }
                }]
            }),
        )
    }
}

// =================================================================================================
// Server
// =================================================================================================

impl Server for CdpProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move { super::CdpServer::spawn_with_llm_actions(ctx).await })
    }

    fn execute_action(&self, action: serde_json::Value) -> Result<ActionResult> {
        let action_type = action
            .get("type")
            .and_then(|v| v.as_str())
            .context("Missing action type")?;

        match action_type {
            "send_cdp_advertisement" => {
                // Validate here, on the pure codec, so a malformed answer is rejected with a
                // message naming the field rather than producing a frame nobody can parse.
                // The transport re-builds from the same JSON; this is the gate, not the build.
                CdpAdvertisement::from_action(&action)
                    .context("send_cdp_advertisement rejected")?;
                Ok(ActionResult::Custom {
                    name: CDP_ACTION_RESULT.to_string(),
                    data: action,
                })
            }
            "no_advertisement" => Ok(ActionResult::Custom {
                name: CDP_ACTION_RESULT.to_string(),
                data: action,
            }),
            _ => Err(anyhow::anyhow!("Unknown CDP action type: {}", action_type)),
        }
    }
}
