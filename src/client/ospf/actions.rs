//! OSPF client protocol actions implementation

use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, Parameter,
};
use crate::protocol::EventType;
use crate::state::app_state::AppState;
use anyhow::{anyhow, Context, Result};
use serde_json::json;
use std::sync::LazyLock;

/// OSPF client connected event
pub static OSPF_CLIENT_CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "ospf_client_connected",
        "OSPF client successfully joined multicast group and ready to query routers",
        json!({
            "type": "wait_for_more"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "interface_ip".to_string(),
            type_hint: "string".to_string(),
            description: "Interface IP address".to_string(),
            required: true,
        },
        Parameter {
            name: "router_id".to_string(),
            type_hint: "string".to_string(),
            description: "Client's OSPF router ID".to_string(),
            required: true,
        },
    ])
});

/// OSPF Hello packet received event
pub static OSPF_CLIENT_HELLO_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "ospf_hello_received",
        "OSPF Hello packet received from router",
        json!({
            "type": "wait_for_more"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "neighbor_id".to_string(),
            type_hint: "string".to_string(),
            description: "Neighbor router ID".to_string(),
            required: true,
        },
        Parameter {
            name: "neighbor_ip".to_string(),
            type_hint: "string".to_string(),
            description: "Neighbor IP address".to_string(),
            required: true,
        },
        Parameter {
            name: "area_id".to_string(),
            type_hint: "string".to_string(),
            description: "OSPF area ID".to_string(),
            required: true,
        },
        Parameter {
            name: "network_mask".to_string(),
            type_hint: "string".to_string(),
            description: "Network mask".to_string(),
            required: true,
        },
        Parameter {
            name: "hello_interval".to_string(),
            type_hint: "number".to_string(),
            description: "Hello interval in seconds".to_string(),
            required: true,
        },
        Parameter {
            name: "router_dead_interval".to_string(),
            type_hint: "number".to_string(),
            description: "Router dead interval in seconds".to_string(),
            required: true,
        },
        Parameter {
            name: "router_priority".to_string(),
            type_hint: "number".to_string(),
            description: "Router priority for DR election".to_string(),
            required: true,
        },
        Parameter {
            name: "dr".to_string(),
            type_hint: "string".to_string(),
            description: "Designated router IP".to_string(),
            required: true,
        },
        Parameter {
            name: "bdr".to_string(),
            type_hint: "string".to_string(),
            description: "Backup designated router IP".to_string(),
            required: true,
        },
        Parameter {
            name: "neighbors".to_string(),
            type_hint: "array".to_string(),
            description: "List of neighbor router IDs".to_string(),
            required: true,
        },
    ])
});

/// OSPF Database Description packet received event
pub static OSPF_CLIENT_DD_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "ospf_database_description_received",
        "OSPF Database Description packet received",
        json!({
            "type": "wait_for_more"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "neighbor_id".to_string(),
            type_hint: "string".to_string(),
            description: "Neighbor router ID".to_string(),
            required: true,
        },
        Parameter {
            name: "sequence".to_string(),
            type_hint: "number".to_string(),
            description: "DD sequence number".to_string(),
            required: true,
        },
        Parameter {
            name: "init".to_string(),
            type_hint: "boolean".to_string(),
            description: "Init flag".to_string(),
            required: true,
        },
        Parameter {
            name: "more".to_string(),
            type_hint: "boolean".to_string(),
            description: "More flag".to_string(),
            required: true,
        },
        Parameter {
            name: "master".to_string(),
            type_hint: "boolean".to_string(),
            description: "Master/Slave flag".to_string(),
            required: true,
        },
    ])
});

/// OSPF Link State Update received event
pub static OSPF_CLIENT_LSU_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "ospf_link_state_update_received",
        "OSPF Link State Update received: a router is flooding LSAs, which is where the \
         topology actually lives. Acknowledge them with send_link_state_ack, passing this \
         event's 'lsa_headers' array straight back - unacknowledged LSAs are retransmitted \
         every RxmtInterval until the router gives up on the adjacency (RFC 2328 §13.5).",
        json!({
            "type": "send_link_state_ack",
            "router_id": "1.1.1.1",
            "area_id": "0.0.0.0",
            "lsa_headers": [{
                "age": 1,
                "options": 2,
                "lsa_type": 1,
                "link_state_id": "2.2.2.2",
                "advertising_router": "2.2.2.2",
                "sequence": 2147483649_u32,
                "checksum": 65262,
                "length": 48
            }],
            "destination": "192.168.1.2"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "neighbor_id".to_string(),
            type_hint: "string".to_string(),
            description: "Neighbor router ID".to_string(),
            required: true,
        },
        Parameter {
            name: "advertised_lsa_count".to_string(),
            type_hint: "number".to_string(),
            description: "LSA count the packet's own header claims. May exceed lsa_count if \
                          the packet was truncated or lied."
                .to_string(),
            required: true,
        },
        Parameter {
            name: "lsa_count".to_string(),
            type_hint: "number".to_string(),
            description: "Number of LSA headers actually parsed out of the packet".to_string(),
            required: true,
        },
        Parameter {
            name: "lsa_headers".to_string(),
            type_hint: "array".to_string(),
            description: "One object per LSA: lsa_type, lsa_type_name, link_state_id, \
                          advertising_router, sequence, age, options, checksum, length. \
                          This is the topology data, and also exactly what \
                          send_link_state_ack needs handed back."
                .to_string(),
            required: true,
        },
    ])
});

/// OSPF client protocol action handler
#[derive(Default)]
pub struct OspfClientProtocol;

impl OspfClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for OspfClientProtocol {
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![
            ActionDefinition {
                name: "send_hello".to_string(),
                description: "Send OSPF Hello packet to discover neighbors".to_string(),
                parameters: vec![
                    Parameter {
                        name: "router_id".to_string(),
                        type_hint: "string".to_string(),
                        description: "Our router ID (e.g., '1.1.1.1')".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "area_id".to_string(),
                        type_hint: "string".to_string(),
                        description: "OSPF area ID (e.g., '0.0.0.0' for backbone)".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "network_mask".to_string(),
                        type_hint: "string".to_string(),
                        description: "Network mask (e.g., '255.255.255.0')".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "priority".to_string(),
                        type_hint: "number".to_string(),
                        description: "Router priority (0-255, 0 means never DR)".to_string(),
                        required: false,
                    },
                    Parameter {
                        name: "neighbors".to_string(),
                        type_hint: "array".to_string(),
                        description: "List of neighbor router IDs we've seen".to_string(),
                        required: false,
                    },
                    Parameter {
                        name: "destination".to_string(),
                        type_hint: "string".to_string(),
                        description: "Destination: 'multicast', 'dr_multicast', or IP address"
                            .to_string(),
                        required: false,
                    },
                ],
                example: json!({
                    "type": "send_hello",
                    "router_id": "1.1.1.1",
                    "area_id": "0.0.0.0",
                    "network_mask": "255.255.255.0",
                    "priority": 1,
                    "neighbors": [],
                    "destination": "multicast"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "send_database_description".to_string(),
                description: "Send Database Description packet to exchange LSDB info".to_string(),
                parameters: vec![
                    Parameter {
                        name: "router_id".to_string(),
                        type_hint: "string".to_string(),
                        description: "Our router ID".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "area_id".to_string(),
                        type_hint: "string".to_string(),
                        description: "OSPF area ID".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "sequence".to_string(),
                        type_hint: "number".to_string(),
                        description: "DD sequence number".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "init".to_string(),
                        type_hint: "boolean".to_string(),
                        description: "Init flag (first DD packet)".to_string(),
                        required: false,
                    },
                    Parameter {
                        name: "more".to_string(),
                        type_hint: "boolean".to_string(),
                        description: "More flag (more DD packets to follow)".to_string(),
                        required: false,
                    },
                    Parameter {
                        name: "master".to_string(),
                        type_hint: "boolean".to_string(),
                        description: "Master/Slave flag".to_string(),
                        required: false,
                    },
                    Parameter {
                        name: "destination".to_string(),
                        type_hint: "string".to_string(),
                        description: "Destination IP address".to_string(),
                        required: true,
                    },
                ],
                example: json!({
                    "type": "send_database_description",
                    "router_id": "1.1.1.1",
                    "area_id": "0.0.0.0",
                    "sequence": 12345,
                    "init": false,
                    "more": true,
                    "master": true,
                    "destination": "192.168.1.2"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "send_link_state_request".to_string(),
                description: "Send Link State Request to query specific LSAs".to_string(),
                parameters: vec![
                    Parameter {
                        name: "router_id".to_string(),
                        type_hint: "string".to_string(),
                        description: "Our router ID".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "area_id".to_string(),
                        type_hint: "string".to_string(),
                        description: "OSPF area ID".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "destination".to_string(),
                        type_hint: "string".to_string(),
                        description: "Destination IP address".to_string(),
                        required: true,
                    },
                ],
                example: json!({
                    "type": "send_link_state_request",
                    "router_id": "1.1.1.1",
                    "area_id": "0.0.0.0",
                    "requests": [{
                        "lsa_type": 1,
                        "link_state_id": "2.2.2.2",
                        "advertising_router": "2.2.2.2"
                    }],
                    "destination": "192.168.1.2"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "send_link_state_ack".to_string(),
                description: "Acknowledge the LSAs a router flooded to us. Without this the \
                              router retransmits every LSA each RxmtInterval until it gives \
                              up on the adjacency."
                    .to_string(),
                parameters: vec![
                    Parameter {
                        name: "router_id".to_string(),
                        type_hint: "string".to_string(),
                        description: "Our router ID".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "area_id".to_string(),
                        type_hint: "string".to_string(),
                        description: "OSPF area ID".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "lsa_headers".to_string(),
                        type_hint: "array".to_string(),
                        description: "The LSA headers being acknowledged - pass back the \
                                      'lsa_headers' array exactly as the \
                                      ospf_link_state_update_received event delivered it. \
                                      An acknowledgement is matched header by header, so an \
                                      empty list acknowledges nothing."
                            .to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "destination".to_string(),
                        type_hint: "string".to_string(),
                        description: "Destination IP address".to_string(),
                        required: true,
                    },
                ],
                example: json!({
                    "type": "send_link_state_ack",
                    "router_id": "1.1.1.1",
                    "area_id": "0.0.0.0",
                    "lsa_headers": [{
                        "age": 1,
                        "options": 2,
                        "lsa_type": 1,
                        "link_state_id": "2.2.2.2",
                        "advertising_router": "2.2.2.2",
                        "sequence": 2147483649_u32,
                        "checksum": 65262,
                        "length": 48
                    }],
                    "destination": "192.168.1.2"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "disconnect".to_string(),
                description: "Stop OSPF client and leave multicast group".to_string(),
                parameters: vec![],
                example: json!({
                    "type": "disconnect"
                }),
                log_template: None,
            },
        ]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![ActionDefinition {
            name: "wait_for_more".to_string(),
            description: "Wait for more OSPF packets without sending a response".to_string(),
            parameters: vec![],
            example: json!({
                "type": "wait_for_more"
            }),
            log_template: None,
        }]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            OSPF_CLIENT_CONNECTED_EVENT.clone(),
            OSPF_CLIENT_HELLO_RECEIVED_EVENT.clone(),
            OSPF_CLIENT_DD_RECEIVED_EVENT.clone(),
            OSPF_CLIENT_LSU_RECEIVED_EVENT.clone(),
        ]
    }
    fn protocol_name(&self) -> &'static str {
        "ospf"
    }
    fn stack_name(&self) -> &'static str {
        "network"
    }
    fn get_startup_parameters(&self) -> Vec<crate::llm::actions::ParameterDefinition> {
        vec![
            crate::llm::actions::ParameterDefinition {
                name: "router_id".to_string(),
                type_hint: "string".to_string(),
                description: "OSPF router ID (defaults to interface IP)".to_string(),
                required: false,
                example: json!("1.1.1.1"),
                default: None,
            },
            crate::llm::actions::ParameterDefinition {
                name: "area_id".to_string(),
                type_hint: "string".to_string(),
                description: "OSPF area ID (default: 0.0.0.0)".to_string(),
                required: false,
                example: json!("0.0.0.0"),
                default: None,
            },
        ]
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["ospf", "ospf client", "open shortest path first"]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2 {
            state: DevelopmentState::Experimental,
            privilege_requirement: PrivilegeRequirement::RawSockets,
            implementation: "Raw IP socket (protocol 89) client for OSPF network monitoring. Parses received Hello, Database Description and Link State Update packets down to their LSA headers; sends Hello, DD, Link State Request and Link State Acknowledgment. Cannot construct LSA bodies, so it can ask for and acknowledge LSAs but never originate one.",
            llm_control:
                "LLM controls Hello sending, Database Description exchange, LSR queries and LSAck. The LSA headers an event reports are the same shape send_link_state_ack and send_link_state_request consume, so the model answers a flood by handing the headers back.",
            e2e_testing: "Weak, and weaker than it looks. tests/client/ospf/e2e_test.rs skips itself with a pass whenever the process is not root - which is every CI run - and even when it runs it asserts only that the word 'OSPF' appears in the client's own output, which the prompt already contains. The real coverage is tests/client/ospf/command_channel_test.rs, which hard-fails either way: unprivileged it asserts connect() returns Err, leaves no command handle behind and makes a later send_to_client fail fast; privileged it asserts the live wiring. The test that actually multicasts a Hello is #[ignore]d because it needs CAP_NET_RAW and a multicast-capable interface.",
            notes: Some("Query mode only - topology discovery, not a full OSPF router. No LSDB, no SPF, no periodic Hello timer, no adjacency state machine: it reacts to what arrives. Packet construction is shared with the OSPF server (crate::server::ospf::actions::OspfProtocol), so both directions agree on the wire format by construction."),
            connectionless: false,
            // The builder's default. `FailureMode` describes what a *server* puts on the wire
            // when the model cannot answer; a client has no peer waiting on a reply, so this
            // says nothing about OSPF either way — it is here because the struct is built by
            // literal rather than through the builder.
            failure_mode: FailureMode::Answers,
            // Likewise the builder's default. `max_inbound_bytes` describes what a *server*
            // buffers from a peer; this client reads each OSPF packet into one fixed-size raw
            // socket buffer and accumulates nothing across reads, so there is no peer-chosen
            // length to declare.
            max_inbound_bytes: None,
            // A client listens on nothing, so it has no port of its own to declare.
            well_known_port: None,
            well_known_transport: PortTransport::Tcp,
            // A client has no peers of its own to message; the declaration is a server's.
            request_only: None,
            // An adjacency is a session: each hello and LSA is read against the last.
            history: HistoryMode::Last(SESSION_HISTORY_ENTRIES),
            // Packets are handled one by one inside the client's read loop.
            batching: BatchingMode::Unsupported,
        }
    }
    fn description(&self) -> &'static str {
        "OSPF client for network topology discovery and OSPF monitoring"
    }
    fn example_prompt(&self) -> &'static str {
        "Connect to 192.168.1.100 via OSPF in area 0, discover neighbors and query LSDB for topology"
    }
    fn group_name(&self) -> &'static str {
        "VPN & Routing"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        use serde_json::json;

        StartupExamples::new(
            // LLM mode: LLM controls OSPF client for topology discovery
            json!({
                "type": "open_client",
                "remote_addr": "192.168.1.1:0",
                "base_stack": "ospf",
                "instruction": "Discover OSPF neighbors in area 0 and request topology info"
            }),
            // Script mode: Code-based handling of OSPF events
            json!({
                "type": "open_client",
                "remote_addr": "192.168.1.1:0",
                "base_stack": "ospf",
                "event_handlers": [{
                    "event_pattern": "ospf_hello_received",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "<ospf_client_handler>"
                    }
                }]
            }),
            // Static mode: Fixed OSPF Hello sending
            json!({
                "type": "open_client",
                "remote_addr": "192.168.1.1:0",
                "base_stack": "ospf",
                "event_handlers": [
                    {
                        "event_pattern": "ospf_client_connected",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "send_hello",
                                "router_id": "1.1.1.1",
                                "area_id": "0.0.0.0",
                                "network_mask": "255.255.255.0",
                                "priority": 0,
                                "neighbors": [],
                                "destination": "multicast"
                            }]
                        }
                    },
                    {
                        "event_pattern": "ospf_hello_received",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "wait_for_more"
                            }]
                        }
                    }
                ]
            }),
        )
    }
}

// Implement Client trait (client-specific functionality)
impl Client for OspfClientProtocol {
    fn connect(
        &self,
        ctx: crate::protocol::ConnectContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::client::ospf::OspfClient;
            OspfClient::connect_with_llm_actions(
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
        let action_type = action["type"]
            .as_str()
            .context("Missing 'type' field in action")?;

        match action_type {
            "send_hello" => Ok(ClientActionResult::Custom {
                name: "ospf_send_hello".to_string(),
                data: action.clone(),
            }),
            "send_database_description" => Ok(ClientActionResult::Custom {
                name: "ospf_send_dd".to_string(),
                data: action.clone(),
            }),
            "send_link_state_request" => Ok(ClientActionResult::Custom {
                name: "ospf_send_lsr".to_string(),
                data: action.clone(),
            }),
            "send_link_state_ack" => Ok(ClientActionResult::Custom {
                name: "ospf_send_lsack".to_string(),
                data: action.clone(),
            }),
            "disconnect" => Ok(ClientActionResult::Disconnect),
            "wait_for_more" => Ok(ClientActionResult::WaitForMore),
            _ => Err(anyhow!("Unknown action type: {}", action_type)),
        }
    }
}
