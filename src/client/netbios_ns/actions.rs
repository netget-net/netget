//! NetBIOS Name Service client vocabulary: the actions the model may take and the events it
//! is asked about.
//!
//! # The suffix is a field, never text
//!
//! Every name here carries a separate `suffix` number plus a readable `suffix_label`.
//! `FILESERVER<0x00>` and `FILESERVER<0x20>` are *different names* that may live on different
//! hosts, so folding the suffix into the name string would silently merge two questions into
//! one. Same rule for `mac_address`, which is a formatted `"00:11:22:33:44:55"` string, and
//! addresses, which are dotted quads. There are no raw bytes and no base64 in this vocabulary.
//!
//! # One list, not two
//!
//! `get_async_actions` carries the whole vocabulary and `get_sync_actions` is empty.
//! `client_llm_action_set` unions async ∪ sync ∪ the firing event's own list, and a client has
//! a single LLM entry point, so a client cannot express a narrowing and duplicating the list
//! into both methods only obscures that. Each event attaches the same list so the model sees
//! the full vocabulary whichever way `call_llm_for_client` is entered.

use std::sync::LazyLock;

use anyhow::{Context, Result};
use serde_json::json;

use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, Parameter, ParameterDefinition, StartupExamples,
};
use crate::protocol::EventType;
use crate::state::app_state::AppState;

// ===========================================================================================
// Actions
// ===========================================================================================

/// The complete client vocabulary.
///
/// A free function rather than an inherent method so the event declarations below — which are
/// `LazyLock` statics and therefore cannot see `self` — attach exactly the same list.
pub fn client_actions() -> Vec<ActionDefinition> {
    vec![
        ActionDefinition {
            name: "send_netbios_name_query".to_string(),
            description: "Resolve a NetBIOS name to its IPv4 address(es) — question type NB. \
                          The reply arrives as a 'netbios_name_response' event, a \
                          'netbios_negative_response' if the name is not held, or a \
                          'netbios_query_timeout' if nothing answers."
                .to_string(),
            parameters: vec![
                Parameter {
                    name: "name".to_string(),
                    type_hint: "string".to_string(),
                    description: "NetBIOS name to resolve, at most 15 characters, ASCII. \
                                  Conventionally upper case."
                        .to_string(),
                    required: true,
                },
                Parameter {
                    name: "suffix".to_string(),
                    type_hint: "number".to_string(),
                    description: "Service suffix selecting which service of that name to ask \
                                  about: 0 workstation, 0x20 (32) file server, 0x1B (27) \
                                  domain master browser, 0x1C (28) domain controllers. \
                                  A number or a hex string like \"0x20\". Defaults to 0."
                        .to_string(),
                    required: false,
                },
                Parameter {
                    name: "target_address".to_string(),
                    type_hint: "string".to_string(),
                    description: "Dotted-quad address to send this query to. Defaults to the \
                                  address this client connected to."
                        .to_string(),
                    required: false,
                },
                Parameter {
                    name: "target_port".to_string(),
                    type_hint: "number".to_string(),
                    description: "UDP port to send to. Defaults to the port this client \
                                  connected to (137 in normal use)."
                        .to_string(),
                    required: false,
                },
                Parameter {
                    name: "broadcast".to_string(),
                    type_hint: "boolean".to_string(),
                    description: "Ask the broadcast form of the question (sets the B and RD \
                                  flags) rather than a directed query to a name server. \
                                  Defaults to false. This describes the question, not the \
                                  routing — the destination is still 'target_address'."
                        .to_string(),
                    required: false,
                },
            ],
            example: json!({
                "type": "send_netbios_name_query",
                "name": "FILESERVER",
                "suffix": 32
            }),
            log_template: None,
        },
        ActionDefinition {
            name: "send_netbios_node_status_query".to_string(),
            description: "Ask a host to list every NetBIOS name it holds — question type \
                          NBSTAT, the 'nbtstat -A' question. The reply names the machine, its \
                          workgroup or domain, often the logged-on user, the service suffixes \
                          it offers and its adapter MAC address. Use the wildcard name '*' \
                          unless you have a reason not to."
                .to_string(),
            parameters: vec![
                Parameter {
                    name: "name".to_string(),
                    type_hint: "string".to_string(),
                    description: "Name to ask about. '*' (the wildcard, the default) means \
                                  'whatever names you hold' and is what nbtstat sends."
                        .to_string(),
                    required: false,
                },
                Parameter {
                    name: "suffix".to_string(),
                    type_hint: "number".to_string(),
                    description: "Service suffix for the name being asked about. Defaults to 0, \
                                  which is what the wildcard question uses."
                        .to_string(),
                    required: false,
                },
                Parameter {
                    name: "target_address".to_string(),
                    type_hint: "string".to_string(),
                    description: "Dotted-quad address of the host to interrogate. Defaults to \
                                  the address this client connected to."
                        .to_string(),
                    required: false,
                },
                Parameter {
                    name: "target_port".to_string(),
                    type_hint: "number".to_string(),
                    description: "UDP port to send to. Defaults to the port this client \
                                  connected to (137 in normal use)."
                        .to_string(),
                    required: false,
                },
            ],
            example: json!({
                "type": "send_netbios_node_status_query",
                "name": "*",
                "suffix": 0
            }),
            log_template: None,
        },
        ActionDefinition {
            name: "wait_for_more".to_string(),
            description: "Send nothing and wait. Use this to end a turn without asking another \
                          question."
                .to_string(),
            parameters: vec![],
            example: json!({"type": "wait_for_more"}),
            log_template: None,
        },
        ActionDefinition {
            name: "disconnect".to_string(),
            description: "Finish. NetBIOS-NS is connectionless, so this releases the socket and \
                          ends the session rather than closing anything on the wire."
                .to_string(),
            parameters: vec![],
            example: json!({"type": "disconnect"}),
            log_template: None,
        },
    ]
}

// ===========================================================================================
// Events
// ===========================================================================================

/// Raised once, as soon as the UDP socket is bound. NBNS has no handshake, so "connected"
/// means "ready to ask" and nothing more.
pub static NETBIOS_NS_CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "netbios_ns_connected",
        "NetBIOS-NS client bound its socket and can start asking questions",
        json!({"type": "send_netbios_node_status_query", "name": "*", "suffix": 0}),
    )
    .with_parameters(vec![
        Parameter {
            name: "remote_addr".to_string(),
            type_hint: "string".to_string(),
            description: "Default target address:port for queries that do not name one".to_string(),
            required: true,
        },
        Parameter {
            name: "local_addr".to_string(),
            type_hint: "string".to_string(),
            description: "Local address:port the client is querying from (an ephemeral port; \
                          NBNS queriers do not need to bind 137)"
                .to_string(),
            required: true,
        },
    ])
    .with_actions(client_actions())
});

/// A POSITIVE NAME QUERY RESPONSE arrived and matched the outstanding transaction id.
pub static NETBIOS_NAME_RESPONSE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "netbios_name_response",
        "A NetBIOS name was resolved to one or more IPv4 addresses",
        json!({"type": "wait_for_more"}),
    )
    .with_parameters(vec![
        Parameter {
            name: "name".to_string(),
            type_hint: "string".to_string(),
            description: "The resolved NetBIOS name, padding trimmed, suffix removed".to_string(),
            required: true,
        },
        Parameter {
            name: "suffix".to_string(),
            type_hint: "number".to_string(),
            description: "Service suffix as a number — a separate field, never part of 'name'"
                .to_string(),
            required: true,
        },
        Parameter {
            name: "suffix_label".to_string(),
            type_hint: "string".to_string(),
            description: "Readable name for the suffix, e.g. 'file_server' for 0x20".to_string(),
            required: true,
        },
        Parameter {
            name: "addresses".to_string(),
            type_hint: "array".to_string(),
            description: "IPv4 addresses as dotted quads".to_string(),
            required: true,
        },
        Parameter {
            name: "ttl".to_string(),
            type_hint: "number".to_string(),
            description: "Seconds this answer may be cached".to_string(),
            required: true,
        },
        Parameter {
            name: "group".to_string(),
            type_hint: "boolean".to_string(),
            description: "True when this is a group name (a workgroup or domain) rather than a \
                          unique host name"
                .to_string(),
            required: true,
        },
        Parameter {
            name: "node_type".to_string(),
            type_hint: "string".to_string(),
            description: "Owner node type reported by the responder: b, p, m or h".to_string(),
            required: true,
        },
        Parameter {
            name: "responder".to_string(),
            type_hint: "string".to_string(),
            description: "address:port the answer actually came from".to_string(),
            required: true,
        },
    ])
    .with_actions(client_actions())
});

/// A NODE STATUS RESPONSE arrived: the host listed its own names.
pub static NETBIOS_NODE_STATUS_RESPONSE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "netbios_node_status_response",
        "A host listed every NetBIOS name it holds, plus its adapter MAC address",
        json!({"type": "wait_for_more"}),
    )
    .with_parameters(vec![
        Parameter {
            name: "name".to_string(),
            type_hint: "string".to_string(),
            description: "The name the request asked about, echoed back ('*' for the wildcard)"
                .to_string(),
            required: true,
        },
        Parameter {
            name: "names".to_string(),
            type_hint: "array".to_string(),
            description: "One object per registered name: {name, suffix, suffix_label, group, \
                          active}. The workgroup or domain is the group entry; a suffix of \
                          0x20 marks the file server service, 0x1C a domain controller list."
                .to_string(),
            required: true,
        },
        Parameter {
            name: "mac_address".to_string(),
            type_hint: "string".to_string(),
            description: "Adapter MAC as '00:11:22:33:44:55'".to_string(),
            required: true,
        },
        Parameter {
            name: "responder".to_string(),
            type_hint: "string".to_string(),
            description: "address:port the answer actually came from".to_string(),
            required: true,
        },
    ])
    .with_actions(client_actions())
});

/// Nothing matched the outstanding transaction id before the deadline.
///
/// **This is a normal outcome, not an error.** On NBNS a node that does not hold the queried
/// name simply says nothing, so silence is the ordinary negative answer for a broadcast-style
/// question.
pub static NETBIOS_QUERY_TIMEOUT_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "netbios_query_timeout",
        "No matching NetBIOS response arrived before the deadline. On NBNS this is normal: a \
         node that does not hold the name stays silent rather than refusing.",
        json!({"type": "wait_for_more"}),
    )
    .with_parameters(vec![
        Parameter {
            name: "name".to_string(),
            type_hint: "string".to_string(),
            description: "Name that was queried".to_string(),
            required: true,
        },
        Parameter {
            name: "suffix".to_string(),
            type_hint: "number".to_string(),
            description: "Service suffix that was queried".to_string(),
            required: true,
        },
        Parameter {
            name: "question_type".to_string(),
            type_hint: "string".to_string(),
            description: "'NB' for a name query, 'NBSTAT' for a node status request".to_string(),
            required: true,
        },
        Parameter {
            name: "target".to_string(),
            type_hint: "string".to_string(),
            description: "address:port the query was sent to".to_string(),
            required: true,
        },
        Parameter {
            name: "timeout_secs".to_string(),
            type_hint: "number".to_string(),
            description: "How long the client waited".to_string(),
            required: true,
        },
        Parameter {
            name: "ignored_datagrams".to_string(),
            type_hint: "number".to_string(),
            description: "Datagrams that arrived during the wait and were discarded because \
                          their transaction id did not match, or they did not decode"
                .to_string(),
            required: true,
        },
    ])
    .with_actions(client_actions())
});

/// The responder refused: a non-zero RCODE.
pub static NETBIOS_NEGATIVE_RESPONSE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "netbios_negative_response",
        "A NetBIOS name server answered with a non-zero RCODE — the name is not held, or the \
         request was refused",
        json!({"type": "wait_for_more"}),
    )
    .with_parameters(vec![
        Parameter {
            name: "name".to_string(),
            type_hint: "string".to_string(),
            description: "Name the refusal is about".to_string(),
            required: true,
        },
        Parameter {
            name: "suffix".to_string(),
            type_hint: "number".to_string(),
            description: "Service suffix, as a separate field".to_string(),
            required: true,
        },
        Parameter {
            name: "rcode".to_string(),
            type_hint: "number".to_string(),
            description: "Numeric RCODE from the response header".to_string(),
            required: true,
        },
        Parameter {
            name: "rcode_name".to_string(),
            type_hint: "string".to_string(),
            description: "Readable RCODE: name_not_found, refused, server_failure, \
                          format_error, unsupported_request, name_active, name_conflict"
                .to_string(),
            required: true,
        },
        Parameter {
            name: "responder".to_string(),
            type_hint: "string".to_string(),
            description: "address:port the refusal came from".to_string(),
            required: true,
        },
    ])
    .with_actions(client_actions())
});

// ===========================================================================================
// Protocol
// ===========================================================================================

/// NetBIOS Name Service client — the `nbtstat` equivalent.
pub struct NetbiosNsClientProtocol;

impl Default for NetbiosNsClientProtocol {
    fn default() -> Self {
        Self::new()
    }
}

impl NetbiosNsClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

impl Protocol for NetbiosNsClientProtocol {
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "port".to_string(),
                type_hint: "number".to_string(),
                description: "UDP port on the target to send queries to. Overrides the port in \
                              remote_addr, and supplies one when remote_addr is a bare address. \
                              Defaults to 137. Querying needs no privilege at all — only \
                              *binding* 137 does, and this client sends from an ephemeral \
                              source port."
                    .to_string(),
                required: false,
                example: json!(137),
                default: None,
            },
            ParameterDefinition {
                name: "query_timeout_secs".to_string(),
                type_hint: "number".to_string(),
                description: "How long to wait for a reply carrying the matching transaction id \
                              before raising 'netbios_query_timeout'. Defaults to 3."
                    .to_string(),
                required: false,
                example: json!(3),
                default: None,
            },
        ]
    }

    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        client_actions()
    }

    /// Empty on purpose: see the module docs. A client has one LLM entry point, so it cannot
    /// express an async/sync narrowing, and `client_llm_action_set` unions the lists anyway.
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        Vec::new()
    }

    fn protocol_name(&self) -> &'static str {
        "NetBIOS-NS"
    }

    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            NETBIOS_NS_CONNECTED_EVENT.clone(),
            NETBIOS_NAME_RESPONSE_EVENT.clone(),
            NETBIOS_NODE_STATUS_RESPONSE_EVENT.clone(),
            NETBIOS_QUERY_TIMEOUT_EVENT.clone(),
            NETBIOS_NEGATIVE_RESPONSE_EVENT.clone(),
        ]
    }

    fn stack_name(&self) -> &'static str {
        "ETH>IP>UDP>NetBIOS-NS"
    }

    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "netbios",
            "netbios-ns",
            "netbios name service",
            "nbns",
            "nbt",
            "nbtstat",
            "nmblookup",
            "windows name lookup",
            "smb host enumeration",
        ]
    }

    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{
            DevelopmentState, PrivilegeRequirement, ProtocolMetadataV2,
        };

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            // Explicit rather than defaulted: a querier binds an ephemeral source port, so
            // nothing here needs privilege. Only *binding* 137, which is the server's job,
            // does.
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation(
                "tokio UdpSocket, reusing the server half's RFC 1001/1002 codec \
                 (crate::server::netbios_ns::packet) for names, header and constants; request \
                 encoding and response decoding live in client/netbios_ns/wire.rs",
            )
            .llm_control(
                "Which names and suffixes to query, which host to ask, NB versus NBSTAT, and \
                 what to do with each answer",
            )
            .e2e_testing(
                "Query encoding pinned byte-for-byte against datagrams captured from Samba \
                 4.24.6 nmblookup; the exchange itself is driven against NetGet's own NBNS \
                 server and a raw UDP stand-in",
            )
            .notes(
                "Experimental, and the reason is precise. The ENCODE direction has independent \
                 evidence: a query this client builds is byte-identical to one Samba's \
                 nmblookup puts on the wire, captured with tcpdump. The DECODE direction has \
                 none — the only NBNS responder it has been driven against is NetGet's own \
                 server, which is same-project evidence that the two halves agree, not that \
                 either matches RFC 1002. No third-party NBNS responder can be reached on a \
                 high port (nmblookup is hard-wired to 137, and binding 137 needs root), so \
                 Beta's 'works against real clients' claim is unsupported in the direction \
                 that matters. Not implemented: retransmission, WACK/redirect handling, name \
                 registration or release, NetBIOS scopes beyond echoing, the datagram service \
                 (UDP 138) and the session service (TCP 139).",
            )
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }

    fn description(&self) -> &'static str {
        "NetBIOS Name Service client (nbtstat): resolve NetBIOS names and enumerate the names, \
         workgroup and adapter MAC a host holds"
    }

    fn example_prompt(&self) -> &'static str {
        "Connect to 192.168.1.10:137 via NetBIOS-NS and run a node status query to list every \
         name that host holds"
    }

    fn group_name(&self) -> &'static str {
        "NetBIOS"
    }

    fn get_startup_examples(&self) -> StartupExamples {
        StartupExamples::new(
            // LLM mode
            json!({
                "type": "open_client",
                "protocol": "NetBIOS-NS",
                "remote_addr": "192.168.1.10:137",
                "instruction": "Run a node status query with the wildcard name and report the \
                                machine name, the workgroup and the adapter MAC."
            }),
            // Script mode
            json!({
                "type": "open_client",
                "protocol": "NetBIOS-NS",
                "remote_addr": "192.168.1.10:137",
                "event_handlers": [{
                    "event_pattern": "netbios_ns_connected",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "<netbios_ns_client_handler>"
                    }
                }]
            }),
            // Static mode
            json!({
                "type": "open_client",
                "protocol": "NetBIOS-NS",
                "remote_addr": "192.168.1.10:137",
                "event_handlers": [
                    {
                        "event_pattern": "netbios_ns_connected",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "send_netbios_node_status_query",
                                "name": "*",
                                "suffix": 0
                            }]
                        }
                    },
                    {
                        "event_pattern": "netbios_node_status_response",
                        "handler": {
                            "type": "static",
                            "actions": [{"type": "disconnect"}]
                        }
                    }
                ]
            }),
        )
    }
}

impl Client for NetbiosNsClientProtocol {
    fn connect(
        &self,
        ctx: crate::protocol::ConnectContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move { super::NetbiosNsClient::connect_with_llm_actions(ctx).await })
    }

    /// Validate one action and describe what it asks for. No socket is touched here: the
    /// connection loop owns the wire, and this same function serves both the LLM path and the
    /// dashboard's injected commands, so the parameter contract exists exactly once.
    fn execute_action(&self, action: serde_json::Value) -> Result<ClientActionResult> {
        let action_type = action
            .get("type")
            .and_then(|v| v.as_str())
            .context("Missing 'type' field in action")?;

        match action_type {
            "send_netbios_name_query" => {
                let name = action
                    .get("name")
                    .and_then(|v| v.as_str())
                    .context("send_netbios_name_query is missing 'name'")?
                    .to_string();
                let suffix = super::wire::parse_suffix(action.get("suffix"))?;
                Ok(ClientActionResult::Custom {
                    name: "netbios_name_query".to_string(),
                    data: json!({
                        "name": name,
                        "suffix": suffix,
                        "target_address": action.get("target_address").cloned(),
                        "target_port": action.get("target_port").cloned(),
                        "broadcast": action.get("broadcast").and_then(|v| v.as_bool())
                            .unwrap_or(false),
                    }),
                })
            }
            "send_netbios_node_status_query" => {
                // The wildcard is the whole point of NBSTAT, so it is the default rather than
                // something the model has to remember to type.
                let name = action
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or(crate::server::netbios_ns::packet::WILDCARD_NAME)
                    .to_string();
                let suffix = super::wire::parse_suffix(action.get("suffix"))?;
                Ok(ClientActionResult::Custom {
                    name: "netbios_node_status_query".to_string(),
                    data: json!({
                        "name": name,
                        "suffix": suffix,
                        "target_address": action.get("target_address").cloned(),
                        "target_port": action.get("target_port").cloned(),
                    }),
                })
            }
            "wait_for_more" => Ok(ClientActionResult::WaitForMore),
            "disconnect" => Ok(ClientActionResult::Disconnect),
            other => Err(anyhow::anyhow!(
                "Unknown NetBIOS-NS client action: {}. Available: \
                 send_netbios_name_query, send_netbios_node_status_query, wait_for_more, \
                 disconnect",
                other
            )),
        }
    }
}
