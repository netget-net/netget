//! XML-RPC client protocol actions implementation

use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, Parameter, ParameterDefinition,
};
use crate::protocol::EventType;
use crate::state::app_state::AppState;
use anyhow::{Context, Result};
use serde_json::json;
use std::sync::LazyLock;

/// XML-RPC client connected event
pub static XMLRPC_CLIENT_CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "xmlrpc_connected",
        "XML-RPC client initialized and ready to call methods",
        json!({
            "type": "call_xmlrpc_method",
            "method_name": "system.listMethods",
            "params": []
        }),
    )
    .with_parameters(vec![Parameter {
        name: "server_url".to_string(),
        type_hint: "string".to_string(),
        description: "XML-RPC server URL".to_string(),
        required: true,
    }])
});

/// XML-RPC client response received event
pub static XMLRPC_CLIENT_RESPONSE_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "xmlrpc_response_received",
        "XML-RPC response received from server",
        json!({
            "type": "call_xmlrpc_method",
            "method_name": "system.listMethods",
            "params": []
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "method_name".to_string(),
            type_hint: "string".to_string(),
            description: "Name of the method that was called".to_string(),
            required: true,
        },
        Parameter {
            name: "result".to_string(),
            type_hint: "any".to_string(),
            description: "Method call result (can be string, number, array, struct, etc.)"
                .to_string(),
            required: false,
        },
        Parameter {
            name: "fault".to_string(),
            type_hint: "object".to_string(),
            description: "Fault information if the call failed".to_string(),
            required: false,
        },
    ])
});

/// XML-RPC client protocol action handler
pub struct XmlRpcClientProtocol;

impl XmlRpcClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for XmlRpcClientProtocol {
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![ParameterDefinition {
            name: "timeout_secs".to_string(),
            description: "Request timeout in seconds (default: 30)".to_string(),
            type_hint: "number".to_string(),
            required: false,
            example: json!(30),
            default: None,
        }]
    }
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![
                ActionDefinition {
                    name: "call_xmlrpc_method".to_string(),
                    description: "Call an XML-RPC method on the server".to_string(),
                    parameters: vec![
                        Parameter {
                            name: "method_name".to_string(),
                            type_hint: "string".to_string(),
                            description: "Name of the XML-RPC method to call".to_string(),
                            required: true,
                        },
                        Parameter {
                            name: "params".to_string(),
                            type_hint: "array".to_string(),
                            description: "Array of parameters for the method call (strings, numbers, bools, arrays, objects)".to_string(),
                            required: false,
                        },
                    ],
                    example: json!({
                        "type": "call_xmlrpc_method",
                        "method_name": "examples.getStateName",
                        "params": [41]
                    }),
                log_template: None,
                },
                ActionDefinition {
                    name: "disconnect".to_string(),
                    description: "Disconnect from the XML-RPC server".to_string(),
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
            name: "call_xmlrpc_method".to_string(),
            description: "Call another XML-RPC method in response to received data".to_string(),
            parameters: vec![
                Parameter {
                    name: "method_name".to_string(),
                    type_hint: "string".to_string(),
                    description: "Name of the XML-RPC method to call".to_string(),
                    required: true,
                },
                Parameter {
                    name: "params".to_string(),
                    type_hint: "array".to_string(),
                    description: "Array of parameters for the method call".to_string(),
                    required: false,
                },
            ],
            example: json!({
                "type": "call_xmlrpc_method",
                "method_name": "system.listMethods",
                "params": []
            }),
            log_template: None,
        }]
    }
    fn protocol_name(&self) -> &'static str {
        "XML-RPC"
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            EventType::new(
                "xmlrpc_connected",
                "Triggered when XML-RPC client is initialized",
                json!({"type": "placeholder", "event_id": "xmlrpc_connected"}),
            ),
            EventType::new(
                "xmlrpc_response_received",
                "Triggered when XML-RPC client receives a response",
                json!({"type": "placeholder", "event_id": "xmlrpc_response_received"}),
            ),
        ]
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>HTTP>XML-RPC"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["xmlrpc", "xml-rpc", "xml rpc", "rpc", "connect to xmlrpc"]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .implementation("xmlrpc crate for method calls")
            .llm_control("Full control over method calls with structured parameters")
            .e2e_testing("Public XML-RPC test servers or local implementation")
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn description(&self) -> &'static str {
        "XML-RPC client for calling remote procedures"
    }
    fn example_prompt(&self) -> &'static str {
        "Connect to http://example.com/xmlrpc and call system.listMethods"
    }
    fn group_name(&self) -> &'static str {
        "RPC & API"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        use serde_json::json;

        StartupExamples::new(
            // LLM mode: LLM controls XML-RPC method calls
            json!({
                "type": "open_client",
                "remote_addr": "http://example.com/xmlrpc",
                "base_stack": "xmlrpc",
                "instruction": "Call system.listMethods to discover available methods"
            }),
            // Script mode: Code-based XML-RPC handling
            json!({
                "type": "open_client",
                "remote_addr": "http://example.com/xmlrpc",
                "base_stack": "xmlrpc",
                "event_handlers": [{
                    "event_pattern": "xmlrpc_response_received",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "<xmlrpc_client_handler>"
                    }
                }]
            }),
            // Static mode: Fixed XML-RPC method call
            json!({
                "type": "open_client",
                "remote_addr": "http://example.com/xmlrpc",
                "base_stack": "xmlrpc",
                "event_handlers": [
                    {
                        "event_pattern": "xmlrpc_connected",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "call_xmlrpc_method",
                                "method_name": "system.listMethods",
                                "params": []
                            }]
                        }
                    },
                    {
                        "event_pattern": "xmlrpc_response_received",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "disconnect"
                            }]
                        }
                    }
                ]
            }),
        )
    }
}

// Implement Client trait (client-specific functionality)
impl Client for XmlRpcClientProtocol {
    fn connect(
        &self,
        ctx: crate::protocol::ConnectContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::client::xmlrpc::XmlRpcClient;
            XmlRpcClient::connect_with_llm_actions(
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
            "call_xmlrpc_method" => {
                let method_name = action
                    .get("method_name")
                    .and_then(|v| v.as_str())
                    .context("Missing 'method_name' field")?
                    .to_string();

                let params = action
                    .get("params")
                    .and_then(|v| v.as_array())
                    .cloned()
                    .unwrap_or_default();

                // Return custom result with method call data
                Ok(ClientActionResult::Custom {
                    name: "xmlrpc_call".to_string(),
                    data: json!({
                        "method_name": method_name,
                        "params": params,
                    }),
                })
            }
            "disconnect" => Ok(ClientActionResult::Disconnect),
            _ => Err(anyhow::anyhow!(
                "Unknown XML-RPC client action: {}",
                action_type
            )),
        }
    }
}
