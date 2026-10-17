//! MCP (Model Context Protocol) client protocol actions implementation

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

/// MCP client connected event (after successful initialize)
pub static MCP_CLIENT_CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "mcp_client_connected",
        "MCP client completed initialization handshake with server",
        json!({"type": "list_resources"}),
    )
    .with_parameters(vec![
        Parameter {
            name: "server_name".to_string(),
            type_hint: "string".to_string(),
            description: "Name of the MCP server".to_string(),
            required: true,
        },
        Parameter {
            name: "server_version".to_string(),
            type_hint: "string".to_string(),
            description: "Version of the MCP server".to_string(),
            required: true,
        },
        Parameter {
            name: "capabilities".to_string(),
            type_hint: "object".to_string(),
            description: "Server capabilities (resources, tools, prompts)".to_string(),
            required: true,
        },
    ])
});

/// MCP client response received event (for tool calls, resource reads, etc.)
pub static MCP_CLIENT_RESPONSE_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "mcp_response_received",
        "MCP client received response from server",
        json!({"type": "call_tool", "name": "search", "arguments": {"query": "test"}}),
    )
    .with_parameters(vec![
        Parameter {
            name: "method".to_string(),
            type_hint: "string".to_string(),
            description: "JSON-RPC method that was called".to_string(),
            required: true,
        },
        Parameter {
            name: "result".to_string(),
            type_hint: "object".to_string(),
            description: "Response result data".to_string(),
            required: true,
        },
    ])
});

/// MCP client protocol action handler
pub struct McpClientProtocol;

impl Default for McpClientProtocol {
    fn default() -> Self {
        Self::new()
    }
}

impl McpClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for McpClientProtocol {
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "client_name".to_string(),
                description: "Name to identify this MCP client".to_string(),
                type_hint: "string".to_string(),
                required: false,
                example: json!("netget-client"),
                default: None,
            },
            ParameterDefinition {
                name: "client_version".to_string(),
                description: "Version of this MCP client".to_string(),
                type_hint: "string".to_string(),
                required: false,
                example: json!("1.0.0"),
                default: None,
            },
        ]
    }
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![
            ActionDefinition {
                name: "list_resources".to_string(),
                description: "List available resources from MCP server".to_string(),
                parameters: vec![],
                example: json!({
                    "type": "list_resources"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "read_resource".to_string(),
                description: "Read a resource from MCP server".to_string(),
                parameters: vec![Parameter {
                    name: "uri".to_string(),
                    type_hint: "string".to_string(),
                    description: "Resource URI (e.g., file:///README.md)".to_string(),
                    required: true,
                }],
                example: json!({
                    "type": "read_resource",
                    "uri": "file:///README.md"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "list_tools".to_string(),
                description: "List available tools from MCP server".to_string(),
                parameters: vec![],
                example: json!({
                    "type": "list_tools"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "call_tool".to_string(),
                description: "Call a tool on the MCP server".to_string(),
                parameters: vec![
                    Parameter {
                        name: "name".to_string(),
                        type_hint: "string".to_string(),
                        description: "Tool name".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "arguments".to_string(),
                        type_hint: "object".to_string(),
                        description: "Tool arguments".to_string(),
                        required: false,
                    },
                ],
                example: json!({
                    "type": "call_tool",
                    "name": "calculate",
                    "arguments": {
                        "expression": "2+2"
                    }
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "list_prompts".to_string(),
                description: "List available prompts from MCP server".to_string(),
                parameters: vec![],
                example: json!({
                    "type": "list_prompts"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "get_prompt".to_string(),
                description: "Get a prompt from MCP server".to_string(),
                parameters: vec![
                    Parameter {
                        name: "name".to_string(),
                        type_hint: "string".to_string(),
                        description: "Prompt name".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "arguments".to_string(),
                        type_hint: "object".to_string(),
                        description: "Prompt arguments".to_string(),
                        required: false,
                    },
                ],
                example: json!({
                    "type": "get_prompt",
                    "name": "code-review",
                    "arguments": {}
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "disconnect".to_string(),
                description: "Disconnect from the MCP server".to_string(),
                parameters: vec![],
                example: json!({
                    "type": "disconnect"
                }),
                log_template: None,
            },
        ]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            ActionDefinition {
                name: "list_resources".to_string(),
                description: "List resources in response to server event".to_string(),
                parameters: vec![],
                example: json!({
                    "type": "list_resources"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "call_tool".to_string(),
                description: "Call a tool in response to server event".to_string(),
                parameters: vec![
                    Parameter {
                        name: "name".to_string(),
                        type_hint: "string".to_string(),
                        description: "Tool name".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "arguments".to_string(),
                        type_hint: "object".to_string(),
                        description: "Tool arguments".to_string(),
                        required: false,
                    },
                ],
                example: json!({
                    "type": "call_tool",
                    "name": "search",
                    "arguments": {
                        "query": "test"
                    }
                }),
                log_template: None,
            },
        ]
    }
    fn protocol_name(&self) -> &'static str {
        "MCP"
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            EventType::new(
                "mcp_client_connected",
                "Triggered when MCP client completes initialization",
                json!({"type": "list_resources"}),
            ),
            EventType::new(
                "mcp_response_received",
                "Triggered when MCP client receives a response",
                json!({"type": "call_tool", "name": "search", "arguments": {"query": "test"}}),
            ),
        ]
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>HTTP>MCP"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "mcp",
            "mcp client",
            "connect to mcp",
            "model context protocol",
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .implementation("Custom JSON-RPC 2.0 client over HTTP")
            .llm_control("Full control over MCP operations (tools, resources, prompts)")
            .e2e_testing("Local MCP server or public MCP endpoint")
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn description(&self) -> &'static str {
        "MCP (Model Context Protocol) client for accessing LLM context servers"
    }
    fn example_prompt(&self) -> &'static str {
        "Connect to http://localhost:8000 via MCP and list available tools"
    }
    fn group_name(&self) -> &'static str {
        "RPC & API"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        use serde_json::json;

        StartupExamples::new(
            // LLM mode: LLM controls MCP operations
            json!({
                "type": "open_client",
                "remote_addr": "http://localhost:8000",
                "base_stack": "mcp",
                "instruction": "List available tools and call the calculate tool with expression 2+2"
            }),
            // Script mode: Code-based MCP handling
            json!({
                "type": "open_client",
                "remote_addr": "http://localhost:8000",
                "base_stack": "mcp",
                "event_handlers": [{
                    "event_pattern": "mcp_response_received",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "<mcp_client_handler>"
                    }
                }]
            }),
            // Static mode: Fixed MCP tool call
            json!({
                "type": "open_client",
                "remote_addr": "http://localhost:8000",
                "base_stack": "mcp",
                "event_handlers": [
                    {
                        "event_pattern": "mcp_client_connected",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "list_tools"
                            }]
                        }
                    },
                    {
                        "event_pattern": "mcp_response_received",
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
impl Client for McpClientProtocol {
    fn connect(
        &self,
        ctx: crate::protocol::ConnectContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::client::mcp::McpClient;
            McpClient::connect_with_llm_actions(
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
            "list_resources" => Ok(ClientActionResult::Custom {
                name: "mcp_list_resources".to_string(),
                data: json!({}),
            }),
            "read_resource" => {
                let uri = action
                    .get("uri")
                    .and_then(|v| v.as_str())
                    .context("Missing 'uri' field")?
                    .to_string();

                Ok(ClientActionResult::Custom {
                    name: "mcp_read_resource".to_string(),
                    data: json!({
                        "uri": uri
                    }),
                })
            }
            "list_tools" => Ok(ClientActionResult::Custom {
                name: "mcp_list_tools".to_string(),
                data: json!({}),
            }),
            "call_tool" => {
                let name = action
                    .get("name")
                    .and_then(|v| v.as_str())
                    .context("Missing 'name' field")?
                    .to_string();

                let arguments = action.get("arguments").and_then(|v| v.as_object()).cloned();

                Ok(ClientActionResult::Custom {
                    name: "mcp_call_tool".to_string(),
                    data: json!({
                        "name": name,
                        "arguments": arguments
                    }),
                })
            }
            "list_prompts" => Ok(ClientActionResult::Custom {
                name: "mcp_list_prompts".to_string(),
                data: json!({}),
            }),
            "get_prompt" => {
                let name = action
                    .get("name")
                    .and_then(|v| v.as_str())
                    .context("Missing 'name' field")?
                    .to_string();

                let arguments = action.get("arguments").and_then(|v| v.as_object()).cloned();

                Ok(ClientActionResult::Custom {
                    name: "mcp_get_prompt".to_string(),
                    data: json!({
                        "name": name,
                        "arguments": arguments
                    }),
                })
            }
            "disconnect" => Ok(ClientActionResult::Disconnect),
            _ => Err(anyhow::anyhow!(
                "Unknown MCP client action: {}",
                action_type
            )),
        }
    }
}
