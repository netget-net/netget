//! WireGuard client protocol actions implementation

use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, Parameter, ParameterDefinition,
};
use crate::protocol::EventType;
use crate::state::app_state::AppState;
use anyhow::{Context, Result};
use serde_json::json;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::LazyLock;

/// WireGuard client connected event
pub static WIREGUARD_CLIENT_CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "wireguard_connected",
        "WireGuard client successfully connected to VPN server",
        json!({}),
    )
    .with_parameters(vec![
        Parameter {
            name: "server_endpoint".to_string(),
            type_hint: "string".to_string(),
            description: "VPN server endpoint (IP:port)".to_string(),
            required: true,
        },
        Parameter {
            name: "client_public_key".to_string(),
            type_hint: "string".to_string(),
            description: "Client's WireGuard public key".to_string(),
            required: true,
        },
        Parameter {
            name: "client_address".to_string(),
            type_hint: "string".to_string(),
            description: "Client's VPN IP address".to_string(),
            required: true,
        },
    ])
});

/// WireGuard client disconnected event
pub static WIREGUARD_CLIENT_DISCONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "wireguard_disconnected",
        "WireGuard client disconnected from VPN server",
        json!({}),
    )
    .with_parameters(vec![Parameter {
        name: "reason".to_string(),
        type_hint: "string".to_string(),
        description: "Disconnection reason".to_string(),
        required: true,
    }])
});

/// WireGuard client protocol action handler
pub struct WireguardClientProtocol;

impl WireguardClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

// Implement Protocol trait (base trait for all protocols)
impl Protocol for WireguardClientProtocol {
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![
            ActionDefinition {
                name: "get_connection_status".to_string(),
                description: "Get current WireGuard connection status and statistics".to_string(),
                parameters: vec![],
                example: json!({
                    "type": "get_connection_status"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "disconnect".to_string(),
                description: "Disconnect from the WireGuard VPN server".to_string(),
                parameters: vec![],
                example: json!({
                    "type": "disconnect"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "get_client_info".to_string(),
                description: "Get WireGuard client configuration information".to_string(),
                parameters: vec![],
                example: json!({
                    "type": "get_client_info"
                }),
                log_template: None,
            },
        ]
    }

    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        // WireGuard doesn't have sync actions (no immediate response to network events)
        vec![]
    }

    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            WIREGUARD_CLIENT_CONNECTED_EVENT.clone(),
            WIREGUARD_CLIENT_DISCONNECTED_EVENT.clone(),
        ]
    }

    fn protocol_name(&self) -> &'static str {
        "wireguard"
    }

    fn stack_name(&self) -> &'static str {
        "VPN"
    }

    fn keywords(&self) -> Vec<&'static str> {
        vec!["wireguard", "wg", "vpn client", "wireguard client"]
    }

    /// On macOS `defguard_wireguard_rs` brings the interface up by running `wireguard-go`.
    ///
    /// Same reasoning as the server half (`src/server/wireguard/actions.rs`): the kernel
    /// implements WireGuard on Linux, FreeBSD and Windows, macOS does not, and there defguard
    /// shells out to a userspace binary that must be installed separately.
    #[cfg(target_os = "macos")]
    fn get_dependencies(&self) -> Vec<crate::protocol::dependencies::ProtocolDependency> {
        let mut deps =
            crate::llm::actions::protocol_trait::default_dependencies_from_privilege(self);
        deps.push(crate::protocol::dependencies::ProtocolDependency::ToolInPath("wireguard-go"));
        deps
    }

    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{
            DevelopmentState, PrivilegeRequirement, ProtocolMetadataV2,
        };

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .implementation("defguard_wireguard_rs with kernel/userspace backend")
            .llm_control("VPN connection control, status queries")
            .e2e_testing("WireGuard server for client connections")
            .privilege_requirement(PrivilegeRequirement::Root)
            .notes("Requires root/CAP_NET_ADMIN on Linux, userspace on macOS")
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }

    fn description(&self) -> &'static str {
        "WireGuard VPN client for secure tunneling"
    }

    fn example_prompt(&self) -> &'static str {
        "Connect to WireGuard VPN at 1.2.3.4:51820 with server public key abc123..."
    }

    fn group_name(&self) -> &'static str {
        "VPN"
    }

    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "server_public_key".to_string(),
                type_hint: "string".to_string(),
                description: "WireGuard server's public key (base64 encoded)".to_string(),
                required: true,
                example: json!("xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg="),
                default: None,
            },
            ParameterDefinition {
                name: "server_endpoint".to_string(),
                type_hint: "string".to_string(),
                description: "Server endpoint IP:port (e.g., 1.2.3.4:51820)".to_string(),
                required: true,
                example: json!("1.2.3.4:51820"),
                default: None,
            },
            ParameterDefinition {
                name: "client_address".to_string(),
                type_hint: "string".to_string(),
                description: "Client's VPN IP address with CIDR (e.g., 10.20.30.2/32)".to_string(),
                required: true,
                example: json!("10.20.30.2/32"),
                default: None,
            },
            ParameterDefinition {
                name: "allowed_ips".to_string(),
                type_hint: "array".to_string(),
                description: "IP ranges to route through VPN (default: 0.0.0.0/0 for all traffic)"
                    .to_string(),
                required: false,
                example: json!(["0.0.0.0/0", "::/0"]),
                default: None,
            },
            ParameterDefinition {
                name: "keepalive".to_string(),
                type_hint: "integer".to_string(),
                description: "Persistent keepalive interval in seconds (optional)".to_string(),
                required: false,
                example: json!(25),
                default: None,
            },
            ParameterDefinition {
                name: "private_key".to_string(),
                type_hint: "string".to_string(),
                description: "Client private key (base64). If not provided, will be generated."
                    .to_string(),
                required: false,
                example: json!("YAnz5TF+lXXJte14tji3zlMNftft3YEPi775qQV8mno="),
                default: None,
            },
        ]
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        use serde_json::json;

        StartupExamples::new(
            // LLM mode: LLM controls VPN connection and status
            json!({
                "type": "open_client",
                "remote_addr": "1.2.3.4:51820",
                "base_stack": "wireguard",
                "instruction": "Connect to VPN and check connection status",
                "startup_params": {
                    "server_public_key": "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=",
                    "server_endpoint": "1.2.3.4:51820",
                    "client_address": "10.20.30.2/32"
                }
            }),
            // Script mode: Code-based VPN event handling
            json!({
                "type": "open_client",
                "remote_addr": "1.2.3.4:51820",
                "base_stack": "wireguard",
                "startup_params": {
                    "server_public_key": "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=",
                    "server_endpoint": "1.2.3.4:51820",
                    "client_address": "10.20.30.2/32"
                },
                "event_handlers": [{
                    "event_pattern": "wireguard_connected",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "<wireguard_client_handler>"
                    }
                }]
            }),
            // Static mode: Fixed VPN connection (stays connected)
            json!({
                "type": "open_client",
                "remote_addr": "1.2.3.4:51820",
                "base_stack": "wireguard",
                "startup_params": {
                    "server_public_key": "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=",
                    "server_endpoint": "1.2.3.4:51820",
                    "client_address": "10.20.30.2/32",
                    "keepalive": 25
                },
                "event_handlers": [
                    {
                        "event_pattern": "wireguard_connected",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "get_connection_status"
                            }]
                        }
                    }
                ]
            }),
        )
    }
}

// Implement Client trait (client-specific functionality)
impl Client for WireguardClientProtocol {
    fn connect(
        &self,
        ctx: crate::protocol::ConnectContext,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<SocketAddr>> + Send>> {
        Box::pin(async move {
            use crate::client::wireguard::WireguardClient;

            // Parse startup params - should be in JSON format in startup_params
            let params = if let Some(startup_params) = &ctx.startup_params {
                // Get required parameters using StartupParams accessors
                crate::client::wireguard::WireguardClientParams {
                    server_public_key: startup_params.get_string("server_public_key")?,
                    server_endpoint: startup_params.get_string("server_endpoint")?,
                    client_address: startup_params.get_string("client_address")?,
                    allowed_ips: startup_params
                        .get_optional_array("allowed_ips")?
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                                .collect()
                        })
                        .unwrap_or_else(|| vec!["0.0.0.0/0".to_string()]),
                    keepalive: startup_params
                        .get_optional_u64("keepalive")?
                        .map(|k| u16::try_from(k).context("WireGuard keepalive exceeds u16"))
                        .transpose()?,
                    private_key: startup_params.get_optional_string("private_key")?,
                }
            } else {
                return Err(anyhow::anyhow!(
                    "Missing startup parameters for WireGuard client"
                ));
            };

            WireguardClient::connect_with_llm_actions(
                ctx.remote_addr,
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.client_id,
                params,
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
            "get_connection_status" => Ok(ClientActionResult::Custom {
                name: "wireguard_get_status".to_string(),
                data: json!({}),
            }),
            "disconnect" => Ok(ClientActionResult::Disconnect),
            "get_client_info" => Ok(ClientActionResult::Custom {
                name: "wireguard_get_info".to_string(),
                data: json!({}),
            }),
            _ => Err(anyhow::anyhow!("Unknown action type: {}", action_type)),
        }
    }
}
