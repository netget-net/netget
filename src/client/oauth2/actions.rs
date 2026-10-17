//! OAuth2 client protocol actions implementation

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

/// OAuth2 client connected event
pub static OAUTH2_CLIENT_CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "oauth2_connected",
        "OAuth2 client initialized and ready to authenticate",
        json!({
            "type": "refresh_token"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "token_url".to_string(),
            type_hint: "string".to_string(),
            description: "OAuth2 token endpoint URL".to_string(),
            required: true,
        },
        Parameter {
            name: "auth_url".to_string(),
            type_hint: "string".to_string(),
            description: "OAuth2 authorization endpoint URL (optional)".to_string(),
            required: false,
        },
    ])
});

/// OAuth2 token obtained event
pub static OAUTH2_TOKEN_OBTAINED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "oauth2_token_obtained",
        "OAuth2 access token successfully obtained",
        json!({
            "type": "refresh_token"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "access_token".to_string(),
            type_hint: "string".to_string(),
            description: "The access token (redacted for security)".to_string(),
            required: true,
        },
        Parameter {
            name: "token_type".to_string(),
            type_hint: "string".to_string(),
            description: "Token type (usually 'Bearer')".to_string(),
            required: true,
        },
        Parameter {
            name: "expires_in".to_string(),
            type_hint: "number".to_string(),
            description: "Token expiration time in seconds".to_string(),
            required: false,
        },
        Parameter {
            name: "refresh_token".to_string(),
            type_hint: "string".to_string(),
            description: "Refresh token (redacted for security)".to_string(),
            required: false,
        },
        Parameter {
            name: "scope".to_string(),
            type_hint: "string".to_string(),
            description: "Granted scopes".to_string(),
            required: false,
        },
    ])
});

/// OAuth2 device code flow started event
pub static OAUTH2_DEVICE_CODE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "oauth2_device_code_started",
        "Device code flow initiated, user needs to visit URL",
        json!({
            "type": "refresh_token"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "verification_uri".to_string(),
            type_hint: "string".to_string(),
            description: "URL the user must visit".to_string(),
            required: true,
        },
        Parameter {
            name: "user_code".to_string(),
            type_hint: "string".to_string(),
            description: "Code the user must enter".to_string(),
            required: true,
        },
        Parameter {
            name: "device_code".to_string(),
            type_hint: "string".to_string(),
            description: "Device code for polling (internal)".to_string(),
            required: true,
        },
        Parameter {
            name: "interval".to_string(),
            type_hint: "number".to_string(),
            description: "Polling interval in seconds".to_string(),
            required: false,
        },
    ])
});

/// OAuth2 token error event
pub static OAUTH2_ERROR_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "oauth2_error",
        "OAuth2 authentication error occurred",
        json!({"type": "placeholder", "event_id": "oauth2_error"}),
    )
    .with_parameters(vec![
        Parameter {
            name: "error".to_string(),
            type_hint: "string".to_string(),
            description: "Error code".to_string(),
            required: true,
        },
        Parameter {
            name: "error_description".to_string(),
            type_hint: "string".to_string(),
            description: "Human-readable error description".to_string(),
            required: false,
        },
    ])
});

/// OAuth2 client protocol action handler
pub struct OAuth2ClientProtocol;

impl OAuth2ClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for OAuth2ClientProtocol {
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "client_id".to_string(),
                description: "OAuth2 client ID".to_string(),
                type_hint: "string".to_string(),
                required: true,
                example: json!("my-client-id"),
                default: None,
            },
            ParameterDefinition {
                name: "client_secret".to_string(),
                description: "OAuth2 client secret".to_string(),
                type_hint: "string".to_string(),
                required: false,
                example: json!("my-client-secret"),
                default: None,
            },
            ParameterDefinition {
                name: "auth_url".to_string(),
                description: "OAuth2 authorization endpoint URL".to_string(),
                type_hint: "string".to_string(),
                required: false,
                example: json!("https://provider.com/oauth/authorize"),
                default: None,
            },
            ParameterDefinition {
                name: "token_url".to_string(),
                description: "OAuth2 token endpoint URL".to_string(),
                type_hint: "string".to_string(),
                required: true,
                example: json!("https://provider.com/oauth/token"),
                default: None,
            },
            ParameterDefinition {
                name: "scopes".to_string(),
                description: "OAuth2 scopes to request (space-separated or array)".to_string(),
                type_hint: "string".to_string(),
                required: false,
                example: json!("read write"),
                default: None,
            },
        ]
    }
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![
                ActionDefinition {
                    name: "exchange_password".to_string(),
                    description: "Exchange username/password for access token (Resource Owner Password Credentials flow)".to_string(),
                    parameters: vec![
                        Parameter {
                            name: "username".to_string(),
                            type_hint: "string".to_string(),
                            description: "Username".to_string(),
                            required: true,
                        },
                        Parameter {
                            name: "password".to_string(),
                            type_hint: "string".to_string(),
                            description: "Password".to_string(),
                            required: true,
                        },
                        Parameter {
                            name: "scopes".to_string(),
                            type_hint: "string".to_string(),
                            description: "Space-separated scopes".to_string(),
                            required: false,
                        },
                    ],
                    example: json!({
                        "type": "exchange_password",
                        "username": "user@example.com",
                        "password": "secret123",
                        "scopes": "read write"
                    }),
                log_template: None,
                },
                ActionDefinition {
                    name: "exchange_client_credentials".to_string(),
                    description: "Exchange client credentials for access token (Client Credentials flow)".to_string(),
                    parameters: vec![
                        Parameter {
                            name: "scopes".to_string(),
                            type_hint: "string".to_string(),
                            description: "Space-separated scopes".to_string(),
                            required: false,
                        },
                    ],
                    example: json!({
                        "type": "exchange_client_credentials",
                        "scopes": "api.read api.write"
                    }),
                log_template: None,
                },
                ActionDefinition {
                    name: "start_device_code_flow".to_string(),
                    description: "Start device code flow for CLI authentication".to_string(),
                    parameters: vec![
                        Parameter {
                            name: "scopes".to_string(),
                            type_hint: "string".to_string(),
                            description: "Space-separated scopes".to_string(),
                            required: false,
                        },
                    ],
                    example: json!({
                        "type": "start_device_code_flow",
                        "scopes": "read"
                    }),
                log_template: None,
                },
                ActionDefinition {
                    name: "poll_device_code".to_string(),
                    description: "Poll for device code flow completion (internal, called automatically)".to_string(),
                    parameters: vec![],
                    example: json!({
                        "type": "poll_device_code"
                    }),
                log_template: None,
                },
                ActionDefinition {
                    name: "refresh_token".to_string(),
                    description: "Refresh access token using refresh token".to_string(),
                    parameters: vec![],
                    example: json!({
                        "type": "refresh_token"
                    }),
                log_template: None,
                },
                ActionDefinition {
                    name: "generate_auth_url".to_string(),
                    description: "Generate authorization URL for authorization code flow".to_string(),
                    parameters: vec![
                        Parameter {
                            name: "scopes".to_string(),
                            type_hint: "string".to_string(),
                            description: "Space-separated scopes".to_string(),
                            required: false,
                        },
                        Parameter {
                            name: "redirect_uri".to_string(),
                            type_hint: "string".to_string(),
                            description: "Redirect URI (e.g., http://localhost:8080/callback)".to_string(),
                            required: false,
                        },
                    ],
                    example: json!({
                        "type": "generate_auth_url",
                        "scopes": "read write",
                        "redirect_uri": "http://localhost:8080/callback"
                    }),
                log_template: None,
                },
                ActionDefinition {
                    name: "exchange_code".to_string(),
                    description: "Exchange authorization code for access token".to_string(),
                    parameters: vec![
                        Parameter {
                            name: "code".to_string(),
                            type_hint: "string".to_string(),
                            description: "Authorization code from callback".to_string(),
                            required: true,
                        },
                    ],
                    example: json!({
                        "type": "exchange_code",
                        "code": "auth-code-here"
                    }),
                log_template: None,
                },
                ActionDefinition {
                    name: "disconnect".to_string(),
                    description: "Disconnect OAuth2 client".to_string(),
                    parameters: vec![],
                    example: json!({
                        "type": "disconnect"
                    }),
                log_template: None,
                },
            ]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        // OAuth2 is typically request-response, so sync actions are the same as async
        vec![ActionDefinition {
            name: "refresh_token".to_string(),
            description: "Refresh access token in response to token expiration".to_string(),
            parameters: vec![],
            example: json!({
                "type": "refresh_token"
            }),
            log_template: None,
        }]
    }
    fn protocol_name(&self) -> &'static str {
        "OAuth2"
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            EventType::new(
                "oauth2_connected",
                "Triggered when OAuth2 client is initialized",
                json!({"type": "placeholder", "event_id": "oauth2_connected"}),
            ),
            EventType::new(
                "oauth2_token_obtained",
                "Triggered when access token is obtained",
                json!({"type": "placeholder", "event_id": "oauth2_token_obtained"}),
            ),
            EventType::new(
                "oauth2_device_code_started",
                "Triggered when device code flow is initiated",
                json!({"type": "placeholder", "event_id": "oauth2_device_code_started"}),
            ),
            EventType::new(
                "oauth2_error",
                "Triggered when OAuth2 error occurs",
                json!({"type": "placeholder", "event_id": "oauth2_error"}),
            ),
        ]
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>HTTP>OAuth2"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "oauth2",
            "oauth",
            "authentication",
            "access token",
            "oauth2 client",
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .implementation(
                "oauth2 crate 4.4 for the password, client-credentials and \
                     authorization-code flows; device code (RFC 8628) by direct HTTP, which \
                     the crate does not expose. token_url is required and connect() refuses \
                     without it, so the SDK's own endpoint defaults can never decide where \
                     traffic goes.",
            )
            .llm_control("Which flow to run, when to refresh, and what to do with the result")
            .e2e_testing(
                "tests/client/oauth2/command_channel_test.rs drives the injected-action \
                     path against a provider served in-process, and is the only part that \
                     runs. Four of the five tests in e2e_test.rs are #[ignore]d for Ollama \
                     AND carry a skip-when-missing gate on the `mcp` feature (for axum), so \
                     they are a silent pass twice over; the fifth is a construction smoke \
                     test that contacts nothing.",
            )
            .notes(
                "Tokens reach the model only as \"[REDACTED]\" - the values live in \
                     protocol_data and the actions read them back. No token is verified: an \
                     access token is an opaque string to this client.",
            )
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn description(&self) -> &'static str {
        "OAuth2 client for authentication and token management"
    }
    fn example_prompt(&self) -> &'static str {
        "Authenticate with OAuth2 using password flow: username 'user@example.com', password 'secret'"
    }
    fn group_name(&self) -> &'static str {
        "Authentication"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        use serde_json::json;

        StartupExamples::new(
            // LLM mode: LLM handles OAuth2 flows intelligently
            json!({
                "type": "open_client",
                "remote_addr": "https://provider.example.com/oauth",
                "base_stack": "oauth2",
                "instruction": "Authenticate using client credentials flow to get an access token",
                "startup_params": {
                    "client_id": "my-client-id",
                    "client_secret": "my-client-secret",
                    "token_url": "https://provider.example.com/oauth/token"
                }
            }),
            // Script mode: Code-based OAuth2 handling
            json!({
                "type": "open_client",
                "remote_addr": "https://provider.example.com/oauth",
                "base_stack": "oauth2",
                "startup_params": {
                    "client_id": "my-client-id",
                    "token_url": "https://provider.example.com/oauth/token"
                },
                "event_handlers": [{
                    "event_pattern": "oauth2_connected",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "<oauth2_client_handler>"
                    }
                }]
            }),
            // Static mode: Fixed OAuth2 action
            json!({
                "type": "open_client",
                "remote_addr": "https://provider.example.com/oauth",
                "base_stack": "oauth2",
                "startup_params": {
                    "client_id": "my-client-id",
                    "client_secret": "my-client-secret",
                    "token_url": "https://provider.example.com/oauth/token"
                },
                "event_handlers": [{
                    "event_pattern": "oauth2_connected",
                    "handler": {
                        "type": "static",
                        "actions": [{
                            "type": "exchange_client_credentials",
                            "scopes": "api.read api.write"
                        }]
                    }
                }]
            }),
        )
    }
}

// Implement Client trait (client-specific functionality)
impl Client for OAuth2ClientProtocol {
    fn connect(
        &self,
        ctx: crate::protocol::ConnectContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::client::oauth2::OAuth2Client;
            OAuth2Client::connect_with_llm_actions(
                ctx.remote_addr,
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.client_id,
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
            "exchange_password" => {
                let username = action
                    .get("username")
                    .and_then(|v| v.as_str())
                    .context("Missing 'username' field")?
                    .to_string();

                let password = action
                    .get("password")
                    .and_then(|v| v.as_str())
                    .context("Missing 'password' field")?
                    .to_string();

                let scopes = action
                    .get("scopes")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());

                Ok(ClientActionResult::Custom {
                    name: "oauth2_exchange_password".to_string(),
                    data: json!({
                        "username": username,
                        "password": password,
                        "scopes": scopes,
                    }),
                })
            }
            "exchange_client_credentials" => {
                let scopes = action
                    .get("scopes")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());

                Ok(ClientActionResult::Custom {
                    name: "oauth2_exchange_client_credentials".to_string(),
                    data: json!({
                        "scopes": scopes,
                    }),
                })
            }
            "start_device_code_flow" => {
                let scopes = action
                    .get("scopes")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());

                Ok(ClientActionResult::Custom {
                    name: "oauth2_start_device_code".to_string(),
                    data: json!({
                        "scopes": scopes,
                    }),
                })
            }
            "poll_device_code" => Ok(ClientActionResult::Custom {
                name: "oauth2_poll_device_code".to_string(),
                data: json!({}),
            }),
            "refresh_token" => Ok(ClientActionResult::Custom {
                name: "oauth2_refresh_token".to_string(),
                data: json!({}),
            }),
            "generate_auth_url" => {
                let scopes = action
                    .get("scopes")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());

                let redirect_uri = action
                    .get("redirect_uri")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());

                Ok(ClientActionResult::Custom {
                    name: "oauth2_generate_auth_url".to_string(),
                    data: json!({
                        "scopes": scopes,
                        "redirect_uri": redirect_uri,
                    }),
                })
            }
            "exchange_code" => {
                let code = action
                    .get("code")
                    .and_then(|v| v.as_str())
                    .context("Missing 'code' field")?
                    .to_string();

                Ok(ClientActionResult::Custom {
                    name: "oauth2_exchange_code".to_string(),
                    data: json!({
                        "code": code,
                    }),
                })
            }
            "disconnect" => Ok(ClientActionResult::Disconnect),
            _ => Err(anyhow::anyhow!(
                "Unknown OAuth2 client action: {}",
                action_type
            )),
        }
    }
}
