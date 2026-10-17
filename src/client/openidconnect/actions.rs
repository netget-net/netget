//! OpenID Connect client protocol actions implementation

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

/// OpenID Connect client discovered configuration event
pub static OIDC_CLIENT_DISCOVERED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "oidc_discovered",
        "OpenID Connect provider configuration discovered",
        json!({
            "type": "fetch_userinfo"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "issuer".to_string(),
            type_hint: "string".to_string(),
            description: "OpenID Connect provider issuer URL".to_string(),
            required: true,
        },
        Parameter {
            name: "authorization_endpoint".to_string(),
            type_hint: "string".to_string(),
            description: "Authorization endpoint URL".to_string(),
            required: true,
        },
        Parameter {
            name: "token_endpoint".to_string(),
            type_hint: "string".to_string(),
            description: "Token endpoint URL".to_string(),
            required: true,
        },
        Parameter {
            name: "userinfo_endpoint".to_string(),
            type_hint: "string".to_string(),
            description: "UserInfo endpoint URL".to_string(),
            required: false,
        },
        Parameter {
            name: "supported_scopes".to_string(),
            type_hint: "array".to_string(),
            description: "Supported OAuth scopes".to_string(),
            required: false,
        },
    ])
});

/// OpenID Connect client token received event
pub static OIDC_CLIENT_TOKEN_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "oidc_token_received",
        "OAuth/OIDC tokens received from provider",
        json!({
            "type": "fetch_userinfo"
        }),
    )
    .with_parameters(vec![
        // The three secrets are reported as `[REDACTED]` (or `""` when absent), never
        // verbatim: the client stores them in `protocol_data` and every action that needs one
        // reads it back, so the model has no use for the value and putting it here copied a
        // live bearer token into the LLM prompt, the log file and the status stream.
        Parameter {
            name: "access_token".to_string(),
            type_hint: "string".to_string(),
            description: "\"[REDACTED]\" - an access token was received. The value is held by \
                          the client; name it in an action (fetch_userinfo, validate_token) \
                          rather than trying to repeat it."
                .to_string(),
            required: true,
        },
        Parameter {
            name: "id_token".to_string(),
            type_hint: "string".to_string(),
            description: "\"[REDACTED]\" if the provider returned an ID token, \"\" if not. \
                          NetGet does not verify its signature, issuer, audience or nonce."
                .to_string(),
            required: false,
        },
        Parameter {
            name: "refresh_token".to_string(),
            type_hint: "string".to_string(),
            description: "\"[REDACTED]\" if a refresh token was received, \"\" if not. Use the \
                          refresh_token action; the value itself is held by the client."
                .to_string(),
            required: false,
        },
        Parameter {
            name: "expires_in".to_string(),
            type_hint: "number".to_string(),
            description: "Token expiration time in seconds".to_string(),
            required: false,
        },
        Parameter {
            name: "token_type".to_string(),
            type_hint: "string".to_string(),
            description: "Token type (usually 'Bearer')".to_string(),
            required: true,
        },
    ])
});

/// OpenID Connect client userinfo received event
pub static OIDC_CLIENT_USERINFO_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "oidc_userinfo_received",
        "UserInfo data received from OpenID Connect provider",
        json!({
            "type": "refresh_token"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "sub".to_string(),
            type_hint: "string".to_string(),
            description: "Subject identifier (user ID)".to_string(),
            required: true,
        },
        Parameter {
            name: "claims".to_string(),
            type_hint: "object".to_string(),
            description: "User claims (name, email, etc.)".to_string(),
            required: true,
        },
    ])
});

/// OpenID Connect client protocol action handler
pub struct OpenIdConnectClientProtocol;

impl OpenIdConnectClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for OpenIdConnectClientProtocol {
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
                ParameterDefinition {
                    name: "client_id".to_string(),
                    description: "OAuth2/OIDC client ID".to_string(),
                    type_hint: "string".to_string(),
                    required: true,
                    example: json!("my-application-id"),
                    default: None,
                },
                ParameterDefinition {
                    name: "client_secret".to_string(),
                    description: "OAuth2/OIDC client secret (if using confidential client)".to_string(),
                    type_hint: "string".to_string(),
                    required: false,
                    example: json!("secret-key-12345"),
                    default: None,
                },
                ParameterDefinition {
                    name: "redirect_uri".to_string(),
                    description: "OAuth2 redirect URI for authorization code flow".to_string(),
                    type_hint: "string".to_string(),
                    required: false,
                    example: json!("http://localhost:8080/callback"),
                    default: None,
                },
                ParameterDefinition {
                    name: "scopes".to_string(),
                    description: "OAuth2 scopes to request (space-separated)".to_string(),
                    type_hint: "string".to_string(),
                    required: false,
                    example: json!("openid profile email"),
                    default: None,
                },
                ParameterDefinition {
                    name: "flow".to_string(),
                    description: "OAuth2/OIDC flow type (device_code, password, client_credentials, authorization_code)".to_string(),
                    type_hint: "string".to_string(),
                    required: false,
                    example: json!("device_code"),
                    default: None,
                },
            ]
    }
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![
                ActionDefinition {
                    name: "discover_configuration".to_string(),
                    description: "Discover OpenID Connect provider configuration from .well-known/openid-configuration".to_string(),
                    parameters: vec![],
                    example: json!({
                        "type": "discover_configuration"
                    }),
                log_template: None,
                },
                ActionDefinition {
                    name: "start_device_flow".to_string(),
                    description: "Start OAuth2 device code flow for CLI authentication".to_string(),
                    parameters: vec![
                        Parameter {
                            name: "scopes".to_string(),
                            type_hint: "string".to_string(),
                            description: "Space-separated OAuth scopes".to_string(),
                            required: false,
                        },
                    ],
                    example: json!({
                        "type": "start_device_flow",
                        "scopes": "openid profile email"
                    }),
                log_template: None,
                },
                ActionDefinition {
                    name: "start_authorization_code_flow".to_string(),
                    description: "Start OAuth2 authorization code flow with local HTTP callback server".to_string(),
                    parameters: vec![
                        Parameter {
                            name: "scopes".to_string(),
                            type_hint: "string".to_string(),
                            description: "Space-separated OAuth scopes".to_string(),
                            required: false,
                        },
                        Parameter {
                            name: "port".to_string(),
                            type_hint: "number".to_string(),
                            description: "Local callback server port (default: 8080)".to_string(),
                            required: false,
                        },
                    ],
                    example: json!({
                        "type": "start_authorization_code_flow",
                        "scopes": "openid profile email",
                        "port": 8080
                    }),
                log_template: None,
                },
                ActionDefinition {
                    name: "exchange_password".to_string(),
                    description: "Exchange username/password for tokens (Resource Owner Password Credentials flow)".to_string(),
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
                            description: "Space-separated OAuth scopes".to_string(),
                            required: false,
                        },
                    ],
                    example: json!({
                        "type": "exchange_password",
                        "username": "user@example.com",
                        "password": "secret123",
                        "scopes": "openid profile"
                    }),
                log_template: None,
                },
                ActionDefinition {
                    name: "exchange_client_credentials".to_string(),
                    description: "Exchange client credentials for access token (machine-to-machine)".to_string(),
                    parameters: vec![
                        Parameter {
                            name: "scopes".to_string(),
                            type_hint: "string".to_string(),
                            description: "Space-separated OAuth scopes".to_string(),
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
                    name: "refresh_token".to_string(),
                    description: "Refresh access token using refresh token".to_string(),
                    parameters: vec![],
                    example: json!({
                        "type": "refresh_token"
                    }),
                log_template: None,
                },
                ActionDefinition {
                    name: "fetch_userinfo".to_string(),
                    description: "Fetch user information from UserInfo endpoint using access token".to_string(),
                    parameters: vec![],
                    example: json!({
                        "type": "fetch_userinfo"
                    }),
                log_template: None,
                },
                ActionDefinition {
                    name: "disconnect".to_string(),
                    description: "Disconnect from the OpenID Connect provider".to_string(),
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
                name: "fetch_userinfo".to_string(),
                description: "Fetch user information after receiving tokens".to_string(),
                parameters: vec![],
                example: json!({
                    "type": "fetch_userinfo"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "refresh_token".to_string(),
                description: "Refresh access token in response to expiration".to_string(),
                parameters: vec![],
                example: json!({
                    "type": "refresh_token"
                }),
                log_template: None,
            },
        ]
    }
    fn protocol_name(&self) -> &'static str {
        "OpenIDConnect"
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            EventType::new(
                "oidc_discovered",
                "Triggered when OIDC provider configuration is discovered",
                json!({"type": "placeholder", "event_id": "oidc_discovered"}),
            ),
            EventType::new(
                "oidc_token_received",
                "Triggered when OAuth/OIDC tokens are received",
                json!({"type": "placeholder", "event_id": "oidc_token_received"}),
            ),
            EventType::new(
                "oidc_userinfo_received",
                "Triggered when UserInfo data is received",
                json!({"type": "placeholder", "event_id": "oidc_userinfo_received"}),
            ),
        ]
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>HTTP>OIDC"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["openidconnect", "oidc", "openid connect", "oauth2 client"]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .implementation(
                "openidconnect 3.5. Discovery, authorization-code, device-code, password \
                     and client-credentials flows are driven; tokens are stored opaquely and \
                     nothing about them is verified.",
            )
            .llm_control("Which flow to run, when to refresh, and what to do with the result")
            .e2e_testing(
                "tests/client/openidconnect/command_channel_test.rs drives the \
                     injected-action path with no provider. The five tests in e2e_test.rs are \
                     #[ignore]d because they point at the real accounts.google.com and need \
                     --use-ollama, so they run nowhere and prove nothing.",
            )
            .notes(
                "No ID token is verified. The openidconnect crate can check a JWT's \
                     signature, issuer, audience and nonce through id_token.claims(..); this \
                     client never calls it and stores the token as an opaque string, so a \
                     forged or expired id_token is accepted exactly as readily as a genuine \
                     one. Access, refresh and ID tokens reach the model only as \"[REDACTED]\".",
            )
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn description(&self) -> &'static str {
        "OpenID Connect client for OAuth2/OIDC authentication"
    }
    fn example_prompt(&self) -> &'static str {
        "Connect to OpenID Connect provider at https://accounts.google.com and authenticate"
    }
    fn group_name(&self) -> &'static str {
        "Authentication"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        use serde_json::json;

        StartupExamples::new(
            // LLM mode: LLM controls OIDC authentication flow
            json!({
                "type": "open_client",
                "remote_addr": "https://accounts.google.com",
                "base_stack": "openidconnect",
                "instruction": "Discover configuration and start device code authentication",
                "startup_params": {
                    "client_id": "my-application-id",
                    "scopes": "openid profile email"
                }
            }),
            // Script mode: Code-based OIDC token handling
            json!({
                "type": "open_client",
                "remote_addr": "https://accounts.google.com",
                "base_stack": "openidconnect",
                "startup_params": {
                    "client_id": "my-application-id"
                },
                "event_handlers": [{
                    "event_pattern": "oidc_token_received",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "<oidc_client_handler>"
                    }
                }]
            }),
            // Static mode: Fixed OIDC discovery and userinfo flow
            json!({
                "type": "open_client",
                "remote_addr": "https://accounts.google.com",
                "base_stack": "openidconnect",
                "startup_params": {
                    "client_id": "my-application-id",
                    "scopes": "openid profile email"
                },
                "event_handlers": [
                    {
                        "event_pattern": "oidc_discovered",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "start_device_flow",
                                "scopes": "openid profile email"
                            }]
                        }
                    },
                    {
                        "event_pattern": "oidc_token_received",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "fetch_userinfo"
                            }]
                        }
                    },
                    {
                        "event_pattern": "oidc_userinfo_received",
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
impl Client for OpenIdConnectClientProtocol {
    fn connect(
        &self,
        ctx: crate::protocol::ConnectContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::client::openidconnect::OpenIdConnectClient;
            OpenIdConnectClient::connect_with_llm_actions(
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
            "discover_configuration" => Ok(ClientActionResult::Custom {
                name: "oidc_discover".to_string(),
                data: json!({}),
            }),
            "start_device_flow" => {
                let scopes = action
                    .get("scopes")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());

                Ok(ClientActionResult::Custom {
                    name: "oidc_device_flow".to_string(),
                    data: json!({
                        "scopes": scopes,
                    }),
                })
            }
            "start_authorization_code_flow" => {
                let scopes = action
                    .get("scopes")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());

                // Range-check before narrowing. `as u16` wraps, so `66079` becomes `543` and
                // the redirect listener binds a port the model never named — and `65536`
                // becomes `0`, which is "pick any ephemeral port", so the redirect URI
                // registered with the provider points somewhere nothing is listening.
                let port = action.get("port").and_then(|v| v.as_u64()).unwrap_or(8080);
                if !(1..=u16::MAX as u64).contains(&port) {
                    return Err(anyhow::anyhow!(
                        "port {port} is not a TCP port (1-65535). This is the local port the \
                         authorization-code redirect is received on."
                    ));
                }
                let port = port as u16;

                Ok(ClientActionResult::Custom {
                    name: "oidc_authorization_code".to_string(),
                    data: json!({
                        "scopes": scopes,
                        "port": port,
                    }),
                })
            }
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
                    name: "oidc_password_flow".to_string(),
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
                    name: "oidc_client_credentials".to_string(),
                    data: json!({
                        "scopes": scopes,
                    }),
                })
            }
            "refresh_token" => Ok(ClientActionResult::Custom {
                name: "oidc_refresh_token".to_string(),
                data: json!({}),
            }),
            "fetch_userinfo" => Ok(ClientActionResult::Custom {
                name: "oidc_fetch_userinfo".to_string(),
                data: json!({}),
            }),
            "disconnect" => Ok(ClientActionResult::Disconnect),
            _ => Err(anyhow::anyhow!(
                "Unknown OpenID Connect client action: {}",
                action_type
            )),
        }
    }
}
