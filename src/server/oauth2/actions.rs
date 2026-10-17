//! OAuth2 protocol actions implementation

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

/// OAuth2 protocol action handler
pub struct OAuth2Protocol;

impl OAuth2Protocol {
    pub fn new() -> Self {
        Self
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for OAuth2Protocol {
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        // OAuth2 has no async actions - it's purely request-response
        Vec::new()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            oauth2_authorize_response_action(),
            oauth2_token_response_action(),
            oauth2_introspect_response_action(),
            oauth2_error_response_action(),
        ]
    }
    fn protocol_name(&self) -> &'static str {
        "OAuth2"
    }
    fn get_event_types(&self) -> Vec<EventType> {
        get_oauth2_event_types()
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>HTTP>OAuth2"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "oauth2",
            "oauth",
            "oauth 2.0",
            "via oauth2",
            "authorization server",
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .implementation(
                "Manual RFC 6749/7662/7009 endpoints over hyper HTTP/1.1. Simulator: tokens are \
                 opaque strings the model invents, nothing is signed, nothing is stored, and no \
                 credential is ever verified.",
            )
            .llm_control(
                "Whether to approve an authorization request, what token strings to return, and \
                 what a token introspects as. Client id/secret are handed to the model as text; \
                 the server itself checks nothing.",
            )
            .e2e_testing("reqwest HTTP client - OAuth2 flow testing")
            .notes(
                "Not an authorization server: no signing keys, no token database, no client \
                 registry, no PKCE, no TLS. Suitable for exercising OAuth2 clients and for \
                 honeypots, never for guarding anything real.",
            )
            .max_inbound_bytes(crate::server::oauth2::MAX_REQUEST_BYTES)
            .request_only("OAuth 2.0 is HTTP request/response; a server cannot send a peer anything unprompted")
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn description(&self) -> &'static str {
        "OAuth2 authorization-server simulator (LLM decides; no tokens are signed or stored)"
    }
    fn example_prompt(&self) -> &'static str {
        "Act as an OAuth2 server on port 8080. Accept client 'testapp' with secret 'secret123'. Issue tokens with 1-hour expiry."
    }
    fn group_name(&self) -> &'static str {
        "AI & API"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        use serde_json::json;

        // Deterministic: issue a fixed authorization code, echoing the client's
        // state parameter, no LLM call. This is an explicit operator decision to
        // always approve — the LLM path must instead default to refusal.
        let script = r#"import json, sys
data = json.load(sys.stdin)
event = data["event"]
if data["event_type_id"] == "oauth2_authorize":
    actions = [{"type": "oauth2_authorize_response",
                "code": "AUTH_CODE_xyz123",
                "state": event.get("state", "")}]
else:
    actions = []
print(json.dumps({"actions": actions}))"#;

        StartupExamples::new(
            // LLM mode: LLM handles OAuth2 authorization
            json!({
                "type": "open_server",
                "port": 8080,
                "base_stack": "oauth2",
                "instruction": "Act as OAuth2 authorization server. Accept client 'testapp' with secret 'secret123'. Issue tokens with 1-hour expiry."
            }),
            // Script mode: Code-based OAuth2 handling
            json!({
                "type": "open_server",
                "port": 8080,
                "base_stack": "oauth2",
                "event_handlers": [{
                    "event_pattern": "oauth2_authorize",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": script
                    }
                }]
            }),
            // Static mode: Fixed OAuth2 responses
            json!({
                "type": "open_server",
                "port": 8080,
                "base_stack": "oauth2",
                "event_handlers": [
                    {
                        "event_pattern": "oauth2_authorize",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "oauth2_authorize_response",
                                "code": "AUTH_CODE_xyz123",
                                "state": "random_state"
                            }]
                        }
                    },
                    {
                        "event_pattern": "oauth2_token",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "oauth2_token_response",
                                "access_token": "ACCESS_TOKEN_xyz123",
                                "token_type": "Bearer",
                                "expires_in": 3600
                            }]
                        }
                    }
                ]
            }),
        )
    }
}

// Implement Server trait (server-specific functionality)
impl Server for OAuth2Protocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::server::oauth2::OAuth2Server;
            OAuth2Server::spawn_with_llm_actions(
                ctx.legacy_listen_addr(),
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.server_id,
            )
            .await
        })
    }
    fn execute_action(&self, action: serde_json::Value) -> Result<ActionResult> {
        let action_type = action
            .get("type")
            .and_then(|v| v.as_str())
            .context("Missing 'type' field in action")?;

        match action_type {
            "oauth2_authorize_response" => self.execute_oauth2_authorize_response(action),
            "oauth2_token_response" => self.execute_oauth2_token_response(action),
            "oauth2_introspect_response" => self.execute_oauth2_introspect_response(action),
            "oauth2_error_response" => self.execute_oauth2_error_response(action),
            _ => Err(anyhow::anyhow!("Unknown OAuth2 action: {action_type}")),
        }
    }
}

/// Envelope key identifying which OAuth2 action produced an [`ActionResult::Output`].
///
/// Every executor below wraps its payload as `{"oauth2_result": <kind>, ...}` so the
/// HTTP layer in `mod.rs` can tell an *approval* from a *denial*. Before this existed the
/// handlers just fished a `code` field out of whatever JSON came back, so an
/// `oauth2_error_response` — the only way the model can say "no" — parsed as "no code
/// present", fell through to the hardcoded default, and the client received a redirect
/// carrying a perfectly usable authorization code. A denial silently became an approval.
pub const OAUTH2_RESULT_KEY: &str = "oauth2_result";

impl OAuth2Protocol {
    /// Execute oauth2_authorize_response sync action
    fn execute_oauth2_authorize_response(&self, action: serde_json::Value) -> Result<ActionResult> {
        let code = action
            .get("code")
            .and_then(|v| v.as_str())
            .context("Missing 'code' field")?;
        let state = action.get("state").and_then(|v| v.as_str());

        let response = json!({
            OAUTH2_RESULT_KEY: "authorize",
            "code": code,
            "state": state,
        });
        let bytes = serde_json::to_vec(&response)?;
        Ok(ActionResult::Output(bytes))
    }

    /// Execute oauth2_token_response sync action
    fn execute_oauth2_token_response(&self, action: serde_json::Value) -> Result<ActionResult> {
        let access_token = action
            .get("access_token")
            .and_then(|v| v.as_str())
            .context("Missing 'access_token' field")?;
        let token_type = action
            .get("token_type")
            .and_then(|v| v.as_str())
            .unwrap_or("Bearer");
        let expires_in = action
            .get("expires_in")
            .and_then(|v| v.as_i64())
            .unwrap_or(3600);

        let mut response = json!({
            OAUTH2_RESULT_KEY: "token",
            "access_token": access_token,
            "token_type": token_type,
            "expires_in": expires_in
        });

        // Optional fields
        if let Some(refresh_token) = action.get("refresh_token").and_then(|v| v.as_str()) {
            response["refresh_token"] = json!(refresh_token);
        }
        if let Some(scope) = action.get("scope").and_then(|v| v.as_str()) {
            response["scope"] = json!(scope);
        }

        let bytes = serde_json::to_vec(&response)?;
        Ok(ActionResult::Output(bytes))
    }

    /// Execute oauth2_introspect_response sync action
    fn execute_oauth2_introspect_response(
        &self,
        action: serde_json::Value,
    ) -> Result<ActionResult> {
        let active = action
            .get("active")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let mut response = json!({
            OAUTH2_RESULT_KEY: "introspect",
            "active": active
        });

        // If active, include additional fields
        if active {
            if let Some(scope) = action.get("scope").and_then(|v| v.as_str()) {
                response["scope"] = json!(scope);
            }
            if let Some(client_id) = action.get("client_id").and_then(|v| v.as_str()) {
                response["client_id"] = json!(client_id);
            }
            if let Some(exp) = action.get("exp").and_then(|v| v.as_i64()) {
                response["exp"] = json!(exp);
            }
            if let Some(token_type) = action.get("token_type").and_then(|v| v.as_str()) {
                response["token_type"] = json!(token_type);
            }
        }

        let bytes = serde_json::to_vec(&response)?;
        Ok(ActionResult::Output(bytes))
    }

    /// Execute oauth2_error_response sync action
    fn execute_oauth2_error_response(&self, action: serde_json::Value) -> Result<ActionResult> {
        let error = action
            .get("error")
            .and_then(|v| v.as_str())
            .context("Missing 'error' field")?;

        let mut response = json!({
            OAUTH2_RESULT_KEY: "error",
            "error": error
        });

        if let Some(error_description) = action.get("error_description").and_then(|v| v.as_str()) {
            response["error_description"] = json!(error_description);
        }
        if let Some(error_uri) = action.get("error_uri").and_then(|v| v.as_str()) {
            response["error_uri"] = json!(error_uri);
        }
        // RFC 6749 §5.2: the token/introspection endpoints answer an error with 400, except
        // invalid_client which is 401. The model may override, but the default must never be
        // the 200 that the previous code sent for every error.
        let status = action
            .get("status_code")
            .and_then(|v| v.as_u64())
            .unwrap_or(if error == "invalid_client" { 401 } else { 400 });
        response["status_code"] = json!(status);

        let bytes = serde_json::to_vec(&response)?;
        Ok(ActionResult::Output(bytes))
    }
}

// ============================================================================
// OAuth2 Action Definitions
// ============================================================================

fn oauth2_authorize_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "oauth2_authorize_response".to_string(),
        description: "Send authorization code response".to_string(),
        parameters: vec![
            Parameter {
                name: "code".to_string(),
                type_hint: "string".to_string(),
                description: "Authorization code to return".to_string(),
                required: true,
            },
            Parameter {
                name: "state".to_string(),
                type_hint: "string".to_string(),
                description: "State parameter from request".to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "oauth2_authorize_response",
            "code": "AUTH_CODE_xyz123",
            "state": "random_state"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> OAuth2 authorize code issued")
                .with_debug("OAuth2 oauth2_authorize_response: code issued"),
        ),
    }
}

fn oauth2_token_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "oauth2_token_response".to_string(),
        description: "Send access token response".to_string(),
        parameters: vec![
            Parameter {
                name: "access_token".to_string(),
                type_hint: "string".to_string(),
                description: "Access token to issue".to_string(),
                required: true,
            },
            Parameter {
                name: "token_type".to_string(),
                type_hint: "string".to_string(),
                description: "Token type (typically 'Bearer')".to_string(),
                required: false,
            },
            Parameter {
                name: "expires_in".to_string(),
                type_hint: "number".to_string(),
                description: "Token lifetime in seconds".to_string(),
                required: false,
            },
            Parameter {
                name: "refresh_token".to_string(),
                type_hint: "string".to_string(),
                description: "Refresh token (optional)".to_string(),
                required: false,
            },
            Parameter {
                name: "scope".to_string(),
                type_hint: "string".to_string(),
                description: "Granted scopes (space-separated)".to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "oauth2_token_response",
            "access_token": "ACCESS_xyz123",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "REFRESH_xyz123",
            "scope": "read write"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> OAuth2 token issued type={token_type} expires={expires_in}s")
                .with_debug("OAuth2 oauth2_token_response: type={token_type}, expires_in={expires_in}, scope={scope}"),
        ),
    }
}

fn oauth2_introspect_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "oauth2_introspect_response".to_string(),
        description: "Send token introspection response".to_string(),
        parameters: vec![
            Parameter {
                name: "active".to_string(),
                type_hint: "boolean".to_string(),
                description: "Whether token is active".to_string(),
                required: true,
            },
            Parameter {
                name: "scope".to_string(),
                type_hint: "string".to_string(),
                description: "Token scopes".to_string(),
                required: false,
            },
            Parameter {
                name: "client_id".to_string(),
                type_hint: "string".to_string(),
                description: "Client ID".to_string(),
                required: false,
            },
            Parameter {
                name: "exp".to_string(),
                type_hint: "number".to_string(),
                description: "Expiration timestamp".to_string(),
                required: false,
            },
            Parameter {
                name: "token_type".to_string(),
                type_hint: "string".to_string(),
                description: "Token type, typically 'Bearer' (only echoed back when active=true)"
                    .to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "oauth2_introspect_response",
            "active": true,
            "scope": "read write",
            "client_id": "client123",
            "token_type": "Bearer",
            "exp": 1234567890
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> OAuth2 introspect active={active}")
                .with_debug("OAuth2 oauth2_introspect_response: active={active}, client_id={client_id}, scope={scope}"),
        ),
    }
}

fn oauth2_error_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "oauth2_error_response".to_string(),
        description: "Send OAuth2 error response".to_string(),
        parameters: vec![
            Parameter {
                name: "error".to_string(),
                type_hint: "string".to_string(),
                description: "Error code (e.g., 'invalid_request', 'unauthorized_client')"
                    .to_string(),
                required: true,
            },
            Parameter {
                name: "error_description".to_string(),
                type_hint: "string".to_string(),
                description: "Human-readable error description".to_string(),
                required: false,
            },
            Parameter {
                name: "error_uri".to_string(),
                type_hint: "string".to_string(),
                description: "URI with error information".to_string(),
                required: false,
            },
            Parameter {
                name: "status_code".to_string(),
                type_hint: "number".to_string(),
                description: "HTTP status for the error (default: 400, or 401 for invalid_client). \
                              Ignored on /authorize, which answers errors with a redirect per RFC 6749 §4.1.2.1."
                    .to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "oauth2_error_response",
            "error": "invalid_client",
            "error_description": "Client authentication failed"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> OAuth2 error {error}")
                .with_debug(
                    "OAuth2 oauth2_error_response: error={error}, description={error_description}",
                ),
        ),
    }
}

// ============================================================================
// OAuth2 Event Type Constants
// ============================================================================

/// OAuth2 authorize event - triggered when client requests authorization
pub static OAUTH2_AUTHORIZE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "oauth2_authorize",
        "OAuth2 authorization request received",
        json!({
            "type": "oauth2_authorize_response",
            "code": "AUTH_CODE_xyz123",
            "state": "echo the state parameter from the request"
        }),
    )
    .with_alternative_example(json!({
        "type": "oauth2_error_response",
        "error": "unauthorized_client",
        "error_description": "Client 'evilapp' is not registered"
    }))
    .with_parameters(vec![
        Parameter {
            name: "response_type".to_string(),
            type_hint: "string".to_string(),
            description: "Response type (e.g., 'code', 'token')".to_string(),
            required: true,
        },
        Parameter {
            name: "client_id".to_string(),
            type_hint: "string".to_string(),
            description: "Client identifier".to_string(),
            required: true,
        },
        Parameter {
            name: "redirect_uri".to_string(),
            type_hint: "string".to_string(),
            description: "Redirection URI".to_string(),
            required: false,
        },
        Parameter {
            name: "scope".to_string(),
            type_hint: "string".to_string(),
            description: "Requested scopes".to_string(),
            required: false,
        },
        Parameter {
            name: "state".to_string(),
            type_hint: "string".to_string(),
            description: "State parameter for CSRF protection".to_string(),
            required: false,
        },
    ])
    // These must be the *real* definitions. `call_llm` advertises `event.event_type.actions`,
    // not `get_sync_actions()`, so the stubs that used to live here (`parameters: vec![]`,
    // `example: json!({})`) were the entire vocabulary the model got: it was told
    // `oauth2_authorize_response` existed but never told that it takes a `code`.
    .with_actions(vec![
        oauth2_authorize_response_action(),
        oauth2_error_response_action(),
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("OAuth2 authorize {response_type} from {client_id}")
            .with_debug("OAuth2 authorize {response_type} from {client_id}, scope={scope}")
            .with_trace("OAuth2 authorize: {json_pretty(.)}"),
    )
});

/// OAuth2 token event - triggered when client requests access token
pub static OAUTH2_TOKEN_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "oauth2_token",
        "OAuth2 token request received",
        json!({
            "type": "oauth2_token_response",
            "access_token": "ACCESS_xyz123",
            "token_type": "Bearer",
            "expires_in": 3600,
            "scope": "read write"
        }),
    )
    .with_alternative_example(json!({
        "type": "oauth2_error_response",
        "error": "invalid_grant",
        "error_description": "Authorization code has expired"
    }))
    .with_parameters(vec![
        Parameter {
            name: "grant_type".to_string(),
            type_hint: "string".to_string(),
            description:
                "Grant type (authorization_code, refresh_token, password, client_credentials)"
                    .to_string(),
            required: true,
        },
        Parameter {
            name: "code".to_string(),
            type_hint: "string".to_string(),
            description: "Authorization code (for authorization_code grant)".to_string(),
            required: false,
        },
        Parameter {
            name: "redirect_uri".to_string(),
            type_hint: "string".to_string(),
            description: "Redirection URI".to_string(),
            required: false,
        },
        Parameter {
            name: "client_id".to_string(),
            type_hint: "string".to_string(),
            description: "Client identifier".to_string(),
            required: false,
        },
        Parameter {
            name: "client_secret".to_string(),
            type_hint: "string".to_string(),
            description: "Client secret".to_string(),
            required: false,
        },
        Parameter {
            name: "refresh_token".to_string(),
            type_hint: "string".to_string(),
            description: "Refresh token (for refresh_token grant)".to_string(),
            required: false,
        },
        Parameter {
            name: "username".to_string(),
            type_hint: "string".to_string(),
            description: "Username (for password grant)".to_string(),
            required: false,
        },
        Parameter {
            name: "password".to_string(),
            type_hint: "string".to_string(),
            description: "Password (for password grant)".to_string(),
            required: false,
        },
        Parameter {
            name: "scope".to_string(),
            type_hint: "string".to_string(),
            description: "Requested scopes".to_string(),
            required: false,
        },
    ])
    .with_actions(vec![
        oauth2_token_response_action(),
        oauth2_error_response_action(),
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("OAuth2 token {grant_type}")
            .with_debug("OAuth2 token {grant_type}, client={client_id}")
            .with_trace("OAuth2 token: {json_pretty(.)}"),
    )
});

/// OAuth2 introspect event - triggered when token introspection is requested
pub static OAUTH2_INTROSPECT_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "oauth2_introspect",
        "OAuth2 token introspection request",
        json!({
            "type": "oauth2_introspect_response",
            "active": true,
            "scope": "read write",
            "client_id": "client123",
            "token_type": "Bearer",
            "exp": 1234567890
        }),
    )
    .with_alternative_example(json!({
        "type": "oauth2_introspect_response",
        "active": false
    }))
    .with_parameters(vec![
        Parameter {
            name: "token".to_string(),
            type_hint: "string".to_string(),
            description: "Token to introspect".to_string(),
            required: true,
        },
        Parameter {
            name: "token_type_hint".to_string(),
            type_hint: "string".to_string(),
            description: "Hint about token type (access_token, refresh_token)".to_string(),
            required: false,
        },
    ])
    .with_actions(vec![
        oauth2_introspect_response_action(),
        oauth2_error_response_action(),
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("OAuth2 introspect")
            .with_debug("OAuth2 introspect, token_type={token_type_hint}")
            .with_trace("OAuth2 introspect: {json_pretty(.)}"),
    )
});

/// OAuth2 revoke event - triggered when token revocation is requested
pub static OAUTH2_REVOKE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "oauth2_revoke",
        "OAuth2 token revocation request. RFC 7009 §2.2 requires the server to answer 200 \
         whether or not the token existed, so the response body is fixed and no protocol \
         action can change it; note the revocation in memory if it matters later.",
        json!({
            "type": "append_memory",
            "value": "revoked token: ACCESS_xyz123"
        }),
    )
    // Deliberately no protocol actions, hence with_no_actions() rather than an empty list:
    // the reply is fixed by RFC 7009 and mod.rs sends it regardless of what the model says.
    // Left empty, `call_llm` would log a BUG and (in debug builds) trip a debug_assert.
    .with_no_actions()
    .with_parameters(vec![
        Parameter {
            name: "token".to_string(),
            type_hint: "string".to_string(),
            description: "Token to revoke".to_string(),
            required: true,
        },
        Parameter {
            name: "token_type_hint".to_string(),
            type_hint: "string".to_string(),
            description: "Hint about token type (access_token, refresh_token)".to_string(),
            required: false,
        },
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("OAuth2 revoke")
            .with_debug("OAuth2 revoke, token_type={token_type_hint}")
            .with_trace("OAuth2 revoke: {json_pretty(.)}"),
    )
});

/// Get OAuth2 event types
pub fn get_oauth2_event_types() -> Vec<EventType> {
    vec![
        OAUTH2_AUTHORIZE_EVENT.clone(),
        OAUTH2_TOKEN_EVENT.clone(),
        OAUTH2_INTROSPECT_EVENT.clone(),
        OAUTH2_REVOKE_EVENT.clone(),
    ]
}
