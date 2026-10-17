//! SAML Service Provider (SP) protocol actions implementation

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

/// SAML SP protocol action handler
pub struct SamlSpProtocol;

impl SamlSpProtocol {
    pub fn new() -> Self {
        Self
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for SamlSpProtocol {
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        Vec::new()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            send_authn_request_action(),
            process_assertion_action(),
            send_metadata_action(),
            send_error_response_action(),
        ]
    }
    fn protocol_name(&self) -> &'static str {
        "SamlSp"
    }
    fn get_event_types(&self) -> Vec<EventType> {
        get_saml_sp_event_types()
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>HTTP>SAML-SP"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "saml sp",
            "saml service provider",
            "service provider",
            "sp",
            "saml-sp",
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .implementation(
                "SAML 2.0 SP endpoints (/login, /acs, /metadata) over hyper HTTP/1.1. Simulator: \
                 the raw SAMLResponse body is handed to the model as text and the model decides \
                 who the user is. NetGet performs no XML signature verification.",
            )
            .llm_control(
                "Whether to accept an assertion at all, which user_id and attributes to read out \
                 of it, the AuthnRequest XML sent to the IDP, and error pages.",
            )
            .e2e_testing("SAML IDP test server")
            .notes(
                "Accepts unsigned and forged assertions: nothing checks <ds:Signature>, issuer, \
                 audience, NotOnOrAfter or assertion-ID replay unless the model's instruction \
                 tells it to look, and it has no key to check a signature against. The session \
                 cookie is the bare user id with no server-side session store.",
            )
            .max_inbound_bytes(crate::server::saml_sp::MAX_REQUEST_BYTES)
            .request_only(
                "SAML is HTTP request/response; a server cannot send a peer anything unprompted",
            )
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn description(&self) -> &'static str {
        "SAML 2.0 Service Provider simulator (LLM reads the assertion; no signature is verified)"
    }
    fn example_prompt(&self) -> &'static str {
        "Start a SAML Service Provider on port 8081. Accept assertions from IDP and grant access to authenticated users"
    }
    fn group_name(&self) -> &'static str {
        "Authentication"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        use serde_json::json;

        // Deterministic: serve SP metadata for every request, no LLM call.
        let script = r#"import json, sys
data = json.load(sys.stdin)
event = data["event"]
if data["event_type_id"] == "saml_sp_request":
    actions = [{"type": "send_metadata",
                "metadata_xml": '<EntityDescriptor entityID="netget-sp"/>'}]
else:
    actions = []
print(json.dumps({"actions": actions}))"#;

        StartupExamples::new(
            // LLM mode: LLM handles SAML SP authorization
            json!({
                "type": "open_server",
                "port": 8081,
                "base_stack": "saml-sp",
                "instruction": "Accept SAML assertions from IDP and grant access to authenticated users"
            }),
            // Script mode: Code-based SAML SP handling
            json!({
                "type": "open_server",
                "port": 8081,
                "base_stack": "saml-sp",
                "event_handlers": [{
                    "event_pattern": "saml_sp_request",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": script
                    }
                }]
            }),
            // Static mode: Fixed SAML SP action
            json!({
                "type": "open_server",
                "port": 8081,
                "base_stack": "saml-sp",
                "event_handlers": [{
                    "event_pattern": "saml_sp_request",
                    "handler": {
                        "type": "static",
                        "actions": [{
                            "type": "process_assertion",
                            "user_id": "testuser",
                            "attributes": {
                                "email": "test@example.com",
                                "role": "user"
                            }
                        }]
                    }
                }]
            }),
        )
    }
}

// Implement Server trait (server-specific functionality)
impl Server for SamlSpProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::server::saml_sp::SamlSpServer;
            SamlSpServer::spawn_with_llm_actions(
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
            "send_authn_request" => self.execute_send_authn_request(action),
            "process_assertion" => self.execute_process_assertion(action),
            "send_metadata" => self.execute_send_metadata(action),
            "send_error_response" => self.execute_send_error_response(action),
            _ => Err(anyhow::anyhow!("Unknown SAML SP action: {action_type}")),
        }
    }
}

impl SamlSpProtocol {
    /// Execute send_authn_request sync action
    fn execute_send_authn_request(&self, action: serde_json::Value) -> Result<ActionResult> {
        let request_xml = action
            .get("request_xml")
            .and_then(|v| v.as_str())
            .context("Missing 'request_xml' field")?;

        let idp_sso_url = action
            .get("idp_sso_url")
            .and_then(|v| v.as_str())
            .context("Missing 'idp_sso_url' field")?;

        let relay_state = action.get("relay_state").and_then(|v| v.as_str());

        let binding = action
            .get("binding")
            .and_then(|v| v.as_str())
            .unwrap_or("HTTP-Redirect");

        let response_html = match binding {
            "HTTP-POST" => build_authn_post_form(request_xml, idp_sso_url, relay_state),
            _ => build_authn_redirect(request_xml, idp_sso_url, relay_state),
        };

        let response_data = json!({
            "status": 200,
            "headers": {
                "Content-Type": "text/html; charset=utf-8"
            },
            "body": response_html
        });

        Ok(ActionResult::Output(
            serde_json::to_vec(&response_data).context("Failed to serialize AuthnRequest")?,
        ))
    }

    /// Execute process_assertion sync action
    fn execute_process_assertion(&self, action: serde_json::Value) -> Result<ActionResult> {
        let user_id = action
            .get("user_id")
            .and_then(|v| v.as_str())
            .context("Missing 'user_id' field")?;

        let attributes = action
            .get("attributes")
            .and_then(|v| v.as_object())
            .map(|obj| {
                obj.iter()
                    .map(|(k, v)| format!("{}: {}", k, v))
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_default();

        let success_html = format!(
            r#"<!DOCTYPE html>
<html>
<head>
    <title>Login Successful</title>
</head>
<body>
    <h1>Authentication Successful</h1>
    <p>Welcome, {}!</p>
    <p>Attributes: {}</p>
</body>
</html>"#,
            escape_html(user_id),
            escape_html(&attributes)
        );

        // `user_id` is whatever the model read out of an attacker-supplied assertion, so it
        // is neither HTML- nor cookie-safe as it stands. Unescaped it was reflected XSS in
        // the page, and raw in `Set-Cookie` it could inject cookie attributes or CR/LF.
        let response_data = json!({
            "status": 200,
            "headers": {
                "Content-Type": "text/html; charset=utf-8",
                "Set-Cookie": format!("session_id={}; HttpOnly; SameSite=Lax", cookie_value(user_id))
            },
            "body": success_html
        });

        Ok(ActionResult::Output(
            serde_json::to_vec(&response_data).context("Failed to serialize assertion response")?,
        ))
    }

    /// Execute send_metadata sync action
    fn execute_send_metadata(&self, action: serde_json::Value) -> Result<ActionResult> {
        let metadata_xml = action
            .get("metadata_xml")
            .and_then(|v| v.as_str())
            .context("Missing 'metadata_xml' field")?;

        let response_data = json!({
            "status": 200,
            "headers": {
                "Content-Type": "application/samlmetadata+xml"
            },
            "body": metadata_xml
        });

        Ok(ActionResult::Output(
            serde_json::to_vec(&response_data).context("Failed to serialize metadata response")?,
        ))
    }

    /// Execute send_error_response sync action
    fn execute_send_error_response(&self, action: serde_json::Value) -> Result<ActionResult> {
        let error_message = action
            .get("error_message")
            .and_then(|v| v.as_str())
            .unwrap_or("Authorization failed");

        // `as u16` truncates: 65736 becomes 200, and a 2xx is the only thing that reads as a
        // completed sign-in. Refuse the wrap and keep the refusal a refusal.
        let status_code = action
            .get("status_code")
            .and_then(|v| v.as_u64())
            .and_then(|raw| u16::try_from(raw).ok())
            .filter(|s| (400..=599).contains(s))
            .unwrap_or(403);

        let error_html = format!(
            "<html><body><h1>Authorization Error</h1><p>{}</p></body></html>",
            escape_html(error_message)
        );

        let response_data = json!({
            "status": status_code,
            "headers": {
                "Content-Type": "text/html; charset=utf-8"
            },
            "body": error_html
        });

        Ok(ActionResult::Output(
            serde_json::to_vec(&response_data).context("Failed to serialize error response")?,
        ))
    }
}

/// Escape text for interpolation into an HTML attribute or text node.
///
/// Every value placed into these pages is model output derived from an untrusted request —
/// the user id and attributes lifted out of a SAML assertion, a RelayState echoed back, an
/// IDP URL. Unescaped, a `"` or `<` broke out of the surrounding attribute and injected
/// markup into a page the browser renders (and, for the POST binding, auto-submits).
fn escape_html(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// Percent-encode a value so it is safe as a cookie value.
///
/// Strips the `;`, `,`, whitespace and CR/LF that would otherwise let a crafted user id
/// append cookie attributes or split the response header.
fn cookie_value(value: &str) -> String {
    urlencoding::encode(value).into_owned()
}

/// Build SAML HTTP-POST form for AuthnRequest
fn build_authn_post_form(
    request_xml: &str,
    idp_sso_url: &str,
    relay_state: Option<&str>,
) -> String {
    let encoded_request =
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, request_xml);
    let relay_state_field = relay_state
        .map(|rs| {
            format!(
                r#"<input type="hidden" name="RelayState" value="{}" />"#,
                escape_html(rs)
            )
        })
        .unwrap_or_default();

    format!(
        r#"<!DOCTYPE html>
<html>
<head>
    <title>SAML POST Binding</title>
</head>
<body onload="document.forms[0].submit()">
    <noscript>
        <p><strong>Note:</strong> Your browser does not support JavaScript, please click Submit to continue.</p>
    </noscript>
    <form method="post" action="{}">
        <input type="hidden" name="SAMLRequest" value="{}" />
        {}
        <noscript>
            <input type="submit" value="Submit" />
        </noscript>
    </form>
</body>
</html>"#,
        escape_html(idp_sso_url),
        encoded_request,
        relay_state_field
    )
}

/// Build SAML HTTP-Redirect for AuthnRequest
fn build_authn_redirect(request_xml: &str, idp_sso_url: &str, relay_state: Option<&str>) -> String {
    let encoded_request =
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, request_xml);
    let relay_param = relay_state
        .map(|rs| format!("&RelayState={}", urlencoding::encode(rs)))
        .unwrap_or_default();
    let redirect_url = format!(
        "{}?SAMLRequest={}{}",
        idp_sso_url,
        urlencoding::encode(&encoded_request),
        relay_param
    );

    format!(
        r#"<!DOCTYPE html>
<html>
<head>
    <title>Redirecting to IDP</title>
    <meta http-equiv="refresh" content="0; url={}" />
</head>
<body>
    <p>Redirecting to Identity Provider...</p>
    <p>If you are not redirected automatically, <a href="{}">click here</a>.</p>
</body>
</html>"#,
        escape_html(&redirect_url),
        escape_html(&redirect_url)
    )
}

// Action definitions
fn send_authn_request_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_authn_request".to_string(),
        description: "Initiate SAML authentication by sending AuthnRequest to IDP".to_string(),
        parameters: vec![
            Parameter {
                name: "request_xml".to_string(),
                type_hint: "string".to_string(),
                description: "SAML AuthnRequest XML".to_string(),
                required: true,
            },
            Parameter {
                name: "idp_sso_url".to_string(),
                type_hint: "string".to_string(),
                description: "IDP Single Sign-On URL".to_string(),
                required: true,
            },
            Parameter {
                name: "relay_state".to_string(),
                type_hint: "string".to_string(),
                description: "Optional RelayState to maintain application state".to_string(),
                required: false,
            },
            Parameter {
                name: "binding".to_string(),
                type_hint: "string".to_string(),
                description: "Binding type: HTTP-Redirect or HTTP-POST (default: HTTP-Redirect)"
                    .to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "send_authn_request",
            "request_xml": "<samlp:AuthnRequest>...</samlp:AuthnRequest>",
            "idp_sso_url": "https://idp.example.com/sso",
            "binding": "HTTP-Redirect"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> SAML AuthnRequest via {binding}")
                .with_debug("SAML AuthnRequest to {idp_sso_url}, binding={binding}"),
        ),
    }
}

fn process_assertion_action() -> ActionDefinition {
    ActionDefinition {
        name: "process_assertion".to_string(),
        description: "Accept a SAML assertion and start a session for the named user. NetGet does \
                      not verify the assertion's signature, issuer, audience or expiry — if any \
                      of that matters, check it yourself in the assertion XML before calling this, \
                      and use send_error_response to reject."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "user_id".to_string(),
                type_hint: "string".to_string(),
                description: "User identifier from assertion (becomes the session cookie value)"
                    .to_string(),
                required: true,
            },
            Parameter {
                name: "attributes".to_string(),
                type_hint: "object".to_string(),
                description: "User attributes from assertion (e.g., email, roles)".to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "process_assertion",
            "user_id": "john.doe",
            "attributes": {
                "email": "john.doe@example.com",
                "role": "admin"
            }
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> SAML session: {user_id}")
                .with_debug("SAML assertion processed: user={user_id}"),
        ),
    }
}

fn send_metadata_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_metadata".to_string(),
        description: "Send SP metadata XML describing ACS endpoint and signing certificates"
            .to_string(),
        parameters: vec![Parameter {
            name: "metadata_xml".to_string(),
            type_hint: "string".to_string(),
            description: "SAML SP metadata XML".to_string(),
            required: true,
        }],
        example: json!({
            "type": "send_metadata",
            "metadata_xml": "<EntityDescriptor>...</EntityDescriptor>"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> SAML SP metadata sent")
                .with_debug("SAML SP metadata response sent"),
        ),
    }
}

fn send_error_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_error_response".to_string(),
        description: "Send an error response when assertion validation fails".to_string(),
        parameters: vec![
            Parameter {
                name: "error_message".to_string(),
                type_hint: "string".to_string(),
                description: "Error message to display".to_string(),
                required: true,
            },
            Parameter {
                name: "status_code".to_string(),
                type_hint: "number".to_string(),
                description: "HTTP status code (default: 403)".to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "send_error_response",
            "error_message": "Invalid assertion signature",
            "status_code": 403
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> SAML error {status_code}: {error_message}")
                .with_debug("SAML SP error response: {status_code} - {error_message}"),
        ),
    }
}

// ============================================================================
// SAML SP Event Type Constants
// ============================================================================

/// SAML SP request event - triggered when client sends request
pub static SAML_SP_REQUEST_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "saml_sp_request",
        "Received SAML assertion response or metadata request",
        json!({
            "type": "process_assertion",
            "user_id": "john.doe",
            "attributes": {
                "email": "john.doe@example.com",
                "role": "user"
            }
        }),
    )
    .with_alternative_example(json!({
        "type": "send_authn_request",
        "request_xml": "<samlp:AuthnRequest>...</samlp:AuthnRequest>",
        "idp_sso_url": "http://localhost:8080/sso",
        "binding": "HTTP-Redirect"
    }))
    .with_alternative_example(json!({
        "type": "send_error_response",
        "error_message": "Assertion is from an untrusted issuer",
        "status_code": 403
    }))
    .with_log_template(
        LogTemplate::new()
            .with_info("{client_ip} SAML SP {method} {path} ({duration_ms}ms)")
            .with_debug("SAML SP request from {client_ip}: {method} {path}")
            .with_trace("SAML SP request: {json_pretty(.)}"),
    )
    .with_parameters(vec![
        Parameter {
            name: "method".to_string(),
            type_hint: "string".to_string(),
            description: "HTTP method (GET or POST)".to_string(),
            required: true,
        },
        Parameter {
            name: "path".to_string(),
            type_hint: "string".to_string(),
            description: "Request path (e.g., /acs, /metadata, /login)".to_string(),
            required: true,
        },
        Parameter {
            name: "query".to_string(),
            type_hint: "string".to_string(),
            description: "Query parameters".to_string(),
            required: false,
        },
        Parameter {
            name: "headers".to_string(),
            type_hint: "array".to_string(),
            description: "HTTP headers".to_string(),
            required: true,
        },
        Parameter {
            name: "body".to_string(),
            type_hint: "string".to_string(),
            description: "Request body (may contain SAMLResponse)".to_string(),
            required: false,
        },
        Parameter {
            name: "client_ip".to_string(),
            type_hint: "string".to_string(),
            description: "IP address of the requesting client".to_string(),
            required: true,
        },
    ])
    .with_actions(vec![
        send_authn_request_action(),
        process_assertion_action(),
        send_metadata_action(),
        send_error_response_action(),
    ])
});

fn get_saml_sp_event_types() -> Vec<EventType> {
    vec![SAML_SP_REQUEST_EVENT.clone()]
}
