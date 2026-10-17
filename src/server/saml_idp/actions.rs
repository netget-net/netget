//! SAML Identity Provider (IDP) protocol actions implementation

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

/// SAML IDP protocol action handler
pub struct SamlIdpProtocol;

impl SamlIdpProtocol {
    pub fn new() -> Self {
        Self
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for SamlIdpProtocol {
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        Vec::new()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            send_saml_response_action(),
            send_metadata_action(),
            send_error_response_action(),
        ]
    }
    fn protocol_name(&self) -> &'static str {
        "SamlIdp"
    }
    fn get_event_types(&self) -> Vec<EventType> {
        get_saml_idp_event_types()
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>HTTP>SAML-IDP"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "saml idp",
            "saml identity provider",
            "identity provider",
            "idp",
            "saml-idp",
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .implementation(
                "SAML 2.0 SSO endpoints over hyper HTTP/1.1. Simulator: the model writes the \
                 assertion XML and NetGet only base64s it into the HTTP-POST form. There is no \
                 signing key anywhere in this protocol.",
            )
            .llm_control(
                "Whether to authenticate, the whole assertion XML (subject, conditions, \
                 attributes), the IDP metadata, and error pages.",
            )
            .e2e_testing("SAML SP client library")
            .notes(
                "No XML signing: assertions carry a <ds:Signature> only if the model invents \
                 one, and it will not verify. Inbound AuthnRequest signatures are not checked \
                 either, and there is no replay protection. Real SPs configured to require \
                 signed assertions will reject these.",
            )
            .max_inbound_bytes(crate::server::saml_idp::MAX_REQUEST_BYTES)
            .request_only(
                "SAML is HTTP request/response; a server cannot send a peer anything unprompted",
            )
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn description(&self) -> &'static str {
        "SAML 2.0 Identity Provider simulator (LLM writes the assertion; nothing is signed)"
    }
    fn example_prompt(&self) -> &'static str {
        "Start a SAML Identity Provider on port 8080. Authenticate all users as 'testuser' with email 'test@example.com'"
    }
    fn group_name(&self) -> &'static str {
        "Authentication"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;

        StartupExamples::new(
            // LLM mode: instruction-based
            json!({
                "type": "open_server",
                "port": 8080,
                "base_stack": "saml-idp",
                "instruction": "SAML Identity Provider. Authenticate all users as 'testuser' with email 'test@example.com'. Return SAML assertions for SSO requests"
            }),
            // Script mode: event_handlers with script handler
            json!({
                "type": "open_server",
                "port": 8080,
                "base_stack": "saml-idp",
                "event_handlers": [{
                    "event_pattern": "saml_idp_request",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "path = event.get('path', '')\nif '/metadata' in path:\n    action('send_metadata', metadata_xml='<EntityDescriptor>...</EntityDescriptor>')\nelse:\n    action('send_saml_response', assertion_xml='<saml:Assertion>...</saml:Assertion>', acs_url='http://localhost:8081/acs')"
                    }
                }]
            }),
            // Static mode: event_handlers with static actions
            json!({
                "type": "open_server",
                "port": 8080,
                "base_stack": "saml-idp",
                "event_handlers": [{
                    "event_pattern": "saml_idp_request",
                    "handler": {
                        "type": "static",
                        "actions": [{
                            "type": "send_saml_response",
                            "assertion_xml": "<saml:Assertion><saml:Subject><saml:NameID>testuser</saml:NameID></saml:Subject></saml:Assertion>",
                            "acs_url": "http://localhost:8081/acs",
                            "relay_state": "original-url"
                        }]
                    }
                }]
            }),
        )
    }
}

// Implement Server trait (server-specific functionality)
impl Server for SamlIdpProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::server::saml_idp::SamlIdpServer;
            SamlIdpServer::spawn_with_llm_actions(
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
            "send_saml_response" => self.execute_send_saml_response(action),
            "send_metadata" => self.execute_send_metadata(action),
            "send_error_response" => self.execute_send_error_response(action),
            _ => Err(anyhow::anyhow!("Unknown SAML IDP action: {action_type}")),
        }
    }
}

impl SamlIdpProtocol {
    /// Execute send_saml_response sync action
    fn execute_send_saml_response(&self, action: serde_json::Value) -> Result<ActionResult> {
        let assertion_xml = action
            .get("assertion_xml")
            .and_then(|v| v.as_str())
            .context("Missing 'assertion_xml' field")?;

        let acs_url = action
            .get("acs_url")
            .and_then(|v| v.as_str())
            .context("Missing 'acs_url' field (the SP's AssertionConsumerService URL)")?;

        let relay_state = action.get("relay_state").and_then(|v| v.as_str());

        // Build HTTP POST form response (SAML HTTP-POST binding)
        let form_html = build_saml_post_form(assertion_xml, acs_url, relay_state);

        let response_data = json!({
            "status": 200,
            "headers": {
                "Content-Type": "text/html; charset=utf-8"
            },
            "body": form_html
        });

        Ok(ActionResult::Output(
            serde_json::to_vec(&response_data).context("Failed to serialize SAML response")?,
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
            .unwrap_or("Authentication failed");

        // `as u16` truncates: 65736 becomes 200, and a 2xx is the only thing that reads as a
        // completed sign-in. Refuse the wrap and keep the refusal a refusal.
        let status_code = action
            .get("status_code")
            .and_then(|v| v.as_u64())
            .and_then(|raw| u16::try_from(raw).ok())
            .filter(|s| (400..=599).contains(s))
            .unwrap_or(403);

        let error_html = format!(
            "<html><body><h1>Authentication Error</h1><p>{}</p></body></html>",
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
/// Everything placed into these pages — RelayState, the ACS URL, error messages — is model
/// output derived from an untrusted request, so `"` or `<` used to break out of the
/// surrounding attribute and inject markup into a page the browser renders and auto-submits.
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

/// Build SAML HTTP-POST form for assertion delivery
///
/// `acs_url` is the SP's AssertionConsumerService endpoint and must be a real URL. The form
/// action used to be the literal string `{{ACS_URL}}` — nothing ever substituted it, and
/// `send_saml_response` had no parameter that could have, so every assertion this IDP
/// produced was posted to a relative path named `{{ACS_URL}}` and never reached any SP.
fn build_saml_post_form(assertion_xml: &str, acs_url: &str, relay_state: Option<&str>) -> String {
    let encoded_assertion =
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, assertion_xml);
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
        <input type="hidden" name="SAMLResponse" value="{}" />
        {}
        <noscript>
            <input type="submit" value="Submit" />
        </noscript>
    </form>
</body>
</html>"#,
        escape_html(acs_url),
        encoded_assertion,
        relay_state_field
    )
}

/// Action definition for send_saml_response (sync)
fn send_saml_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_saml_response".to_string(),
        description: "Send a SAML response with authentication assertion to the Service Provider. \
                      NetGet base64-encodes the XML into an auto-submitting HTTP-POST form for \
                      you — provide plain XML, never base64. Nothing is signed: if the SP \
                      requires a signed assertion it will reject this."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "assertion_xml".to_string(),
                type_hint: "string".to_string(),
                description:
                    "SAML assertion XML containing authentication statement and user attributes"
                        .to_string(),
                required: true,
            },
            Parameter {
                name: "acs_url".to_string(),
                type_hint: "string".to_string(),
                description: "The SP's AssertionConsumerService URL that the generated form posts \
                              to. Usually the AssertionConsumerServiceURL of the AuthnRequest, or \
                              the SP's configured ACS endpoint."
                    .to_string(),
                required: true,
            },
            Parameter {
                name: "relay_state".to_string(),
                type_hint: "string".to_string(),
                description: "Optional RelayState parameter to maintain SP state. Echo back the \
                              RelayState the SP sent."
                    .to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "send_saml_response",
            "assertion_xml": "<saml:Assertion>...</saml:Assertion>",
            "acs_url": "http://localhost:8081/acs",
            "relay_state": "original-sp-url"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> SAML assertion sent")
                .with_debug("SAML response: assertion with relay_state={relay_state}"),
        ),
    }
}

/// Action definition for send_metadata (sync)
fn send_metadata_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_metadata".to_string(),
        description: "Send IDP metadata XML describing SSO endpoints and signing certificates"
            .to_string(),
        parameters: vec![Parameter {
            name: "metadata_xml".to_string(),
            type_hint: "string".to_string(),
            description: "SAML IDP metadata XML".to_string(),
            required: true,
        }],
        example: json!({
            "type": "send_metadata",
            "metadata_xml": "<EntityDescriptor>...</EntityDescriptor>"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> SAML metadata sent")
                .with_debug("SAML metadata response sent"),
        ),
    }
}

/// Action definition for send_error_response (sync)
fn send_error_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_error_response".to_string(),
        description: "Send an error response when authentication fails".to_string(),
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
            "error_message": "Invalid credentials",
            "status_code": 403
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> SAML error {status_code}: {error_message}")
                .with_debug("SAML error response: {status_code} - {error_message}"),
        ),
    }
}

// ============================================================================
// SAML IDP Event Type Constants
// ============================================================================

/// SAML IDP request event - triggered when client sends request
pub static SAML_IDP_REQUEST_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "saml_idp_request",
        "Received SAML authentication request or metadata request",
        json!({
            "type": "send_saml_response",
            "assertion_xml": "<saml:Assertion>...</saml:Assertion>",
            "acs_url": "http://localhost:8081/acs",
            "relay_state": "original-sp-url"
        }),
    )
    .with_alternative_example(json!({
        "type": "send_metadata",
        "metadata_xml": "<EntityDescriptor entityID=\"http://localhost:8080\">...</EntityDescriptor>"
    }))
    .with_alternative_example(json!({
        "type": "send_error_response",
        "error_message": "Unknown service provider",
        "status_code": 403
    }))
    .with_log_template(
        LogTemplate::new()
            .with_info("{client_ip} SAML {method} {path} ({duration_ms}ms)")
            .with_debug("SAML IDP request from {client_ip}: {method} {path}")
            .with_trace("SAML IDP request: {json_pretty(.)}"),
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
            description: "Request path (e.g., /sso, /metadata)".to_string(),
            required: true,
        },
        Parameter {
            name: "query".to_string(),
            type_hint: "string".to_string(),
            description: "Query parameters (for HTTP-Redirect binding)".to_string(),
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
            description: "Request body (for HTTP-POST binding)".to_string(),
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
        send_saml_response_action(),
        send_metadata_action(),
        send_error_response_action(),
    ])
});

fn get_saml_idp_event_types() -> Vec<EventType> {
    vec![SAML_IDP_REQUEST_EVENT.clone()]
}
