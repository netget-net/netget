//! HTTP Proxy protocol actions implementation
//!
//! This module provides actions for:
//! - Handling intercepted requests (pass/block/modify)
//! - Handling intercepted responses (pass/block/modify)
//! - Handling HTTPS connections in pass-through mode (allow/block)
//!
//! Certificate mode and filter modes are configured through startup parameters,
//! not actions: the configuration is read once when the server spawns.

use super::filter;
use super::filter::{HttpsConnectionAction, RequestAction, ResponseAction};
use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter, ParameterDefinition,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::EventType;
use crate::state::app_state::AppState;
use anyhow::{Context, Result};
use serde_json::json;
use std::sync::LazyLock;

/// Read a model-supplied HTTP status, refusing anything outside 100-599.
///
/// `as u16` on a `u64` wraps in silence: `status: 65736` is `200`, so a *block* — the only
/// way the model can refuse a request — reached the client as the success it was refusing.
/// Clamping would be a different lie, so an out-of-range value is an error the repair loop
/// can see and correct.
fn parse_status(action: &serde_json::Value, default: u16) -> Result<u16> {
    let Some(value) = action.get("status") else {
        return Ok(default);
    };
    if value.is_null() {
        return Ok(default);
    }
    let raw = value
        .as_u64()
        .with_context(|| format!("'status' must be an HTTP status code, got {value}"))?;
    if !(100..=599).contains(&raw) {
        return Err(anyhow::anyhow!(
            "'status' {raw} is not an HTTP status code; use 100-599 \
             (e.g. 403 to block a request, 502 to block a response)"
        ));
    }
    Ok(raw as u16)
}

/// HTTP Proxy protocol action handler
pub struct ProxyProtocol;

impl ProxyProtocol {
    pub fn new() -> Self {
        Self
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for ProxyProtocol {
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
                ParameterDefinition {
                    name: "certificate_mode".to_string(),
                    type_hint: "string".to_string(),
                    description: "Certificate mode: 'generate' (MITM - decrypt HTTPS using a CA generated fresh at startup, requires clients to trust it) or 'none' (pass-through, no decryption, allow/block only). Default: 'none'. 'load_from_file' is not implemented and is rejected at startup.".to_string(),
                    required: false,
                    example: json!("generate"),
                    default: None,
                },
                // cert_path / key_path are read by ProxyServer::spawn_with_llm_actions in the
                // 'load_from_file' branch. They must be declared even though that mode is
                // rejected: StartupParams validates every key against this list *before*
                // add_server, so an undeclared read produced "Attempted to access undeclared
                // startup parameter 'cert_path'" and the caller never saw the deliberate
                // "not implemented" message written below it.
                ParameterDefinition {
                    name: "cert_path".to_string(),
                    type_hint: "string".to_string(),
                    description: "Path to a CA certificate in PEM format. Only read when certificate_mode is 'load_from_file', which is NOT implemented and is rejected at startup - so setting this cannot make HTTPS interception use your own CA. Use certificate_mode 'generate' with ca_export_path instead.".to_string(),
                    required: false,
                    example: json!("./ca.crt"),
                    default: None,
                },
                ParameterDefinition {
                    name: "key_path".to_string(),
                    type_hint: "string".to_string(),
                    description: "Path to the CA private key in PEM format. Same restriction as cert_path: only read by the unimplemented 'load_from_file' certificate mode. The key is never read by any working code path.".to_string(),
                    required: false,
                    example: json!("./ca.key"),
                    default: None,
                },
                ParameterDefinition {
                    name: "ca_export_path".to_string(),
                    type_hint: "string".to_string(),
                    description: "Write the generated MITM CA certificate (public certificate only, never the private key) to this path. Clients must be configured to trust this certificate or HTTPS interception will fail with an unknown-issuer error. The CA is regenerated on every server start, so a previously exported file stops working once the server restarts.".to_string(),
                    required: false,
                    example: json!("./netget-ca.crt"),
                    default: None,
                },
                ParameterDefinition {
                    name: "request_filter_mode".to_string(),
                    type_hint: "string".to_string(),
                    description: "Request filter mode: 'all' (intercept everything), 'match_only' (only if filters match), 'none' (pass through)".to_string(),
                    required: false,
                    example: json!("match_only"),
                    default: None,
                },
                ParameterDefinition {
                    name: "response_filter_mode".to_string(),
                    type_hint: "string".to_string(),
                    description: "Response filter mode: 'all', 'match_only', or 'none'".to_string(),
                    required: false,
                    example: json!("all"),
                    default: None,
                },
                ParameterDefinition {
                    name: "https_connection_filter_mode".to_string(),
                    type_hint: "string".to_string(),
                    description: "HTTPS connection filter mode (pass-through only): 'all', 'match_only', or 'none'".to_string(),
                    required: false,
                    example: json!("match_only"),
                    default: None,
                },
            ]
    }
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        // Deliberately empty. Six configuration actions used to be advertised here
        // (configure_certificate, configure_request_filters,
        // configure_response_filters, configure_https_connection_filters,
        // set_filter_mode, export_ca_certificate). Every one of them only
        // serialised its arguments into ActionResult::Output, which nothing ever
        // read back: the filter config is snapshotted at spawn time and cloned per
        // connection, and no code path called set_proxy_filter_config afterwards.
        // So they reported success while changing nothing, and worse, an Output
        // emitted during a request event was mis-parsed as a RequestAction and
        // aborted the decision for that request.
        //
        // Certificate mode, the three filter modes and the CA export path are all
        // configured through startup parameters instead (see
        // get_startup_parameters), which do take effect.
        Vec::new()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            // Request handling actions (sync - in response to intercepted request)
            handle_request_pass_action(),
            handle_request_block_action(),
            handle_request_modify_action(),
            // Response handling actions (sync - in response to intercepted response)
            handle_response_pass_action(),
            handle_response_block_action(),
            handle_response_modify_action(),
            // HTTPS connection handling (sync - in response to HTTPS CONNECT in pass-through mode)
            handle_https_connection_allow_action(),
            handle_https_connection_block_action(),
        ]
    }
    fn protocol_name(&self) -> &'static str {
        "Proxy"
    }
    fn get_event_types(&self) -> Vec<EventType> {
        get_proxy_event_types()
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>HTTP>PROXY"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["proxy", "mitm"]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .well_known_port(8080)
            .implementation("Manual HTTP/1.1 with rcgen v0.14 + rustls")
            .llm_control("Request pass/block/modify, response pass/block/modify (MITM only), HTTPS allow/block")
            .e2e_testing("reqwest configured as a real proxy client against local target servers (tests/server/proxy/test.rs), plus mocked-LLM startup and MITM scenarios (tests/server/proxy/e2e_test.rs). No curl and no browser has been run against it.")
            .notes(
                "OPEN RELAY BY DESIGN, AND UNRESTRICTED: the destination of every request and \
                 every CONNECT is chosen by the peer (from the request-target or the Host \
                 header), and there is no allow-list, deny-list or network restriction of any \
                 kind. Loopback, link-local (including 169.254.169.254, the cloud \
                 instance-metadata endpoint) and every RFC 1918 range are reachable, so anyone \
                 who can reach this port can reach whatever this host can -- an SSRF pivot into \
                 the operator's private network, and a relay someone else's traffic can be \
                 laundered through. The only gate is the model, and `request_filter_mode` / \
                 `https_connection_filter_mode` decide whether it is consulted at all: at \
                 `none`, or at `match_only` with filters that miss, traffic is forwarded with no \
                 consultation whatsoever. The `*_filters` lists select what the model is ASKED \
                 about; they do not restrict anything on their own. Do not expose this to an \
                 untrusted network. \
                 In MITM mode the generated CA's private key never leaves memory and is never \
                 written to disk -- `ca_export_path` writes the public certificate only -- but a \
                 client that trusts that CA has its TLS broken for every host, so the exported \
                 file must be treated as the sensitive artefact it is. \
                 HTTP/1.1 only; the MITM CA is generated per run and clients must trust it; \
                 certificate_mode 'load_from_file' is not implemented and is rejected at startup \
                 (its cert_path/key_path parameters are declared only so that rejection is the \
                 error the caller sees); responses on plain HTTP are forwarded without LLM \
                 consultation; only the first exchange of a keep-alive HTTPS connection is \
                 inspected; the request head is capped at 64 KiB with a 30s deadline and an \
                 upstream response at 8 MiB, but the number of concurrent connections is \
                 unbounded.",
            )
            .max_inbound_bytes(crate::server::proxy::MAX_REQUEST_BYTES)
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn description(&self) -> &'static str {
        "HTTP/HTTPS proxy server"
    }
    fn example_prompt(&self) -> &'static str {
        "Start an HTTP proxy on port 8080"
    }
    fn group_name(&self) -> &'static str {
        "Proxy & Network"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;

        StartupExamples::new(
            // LLM mode
            json!({
                "type": "open_server",
                "port": 8080,
                "base_stack": "proxy",
                "instruction": "HTTP/HTTPS proxy server. Pass all HTTP requests through. For HTTPS CONNECT requests, allow all connections in pass-through mode."
            }),
            // Script mode
            json!({
                "type": "open_server",
                "port": 8080,
                "base_stack": "proxy",
                "event_handlers": [{
                    "event_pattern": "proxy_http_request",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "return [{\"type\": \"handle_request_pass\"}]"
                    }
                }, {
                    "event_pattern": "proxy_https_connect",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "return [{\"type\": \"handle_https_connection_allow\"}]"
                    }
                }]
            }),
            // Static mode
            json!({
                "type": "open_server",
                "port": 8080,
                "base_stack": "proxy",
                "event_handlers": [{
                    "event_pattern": "proxy_http_request",
                    "handler": {
                        "type": "static",
                        "actions": [{
                            "type": "handle_request_pass"
                        }]
                    }
                }, {
                    "event_pattern": "proxy_https_connect",
                    "handler": {
                        "type": "static",
                        "actions": [{
                            "type": "handle_https_connection_allow"
                        }]
                    }
                }]
            }),
        )
    }
}

// Implement Server trait (server-specific functionality)
impl Server for ProxyProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::server::proxy::ProxyServer;
            ProxyServer::spawn_with_llm_actions(
                ctx.legacy_listen_addr(),
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.server_id,
                ctx.startup_params,
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
            // Request handling
            "handle_request_pass" => self.execute_handle_request_pass(action),
            "handle_request_block" => self.execute_handle_request_block(action),
            "handle_request_modify" => self.execute_handle_request_modify(action),

            // Response handling
            "handle_response_pass" => self.execute_handle_response_pass(action),
            "handle_response_block" => self.execute_handle_response_block(action),
            "handle_response_modify" => self.execute_handle_response_modify(action),

            // HTTPS connection handling
            "handle_https_connection_allow" => self.execute_handle_https_connection_allow(action),
            "handle_https_connection_block" => self.execute_handle_https_connection_block(action),

            _ => Err(anyhow::anyhow!("Unknown Proxy action: {}", action_type)),
        }
    }
}

impl ProxyProtocol {
    // ========================================================================
    // Request Handling Actions
    // ========================================================================

    /// Pass request through unchanged
    fn execute_handle_request_pass(&self, _action: serde_json::Value) -> Result<ActionResult> {
        let result = RequestAction::Pass;
        Ok(ActionResult::Output(
            serde_json::to_vec(&result).context("Failed to serialize request action")?,
        ))
    }

    /// Block request and return error response
    fn execute_handle_request_block(&self, action: serde_json::Value) -> Result<ActionResult> {
        let status = parse_status(&action, 403)?;

        let body = action
            .get("body")
            .and_then(|v| v.as_str())
            .unwrap_or("Request blocked by proxy")
            .to_string();

        let result = RequestAction::Block { status, body };
        Ok(ActionResult::Output(
            serde_json::to_vec(&result).context("Failed to serialize request action")?,
        ))
    }

    /// Modify request before forwarding
    fn execute_handle_request_modify(&self, action: serde_json::Value) -> Result<ActionResult> {
        let headers: Option<std::collections::HashMap<String, String>> = action
            .get("headers")
            .and_then(|v| serde_json::from_value(v.clone()).ok());
        if let Some(headers) = &headers {
            filter::check_modify_headers(headers)?;
        }

        let remove_headers = action
            .get("remove_headers")
            .and_then(|v| serde_json::from_value(v.clone()).ok());

        let new_path = action
            .get("new_path")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        if let Some(path) = &new_path {
            filter::check_request_target_part("new_path", path)?;
        }

        let query_params: Option<std::collections::HashMap<String, String>> = action
            .get("query_params")
            .and_then(|v| serde_json::from_value(v.clone()).ok());
        if let Some(params) = &query_params {
            filter::check_query_params(params)?;
        }

        let new_body = action
            .get("new_body")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let body_replacements = action
            .get("body_replacements")
            .and_then(|v| serde_json::from_value(v.clone()).ok());

        let result = RequestAction::Modify {
            headers,
            remove_headers,
            new_path,
            query_params,
            new_body,
            body_replacements,
        };

        Ok(ActionResult::Output(
            serde_json::to_vec(&result).context("Failed to serialize request action")?,
        ))
    }

    // ========================================================================
    // Response Handling Actions
    // ========================================================================

    /// Pass response through unchanged
    fn execute_handle_response_pass(&self, _action: serde_json::Value) -> Result<ActionResult> {
        let result = ResponseAction::Pass;
        Ok(ActionResult::Output(
            serde_json::to_vec(&result).context("Failed to serialize response action")?,
        ))
    }

    /// Block response and return different one
    fn execute_handle_response_block(&self, action: serde_json::Value) -> Result<ActionResult> {
        let status = parse_status(&action, 502)?;

        let body = action
            .get("body")
            .and_then(|v| v.as_str())
            .unwrap_or("Response blocked by proxy")
            .to_string();

        let result = ResponseAction::Block { status, body };
        Ok(ActionResult::Output(
            serde_json::to_vec(&result).context("Failed to serialize response action")?,
        ))
    }

    /// Modify response before returning to client
    fn execute_handle_response_modify(&self, action: serde_json::Value) -> Result<ActionResult> {
        // A modify that leaves the status alone is legitimate, so `None` stays `None` — but a
        // status that *is* named has to be a real one.
        let status = match action.get("status") {
            None => None,
            Some(v) if v.is_null() => None,
            Some(_) => Some(parse_status(&action, 0)?),
        };

        let headers: Option<std::collections::HashMap<String, String>> = action
            .get("headers")
            .and_then(|v| serde_json::from_value(v.clone()).ok());
        if let Some(headers) = &headers {
            filter::check_modify_headers(headers)?;
        }

        let remove_headers = action
            .get("remove_headers")
            .and_then(|v| serde_json::from_value(v.clone()).ok());

        let new_body = action
            .get("new_body")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let body_replacements = action
            .get("body_replacements")
            .and_then(|v| serde_json::from_value(v.clone()).ok());

        let result = ResponseAction::Modify {
            status,
            headers,
            remove_headers,
            new_body,
            body_replacements,
        };

        Ok(ActionResult::Output(
            serde_json::to_vec(&result).context("Failed to serialize response action")?,
        ))
    }

    // ========================================================================
    // HTTPS Connection Handling (Pass-Through Mode)
    // ========================================================================

    /// Allow HTTPS connection to proceed
    fn execute_handle_https_connection_allow(
        &self,
        _action: serde_json::Value,
    ) -> Result<ActionResult> {
        let result = HttpsConnectionAction::Allow;
        Ok(ActionResult::Output(
            serde_json::to_vec(&result).context("Failed to serialize HTTPS connection action")?,
        ))
    }

    /// Block HTTPS connection
    fn execute_handle_https_connection_block(
        &self,
        action: serde_json::Value,
    ) -> Result<ActionResult> {
        let reason = action
            .get("reason")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let result = HttpsConnectionAction::Block { reason };
        Ok(ActionResult::Output(
            serde_json::to_vec(&result).context("Failed to serialize HTTPS connection action")?,
        ))
    }
}

// ============================================================================
// Action Definitions
// ============================================================================

// Request Handling Actions

fn handle_request_pass_action() -> ActionDefinition {
    ActionDefinition {
        name: "handle_request_pass".to_string(),
        description: "Pass the intercepted request through unchanged to its destination"
            .to_string(),
        parameters: vec![],
        example: json!({
            "type": "handle_request_pass"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> Proxy PASS request")
                .with_debug("Proxy handle_request_pass: forwarding unchanged"),
        ),
    }
}

fn handle_request_block_action() -> ActionDefinition {
    ActionDefinition {
        name: "handle_request_block".to_string(),
        description: "Block the intercepted request and return an error response to the client"
            .to_string(),
        parameters: vec![
            Parameter {
                name: "status".to_string(),
                type_hint: "number".to_string(),
                description: "HTTP status code (default: 403)".to_string(),
                required: false,
            },
            Parameter {
                name: "body".to_string(),
                type_hint: "string".to_string(),
                description: "Response body explaining why request was blocked".to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "handle_request_block",
            "status": 403,
            "body": "Access denied by security policy"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> Proxy BLOCK request {status}")
                .with_debug("Proxy handle_request_block: status={status}"),
        ),
    }
}

fn handle_request_modify_action() -> ActionDefinition {
    ActionDefinition {
        name: "handle_request_modify".to_string(),
        description: "Modify the intercepted request before forwarding to destination".to_string(),
        parameters: vec![
            Parameter {
                name: "headers".to_string(),
                type_hint: "object".to_string(),
                description: "Headers to add or modify (key-value pairs)".to_string(),
                required: false,
            },
            Parameter {
                name: "remove_headers".to_string(),
                type_hint: "array".to_string(),
                description: "Header names to remove".to_string(),
                required: false,
            },
            Parameter {
                name: "new_path".to_string(),
                type_hint: "string".to_string(),
                description: "New URL path (replaces entire path)".to_string(),
                required: false,
            },
            Parameter {
                name: "query_params".to_string(),
                type_hint: "object".to_string(),
                description: "Query parameters to add/modify".to_string(),
                required: false,
            },
            Parameter {
                name: "new_body".to_string(),
                type_hint: "string".to_string(),
                description: "Complete body replacement".to_string(),
                required: false,
            },
            Parameter {
                name: "body_replacements".to_string(),
                type_hint: "array".to_string(),
                description:
                    "Array of regex replacements: [{pattern: 'regex', replacement: 'text'}]"
                        .to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "handle_request_modify",
            "headers": {
                "X-Proxy-Modified": "true",
                "User-Agent": "CustomBot/1.0"
            },
            "remove_headers": ["Cookie"],
            "body_replacements": [
                {
                    "pattern": "password",
                    "replacement": "****REDACTED****"
                }
            ]
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> Proxy MODIFY request")
                .with_debug("Proxy handle_request_modify: path={new_path}"),
        ),
    }
}

// Response Handling Actions

fn handle_response_pass_action() -> ActionDefinition {
    ActionDefinition {
        name: "handle_response_pass".to_string(),
        description: "Pass the intercepted response through unchanged to the client".to_string(),
        parameters: vec![],
        example: json!({
            "type": "handle_response_pass"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> Proxy PASS response")
                .with_debug("Proxy handle_response_pass: forwarding unchanged"),
        ),
    }
}

fn handle_response_block_action() -> ActionDefinition {
    ActionDefinition {
        name: "handle_response_block".to_string(),
        description: "Block the intercepted response and return a different response to the client"
            .to_string(),
        parameters: vec![
            Parameter {
                name: "status".to_string(),
                type_hint: "number".to_string(),
                description: "HTTP status code (default: 502)".to_string(),
                required: false,
            },
            Parameter {
                name: "body".to_string(),
                type_hint: "string".to_string(),
                description: "Response body".to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "handle_response_block",
            "status": 502,
            "body": "Response blocked by content policy"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> Proxy BLOCK response {status}")
                .with_debug("Proxy handle_response_block: status={status}"),
        ),
    }
}

fn handle_response_modify_action() -> ActionDefinition {
    ActionDefinition {
        name: "handle_response_modify".to_string(),
        description: "Modify the intercepted response before returning to client".to_string(),
        parameters: vec![
            Parameter {
                name: "status".to_string(),
                type_hint: "number".to_string(),
                description: "New HTTP status code".to_string(),
                required: false,
            },
            Parameter {
                name: "headers".to_string(),
                type_hint: "object".to_string(),
                description: "Headers to add or modify (key-value pairs)".to_string(),
                required: false,
            },
            Parameter {
                name: "remove_headers".to_string(),
                type_hint: "array".to_string(),
                description: "Header names to remove".to_string(),
                required: false,
            },
            Parameter {
                name: "new_body".to_string(),
                type_hint: "string".to_string(),
                description: "Complete body replacement".to_string(),
                required: false,
            },
            Parameter {
                name: "body_replacements".to_string(),
                type_hint: "array".to_string(),
                description:
                    "Array of regex replacements: [{pattern: 'regex', replacement: 'text'}]"
                        .to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "handle_response_modify",
            "headers": {
                "X-Content-Filtered": "true"
            },
            "body_replacements": [
                {
                    "pattern": "secret-api-key-\\w+",
                    "replacement": "****REDACTED****"
                }
            ]
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> Proxy MODIFY response")
                .with_debug("Proxy handle_response_modify: status={status}"),
        ),
    }
}

// HTTPS Connection Handling Actions

fn handle_https_connection_allow_action() -> ActionDefinition {
    ActionDefinition {
        name: "handle_https_connection_allow".to_string(),
        description: "Allow HTTPS connection to proceed (pass-through mode only, no MITM)"
            .to_string(),
        parameters: vec![],
        example: json!({
            "type": "handle_https_connection_allow"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> Proxy ALLOW HTTPS")
                .with_debug("Proxy handle_https_connection_allow: tunnel established"),
        ),
    }
}

fn handle_https_connection_block_action() -> ActionDefinition {
    ActionDefinition {
        name: "handle_https_connection_block".to_string(),
        description: "Block HTTPS connection (pass-through mode only, no MITM)".to_string(),
        parameters: vec![Parameter {
            name: "reason".to_string(),
            type_hint: "string".to_string(),
            description: "Optional reason for blocking".to_string(),
            required: false,
        }],
        example: json!({
            "type": "handle_https_connection_block",
            "reason": "Destination blocked by security policy"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> Proxy BLOCK HTTPS")
                .with_debug("Proxy handle_https_connection_block: reason={reason}"),
        ),
    }
}

// ============================================================================
// Proxy Event Type Constants
// ============================================================================

/// HTTP request event - triggered when proxy receives HTTP request
pub static PROXY_HTTP_REQUEST_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "proxy_http_request",
        "HTTP request intercepted by proxy",
        json!({"type": "placeholder", "event_id": "proxy_http_request"}),
    )
    .with_parameters(vec![
        Parameter {
            name: "method".to_string(),
            type_hint: "string".to_string(),
            description: "HTTP method (GET, POST, etc.)".to_string(),
            required: true,
        },
        Parameter {
            name: "url".to_string(),
            type_hint: "string".to_string(),
            description: "Full request URL".to_string(),
            required: true,
        },
        Parameter {
            name: "host".to_string(),
            type_hint: "string".to_string(),
            description: "Host header value".to_string(),
            required: true,
        },
        Parameter {
            name: "path".to_string(),
            type_hint: "string".to_string(),
            description: "Request path".to_string(),
            required: true,
        },
    ])
    .with_actions(vec![
        handle_request_pass_action(),
        handle_request_block_action(),
        handle_request_modify_action(),
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("Proxy {client_ip} {method} {host}")
            .with_debug("HTTP proxy {method} to {host} from {client_ip}:{client_port}")
            .with_trace("Proxy: {json_pretty(.)}"),
    )
});

/// HTTP response event - triggered when proxy receives HTTP response from upstream server
pub static PROXY_HTTP_RESPONSE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "proxy_http_response",
        "HTTP response received from upstream server",
        json!({"type": "placeholder", "event_id": "proxy_http_response"}),
    )
    .with_parameters(vec![
        Parameter {
            name: "status_code".to_string(),
            type_hint: "number".to_string(),
            description: "HTTP status code (200, 404, etc.)".to_string(),
            required: true,
        },
        Parameter {
            name: "url".to_string(),
            type_hint: "string".to_string(),
            description: "Original request URL".to_string(),
            required: true,
        },
        Parameter {
            name: "headers".to_string(),
            type_hint: "object".to_string(),
            description: "Response headers as key-value pairs".to_string(),
            required: true,
        },
        Parameter {
            name: "body".to_string(),
            type_hint: "string".to_string(),
            description: "Response body (may be truncated for large responses)".to_string(),
            required: false,
        },
    ])
    .with_actions(vec![
        handle_response_pass_action(),
        handle_response_block_action(),
        handle_response_modify_action(),
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("Proxy {client_ip} response {status_code}")
            .with_debug("HTTP proxy response {status_code} from {url}")
            .with_trace("Proxy: {json_pretty(.)}"),
    )
});

/// HTTPS connection event - triggered when proxy receives CONNECT request
pub static PROXY_HTTPS_CONNECT_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "proxy_https_connect",
        "HTTPS CONNECT request intercepted by proxy (pass-through mode)",
        json!({"type": "handle_https_connection_allow"}),
    )
    .with_parameters(vec![
        Parameter {
            name: "destination_host".to_string(),
            type_hint: "string".to_string(),
            description: "Destination hostname".to_string(),
            required: true,
        },
        Parameter {
            name: "destination_port".to_string(),
            type_hint: "number".to_string(),
            description: "Destination port".to_string(),
            required: true,
        },
        Parameter {
            name: "sni".to_string(),
            type_hint: "string".to_string(),
            description: "SNI (Server Name Indication) from TLS handshake".to_string(),
            required: false,
        },
    ])
    .with_actions(vec![
        handle_https_connection_allow_action(),
        handle_https_connection_block_action(),
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("Proxy {client_ip} CONNECT {destination_host}:{destination_port}")
            .with_debug("HTTPS CONNECT to {destination_host}:{destination_port} from {client_ip}:{client_port}")
            .with_trace("Proxy: {json_pretty(.)}"),
    )
});

/// Get Proxy event types
pub fn get_proxy_event_types() -> Vec<EventType> {
    vec![
        PROXY_HTTP_REQUEST_EVENT.clone(),
        PROXY_HTTP_RESPONSE_EVENT.clone(),
        PROXY_HTTPS_CONNECT_EVENT.clone(),
    ]
}
