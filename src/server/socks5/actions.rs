//! SOCKS5 protocol actions implementation

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
use tracing::debug;

/// SOCKS5 protocol action handler
pub struct Socks5Protocol {}

impl Socks5Protocol {
    pub fn new() -> Self {
        Self {}
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for Socks5Protocol {
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        // Future: Could add actions like:
        // - close_socks5_connection(connection_id)
        // - set_socks5_filter(patterns)
        // - list_socks5_connections()
        Vec::new()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            allow_socks5_connect_action(),
            deny_socks5_connect_action(),
            allow_socks5_auth_action(),
            deny_socks5_auth_action(),
            forward_socks5_data_action(),
            modify_socks5_data_action(),
            close_connection_action(),
        ]
    }
    fn protocol_name(&self) -> &'static str {
        "SOCKS5"
    }
    fn get_event_types(&self) -> Vec<EventType> {
        get_socks5_event_types()
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>SOCKS5"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["socks", "socks5"]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .well_known_port(1080)
            .implementation("Manual SOCKS5 protocol (RFC 1928)")
            .llm_control("Auth allow/deny, connection allow/deny, MITM data forward/modify/close")
            // Not "curl --socks5", which this claimed and which no test does. The peer in
            // tests/server/socks5/e2e_test.rs is a SOCKS5 client hand-written inside the test
            // over a raw TcpStream -- an independent reading of RFC 1928, not an independent
            // implementation, so it does not clear the bar for Beta.
            .e2e_testing(
                "A SOCKS5 client hand-written in tests/server/socks5/e2e_test.rs (raw TcpStream, \
                 RFC 1928/1929 by hand): no-auth and username/password handshakes, CONNECT by \
                 IPv4 and by domain, a refusal, and an HTTP exchange through a MITM tunnel. No \
                 third-party SOCKS5 client has been run against it.",
            )
            .notes(
                "OPEN RELAY BY DESIGN, AND UNRESTRICTED: the destination of every connection is \
                 chosen by the peer, and there is no allow-list, deny-list or network \
                 restriction of any kind. Loopback, link-local (including 169.254.169.254, the \
                 cloud instance-metadata endpoint), and every RFC 1918 range are all reachable, \
                 so anyone who can reach this port can reach whatever this host can -- an SSRF \
                 pivot into the operator's private network, and a relay someone else's traffic \
                 can be laundered through. The only gate is the model: `filter_mode` decides \
                 whether it is consulted at all, and `allow_all` or a `selective` filter whose \
                 patterns miss (with `default_action: allow`) connects with no consultation \
                 whatsoever. `target_host_patterns` and `target_port_ranges` select what the \
                 model is ASKED about; they do not restrict anything on their own. Do not \
                 expose this to an untrusted network. \
                 CONNECT only (no BIND/UDP ASSOCIATE); a connect/auth event with no explicit \
                 allow action is denied; MITM inspection costs one LLM call per data chunk in \
                 each direction; the handshake reads time out after 30s but the number of \
                 concurrent connections is unbounded.",
            )
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn description(&self) -> &'static str {
        "SOCKS5 proxy server"
    }
    fn example_prompt(&self) -> &'static str {
        "Start a SOCKS5 proxy on port 1080 that asks before connecting"
    }
    fn get_startup_parameters(&self) -> Vec<crate::llm::actions::ParameterDefinition> {
        use crate::llm::actions::ParameterDefinition;
        vec![
                ParameterDefinition {
                    name: "auth_methods".to_string(),
                    type_hint: "array".to_string(),
                    description: "Array of allowed authentication methods: 'none' (no auth) or 'username_password' (RFC 1929)".to_string(),
                    required: false,
                    example: json!(["none", "username_password"]),
                    default: None,
                },
                ParameterDefinition {
                    name: "default_action".to_string(),
                    type_hint: "string".to_string(),
                    description: "Default action when no filter matches: 'allow' or 'deny'".to_string(),
                    required: false,
                    example: json!("allow"),
                    default: None,
                },
                ParameterDefinition {
                    name: "filter_mode".to_string(),
                    type_hint: "string".to_string(),
                    description: "Filter mode: 'allow_all', 'deny_all', 'ask_llm', or 'selective'".to_string(),
                    required: false,
                    example: json!("selective"),
                    default: None,
                },
                ParameterDefinition {
                    name: "filter".to_string(),
                    type_hint: "object".to_string(),
                    description: "Filter configuration object with 'target_host_patterns' (array of regex) and 'target_port_ranges' (array of [start, end])".to_string(),
                    required: false,
                    example: json!({
                        "target_host_patterns": [".*\\.example\\.com"],
                        "target_port_ranges": [[80, 80], [443, 443]]
                    }),
                    default: None,
                },
                ParameterDefinition {
                    name: "mitm_by_default".to_string(),
                    type_hint: "boolean".to_string(),
                    description: "Enable Man-in-the-Middle inspection for all allowed connections by default".to_string(),
                    required: false,
                    example: json!(false),
                    default: None,
                },
                ParameterDefinition {
                    name: "idle_timeout_secs".to_string(),
                    type_hint: "number".to_string(),
                    description: "Seconds an established tunnel may move no data in either \
                                  direction before the proxy closes it (default 3600). Traffic \
                                  either way keeps it open. Raise it for long-idle protocols \
                                  such as SSH without keepalives."
                        .to_string(),
                    required: false,
                    example: json!(3600),
                    default: Some(serde_json::json!(super::RELAY_IDLE_TIMEOUT.as_secs())),
                },
            ]
    }
    fn group_name(&self) -> &'static str {
        "Proxy & Network"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;

        // Deterministic: allow every auth attempt and every CONNECT (no MITM),
        // no LLM call. One script handles both events.
        let script = r#"import json, sys
data = json.load(sys.stdin)
event = data["event"]
et = data["event_type_id"]
if et == "socks5_connect_request":
    actions = [{"type": "allow_socks5_connect", "mitm": False}]
elif et == "socks5_auth_request":
    actions = [{"type": "allow_socks5_auth"}]
else:
    actions = []
print(json.dumps({"actions": actions}))"#;

        StartupExamples::new(
            // LLM mode
            json!({
                "type": "open_server",
                "port": 1080,
                "base_stack": "socks5",
                "instruction": "SOCKS5 proxy server. Accept all connections without authentication. Allow all CONNECT requests to pass through."
            }),
            // Script mode
            json!({
                "type": "open_server",
                "port": 1080,
                "base_stack": "socks5",
                "event_handlers": [{
                    "event_pattern": "socks5_connect_request",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": script
                    }
                }, {
                    "event_pattern": "socks5_auth_request",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": script
                    }
                }]
            }),
            // Static mode
            json!({
                "type": "open_server",
                "port": 1080,
                "base_stack": "socks5",
                "event_handlers": [{
                    "event_pattern": "socks5_connect_request",
                    "handler": {
                        "type": "static",
                        "actions": [{
                            "type": "allow_socks5_connect",
                            "mitm": false
                        }]
                    }
                }]
            }),
        )
    }
}

// Implement Server trait (server-specific functionality)
impl Server for Socks5Protocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::server::socks5::Socks5Server;
            Socks5Server::spawn_with_llm_actions(
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
            "allow_socks5_connect" => self.execute_allow_connect(action),
            "deny_socks5_connect" => self.execute_deny_connect(action),
            "allow_socks5_auth" => self.execute_allow_auth(action),
            "deny_socks5_auth" => self.execute_deny_auth(action),
            "forward_socks5_data" => self.execute_forward_data(action),
            "modify_socks5_data" => self.execute_modify_data(action),
            "close_connection" => self.execute_close_connection(action),
            _ => Err(anyhow::anyhow!("Unknown SOCKS5 action: {}", action_type)),
        }
    }
}

impl Socks5Protocol {
    fn execute_allow_connect(&self, action: serde_json::Value) -> Result<ActionResult> {
        let _mitm = action
            .get("mitm")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        debug!("SOCKS5 allowing connection (MITM: {})", _mitm);

        // Return NoAction to signal connection should proceed
        Ok(ActionResult::NoAction)
    }

    fn execute_deny_connect(&self, action: serde_json::Value) -> Result<ActionResult> {
        let reason = action
            .get("reason")
            .and_then(|v| v.as_str())
            .unwrap_or("Connection denied by policy");

        debug!("SOCKS5 denying connection: {}", reason);

        // Return CloseConnection to deny
        Ok(ActionResult::CloseConnection)
    }

    fn execute_allow_auth(&self, _action: serde_json::Value) -> Result<ActionResult> {
        debug!("SOCKS5 allowing authentication");
        Ok(ActionResult::NoAction)
    }

    fn execute_deny_auth(&self, action: serde_json::Value) -> Result<ActionResult> {
        let reason = action
            .get("reason")
            .and_then(|v| v.as_str())
            .unwrap_or("Authentication failed");

        debug!("SOCKS5 denying authentication: {}", reason);
        Ok(ActionResult::CloseConnection)
    }

    fn execute_forward_data(&self, _action: serde_json::Value) -> Result<ActionResult> {
        debug!("SOCKS5 forwarding data as-is");
        // Return NoAction to signal data should be forwarded unchanged
        Ok(ActionResult::NoAction)
    }

    fn execute_modify_data(&self, action: serde_json::Value) -> Result<ActionResult> {
        let modified_data = action
            .get("data")
            .and_then(|v| v.as_str())
            .context("Missing 'data' field for modify_socks5_data action")?;

        // The `data` field used to be documented as "base64 or UTF-8" while the
        // executor only ever took `.as_bytes()`, so a base64 payload was relayed
        // as its literal base64 text. Encoding is now explicit and honoured.
        let bytes = decode_outbound_data(modified_data, &action)?;

        debug!("SOCKS5 modifying data (new length: {} bytes)", bytes.len());

        // Return Output with the modified data
        Ok(ActionResult::Output(bytes))
    }

    fn execute_close_connection(&self, action: serde_json::Value) -> Result<ActionResult> {
        let reason = action
            .get("reason")
            .and_then(|v| v.as_str())
            .unwrap_or("Connection closed by policy");

        debug!("SOCKS5 closing connection: {}", reason);
        Ok(ActionResult::CloseConnection)
    }
}

/// Turn the `data` field of a MITM action into the exact bytes to relay,
/// honouring the action's optional `encoding` field.
///
/// - `encoding` absent or `"utf8"`: the string's UTF-8 bytes are relayed verbatim.
/// - `encoding` = `"hex"`: `data` is decoded as hex.
///
/// There is deliberately no auto-detection: `"48656c6c6f"` is both valid text and
/// valid hex, so the caller must say which it means.
fn decode_outbound_data(data: &str, action: &serde_json::Value) -> Result<Vec<u8>> {
    let encoding = action
        .get("encoding")
        .and_then(|v| v.as_str())
        .unwrap_or("utf8");

    match encoding {
        "utf8" => Ok(data.as_bytes().to_vec()),
        "hex" => {
            let cleaned: String = data
                .chars()
                .filter(|c| !c.is_ascii_whitespace() && *c != ':')
                .collect();
            let cleaned = cleaned.strip_prefix("0x").unwrap_or(&cleaned);

            if cleaned.len() % 2 != 0 {
                return Err(anyhow::anyhow!(
                    "Invalid hex in 'data': expected an even number of hex digits, got {} \
                     ({data:?}). Each byte is two hex digits, e.g. \"48656c6c6f\" = \"Hello\".",
                    cleaned.len()
                ));
            }

            hex::decode(cleaned).map_err(|e| {
                anyhow::anyhow!(
                    "Invalid hex in 'data' ({data:?}): {e}. Use only 0-9/a-f, two digits per \
                     byte. To relay this string as literal text instead, omit 'encoding' or \
                     set it to \"utf8\"."
                )
            })
        }
        other => Err(anyhow::anyhow!(
            "Unknown 'encoding' value {other:?}. Valid values are \"utf8\" (default) and \"hex\"."
        )),
    }
}

// ============================================================================
// SOCKS5 Action Definitions
// ============================================================================

fn allow_socks5_connect_action() -> ActionDefinition {
    ActionDefinition {
        name: "allow_socks5_connect".to_string(),
        description: "Allow SOCKS5 CONNECT request to proceed".to_string(),
        parameters: vec![Parameter {
            name: "mitm".to_string(),
            type_hint: "boolean".to_string(),
            description: "Enable MITM inspection for this connection (default: false)".to_string(),
            required: false,
        }],
        example: json!({
            "type": "allow_socks5_connect",
            "mitm": false
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> SOCKS5 allow (MITM={mitm})")
                .with_debug("SOCKS5 allow_socks5_connect: mitm={mitm}"),
        ),
    }
}

fn deny_socks5_connect_action() -> ActionDefinition {
    ActionDefinition {
        name: "deny_socks5_connect".to_string(),
        description: "Deny SOCKS5 CONNECT request".to_string(),
        parameters: vec![Parameter {
            name: "reason".to_string(),
            type_hint: "string".to_string(),
            description: "Reason for denial (for logging)".to_string(),
            required: false,
        }],
        example: json!({
            "type": "deny_socks5_connect",
            "reason": "Blocked by security policy"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> SOCKS5 deny: {reason}")
                .with_debug("SOCKS5 deny_socks5_connect: reason={reason}"),
        ),
    }
}

fn allow_socks5_auth_action() -> ActionDefinition {
    ActionDefinition {
        name: "allow_socks5_auth".to_string(),
        description: "Allow SOCKS5 username/password authentication".to_string(),
        parameters: vec![],
        example: json!({
            "type": "allow_socks5_auth"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> SOCKS5 auth allowed")
                .with_debug("SOCKS5 allow_socks5_auth"),
        ),
    }
}

fn deny_socks5_auth_action() -> ActionDefinition {
    ActionDefinition {
        name: "deny_socks5_auth".to_string(),
        description: "Deny SOCKS5 authentication".to_string(),
        parameters: vec![Parameter {
            name: "reason".to_string(),
            type_hint: "string".to_string(),
            description: "Reason for denial (for logging)".to_string(),
            required: false,
        }],
        example: json!({
            "type": "deny_socks5_auth",
            "reason": "Invalid credentials"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> SOCKS5 auth denied: {reason}")
                .with_debug("SOCKS5 deny_socks5_auth: reason={reason}"),
        ),
    }
}

fn forward_socks5_data_action() -> ActionDefinition {
    ActionDefinition {
        name: "forward_socks5_data".to_string(),
        description: "Forward SOCKS5 data without modification (MITM mode)".to_string(),
        parameters: vec![],
        example: json!({
            "type": "forward_socks5_data"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> SOCKS5 forward")
                .with_debug("SOCKS5 forward_socks5_data"),
        ),
    }
}

fn modify_socks5_data_action() -> ActionDefinition {
    ActionDefinition {
        name: "modify_socks5_data".to_string(),
        description: "Modify SOCKS5 data before forwarding (MITM mode)".to_string(),
        parameters: vec![
            Parameter {
                name: "data".to_string(),
                type_hint: "string".to_string(),
                description: "Replacement payload. Interpreted according to 'encoding'.".to_string(),
                required: true,
            },
            Parameter {
                name: "encoding".to_string(),
                type_hint: "string".to_string(),
                description: "How to interpret 'data': \"utf8\" (default) relays the string's bytes verbatim; \"hex\" decodes it as hex first. Match the 'encoding' reported on the event to round-trip binary payloads.".to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "modify_socks5_data",
            "data": "Modified payload"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> SOCKS5 modify data")
                .with_debug("SOCKS5 modify_socks5_data"),
        ),
    }
}

fn close_connection_action() -> ActionDefinition {
    ActionDefinition {
        name: "close_connection".to_string(),
        description: "Close the SOCKS5 connection (MITM mode)".to_string(),
        parameters: vec![Parameter {
            name: "reason".to_string(),
            type_hint: "string".to_string(),
            description: "Reason for closing (for logging)".to_string(),
            required: false,
        }],
        example: json!({
            "type": "close_connection",
            "reason": "Suspicious data detected"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> SOCKS5 close: {reason}")
                .with_debug("SOCKS5 close_connection: reason={reason}"),
        ),
    }
}

// ============================================================================
// SOCKS5 Event Type Constants
// ============================================================================

pub static SOCKS5_AUTH_REQUEST_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "socks5_auth_request",
        "SOCKS5 client authentication request (username/password)",
        json!({
            "type": "allow_socks5_auth"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "username".to_string(),
            type_hint: "string".to_string(),
            description: "Username provided by client".to_string(),
            required: true,
        },
        Parameter {
            name: "password".to_string(),
            type_hint: "string".to_string(),
            description: "Password provided by client".to_string(),
            required: true,
        },
    ])
    .with_actions(vec![allow_socks5_auth_action(), deny_socks5_auth_action()])
});

pub static SOCKS5_CONNECT_REQUEST_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "socks5_connect_request",
        "SOCKS5 CONNECT request to target address",
        json!({
            "type": "allow_socks5_connect",
            "mitm": false
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "target".to_string(),
            type_hint: "string".to_string(),
            description: "Target address (IP or domain:port)".to_string(),
            required: true,
        },
        Parameter {
            name: "username".to_string(),
            type_hint: "string".to_string(),
            description: "Authenticated username (if any)".to_string(),
            required: false,
        },
    ])
    .with_actions(vec![
        allow_socks5_connect_action(),
        deny_socks5_connect_action(),
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("SOCKS5 {client_ip} -> {target}")
            .with_debug("SOCKS5 connection from {client_ip}:{client_port} to {target}")
            .with_trace("SOCKS5: {json_pretty(.)}"),
    )
});

pub static SOCKS5_DATA_TO_TARGET_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "socks5_data_to_target",
        "Data from client to target (MITM inspection mode)",
        json!({
            "type": "forward_socks5_data"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "data".to_string(),
            type_hint: "string".to_string(),
            description: "Data being sent from client to target. Printable payloads arrive as text, binary arrives hex-encoded; check 'encoding'.".to_string(),
            required: true,
        },
        Parameter {
            name: "encoding".to_string(),
            type_hint: "string".to_string(),
            description: "How 'data' is encoded: \"utf8\" or \"hex\". Pass the same value to modify_socks5_data when replacing the payload.".to_string(),
            required: true,
        },
        Parameter {
            name: "target".to_string(),
            type_hint: "string".to_string(),
            description: "Target address (IP or domain:port)".to_string(),
            required: true,
        },
        Parameter {
            name: "username".to_string(),
            type_hint: "string".to_string(),
            description: "Authenticated username (if any)".to_string(),
            required: false,
        },
    ])
    .with_actions(vec![
        forward_socks5_data_action(),
        modify_socks5_data_action(),
        close_connection_action(),
    ])
});

pub static SOCKS5_DATA_FROM_TARGET_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "socks5_data_from_target",
        "Data from target to client (MITM inspection mode)",
        json!({
            "type": "forward_socks5_data"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "data".to_string(),
            type_hint: "string".to_string(),
            description: "Data being sent from target to client. Printable payloads arrive as text, binary arrives hex-encoded; check 'encoding'.".to_string(),
            required: true,
        },
        Parameter {
            name: "encoding".to_string(),
            type_hint: "string".to_string(),
            description: "How 'data' is encoded: \"utf8\" or \"hex\". Pass the same value to modify_socks5_data when replacing the payload.".to_string(),
            required: true,
        },
        Parameter {
            name: "target".to_string(),
            type_hint: "string".to_string(),
            description: "Target address (IP or domain:port)".to_string(),
            required: true,
        },
        Parameter {
            name: "username".to_string(),
            type_hint: "string".to_string(),
            description: "Authenticated username (if any)".to_string(),
            required: false,
        },
    ])
    .with_actions(vec![
        forward_socks5_data_action(),
        modify_socks5_data_action(),
        close_connection_action(),
    ])
});

pub fn get_socks5_event_types() -> Vec<EventType> {
    vec![
        SOCKS5_AUTH_REQUEST_EVENT.clone(),
        SOCKS5_CONNECT_REQUEST_EVENT.clone(),
        SOCKS5_DATA_TO_TARGET_EVENT.clone(),
        SOCKS5_DATA_FROM_TARGET_EVENT.clone(),
    ]
}
