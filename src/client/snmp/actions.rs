//! SNMP client protocol actions implementation

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

/// SNMP client connected event
pub static SNMP_CLIENT_CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "snmp_connected",
        "SNMP client successfully connected to agent",
        json!({
            "type": "send_snmp_get",
            "oids": ["1.3.6.1.2.1.1.3.0"]
        }),
    )
    .with_parameters(vec![Parameter {
        name: "remote_addr".to_string(),
        type_hint: "string".to_string(),
        description: "SNMP agent address".to_string(),
        required: true,
    }])
});

/// SNMP client response received event
pub static SNMP_CLIENT_RESPONSE_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "snmp_response_received",
        "Response received from SNMP agent",
        json!({
            "type": "send_snmp_getnext",
            "oids": ["1.3.6.1.2.1.1.1.0"]
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "request_type".to_string(),
            type_hint: "string".to_string(),
            description:
                "Type of SNMP request (GetRequest, GetNextRequest, GetBulkRequest, SetRequest)"
                    .to_string(),
            required: true,
        },
        Parameter {
            name: "variables".to_string(),
            type_hint: "array".to_string(),
            description: "Array of OID/value pairs in response".to_string(),
            required: true,
        },
        Parameter {
            name: "error_status".to_string(),
            type_hint: "integer".to_string(),
            description: "SNMP error status (0=noError, 2=noSuchName, etc.)".to_string(),
            required: true,
        },
        Parameter {
            name: "usm_report".to_string(),
            type_hint: "object".to_string(),
            description: "SNMPv3 only, present when the agent answered with a USM report instead of a response: {report, count}, report being usmStatsWrongDigests (wrong auth password), usmStatsUnknownUserNames, usmStatsUnsupportedSecLevels, usmStatsDecryptionErrors (wrong privacy password) or usmStatsNotInTimeWindows (the clock was resynchronised from it; resend). variables is then empty".to_string(),
            required: false,
        },
    ])
});

/// SNMP client protocol action handler
pub struct SnmpClientProtocol;

impl SnmpClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for SnmpClientProtocol {
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![
            ActionDefinition {
                name: "send_snmp_get".to_string(),
                description: "Send SNMP GET request for one or more OIDs".to_string(),
                parameters: vec![Parameter {
                    name: "oids".to_string(),
                    type_hint: "array".to_string(),
                    description: "Array of OID strings (e.g., [\"1.3.6.1.2.1.1.1.0\"])".to_string(),
                    required: true,
                }],
                example: json!({
                    "type": "send_snmp_get",
                    "oids": ["1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.5.0"]
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "send_snmp_getnext".to_string(),
                description: "Send SNMP GETNEXT request to walk OID tree".to_string(),
                parameters: vec![Parameter {
                    name: "oids".to_string(),
                    type_hint: "array".to_string(),
                    description: "Array of starting OID strings".to_string(),
                    required: true,
                }],
                example: json!({
                    "type": "send_snmp_getnext",
                    "oids": ["1.3.6.1.2.1.1"]
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "send_snmp_getbulk".to_string(),
                description:
                    "Send SNMP GETBULK request for efficient bulk retrieval (SNMPv2c only)"
                        .to_string(),
                parameters: vec![
                    Parameter {
                        name: "oids".to_string(),
                        type_hint: "array".to_string(),
                        description: "Array of starting OID strings".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "non_repeaters".to_string(),
                        type_hint: "integer".to_string(),
                        description: "Number of non-repeating variables (default: 0)".to_string(),
                        required: false,
                    },
                    Parameter {
                        name: "max_repetitions".to_string(),
                        type_hint: "integer".to_string(),
                        description:
                            "Maximum repetitions for each repeating variable (default: 10)"
                                .to_string(),
                        required: false,
                    },
                ],
                example: json!({
                    "type": "send_snmp_getbulk",
                    "oids": ["1.3.6.1.2.1.2.2.1"],
                    "non_repeaters": 0,
                    "max_repetitions": 10
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "send_snmp_set".to_string(),
                description: "Send SNMP SET request to modify agent values".to_string(),
                parameters: vec![Parameter {
                    name: "variables".to_string(),
                    type_hint: "array".to_string(),
                    description: "Array of {oid, type, value} objects".to_string(),
                    required: true,
                }],
                example: json!({
                    "type": "send_snmp_set",
                    "variables": [
                        {"oid": "1.3.6.1.2.1.1.5.0", "type": "string", "value": "new-hostname"}
                    ]
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "disconnect".to_string(),
                description: "Disconnect from the SNMP agent".to_string(),
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
                name: "send_snmp_get".to_string(),
                description: "Send follow-up SNMP GET request based on response".to_string(),
                parameters: vec![Parameter {
                    name: "oids".to_string(),
                    type_hint: "array".to_string(),
                    description: "Array of OID strings".to_string(),
                    required: true,
                }],
                example: json!({
                    "type": "send_snmp_get",
                    "oids": ["1.3.6.1.2.1.1.3.0"]
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "send_snmp_getnext".to_string(),
                description: "Continue walking OID tree".to_string(),
                parameters: vec![Parameter {
                    name: "oids".to_string(),
                    type_hint: "array".to_string(),
                    description: "Array of OID strings from previous response".to_string(),
                    required: true,
                }],
                example: json!({
                    "type": "send_snmp_getnext",
                    "oids": ["1.3.6.1.2.1.1.1.0"]
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "wait_for_more".to_string(),
                description: "Wait for more responses (no action)".to_string(),
                parameters: vec![],
                example: json!({
                    "type": "wait_for_more"
                }),
                log_template: None,
            },
        ]
    }
    fn protocol_name(&self) -> &'static str {
        "SNMP"
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            EventType::new(
                "snmp_connected",
                "Triggered when SNMP client connects to agent",
                json!({"type": "placeholder", "event_id": "snmp_connected"}),
            ),
            EventType::new(
                "snmp_response_received",
                "Triggered when SNMP client receives a response",
                json!({"type": "placeholder", "event_id": "snmp_response_received"}),
            ),
        ]
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>UDP>SNMP"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "snmp",
            "snmp client",
            "connect to snmp",
            "network management",
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .implementation("UDP-based with rasn-snmp for BER encoding/decoding; SNMPv3 USM (src/server/snmp/usm.rs, shared with the agent): engine discovery at start, HMAC-MD5/SHA-1/SHA-224/256/384/512 authentication, DES-CBC and AES-128-CFB privacy, every reply's message id, engine, level and MAC checked before it is read")
            .llm_control("Full control over SNMP operations (GET, GETNEXT, GETBULK, SET); SNMPv3 reports reach the handler as usm_report")
            .e2e_testing("tests/client/snmp/real_server_test.rs: Net-SNMP's snmpd, unprivileged in a temp dir, with a SHA-256/AES and an MD5/DES user. NetGet discovers its engine, GETs, and a handler SETs sysContact from the reply; the value is read back with Net-SNMP's snmpget as the other user. A wrong password is snmpd's own wrongDigests report. Fails, not skips, without snmpd")
            .notes("v1/v2c with a community; v3 with one USM user per client. No AES-192/256 (expired drafts with two incompatible key extensions), no VACM on this side, no v3 informs or traps")
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn description(&self) -> &'static str {
        "SNMP client for network device monitoring and management"
    }
    fn example_prompt(&self) -> &'static str {
        "Connect to SNMP agent at localhost:161 and query system description (OID 1.3.6.1.2.1.1.1.0)"
    }
    fn group_name(&self) -> &'static str {
        "Network Management"
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "community".to_string(),
                description: "SNMP community string (default: 'public')".to_string(),
                type_hint: "string".to_string(),
                required: false,
                example: json!("public"),
                default: None,
            },
            ParameterDefinition {
                name: "version".to_string(),
                description: "SNMP version: 'v1', 'v2c' or 'v3' (default: 'v2c'). v3 needs v3_user; the agent's engine is discovered when the client starts, and an agent that never answers discovery fails the start".to_string(),
                type_hint: "string".to_string(),
                required: false,
                example: json!("v2c"),
                default: None,
            },
            ParameterDefinition {
                name: "v3_user".to_string(),
                description: "SNMPv3 USM user: {name, auth_protocol: none|md5|sha|sha224|sha256|sha384|sha512, auth_password, priv_protocol: none|des|aes, priv_password}. Passwords are 8 to 256 bytes and never appear in events or logs. The level follows from the protocols: no auth is noAuthNoPriv, auth alone authNoPriv, both authPriv".to_string(),
                type_hint: "object".to_string(),
                required: false,
                example: json!({"name": "monitor", "auth_protocol": "sha256", "auth_password": "monitor-auth-pass", "priv_protocol": "aes", "priv_password": "monitor-priv-pass"}),
                default: None,
            },
            ParameterDefinition {
                name: "context_name".to_string(),
                description: "SNMPv3 contextName for every request, at most 32 bytes (default: the empty default context)".to_string(),
                type_hint: "string".to_string(),
                required: false,
                example: json!("vlan-7"),
                default: None,
            },
            ParameterDefinition {
                name: "timeout_ms".to_string(),
                description: "Request timeout in milliseconds (default: 5000)".to_string(),
                type_hint: "integer".to_string(),
                required: false,
                example: json!(5000),
                default: None,
            },
            ParameterDefinition {
                name: "retries".to_string(),
                description: "Number of retries on timeout (default: 3)".to_string(),
                type_hint: "integer".to_string(),
                required: false,
                example: json!(3),
                default: None,
            },
        ]
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        use serde_json::json;

        StartupExamples::new(
            // LLM mode: LLM controls SNMP queries
            json!({
                "type": "open_client",
                "remote_addr": "192.168.1.1:161",
                "base_stack": "snmp",
                "instruction": "Query the system description (1.3.6.1.2.1.1.1.0) and system uptime (1.3.6.1.2.1.1.3.0)"
            }),
            // Script mode: Code-based deterministic responses
            json!({
                "type": "open_client",
                "remote_addr": "192.168.1.1:161",
                "base_stack": "snmp",
                "event_handlers": [{
                    "event_pattern": "snmp_response_received",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "<snmp_client_handler>"
                    }
                }]
            }),
            // Static mode: Fixed SNMP GET on connect
            json!({
                "type": "open_client",
                "remote_addr": "192.168.1.1:161",
                "base_stack": "snmp",
                "event_handlers": [
                    {
                        "event_pattern": "snmp_connected",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "send_snmp_get",
                                "oids": ["1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.5.0"]
                            }]
                        }
                    },
                    {
                        "event_pattern": "snmp_response_received",
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
impl Client for SnmpClientProtocol {
    fn connect(
        &self,
        ctx: crate::protocol::ConnectContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::client::snmp::SnmpClient;
            SnmpClient::connect_with_llm_actions(
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
            "send_snmp_get" => {
                let oids = action
                    .get("oids")
                    .and_then(|v| v.as_array())
                    .context("Missing 'oids' array")?
                    .iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect::<Vec<_>>();

                if oids.is_empty() {
                    return Err(anyhow::anyhow!("At least one OID required for GET"));
                }

                Ok(ClientActionResult::Custom {
                    name: "snmp_get".to_string(),
                    data: json!({
                        "oids": oids,
                    }),
                })
            }
            "send_snmp_getnext" => {
                let oids = action
                    .get("oids")
                    .and_then(|v| v.as_array())
                    .context("Missing 'oids' array")?
                    .iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect::<Vec<_>>();

                if oids.is_empty() {
                    return Err(anyhow::anyhow!("At least one OID required for GETNEXT"));
                }

                Ok(ClientActionResult::Custom {
                    name: "snmp_getnext".to_string(),
                    data: json!({
                        "oids": oids,
                    }),
                })
            }
            "send_snmp_getbulk" => {
                let oids = action
                    .get("oids")
                    .and_then(|v| v.as_array())
                    .context("Missing 'oids' array")?
                    .iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect::<Vec<_>>();

                if oids.is_empty() {
                    return Err(anyhow::anyhow!("At least one OID required for GETBULK"));
                }

                let non_repeaters = action
                    .get("non_repeaters")
                    .and_then(|v| v.as_i64())
                    .unwrap_or(0) as i32;

                let max_repetitions = action
                    .get("max_repetitions")
                    .and_then(|v| v.as_i64())
                    .unwrap_or(10) as i32;

                Ok(ClientActionResult::Custom {
                    name: "snmp_getbulk".to_string(),
                    data: json!({
                        "oids": oids,
                        "non_repeaters": non_repeaters,
                        "max_repetitions": max_repetitions,
                    }),
                })
            }
            "send_snmp_set" => {
                let variables = action
                    .get("variables")
                    .and_then(|v| v.as_array())
                    .context("Missing 'variables' array")?
                    .clone();

                if variables.is_empty() {
                    return Err(anyhow::anyhow!("At least one variable required for SET"));
                }

                Ok(ClientActionResult::Custom {
                    name: "snmp_set".to_string(),
                    data: json!({
                        "variables": variables,
                    }),
                })
            }
            "disconnect" => Ok(ClientActionResult::Disconnect),
            "wait_for_more" => Ok(ClientActionResult::WaitForMore),
            _ => Err(anyhow::anyhow!(
                "Unknown SNMP client action: {}",
                action_type
            )),
        }
    }
}
