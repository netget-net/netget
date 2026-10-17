//! SNMP protocol actions implementation

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

/// SNMP protocol action handler
pub struct SnmpProtocol;

impl SnmpProtocol {
    pub fn new() -> Self {
        Self
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for SnmpProtocol {
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        // SNMP has async action for sending traps
        vec![send_trap_action()]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            send_snmp_response_action(),
            send_snmp_error_action(),
            ignore_request_action(),
            acknowledge_notification_action(),
            ignore_notification_action(),
        ]
    }
    fn protocol_name(&self) -> &'static str {
        "SNMP"
    }
    fn get_event_types(&self) -> Vec<EventType> {
        get_snmp_event_types()
    }
    fn get_startup_parameters(&self) -> Vec<crate::llm::actions::ParameterDefinition> {
        use crate::llm::actions::ParameterDefinition;
        vec![
            ParameterDefinition {
                name: "v3_users".into(),
                type_hint: "array".into(),
                description: "SNMPv3 USM users: [{name, auth_protocol: none|md5|sha|sha224|sha256|sha384|sha512, auth_password, priv_protocol: none|des|aes, priv_password}]. Passwords are 8 to 256 bytes. A user is answered only at the level it is configured for (authPriv users never get an unencrypted answer); others get the USM's reports. Absent means SNMPv3 is not served and v3 messages are dropped".into(),
                required: false,
                example: json!([{"name": "monitor", "auth_protocol": "sha256", "auth_password": "monitor-auth-pass", "priv_protocol": "aes", "priv_password": "monitor-priv-pass"}]),
                default: None,
            },
            ParameterDefinition {
                name: "engine_id".into(),
                type_hint: "string".into(),
                description: "The agent's snmpEngineID in hexadecimal, 5 to 32 bytes, as Net-SNMP writes it. Absent means a random RFC 3411 format-5 ID chosen at start".into(),
                required: false,
                example: json!("8000000005a1b2c3d4e5f60718"),
                default: None,
            },
            ParameterDefinition {
                name: "engine_boots".into(),
                type_hint: "number".into(),
                description: "The agent's snmpEngineBoots, 1 to 2147483646. Absent means the number of wall-clock seconds since 2024-01-01, so each restart reports more boots than the last and an authenticated message captured in one run is refused in the next even with a fixed engine_id. Set it only where the wall clock cannot be trusted, and then raise it on every restart".into(),
                required: false,
                example: json!(2),
                // Derived from the wall clock at start (`usm::default_engine_boots`); no single
                // number describes it.
                default: None,
            },
        ]
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>UDP>SNMP"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["snmp", "snmp agent"]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{
            DevelopmentState, PrivilegeRequirement, ProtocolMetadataV2,
        };

        ProtocolMetadataV2::builder()
            .connectionless()
            // Answers on failure: a Response PDU with error-status genErr for the request's own id.
            .answers_on_failure()
            .state(DevelopmentState::Beta)
            .privilege_requirement(PrivilegeRequirement::PrivilegedPort(161))
            .well_known_udp_port(161)
            .implementation("rasn-snmp v0.18 for parsing + manual BER encoding; SNMPv3 USM in usm.rs (RustCrypto hmac/md-5/sha1/sha2/des/aes)")
            .llm_control("OID responses (sysDescr, ifTable, custom MIBs)")
            .e2e_testing("Net-SNMP's own snmpget/snmpgetnext (tests/server/snmp/test.rs), run with -On -Oe so the assertions pin the decoded type tag and value rather than the local MIB set. Not ignored, and it hard-fails rather than skipping when the binaries are absent. Not the `snmp` Rust crate, whatever the older notes said. Notifications (tests/server/snmp/notification_test.rs): Net-SNMP's snmptrap (v1 and v2c) and snmpinform send to NetGet, and snmptrapd receives NetGet's v2c trap, v2c inform (acknowledged) and v1 trap. SNMPv3 (tests/server/snmp/usm_test.rs): Net-SNMP's snmpget/getnext/bulkget/set and pysnmp 7.1.22 at every level, with MD5, SHA-1, SHA-224/256/384/512 and DES/AES-128, plus the USM's refusals and RFC 3414's key vectors")
            .notes("SNMPv1/v2c with a community; SNMPv3 with the USM when v3_users is set (RFC 3414 procedure and reports, HMAC-MD5/SHA-1/SHA-2 authentication, DES-CBC and AES-128-CFB privacy; a user is served only at its configured level; no VACM - the event names the user and level - no AES-192/256, no v3 notifications). request-id and community are echoed from the request automatically. Notifications both ways: send_trap sends v1/v2c traps and v2c informs (resent until acknowledged), and received traps and informs are snmp_notification events, an inform acknowledged only when the handler says so. Incoming BER is depth- and length-screened before rasn decodes it, decrypted v3 PDUs included: rasn 0.18 recurses without a bound on constructed OCTET STRINGs, and a 60 KB datagram was enough to stack-overflow the whole process")
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn description(&self) -> &'static str {
        "SNMP agent for network monitoring"
    }
    fn example_prompt(&self) -> &'static str {
        "SNMP Port 8161 serve OID 1.3.6.1.2.1.1.1.0 (sysDescr) return 'NetGet SNMP Server v0.1'"
    }
    fn group_name(&self) -> &'static str {
        "Core"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        StartupExamples::new(
            // LLM-driven example
            json!({
                "type": "open_server",
                "port": 161,
                "base_stack": "snmp",
                "instruction": "SNMP agent serving OID 1.3.6.1.2.1.1.1.0 (sysDescr) as 'NetGet SNMP Server v1.0'"
            }),
            // Script-based example
            json!({
                "type": "open_server",
                "port": 161,
                "base_stack": "snmp",
                "event_handlers": [{
                    "event_pattern": "snmp_request",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "# Handle SNMP GET request\noids = event.get('oids', [])\nvariables = [{'oid': oid, 'type': 'string', 'value': 'NetGet SNMP Server'} for oid in oids]\nrespond([{'type': 'send_snmp_response', 'variables': variables}])"
                    }
                }]
            }),
            // Static handler example
            json!({
                "type": "open_server",
                "port": 161,
                "base_stack": "snmp",
                "event_handlers": [{
                    "event_pattern": "snmp_request",
                    "handler": {
                        "type": "static",
                        "actions": [{
                            "type": "send_snmp_response",
                            "variables": [{
                                "oid": "1.3.6.1.2.1.1.1.0",
                                "type": "string",
                                "value": "NetGet SNMP Server v1.0"
                            }]
                        }]
                    }
                }]
            }),
        )
    }
}

// Implement Server trait (server-specific functionality)
impl Server for SnmpProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::server::snmp::SnmpServer;
            let usm = super::usm::agent_from_params(ctx.startup_params.as_ref())?;
            SnmpServer::spawn_with_llm_actions(
                ctx.legacy_listen_addr(),
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.server_id,
                usm,
            )
            .await
        })
    }
    fn execute_action_with_state<'a>(
        &'a self,
        action: serde_json::Value,
        state: AppState,
        server_id: Option<crate::state::ServerId>,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<ActionResult>> + Send + 'a>,
    > {
        if action.get("type").and_then(|v| v.as_str()) != Some("send_trap") {
            let result = self.execute_action(action);
            return Box::pin(async move { result });
        }
        Box::pin(async move {
            let out = super::notify::build(&action)?;
            let kind = if out.inform { "inform" } else { "trap" };
            let target = out.target.clone();
            let log_state = state.clone();
            let send = async move {
                let outcome = super::notify::send(&out).await;
                if let Some(id) = server_id {
                    log_state
                        .record_access_log(
                            crate::state::AccessLogOwner::Server(id.as_u32()),
                            "SNMP",
                            None,
                            "snmp_notification_sent",
                            json!({"kind": kind, "target": out.target}),
                            vec![match &outcome {
                                Ok(result) => result.clone(),
                                Err(e) => json!({"sent": false, "error": format!("{e:#}")}),
                            }],
                        )
                        .await;
                }
                match outcome {
                    Ok(result) => {
                        let acknowledged = result["acknowledged"].as_bool();
                        tracing::info!(
                            "SNMP {} to {} sent{} ({})",
                            kind,
                            out.target,
                            match acknowledged {
                                Some(true) => ", acknowledged",
                                Some(false) => ", never acknowledged",
                                None => "",
                            },
                            result
                        );
                    }
                    Err(e) => tracing::warn!("SNMP {} to {} failed: {:#}", kind, out.target, e),
                }
            };
            // An inform waits for its Response; run it beside the request that asked for it
            // rather than in front of that request's own answer.
            match server_id {
                Some(id) => {
                    state.spawn_server_task(id, send).await;
                }
                None => send.await,
            }
            Ok(ActionResult::Custom {
                name: "send_trap".into(),
                data: json!({"kind": kind, "target": target}),
            })
        })
    }

    fn execute_action(&self, action: serde_json::Value) -> Result<ActionResult> {
        let action_type = action
            .get("type")
            .and_then(|v| v.as_str())
            .context("Missing 'type' field in action")?;

        match action_type {
            "send_trap" => self.execute_send_trap(action),
            "send_snmp_response" => self.execute_send_snmp_response(action),
            "send_snmp_error" => self.execute_send_snmp_error(action),
            "ignore_request" => Ok(ActionResult::NoAction),
            "acknowledge_notification" => Ok(ActionResult::Custom {
                name: "acknowledge_notification".into(),
                data: json!({}),
            }),
            "ignore_notification" => Ok(ActionResult::NoAction),
            _ => Err(anyhow::anyhow!("Unknown SNMP action: {}", action_type)),
        }
    }
}

impl SnmpProtocol {
    /// `send_trap` without a running server only validates and encodes: the datagram goes out
    /// from `execute_action_with_state`, which every executor path calls.
    fn execute_send_trap(&self, action: serde_json::Value) -> Result<ActionResult> {
        super::notify::build(&action)?;
        Ok(ActionResult::NoAction)
    }

    /// Execute send_snmp_response sync action
    fn execute_send_snmp_response(&self, action: serde_json::Value) -> Result<ActionResult> {
        let variables = action
            .get("variables")
            .and_then(|v| v.as_array())
            .context("Missing 'variables' parameter")?;

        // Encode response data as JSON
        // The caller will convert this to actual SNMP response format
        let response_data = json!({
            "variables": variables,
            "error": false
        });

        Ok(ActionResult::Output(
            serde_json::to_vec(&response_data).context("Failed to serialize SNMP response")?,
        ))
    }

    /// Execute send_snmp_error sync action
    fn execute_send_snmp_error(&self, action: serde_json::Value) -> Result<ActionResult> {
        let error_message = action
            .get("error_message")
            .and_then(|v| v.as_str())
            .context("Missing 'error_message' parameter")?;

        // SNMP puts the reason on the wire as a number, not text: map the optional
        // 'error_status' (name or code) onto it, defaulting to genErr.
        let error_status = match action.get("error_status") {
            None => 5,
            Some(v) if v.is_null() => 5,
            Some(v) => {
                if let Some(n) = v.as_u64() {
                    if n > 5 {
                        return Err(anyhow::anyhow!(
                            "Invalid 'error_status' {n}: SNMPv1 defines 0-5 \
                             (0 noError, 1 tooBig, 2 noSuchName, 3 badValue, 4 readOnly, 5 genErr)"
                        ));
                    }
                    n as u8
                } else if let Some(s) = v.as_str() {
                    match s.trim().to_ascii_lowercase().as_str() {
                        "noerror" => 0,
                        "toobig" => 1,
                        "nosuchname" => 2,
                        "badvalue" => 3,
                        "readonly" => 4,
                        "generr" | "genericerror" => 5,
                        other => {
                            return Err(anyhow::anyhow!(
                                "Invalid 'error_status' {other:?}: expected one of noError, \
                                 tooBig, noSuchName, badValue, readOnly, genErr, or the \
                                 matching code 0-5"
                            ))
                        }
                    }
                } else {
                    return Err(anyhow::anyhow!(
                        "Invalid 'error_status': expected a name or a code 0-5, got {v}"
                    ));
                }
            }
        };

        let error_index = action
            .get("error_index")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        // Encode error response as JSON
        let response_data = json!({
            "error": true,
            "error_message": error_message,
            "error_status": error_status,
            "error_index": error_index
        });

        Ok(ActionResult::Output(
            serde_json::to_vec(&response_data).context("Failed to serialize SNMP error")?,
        ))
    }
}

fn param(name: &str, type_hint: &str, description: &str, required: bool) -> Parameter {
    Parameter {
        name: name.to_string(),
        type_hint: type_hint.to_string(),
        description: description.to_string(),
        required,
    }
}

/// Action definition for send_trap: a v1 or v2c trap, or a v2c inform.
fn send_trap_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_trap".to_string(),
        description: "Send an SNMP notification to a manager: a v2c trap (default), a v2c inform that is resent until the manager acknowledges it, or a v1 trap. sysUpTime.0 and snmpTrapOID.0 are added for v2c; the result is logged".to_string(),
        parameters: vec![
            param("target", "string", "The manager: host or host:port (port 162 when omitted)", true),
            param("trap_oid", "string", "v2c: the notification's OID (snmpTrapOID.0), e.g. 1.3.6.1.6.3.1.1.5.3 linkDown, 1.3.6.1.6.3.1.1.5.4 linkUp", false),
            param("variables", "array", "Variable bindings [{oid, type, value}]; type is integer, string (encoding hex for binary), oid, ipaddress, counter, gauge, timeticks, counter64 (v2c only) or null", false),
            param("version", "string", "v2c (default) or v1", false),
            param("inform", "boolean", "v2c: send an InformRequest and wait for the manager's acknowledgement (default false: a trap)", false),
            param("community", "string", "Community string (default public)", false),
            param("uptime", "number", "sysUpTime / time-stamp in hundredths of a second (default: time since NetGet started)", false),
            param("enterprise", "string", "v1: the enterprise OID (default 1.3.6.1.4.1.8072.9999)", false),
            param("generic_trap", "number", "v1: 0 coldStart, 1 warmStart, 2 linkDown, 3 linkUp, 4 authenticationFailure, 5 egpNeighborLoss, 6 enterpriseSpecific (default)", false),
            param("specific_trap", "number", "v1: the enterprise-specific trap number (default 0)", false),
            param("agent_addr", "string", "v1: the agent's IPv4 address in the trap (default 0.0.0.0)", false),
        ],
        example: json!({
            "type": "send_trap",
            "target": "127.0.0.1:162",
            "trap_oid": "1.3.6.1.6.3.1.1.5.3",
            "variables": [
                {"oid": "1.3.6.1.2.1.2.2.1.1.2", "type": "integer", "value": 2}
            ]
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> SNMP notification to {target}")
                .with_debug("SNMP send_trap: target={target}, {variables_len} vars"),
        ),
    }
}

fn acknowledge_notification_action() -> ActionDefinition {
    ActionDefinition {
        name: "acknowledge_notification".to_string(),
        description: "Accept the notification. For an inform this sends the Response the sender is waiting for; for a trap nothing goes on the wire".to_string(),
        parameters: vec![],
        example: json!({"type": "acknowledge_notification"}),
        log_template: Some(
            LogTemplate::new()
                .with_info("SNMP notification acknowledged")
                .with_debug("SNMP acknowledge_notification"),
        ),
    }
}

fn ignore_notification_action() -> ActionDefinition {
    ActionDefinition {
        name: "ignore_notification".to_string(),
        description:
            "Do not accept it: an inform gets no Response, so its sender retries and then gives up"
                .to_string(),
        parameters: vec![],
        example: json!({"type": "ignore_notification"}),
        log_template: Some(
            LogTemplate::new()
                .with_info("SNMP notification ignored")
                .with_debug("SNMP ignore_notification"),
        ),
    }
}

pub static SNMP_NOTIFICATION_EVENT: LazyLock<EventType> =
    LazyLock::new(|| {
        EventType::new(
            "snmp_notification",
            "A trap or inform arrived from an agent",
            json!({"type": "acknowledge_notification"}),
        )
        .with_parameters(vec![
        param(
            "kind",
            "string",
            "trap or inform (an inform waits for acknowledgement)",
            true,
        ),
        param("version", "string", "The SNMP version the notification used: v1 or v2c", true),
        param(
            "community",
            "string",
            "Community string the sender used",
            true,
        ),
        param(
            "trap_oid",
            "string",
            "v2c: snmpTrapOID.0, the notification's identity (e.g. 1.3.6.1.6.3.1.1.5.3 linkDown)",
            false,
        ),
        param(
            "uptime",
            "number",
            "The sender's sysUpTime (v2c) or time-stamp (v1), hundredths of a second",
            false,
        ),
        param("enterprise", "string", "v1: the enterprise OID", false),
        param(
            "agent_addr",
            "string",
            "v1: the agent address the trap names",
            false,
        ),
        param(
            "generic_trap",
            "number",
            "v1: 0 coldStart … 6 enterpriseSpecific",
            false,
        ),
        param(
            "specific_trap",
            "number",
            "v1: the enterprise-specific trap number",
            false,
        ),
        param(
            "variables",
            "array",
            "The other variable bindings [{oid, type, value}] (binary strings carry encoding hex)",
            true,
        ),
        param(
            "request_id",
            "number",
            "v2c: the PDU's request id (an inform's acknowledgement echoes it automatically)",
            false,
        ),
        param(
            "client_ip",
            "string",
            "Where the notification came from",
            true,
        ),
    ])
        .with_actions(vec![
            acknowledge_notification_action(),
            ignore_notification_action(),
            send_trap_action(),
        ])
        .with_log_template(
            LogTemplate::new()
                .with_info("SNMP {kind} from {client_ip}")
                .with_debug("SNMP {version} {kind} from {client_ip}: {trap_oid} {variables}")
                .with_trace("SNMP: {json_pretty(.)}"),
        )
    });

/// Action definition for send_snmp_response (sync)
fn send_snmp_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_snmp_response".to_string(),
        description: "Answer the request with a set of OID values. The request-id, community string and SNMP version are copied from the request being answered, so you only supply the values. Return exactly one entry per OID in the event's 'oids' list, in the same order, and no others; each value is the one your instructions give for that OID, word for word. The example's OID and value are placeholders for the shape, never data.".to_string(),
        parameters: vec![Parameter {
            name: "variables".to_string(),
            type_hint: "array".to_string(),
            description: "Variable bindings, each an object {\"oid\": ..., \"type\": ..., \"value\": ...}. 'oid' is dotted decimal such as \"1.3.6.1.2.1.1.1.0\" (first component 0-2, every component numeric). 'type' is one of: \"string\" (text), \"integer\" (signed 32-bit), \"counter\" (Counter32, monotonically increasing), \"gauge\" (Gauge32, a value that goes up and down), \"timeticks\" (hundredths of a second since start-up, e.g. sysUpTime), \"null\" (no value for this OID). 'value' must match the type: a JSON string for \"string\", a JSON number for the numeric types, omitted for \"null\". An unrecognised type encodes as NULL".to_string(),
            required: true,
        }],
        example: json!({
            "type": "send_snmp_response",
            "variables": [
                {"oid": "1.3.6.1.4.1.99999.1.0", "type": "string", "value": "<the value your instructions give for this OID>"}
            ]
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> SNMP response {variables_len} vars")
                .with_debug("SNMP send_snmp_response: {variables_len} variables"),
        ),
    }
}

/// Action definition for send_snmp_error (sync)
fn send_snmp_error_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_snmp_error".to_string(),
        description: "Answer the request with an SNMP error instead of values - use it when the requested OID does not exist here, or when a SET is refused. The reply carries the numeric error-status and no variable bindings; the request-id and community are echoed automatically.".to_string(),
        parameters: vec![
            Parameter {
                name: "error_message".to_string(),
                type_hint: "string".to_string(),
                description: "Why the request failed. SNMP has no field for text, so this only reaches NetGet's logs and access log - the client sees 'error_status'".to_string(),
                required: true,
            },
            Parameter {
                name: "error_status".to_string(),
                type_hint: "string | number".to_string(),
                description: "Which error the client is told about: \"noSuchName\" (2) for an OID this agent does not serve, \"badValue\" (3) for a SET with an unusable value, \"readOnly\" (4) for a SET of a read-only OID, \"tooBig\" (1) if the answer would not fit, \"genErr\" (5) for anything else. Accepts the name or the number. Default: genErr".to_string(),
                required: false,
            },
            Parameter {
                name: "error_index".to_string(),
                type_hint: "number".to_string(),
                description: "1-based position of the offending OID in the request's list, or 0 when no single OID is to blame. Default 0".to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "send_snmp_error",
            "error_message": "OID 1.3.6.1.4.1.9999.1.0 is not served by this agent",
            "error_status": "noSuchName",
            "error_index": 1
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> SNMP error: {error_message}")
                .with_debug("SNMP send_snmp_error: {error_message}"),
        ),
    }
}

/// Action definition for ignore_request (sync)
fn ignore_request_action() -> ActionDefinition {
    ActionDefinition {
        name: "ignore_request".to_string(),
        description: "Ignore this SNMP request and don't send a response".to_string(),
        parameters: vec![],
        example: json!({
            "type": "ignore_request"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("SNMP request ignored")
                .with_debug("SNMP ignore_request"),
        ),
    }
}

// ============================================================================
// SNMP Event Type Constants
// ============================================================================

pub static SNMP_REQUEST_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "snmp_request",
        "SNMP client sent a GET/GETNEXT/GETBULK request",
        json!({
            "type": "send_snmp_response",
            "variables": [
                {"oid": "1.3.6.1.4.1.99999.1.0", "type": "string", "value": "<the value your instructions give for this OID>"}
            ]
        })
    )
    .with_parameters(vec![
        Parameter {
            name: "request_type".to_string(),
            type_hint: "string".to_string(),
            description: "PDU type of the request, spelled exactly: 'GetRequest', 'GetNextRequest', 'GetBulkRequest' or 'SetRequest'. GetNextRequest asks for the OID that follows the one given (table walking); GetBulkRequest asks for several at once".to_string(),
            required: true,
        },
        Parameter {
            name: "oids".to_string(),
            type_hint: "array".to_string(),
            description: "OIDs the client asked about, in dotted decimal, in request order. Answer with one variable binding per OID in the same order".to_string(),
            required: true,
        },
        Parameter {
            name: "answer_with".to_string(),
            type_hint: "string".to_string(),
            description: "Which answer this request takes: the variables to return, each OID named with its MIB-2 name where it has one (sysDescr, sysName, ...), and when to answer noSuchName instead".to_string(),
            required: true,
        },
        Parameter {
            name: "community".to_string(),
            type_hint: "string".to_string(),
            description: "Community string the client sent - SNMPv1/v2c's only credential, typically 'public'. It is echoed back automatically; check it here if the instruction says to reject unknown communities".to_string(),
            required: false,
        },
        Parameter {
            name: "request_id".to_string(),
            type_hint: "number".to_string(),
            description: "Request id chosen by the client. The response echoes it automatically - it is exposed only for logging".to_string(),
            required: false,
        },
        Parameter {
            name: "version".to_string(),
            type_hint: "string".to_string(),
            description: "'v1', 'v2c' or 'v3'. The reply uses the same version".to_string(),
            required: false,
        },
        Parameter {
            name: "client_ip".to_string(),
            type_hint: "string".to_string(),
            description: "IP address the request came from".to_string(),
            required: false,
        },
        Parameter {
            name: "user".to_string(),
            type_hint: "string".to_string(),
            description: "SNMPv3 only: the USM user the request was authenticated as (its MAC verified and its time checked before you see it). Decide per user what it may read or write".to_string(),
            required: false,
        },
        Parameter {
            name: "security_level".to_string(),
            type_hint: "string".to_string(),
            description: "SNMPv3 only: noAuthNoPriv, authNoPriv or authPriv - always the level the user is configured for. The answer goes back at the same level, encrypted when authPriv".to_string(),
            required: false,
        },
        Parameter {
            name: "context_name".to_string(),
            type_hint: "string".to_string(),
            description: "SNMPv3 only: the contextName the manager asked in, empty for the default context".to_string(),
            required: false,
        },
    ])
    .with_actions(vec![
        send_snmp_response_action(),
        send_snmp_error_action(),
        ignore_request_action(),
        send_trap_action(),
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("SNMP {request_type} from {client_ip}")
            .with_debug("SNMP {request_type} from {client_ip} ({version}, community={community}): {oids}")
            .with_trace("SNMP: {json_pretty(.)}"),
    )
});

/// The MIB-2 name and meaning of the OIDs a small model is most often asked for.
///
/// A model that has not memorised MIB-2 does not know that 1.3.6.1.2.1.1.1.0 is "the system
/// description" an instruction talks about, so the request names it.
fn well_known_oid(oid: &str) -> Option<&'static str> {
    Some(match oid.trim_start_matches('.') {
        "1.3.6.1.2.1.1.1.0" => "sysDescr, the system description your instructions give",
        "1.3.6.1.2.1.1.2.0" => "sysObjectID, the vendor's object identifier",
        "1.3.6.1.2.1.1.3.0" => "sysUpTime, timeticks since start-up",
        "1.3.6.1.2.1.1.4.0" => "sysContact, the contact person",
        "1.3.6.1.2.1.1.5.0" => {
            "sysName, the device's name exactly as your instructions write it - a hostname, \
             character for character, never reworded or capitalised"
        }
        "1.3.6.1.2.1.1.6.0" => "sysLocation, where the system is",
        "1.3.6.1.2.1.1.7.0" => "sysServices, an integer",
        "1.3.6.1.2.1.2.1.0" => "ifNumber, how many interfaces",
        _ => return None,
    })
}

/// The `answer_with` event field: the variables this request takes, OID by OID.
///
/// `send_snmp_response`'s example used to carry sysDescr = "System Description" and sysName =
/// "hostname". Told "your system description is NetGet Eval Switch 1.0", llama3.1:8b answered
/// with those two example values - and both OIDs, so a one-OID snmpget got two varbinds - ten
/// runs in ten. The request now names each OID it asks for, what it means, and that nothing
/// else belongs in the answer.
pub fn answer_with_for_request(request_type: &str, oids: &[String]) -> String {
    let named: Vec<String> = oids
        .iter()
        .map(|oid| match well_known_oid(oid) {
            Some(name) => format!("{oid} ({name})"),
            None => oid.clone(),
        })
        .collect();
    let list = named.join(", ");
    let n = oids.len();
    let noun = if n == 1 { "variable" } else { "variables" };
    match request_type {
        "GetNextRequest" | "GetBulkRequest" => format!(
            "send_snmp_response with the OID that follows each of {list} in your agent's tree, \
             and its value; send_snmp_error with noSuchName when nothing follows"
        ),
        "SetRequest" => format!(
            "send_snmp_response echoing the {n} {noun} set on {list} when your instructions let \
             them be written; send_snmp_error with readOnly when they do not"
        ),
        _ => format!(
            "send_snmp_response with exactly {n} {noun}, in this order: {list}. Each value is \
             the one your instructions give for it, word for word; add no other OIDs. If your \
             instructions give no value for one of them, send_snmp_error with noSuchName and \
             its 1-based error_index instead"
        ),
    }
}

pub fn get_snmp_event_types() -> Vec<EventType> {
    vec![SNMP_REQUEST_EVENT.clone(), SNMP_NOTIFICATION_EVENT.clone()]
}
