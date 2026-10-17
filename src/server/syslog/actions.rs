//! Syslog protocol actions implementation

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

/// Syslog protocol action handler
pub struct SyslogProtocol;

impl SyslogProtocol {
    pub fn new() -> Self {
        Self
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for SyslogProtocol {
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        // Syslog has async actions for forwarding logs
        vec![forward_syslog_action()]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            store_syslog_message_action(),
            ignore_syslog_message_action(),
        ]
    }
    fn protocol_name(&self) -> &'static str {
        "Syslog"
    }
    fn get_event_types(&self) -> Vec<EventType> {
        get_syslog_event_types()
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>UDP>SYSLOG"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["syslog"]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{
            DevelopmentState, PrivilegeRequirement, ProtocolMetadataV2,
        };

        ProtocolMetadataV2::builder()
            .connectionless()
            // Deliberately silent: syslog is one-way. RFC 5424/5426 define no reply message at all,
            // so there is nothing to answer a sender with, whatever the model does.
            .deliberately_silent()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::PrivilegedPort(514))
            .well_known_udp_port(514)
            .implementation("syslog_loose v0.22 for parsing RFC 3164/5424 messages")
            .llm_control("Message filtering, forwarding, alerting")
            .e2e_testing("logger command (Linux/macOS built-in)")
            .notes("RFC 3164 and RFC 5424 over UDP. Receive-only: nothing is ever sent back to the sender. No E2E test coverage")
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn description(&self) -> &'static str {
        "Syslog server for log aggregation and analysis"
    }
    fn example_prompt(&self) -> &'static str {
        "Syslog Port 514 collect system logs and alert on critical errors"
    }
    fn group_name(&self) -> &'static str {
        "Core"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        use serde_json::json;

        // Deterministic: record every received syslog line into server memory,
        // no LLM call.
        let script = r#"import json, sys
data = json.load(sys.stdin)
event = data["event"]
if data["event_type_id"] == "syslog_message":
    actions = [{"type": "store_syslog_message",
                "message": str(event.get("message", ""))}]
else:
    actions = []
print(json.dumps({"actions": actions}))"#;

        StartupExamples::new(
            // LLM mode: LLM handles all syslog messages intelligently
            json!({
                "type": "open_server",
                "port": 514,
                "base_stack": "syslog",
                "instruction": "Syslog server collecting and analyzing system logs"
            }),
            // Script mode: Code-based deterministic responses
            json!({
                "type": "open_server",
                "port": 514,
                "base_stack": "syslog",
                "event_handlers": [{
                    "event_pattern": "syslog_message",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": script
                    }
                }]
            }),
            // Static mode: Fixed responses
            json!({
                "type": "open_server",
                "port": 514,
                "base_stack": "syslog",
                "event_handlers": [{
                    "event_pattern": "syslog_message",
                    "handler": {
                        "type": "static",
                        "actions": [{
                            "type": "store_syslog_message",
                            "message": ""
                        }]
                    }
                }]
            }),
        )
    }
}

// Implement Server trait (server-specific functionality)
impl Server for SyslogProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::server::syslog::SyslogServer;
            SyslogServer::spawn_with_llm_actions(
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
            "forward_syslog" => self.execute_forward_syslog(action),
            "store_syslog_message" => self.execute_store_syslog_message(action),
            "ignore_syslog_message" => Ok(ActionResult::NoAction),
            _ => Err(anyhow::anyhow!("Unknown Syslog action: {}", action_type)),
        }
    }
}

impl SyslogProtocol {
    /// Execute forward_syslog: relay the message to another syslog collector over UDP.
    ///
    /// The datagram is sent from an ephemeral local port, so the receiving collector sees
    /// NetGet as the source (syslog has no relay/forwarded-for field in RFC 3164; a real
    /// relay would rewrite the hostname, which the LLM can do in `message`).
    fn execute_forward_syslog(&self, action: serde_json::Value) -> Result<ActionResult> {
        use std::net::{ToSocketAddrs, UdpSocket};

        let target = action.get("target").and_then(|v| v.as_str()).context(
            "Missing 'target' parameter (expected \"IP:port\", e.g. \"192.168.1.100:514\")",
        )?;

        let message = action
            .get("message")
            .and_then(|v| v.as_str())
            .context("Missing 'message' parameter")?;

        let addr = target
            .to_socket_addrs()
            .with_context(|| {
                format!("Invalid 'target' {target:?}: expected \"HOST:PORT\", e.g. \"192.168.1.100:514\"")
            })?
            .next()
            .with_context(|| format!("'target' {target:?} did not resolve to any address"))?;

        let bind_addr = if addr.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let socket = UdpSocket::bind(bind_addr)
            .with_context(|| format!("Failed to open a local UDP socket to forward to {addr}"))?;
        let sent = socket
            .send_to(message.as_bytes(), addr)
            .with_context(|| format!("Failed to forward syslog message to {addr}"))?;

        tracing::debug!("Syslog forwarded {} bytes to {}", sent, addr);

        // Syslog is one-way: nothing is written back to the original sender.
        Ok(ActionResult::NoAction)
    }

    /// Execute store_syslog_message: record the message in the server's access log.
    ///
    /// NetGet protocols do not implement storage (see CLAUDE.md). The durable record is
    /// the access log entry written for every handled event, which already contains this
    /// action verbatim and is readable via the `list_access_logs` / `get_access_log`
    /// MCP tools. This executor therefore only validates and echoes the message.
    fn execute_store_syslog_message(&self, action: serde_json::Value) -> Result<ActionResult> {
        let message = action.get("message").and_then(|v| v.as_str()).unwrap_or("");

        tracing::debug!("Syslog message retained in access log: {}", message);

        Ok(ActionResult::NoAction)
    }
}

/// Action definition for forward_syslog (async)
fn forward_syslog_action() -> ActionDefinition {
    ActionDefinition {
        name: "forward_syslog".to_string(),
        description: "Relay a syslog message to another syslog collector over UDP. The message is sent exactly as given, so include the '<PRI>' header if the receiver expects a well-formed syslog line - the 'raw_message' field of the syslog_message event is the original datagram and can be forwarded unchanged.".to_string(),
        parameters: vec![
            Parameter {
                name: "target".to_string(),
                type_hint: "string".to_string(),
                description: "Destination collector as 'HOST:PORT', e.g. '192.168.1.100:514'. Port is mandatory".to_string(),
                required: true,
            },
            Parameter {
                name: "message".to_string(),
                type_hint: "string".to_string(),
                description: "Exact text of the datagram to send. Pass the event's 'raw_message' to relay it untouched, or build a new syslog line such as '<34>Oct 11 22:14:15 host app: text'".to_string(),
                required: true,
            },
        ],
        example: json!({
            "type": "forward_syslog",
            "target": "192.168.1.100:514",
            "message": "<34>Oct 11 22:14:15 mymachine su: 'su root' failed for user on /dev/pts/8"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> Syslog forwarded to {target}")
                .with_debug("Syslog forward_syslog: target={target}"),
        ),
    }
}

/// Action definition for store_syslog_message (sync)
fn store_syslog_message_action() -> ActionDefinition {
    ActionDefinition {
        name: "store_syslog_message".to_string(),
        description: "Keep this log line - unless the instruction says to drop messages like it, in which case the answer is ignore_syslog_message instead, never both. The action and its message are written to the server's access log, which is readable later with the list_access_logs / get_access_log tools. NetGet does not write syslog messages to a database or to disk, and nothing is sent back to the client. Use forward_syslog if the message must reach another collector.".to_string(),
        parameters: vec![Parameter {
            name: "message".to_string(),
            type_hint: "string".to_string(),
            description: "Text to record. Usually the event's 'raw_message' (the original datagram) or its 'message' field, optionally annotated with your own note".to_string(),
            required: true,
        }],
        example: json!({
            "type": "store_syslog_message",
            "message": "<34>Oct 11 22:14:15 mymachine su: 'su root' failed for user on /dev/pts/8"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> Syslog stored")
                .with_debug("Syslog store_syslog_message"),
        ),
    }
}

/// Action definition for ignore_syslog_message (sync)
fn ignore_syslog_message_action() -> ActionDefinition {
    ActionDefinition {
        name: "ignore_syslog_message".to_string(),
        description: "Drop this message: nothing is kept. The answer whenever the instruction says to throw away, discard, ignore or filter out messages like this one - e.g. told to drop anything mentioning healthcheck, a message whose text mentions healthcheck gets this and nothing else. One of store_syslog_message or ignore_syslog_message per message, never both.".to_string(),
        // `reason` is recorded nowhere but the log line. It exists because a parameterless
        // action loses to one with a `message` field: told to drop anything mentioning
        // healthcheck, llama3.1:8b wrote "I've ignored the message" beside a
        // store_syslog_message carrying it, every run. Giving the drop somewhere to say why
        // gives it the same shape as the keep.
        parameters: vec![Parameter {
            name: "reason".to_string(),
            type_hint: "string".to_string(),
            description: "Why this message is dropped, e.g. 'mentions healthcheck'. Logged, \
                          never stored."
                .to_string(),
            required: false,
        }],
        example: json!({
            "type": "ignore_syslog_message",
            "reason": "matches the drop rule in the instruction"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> Syslog ignored")
                .with_debug("Syslog ignore_syslog_message: {reason}"),
        ),
    }
}

// ============================================================================
// Syslog Event Type Constants
// ============================================================================

pub static SYSLOG_MESSAGE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "syslog_message",
        "Syslog client sent a log message. Syslog is one-way: no response is ever sent back to the client, so the only useful actions are recording, forwarding or dropping the message",
        // Dropping is the primary example on purpose: with keeping first, llama3.1:8b stored
        // a message the instruction told it to throw away in every run, reading the first
        // example as the answer rather than as one of two.
        json!({"type": "ignore_syslog_message", "reason": "matches the drop rule in the instruction"}),
    )
    .with_parameters(vec![
        Parameter {
            name: "facility".to_string(),
            type_hint: "string".to_string(),
            description: "Facility name, exactly one of: kern, user, mail, daemon, auth, syslog, lpr, news, uucp, cron, authpriv, ftp, ntp, audit, alert, clockd, local0-local7. Defaults to 'user' when the datagram carried no <PRI> header".to_string(),
            required: true,
        },
        Parameter {
            name: "facility_code".to_string(),
            type_hint: "number".to_string(),
            description: "Numeric facility, 0 (kern) to 23 (local7)".to_string(),
            required: true,
        },
        Parameter {
            name: "severity".to_string(),
            type_hint: "string".to_string(),
            description: "Severity name, exactly one of: emerg, alert, crit, err, warning, notice, info, debug. Defaults to 'notice' when the datagram carried no <PRI> header".to_string(),
            required: true,
        },
        Parameter {
            name: "severity_code".to_string(),
            type_hint: "number".to_string(),
            description: "Numeric severity, 0 = emerg (most severe) to 7 = debug (least severe). Compare against this rather than the name when filtering by importance, e.g. severity_code <= 3 means error or worse".to_string(),
            required: true,
        },
        Parameter {
            name: "priority".to_string(),
            type_hint: "number".to_string(),
            description: "The wire PRI value, facility_code * 8 + severity_code".to_string(),
            required: true,
        },
        Parameter {
            name: "timestamp".to_string(),
            type_hint: "string".to_string(),
            description: "Timestamp reported by the sender in RFC 3339 form, or 'unknown' if the message had none. This is the client's clock, not the server's".to_string(),
            required: false,
        },
        Parameter {
            name: "hostname".to_string(),
            type_hint: "string".to_string(),
            description: "Hostname claimed by the sender, or 'unknown'. Unauthenticated and easily forged - use 'source_ip' for the address the datagram actually came from".to_string(),
            required: false,
        },
        Parameter {
            name: "appname".to_string(),
            type_hint: "string".to_string(),
            description: "Application/tag name (APP-NAME in RFC 5424, the tag before ':' in RFC 3164), or 'unknown'".to_string(),
            required: false,
        },
        Parameter {
            name: "procid".to_string(),
            type_hint: "string".to_string(),
            description: "Process id or name if the sender included one, otherwise null".to_string(),
            required: false,
        },
        Parameter {
            name: "message".to_string(),
            type_hint: "string".to_string(),
            description: "Log text with the syslog header (priority, timestamp, hostname, tag) stripped off".to_string(),
            required: true,
        },
        Parameter {
            name: "source_ip".to_string(),
            type_hint: "string".to_string(),
            description: "IP address the datagram was received from".to_string(),
            required: true,
        },
        Parameter {
            name: "raw_message".to_string(),
            type_hint: "string".to_string(),
            description: "The complete datagram as received, header included. Forward or store this to preserve the message byte-for-byte".to_string(),
            required: true,
        },
    ])
    .with_alternative_example(json!({"type": "store_syslog_message", "message": "<34>Oct 11 22:14:15 mymachine su: 'su root' failed"}))
    .with_actions(vec![
        store_syslog_message_action(),
        ignore_syslog_message_action(),
        forward_syslog_action(),
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("syslog {facility}.{severity} from {hostname}")
            .with_debug("syslog {facility}.{severity} from {hostname} ({source_ip}) app={appname}: {message}")
            .with_trace("syslog: {json_pretty(.)}"),
    )
});

pub fn get_syslog_event_types() -> Vec<EventType> {
    vec![SYSLOG_MESSAGE_EVENT.clone()]
}
