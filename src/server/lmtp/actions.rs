use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter, ParameterDefinition,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::{EventType, SpawnContext};
use crate::state::app_state::AppState;
use anyhow::{bail, ensure, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

#[derive(Default)]
pub struct LmtpProtocol;
impl LmtpProtocol {
    pub fn new() -> Self {
        Self
    }
}

pub fn parameter(name: &str, kind: &str, description: &str, required: bool) -> Parameter {
    Parameter {
        name: name.into(),
        type_hint: kind.into(),
        description: description.into(),
        required,
    }
}

pub fn action(
    name: &str,
    description: &str,
    parameters: Vec<Parameter>,
    example: Value,
) -> ActionDefinition {
    let log_template = match name {
        "lmtp_recipient_reply" => {
            LogTemplate::new().with_info("-> LMTP recipient accept={accept} temporary={temporary}")
        }
        "lmtp_delivery" => LogTemplate::new()
            .with_info("-> LMTP delivery deliver_all={deliver_all} results={preview(results,120)}"),
        "lmtp_send" => {
            LogTemplate::new().with_info("-> LMTP send from={from} to={preview(to,120)}")
        }
        "disconnect" => LogTemplate::new().with_info("-> LMTP QUIT"),
        _ => LogTemplate::new().with_info(format!("-> LMTP {name}")),
    };
    ActionDefinition {
        name: name.into(),
        description: description.into(),
        parameters,
        example,
        log_template: Some(log_template),
    }
}

fn recipient_action() -> ActionDefinition {
    action(
        "lmtp_recipient_reply",
        "Accept or refuse one RCPT TO. Refusal is permanent (550) unless temporary is true (450).",
        vec![
            parameter("accept", "boolean", "True to accept this recipient", true),
            parameter(
                "temporary",
                "boolean",
                "With accept false: a temporary failure the sender should retry",
                false,
            ),
            parameter("reason", "string", "Human-readable reply text", false),
        ],
        json!({"type":"lmtp_recipient_reply","accept":true}),
    )
}

fn delivery_action() -> ActionDefinition {
    action(
        "lmtp_delivery",
        "Report the delivery outcome for each accepted recipient of the message. LMTP answers \
         DATA once per recipient, in RCPT order; a recipient you do not list gets deliver_all, \
         or a temporary failure (451) when deliver_all is absent.",
        vec![
            parameter(
                "results",
                "array",
                "[{recipient, delivered: bool, temporary?: bool, reason?: string}]",
                false,
            ),
            parameter(
                "deliver_all",
                "boolean",
                "Outcome for recipients not listed in results: true delivers them, false refuses them permanently",
                false,
            ),
        ],
        json!({"type":"lmtp_delivery","deliver_all":true}),
    )
}

pub static RECIPIENT_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "lmtp_recipient",
        "A sender named a recipient with RCPT TO; decide whether this mailbox exists here.",
        recipient_action().example.clone(),
    )
    .with_parameters(vec![
        parameter("recipient", "string", "Address from RCPT TO", true),
        parameter(
            "mail_from",
            "string",
            "Reverse path from MAIL FROM (may be empty)",
            true,
        ),
        parameter("lhlo", "string", "Domain the client gave in LHLO", true),
        parameter(
            "accepted_so_far",
            "number",
            "Recipients already accepted in this transaction",
            true,
        ),
    ])
    .with_actions(vec![recipient_action()])
});

pub static MESSAGE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "lmtp_message",
        "A complete message after DATA, for the recipients you accepted. Decide the outcome per recipient.",
        delivery_action().example.clone(),
    )
    .with_parameters(vec![
        parameter("mail_from", "string", "Reverse path from MAIL FROM", true),
        parameter("recipients", "array", "Accepted recipients, in RCPT order", true),
        parameter("size", "number", "Message size in bytes after dot-unstuffing", true),
        parameter("headers", "object", "Header fields by lowercase name (first occurrence)", true),
        parameter("subject", "string", "Subject header, if any", false),
        parameter("body", "string", "Body text after the header block, at most 64 KiB", true),
        parameter("body_truncated", "boolean", "True when the body was longer than shown", true),
    ])
    .with_actions(vec![delivery_action()])
});

impl Protocol for LmtpProtocol {
    fn protocol_name(&self) -> &'static str {
        "LMTP"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>LMTP"
    }
    fn description(&self) -> &'static str {
        "LMTP local delivery server (RFC 2033) with per-recipient delivery decisions"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["lmtp", "rfc2033", "lhlo", "mail delivery", "mda"]
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![recipient_action(), delivery_action()]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![RECIPIENT_EVENT.clone(), MESSAGE_EVENT.clone()]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "hostname".into(),
                type_hint: "string".into(),
                description: "Name in the 220 greeting and the LHLO reply".into(),
                required: false,
                example: json!("mail.example.test"),
                default: Some(json!(super::DEFAULT_HOSTNAME)),
            },
            ParameterDefinition {
                name: "max_message_bytes".into(),
                type_hint: "number".into(),
                description: "Largest message accepted, advertised as SIZE (1..=67108864)".into(),
                required: false,
                example: json!(1048576),
                default: Some(json!(super::wire::DEFAULT_MAX_MESSAGE_BYTES)),
            },
            ParameterDefinition {
                name: "idle_timeout_secs".into(),
                type_hint: "number".into(),
                description: "Seconds to wait for each command or DATA line (1..=3600)".into(),
                required: false,
                example: json!(300),
                default: Some(json!(super::IDLE_TIMEOUT.as_secs())),
            },
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::PrivilegedPort(24))
            .well_known_port(24)
            .implementation("RFC 2033 over Tokio TCP: LHLO, MAIL, RCPT, DATA with one reply per accepted recipient, RSET, NOOP, VRFY, QUIT; PIPELINING, ENHANCEDSTATUSCODES, 8BITMIME and SIZE")
            .llm_control("Whether each recipient exists (RCPT), and the per-recipient delivery outcome of each message (DATA)")
            .e2e_testing("tests/server/lmtp: raw-wire sessions and bounds; CPython smtplib.LMTP and swaks --protocol LMTP as independent clients")
            .notes("Plain TCP only: no STARTTLS or AUTH. No mailbox storage: the handler decides delivery and keeps whatever it needs in memory or the SQLite facility. HELO/EHLO are refused as RFC 2033 requires. Lines are 1000 bytes, 100 recipients per transaction, 10 MiB messages by default, 20 consecutive bad commands close the session with 421. A handler failure answers 451 4.3.0, never a false delivery.")
            .request_only("LMTP replies answer the command just read; the server never speaks first except for its greeting")
            .max_inbound_bytes(super::wire::MAX_LINE_BYTES)
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            // Pipelined RCPT runs that arrive during a call are decided in one; an answer
            // without exactly one lmtp_recipient_reply per recipient refuses each with 451.
            // MAIL, DATA and its body are never batched. See `recipient_batch` in mod.rs.
            .batching(crate::protocol::metadata::BatchingMode::On)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "LMTP server on port 2424 that accepts mail for alice@example.test and bob@example.test"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let llm = json!({"type":"open_server","base_stack":"lmtp","port":2424,"instruction":"Accept mail for alice@example.test only"});
        let mut scripted = llm.clone();
        scripted["event_handlers"] = json!([
            {"event_pattern":"lmtp_recipient","handler":{"type":"script","language":"python","code":"import json,sys\ni=json.load(sys.stdin)\nok=i['event']['recipient'].endswith('@example.test')\nprint(json.dumps({'actions':[{'type':'lmtp_recipient_reply','accept':ok}]}))"}},
            {"event_pattern":"lmtp_message","handler":{"type":"static","actions":[{"type":"lmtp_delivery","deliver_all":true}]}}
        ]);
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([
            {"event_pattern":"lmtp_recipient","handler":{"type":"static","actions":[{"type":"lmtp_recipient_reply","accept":true}]}},
            {"event_pattern":"lmtp_message","handler":{"type":"static","actions":[{"type":"lmtp_delivery","deliver_all":true}]}}
        ]);
        crate::llm::actions::StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Application"
    }
}

impl Server for LmtpProtocol {
    fn spawn(
        &self,
        ctx: SpawnContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::spawn(ctx))
    }
    fn execute_action(&self, v: Value) -> Result<ActionResult> {
        match v["type"].as_str() {
            Some("lmtp_recipient_reply") => {
                ensure!(v["accept"].is_boolean(), "accept must be a boolean");
                ensure!(
                    v.get("temporary").is_none_or(Value::is_boolean),
                    "temporary must be a boolean"
                );
                ensure!(
                    v.get("reason").is_none_or(Value::is_string),
                    "reason must be a string"
                );
                Ok(ActionResult::Custom {
                    name: "lmtp_recipient_reply".into(),
                    data: v,
                })
            }
            Some("lmtp_delivery") => {
                ensure!(
                    v.get("deliver_all").is_none_or(Value::is_boolean),
                    "deliver_all must be a boolean"
                );
                if let Some(results) = v.get("results") {
                    let results = results
                        .as_array()
                        .ok_or_else(|| anyhow::anyhow!("results must be an array"))?;
                    ensure!(
                        results.len() <= super::wire::MAX_RECIPIENTS,
                        "results lists more recipients than a transaction can hold"
                    );
                    for result in results {
                        ensure!(
                            result["recipient"].is_string(),
                            "each result needs a recipient"
                        );
                        ensure!(
                            result["delivered"].is_boolean(),
                            "each result needs delivered"
                        );
                    }
                }
                Ok(ActionResult::Custom {
                    name: "lmtp_delivery".into(),
                    data: v,
                })
            }
            _ => bail!("Unknown LMTP server action"),
        }
    }
}
