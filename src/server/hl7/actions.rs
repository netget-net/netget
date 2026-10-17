use super::wire;
use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter, ParameterDefinition,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::{EventType, SpawnContext};
use crate::state::app_state::AppState;
use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

#[derive(Default)]
pub struct Hl7Protocol;
impl Hl7Protocol {
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
        "hl7_ack" => LogTemplate::new().with_info("-> HL7 ACK {code} {text}"),
        // Message bodies carry patient data; log the type only.
        "hl7_send" => LogTemplate::new().with_info("-> HL7 send {message_type}"),
        _ => LogTemplate::new().with_info(format!("-> HL7 {name}")),
    };
    ActionDefinition {
        name: name.into(),
        description: description.into(),
        parameters,
        example,
        log_template: Some(log_template),
    }
}

pub const SEGMENTS_HELP: &str = "[{id: three-letter segment id, fields: [field 1, field 2, ...]}]; component ^, repetition ~ and sub-component & keep their meaning, '|' is escaped, CR/LF and other control characters are refused";

fn ack_action() -> ActionDefinition {
    action(
        "hl7_ack",
        "Acknowledge the pending message. Rust builds the MSH (sender and receiver swapped, ACK^<trigger>^ACK, a fresh control id) and MSA echoing the original control id.",
        vec![
            parameter("code", "string", "AA accept, AE application error, AR reject (original mode); CA, CE, CR (enhanced mode commit)", true),
            parameter("text", "string", "MSA-3 text message, e.g. why it was rejected", false),
            parameter("error", "object", "Adds an ERR segment: {code: HL7 table 0357 code such as 207^Application internal error, severity: E|W|I, message, location}", false),
            parameter("segments", "array", &format!("Extra response segments after MSA (e.g. a query result): {SEGMENTS_HELP}"), false),
        ],
        json!({"type":"hl7_ack","code":"AA","text":"admitted"}),
    )
}

pub static MESSAGE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "hl7_message",
        "A framed, parsed HL7 v2 message. Decide its acknowledgment; there is no clinical store in Rust.",
        ack_action().example.clone(),
    )
    .with_parameters(vec![
        parameter("message_type", "string", "MSH-9, e.g. ADT^A01^ADT_A01", true),
        parameter("control_id", "string", "MSH-10, echoed by Rust in MSA-2", true),
        parameter("version", "string", "MSH-12, e.g. 2.5", true),
        parameter("processing_id", "string", "MSH-11: P production, T training, D debugging", true),
        parameter("sending_application", "string", "MSH-3: the system that sent the message, e.g. LAB", true),
        parameter("sending_facility", "string", "MSH-4: the facility the sender belongs to", true),
        parameter("receiving_application", "string", "MSH-5: the system the message is addressed to (this endpoint)", true),
        parameter("receiving_facility", "string", "MSH-6: the facility the message is addressed to", true),
        parameter("segments", "array", "Every segment as {id, fields}; fields[n] is field n+1 (for MSH, fields[0] is MSH-2)", true),
        parameter("charset_assumed", "string", "ISO-8859-1 when the bytes were not UTF-8", false),
    ])
    .with_actions(vec![ack_action()])
});

impl Protocol for Hl7Protocol {
    fn protocol_name(&self) -> &'static str {
        "HL7"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>MLLP>HL7"
    }
    fn description(&self) -> &'static str {
        "HL7 v2 MLLP integration endpoint that acknowledges messages as the handler decides"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "hl7",
            "hl7v2",
            "mllp",
            "adt",
            "healthcare",
            "interface engine",
        ]
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![ack_action()]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![MESSAGE_EVENT.clone()]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![ParameterDefinition {
            name: "idle_timeout_secs".into(),
            type_hint: "number".into(),
            description: "Seconds (1..=86400) a connection may wait between messages; a parked handler does not count".into(),
            required: false,
            example: json!(600),
            default: Some(json!(super::IDLE_TIMEOUT.as_secs())),
        }]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .well_known_port(2575)
            .implementation("Native MLLP framing and HL7 v2 ER7 parsing over Tokio TCP; Rust owns MSH construction, control ids, MSA correlation and refusals")
            .llm_control("The acknowledgment code, text, ERR detail and any response segments for each message")
            .e2e_testing("tests/server/hl7: python-hl7 0.4.5 MLLP client (independent) sends ADT and ORU messages and checks the ACKs; framing, field-injection and bound tests")
            .notes("No clinical data store and no message-profile conformance engine: structural checks only (MSH first, standard separators and encoding characters, control id and type present). One message in flight per connection (original-mode acknowledgment). UTF-8, else read as ISO-8859-1. 1 MiB messages, 4096 segments, 512 fields.")
            .request_only("MLLP acknowledges each received message; nothing is sent unprompted")
            .answers_on_failure()
            .max_inbound_bytes(wire::MAX_MESSAGE_BYTES)
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "HL7 MLLP endpoint on port 2575 that accepts ADT admissions and rejects everything else"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let llm = json!({"type":"open_server","base_stack":"hl7","port":2575,"instruction":"Accept ADT messages with AA, reject others with AR"});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([{"event_pattern":"hl7_message","handler":{"type":"static","actions":[{"type":"hl7_ack","code":"AA"}]}}]);
        let mut scripted = llm.clone();
        scripted["event_handlers"] = json!([{"event_pattern":"hl7_message","handler":{"type":"script","language":"python","code":"import json,sys\ne=json.load(sys.stdin)['event']\ncode='AA' if e['message_type'].startswith('ADT') else 'AR'\nprint(json.dumps({'actions':[{'type':'hl7_ack','code':code}]}))"}}]);
        crate::llm::actions::StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Healthcare"
    }
}

impl Server for Hl7Protocol {
    fn spawn(
        &self,
        ctx: SpawnContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::spawn(ctx))
    }
    fn execute_action(&self, v: Value) -> Result<ActionResult> {
        match v["type"].as_str() {
            Some("hl7_ack") => {
                validate_ack(&v)?;
                Ok(ActionResult::Custom {
                    name: "hl7_ack".into(),
                    data: v,
                })
            }
            _ => bail!("Unknown HL7 server action"),
        }
    }
}

pub fn validate_ack(v: &Value) -> Result<()> {
    let code = v["code"].as_str().context("code is required")?;
    ensure!(
        wire::ACK_CODES.contains(&code),
        "code must be one of {:?}",
        wire::ACK_CODES
    );
    if let Some(text) = v.get("text").filter(|t| !t.is_null()) {
        wire::field(text.as_str().context("text must be a string")?)?;
    }
    if let Some(e) = v.get("error").filter(|t| !t.is_null()) {
        let e = e.as_object().context("error must be an object")?;
        for (k, val) in e {
            ensure!(
                matches!(k.as_str(), "code" | "severity" | "message" | "location"),
                "unknown error field '{k}'"
            );
            wire::field(val.as_str().context("error fields must be strings")?)?;
        }
        if let Some(sev) = e.get("severity").and_then(Value::as_str) {
            ensure!(
                matches!(sev, "E" | "W" | "I" | "F"),
                "severity must be E, W, I or F"
            );
        }
    }
    wire::segments_from(v.get("segments").unwrap_or(&Value::Null))?;
    Ok(())
}
