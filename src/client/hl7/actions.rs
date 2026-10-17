use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, ParameterDefinition,
};
use crate::protocol::{ConnectContext, EventType};
use crate::server::hl7::actions::{action, parameter, SEGMENTS_HELP};
use crate::server::hl7::wire;
use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

#[derive(Default)]
pub struct Hl7ClientProtocol;
impl Hl7ClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

fn send_action() -> ActionDefinition {
    action(
        "hl7_send",
        "Send one HL7 v2 message and wait for its acknowledgment. Rust builds MSH from the startup identity, assigns the control id and matches the ACK's MSA-2 to it.",
        vec![
            parameter("message_type", "string", "MSH-9, e.g. ADT^A01^ADT_A01 or ORU^R01^ORU_R01", true),
            parameter("segments", "array", &format!("Body segments after MSH: {SEGMENTS_HELP}"), true),
            parameter("processing_id", "string", "MSH-11 override: P, T or D (default from startup)", false),
        ],
        json!({"type":"hl7_send","message_type":"ADT^A01^ADT_A01","segments":[{"id":"EVN","fields":["A01","20260101120000"]},{"id":"PID","fields":["1","","12345^^^HOSP^MR","","Doe^John"]}]}),
    )
}
fn disconnect_action() -> ActionDefinition {
    action(
        "disconnect",
        "Close the MLLP connection",
        vec![],
        json!({"type":"disconnect"}),
    )
}
fn actions() -> Vec<ActionDefinition> {
    vec![send_action(), disconnect_action()]
}

pub static CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "hl7_connected",
        "Connected to the MLLP receiver; send a message",
        send_action().example.clone(),
    )
    .with_parameters(vec![parameter(
        "remote_addr",
        "string",
        "Receiver address",
        true,
    )])
    .with_actions(actions())
});
pub static ACK_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new("hl7_ack_received", "The receiver acknowledged the last message (MSA-2 matched its control id)", disconnect_action().example.clone())
        .with_parameters(vec![
            parameter("code", "string", "MSA-1: AA, AE, AR, CA, CE or CR", true),
            parameter("control_id", "string", "The control id of the message acknowledged", true),
            parameter("text", "string", "MSA-3: the receiver's free-text explanation, e.g. why it rejected the message", true),
            parameter("message_type", "string", "MSH-9 of the acknowledgment", true),
            parameter("segments", "array", "Every segment of the acknowledgment as {id, fields}, including ERR and any response segments", true),
        ])
        .with_actions(actions())
});

fn startup(
    name: &str,
    description: &str,
    example: Value,
    default: Option<Value>,
) -> ParameterDefinition {
    ParameterDefinition {
        name: name.into(),
        type_hint: "string".into(),
        description: description.into(),
        required: false,
        example,
        default,
    }
}

impl Protocol for Hl7ClientProtocol {
    fn protocol_name(&self) -> &'static str {
        "HL7"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>MLLP>HL7"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["hl7", "hl7v2", "mllp", "adt", "oru", "healthcare"]
    }
    fn description(&self) -> &'static str {
        "HL7 v2 MLLP sender with Rust-built headers and correlated acknowledgments"
    }
    fn get_async_actions(&self, _: &crate::state::app_state::AppState) -> Vec<ActionDefinition> {
        actions()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![CONNECTED_EVENT.clone(), ACK_EVENT.clone()]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            startup(
                "sending_application",
                "MSH-3 of every message sent",
                json!("NETGET"),
                Some(json!(super::DEFAULT_APPLICATION)),
            ),
            startup(
                "sending_facility",
                "MSH-4 of every message sent",
                json!("LAB"),
                None,
            ),
            startup(
                "receiving_application",
                "MSH-5 of every message sent",
                json!("EHR"),
                None,
            ),
            startup(
                "receiving_facility",
                "MSH-6 of every message sent",
                json!("HOSPITAL"),
                None,
            ),
            startup(
                "version",
                "MSH-12 HL7 version",
                json!("2.5.1"),
                Some(json!(super::DEFAULT_VERSION)),
            ),
            startup(
                "processing_id",
                "MSH-11: P production, T training, D debugging",
                json!("T"),
                Some(json!(super::DEFAULT_PROCESSING)),
            ),
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .well_known_port(2575)
            .implementation("Native MLLP framing and ER7 building/parsing shared with the server; Rust-assigned control ids; MSA-2 correlation")
            .llm_control("Which messages to send (type and body segments) and how to react to each acknowledgment")
            .e2e_testing("tests/client/hl7: python-hl7 0.4.5 MLLP server (independent) receives ADT/ORU and answers AA/AE/AR; NetGet pair, mismatched control id and framing refusals")
            .notes("Original-mode, one message in flight. No message-profile validation of the body. 1 MiB messages.")
            .max_inbound_bytes(wire::MAX_MESSAGE_BYTES)
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Send an ADT^A01 admission for John Doe to the MLLP endpoint at 127.0.0.1:2575"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let llm = json!({"type":"open_client","protocol":"hl7","remote_addr":"127.0.0.1:2575","instruction":"Admit John Doe, MRN 12345"});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([
            {"event_pattern":"hl7_connected","handler":{"type":"static","actions":[send_action().example]}},
            {"event_pattern":"hl7_ack_received","handler":{"type":"static","actions":[{"type":"disconnect"}]}}
        ]);
        let mut scripted = static_example.clone();
        scripted["event_handlers"][1]["handler"] = json!({"type":"script","language":"python","code":"import json\nprint(json.dumps({'actions':[{'type':'disconnect'}]}))"});
        crate::llm::actions::StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Healthcare"
    }
}

impl Client for Hl7ClientProtocol {
    fn connect(
        &self,
        ctx: ConnectContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::connect(ctx))
    }
    fn execute_action(&self, v: Value) -> Result<ClientActionResult> {
        match v["type"].as_str() {
            Some("hl7_send") => {
                let t = v["message_type"]
                    .as_str()
                    .context("message_type is required")?;
                wire::field(t)?;
                ensure!(!t.is_empty(), "message_type is required");
                if let Some(p) = v.get("processing_id").and_then(Value::as_str) {
                    ensure!(
                        matches!(p, "P" | "T" | "D"),
                        "processing_id must be P, T or D"
                    );
                }
                wire::segments_from(&v["segments"])?;
                Ok(ClientActionResult::Custom {
                    name: "hl7_send".into(),
                    data: v,
                })
            }
            Some("disconnect") => Ok(ClientActionResult::Disconnect),
            _ => bail!("Unknown HL7 client action"),
        }
    }
}
