use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, ParameterDefinition,
};
use crate::protocol::{ConnectContext, EventType};
use crate::server::smpp::{
    actions::{action, parameter},
    wire,
};
use crate::state::app_state::AppState;
use anyhow::{bail, ensure, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

#[derive(Default)]
pub struct SmppClientProtocol;
impl SmppClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

fn submit_action() -> ActionDefinition {
    action(
        "smpp_submit",
        "Submit a short message; the SMSC's answer arrives as smpp_submit_result, and any receipt later as smpp_deliver.",
        vec![
            parameter("source_addr", "string", "Sender address, at most 20 characters", true),
            parameter("destination_addr", "string", "Recipient address, at most 20 characters", true),
            parameter("text", "string", "Message text; ASCII goes as the default alphabet, anything else as UCS-2", true),
            parameter("registered_delivery", "boolean", "Ask the SMSC for a delivery receipt", false),
        ],
        json!({"type":"smpp_submit","source_addr":"NetGet","destination_addr":"15551234567","text":"Hello","registered_delivery":true}),
    )
}

fn enquire_action() -> ActionDefinition {
    action(
        "smpp_enquire_link",
        "Check the session is alive; the answer arrives as smpp_link_ok.",
        vec![],
        json!({"type":"smpp_enquire_link"}),
    )
}

fn disconnect_action() -> ActionDefinition {
    action(
        "disconnect",
        "Unbind from the SMSC and close the session",
        vec![],
        json!({"type":"disconnect"}),
    )
}

fn actions() -> Vec<ActionDefinition> {
    vec![submit_action(), enquire_action(), disconnect_action()]
}

pub static BOUND_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "smpp_bound",
        "The SMSC accepted the bind.",
        submit_action().example.clone(),
    )
    .with_parameters(vec![
        parameter(
            "smsc_system_id",
            "string",
            "The system_id the SMSC returned",
            true,
        ),
        parameter(
            "bind",
            "string",
            "transmitter, receiver or transceiver",
            true,
        ),
    ])
    .with_actions(actions())
});

pub static SUBMIT_RESULT_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "smpp_submit_result",
        "The SMSC answered a submit_sm.",
        enquire_action().example.clone(),
    )
    .with_parameters(vec![
        parameter(
            "destination_addr",
            "string",
            "The recipient that submit was for",
            true,
        ),
        parameter(
            "status",
            "string",
            "ESME_ROK, or the SMSC's error status name",
            true,
        ),
        parameter(
            "message_id",
            "string",
            "The SMSC's id for the message, when accepted",
            false,
        ),
    ])
    .with_actions(actions())
});

pub static DELIVER_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "smpp_deliver",
        "The SMSC delivered a message or a delivery receipt; Rust has acknowledged it.",
        submit_action().example.clone(),
    )
    .with_parameters(vec![
        parameter("source_addr", "string", "The sender's address", true),
        parameter("destination_addr", "string", "Recipient address", true),
        parameter(
            "text",
            "string",
            "The text, when its data_coding decodes",
            false,
        ),
        parameter(
            "data",
            "string",
            "The octets in hex, when they are binary",
            false,
        ),
        parameter(
            "is_receipt",
            "boolean",
            "Whether this is a delivery receipt (esm_class 0x04)",
            true,
        ),
        parameter(
            "receipt",
            "object",
            "For a receipt: its id, stat, err and dates",
            false,
        ),
    ])
    .with_actions(actions())
});

pub static LINK_OK_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "smpp_link_ok",
        "The SMSC answered enquire_link.",
        enquire_action().example.clone(),
    )
    .with_parameters(vec![parameter(
        "status",
        "string",
        "The enquire_link_resp status name",
        true,
    )])
    .with_actions(actions())
});

pub fn check(v: &Value) -> Result<()> {
    match v["type"].as_str() {
        Some("smpp_submit") => {
            for key in ["source_addr", "destination_addr"] {
                let a = v[key]
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("{key} must be a string"))?;
                ensure!(
                    a.len() <= 20 && a.is_ascii(),
                    "{key} is at most 20 ASCII characters"
                );
            }
            let text = v["text"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("text must be a string"))?;
            ensure!(
                wire::encode_text(text).1.len() <= wire::MAX_PAYLOAD,
                "text exceeds 64 KiB"
            );
            ensure!(
                v.get("registered_delivery").is_none_or(Value::is_boolean),
                "registered_delivery must be a boolean"
            );
        }
        Some("smpp_enquire_link") => {}
        _ => bail!("Unknown SMPP client action"),
    }
    Ok(())
}

impl Protocol for SmppClientProtocol {
    fn protocol_name(&self) -> &'static str {
        "SMPP"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>SMPP"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["smpp", "sms", "esme", "submit_sm"]
    }
    fn description(&self) -> &'static str {
        "SMPP 3.4 ESME: binds to an SMSC, submits messages, receives receipts and mobile-originated messages"
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        actions()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            BOUND_EVENT.clone(),
            SUBMIT_RESULT_EVENT.clone(),
            DELIVER_EVENT.clone(),
            LINK_OK_EVENT.clone(),
        ]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "system_id".into(),
                type_hint: "string".into(),
                description: "system_id to bind as, at most 15 characters".into(),
                required: true,
                example: json!("esme1"),
                default: None,
            },
            ParameterDefinition {
                name: "password".into(),
                type_hint: "string".into(),
                description: "Bind password, at most 8 characters".into(),
                required: false,
                example: json!("secret"),
                default: None,
            },
            ParameterDefinition {
                name: "system_type".into(),
                type_hint: "string".into(),
                description: "system_type to announce, usually empty".into(),
                required: false,
                example: json!(""),
                default: None,
            },
            ParameterDefinition {
                name: "bind".into(),
                type_hint: "string".into(),
                description: "transceiver (send and receive), transmitter (send only) or receiver (receive only)".into(),
                required: false,
                example: json!("transmitter"),
                default: Some(json!(super::DEFAULT_BIND)),
            },
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .well_known_port(2775)
            .implementation("SMPP 3.4 over Tokio TCP: bind_transmitter/receiver/transceiver, submit_sm (message_payload past 254 octets), enquire_link, deliver_sm answered in Rust and decoded including Appendix B receipts, unbind")
            .llm_control("What to submit and to whom, and what to do with each result, receipt and incoming message")
            .e2e_testing("tests/client/smpp: NetGet's own SMSC; fiorix/go-smpp's smpptest server (Go) as the independent peer")
            .notes("Plain TCP, no TLS. A refused bind fails the connection with the SMSC's status. Submits may be pipelined; each result is matched by sequence number. PDUs are capped at 64 KiB of payload; each request has a 30 s deadline.")
            .max_inbound_bytes(wire::MAX_PDU)
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Bind to the SMSC at 127.0.0.1:2775 as esme1/secret and send Hello to 15551234567 with a receipt"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let llm = json!({"type":"open_client","protocol":"smpp","remote_addr":"127.0.0.1:2775","instruction":"Send Hello to 15551234567 and report the receipt","startup_params":{"system_id":"esme1","password":"secret"}});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([
            {"event_pattern":"smpp_bound","handler":{"type":"static","actions":[{"type":"smpp_submit","source_addr":"NetGet","destination_addr":"15551234567","text":"Hello","registered_delivery":true}]}},
            {"event_pattern":"smpp_deliver","handler":{"type":"static","actions":[{"type":"disconnect"}]}}
        ]);
        let mut scripted = static_example.clone();
        scripted["event_handlers"][1]["handler"] = json!({"type":"script","language":"python","code":"import json,sys\ne=json.load(sys.stdin)['event']\nprint(json.dumps({'actions':[{'type':'disconnect'}] if e['is_receipt'] else []}))"});
        crate::llm::actions::StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Application"
    }
}

impl Client for SmppClientProtocol {
    fn connect(
        &self,
        ctx: ConnectContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::connect(ctx))
    }
    fn execute_action(&self, v: Value) -> Result<ClientActionResult> {
        if v["type"] == "disconnect" {
            return Ok(ClientActionResult::Disconnect);
        }
        check(&v)?;
        Ok(ClientActionResult::Custom {
            name: v["type"].as_str().unwrap_or_default().to_string(),
            data: v,
        })
    }
}
