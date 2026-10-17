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
pub struct SmppProtocol;
impl SmppProtocol {
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
    let log_template =
        match name {
            "smpp_accept" => LogTemplate::new()
                .with_info("-> SMPP accept message_id={message_id} receipt={receipt}"),
            "smpp_reject" | "smpp_bind_reject" => {
                LogTemplate::new().with_info(format!("-> SMPP {name} {{status}}"))
            }
            "smpp_submit" => LogTemplate::new()
                .with_info("-> SMPP submit to {destination_addr}: {preview(text,80)}"),
            _ => LogTemplate::new().with_info(format!("-> SMPP {name}")),
        };
    ActionDefinition {
        name: name.into(),
        description: description.into(),
        parameters,
        example,
        log_template: Some(log_template),
    }
}

fn bind_accept_action() -> ActionDefinition {
    action(
        "smpp_bind_accept",
        "Accept the bind; the ESME may then submit (and receive, when bound as receiver or transceiver).",
        vec![],
        json!({"type":"smpp_bind_accept"}),
    )
}

fn bind_reject_action() -> ActionDefinition {
    action(
        "smpp_bind_reject",
        "Refuse the bind with an SMPP status; the connection is then closed.",
        vec![parameter(
            "status",
            "string",
            "ESME_RINVPASWD, ESME_RINVSYSID or ESME_RBINDFAIL (default)",
            false,
        )],
        json!({"type":"smpp_bind_reject","status":"ESME_RINVPASWD"}),
    )
}

fn accept_action() -> ActionDefinition {
    action(
        "smpp_accept",
        "Accept the message. Rust answers submit_sm_resp, then sends a delivery receipt if the ESME asked for one, and an optional mobile-originated reply.",
        vec![
            parameter("message_id", "string", "SMSC message id, at most 64 characters; Rust assigns one when absent", false),
            parameter("receipt", "string", "Final state for the delivery receipt: DELIVRD, UNDELIV, EXPIRED, REJECTD or DELETED; none when absent", false),
            parameter("reply_text", "string", "Text sent back to the sender as a mobile-originated deliver_sm from the destination", false),
        ],
        json!({"type":"smpp_accept","receipt":"DELIVRD"}),
    )
}

fn reject_action() -> ActionDefinition {
    action(
        "smpp_reject",
        "Refuse the message with an SMPP error status in submit_sm_resp.",
        vec![parameter(
            "status",
            "string",
            "ESME_RINVDSTADR, ESME_RINVSRCADR, ESME_RINVMSGLEN, ESME_RTHROTTLED, ESME_RSUBMITFAIL, ESME_RX_T_APPN or ESME_RX_P_APPN",
            true,
        )],
        json!({"type":"smpp_reject","status":"ESME_RINVDSTADR"}),
    )
}

pub static BIND_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "smpp_bind",
        "An ESME is binding and no credentials are configured; accept or refuse it.",
        bind_accept_action().example.clone(),
    )
    .with_parameters(vec![
        parameter(
            "mode",
            "string",
            "transmitter, receiver or transceiver",
            true,
        ),
        parameter("system_id", "string", "The ESME's system_id", true),
        parameter("password", "string", "The password it sent", true),
        parameter(
            "system_type",
            "string",
            "Its system_type, often empty",
            true,
        ),
        parameter(
            "interface_version",
            "number",
            "SMPP version it speaks (0x34 = 52 for 3.4)",
            true,
        ),
        parameter("remote_addr", "string", "ESME address and port", true),
    ])
    .with_actions(vec![bind_accept_action(), bind_reject_action()])
});

pub static SUBMIT_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "smpp_submit",
        "A bound ESME submitted a short message; accept it (optionally with a receipt or reply) or reject it.",
        accept_action().example.clone(),
    )
    .with_parameters(vec![
        parameter("system_id", "string", "The submitting ESME's system_id", true),
        parameter("source_addr", "string", "The sender's address", true),
        parameter("destination_addr", "string", "Recipient address", true),
        parameter("text", "string", "The message text, when its data_coding decodes", false),
        parameter("data", "string", "The message octets in hex, when they are binary", false),
        parameter("data_coding", "number", "0 default alphabet, 3 Latin-1, 8 UCS-2, others binary", true),
        parameter("registered_delivery", "boolean", "Whether the ESME asked for a delivery receipt", true),
        parameter("esm_class", "number", "esm_class octet (0x40 = UDH present)", true),
        parameter("remote_addr", "string", "ESME address and port", true),
    ])
    .with_actions(vec![accept_action(), reject_action()])
});

pub fn check_message_id(v: &Value) -> Result<()> {
    if let Some(id) = v.get("message_id") {
        let id = id
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("message_id must be a string"))?;
        ensure!(
            !id.is_empty() && id.len() <= 64 && id.chars().all(|c| c.is_ascii_graphic()),
            "message_id must be 1 to 64 printable ASCII characters"
        );
    }
    Ok(())
}

impl Protocol for SmppProtocol {
    fn protocol_name(&self) -> &'static str {
        "SMPP"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>SMPP"
    }
    fn description(&self) -> &'static str {
        "SMPP 3.4 SMSC: binds, submit_sm, delivery receipts and mobile-originated replies decided by the handler"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["smpp", "sms", "smsc", "esme", "short message", "submit_sm"]
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            bind_accept_action(),
            bind_reject_action(),
            accept_action(),
            reject_action(),
        ]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![BIND_EVENT.clone(), SUBMIT_EVENT.clone()]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "system_id".into(),
                type_hint: "string".into(),
                description: "This SMSC's own system_id, returned in every bind response".into(),
                required: false,
                example: json!("SMSC"),
                default: Some(json!(super::DEFAULT_SYSTEM_ID)),
            },
            ParameterDefinition {
                name: "esme_system_id".into(),
                type_hint: "string".into(),
                description: "With password: the only system_id allowed to bind, checked in Rust (no smpp_bind event)".into(),
                required: false,
                example: json!("esme1"),
                default: None,
            },
            ParameterDefinition {
                name: "password".into(),
                type_hint: "string".into(),
                description: "With esme_system_id: the password checked in Rust, at most 8 characters".into(),
                required: false,
                example: json!("secret"),
                default: None,
            },
            ParameterDefinition {
                name: "idle_timeout_secs".into(),
                type_hint: "number".into(),
                description: "Seconds a session may stay silent; ESMEs keep it alive with enquire_link (1..=86400)".into(),
                required: false,
                example: json!(600),
                default: Some(json!(super::IDLE_TIMEOUT.as_secs())),
            },
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .well_known_port(2775)
            .implementation("SMPP 3.4 over Tokio TCP, hand-written: bind_transmitter/receiver/transceiver, submit_sm with short_message or message_payload, deliver_sm receipts (Appendix B text plus receipted_message_id and message_state) and MO messages, enquire_link, unbind, generic_nack")
            .llm_control("Bind decisions (unless credentials are configured), and per message: accept with an id, a delivery receipt state and an optional reply, or reject with a status")
            .e2e_testing("tests/server/smpp: raw PDUs and bounds; Python smpplib and linxGnu/gosmpp (Go) as independent ESMEs")
            .notes("Plain TCP, no TLS. Text is decoded for data_coding 0, 1, 3 and 8; other codings reach the handler as hex. Receipts and replies go only to sessions bound as receiver or transceiver, and receipts only when registered_delivery asked. PDUs are capped at 64 KiB of payload; the first PDU must be a bind within the idle timeout. A handler failure on a submit answers ESME_RSYSERR (ESME_RTHROTTLED when the backend is saturated), on a bind ESME_RBINDFAIL; nothing is ever accepted by default.")
            .request_only("Every response answers the ESME's PDU; receipts and replies follow a submit the handler accepted")
            .max_inbound_bytes(super::wire::MAX_PDU)
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "SMPP SMSC on port 2775 that accepts messages to +1555 numbers with a delivered receipt and rejects the rest"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let llm = json!({"type":"open_server","base_stack":"smpp","port":2775,"instruction":"Accept messages to numbers starting 1555 with a DELIVRD receipt; reject others with ESME_RINVDSTADR","startup_params":{"esme_system_id":"esme1","password":"secret"}});
        let mut scripted = llm.clone();
        scripted["event_handlers"] = json!([{"event_pattern":"smpp_submit","handler":{"type":"script","language":"python","code":"import json,sys\ne=json.load(sys.stdin)['event']\nok=e['destination_addr'].lstrip('+').startswith('1555')\na={'type':'smpp_accept','receipt':'DELIVRD'} if ok else {'type':'smpp_reject','status':'ESME_RINVDSTADR'}\nprint(json.dumps({'actions':[a]}))"}}]);
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([{"event_pattern":"smpp_submit","handler":{"type":"static","actions":[{"type":"smpp_accept","receipt":"DELIVRD"}]}}]);
        crate::llm::actions::StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Application"
    }
}

impl Server for SmppProtocol {
    fn spawn(
        &self,
        ctx: SpawnContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::spawn(ctx))
    }
    fn execute_action(&self, v: Value) -> Result<ActionResult> {
        let name = v["type"].as_str().unwrap_or_default().to_string();
        match name.as_str() {
            "smpp_bind_accept" => {}
            "smpp_bind_reject" => {
                if let Some(s) = v.get("status") {
                    let s = s
                        .as_str()
                        .ok_or_else(|| anyhow::anyhow!("status must be a string"))?;
                    ensure!(
                        matches!(s, "ESME_RINVPASWD" | "ESME_RINVSYSID" | "ESME_RBINDFAIL"),
                        "bind status must be ESME_RINVPASWD, ESME_RINVSYSID or ESME_RBINDFAIL"
                    );
                }
            }
            "smpp_accept" => {
                check_message_id(&v)?;
                if let Some(r) = v.get("receipt") {
                    ensure!(
                        matches!(
                            r.as_str(),
                            Some("DELIVRD" | "UNDELIV" | "EXPIRED" | "REJECTD" | "DELETED")
                        ),
                        "receipt must be DELIVRD, UNDELIV, EXPIRED, REJECTD or DELETED"
                    );
                }
                if let Some(t) = v.get("reply_text") {
                    let t = t
                        .as_str()
                        .ok_or_else(|| anyhow::anyhow!("reply_text must be a string"))?;
                    ensure!(
                        super::wire::encode_text(t).1.len() <= super::wire::MAX_PAYLOAD,
                        "reply_text exceeds 64 KiB"
                    );
                }
            }
            "smpp_reject" => {
                let s = v["status"]
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("status must be a string"))?;
                ensure!(super::wire::status_code(s).is_some(), "unknown status {s}");
            }
            _ => bail!("Unknown SMPP server action"),
        }
        Ok(ActionResult::Custom { name, data: v })
    }
}
