use super::frame;
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
pub struct OcppProtocol;
impl OcppProtocol {
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
        "ocpp_call_result" => LogTemplate::new().with_info("-> OCPP CALLRESULT"),
        "ocpp_call_error" => LogTemplate::new().with_info("-> OCPP CALLERROR {code}"),
        "ocpp_send_call" | "ocpp_call" => LogTemplate::new().with_info("-> OCPP CALL {action}"),
        _ => LogTemplate::new().with_info(format!("-> OCPP {name}")),
    };
    ActionDefinition {
        name: name.into(),
        description: description.into(),
        parameters,
        example,
        log_template: Some(log_template),
    }
}

pub fn result_action() -> ActionDefinition {
    action(
        "ocpp_call_result",
        "Answer the pending CALL with a CALLRESULT. Rust echoes the message id and checks the core actions' required response fields (e.g. BootNotification needs status, currentTime, interval).",
        vec![parameter("payload", "object", "The response payload for the action, e.g. {\"status\":\"Accepted\",\"currentTime\":\"2026-01-01T00:00:00Z\",\"interval\":300}", true)],
        json!({"type":"ocpp_call_result","payload":{"status":"Accepted","currentTime":"2026-01-01T00:00:00Z","interval":300}}),
    )
}

pub fn error_action() -> ActionDefinition {
    action(
        "ocpp_call_error",
        "Answer the pending CALL with a CALLERROR.",
        vec![
            parameter("code", "string", "OCPP error code: NotImplemented, NotSupported, InternalError, ProtocolError, SecurityError, PropertyConstraintViolation, TypeConstraintViolation, GenericError (and the version's formation/occurrence spellings)", true),
            parameter("description", "string", "Short human-readable description (≤255 characters)", false),
            parameter("details", "object", "Extra error details object", false),
        ],
        json!({"type":"ocpp_call_error","code":"NotSupported","description":"not offered here"}),
    )
}

fn send_call_action() -> ActionDefinition {
    action(
        "ocpp_send_call",
        "Send a CSMS-initiated CALL to this charge point (one outstanding at a time); the reply raises ocpp_call_response.",
        vec![
            parameter("action", "string", "OCPP action, e.g. RemoteStartTransaction, Reset, ChangeConfiguration (1.6) or RequestStartTransaction, SetVariables (2.0.1)", true),
            parameter("payload", "object", "The request payload", true),
        ],
        json!({"type":"ocpp_send_call","action":"Reset","payload":{"type":"Soft"}}),
    )
}

fn disconnect_action() -> ActionDefinition {
    action(
        "disconnect",
        "Close this charge point's WebSocket",
        vec![],
        json!({"type":"disconnect"}),
    )
}

pub static CALL_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "ocpp_call",
        "A charge point sent a CALL (BootNotification, Heartbeat, StatusNotification, Authorize, StartTransaction/StopTransaction or TransactionEvent, MeterValues, ...). Answer with a CALLRESULT or CALLERROR; there is no charging database in Rust.",
        result_action().example.clone(),
    )
    .with_parameters(vec![
        parameter("charge_point_id", "string", "Identity from the WebSocket URL", true),
        parameter("ocpp_version", "string", "Negotiated version: 1.6 or 2.0.1", true),
        parameter("action", "string", "The CALL's action name", true),
        parameter("message_id", "string", "The CALL's unique id (echoed by Rust)", true),
        parameter("payload", "object", "The CALL's payload", true),
    ])
    .with_actions(vec![result_action(), error_action()])
});

pub static CALL_RESPONSE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "ocpp_call_response",
        "A charge point answered a CSMS-initiated CALL",
        json!({"type":"ocpp_send_call","action":"GetConfiguration","payload":{}}),
    )
    .with_parameters(vec![
        parameter(
            "charge_point_id",
            "string",
            "Identity from the WebSocket URL",
            true,
        ),
        parameter("action", "string", "The CALL's action", true),
        parameter(
            "message_id",
            "string",
            "The id Rust assigned to the CALL this answers (csms-N or cp-N)",
            true,
        ),
        parameter("payload", "object", "CALLRESULT payload", false),
        parameter(
            "error",
            "object",
            "CALLERROR {code, description, details}",
            false,
        ),
    ])
    .with_actions(vec![send_call_action(), disconnect_action()])
});

impl Protocol for OcppProtocol {
    fn protocol_name(&self) -> &'static str {
        "OCPP"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>HTTP>WebSocket>OCPP"
    }
    fn description(&self) -> &'static str {
        "OCPP-J 1.6 / 2.0.1 charging station management system (CSMS) over WebSocket"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "ocpp",
            "ocpp-j",
            "ev charging",
            "csms",
            "central system",
            "charge point",
        ]
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        vec![send_call_action(), disconnect_action()]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![result_action(), error_action()]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![CALL_EVENT.clone(), CALL_RESPONSE_EVENT.clone()]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "ocpp_versions".into(),
                type_hint: "array".into(),
                description: "Versions offered in subprotocol negotiation, in preference order: \"1.6\" and/or \"2.0.1\"".into(),
                required: false,
                example: json!(["2.0.1"]),
                default: Some(json!(super::DEFAULT_VERSIONS)),
            },
            ParameterDefinition {
                name: "call_timeout_secs".into(),
                type_hint: "number".into(),
                description: "Seconds (1..=300) a CSMS-initiated CALL waits for its answer".into(),
                required: false,
                example: json!(30),
                default: Some(json!(super::CALL_TIMEOUT.as_secs())),
            },
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation("tokio-tungstenite WebSocket with ocpp1.6/ocpp2.0.1 subprotocol negotiation; Rust owns RPC framing, message-id correlation, one outstanding CALL per direction and required-field checks for the core workflows")
            .llm_control("Every CALLRESULT/CALLERROR to charge-point calls (boot acceptance, authorization, transaction ids, timers) and CSMS-initiated calls such as remote start, reset or configuration")
            .e2e_testing("tests/server/ocpp: python ocpp 2.1.0 (independent, schema-validating) charge points over 1.6 and 2.0.1 run boot/heartbeat/status/authorize/transaction workflows and answer CSMS calls; frame and bound tests")
            .notes("No charging database or payload schema engine: Rust checks frame structure and the core actions' required fields; full JSON-schema validation is the peer's job. Plain ws:// (put TLS and security profiles in front). 64 KiB messages.")
            .answers_on_failure()
            .max_inbound_bytes(frame::MAX_MESSAGE_BYTES)
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "OCPP 1.6 central system on port 9000 that accepts every charge point boot"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let llm = json!({"type":"open_server","base_stack":"ocpp","port":9000,"instruction":"Accept every BootNotification with a 300 s heartbeat; authorize tag ABC only"});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([{"event_pattern":"ocpp_call","handler":{"type":"static","actions":[{"type":"ocpp_call_error","code":"NotSupported","description":"static policy"}]}}]);
        let mut scripted = llm.clone();
        scripted["event_handlers"] = json!([{"event_pattern":"ocpp_call","handler":{"type":"script","language":"python","code":"import json,sys\ne=json.load(sys.stdin)['event']\nif e['action']=='Heartbeat':\n    a={'type':'ocpp_call_result','payload':{'currentTime':'2026-01-01T00:00:00Z'}}\nelse:\n    a={'type':'ocpp_call_error','code':'NotImplemented'}\nprint(json.dumps({'actions':[a]}))"}}]);
        crate::llm::actions::StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Industrial"
    }
}

impl Server for OcppProtocol {
    fn spawn(
        &self,
        ctx: SpawnContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::spawn(ctx))
    }
    fn execute_action(&self, v: Value) -> Result<ActionResult> {
        match v["type"].as_str() {
            Some(name @ ("ocpp_call_result" | "ocpp_call_error" | "ocpp_send_call")) => {
                validate_answer(&v)?;
                Ok(ActionResult::Custom {
                    name: name.into(),
                    data: v,
                })
            }
            Some("disconnect") => Ok(ActionResult::CloseConnection),
            _ => bail!("Unknown OCPP server action"),
        }
    }
}

/// Shape checks that need no version; version-specific checks happen at send time.
pub fn validate_answer(v: &Value) -> Result<()> {
    match v["type"].as_str() {
        Some("ocpp_call_result") => ensure!(
            v["payload"].is_object() && frame::budget_ok(&v["payload"]),
            "payload must be a bounded object"
        ),
        Some("ocpp_call_error") => {
            let code = v["code"].as_str().context("code is required")?;
            ensure!(!code.is_empty() && code.len() <= 64, "invalid error code");
            if let Some(d) = v.get("description").filter(|d| !d.is_null()) {
                ensure!(
                    d.as_str().is_some_and(|s| s.len() <= 255),
                    "description must be a string of ≤255 characters"
                );
            }
            ensure!(
                v.get("details")
                    .is_none_or(|d| d.is_null() || d.is_object()),
                "details must be an object"
            );
        }
        Some("ocpp_send_call" | "ocpp_call") => {
            let action = v["action"].as_str().context("action is required")?;
            ensure!(
                !action.is_empty()
                    && action.len() <= 64
                    && action.bytes().all(|b| b.is_ascii_alphanumeric()),
                "action must be ASCII letters or digits"
            );
            ensure!(
                v["payload"].is_object() && frame::budget_ok(&v["payload"]),
                "payload must be a bounded object"
            );
        }
        _ => bail!("unknown OCPP answer"),
    }
    Ok(())
}
