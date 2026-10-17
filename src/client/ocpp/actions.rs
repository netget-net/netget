use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, ParameterDefinition,
};
use crate::protocol::{ConnectContext, EventType};
use crate::server::ocpp::actions::{
    action, error_action, parameter, result_action, validate_answer,
};
use anyhow::{bail, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

#[derive(Default)]
pub struct OcppClientProtocol;
impl OcppClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

fn call_action() -> ActionDefinition {
    action(
        "ocpp_call",
        "Send a CALL to the central system (one outstanding at a time). Rust assigns the message id, checks the core actions' required request fields and raises ocpp_call_response with the answer.",
        vec![
            parameter("action", "string", "BootNotification, Heartbeat, StatusNotification, Authorize, StartTransaction, StopTransaction, MeterValues (1.6) or TransactionEvent (2.0.1), ...", true),
            parameter("payload", "object", "The request payload, e.g. {\"chargePointVendor\":\"NetGet\",\"chargePointModel\":\"Sim-1\"}", true),
        ],
        json!({"type":"ocpp_call","action":"BootNotification","payload":{"chargePointVendor":"NetGet","chargePointModel":"Sim-1"}}),
    )
}
fn disconnect_action() -> ActionDefinition {
    action(
        "disconnect",
        "Close the WebSocket to the central system",
        vec![],
        json!({"type":"disconnect"}),
    )
}
fn actions() -> Vec<ActionDefinition> {
    vec![
        call_action(),
        result_action(),
        error_action(),
        disconnect_action(),
    ]
}

pub static CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new("ocpp_connected", "WebSocket open and subprotocol agreed; a charge point usually sends BootNotification first", call_action().example.clone())
        .with_parameters(vec![
            parameter("charge_point_id", "string", "This charge point's identity", true),
            parameter("ocpp_version", "string", "Negotiated version: 1.6 or 2.0.1", true),
        ])
        .with_actions(actions())
});
pub static RESPONSE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "ocpp_call_response",
        "The central system answered this charge point's CALL",
        json!({"type":"ocpp_call","action":"Heartbeat","payload":{}}),
    )
    .with_parameters(vec![
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
    .with_actions(actions())
});
pub static CSMS_CALL_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new("ocpp_csms_call", "The central system sent a CALL (RemoteStartTransaction, Reset, ChangeConfiguration, GetConfiguration, SetVariables, ...). Answer with ocpp_call_result or ocpp_call_error.", result_action().example.clone())
        .with_parameters(vec![
            parameter("action", "string", "The CALL's action", true),
            parameter("message_id", "string", "The CALL's id (echoed by Rust)", true),
            parameter("payload", "object", "The CALL's payload", true),
        ])
        .with_actions(actions())
});

impl Protocol for OcppClientProtocol {
    fn protocol_name(&self) -> &'static str {
        "OCPP"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>HTTP>WebSocket>OCPP"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["ocpp", "charge point", "ev charger simulator", "ocpp-j"]
    }
    fn description(&self) -> &'static str {
        "Simulated OCPP-J 1.6 / 2.0.1 charge point talking to a central system"
    }
    fn get_async_actions(&self, _: &crate::state::app_state::AppState) -> Vec<ActionDefinition> {
        actions()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            CONNECTED_EVENT.clone(),
            RESPONSE_EVENT.clone(),
            CSMS_CALL_EVENT.clone(),
        ]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "charge_point_id".into(),
                type_hint: "string".into(),
                description: "Identity appended to the WebSocket URL, e.g. CP-001".into(),
                required: true,
                example: json!("CP-001"),
                default: None,
            },
            ParameterDefinition {
                name: "ocpp_version".into(),
                type_hint: "string".into(),
                description: "Subprotocol to request: \"1.6\" or \"2.0.1\"".into(),
                required: false,
                example: json!("2.0.1"),
                default: Some(json!(super::DEFAULT_VERSION)),
            },
            ParameterDefinition {
                name: "path_prefix".into(),
                type_hint: "string".into(),
                description: "URL path before the charge point id, e.g. /ocpp/".into(),
                required: false,
                example: json!("/ocpp/"),
                default: Some(json!(super::DEFAULT_PREFIX)),
            },
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation("tokio-tungstenite client requesting ocpp1.6 or ocpp2.0.1; shared OCPP-J framing and core required-field checks; one outstanding CALL per direction")
            .llm_control("Which calls the simulated charge point makes (boot, heartbeat, status, authorize, transactions) and how it answers central-system calls")
            .e2e_testing("tests/client/ocpp: python ocpp 2.1.0 central systems (independent, schema-validating) over 1.6 and 2.0.1, including CSMS-initiated calls; NetGet pair and refusals")
            .notes("Plain ws:// only, no security profiles. No meter or connector simulation in Rust: the handler supplies every payload. 64 KiB messages.")
            .max_inbound_bytes(crate::server::ocpp::frame::MAX_MESSAGE_BYTES)
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Simulate charge point CP-001 booting against the OCPP 1.6 central system at 127.0.0.1:9000"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let llm = json!({"type":"open_client","protocol":"ocpp","remote_addr":"127.0.0.1:9000","instruction":"Boot, then send a heartbeat","startup_params":{"charge_point_id":"CP-001"}});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([
            {"event_pattern":"ocpp_connected","handler":{"type":"static","actions":[call_action().example]}},
            {"event_pattern":"ocpp_call_response","handler":{"type":"static","actions":[]}},
            {"event_pattern":"ocpp_csms_call","handler":{"type":"static","actions":[{"type":"ocpp_call_error","code":"NotSupported"}]}}
        ]);
        let mut scripted = static_example.clone();
        scripted["event_handlers"][1]["handler"] = json!({"type":"script","language":"python","code":"import json\nprint(json.dumps({'actions':[]}))"});
        crate::llm::actions::StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Industrial"
    }
}

impl Client for OcppClientProtocol {
    fn connect(
        &self,
        ctx: ConnectContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::connect(ctx))
    }
    fn execute_action(&self, v: Value) -> Result<ClientActionResult> {
        match v["type"].as_str() {
            Some(name @ ("ocpp_call" | "ocpp_call_result" | "ocpp_call_error")) => {
                validate_answer(&v)?;
                Ok(ClientActionResult::Custom {
                    name: name.into(),
                    data: v,
                })
            }
            Some("disconnect") => Ok(ClientActionResult::Disconnect),
            _ => bail!("Unknown OCPP client action"),
        }
    }
}
