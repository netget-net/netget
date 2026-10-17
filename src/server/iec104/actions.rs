use crate::llm::actions::protocol_trait::{ActionResult, Server};
use crate::llm::actions::{protocol_trait::Protocol, ActionDefinition};
use crate::protocol::{EventType, SpawnContext};
use crate::server::ics_support::{action, parameter};
use crate::state::AppState;
use anyhow::{ensure, Result};
use serde_json::{json, Value};
use std::{
    future::Future,
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, LazyLock},
};
#[derive(Default)]
pub struct Iec104Protocol;
impl Iec104Protocol {
    pub fn new() -> Self {
        Self
    }
}
pub fn replies() -> Vec<ActionDefinition> {
    vec![
        action(
            "iec104_measurements",
            "Return interrogation/read telemetry",
            vec![parameter(
                "points",
                "array",
                "Up to eight {kind:binary|analog,ioa,value,quality}",
                true,
            )],
            json!({"type":"iec104_measurements","points":[{"kind":"analog","ioa":1,"value":12.5,"quality":0}]}),
        ),
        action(
            "iec104_command_result",
            "Approve or refuse direct single command",
            vec![parameter("accepted", "boolean", "Explicit approval", true)],
            json!({"type":"iec104_command_result","accepted":false}),
        ),
    ]
}
pub static EVENTS: LazyLock<Vec<EventType>> = LazyLock::new(|| {
    vec![EventType::new(
        "iec104_request",
        "Controlled/controlling station: interrogation, telemetry and single commands",
        replies()[0].example.clone(),
    )
    .with_parameters(vec![
        parameter("operation", "string", "interrogate,read,command", true),
        parameter(
            "common_address",
            "number",
            "Station common address, 0..65535",
            true,
        ),
        parameter(
            "ioa",
            "number",
            "IEC information object address, 0..16777215",
            true,
        ),
        parameter("originator", "number", "Originator address", true),
        parameter("qualifier", "number", "Interrogation qualifier", false),
        parameter(
            "value",
            "boolean",
            "Requested boolean single-command state",
            false,
        ),
        parameter(
            "select",
            "boolean",
            "Whether this is a select-before-operate request",
            false,
        ),
    ])
    .with_actions(replies())]
});
impl Protocol for Iec104Protocol {
    fn protocol_name(&self) -> &'static str {
        "IEC 60870-5-104"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>IEC104"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["iec104"]
    }
    fn description(&self) -> &'static str {
        "Controlled/controlling station: interrogation, telemetry and single commands"
    }
    fn example_prompt(&self) -> &'static str {
        "Simulate a IEC 60870-5-104 device on localhost"
    }
    fn group_name(&self) -> &'static str {
        "Industrial"
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        vec![action(
            "disconnect",
            "Close this peer",
            vec![],
            json!({"type":"disconnect"}),
        )]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        replies()
    }
    fn get_event_types(&self) -> Vec<EventType> {
        EVENTS.clone()
    }

    fn metadata(&self) -> crate::protocol::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder().state(DevelopmentState::Experimental).privilege_requirement(PrivilegeRequirement::None).implementation("APCI START/STOP/TEST, sequence windows, t1/t3 timers; selected GI, read, single command, binary and float ASDUs").llm_control("Handler supplies device values, operation approvals and refusals; client handler selects structured operations").e2e_testing("Independent peer integration plus negative and lifecycle tests in tests/server/iec104").notes("Selected ASDUs 1,13,45,100,102. Direct commands only; select rejected. Polled handler telemetry; client also accepts spontaneous binary/float telemetry. k=12, immediate acknowledgments (within w=8/t2), t1=15s,t3=20s; 10s command deadline. No timestamped ASDUs, file transfer, clock sync or redundancy.").max_inbound_bytes(crate::server::iec104::codec::MAX_FRAME).well_known_port(2404).answers_on_failure().history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
        .batching(crate::protocol::metadata::BatchingMode::Unsupported)
        .build()
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let base = json!({"type":"open_server","base_stack":"iec104","port":2404,"instruction":"Supply device decisions with structured actions"});
        let a = replies()[0].example.clone();
        let mut fixed = base.clone();
        fixed["event_handlers"] = json!([{"event_pattern":"iec104_request","handler":{"type":"static","actions":[a.clone()]}}]);
        let code = format!("print({})", json!(json!({"actions":[a]}).to_string()));
        let mut script = base.clone();
        script["event_handlers"] = json!([{"event_pattern":"iec104_request","handler":{"type":"script","language":"python","code":code}}]);
        crate::llm::actions::StartupExamples::new(base, script, fixed)
    }
}
impl Server for Iec104Protocol {
    fn spawn(&self, ctx: SpawnContext) -> Pin<Box<dyn Future<Output = Result<SocketAddr>> + Send>> {
        Box::pin(crate::server::ics_support::spawn(
            ctx,
            Arc::new(Self),
            super::codec::Device::default,
            &EVENTS,
        ))
    }
    fn execute_action(&self, v: Value) -> Result<ActionResult> {
        if v["type"] == "disconnect" {
            return Ok(ActionResult::CloseConnection);
        }
        ensure!(
            replies().iter().any(|a| v["type"] == a.name),
            "unknown device reply action"
        );
        ensure!(
            crate::utils::json_budget::within_budget(&v, 4096, 1024, 16),
            "reply exceeds JSON budget"
        );
        Ok(ActionResult::Custom {
            name: v["type"].as_str().expect("validated").into(),
            data: v,
        })
    }
}
