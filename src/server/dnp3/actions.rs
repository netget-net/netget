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
pub struct Dnp3Protocol;
impl Dnp3Protocol {
    pub fn new() -> Self {
        Self
    }
}
pub fn replies() -> Vec<ActionDefinition> {
    vec![action("dnp3_measurements","Return typed static/class events with point kind, index, value, flags, class and optional deterministic timestamp_ms",vec![parameter("points","array","Up to 64 {kind:binary|analog|counter,index,value,flags,class:0..3,timestamp_ms}",true)],json!({"type":"dnp3_measurements","points":[{"kind":"analog","index":0,"value":12.5,"flags":1,"class":0}]})),action("dnp3_control_result","Approve or refuse the declared binary direct-operate control",vec![parameter("status","string","success, denied, not_supported or out_of_range",true)],json!({"type":"dnp3_control_result","status":"denied"}))]
}
pub static EVENTS: LazyLock<Vec<EventType>> = LazyLock::new(|| {
    vec![EventType::new(
        "dnp3_request",
        "DNP3 outstation/master: class polls, typed points and binary direct-operate",
        replies()[0].example.clone(),
    )
    .with_parameters(vec![
        parameter("operation", "string", "poll or control", true),
        parameter("sequence", "number", "Application sequence 0..15", true),
        parameter("function", "number", "DNP3 application function", true),
        parameter("classes", "array", "Classes being polled", false),
        parameter("index", "number", "Control point index", false),
        parameter(
            "code",
            "number",
            "Binary control operation code, 1..4",
            false,
        ),
        parameter("count", "number", "Control repeat count", false),
        parameter("on_ms", "number", "On milliseconds", false),
        parameter("off_ms", "number", "Off milliseconds", false),
    ])
    .with_actions(replies())]
});
impl Protocol for Dnp3Protocol {
    fn protocol_name(&self) -> &'static str {
        "DNP3"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>DNP3"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["dnp3"]
    }
    fn description(&self) -> &'static str {
        "DNP3 outstation/master: class polls, typed points and binary direct-operate"
    }
    fn example_prompt(&self) -> &'static str {
        "Simulate a DNP3 device on localhost"
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
        ProtocolMetadataV2::builder().state(DevelopmentState::Experimental).privilege_requirement(PrivilegeRequirement::None).implementation("Own CRC-validated link framing and bounded transport reassembly; selected DNP3 application objects, class polls, confirmation and CROB direct-operate").llm_control("Handler supplies device values, operation approvals and refusals; client handler selects structured operations").e2e_testing("Independent peer integration plus negative and lifecycle tests in tests/server/dnp3").notes("Self-contained Rust subset; no Step Function dependency. Independent Apache-2.0 OpenDNP3 3.1.2 peer. Link addresses fixed master=1/outstation=10. Static binary G1v2, analog G30v5, counter G20v1; event G2v1/2, G32v5/7, G22v1/5. Handler-sourced class events, confirmations and last-request replay. No unsolicited reporting, SELECT/OPERATE, analog controls, serial or Secure Authentication. Deterministic handler timestamps and 10 s response deadlines. 292-byte link frames and 2048-byte app assembly.").max_inbound_bytes(crate::server::dnp3::codec::MAX_FRAME).well_known_port(20000).answers_on_failure().history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
        .batching(crate::protocol::metadata::BatchingMode::Unsupported)
        .build()
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let base = json!({"type":"open_server","base_stack":"dnp3","port":20000,"instruction":"Supply device decisions with structured actions"});
        let a = replies()[0].example.clone();
        let mut fixed = base.clone();
        fixed["event_handlers"] = json!([{"event_pattern":"dnp3_request","handler":{"type":"static","actions":[a.clone()]}}]);
        let code = format!("print({})", json!(json!({"actions":[a]}).to_string()));
        let mut script = base.clone();
        script["event_handlers"] = json!([{"event_pattern":"dnp3_request","handler":{"type":"script","language":"python","code":code}}]);
        crate::llm::actions::StartupExamples::new(base, script, fixed)
    }
}
impl Server for Dnp3Protocol {
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
