use crate::llm::actions::client_trait::{Client, ClientActionResult};
use crate::llm::actions::{protocol_trait::Protocol, ActionDefinition};
use crate::protocol::{ConnectContext, EventType};
use crate::server::ics_support::{action, parameter};
use crate::state::AppState;
use anyhow::Result;
use serde_json::{json, Value};
use std::{future::Future, net::SocketAddr, pin::Pin, sync::LazyLock};
#[derive(Default)]
pub struct Dnp3ClientProtocol;
impl Dnp3ClientProtocol {
    pub fn new() -> Self {
        Self
    }
}
pub fn requests() -> Vec<ActionDefinition> {
    vec![action("dnp3_poll","Read classes (0 static, 1/2/3 events)",vec![parameter("classes","array","One to four class numbers 0..3",true)],json!({"type":"dnp3_poll","classes":[0]})),action("dnp3_control","One CROB direct-operate, 16-bit index; code values 1 pulse on,2 pulse off,3 latch on,4 latch off",vec![parameter("index","number","Output index 0..65535",true),parameter("code","number","CROB code, low nibble 0..4",true),parameter("count","number","Repeat count 1..255",true),parameter("on_ms","number","On duration, 32-bit milliseconds",true),parameter("off_ms","number","Off duration, 32-bit milliseconds",true)],json!({"type":"dnp3_control","index":0,"code":3,"count":1,"on_ms":0,"off_ms":0})),action("disconnect","Close master link",vec![],json!({"type":"disconnect"}))]
}
pub static EVENTS: LazyLock<Vec<EventType>> = LazyLock::new(|| {
    vec![
        EventType::new(
            "dnp3_connected",
            "Transport ready for device operations",
            requests()[0].example.clone(),
        )
        .with_parameters(vec![parameter(
            "remote_addr",
            "string",
            "Address of the connected remote device",
            true,
        )])
        .with_actions(requests()),
        EventType::new(
            "dnp3_response",
            "Device operation result or protocol status",
            requests()[0].example.clone(),
        )
        .with_parameters(vec![
            parameter(
                "success",
                "boolean",
                "Whether the device accepted the operation",
                false,
            ),
            parameter("status", "number", "Protocol error status, if any", false),
            parameter("value", "object", "Decoded response fields", false),
        ])
        .with_actions(requests()),
    ]
});
impl Protocol for Dnp3ClientProtocol {
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
        "Connect to a DNP3 device on localhost"
    }
    fn group_name(&self) -> &'static str {
        "Industrial"
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        requests()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        EVENTS.clone()
    }

    fn metadata(&self) -> crate::protocol::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder().state(DevelopmentState::Experimental).privilege_requirement(PrivilegeRequirement::None).implementation("Own CRC-validated link framing and bounded transport reassembly; selected DNP3 application objects, class polls, confirmation and CROB direct-operate").llm_control("Handler supplies device values, operation approvals and refusals; client handler selects structured operations").e2e_testing("Independent peer integration plus negative and lifecycle tests in tests/client/dnp3").notes("Self-contained Rust subset; no Step Function dependency. Independent Apache-2.0 OpenDNP3 3.1.2 peer. Link addresses fixed master=1/outstation=10. Static binary G1v2, analog G30v5, counter G20v1; event G2v1/2, G32v5/7, G22v1/5. Handler-sourced class events, confirmations and last-request replay. No unsolicited reporting, SELECT/OPERATE, analog controls, serial or Secure Authentication. Deterministic handler timestamps and 10 s response deadlines. 292-byte link frames and 2048-byte app assembly.").max_inbound_bytes(crate::server::dnp3::codec::MAX_FRAME).history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
        .batching(crate::protocol::metadata::BatchingMode::Unsupported)
        .build()
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let base = json!({"type":"open_client","protocol":"dnp3","remote_addr":"127.0.0.1:20000","instruction":"Supply device decisions with structured actions"});
        let a = requests()[0].example.clone();
        let mut fixed = base.clone();
        fixed["event_handlers"] = json!([{"event_pattern":"dnp3_connected","handler":{"type":"static","actions":[a.clone()]}}]);
        let code = format!("print({})", json!(json!({"actions":[a]}).to_string()));
        let mut script = base.clone();
        script["event_handlers"] = json!([{"event_pattern":"dnp3_connected","handler":{"type":"script","language":"python","code":code}}]);
        crate::llm::actions::StartupExamples::new(base, script, fixed)
    }
}
impl Client for Dnp3ClientProtocol {
    fn connect(
        &self,
        ctx: ConnectContext,
    ) -> Pin<Box<dyn Future<Output = Result<SocketAddr>> + Send>> {
        Box::pin(super::connect(ctx))
    }
    fn execute_action(&self, v: Value) -> Result<ClientActionResult> {
        if v["type"] == "disconnect" {
            return Ok(ClientActionResult::Disconnect);
        }
        crate::server::dnp3::codec::validate(&v)?;
        Ok(ClientActionResult::Custom {
            name: v["type"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("action type"))?
                .into(),
            data: v,
        })
    }
}
