use crate::llm::actions::client_trait::{Client, ClientActionResult};
use crate::llm::actions::{protocol_trait::Protocol, ActionDefinition};
use crate::protocol::{ConnectContext, EventType};
use crate::server::ics_support::{action, parameter};
use crate::state::AppState;
use anyhow::Result;
use serde_json::{json, Value};
use std::{future::Future, net::SocketAddr, pin::Pin, sync::LazyLock};
#[derive(Default)]
pub struct Iec104ClientProtocol;
impl Iec104ClientProtocol {
    pub fn new() -> Self {
        Self
    }
}
pub fn requests() -> Vec<ActionDefinition> {
    let f = || {
        vec![
            parameter("common_address", "number", "Common address 0..65535", true),
            parameter(
                "ioa",
                "number",
                "Information object address 0..16777215",
                true,
            ),
        ]
    };
    let mut cmd = f();
    cmd.push(parameter("value", "boolean", "Single command state", true));
    vec![
        action(
            "iec104_interrogate",
            "General interrogation",
            vec![parameter(
                "common_address",
                "number",
                "Station common address, 0..65535",
                true,
            )],
            json!({"type":"iec104_interrogate","common_address":1}),
        ),
        action(
            "iec104_read",
            "Read one information object",
            f(),
            json!({"type":"iec104_read","common_address":1,"ioa":1}),
        ),
        action(
            "iec104_command",
            "Direct single command",
            cmd,
            json!({"type":"iec104_command","common_address":1,"ioa":1,"value":true}),
        ),
        action(
            "disconnect",
            "Close the IEC 104 station connection",
            vec![],
            json!({"type":"disconnect"}),
        ),
    ]
}
pub static EVENTS: LazyLock<Vec<EventType>> = LazyLock::new(|| {
    vec![
        EventType::new(
            "iec104_connected",
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
            "iec104_response",
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
impl Protocol for Iec104ClientProtocol {
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
        "Connect to a IEC 60870-5-104 device on localhost"
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
        ProtocolMetadataV2::builder().state(DevelopmentState::Experimental).privilege_requirement(PrivilegeRequirement::None).implementation("APCI START/STOP/TEST, sequence windows, t1/t3 timers; selected GI, read, single command, binary and float ASDUs").llm_control("Handler supplies device values, operation approvals and refusals; client handler selects structured operations").e2e_testing("Independent peer integration plus negative and lifecycle tests in tests/client/iec104").notes("Selected ASDUs 1,13,45,100,102. Direct commands only; select rejected. Polled handler telemetry; client also accepts spontaneous binary/float telemetry. k=12, immediate acknowledgments (within w=8/t2), t1=15s,t3=20s; 10s command deadline. No timestamped ASDUs, file transfer, clock sync or redundancy.").max_inbound_bytes(crate::server::iec104::codec::MAX_FRAME).history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
        .batching(crate::protocol::metadata::BatchingMode::Unsupported)
        .build()
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let base = json!({"type":"open_client","protocol":"iec104","remote_addr":"127.0.0.1:2404","instruction":"Supply device decisions with structured actions"});
        let a = requests()[0].example.clone();
        let mut fixed = base.clone();
        fixed["event_handlers"] = json!([{"event_pattern":"iec104_connected","handler":{"type":"static","actions":[a.clone()]}}]);
        let code = format!("print({})", json!(json!({"actions":[a]}).to_string()));
        let mut script = base.clone();
        script["event_handlers"] = json!([{"event_pattern":"iec104_connected","handler":{"type":"script","language":"python","code":code}}]);
        crate::llm::actions::StartupExamples::new(base, script, fixed)
    }
}
impl Client for Iec104ClientProtocol {
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
        crate::server::iec104::codec::validate(&v)?;
        Ok(ClientActionResult::Custom {
            name: v["type"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("action type"))?
                .into(),
            data: v,
        })
    }
}
