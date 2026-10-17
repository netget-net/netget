use crate::llm::actions::protocol_trait::{ActionResult, Server};
use crate::llm::actions::{protocol_trait::Protocol, ActionDefinition};
use crate::protocol::{EventType, SpawnContext};
use crate::server::ics_support::{action, parameter};
use crate::state::AppState;
use anyhow::{ensure, Result};
use serde_json::{json, Value};
use std::{future::Future, net::SocketAddr, pin::Pin, sync::LazyLock};
#[derive(Default)]
pub struct BacnetProtocol;
impl BacnetProtocol {
    pub fn new() -> Self {
        Self
    }
}
pub fn replies() -> Vec<ActionDefinition> {
    vec![action(
        "bacnet_reply",
        "Typed read value, explicit write approval or BACnet error",
        vec![
            parameter(
                "value_type",
                "string",
                "null,boolean,unsigned,signed,real,string,enumerated,object_identifier",
                false,
            ),
            parameter("value", "any", "Typed property value", false),
            parameter(
                "accepted",
                "boolean",
                "Explicit approval of the property write",
                false,
            ),
            parameter("error_class", "number", "BACnet error class 0..7", false),
            parameter("error_code", "number", "BACnet error code", false),
        ],
        json!({"type":"bacnet_reply","value_type":"real","value":12.5}),
    )]
}
pub static EVENTS: LazyLock<Vec<EventType>> = LazyLock::new(|| {
    vec![EventType::new(
        "bacnet_request",
        "BACnet/IP discovery and typed property reads/writes",
        replies()[0].example.clone(),
    )
    .with_parameters(vec![
        parameter(
            "operation",
            "string",
            "Device data read or write operation",
            true,
        ),
        parameter(
            "object_type",
            "number",
            "BACnet object type number, 0..1023",
            true,
        ),
        parameter("instance", "number", "Object instance", true),
        parameter(
            "property",
            "number",
            "BACnet property identifier number",
            true,
        ),
        parameter(
            "invoke_id",
            "number",
            "BACnet transaction invoke identifier",
            true,
        ),
        parameter("service", "number", "Confirmed service", true),
        parameter(
            "array_index",
            "number",
            "Optional property array element index",
            false,
        ),
        parameter(
            "priority",
            "number",
            "BACnet write priority number, 1..16",
            false,
        ),
        parameter(
            "value_type",
            "string",
            "Type of the decoded write request value",
            false,
        ),
        parameter(
            "value",
            "any",
            "Decoded typed value of the write request",
            false,
        ),
    ])
    .with_actions(replies())]
});
impl Protocol for BacnetProtocol {
    fn protocol_name(&self) -> &'static str {
        "BACnet/IP"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>UDP>BACnet"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["bacnet"]
    }
    fn description(&self) -> &'static str {
        "BACnet/IP discovery and typed property reads/writes"
    }
    fn example_prompt(&self) -> &'static str {
        "Simulate a BACnet/IP device on localhost"
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
    fn get_startup_parameters(&self) -> Vec<crate::llm::actions::ParameterDefinition> {
        vec![crate::llm::actions::ParameterDefinition {
            name: "device_id".into(),
            type_hint: "number".into(),
            description: "BACnet Device instance 0..4194303".into(),
            required: false,
            example: json!(1234),
            default: Some(json!(super::codec::DEFAULT_DEVICE_ID)),
        }]
    }
    fn metadata(&self) -> crate::protocol::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder().state(DevelopmentState::Experimental).privilege_requirement(PrivilegeRequirement::None).implementation("BVLC/NPDU/APDU with unsegmented WhoIs/IAm and ReadProperty/WriteProperty, explicit Error/Reject/Abort responses").llm_control("Handler supplies device values, operation approvals and refusals; client handler selects structured operations").e2e_testing("Independent peer integration plus negative and lifecycle tests in tests/server/bacnet").notes("Local IPv4 and unicast client discovery. Broadcast WhoIs accepted. No BBMD, routing, segmentation, ReadPropertyMultiple or COV. Segmented requests abort; unsupported services reject. Typed primitives only; no stored object data. 480-byte datagrams; 256 concurrent handler turns; 10s response timeout.").max_inbound_bytes(crate::server::bacnet::codec::MAX_FRAME).well_known_udp_port(47808).answers_on_failure().connectionless().history(crate::protocol::metadata::HistoryMode::Off)
        .batching(crate::protocol::metadata::BatchingMode::Unsupported)
        .build()
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let base = json!({"type":"open_server","base_stack":"bacnet","port":47808,"instruction":"Supply device decisions with structured actions"});
        let a = replies()[0].example.clone();
        let mut fixed = base.clone();
        fixed["event_handlers"] = json!([{"event_pattern":"bacnet_request","handler":{"type":"static","actions":[a.clone()]}}]);
        let code = format!("print({})", json!(json!({"actions":[a]}).to_string()));
        let mut script = base.clone();
        script["event_handlers"] = json!([{"event_pattern":"bacnet_request","handler":{"type":"script","language":"python","code":code}}]);
        crate::llm::actions::StartupExamples::new(base, script, fixed)
    }
}
impl Server for BacnetProtocol {
    fn spawn(&self, ctx: SpawnContext) -> Pin<Box<dyn Future<Output = Result<SocketAddr>> + Send>> {
        Box::pin(super::spawn(ctx))
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
