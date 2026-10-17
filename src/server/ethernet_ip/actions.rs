use crate::llm::actions::protocol_trait::{ActionResult, Server};
use crate::llm::actions::{protocol_trait::Protocol, ActionDefinition};
use crate::protocol::{EventType, SpawnContext};
use crate::server::ics_support::{action, parameter};
use crate::state::AppState;
use anyhow::{ensure, Result};
use serde_json::{json, Value};
use std::{future::Future, net::SocketAddr, pin::Pin, sync::LazyLock};
#[derive(Default)]
pub struct EthernetIpProtocol;
impl EthernetIpProtocol {
    pub fn new() -> Self {
        Self
    }
}
pub fn replies() -> Vec<ActionDefinition> {
    vec![action(
        "ethernet_ip_reply",
        "Get: value_type plus value. Set: accepted=true. Error: status=1..255",
        vec![
            parameter(
                "value_type",
                "string",
                "uint8, uint16, uint32, int32, real or string",
                false,
            ),
            parameter("value", "any", "The typed attribute value", false),
            parameter("accepted", "boolean", "Explicit write approval", false),
            parameter("status", "number", "CIP error status 1..255", false),
        ],
        json!({"type":"ethernet_ip_reply","value_type":"uint16","value":42}),
    )]
}
pub static EVENTS: LazyLock<Vec<EventType>> = LazyLock::new(|| {
    vec![EventType::new(
        "ethernet_ip_request",
        "Adapter/scanner discovery and explicit CIP attribute messaging",
        replies()[0].example.clone(),
    )
    .with_parameters(vec![
        parameter(
            "operation",
            "string",
            "Attribute get or set operation",
            true,
        ),
        parameter(
            "class",
            "number",
            "CIP object class identifier, 0..65535",
            true,
        ),
        parameter("instance", "number", "Object instance", true),
        parameter("attribute", "number", "Attribute number", true),
        parameter("value_type", "string", "Decoded set type", false),
        parameter("value", "any", "Decoded set value", false),
    ])
    .with_actions(replies())]
});
impl Protocol for EthernetIpProtocol {
    fn protocol_name(&self) -> &'static str {
        "EtherNet/IP"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>EtherNet/IP>CIP"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["ethernet_ip"]
    }
    fn description(&self) -> &'static str {
        "Adapter/scanner discovery and explicit CIP attribute messaging"
    }
    fn example_prompt(&self) -> &'static str {
        "Simulate a EtherNet/IP device on localhost"
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
        vec![crate::llm::actions::ParameterDefinition{name:"attribute_types".into(),type_hint:"array".into(),description:"Extra writable attribute schemas [{class,instance,attribute,value_type}]; Identity 1/1 attributes 1..8 have standard types. These define types, never stored values.".into(),required:false,example:json!([{"class":100,"instance":1,"attribute":1,"value_type":"uint16"}]),default:None}]
    }
    fn metadata(&self) -> crate::protocol::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder().state(DevelopmentState::Experimental).privilege_requirement(PrivilegeRequirement::None).implementation("Bounded EtherNet/IP encapsulation, session correlation, CPF and Get/SetAttributeSingle with logical class/instance/attribute paths").llm_control("Handler supplies device values, operation approvals and refusals; client handler selects structured operations").e2e_testing("Independent peer integration plus negative and lifecycle tests in tests/server/ethernet_ip").notes("Explicit unconnected object attributes only. TCP and unicast UDP ListIdentity. Identity is a NetGet simulator (vendor 0). No ForwardOpen, routing, symbolic tags or cyclic I/O. Set types use declared schema. No attribute storage. 4096-byte frames; shared 30/600/10 s deadlines and 256 connections.").max_inbound_bytes(crate::server::ethernet_ip::codec::MAX_FRAME).well_known_port(44818).answers_on_failure().history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
        .batching(crate::protocol::metadata::BatchingMode::Unsupported)
        .build()
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let base = json!({"type":"open_server","base_stack":"ethernet_ip","port":44818,"instruction":"Supply device decisions with structured actions"});
        let a = replies()[0].example.clone();
        let mut fixed = base.clone();
        fixed["event_handlers"] = json!([{"event_pattern":"ethernet_ip_request","handler":{"type":"static","actions":[a.clone()]}}]);
        let code = format!("print({})", json!(json!({"actions":[a]}).to_string()));
        let mut script = base.clone();
        script["event_handlers"] = json!([{"event_pattern":"ethernet_ip_request","handler":{"type":"script","language":"python","code":code}}]);
        crate::llm::actions::StartupExamples::new(base, script, fixed)
    }
}
impl Server for EthernetIpProtocol {
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
