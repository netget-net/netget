use crate::llm::actions::client_trait::{Client, ClientActionResult};
use crate::llm::actions::{protocol_trait::Protocol, ActionDefinition};
use crate::protocol::{ConnectContext, EventType};
use crate::server::ics_support::{action, parameter};
use crate::state::AppState;
use anyhow::Result;
use serde_json::{json, Value};
use std::{future::Future, net::SocketAddr, pin::Pin, sync::LazyLock};
#[derive(Default)]
pub struct EthernetIpClientProtocol;
impl EthernetIpClientProtocol {
    pub fn new() -> Self {
        Self
    }
}
pub fn requests() -> Vec<ActionDefinition> {
    let fields = || {
        vec![
            parameter("class", "number", "CIP object class, 0..65535", true),
            parameter("instance", "number", "Object instance, 0..65535", true),
            parameter("attribute", "number", "Attribute number, 0..65535", true),
            parameter(
                "value_type",
                "string",
                "uint8, uint16, uint32, int32, real or string",
                true,
            ),
        ]
    };
    let mut set = fields();
    set.push(parameter("value", "any", "Typed attribute value", true));
    vec![
        action(
            "ethernet_ip_discover",
            "ListIdentity on this adapter",
            vec![],
            json!({"type":"ethernet_ip_discover"}),
        ),
        action(
            "ethernet_ip_get",
            "GetAttributeSingle",
            fields(),
            json!({"type":"ethernet_ip_get","class":1,"instance":1,"attribute":1,"value_type":"uint16"}),
        ),
        action(
            "ethernet_ip_set",
            "SetAttributeSingle",
            set,
            json!({"type":"ethernet_ip_set","class":1,"instance":1,"attribute":1,"value_type":"uint16","value":42}),
        ),
        action(
            "disconnect",
            "Close the adapter connection",
            vec![],
            json!({"type":"disconnect"}),
        ),
    ]
}
pub static EVENTS: LazyLock<Vec<EventType>> = LazyLock::new(|| {
    vec![
        EventType::new(
            "ethernet_ip_connected",
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
            "ethernet_ip_response",
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
            parameter("value", "any", "Decoded response fields", false),
        ])
        .with_actions(requests()),
    ]
});
impl Protocol for EthernetIpClientProtocol {
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
        "Connect to a EtherNet/IP device on localhost"
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
        ProtocolMetadataV2::builder().state(DevelopmentState::Experimental).privilege_requirement(PrivilegeRequirement::None).implementation("Bounded EtherNet/IP encapsulation, session correlation, CPF and Get/SetAttributeSingle with logical class/instance/attribute paths").llm_control("Handler supplies device values, operation approvals and refusals; client handler selects structured operations").e2e_testing("Independent peer integration plus negative and lifecycle tests in tests/client/ethernet_ip").notes("Explicit unconnected object attributes only. TCP and unicast UDP ListIdentity. Identity is a NetGet simulator (vendor 0). No ForwardOpen, routing, symbolic tags or cyclic I/O. Set types use declared schema. No attribute storage. 4096-byte frames; shared 30/600/10 s deadlines and 256 connections.").max_inbound_bytes(crate::server::ethernet_ip::codec::MAX_FRAME).history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
        .batching(crate::protocol::metadata::BatchingMode::Unsupported)
        .build()
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let base = json!({"type":"open_client","protocol":"ethernet_ip","remote_addr":"127.0.0.1:44818","instruction":"Supply device decisions with structured actions"});
        let a = requests()[0].example.clone();
        let mut fixed = base.clone();
        fixed["event_handlers"] = json!([{"event_pattern":"ethernet_ip_connected","handler":{"type":"static","actions":[a.clone()]}}]);
        let code = format!("print({})", json!(json!({"actions":[a]}).to_string()));
        let mut script = base.clone();
        script["event_handlers"] = json!([{"event_pattern":"ethernet_ip_connected","handler":{"type":"script","language":"python","code":code}}]);
        crate::llm::actions::StartupExamples::new(base, script, fixed)
    }
}
impl Client for EthernetIpClientProtocol {
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
        crate::server::ethernet_ip::codec::validate(&v)?;
        Ok(ClientActionResult::Custom {
            name: v["type"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("action type"))?
                .into(),
            data: v,
        })
    }
}
