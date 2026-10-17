use crate::llm::actions::client_trait::{Client, ClientActionResult};
use crate::llm::actions::{protocol_trait::Protocol, ActionDefinition};
use crate::protocol::{ConnectContext, EventType};
use crate::server::ics_support::{action, parameter};
use crate::state::AppState;
use anyhow::Result;
use serde_json::{json, Value};
use std::{future::Future, net::SocketAddr, pin::Pin, sync::LazyLock};
#[derive(Default)]
pub struct BacnetClientProtocol;
impl BacnetClientProtocol {
    pub fn new() -> Self {
        Self
    }
}
pub fn requests() -> Vec<ActionDefinition> {
    let f = || {
        vec![
            parameter("object_type", "number", "Object type 0..1023", true),
            parameter("instance", "number", "Object instance 0..4194303", true),
            parameter("property", "number", "Property identifier", true),
            parameter("array_index", "number", "Optional array index", false),
        ]
    };
    let mut w = f();
    w.extend([
        parameter("value_type", "string", "Application value type", true),
        parameter("value", "any", "Typed property value", true),
        parameter("priority", "number", "Write priority 1..16", false),
    ]);
    vec![
        action(
            "bacnet_discover",
            "Unicast WhoIs/IAm discovery",
            vec![],
            json!({"type":"bacnet_discover"}),
        ),
        action(
            "bacnet_read",
            "Read a typed BACnet object property",
            f(),
            json!({"type":"bacnet_read","object_type":2,"instance":1,"property":85}),
        ),
        action(
            "bacnet_write",
            "Write a typed BACnet object property",
            w,
            json!({"type":"bacnet_write","object_type":2,"instance":1,"property":85,"value_type":"real","value":12.5}),
        ),
        action(
            "disconnect",
            "Close UDP client",
            vec![],
            json!({"type":"disconnect"}),
        ),
    ]
}
pub static EVENTS: LazyLock<Vec<EventType>> = LazyLock::new(|| {
    vec![
        EventType::new(
            "bacnet_connected",
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
            "bacnet_response",
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
impl Protocol for BacnetClientProtocol {
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
        "Connect to a BACnet/IP device on localhost"
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
        ProtocolMetadataV2::builder().state(DevelopmentState::Experimental).privilege_requirement(PrivilegeRequirement::None).implementation("BVLC/NPDU/APDU with unsegmented WhoIs/IAm and ReadProperty/WriteProperty, explicit Error/Reject/Abort responses").llm_control("Handler supplies device values, operation approvals and refusals; client handler selects structured operations").e2e_testing("Independent peer integration plus negative and lifecycle tests in tests/client/bacnet").notes("Local IPv4 and unicast client discovery. Broadcast WhoIs accepted. No BBMD, routing, segmentation, ReadPropertyMultiple or COV. Segmented requests abort; unsupported services reject. Typed primitives only; no stored object data. 480-byte datagrams; 256 concurrent handler turns; 10s response timeout.").max_inbound_bytes(crate::server::bacnet::codec::MAX_FRAME).history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
        .batching(crate::protocol::metadata::BatchingMode::Unsupported)
        .build()
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let base = json!({"type":"open_client","protocol":"bacnet","remote_addr":"127.0.0.1:47808","instruction":"Supply device decisions with structured actions"});
        let a = requests()[0].example.clone();
        let mut fixed = base.clone();
        fixed["event_handlers"] = json!([{"event_pattern":"bacnet_connected","handler":{"type":"static","actions":[a.clone()]}}]);
        let code = format!("print({})", json!(json!({"actions":[a]}).to_string()));
        let mut script = base.clone();
        script["event_handlers"] = json!([{"event_pattern":"bacnet_connected","handler":{"type":"script","language":"python","code":code}}]);
        crate::llm::actions::StartupExamples::new(base, script, fixed)
    }
}
impl Client for BacnetClientProtocol {
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
        crate::server::bacnet::codec::validate(&v)?;
        Ok(ClientActionResult::Custom {
            name: v["type"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("action type"))?
                .into(),
            data: v,
        })
    }
}
