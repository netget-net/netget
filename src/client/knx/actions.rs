use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, ParameterDefinition, StartupExamples,
};
use crate::protocol::{ConnectContext, EventType};
use crate::server::knx::{
    actions::{action, parameter, write_action},
    wire,
};
use crate::state::app_state::AppState;
use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

#[derive(Default)]
pub struct KnxClientProtocol;
impl KnxClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

fn read_action() -> ActionDefinition {
    action(
        "knx_group_read",
        "Ask the bus for a group address's value; a device's answer arrives as knx_telegram with kind response.",
        vec![parameter("group_address", "string", "Group address main/middle/sub, e.g. 1/2/4", true)],
        json!({"type":"knx_group_read","group_address":"1/2/4"}),
        "-> KNX read {group_address}",
    )
}

fn disconnect_action() -> ActionDefinition {
    action(
        "disconnect",
        "Close the tunnelling connection (DISCONNECT_REQUEST).",
        vec![],
        json!({"type":"disconnect"}),
        "-> KNX disconnect",
    )
}

pub fn actions() -> Vec<ActionDefinition> {
    vec![write_action(), read_action(), disconnect_action()]
}

pub static CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "knx_connected",
        "The tunnel is open; telegrams on the bus now arrive as knx_telegram.",
        read_action().example.clone(),
    )
    .with_parameters(vec![
        parameter(
            "remote_addr",
            "string",
            "The KNXnet/IP gateway's address",
            true,
        ),
        parameter(
            "individual_address",
            "string",
            "The individual address the gateway gave this tunnel",
            true,
        ),
    ])
    .with_actions(actions())
});

pub static TELEGRAM_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "knx_telegram",
        "A group telegram on the bus: a write, a read, or a response to a read.",
        read_action().example.clone(),
    )
    .with_parameters(vec![
        parameter("kind", "string", "write, read or response", true),
        parameter("source", "string", "Individual address of the sender", true),
        parameter(
            "destination",
            "string",
            "Group address, main/middle/sub",
            true,
        ),
        parameter(
            "dpt",
            "string",
            "The DPT configured for this address, if any",
            false,
        ),
        parameter(
            "value",
            "any",
            "The value decoded by that DPT, when one is configured",
            false,
        ),
        parameter(
            "interpretations",
            "object",
            "Every reading the value's size allows, keyed by DPT",
            true,
        ),
    ])
    .with_actions(actions())
});

impl Protocol for KnxClientProtocol {
    fn protocol_name(&self) -> &'static str {
        "KNX/IP"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>UDP>KNXnet/IP"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["knx", "knxnet/ip", "knx/ip", "knx tunnelling"]
    }
    fn description(&self) -> &'static str {
        "KNXnet/IP tunnelling client: writes and reads group addresses and hears the bus"
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        actions()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![CONNECTED_EVENT.clone(), TELEGRAM_EVENT.clone()]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![ParameterDefinition {
            name: "group_types".into(),
            type_hint: "object".into(),
            description: "DPT per group address, e.g. {\"1/2/3\": \"1\"}: values on those addresses are decoded and encoded by it".into(),
            required: false,
            example: json!({"1/2/3": "1", "1/2/4": "9.001"}),
            default: None,
        }]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation("The server's KNXnet/IP and cEMI codec over Tokio UDP: connect (tunnel, link layer, NAT mode), heartbeats, tunnelling requests with acks and sequence numbers, L_Data.req out and L_Data.ind/con in")
            .llm_control("Which group addresses to write and read, and what to do with every telegram on the bus")
            .e2e_testing("tests/client/knx: NetGet's own gateway; knxd as the gateway, observed with knxtool and answered by xknx on the same bus")
            .notes("Tunnelling v1 over UDP only. A request is retransmitted once if its ack does not come within a second, and the tunnel closes if the second goes unanswered too. Heartbeat every 60 s. A handler chain stops after 8 follow-ups.")
            .max_inbound_bytes(wire::MAX_FRAME)
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Connect to the KNX/IP gateway at 192.168.1.10 and switch on the light at 1/2/3"
    }
    fn get_startup_examples(&self) -> StartupExamples {
        let llm = json!({"type":"open_client","protocol":"knx","remote_addr":"127.0.0.1:3671","startup_params":{"group_types":{"1/2/3":"1"}},"instruction":"Switch the light at 1/2/3 on"});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([{"event_pattern":"knx_connected","handler":{"type":"static","actions":[{"type":"knx_group_write","group_address":"1/2/3","value":true,"dpt":"1"}]}}]);
        let mut scripted = llm.clone();
        scripted["event_handlers"] = json!([{"event_pattern":"knx_telegram","handler":{"type":"script","language":"python","code":"import json,sys\ne=json.load(sys.stdin)['event']\nprint(json.dumps({'actions':[]}))"}}]);
        StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Industrial"
    }
}

impl Client for KnxClientProtocol {
    fn connect(
        &self,
        ctx: ConnectContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::connect(ctx))
    }
    fn execute_action(&self, v: Value) -> Result<ClientActionResult> {
        let name = v["type"].as_str().unwrap_or_default().to_string();
        match name.as_str() {
            "disconnect" => return Ok(ClientActionResult::Disconnect),
            "knx_group_read" => {
                wire::parse_group(
                    v["group_address"]
                        .as_str()
                        .context("group_address required")?,
                )?;
            }
            "knx_group_write" => {
                wire::parse_group(
                    v["group_address"]
                        .as_str()
                        .context("group_address required")?,
                )?;
                if let Some(dpt) = v["dpt"].as_str() {
                    wire::encode(dpt, &v["value"])?;
                }
            }
            _ => bail!("Unknown KNX/IP client action"),
        }
        Ok(ClientActionResult::Custom { name, data: v })
    }
}
