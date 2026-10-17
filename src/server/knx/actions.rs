use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter, ParameterDefinition, StartupExamples,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::{EventType, SpawnContext};
use crate::state::app_state::AppState;
use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

use super::wire;

#[derive(Default)]
pub struct KnxProtocol;
impl KnxProtocol {
    pub fn new() -> Self {
        Self
    }
}

pub fn parameter(name: &str, kind: &str, description: &str, required: bool) -> Parameter {
    Parameter {
        name: name.into(),
        type_hint: kind.into(),
        description: description.into(),
        required,
    }
}

pub fn action(
    name: &str,
    description: &str,
    parameters: Vec<Parameter>,
    example: Value,
    log: &str,
) -> ActionDefinition {
    ActionDefinition {
        name: name.into(),
        description: description.into(),
        parameters,
        example,
        log_template: Some(LogTemplate::new().with_info(log)),
    }
}

fn value_params() -> Vec<Parameter> {
    vec![
        parameter("value", "any", "The value: true/false, a number or text, as its DPT takes", true),
        parameter("dpt", "string", &format!("Datapoint type, e.g. 9.001; may be omitted when group_types configures the address. Supported: {}", wire::DPT_NOTE), false),
    ]
}

fn response_action() -> ActionDefinition {
    action(
        "knx_group_response",
        "Answer the group read with the address's current value (sent on the bus from this gateway's address).",
        value_params(),
        json!({"type":"knx_group_response","value":21.5,"dpt":"9.001"}),
        "-> KNX response {value}",
    )
}

pub fn write_action() -> ActionDefinition {
    let mut params = vec![parameter(
        "group_address",
        "string",
        "Group address main/middle/sub, e.g. 1/2/3",
        true,
    )];
    params.extend(value_params());
    action(
        "knx_group_write",
        "Put a GroupValueWrite on the bus to every tunnel (e.g. an actuator's status feedback).",
        params,
        json!({"type":"knx_group_write","group_address":"1/2/10","value":true,"dpt":"1"}),
        "-> KNX write {group_address} = {value}",
    )
}

fn ignore_action() -> ActionDefinition {
    action(
        "knx_ignore",
        "No device reacts to this telegram; nothing further goes on the bus.",
        vec![],
        json!({"type":"knx_ignore"}),
        "-> KNX ignore",
    )
}

fn telegram_params() -> Vec<Parameter> {
    vec![
        parameter(
            "source",
            "string",
            "Individual address of the sender (the tunnel's)",
            true,
        ),
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
            "Every reading the value's size allows, keyed by DPT, when none is configured",
            true,
        ),
    ]
}

pub static TELEGRAM_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    let mut params = vec![parameter(
        "kind",
        "string",
        "write, or response (a device answering a read)",
        true,
    )];
    params.extend(telegram_params());
    EventType::new(
        "knx_group_telegram",
        "A tunnel put a group value on the bus (GroupValueWrite or GroupValueResponse). Other tunnels already received it.",
        ignore_action().example.clone(),
    )
    .with_parameters(params)
    .with_actions(vec![ignore_action(), write_action()])
});

pub static READ_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "knx_group_read",
        "A tunnel asked for a group address's value (GroupValueRead). Answer with knx_group_response, or stay silent if no device holds it.",
        response_action().example.clone(),
    )
    .with_parameters(vec![
        parameter("source", "string", "Individual address of the reader", true),
        parameter("destination", "string", "Group address read, main/middle/sub", true),
        parameter("dpt", "string", "The DPT configured for this address, if any", false),
    ])
    .with_actions(vec![response_action(), ignore_action(), write_action()])
});

/// Check a value action; returns the destination (when the action names one) and the data.
pub fn value_of(action: &Value, configured: Option<&str>) -> Result<wire::Data> {
    let dpt = action["dpt"]
        .as_str()
        .or(configured)
        .context("dpt required: the address has no configured type")?;
    wire::encode(dpt, &action["value"])
}

impl Protocol for KnxProtocol {
    fn protocol_name(&self) -> &'static str {
        "KNX/IP"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>UDP>KNXnet/IP"
    }
    fn description(&self) -> &'static str {
        "KNXnet/IP tunnelling gateway: tunnels connect, group writes are routed between them, and the handler plays every device on the bus"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "knx",
            "knxnet/ip",
            "knx/ip",
            "eib",
            "building automation",
            "knx tunnelling",
        ]
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![response_action(), write_action(), ignore_action()]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![TELEGRAM_EVENT.clone(), READ_EVENT.clone()]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "group_types".into(),
                type_hint: "object".into(),
                description: "DPT per group address, e.g. {\"1/2/3\": \"1\", \"1/2/4\": \"9.001\"}: values on those addresses are decoded and encoded by it".into(),
                required: false,
                example: json!({"1/2/3": "1", "1/2/4": "9.001"}),
                default: None,
            },
            ParameterDefinition {
                name: "individual_address".into(),
                type_hint: "string".into(),
                description: "This gateway's own individual address, the source of the telegrams it puts on the bus".into(),
                required: false,
                example: json!("1.1.250"),
                default: Some(json!(super::DEFAULT_ADDRESS)),
            },
            ParameterDefinition {
                name: "max_tunnels".into(),
                type_hint: "number".into(),
                description: "How many tunnelling connections at once (1..=64)".into(),
                required: false,
                example: json!(8),
                default: Some(json!(super::DEFAULT_MAX_TUNNELS)),
            },
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .well_known_udp_port(3671)
            .implementation("Hand-written KNXnet/IP over Tokio UDP: search, description, connect (tunnel, link layer), connection state, disconnect, tunnelling requests and acks with sequence checking; cEMI L_Data.req/con/ind; group telegrams routed between tunnels; values decoded by DPT")
            .llm_control("Every group read's answer and any telegram a device sends in reaction; the handler is every device on the bus")
            .e2e_testing("tests/server/knx: raw frames and bounds; xknx (Python) and knxd (C++, connecting as a tunnel client with -b ipt:, driven by knxtool) as independent clients")
            .notes("Tunnelling only: no routing (multicast), no device management, no secure tunnelling, no tunnelling v2 over TCP. Telegrams NetGet sends are not retransmitted. Frames are capped at 512 bytes; a tunnel silent for 120 s is dropped, as the specification's heartbeat requires. A handler failure on a read sends nothing — an invented value would be a device that does not exist.")
            .deliberately_silent()
            .max_inbound_bytes(wire::MAX_FRAME)
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "KNX/IP gateway where 1/2/3 is a light switch and 1/2/4 a temperature of 21.5 °C"
    }
    fn get_startup_examples(&self) -> StartupExamples {
        let llm = json!({"type":"open_server","base_stack":"knx","port":3671,"startup_params":{"group_types":{"1/2/3":"1","1/2/4":"9.001"}},"instruction":"1/2/3 is a light; 1/2/4 reads 21.5 °C"});
        let mut scripted = llm.clone();
        scripted["event_handlers"] = json!([{"event_pattern":"knx_group_read","handler":{"type":"script","language":"python","code":"import json,sys\ne=json.load(sys.stdin)['event']\na={'type':'knx_group_response','value':21.5} if e['destination']=='1/2/4' else {'type':'knx_ignore'}\nprint(json.dumps({'actions':[a]}))"}}]);
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([{"event_pattern":"knx_group_read","handler":{"type":"static","actions":[{"type":"knx_group_response","value":21.5,"dpt":"9.001"}]}}]);
        StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Industrial"
    }
}

impl Server for KnxProtocol {
    fn spawn(
        &self,
        ctx: SpawnContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::spawn(ctx))
    }
    fn execute_action(&self, v: Value) -> Result<ActionResult> {
        let name = v["type"].as_str().unwrap_or_default().to_string();
        match name.as_str() {
            "knx_ignore" => {}
            "knx_group_response" => {
                if let Some(dpt) = v["dpt"].as_str() {
                    wire::encode(dpt, &v["value"])?;
                }
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
            _ => bail!("Unknown KNX/IP server action"),
        }
        Ok(ActionResult::Custom { name, data: v })
    }
}
