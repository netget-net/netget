use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter, ParameterDefinition,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::{EventType, SpawnContext};
use crate::state::app_state::AppState;
use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

#[derive(Default)]
pub struct Lwm2mProtocol;
impl Lwm2mProtocol {
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
) -> ActionDefinition {
    ActionDefinition {
        name: name.into(),
        description: description.into(),
        parameters,
        example,
        log_template: Some(LogTemplate::new().with_info(format!("LwM2M {name}"))),
    }
}

fn path(description: &str) -> Parameter {
    parameter("path", "string", description, true)
}

pub const VALUES_HELP: &str = "[{path, value}] with value a string, number or boolean; {path, opaque: hex} or {path, object_link: \"3:0\"} for those types";

/// The device management operations a server performs on a registered client.
pub fn operations() -> Vec<ActionDefinition> {
    vec![
        action("lwm2m_read", "Read an object, instance or resource from the device; the values arrive as lwm2m_response", vec![path("LwM2M path, e.g. /3/0 or /3/0/0"), parameter("format", "string", "senml (default, SenML JSON) or text (one resource)", false)], json!({"type": "lwm2m_read", "path": "/3/0/0"})),
        action(
            "lwm2m_write",
            "Write to the device: one resource with value (plain text), or several with values (SenML JSON; mode replace or update)",
            vec![path("LwM2M path, e.g. /3/0/14 or /1/0"), parameter("value", "any", "The value for a single resource", false), parameter("values", "array", VALUES_HELP, false), parameter("mode", "string", "replace (PUT, default) or update (POST) for values", false)],
            json!({"type": "lwm2m_write", "path": "/3/0/14", "value": "+02"}),
        ),
        action("lwm2m_execute", "Execute a resource on the device, e.g. /3/0/4 Reboot", vec![path("LwM2M resource path"), parameter("arguments", "string", "Execute arguments, e.g. 0='a',1", false)], json!({"type": "lwm2m_execute", "path": "/3/0/4"})),
        action("lwm2m_discover", "Ask the device which instances and resources a path has", vec![path("LwM2M object or instance path")], json!({"type": "lwm2m_discover", "path": "/3"})),
        action("lwm2m_observe", "Observe a path: its changes arrive as lwm2m_notification", vec![path("LwM2M path, e.g. /3303/0/5700")], json!({"type": "lwm2m_observe", "path": "/3303/0/5700"})),
        action("lwm2m_cancel_observe", "Stop observing a path", vec![path("The observed path")], json!({"type": "lwm2m_cancel_observe", "path": "/3303/0/5700"})),
        action("lwm2m_create", "Create an object instance on the device", vec![path("The object, e.g. /1"), parameter("values", "array", VALUES_HELP, true)], json!({"type": "lwm2m_create", "path": "/3303", "values": [{"path": "/3303/1/5700", "value": 20.0}]})),
        action("lwm2m_delete", "Delete an object instance on the device", vec![path("The instance, e.g. /3303/1")], json!({"type": "lwm2m_delete", "path": "/3303/1"})),
    ]
}

fn accept() -> ActionDefinition {
    action("lwm2m_accept", "Accept the registration (2.01 Created); operations in the same answer run once it is registered", vec![], json!({"type": "lwm2m_accept"}))
}
fn reject() -> ActionDefinition {
    action(
        "lwm2m_reject",
        "Refuse the registration",
        vec![parameter(
            "reason",
            "string",
            "forbidden (4.03, default) or bad_request (4.00)",
            false,
        )],
        json!({"type": "lwm2m_reject", "reason": "forbidden"}),
    )
}

fn endpoint_param() -> Parameter {
    parameter("endpoint", "string", "The device's endpoint name", true)
}

pub static REGISTER_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    let mut actions = vec![accept(), reject()];
    actions.extend(operations());
    EventType::new(
        "lwm2m_register",
        "A device registered; accept (and optionally start reading or observing) or refuse it",
        accept().example.clone(),
    )
    .with_parameters(vec![
        endpoint_param(),
        parameter("address", "string", "The device's UDP address", true),
        parameter(
            "lifetime",
            "number",
            "Registration lifetime in seconds",
            true,
        ),
        parameter("version", "string", "LwM2M version the device speaks", true),
        parameter("binding", "string", "Binding mode, e.g. U", true),
        parameter(
            "objects",
            "array",
            "The object instances it declared: [{path, attributes}]",
            true,
        ),
    ])
    .with_actions(actions)
});
fn event_with_ops(id: &str, description: &str, params: Vec<Parameter>) -> EventType {
    let mut p = vec![endpoint_param()];
    p.extend(params);
    EventType::new(
        id,
        description,
        json!({"type": "lwm2m_read", "path": "/3/0"}),
    )
    .with_parameters(p)
    .with_actions(operations())
}
pub static UPDATE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event_with_ops(
        "lwm2m_update",
        "A registered device refreshed its registration",
        vec![
            parameter("lifetime", "number", "The registration lifetime", true),
            parameter(
                "objects",
                "array",
                "A new object list, when it sent one",
                false,
            ),
        ],
    )
});
pub static RESPONSE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event_with_ops(
        "lwm2m_response",
        "The device answered an operation",
        vec![
            parameter(
                "operation",
                "string",
                "read, write, execute, discover, observe, cancel_observe, create or delete",
                true,
            ),
            parameter("path", "string", "The path operated on", true),
            parameter(
                "code",
                "string",
                "The CoAP response code, e.g. 2.05 or 4.04",
                true,
            ),
            parameter(
                "values",
                "array",
                "For read and observe: [{path, value}]",
                false,
            ),
            parameter(
                "links",
                "array",
                "For discover: [{path, attributes}]",
                false,
            ),
            parameter(
                "error",
                "string",
                "Why the operation failed (no answer, an unsupported format)",
                false,
            ),
        ],
    )
});
pub static NOTIFICATION_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event_with_ops(
        "lwm2m_notification",
        "An observed path changed on the device",
        vec![
            parameter("path", "string", "The observed path", true),
            parameter("values", "array", "[{path, value}]", true),
            parameter(
                "sequence",
                "number",
                "The notification's Observe sequence number",
                true,
            ),
        ],
    )
});
pub static DEREGISTER_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "lwm2m_deregister",
        "A device left: it deregistered or its lifetime expired",
        json!({"type": "lwm2m_accept"}),
    )
    .with_parameters(vec![
        endpoint_param(),
        parameter(
            "reason",
            "string",
            "deregistered (the device said so) or expired (no update within the lifetime)",
            true,
        ),
    ])
    .with_no_actions()
});

/// Check an operation's fields.
pub fn validate_operation(v: &Value) -> Result<()> {
    let p = v["path"].as_str().context("path is an LwM2M path")?;
    ensure!(
        super::content::valid_path(p),
        "{p:?} is not an LwM2M path like /3/0/0"
    );
    match v["type"].as_str() {
        Some("lwm2m_read") => ensure!(
            matches!(
                v.get("format").and_then(Value::as_str),
                None | Some("senml" | "text")
            ),
            "format is senml or text"
        ),
        Some("lwm2m_write") => {
            if let Some(values) = v.get("values").filter(|x| !x.is_null()) {
                super::content::senml_encode(values.as_array().context("values is an array")?)?;
                ensure!(
                    matches!(
                        v.get("mode").and_then(Value::as_str),
                        None | Some("replace" | "update")
                    ),
                    "mode is replace or update"
                );
            } else {
                super::content::text_encode(v).context("write needs value or values")?;
            }
        }
        Some("lwm2m_create") => {
            super::content::senml_encode(v["values"].as_array().context("values is an array")?)?;
        }
        Some("lwm2m_execute") => ensure!(
            v.get("arguments")
                .is_none_or(|a| a.is_null() || a.as_str().is_some_and(|s| s.len() <= 1024)),
            "arguments is text"
        ),
        Some("lwm2m_discover" | "lwm2m_observe" | "lwm2m_cancel_observe" | "lwm2m_delete") => {}
        _ => bail!("not an LwM2M operation"),
    }
    Ok(())
}

impl Protocol for Lwm2mProtocol {
    fn protocol_name(&self) -> &'static str {
        "LwM2M"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>UDP>CoAP>LwM2M"
    }
    fn description(&self) -> &'static str {
        "LwM2M 1.1 server over CoAP/UDP: devices register, and the handler reads, writes, executes and observes their objects"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "lwm2m",
            "lightweight m2m",
            "oma lwm2m",
            "device management",
            "lwm2m server",
        ]
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        operations()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        let mut out = vec![accept(), reject()];
        out.extend(operations());
        out
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            REGISTER_EVENT.clone(),
            UPDATE_EVENT.clone(),
            RESPONSE_EVENT.clone(),
            NOTIFICATION_EVENT.clone(),
            DEREGISTER_EVENT.clone(),
        ]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .well_known_udp_port(5683)
            .implementation("LwM2M registration interface and device management over the coap feature's codec: confirmable exchanges with retransmission, duplicate suppression, observation; SenML JSON, plain text and link format payloads")
            .llm_control("Which devices may register, and every read, write, execute, discover, observe, create and delete")
            .e2e_testing("tests/server/lwm2m: the Eclipse Leshan 2.0.0-M15 client demo (independent, Java/Californium) registers, is read, written, executed, discovered and observed, and deregisters")
            .notes("No DTLS, OSCORE, bootstrap or queue mode; no TLV, CBOR or LwM2M JSON (SenML JSON, text, opaque and link format are); no block-wise transfer, so payloads stay under one datagram. 16 KiB datagrams; registrations expire 15 s after their lifetime; operation chains stop at depth 4.")
            .answers_on_failure()
            .max_inbound_bytes(super::exchange::MAX_DATAGRAM)
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "LwM2M server on UDP 5683 that reads every device's manufacturer when it registers"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let llm = json!({"type":"open_server","base_stack":"lwm2m","port":5683,"instruction":"Accept every device and read /3/0 when it registers"});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([{"event_pattern":"lwm2m_register","handler":{"type":"static","actions":[{"type":"lwm2m_accept"},{"type":"lwm2m_read","path":"/3/0/0"}]}}]);
        let mut scripted = llm.clone();
        scripted["event_handlers"] = json!([{"event_pattern":"lwm2m_register","handler":{"type":"script","language":"python","code":"import json,sys\ne=json.load(sys.stdin)['event']\nok=e['endpoint'].startswith('sensor-')\nprint(json.dumps({'actions':[{'type':'lwm2m_accept'},{'type':'lwm2m_observe','path':'/3303/0/5700'}] if ok else [{'type':'lwm2m_reject'}]}))"}}]);
        crate::llm::actions::StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "IoT"
    }
}

impl Server for Lwm2mProtocol {
    fn spawn(
        &self,
        ctx: SpawnContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::spawn(ctx))
    }
    fn execute_action(&self, v: Value) -> Result<ActionResult> {
        match v["type"].as_str() {
            Some("lwm2m_accept") => {}
            Some("lwm2m_reject") => ensure!(
                matches!(
                    v.get("reason").and_then(Value::as_str),
                    None | Some("forbidden" | "bad_request")
                ),
                "reason is forbidden or bad_request"
            ),
            _ => validate_operation(&v)?,
        }
        Ok(ActionResult::Custom {
            name: v["type"].as_str().unwrap_or_default().into(),
            data: v,
        })
    }
}
