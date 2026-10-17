use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, Parameter, ParameterDefinition,
};
use crate::protocol::{ConnectContext, EventType};
use crate::server::lwm2m::actions::{action, parameter, VALUES_HELP};
use crate::server::lwm2m::content;
use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

#[derive(Default)]
pub struct Lwm2mClientProtocol;
impl Lwm2mClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

fn content_action() -> ActionDefinition {
    action(
        "lwm2m_content",
        "Answer a read with the values at the requested path",
        vec![parameter("values", "array", VALUES_HELP, true)],
        json!({"type": "lwm2m_content", "values": [{"path": "/3/0/0", "value": "NetGet"}]}),
    )
}
fn ok() -> ActionDefinition {
    action(
        "lwm2m_ok",
        "Accept a write, execute, create or delete request",
        vec![],
        json!({"type": "lwm2m_ok"}),
    )
}
fn error() -> ActionDefinition {
    action(
        "lwm2m_error",
        "Refuse a request with an LwM2M error",
        vec![parameter("code", "string", "not_found (4.04), method_not_allowed (4.05), bad_request (4.00) or unauthorized (4.01)", true)],
        json!({"type": "lwm2m_error", "code": "not_found"}),
    )
}
fn notify() -> ActionDefinition {
    action(
        "lwm2m_notify",
        "Send the server a notification for a path it observes (the observed path or a resource beneath it)",
        vec![parameter("path", "string", "The observed path", true), parameter("values", "array", VALUES_HELP, true)],
        json!({"type": "lwm2m_notify", "path": "/3303/0/5700", "values": [{"path": "/3303/0/5700", "value": 22.5}]}),
    )
}
fn update() -> ActionDefinition {
    action(
        "lwm2m_update",
        "Send a registration update now",
        vec![],
        json!({"type": "lwm2m_update"}),
    )
}
fn disconnect() -> ActionDefinition {
    action(
        "disconnect",
        "Deregister from the server and stop",
        vec![],
        json!({"type": "disconnect"}),
    )
}

fn answers() -> Vec<ActionDefinition> {
    vec![content_action(), ok(), error(), notify()]
}
fn path_param() -> Parameter {
    parameter("path", "string", "The LwM2M path the server named", true)
}
fn request_event(
    id: &str,
    description: &str,
    mut params: Vec<Parameter>,
    example: Value,
) -> EventType {
    params.insert(0, path_param());
    EventType::new(id, description, example)
        .with_parameters(params)
        .with_actions(answers())
}

pub static REGISTERED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "lwm2m_registered",
        "The server accepted the registration",
        json!({"type": "lwm2m_update"}),
    )
    .with_parameters(vec![
        parameter("server", "string", "The server's address", true),
        parameter(
            "location",
            "string",
            "The registration's location, e.g. /rd/5",
            true,
        ),
        parameter(
            "lifetime",
            "number",
            "The registration lifetime in seconds",
            true,
        ),
    ])
    .with_actions(vec![notify(), update(), disconnect()])
});
pub static READ_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    request_event(
        "lwm2m_read_request",
        "The server reads (or starts observing) a path; answer with its values",
        vec![parameter(
            "observe",
            "boolean",
            "Whether the server also starts observing it",
            true,
        )],
        content_action().example.clone(),
    )
});
pub static WRITE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    request_event(
        "lwm2m_write_request",
        "The server writes values",
        vec![
            parameter("values", "array", "[{path, value}]", true),
            parameter("mode", "string", "replace (PUT) or update (POST)", true),
        ],
        ok().example.clone(),
    )
});
pub static EXECUTE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    request_event(
        "lwm2m_execute_request",
        "The server executes a resource",
        vec![parameter(
            "arguments",
            "string",
            "The execute arguments, if any",
            false,
        )],
        ok().example.clone(),
    )
});
pub static CREATE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    request_event(
        "lwm2m_create_request",
        "The server creates an object instance",
        vec![parameter("values", "array", "[{path, value}]", true)],
        ok().example.clone(),
    )
});
pub static DELETE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    request_event(
        "lwm2m_delete_request",
        "The server deletes an object instance",
        vec![],
        ok().example.clone(),
    )
});

/// The error code an `lwm2m_error` names.
pub fn error_code(name: &str) -> Option<u8> {
    use crate::server::coap::codec::code;
    Some(match name {
        "not_found" => code(4, 4),
        "method_not_allowed" => code(4, 5),
        "bad_request" => code(4, 0),
        "unauthorized" => code(4, 1),
        _ => return None,
    })
}

impl Protocol for Lwm2mClientProtocol {
    fn protocol_name(&self) -> &'static str {
        "LwM2M"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>UDP>CoAP>LwM2M"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "lwm2m",
            "lwm2m client",
            "lwm2m device",
            "device management client",
        ]
    }
    fn description(&self) -> &'static str {
        "LwM2M 1.1 device over CoAP/UDP: registers its objects with a server and answers its reads, writes, executes and observations"
    }
    fn get_async_actions(&self, _: &crate::state::app_state::AppState) -> Vec<ActionDefinition> {
        vec![notify(), update(), disconnect()]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        answers()
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            REGISTERED_EVENT.clone(),
            READ_EVENT.clone(),
            WRITE_EVENT.clone(),
            EXECUTE_EVENT.clone(),
            CREATE_EVENT.clone(),
            DELETE_EVENT.clone(),
        ]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "endpoint".into(),
                type_hint: "string".into(),
                description: "Endpoint name; netget-<id> when omitted".into(),
                required: false,
                example: json!("sensor-7"),
                default: None,
            },
            ParameterDefinition {
                name: "lifetime".into(),
                type_hint: "number".into(),
                description: "Registration lifetime in seconds; updates are sent at half of it"
                    .into(),
                required: false,
                example: json!(60),
                default: Some(json!(super::DEFAULT_LIFETIME)),
            },
            ParameterDefinition {
                name: "objects".into(),
                type_hint: "array".into(),
                description:
                    "The object instances to register, e.g. [\"/1/0\", \"/3/0\", \"/3303/0\"]"
                        .into(),
                required: false,
                example: json!(["/1/0", "/3/0", "/3303/0"]),
                default: Some(json!(super::DEFAULT_OBJECTS)),
            },
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation("The server's CoAP exchange and LwM2M content code as a device: registration with updates, discovery from the registered objects, and the handler's answers to every request")
            .llm_control("The values the device reports, which writes, executes, creates and deletes it accepts, and when it notifies")
            .e2e_testing("tests/client/lwm2m: the Eclipse Leshan 2.0.0-M15 server demo (independent, Java/Californium) reads, writes, executes and observes the device through its REST API")
            .notes("No DTLS, OSCORE or bootstrap; SenML JSON, text and link format only; no block-wise transfer.")
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Register with the LwM2M server at 127.0.0.1:5683 as a temperature sensor reading 21.5"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let llm = json!({"type":"open_client","protocol":"lwm2m","remote_addr":"127.0.0.1:5683","instruction":"Be a temperature sensor at 21.5 C","startup_params":{"objects":["/1/0","/3/0","/3303/0"]}});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([{"event_pattern":"lwm2m_read_request","handler":{"type":"static","actions":[{"type":"lwm2m_content","values":[{"path":"/3303/0/5700","value":21.5}]}]}}]);
        let mut scripted = llm.clone();
        scripted["event_handlers"] = json!([{"event_pattern":"lwm2m_read_request","handler":{"type":"script","language":"python","code":"import json,sys\ne=json.load(sys.stdin)['event']\nprint(json.dumps({'actions':[{'type':'lwm2m_content','values':[{'path':e['path'],'value':21.5}]}]}))"}}]);
        crate::llm::actions::StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "IoT"
    }
}

impl Client for Lwm2mClientProtocol {
    fn connect(
        &self,
        ctx: ConnectContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::connect(ctx))
    }
    fn execute_action(&self, v: Value) -> Result<ClientActionResult> {
        match v["type"].as_str() {
            Some("disconnect") => return Ok(ClientActionResult::Disconnect),
            Some("lwm2m_update" | "lwm2m_ok") => {}
            Some("lwm2m_content") => {
                content::senml_encode(v["values"].as_array().context("values is an array")?)?;
            }
            Some("lwm2m_notify") => {
                ensure!(
                    v["path"].as_str().is_some_and(content::valid_path),
                    "path is an LwM2M path"
                );
                content::senml_encode(v["values"].as_array().context("values is an array")?)?;
            }
            Some("lwm2m_error") => ensure!(
                v["code"].as_str().and_then(error_code).is_some(),
                "code is not_found, method_not_allowed, bad_request or unauthorized"
            ),
            _ => bail!("Unknown LwM2M client action"),
        }
        Ok(ClientActionResult::Custom {
            name: v["type"].as_str().unwrap_or_default().into(),
            data: v,
        })
    }
}
