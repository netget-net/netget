//! What the model decides as a TR-069 ACS: which devices it manages and what it asks each one
//! in a session — read and write parameters, discover the data model, add and delete objects,
//! reboot. Rust owns the HTTP sessions, the SOAP envelopes and the order RPCs are sent in.
use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter, ParameterDefinition, StartupExamples,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::{EventType, SpawnContext};
use crate::state::app_state::AppState;
use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

pub const GPV: &str = "tr069_get_parameter_values";
pub const SPV: &str = "tr069_set_parameter_values";
pub const GPN: &str = "tr069_get_parameter_names";
pub const ADD: &str = "tr069_add_object";
pub const DELETE: &str = "tr069_delete_object";
pub const REBOOT: &str = "tr069_reboot";
pub const FACTORY_RESET: &str = "tr069_factory_reset";
pub const REJECT: &str = "tr069_reject";
/// RPCs one answer may queue.
pub const MAX_QUEUED: usize = 32;

#[derive(Default)]
pub struct Tr069Protocol;
impl Tr069Protocol {
    pub fn new() -> Self {
        Self
    }
}

pub fn p(name: &str, kind: &str, description: &str, required: bool) -> Parameter {
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
        log_template: Some(LogTemplate::new().with_info(format!("-> TR-069 {name}"))),
    }
}

fn object_param() -> Parameter {
    p(
        "object",
        "string",
        "Object path ending in a dot, e.g. Device.IP.Interface. (or …Interface.2. to delete)",
        true,
    )
}

pub fn rpc_actions() -> Vec<ActionDefinition> {
    vec![
        action(GPV, "Ask the device for parameter values (GetParameterValues). A path ending in a dot asks for everything under it.",
            vec![p("names", "array", "Parameter names or partial paths, e.g. [\"Device.DeviceInfo.SoftwareVersion\"]", true)],
            json!({"type": GPV, "names": ["Device.DeviceInfo.SoftwareVersion"]})),
        action(SPV, "Set parameter values on the device (SetParameterValues).",
            vec![
                p("values", "object", "Name to value, e.g. {\"Device.ManagementServer.PeriodicInformInterval\": 300}", true),
                p("types", "object", "Name to xsd type where the default (from the JSON value) is wrong, e.g. {\"X\": \"xsd:dateTime\"}", false),
                p("parameter_key", "string", "Opaque key the device stores as ParameterKey", false),
            ],
            json!({"type": SPV, "values": {"Device.ManagementServer.PeriodicInformInterval": 300}})),
        action(GPN, "Discover the data model below a path (GetParameterNames).",
            vec![
                p("path", "string", "A partial path ending in a dot (or a full name), e.g. Device.DeviceInfo.", true),
                p("next_level", "boolean", "Only the level directly below (default true)", false),
            ],
            json!({"type": GPN, "path": "Device.DeviceInfo.", "next_level": true})),
        action(ADD, "Create a new instance of a multi-instance object (AddObject).",
            vec![object_param(), p("parameter_key", "string", "Opaque key the device stores as ParameterKey", false)],
            json!({"type": ADD, "object": "Device.IP.Interface."})),
        action(DELETE, "Delete an object instance (DeleteObject).",
            vec![object_param(), p("parameter_key", "string", "Opaque key the device stores as ParameterKey", false)],
            json!({"type": DELETE, "object": "Device.IP.Interface.2."})),
        action(REBOOT, "Reboot the device (Reboot).", vec![p("command_key", "string", "Key the device reports back in its M Reboot event", false)],
            json!({"type": REBOOT, "command_key": "maintenance"})),
        action(FACTORY_RESET, "Reset the device to factory defaults (FactoryReset).", vec![], json!({"type": FACTORY_RESET})),
    ]
}

fn reject() -> ActionDefinition {
    action(REJECT, "Refuse to manage the device: its Inform is answered with fault 8001 (request denied) and the session ends.",
        vec![p("message", "string", "Why, as the device will see it", true)], json!({"type": REJECT, "message": "unknown device"}))
}

pub static INFORM_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    let mut actions = rpc_actions();
    actions.push(reject());
    EventType::new("tr069_inform", "A device opened a session (Inform). Queue the RPCs to send it in this session, in order; with none, the session ends after the InformResponse.",
        json!({"type": GPV, "names": ["Device.DeviceInfo.SoftwareVersion"]}))
        .with_parameters(vec![
            p("device_id", "object", "{manufacturer, oui, product_class, serial_number}", true),
            p("events", "array", "Why it informed: [{code, command_key}], codes like 0 BOOTSTRAP, 1 BOOT, 2 PERIODIC, 6 CONNECTION REQUEST", true),
            p("parameters", "array", "The values it reported: [{name, value, type}]", true),
            p("retry_count", "number", "How many times it has retried this Inform", true),
            p("remote_addr", "string", "The device's address and port", true),
        ])
        .with_actions(actions)
});

pub static RESPONSE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new("tr069_response", "The device answered an RPC (or faulted). Queue further RPCs, or none to end the session.",
        json!({"type": GPV, "names": ["Device.DeviceInfo."]}))
        .with_parameters(vec![
            p("device_id", "object", "{manufacturer, oui, product_class, serial_number}", true),
            p("method", "string", "The RPC this answers, e.g. GetParameterValues", true),
            p("ok", "boolean", "False when the device answered with a fault", true),
            p("result", "object", "GetParameterValues: {parameters: [{name, value, type}]}; GetParameterNames: {parameters: [{name, writable}]}; Set/Add/Delete: {status, instance_number}", false),
            p("fault", "object", "{code, message} when the device refused", false),
            p("pending", "number", "RPCs still queued for this session", true),
        ])
        .with_actions(rpc_actions())
});

fn path_ok(s: &str) -> bool {
    !s.is_empty() && s.len() <= 256 && !s.chars().any(|c| c.is_whitespace())
}

pub fn check(v: &Value) -> Result<()> {
    match v["type"].as_str().unwrap_or_default() {
        GPV => {
            let names = v["names"].as_array().context("names must be a list")?;
            ensure!(
                !names.is_empty() && names.len() <= 1000,
                "names must hold 1-1000 paths"
            );
            ensure!(
                names.iter().all(|n| n.as_str().is_some_and(path_ok)),
                "each name is a parameter path"
            );
        }
        SPV => {
            ensure!(
                v["values"].as_object().is_some_and(|o| !o.is_empty()),
                "values must name at least one parameter"
            );
            super::wire::triples(&v["values"], v.get("types").filter(|t| !t.is_null()))?;
        }
        GPN => ensure!(
            v["path"].as_str().is_some_and(path_ok),
            "path is a parameter path"
        ),
        ADD | DELETE => {
            let o = v["object"].as_str().context("object is required")?;
            ensure!(
                path_ok(o) && o.ends_with('.'),
                "object is a path ending in a dot"
            );
        }
        REBOOT | FACTORY_RESET => {}
        REJECT => ensure!(
            v["message"]
                .as_str()
                .is_some_and(|m| !m.is_empty() && m.len() <= 256),
            "message must be 1-256 bytes"
        ),
        other => bail!("Unknown TR-069 action {other:?}"),
    }
    Ok(())
}

impl Protocol for Tr069Protocol {
    fn protocol_name(&self) -> &'static str {
        "TR-069"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>HTTP>CWMP"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "tr-069",
            "tr069",
            "cwmp",
            "acs",
            "auto configuration server",
            "cpe management",
        ]
    }
    fn description(&self) -> &'static str {
        "TR-069 (CWMP) auto-configuration server: devices inform, and the model decides what to read, set, add, delete or reboot in each session"
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        Vec::new()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        let mut a = rpc_actions();
        a.push(reject());
        a
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![INFORM_EVENT.clone(), RESPONSE_EVENT.clone()]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![ParameterDefinition {
            name: "session_timeout_secs".into(),
            type_hint: "number".into(),
            description: "Seconds a CWMP session may wait for the device's next request before it is forgotten (1..=3600)".into(),
            required: false,
            example: json!(60),
            default: Some(json!(super::SESSION_TIMEOUT.as_secs())),
        }]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .well_known_port(7547)
            .implementation("hyper HTTP/1.1 with cookie sessions; SOAP 1.1 envelopes read with quick-xml into a bounded tree (1 MiB, depth 32, no DOCTYPE) and written escaped: Inform/InformResponse, GetParameterValues, SetParameterValues, GetParameterNames, AddObject, DeleteObject, Reboot, FactoryReset and their responses and faults; TransferComplete and GetRPCMethods from the device are answered")
            .llm_control("Which devices to manage, and the RPCs of every session: what to read, write, discover, create, delete and when to reboot")
            .e2e_testing("tests/server/tr069: genieacs-sim (the GenieACS project's CPE simulator, a TR-098 device of 1000 parameters) informs and answers every RPC; raw HTTP for faults, bounds and a failed handler")
            .notes("No authentication of devices (no HTTP Basic or Digest), no TLS, no connection requests to devices, no Download/Upload, no persistence. Sessions are cookie-bound and forgotten after session_timeout_secs. Envelopes are capped at 1 MiB.")
            .request_only("Every message answers a device's HTTP request: CWMP sessions are device-initiated")
            .answers_on_failure()
            .max_inbound_bytes(super::wire::MAX_ENVELOPE)
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "TR-069 ACS on port 7547 that reads every device's software version and sets its inform interval to 300"
    }
    fn get_startup_examples(&self) -> StartupExamples {
        let llm = json!({"type":"open_server","base_stack":"tr069","port":7547,
            "instruction":"On every Inform read DeviceInfo.SoftwareVersion; on 1 BOOT set PeriodicInformInterval to 300"});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([{"event_pattern":"tr069_inform","handler":{"type":"static","actions":[{"type":GPV,"names":["Device.DeviceInfo.SoftwareVersion"]}]}},
                                                   {"event_pattern":"tr069_response","handler":{"type":"static","actions":[]}}]);
        let mut scripted = llm.clone();
        scripted["event_handlers"] = json!([{"event_pattern":"*","handler":{"type":"script","language":"python",
            "code":"import json,sys\ni=json.load(sys.stdin); t=i['event_type_id']\na=[{'type':'tr069_get_parameter_values','names':['Device.DeviceInfo.SoftwareVersion']}] if t=='tr069_inform' else []\nprint(json.dumps({'actions':a}))"}}]);
        StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Application"
    }
}

impl Server for Tr069Protocol {
    fn spawn(
        &self,
        ctx: SpawnContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::spawn(ctx))
    }
    fn execute_action(&self, action: Value) -> Result<ActionResult> {
        check(&action)?;
        Ok(ActionResult::Custom {
            name: action["type"].as_str().unwrap_or_default().to_string(),
            data: action,
        })
    }
}
