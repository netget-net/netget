//! What the model does as a TR-069 device (CPE): open sessions with the ACS, and answer each
//! RPC the ACS sends — parameter values, the data model's names, the outcome of a set, an
//! added or deleted object, a reboot — or refuse it with a CWMP fault.
use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, ParameterDefinition, StartupExamples,
};
use crate::protocol::{ConnectContext, EventType};
use crate::server::tr069::actions::{action, p};
use crate::server::tr069::wire;
use crate::state::app_state::AppState;
use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

pub const INFORM: &str = "tr069_inform";
pub const VALUES: &str = "tr069_parameter_values";
pub const NAMES: &str = "tr069_parameter_names";
pub const DONE: &str = "tr069_done";
pub const FAULT: &str = "tr069_fault";
/// The events of the session opened on connect when none are named.
pub const DEFAULT_EVENTS: &[&str] = &["1 BOOT"];
pub const DEFAULT_SERIAL: &str = "NETGET0001";
pub const DEFAULT_MANUFACTURER: &str = "NetGet";
pub const DEFAULT_OUI: &str = "4E4554";
pub const DEFAULT_PRODUCT_CLASS: &str = "NetGetCPE";
/// The data model root: Device (TR-181) or InternetGatewayDevice (TR-098).
pub const DEFAULT_ROOT: &str = "Device";
/// Where the connection-request listener binds when nowhere is named.
pub const DEFAULT_CR_LISTEN: &str = "127.0.0.1:0";

#[derive(Default)]
pub struct Tr069ClientProtocol;
impl Tr069ClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

pub fn actions() -> Vec<ActionDefinition> {
    vec![
        action(INFORM, "Open a session with the ACS (Inform) for these events; the ACS's RPCs follow as tr069_rpc events.",
            vec![
                p("events", "array", "Event codes, e.g. [\"2 PERIODIC\"] or [\"4 VALUE CHANGE\"]", true),
                p("parameters", "object", "Extra parameter values to report in the Inform, name to value", false),
            ],
            json!({"type": INFORM, "events": ["2 PERIODIC"]})),
        action(VALUES, "Answer GetParameterValues: the value of each parameter asked for (and of everything under a partial path).",
            vec![
                p("parameters", "object", "Name to value, e.g. {\"Device.DeviceInfo.SoftwareVersion\": \"1.0\"}", true),
                p("types", "object", "Name to xsd type where the default from the JSON value is wrong", false),
            ],
            json!({"type": VALUES, "parameters": {"Device.DeviceInfo.SoftwareVersion": "1.0"}})),
        action(NAMES, "Answer GetParameterNames: the names under the path, objects ending in a dot.",
            vec![p("parameters", "array", "[{name, writable}], e.g. [{\"name\": \"Device.DeviceInfo.\", \"writable\": false}]", true)],
            json!({"type": NAMES, "parameters": [{"name": "Device.DeviceInfo.SoftwareVersion", "writable": false}]})),
        action(DONE, "Answer SetParameterValues, AddObject, DeleteObject, Reboot or FactoryReset as done.",
            vec![
                p("status", "number", "0 when applied, 1 when it takes effect after a reboot (default 0)", false),
                p("instance_number", "number", "For AddObject: the new instance's number", false),
            ],
            json!({"type": DONE, "status": 0})),
        action(FAULT, "Refuse the RPC with a CWMP fault, e.g. 9005 invalid parameter name, 9001 request denied.",
            vec![
                p("code", "number", "CWMP fault code, 9000-9899", true),
                p("message", "string", "Fault text for the ACS", true),
            ],
            json!({"type": FAULT, "code": 9005, "message": "Invalid parameter name"})),
        action("disconnect", "Stop being a device: the connection-request listener closes.", vec![], json!({"type": "disconnect"})),
    ]
}

fn event(
    id: &str,
    description: &str,
    params: Vec<crate::llm::actions::Parameter>,
    example: Value,
) -> EventType {
    EventType::new(id, description, example)
        .with_parameters(params)
        .with_actions(actions())
}

pub static RPC_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event("tr069_rpc", "The ACS sent an RPC in the session; answer it (tr069_parameter_values, tr069_parameter_names, tr069_done or tr069_fault).", vec![
        p("method", "string", "GetParameterValues, SetParameterValues, GetParameterNames, AddObject, DeleteObject, Reboot, FactoryReset, …", true),
        p("arguments", "object", "GetParameterValues: {names}; SetParameterValues: {parameters: [{name, value, type}], parameter_key}; GetParameterNames: {path, next_level}; Add/DeleteObject: {object}", true),
    ], json!({"type": VALUES, "parameters": {"Device.DeviceInfo.SoftwareVersion": "1.0"}}))
});

pub static SESSION_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event(
        "tr069_session",
        "A session with the ACS ended (or could not start).",
        vec![
            p("ok", "boolean", "Whether the ACS accepted the Inform", true),
            p(
                "events",
                "array",
                "The event codes the session was opened for",
                true,
            ),
            p("rpcs", "number", "How many RPCs the ACS sent", true),
            p(
                "error",
                "string",
                "Why the session failed (a fault, or the ACS unreachable)",
                false,
            ),
        ],
        json!({"type": INFORM, "events": ["2 PERIODIC"]}),
    )
});

pub fn check(v: &Value) -> Result<()> {
    match v["type"].as_str().unwrap_or_default() {
        INFORM => {
            let events = v["events"].as_array().context("events must be a list")?;
            ensure!(
                !events.is_empty() && events.len() <= 16,
                "events must hold 1-16 codes"
            );
            ensure!(
                events
                    .iter()
                    .all(|e| e.as_str().is_some_and(|s| !s.is_empty() && s.len() <= 64)),
                "events are codes like 2 PERIODIC"
            );
            if let Some(ps) = v.get("parameters").filter(|x| !x.is_null()) {
                wire::triples(ps, None)?;
            }
        }
        VALUES => {
            wire::triples(&v["parameters"], v.get("types").filter(|t| !t.is_null()))?;
        }
        NAMES => {
            let ps = v["parameters"]
                .as_array()
                .context("parameters must be a list of {name, writable}")?;
            ensure!(ps.len() <= wire::MAX_PARAMETERS, "too many names");
            ensure!(
                ps.iter()
                    .all(|p| p["name"].as_str().is_some_and(|n| !n.is_empty())),
                "each entry needs a name"
            );
        }
        DONE => {
            if let Some(s) = v.get("status").filter(|x| !x.is_null()) {
                ensure!(matches!(s.as_u64(), Some(0 | 1)), "status is 0 or 1");
            }
        }
        FAULT => {
            let c = v["code"].as_u64().context("code must be a number")?;
            ensure!((9000..=9899).contains(&c), "a CPE fault code is 9000-9899");
            ensure!(
                v["message"].as_str().is_some_and(|m| m.len() <= 256),
                "message must be at most 256 bytes"
            );
        }
        other => bail!("Unknown TR-069 client action {other:?}"),
    }
    Ok(())
}

fn string_param(
    name: &str,
    description: &str,
    example: &str,
    default: Option<&str>,
) -> ParameterDefinition {
    ParameterDefinition {
        name: name.into(),
        type_hint: "string".into(),
        description: description.into(),
        required: false,
        example: json!(example),
        default: default.map(|d| json!(d)),
    }
}

impl Protocol for Tr069ClientProtocol {
    fn protocol_name(&self) -> &'static str {
        "TR-069"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>HTTP>CWMP"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["tr-069", "tr069", "cwmp", "cpe", "tr-069 device"]
    }
    fn description(&self) -> &'static str {
        "TR-069 (CWMP) device: informs an ACS and answers its RPCs with the data model the model invents"
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        actions()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![RPC_EVENT.clone(), SESSION_EVENT.clone()]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            string_param("serial_number", "The device's serial number in its DeviceId", "CPE12345", Some(DEFAULT_SERIAL)),
            string_param("manufacturer", "The device's manufacturer in its DeviceId", "Acme", Some(DEFAULT_MANUFACTURER)),
            string_param("oui", "The manufacturer's OUI (six hex digits) in its DeviceId", "001122", Some(DEFAULT_OUI)),
            string_param("product_class", "The device's product class in its DeviceId", "HomeGateway", Some(DEFAULT_PRODUCT_CLASS)),
            string_param("root", "Data model root: Device (TR-181) or InternetGatewayDevice (TR-098)", "InternetGatewayDevice", Some(DEFAULT_ROOT)),
            string_param("connection_request_listen", "Where the ACS can reach the device to ask it to open a session (an HTTP GET starts one)", "0.0.0.0:7547", Some(DEFAULT_CR_LISTEN)),
            ParameterDefinition {
                name: "events".into(),
                type_hint: "array".into(),
                description: "Event codes of the session opened on connect, e.g. [\"0 BOOTSTRAP\", \"1 BOOT\"]".into(),
                required: false,
                example: json!(["0 BOOTSTRAP", "1 BOOT"]),
                default: Some(json!(DEFAULT_EVENTS)),
            },
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation("reqwest POSTs with the ACS's session cookie carried by hand; the server role's SOAP reader and writer; a hyper listener for connection requests that opens a 6 CONNECTION REQUEST session")
            .llm_control("When to inform, and the answer to every RPC: parameter values, data-model names, set/add/delete outcomes, faults")
            .e2e_testing("tests/client/tr069: GenieACS 1.2.16 (cwmp and nbi) over MongoDB 8.0.4 registers the device, sends it queued tasks and a connection request, and its NBI is read back")
            .notes("No ACS authentication (Basic or Digest), no TLS, no Download/Upload, no persistence: the data model is whatever the model answers. An RPC the model does not answer within 60 s is refused with fault 9002. A handler chain stops after 8 follow-ups.")
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Be a TR-069 home gateway reporting to the ACS at http://127.0.0.1:7547/ with software version 2.1"
    }
    fn get_startup_examples(&self) -> StartupExamples {
        let llm = json!({"type":"open_client","protocol":"tr069","remote_addr":"http://127.0.0.1:7547/",
            "instruction":"You are a home gateway with software version 2.1; answer the ACS truthfully about that and refuse anything you do not know with fault 9005"});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([{"event_pattern":"tr069_rpc","handler":{"type":"static","actions":[{"type":FAULT,"code":9001,"message":"Request denied"}]}}]);
        let mut scripted = llm.clone();
        scripted["event_handlers"] = json!([{"event_pattern":"*","handler":{"type":"script","language":"python",
            "code":"import json,sys\ni=json.load(sys.stdin); t=i['event_type_id']; e=i['event']\na=[]\nif t=='tr069_rpc':\n  a=[{'type':'tr069_parameter_values','parameters':{n:'2.1' for n in e['arguments'].get('names',[])}}] if e['method']=='GetParameterValues' else [{'type':'tr069_done'}]\nprint(json.dumps({'actions':a}))"}}]);
        StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Application"
    }
}

impl Client for Tr069ClientProtocol {
    fn connect(
        &self,
        ctx: ConnectContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::connect(ctx))
    }
    fn execute_action(&self, v: Value) -> Result<ClientActionResult> {
        let name = v["type"].as_str().unwrap_or_default().to_string();
        if name == "disconnect" {
            return Ok(ClientActionResult::Disconnect);
        }
        check(&v)?;
        Ok(ClientActionResult::Custom { name, data: v })
    }
}
