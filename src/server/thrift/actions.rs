use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter, ParameterDefinition,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::{EventType, SpawnContext};
use crate::state::app_state::AppState;
use anyhow::{bail, ensure, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

#[derive(Default)]
pub struct ThriftProtocol;
impl ThriftProtocol {
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
        log_template: Some(LogTemplate::new().with_info(format!("-> Thrift {name}"))),
    }
}

fn ret() -> ActionDefinition {
    action(
        "thrift_return",
        "Return from the call: Rust encodes `value` as the function's declared return type (structs as objects keyed by field name, enums by label); omit it for void",
        vec![parameter("value", "any", "The result, matching the IDL return type", false)],
        json!({"type": "thrift_return", "value": {"id": 7, "name": "Ada", "role": "ADMIN"}}),
    )
}
fn throw() -> ActionDefinition {
    action(
        "thrift_throw",
        "Throw one of the function's declared exceptions",
        vec![
            parameter(
                "exception",
                "string",
                "The throws-clause field name or the exception type name, e.g. missing or NotFound",
                true,
            ),
            parameter("value", "object", "The exception's fields by name", true),
        ],
        json!({"type": "thrift_throw", "exception": "missing", "value": {"message": "no such user", "id": 404}}),
    )
}
fn error() -> ActionDefinition {
    action(
        "thrift_error",
        "Fail the call with a TApplicationException (INTERNAL_ERROR) carrying this message, for errors the IDL does not declare",
        vec![parameter("message", "string", "The error message, up to 256 characters", true)],
        json!({"type": "thrift_error", "message": "backend unavailable"}),
    )
}
fn ignore() -> ActionDefinition {
    action(
        "thrift_ignore",
        "Acknowledge a oneway call; nothing is sent back",
        vec![],
        json!({"type": "thrift_ignore"}),
    )
}

pub static CALL_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "thrift_call",
        "A call to a function of the IDL's service; arguments decoded by their declared types",
        ret().example.clone(),
    )
    .with_parameters(vec![
        parameter("service", "string", "The service name", true),
        parameter("method", "string", "The function called", true),
        parameter(
            "oneway",
            "boolean",
            "true for a oneway function (no reply is possible)",
            true,
        ),
        parameter(
            "args",
            "object",
            "Arguments by name, values as JSON (unknown field ids appear as _<id>)",
            true,
        ),
        parameter(
            "returns",
            "string",
            "The declared return type, or void",
            true,
        ),
        parameter(
            "throws",
            "array",
            "The declared exceptions: [{name, type}]",
            true,
        ),
    ])
    .with_actions(vec![ret(), throw(), error(), ignore()])
});

pub fn check_answer(v: &Value) -> Result<()> {
    ensure!(
        crate::utils::json_budget::within_budget(v, 4 * 1024 * 1024, 200_000, 64),
        "answer exceeds the Thrift bounds"
    );
    match v["type"].as_str() {
        Some("thrift_return" | "thrift_ignore") => {}
        Some("thrift_throw") => {
            ensure!(
                v["exception"]
                    .as_str()
                    .is_some_and(|e| !e.is_empty() && e.len() <= 128),
                "exception names a declared exception"
            );
            ensure!(
                v["value"].is_object(),
                "value is the exception's fields as an object"
            );
        }
        Some("thrift_error") => ensure!(
            v["message"]
                .as_str()
                .is_some_and(|m| m.len() <= 256 && !crate::utils::sanitize::has_controls(&m)),
            "message is up to 256 printable characters"
        ),
        _ => bail!("Unknown Thrift server action"),
    }
    Ok(())
}

fn startup(
    name: &str,
    kind: &str,
    description: &str,
    required: bool,
    example: Value,
) -> ParameterDefinition {
    ParameterDefinition {
        name: name.into(),
        type_hint: kind.into(),
        description: description.into(),
        required,
        example,
        default: None,
    }
}

pub const EXAMPLE_IDL: &str = "enum Role { ADMIN = 1, USER = 2 }\nstruct User { 1: required i64 id, 2: required string name, 3: optional Role role }\nexception NotFound { 1: string message, 2: i64 id }\nservice Users {\n  User get_user(1: i64 id) throws (1: NotFound missing),\n  oneway void ping(1: string note)\n}\n";

impl Protocol for ThriftProtocol {
    fn protocol_name(&self) -> &'static str {
        "Thrift"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>Thrift"
    }
    fn description(&self) -> &'static str {
        "Apache Thrift RPC server for a service declared in IDL: framed or unframed transport, binary or compact protocol, calls answered by the handler"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "thrift",
            "apache thrift",
            "rpc",
            "idl",
            "tbinaryprotocol",
            "tcompactprotocol",
        ]
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![ret(), throw(), error(), ignore()]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![CALL_EVENT.clone()]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            startup("idl", "string", "The Thrift IDL (enums, structs, unions, exceptions, typedefs, services; no include), up to 256 KiB", true, json!(EXAMPLE_IDL)),
            startup("service", "string", "Which service in the IDL to serve; the last one when omitted", false, json!("Users")),
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation("Hand-written Thrift IDL parser, binary (strict and old) and compact protocols, framed and unframed transports detected per connection; arguments and results converted by their IDL types")
            .llm_control("The result, declared exception or error of every call")
            .e2e_testing("tests/server/thrift: thriftpy2 0.7.1 (IDL-driven, framed binary and compact) and Apache Thrift 0.25 (Python, its own binary and compact codecs over framed and buffered transports), independent, call functions, get declared exceptions and UNKNOWN_METHOD")
            .notes("One service per server; no multiplexed protocol, HTTP or header transport, JSON protocol, or include. Binary values are shown as text when UTF-8.")
            .answers_on_failure()
            .max_inbound_bytes(super::codec::MAX_MESSAGE)
            .request_only("Thrift answers each call; the server pushes nothing")
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Thrift server on port 9090 for this IDL that returns a demo user for any id below 100"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let llm = json!({"type":"open_server","base_stack":"thrift","port":9090,"instruction":"Return a demo user for ids below 100, NotFound otherwise","startup_params":{"idl": EXAMPLE_IDL}});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([{"event_pattern":"thrift_call","handler":{"type":"static","actions":[{"type":"thrift_error","message":"not implemented"}]}}]);
        let mut scripted = llm.clone();
        scripted["event_handlers"] = json!([{"event_pattern":"thrift_call","handler":{"type":"script","language":"python","code":"import json,sys\ne=json.load(sys.stdin)['event']\nif e['oneway']: a={'type':'thrift_ignore'}\nelif e['args'].get('id',0)<100: a={'type':'thrift_return','value':{'id':e['args']['id'],'name':'demo'}}\nelse: a={'type':'thrift_throw','exception':'missing','value':{'message':'no such user','id':e['args']['id']}}\nprint(json.dumps({'actions':[a]}))"}}]);
        crate::llm::actions::StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Application"
    }
}

impl Server for ThriftProtocol {
    fn spawn(
        &self,
        ctx: SpawnContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::spawn(ctx))
    }
    fn execute_action(&self, v: Value) -> Result<ActionResult> {
        check_answer(&v)?;
        Ok(ActionResult::Custom {
            name: v["type"].as_str().unwrap_or_default().into(),
            data: v,
        })
    }
}
