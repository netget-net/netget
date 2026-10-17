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

#[derive(Default)]
pub struct CapnpRpcProtocol;
impl CapnpRpcProtocol {
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

pub const VALUE_NOTE: &str = "Fields by name as the schema declares them: numbers, booleans, strings, enums by enumerant name, lists as arrays, structs and groups as objects, a union as its one member, Data as {\"$hex\": \"…\"}";

fn return_action() -> ActionDefinition {
    action(
        "capnp_return",
        "Answer the call with its results struct; the event's results_shape lists the fields.",
        vec![parameter("results", "object", VALUE_NOTE, true)],
        json!({"type":"capnp_return","results":{"sum":5}}),
        "-> Cap'n Proto return {preview(results,100)}",
    )
}

pub fn exception_action() -> ActionDefinition {
    action(
        "capnp_exception",
        "Answer the call with an exception instead of results.",
        vec![
            parameter(
                "reason",
                "string",
                "Human-readable reason, at most 1024 bytes",
                true,
            ),
            parameter(
                "kind",
                "string",
                "failed (default), overloaded or unimplemented",
                false,
            ),
        ],
        json!({"type":"capnp_exception","reason":"no such entry","kind":"failed"}),
        "-> Cap'n Proto exception {reason}",
    )
}

pub static CALL_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "capnp_call",
        "A peer called a method on the bootstrap capability. Answer with its results or an exception.",
        return_action().example.clone(),
    )
    .with_parameters(vec![
        parameter("interface", "string", "The interface the method belongs to", true),
        parameter("method", "string", "The method's name", true),
        parameter("params", "object", VALUE_NOTE, true),
        parameter(
            "results_shape",
            "string",
            "The fields capnp_return's results may set, with their types",
            true,
        ),
        parameter("remote_addr", "string", "Peer address and port", true),
    ])
    .with_actions(vec![return_action(), exception_action()])
});

/// Check an exception action's fields; returns (reason, type code).
pub fn check_exception(v: &Value) -> Result<(String, u16)> {
    let reason = v["reason"].as_str().context("reason required")?;
    ensure!(
        !reason.is_empty() && reason.len() <= 1024 && !crate::utils::sanitize::has_controls(reason),
        "reason must be 1..=1024 bytes without control characters"
    );
    let kind = match v.get("kind").and_then(Value::as_str) {
        None => super::rpc::EXC_FAILED,
        Some(name) => super::rpc::exception_type(name)
            .filter(|t| *t != 2)
            .context("kind must be failed, overloaded or unimplemented")?,
    };
    Ok((reason.to_string(), kind))
}

fn param(
    name: &str,
    kind: &str,
    description: &str,
    required: bool,
    example: Value,
    default: Option<Value>,
) -> ParameterDefinition {
    ParameterDefinition {
        name: name.into(),
        type_hint: kind.into(),
        description: description.into(),
        required,
        example,
        default,
    }
}

/// A small inline schema for the examples.
pub const EXAMPLE_SCHEMA: &str = "interface Directory {\n  lookup @0 (name :Text) -> (size :UInt64, kind :Text);\n  add @1 (a :Int32, b :Int32) -> (sum :Int64);\n}";

pub fn schema_parameters() -> Vec<ParameterDefinition> {
    vec![
        param(
            "schema",
            "string",
            "The interface's Cap'n Proto schema: inline source (a file id is added if absent), a path to a .capnp file (both compiled at startup with the capnp tool), or a path to its compiled form (`capnp compile -o- file.capnp > file.bin`, which needs no tool)",
            true,
            json!(EXAMPLE_SCHEMA),
            None,
        ),
        param(
            "interface",
            "string",
            "Name of the interface the bootstrap capability implements, e.g. Directory",
            true,
            json!("Directory"),
            None,
        ),
    ]
}

impl Protocol for CapnpRpcProtocol {
    fn protocol_name(&self) -> &'static str {
        "Cap'n Proto RPC"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>CapnProtoRPC"
    }
    fn description(&self) -> &'static str {
        "Cap'n Proto RPC server: exports one capability whose method results the handler decides, typed by a startup schema"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "capnp",
            "cap'n proto",
            "capnproto",
            "capnp-rpc",
            "capability rpc",
        ]
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![return_action(), exception_action()]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![CALL_EVENT.clone()]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        let mut p = schema_parameters();
        p.push(param(
            "idle_timeout_secs",
            "number",
            "Seconds a connection may stay silent between messages (1..=86400)",
            false,
            json!(600),
            Some(json!(super::IDLE_TIMEOUT.as_secs())),
        ));
        p
    }
    fn get_dependencies(&self) -> Vec<crate::protocol::dependencies::ProtocolDependency> {
        let mut deps =
            crate::llm::actions::protocol_trait::default_dependencies_from_privilege(self);
        deps.push(crate::protocol::dependencies::ProtocolDependency::ToolInPath("capnp"));
        deps
    }
    fn startup_dependencies(
        &self,
        startup_params: Option<&Value>,
    ) -> Vec<crate::protocol::dependencies::ProtocolDependency> {
        let mut deps = self.get_dependencies();
        if !super::needs_compiler(startup_params) {
            deps.retain(|d| {
                *d != crate::protocol::dependencies::ProtocolDependency::ToolInPath("capnp")
            });
        }
        deps
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation("Hand-written Cap'n Proto encoding (bounded pointer-following reader, single-segment builder) and RPC level 1 over Tokio TCP: Bootstrap, Call (on the bootstrap capability or its promised answer), Return, Finish, Release, Abort, Unimplemented; params and results mapped to JSON by a schema loaded at startup")
            .llm_control("The results or exception of every call")
            .e2e_testing("tests/server/capnp_rpc: raw messages, the codec and bounds; pycapnp (the C++ Cap'n Proto runtime) and capnproto.org/go/capnp v3 as independent clients")
            .notes("One capability is exported (the bootstrap); results carry no capabilities, so promise pipelining reaches only the bootstrap answer. Interface and AnyPointer fields are not mapped. Messages are capped at 4 MiB and 64 segments, nesting at 64, traversal at four times the message size. A handler failure answers an exception, never fabricated results.")
            .request_only("Every Return answers a Bootstrap or a Call")
            .answers_on_failure()
            .max_inbound_bytes(super::layout::MAX_MESSAGE_BYTES)
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Cap'n Proto RPC server on port 5923 exporting a Directory interface with lookup and add methods"
    }
    fn get_startup_examples(&self) -> StartupExamples {
        let llm = json!({"type":"open_server","base_stack":"capnp-rpc","port":5923,"startup_params":{"schema":EXAMPLE_SCHEMA,"interface":"Directory"},"instruction":"Answer lookups for a small fictional directory"});
        let mut scripted = llm.clone();
        scripted["event_handlers"] = json!([{"event_pattern":"capnp_call","handler":{"type":"script","language":"python","code":"import json,sys\ne=json.load(sys.stdin)['event']\nif e['method']=='add':\n    a={'type':'capnp_return','results':{'sum':e['params']['a']+e['params']['b']}}\nelse:\n    a={'type':'capnp_exception','reason':'not implemented: '+e['method']}\nprint(json.dumps({'actions':[a]}))"}}]);
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([{"event_pattern":"capnp_call","handler":{"type":"static","actions":[{"type":"capnp_exception","reason":"maintenance"}]}}]);
        StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Application"
    }
}

impl Server for CapnpRpcProtocol {
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
            "capnp_return" => ensure!(
                v["results"].is_object(),
                "results must be an object of the result fields"
            ),
            "capnp_exception" => {
                check_exception(&v)?;
            }
            _ => bail!("Unknown Cap'n Proto RPC server action"),
        }
        Ok(ActionResult::Custom { name, data: v })
    }
}
