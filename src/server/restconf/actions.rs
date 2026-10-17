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
pub struct RestconfProtocol;
impl RestconfProtocol {
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
        log_template: Some(LogTemplate::new().with_info(format!("RESTCONF {name}"))),
    }
}

/// RFC 8040 section 7 error tags and the status each defaults to.
pub const ERROR_TAGS: &[(&str, u16)] = &[
    ("in-use", 409),
    ("invalid-value", 400),
    ("too-big", 413),
    ("missing-attribute", 400),
    ("bad-attribute", 400),
    ("unknown-attribute", 400),
    ("bad-element", 400),
    ("unknown-element", 400),
    ("unknown-namespace", 400),
    ("access-denied", 403),
    ("lock-denied", 409),
    ("resource-denied", 409),
    ("rollback-failed", 500),
    ("data-exists", 409),
    ("data-missing", 409),
    ("operation-not-supported", 405),
    ("operation-failed", 500),
    ("partial-operation", 500),
    ("malformed-message", 400),
];

fn data() -> ActionDefinition {
    action(
        "restconf_data",
        "Answer a GET or HEAD with the resource's data as YANG JSON (RFC 7951: top-level members carry their module, e.g. {\"example:car\": {...}})",
        vec![parameter("data", "object", "The data, e.g. {\"example:car\": {\"speed\": 100}} for a GET of example:car", true)],
        json!({"type": "restconf_data", "data": {"example:car": {"speed": 100, "tire": [{"pos": 0, "size": "H15"}]}}}),
    )
}
fn ok() -> ActionDefinition {
    action(
        "restconf_ok",
        "Accept an edit: 201 Created (POST, with the new resource's Location) or 204 No Content (PUT, PATCH, DELETE)",
        vec![parameter("status", "number", "201 or 204 (default 201 for POST, 204 otherwise)", false), parameter("location", "string", "For 201, the new resource's path under data/, e.g. example:car/tire=4", false)],
        json!({"type": "restconf_ok"}),
    )
}
fn error() -> ActionDefinition {
    action(
        "restconf_error",
        "Refuse with an RFC 8040 error: the error-tag decides the default status (invalid-value 400, data-missing 409, access-denied 403, data-exists 409, operation-not-supported 405, operation-failed 500)",
        vec![
            parameter("error_tag", "string", "RFC 8040 error-tag, e.g. invalid-value, data-missing, data-exists, access-denied", true),
            parameter("message", "string", "error-message text", false),
            parameter("status", "number", "HTTP status overriding the tag's default, e.g. 404 for a missing resource", false),
            parameter("error_type", "string", "transport, rpc, protocol (default) or application", false),
            parameter("error_path", "string", "The instance identifier the error concerns", false),
        ],
        json!({"type": "restconf_error", "error_tag": "invalid-value", "status": 404, "message": "no such tire"}),
    )
}
fn output() -> ActionDefinition {
    action(
        "restconf_output",
        "Answer an operation: 200 with its output (wrapped as module:output), or 204 when there is none",
        vec![parameter("output", "object", "The operation's output leaves, e.g. {\"oilLevel\": 12.5}", false)],
        json!({"type": "restconf_output", "output": {"oilLevel": 12.5}}),
    )
}

pub static DATA_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "restconf_data_request",
        "A client read or edited a data resource. GET and HEAD want restconf_data; POST, PUT, PATCH and DELETE want restconf_ok; any may get restconf_error.",
        data().example.clone(),
    )
    .with_parameters(vec![
        parameter("method", "string", "GET, HEAD, POST, PUT, PATCH or DELETE", true),
        parameter("path", "string", "The resource under data/, e.g. example:car/tire=1 (empty: the whole datastore)", true),
        parameter("target", "array", "The path parsed: [{module, name, keys}]", true),
        parameter("query", "object", "RESTCONF query parameters: depth, content, fields, with-defaults, insert, point", true),
        parameter("body", "object", "The YANG JSON body of a POST, PUT or PATCH", false),
    ])
    .with_actions(vec![data(), ok(), error()])
});

pub static OPERATION_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "restconf_operation",
        "A client invoked an RPC under operations/",
        output().example.clone(),
    )
    .with_parameters(vec![
        parameter("operation", "string", "module:name of the RPC", true),
        parameter(
            "input",
            "object",
            "The input leaves (the module:input wrapper removed)",
            false,
        ),
    ])
    .with_actions(vec![output(), error()])
});

impl Protocol for RestconfProtocol {
    fn protocol_name(&self) -> &'static str {
        "RESTCONF"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>HTTP>RESTCONF"
    }
    fn description(&self) -> &'static str {
        "RESTCONF (RFC 8040) server: YANG-shaped data resources and operations over HTTP with JSON, discovery and RFC 8040 errors; the handler is the datastore"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["restconf", "rfc8040", "yang", "network management api"]
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![data(), ok(), error(), output()]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![DATA_EVENT.clone(), OPERATION_EVENT.clone()]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "modules".into(),
                type_hint: "array".into(),
                description: "The YANG modules the server implements, listed in ietf-yang-library: [{name, revision, namespace}]".into(),
                required: false,
                example: json!([{"name": "example", "revision": "2026-10-01", "namespace": "urn:example"}]),
                default: None,
            },
            ParameterDefinition {
                name: "operations".into(),
                type_hint: "array".into(),
                description: "The RPCs listed under operations/, e.g. [\"example:reset\"]".into(),
                required: false,
                example: json!(["example:reset"]),
                default: None,
            },
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation("RFC 8040 over hyper HTTP/1.1: host-meta discovery, the API root, yang-library-version, ietf-yang-library modules-state from the declared modules, data-resource paths, query parameters, media types and RFC 8040 error documents are Rust's; data and operation answers are the handler's")
            .llm_control("Every data resource's content, which edits are accepted, and every operation's output or error")
            .e2e_testing("tests/server/restconf: the FreeCONF RESTCONF client (independent, Go) discovers the server, loads the module list, reads, edits and invokes an operation")
            .notes("JSON only (application/yang-data+json); no XML, no event streams, no ETag/Last-Modified, no YANG validation (declared modules are listed, not parsed). No storage: the handler keeps data in memory or SQLite. 1 MiB bodies.")
            .request_only("RESTCONF answers each HTTP request; event streams are not offered")
            .answers_on_failure()
            .max_inbound_bytes(super::MAX_BODY)
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "RESTCONF server on port 8080 for an example:car module with a speed leaf"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let llm = json!({"type":"open_server","base_stack":"restconf","port":8080,"instruction":"Serve example:car with speed 100","startup_params":{"modules":[{"name":"example","revision":"2026-10-01","namespace":"urn:example"}]}});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([{"event_pattern":"restconf_data_request","handler":{"type":"static","actions":[{"type":"restconf_data","data":{"speed":100}}]}}]);
        let mut scripted = llm.clone();
        scripted["event_handlers"] = json!([{"event_pattern":"restconf_data_request","handler":{"type":"script","language":"python","code":"import json,sys\ne=json.load(sys.stdin)['event']\na={'type':'restconf_data','data':{'speed':100}} if e['method'] in ('GET','HEAD') else {'type':'restconf_ok'}\nprint(json.dumps({'actions':[a]}))"}}]);
        crate::llm::actions::StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Network Management"
    }
}

impl Server for RestconfProtocol {
    fn spawn(
        &self,
        ctx: SpawnContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::spawn(ctx))
    }
    fn execute_action(&self, v: Value) -> Result<ActionResult> {
        match v["type"].as_str() {
            Some("restconf_data") => ensure!(v["data"].is_object(), "data is a JSON object"),
            Some("restconf_ok") => ensure!(
                matches!(
                    v.get("status").and_then(Value::as_u64),
                    None | Some(201 | 204)
                ),
                "status is 201 or 204"
            ),
            Some("restconf_output") => ensure!(
                v.get("output").is_none_or(|o| o.is_null() || o.is_object()),
                "output is an object"
            ),
            Some("restconf_error") => {
                let tag = v["error_tag"].as_str().unwrap_or_default();
                ensure!(
                    ERROR_TAGS.iter().any(|(t, _)| *t == tag),
                    "error_tag is an RFC 8040 error-tag such as invalid-value or data-missing"
                );
                ensure!(
                    v.get("status")
                        .and_then(Value::as_u64)
                        .is_none_or(|s| (400..=599).contains(&s)),
                    "status is 400-599"
                );
                ensure!(
                    matches!(
                        v.get("error_type").and_then(Value::as_str),
                        None | Some("transport" | "rpc" | "protocol" | "application")
                    ),
                    "error_type is transport, rpc, protocol or application"
                );
            }
            _ => bail!("Unknown RESTCONF server action"),
        }
        Ok(ActionResult::Custom {
            name: v["type"].as_str().unwrap_or_default().into(),
            data: v,
        })
    }
}
