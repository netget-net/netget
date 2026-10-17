use super::model;
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
pub struct RedfishProtocol;
impl RedfishProtocol {
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
        log_template: Some(LogTemplate::new().with_info(format!("-> Redfish {name}"))),
    }
}

fn accept_action() -> ActionDefinition {
    action(
        "redfish_login_accept",
        "Accept the credentials. Rust creates the session (X-Auth-Token, Location, Session resource) or admits the Basic-auth request.",
        vec![parameter("role", "string", "Role reported on the session, e.g. Administrator, Operator or ReadOnly (default Administrator)", false)],
        json!({"type":"redfish_login_accept","role":"Administrator"}),
    )
}
fn reject_action() -> ActionDefinition {
    action(
        "redfish_login_reject",
        "Refuse the credentials: the client gets 401 with a NoValidSession error",
        vec![parameter(
            "reason",
            "string",
            "Why, for the log only; the client sees the standard message",
            false,
        )],
        json!({"type":"redfish_login_reject","reason":"unknown user"}),
    )
}
fn resource_action() -> ActionDefinition {
    action(
        "redfish_resource",
        "Answer with a Redfish resource: the GET result, the resource after a PATCH, or the created member of a collection POST (sent 201 with Location). Rust fills @odata.id when missing, checks @odata.type, Id and Name, and counts collection Members.",
        vec![parameter("resource", "object", "The resource JSON, e.g. {\"@odata.type\": \"#ComputerSystem.v1_22_0.ComputerSystem\", \"Id\": \"1\", \"Name\": \"Server\", \"PowerState\": \"On\"}; collections use \"#XCollection.XCollection\" with Members [{\"@odata.id\": ...}]", true)],
        json!({"type":"redfish_resource","resource":{"@odata.type":"#ComputerSystemCollection.ComputerSystemCollection","Name":"Computer System Collection","Members":[{"@odata.id":"/redfish/v1/Systems/1"}]}}),
    )
}
fn no_content_action() -> ActionDefinition {
    action(
        "redfish_no_content",
        "Succeed without a body (204): an action that completed, a PATCH applied without returning the resource, a DELETE",
        vec![],
        json!({"type":"redfish_no_content"}),
    )
}
fn task_action() -> ActionDefinition {
    action(
        "redfish_task",
        "Accept the request as a long-running task: the client gets 202 with a task monitor; Rust runs the Task resource and reports the final state after complete_after_secs",
        vec![
            parameter("final_state", "string", "State the task reaches: Completed (default), Exception, Killed or Cancelled", false),
            parameter("complete_after_secs", "number", "Seconds until the task finishes, 0 to 600 (default 2)", false),
            parameter("messages", "array", "Messages the finished task reports, as strings", false),
            parameter("result", "object", "Optional body the task monitor returns once the task completes (default: no body, 204)", false),
        ],
        json!({"type":"redfish_task","final_state":"Completed","complete_after_secs":2,"messages":["Reset completed"]}),
    )
}
fn error_action() -> ActionDefinition {
    action(
        "redfish_error",
        "Refuse the request with a Redfish error body carrying a Base-registry message",
        vec![
            parameter("error", "string", "One of resource_not_found (404), property_not_writable, property_unknown, property_value_not_in_list, action_not_supported, action_parameter_missing, action_parameter_value_not_in_list (400), insufficient_privilege (403), operation_not_allowed (405), resource_in_use, resource_already_exists (409), service_temporarily_unavailable (503), general_error (500)", true),
            parameter("message", "string", "Optional human-readable message replacing the registry's default", false),
        ],
        json!({"type":"redfish_error","error":"resource_not_found"}),
    )
}

pub static LOGIN_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "redfish_login",
        "A client presents credentials: a session login (POST SessionService/Sessions) or HTTP Basic auth. Accept or reject; Rust owns tokens and expiry.",
        accept_action().example.clone(),
    )
    .with_parameters(vec![
        parameter("user_name", "string", "The UserName the client sent", true),
        parameter("password", "string", "The password the client sent, in the clear", true),
        parameter("method", "string", "session or basic", true),
    ])
    .with_actions(vec![accept_action(), reject_action()])
});

pub static REQUEST_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "redfish_request",
        "An authenticated request for a resource the handler owns (everything except the service root, OData documents, SessionService and TaskService, which Rust serves). Answer with the resource, no content, a task or an error.",
        resource_action().example.clone(),
    )
    .with_parameters(vec![
        parameter("method", "string", "GET, PATCH, POST or DELETE", true),
        parameter("kind", "string", "read, update (PATCH), create (POST to a collection), action (POST to .../Actions/X) or delete", true),
        parameter("path", "string", "Normalised request path, e.g. /redfish/v1/Systems/1", true),
        parameter("body", "object", "The JSON request body for PATCH and POST", false),
        parameter("action", "string", "For kind action: the action name, e.g. ComputerSystem.Reset", false),
        parameter("resource_path", "string", "For kind action: the resource the action belongs to", false),
        parameter("user_name", "string", "The authenticated user", false),
        parameter("if_match", "string", "The If-Match header, when the client sent one", false),
    ])
    .with_actions(vec![
        resource_action(),
        no_content_action(),
        task_action(),
        error_action(),
    ])
});

fn startup(
    name: &str,
    kind: &str,
    description: &str,
    example: Value,
    default: Value,
) -> ParameterDefinition {
    ParameterDefinition {
        name: name.into(),
        type_hint: kind.into(),
        description: description.into(),
        required: false,
        example,
        default: Some(default),
    }
}

impl Protocol for RedfishProtocol {
    fn protocol_name(&self) -> &'static str {
        "Redfish"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>HTTP>Redfish"
    }
    fn description(&self) -> &'static str {
        "DMTF Redfish service: service root, sessions, tasks and handler-supplied Systems, Chassis, Managers and actions"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "redfish",
            "bmc",
            "dmtf",
            "ipmi replacement",
            "out-of-band management",
        ]
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            accept_action(),
            reject_action(),
            resource_action(),
            no_content_action(),
            task_action(),
            error_action(),
        ]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![LOGIN_EVENT.clone(), REQUEST_EVENT.clone()]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            startup("product", "string", "Product name on the service root", json!("PowerEdge R760"), json!(super::DEFAULT_PRODUCT)),
            startup("vendor", "string", "Vendor name on the service root", json!("Contoso"), json!(super::DEFAULT_VENDOR)),
            startup("uuid", "string", "Service UUID on the service root", json!("92384634-2938-2342-8820-489239905423"), json!(super::DEFAULT_UUID)),
            startup("auth", "string", "required (sessions or Basic auth for everything but the service root and OData documents) or none", json!("none"), json!(super::DEFAULT_AUTH)),
            startup("session_timeout_secs", "integer", "Seconds of inactivity after which a session expires (30 to 86400)", json!(600), json!(super::DEFAULT_SESSION_TIMEOUT.as_secs())),
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation("hyper HTTP/1.1; Rust serves the service root, /redfish/v1/odata, $metadata, SessionService (X-Auth-Token sessions, Basic auth) and TaskService (202 task monitors); handler answers every other resource, PATCH, create, delete and action; envelopes and Base-registry errors checked by Rust")
            .llm_control("Login decisions and every resource, update, action result and task outcome")
            .e2e_testing("tests/server/redfish: gofish v0.26.0 (Go) and DMTF redfishtool 1.1.8 (Python), both independent, log in, walk systems, chassis sensors and managers, reset a system through a task, PATCH, and are refused a bad password")
            .notes("Plain HTTP (put TLS in front); no $expand, $select, $filter, ETag checks, EventService subscriptions or SSE. No storage: resources come from the handler; sessions and tasks live in memory. 1 MiB bodies.")
            .request_only("Redfish answers each HTTP request; event subscriptions are not offered")
            .answers_on_failure()
            .max_inbound_bytes(model::MAX_BODY_BYTES)
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Redfish BMC for one rack server with two CPUs, a chassis with temperature sensors and a manager; accept admin/secret"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let llm = json!({"type":"open_server","base_stack":"redfish","port":8443,"instruction":"A BMC for one server, Systems/1, powered on; accept admin/secret"});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([
            {"event_pattern":"redfish_login","handler":{"type":"static","actions":[{"type":"redfish_login_accept"}]}},
            {"event_pattern":"redfish_request","handler":{"type":"static","actions":[{"type":"redfish_error","error":"resource_not_found"}]}}
        ]);
        let mut scripted = static_example.clone();
        scripted["event_handlers"][0]["handler"] = json!({"type":"script","language":"python","code":"import json,sys\ne=json.load(sys.stdin)['event']\nok=e['user_name']=='admin' and e['password']=='secret'\nprint(json.dumps({'actions':[{'type':'redfish_login_accept' if ok else 'redfish_login_reject'}]}))"});
        crate::llm::actions::StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Network Management"
    }
}

impl Server for RedfishProtocol {
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

pub fn check_answer(v: &Value) -> Result<()> {
    ensure!(model::budget_ok(v), "answer exceeds the Redfish bounds");
    match v["type"].as_str() {
        Some("redfish_login_accept") => {
            if let Some(r) = v.get("role").filter(|r| !r.is_null()) {
                ensure!(
                    r.as_str().is_some_and(|r| !r.is_empty()
                        && r.len() <= 64
                        && r.bytes().all(|b| b.is_ascii_alphanumeric())),
                    "role is an identifier"
                );
            }
        }
        Some("redfish_login_reject" | "redfish_no_content") => {}
        Some("redfish_resource") => {
            ensure!(v["resource"].is_object(), "resource must be an object");
        }
        Some("redfish_task") => {
            if let Some(s) = v.get("final_state").filter(|s| !s.is_null()) {
                let s = s.as_str().context("final_state must be a string")?;
                ensure!(
                    model::task_finished(s),
                    "final_state must be Completed, Exception, Killed or Cancelled"
                );
            }
            if let Some(n) = v.get("complete_after_secs").filter(|n| !n.is_null()) {
                ensure!(
                    n.as_u64().is_some_and(|n| n <= 600),
                    "complete_after_secs must be 0..=600"
                );
            }
            model::messages_from(v.get("messages"))?;
            if let Some(r) = v.get("result").filter(|r| !r.is_null()) {
                ensure!(r.is_object(), "result must be an object");
            }
        }
        Some("redfish_error") => {
            let name = v["error"].as_str().context("error is required")?;
            ensure!(model::error_named(name).is_some(), "unknown error '{name}'");
            if let Some(m) = v.get("message").filter(|m| !m.is_null()) {
                ensure!(
                    m.as_str().is_some_and(|m| !m.is_empty() && m.len() <= 1024),
                    "message must be 1..1024 bytes"
                );
            }
        }
        _ => bail!("Unknown Redfish server action"),
    }
    Ok(())
}
