use super::model_bounds;
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
pub struct ScimProtocol;
impl ScimProtocol {
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
        log_template: Some(LogTemplate::new().with_info(format!("-> SCIM {name}"))),
    }
}

fn resources_action() -> ActionDefinition {
    action(
        "scim_resources",
        "Answer a list or search with the resources of that type. You may pre-filter, but need not: Rust applies the filter, sorting, startIndex/count paging and attribute selection itself and builds the ListResponse.",
        vec![parameter("resources", "array", "Resources of the requested type, each with id and schemas, e.g. [{\"id\": \"2819c223\", \"schemas\": [\"urn:ietf:params:scim:schemas:core:2.0:User\"], \"userName\": \"bjensen\"}]", true)],
        json!({"type":"scim_resources","resources":[{"id":"2819c223","schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"bjensen","active":true}]}),
    )
}
fn resource_action() -> ActionDefinition {
    action(
        "scim_resource",
        "Answer get, create, replace or patch with the resource as it now is. Rust checks id and schemas, writes meta (resourceType, location, timestamps when absent) and applies attributes/excludedAttributes; a create is sent 201 with Location.",
        vec![parameter("resource", "object", "The full resource, e.g. {\"id\": \"2819c223\", \"schemas\": [\"urn:ietf:params:scim:schemas:core:2.0:User\"], \"userName\": \"bjensen\", \"name\": {\"givenName\": \"Barbara\"}}", true)],
        json!({"type":"scim_resource","resource":{"id":"2819c223","schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"bjensen"}}),
    )
}
fn no_content_action() -> ActionDefinition {
    action(
        "scim_no_content",
        "Succeed without a body (204): a delete, or a patch whose result you do not return",
        vec![],
        json!({"type":"scim_no_content"}),
    )
}
fn error_action() -> ActionDefinition {
    action(
        "scim_error",
        "Refuse with a SCIM error (RFC 7644 §3.12)",
        vec![
            parameter("status", "number", "HTTP status: 400, 403, 404, 409 (uniqueness), 412, 413, 500 or 501", true),
            parameter("scim_type", "string", "For 400/409: invalidFilter, tooMany, uniqueness, mutability, invalidSyntax, invalidPath, noTarget, invalidValue, invalidVers or sensitive", false),
            parameter("detail", "string", "Human-readable explanation the client sees", false),
        ],
        json!({"type":"scim_error","status":404,"detail":"User 2819c223 not found"}),
    )
}

pub static REQUEST_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "scim_request",
        "A SCIM operation on Users or Groups. Discovery (ServiceProviderConfig, ResourceTypes, Schemas) is answered by Rust from RFC 7643's schemas; you own the data.",
        resource_action().example.clone(),
    )
    .with_parameters(vec![
        parameter("operation", "string", "list (GET collection or .search), get, create (POST), replace (PUT), patch or delete", true),
        parameter("resource_type", "string", "Which resource type the operation is on: User or Group", true),
        parameter("id", "string", "The resource id for get, replace, patch and delete", false),
        parameter("resource", "object", "The resource the client sent for create and replace (readOnly id and meta removed)", false),
        parameter("operations", "array", "For patch: [{op: add|remove|replace, path, parsed_path, value}] with the path already parsed", false),
        parameter("filter", "string", "For list: the filter as sent, e.g. userName eq \"bjensen\"", false),
        parameter("filter_parsed", "object", "For list: the filter as a tree ({op, path, value}, {and: [...]}, {or: [...]}, {not: ...}, {value_path, filter})", false),
        parameter("sort_by", "string", "For list: the attribute to sort on (Rust sorts)", false),
    ])
    .with_actions(vec![resources_action(), resource_action(), no_content_action(), error_action()])
});

fn startup(
    name: &str,
    kind: &str,
    description: &str,
    example: Value,
    default: Option<Value>,
) -> ParameterDefinition {
    ParameterDefinition {
        name: name.into(),
        type_hint: kind.into(),
        description: description.into(),
        required: false,
        example,
        default,
    }
}

impl Protocol for ScimProtocol {
    fn protocol_name(&self) -> &'static str {
        "SCIM"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>HTTP>SCIM"
    }
    fn description(&self) -> &'static str {
        "SCIM 2.0 provisioning service: Users and Groups with discovery, CRUD, PATCH, filtering, sorting and paging"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "scim",
            "scim2",
            "provisioning",
            "identity",
            "user provisioning",
            "okta",
            "entra",
        ]
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            resources_action(),
            resource_action(),
            no_content_action(),
            error_action(),
        ]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![REQUEST_EVENT.clone()]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            startup("base_path", "string", "URL path the SCIM endpoints live under (empty for the root)", json!("/scim/v2"), Some(json!(super::DEFAULT_BASE_PATH))),
            startup("bearer_token", "string", "When set, every request must carry Authorization: Bearer <token> (compared by Rust)", json!("s3cr3t"), None),
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation("hyper HTTP/1.1; RFC 7643 schemas embedded verbatim for discovery; RFC 7644 filter grammar parsed and evaluated, PATCH paths parsed, sorting, paging and attribute projection done by Rust over handler-supplied resources")
            .llm_control("The data: which resources exist, what create, replace and patch do to them, and refusals")
            .e2e_testing("tests/server/scim: scim2-tester 0.5.1 (independent compliance checker) runs discovery, CRUD, PATCH add/replace/remove and attribute selection; scim2-cli 0.4.0 creates, filters, patches and deletes")
            .notes("Users (with the Enterprise extension) and Groups only; no Bulk, /Me, ETags, changePassword or custom schemas. No storage: the handler owns every resource. 1 MiB bodies, 200 results per page, filters of 4 KiB.")
            .request_only("SCIM answers each HTTP request; nothing is pushed")
            .answers_on_failure()
            .max_inbound_bytes(model_bounds::MAX_BODY_BYTES)
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "SCIM server for an HR system with three users and an Engineering group"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let llm = json!({"type":"open_server","base_stack":"scim","port":8080,"instruction":"An identity provider with users alice and bob, both active"});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([
            {"event_pattern":"scim_request","handler":{"type":"static","actions":[resources_action().example]}}
        ]);
        let mut scripted = static_example.clone();
        scripted["event_handlers"][0]["handler"] = json!({"type":"script","language":"python","code":"import json,sys\ne=json.load(sys.stdin)['event']\na={'type':'scim_resources','resources':[]} if e['operation']=='list' else {'type':'scim_error','status':404,'detail':'not found'}\nprint(json.dumps({'actions':[a]}))"});
        crate::llm::actions::StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Authentication"
    }
}

impl Server for ScimProtocol {
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
    ensure!(model_bounds::budget_ok(v), "answer exceeds the SCIM bounds");
    match v["type"].as_str() {
        Some("scim_resources") => {
            let list = v["resources"]
                .as_array()
                .context("resources must be an array")?;
            ensure!(
                list.iter().all(|r| r.is_object()),
                "each resource is an object"
            );
        }
        Some("scim_resource") => ensure!(v["resource"].is_object(), "resource must be an object"),
        Some("scim_no_content") => {}
        Some("scim_error") => {
            let status = v["status"].as_u64().context("status is required")?;
            ensure!(
                matches!(status, 400 | 403 | 404 | 409 | 412 | 413 | 500 | 501),
                "status must be one SCIM defines"
            );
            if let Some(t) = v.get("scim_type").filter(|t| !t.is_null()) {
                let t = t.as_str().context("scim_type must be a string")?;
                ensure!(
                    model_bounds::SCIM_TYPES.contains(&t),
                    "unknown scim_type {t}"
                );
            }
            if let Some(d) = v.get("detail").filter(|d| !d.is_null()) {
                ensure!(
                    d.as_str().is_some_and(|d| d.len() <= 2048),
                    "detail must be at most 2048 bytes"
                );
            }
        }
        _ => bail!("Unknown SCIM server action"),
    }
    Ok(())
}
