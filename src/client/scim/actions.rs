use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, ParameterDefinition,
};
use crate::protocol::{ConnectContext, EventType};
use crate::server::scim::actions::{action, parameter};
use crate::server::scim::{model_bounds, query};
use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

#[derive(Default)]
pub struct ScimClientProtocol;
impl ScimClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

fn rt() -> crate::llm::actions::Parameter {
    parameter(
        "resource_type",
        "string",
        "Endpoint name of the resource type, e.g. Users or Groups",
        true,
    )
}
fn rid() -> crate::llm::actions::Parameter {
    parameter("id", "string", "The resource id", true)
}
fn list_action() -> ActionDefinition {
    action(
        "scim_list",
        "Query a resource type (GET with filter, sortBy, startIndex, count, attributes); Rust checks the filter syntax before sending",
        vec![
            rt(),
            parameter("filter", "string", "SCIM filter, e.g. userName eq \"bjensen\" or emails[type eq \"work\"]", false),
            parameter("sort_by", "string", "Attribute to sort on, e.g. userName", false),
            parameter("sort_order", "string", "ascending or descending", false),
            parameter("start_index", "number", "1-based index of the first result", false),
            parameter("count", "number", "Maximum results to return", false),
            parameter("attributes", "string", "Comma-separated attributes to return, e.g. userName,emails", false),
        ],
        json!({"type":"scim_list","resource_type":"Users","filter":"userName sw \"b\"","count":10}),
    )
}
fn get_action() -> ActionDefinition {
    action(
        "scim_get",
        "Read one resource",
        vec![rt(), rid()],
        json!({"type":"scim_get","resource_type":"Users","id":"2819c223"}),
    )
}
fn create_action() -> ActionDefinition {
    action(
        "scim_create",
        "Create a resource (POST); Rust adds the core schema URN when schemas is missing",
        vec![rt(), parameter("resource", "object", "The resource, e.g. {\"userName\": \"bjensen\", \"name\": {\"givenName\": \"Barbara\"}}", true)],
        json!({"type":"scim_create","resource_type":"Users","resource":{"userName":"bjensen","active":true}}),
    )
}
fn replace_action() -> ActionDefinition {
    action(
        "scim_replace",
        "Replace a resource (PUT)",
        vec![
            rt(),
            rid(),
            parameter("resource", "object", "The complete new resource", true),
        ],
        json!({"type":"scim_replace","resource_type":"Users","id":"2819c223","resource":{"userName":"bjensen","active":false}}),
    )
}
fn patch_action() -> ActionDefinition {
    action(
        "scim_patch",
        "Modify a resource with PatchOp operations; Rust checks each op and path before sending",
        vec![rt(), rid(), parameter("operations", "array", "[{op: add|remove|replace, path, value}], e.g. [{\"op\": \"replace\", \"path\": \"active\", \"value\": false}]", true)],
        json!({"type":"scim_patch","resource_type":"Users","id":"2819c223","operations":[{"op":"replace","path":"active","value":false}]}),
    )
}
fn delete_action() -> ActionDefinition {
    action(
        "scim_delete",
        "Delete a resource",
        vec![rt(), rid()],
        json!({"type":"scim_delete","resource_type":"Users","id":"2819c223"}),
    )
}
fn disconnect_action() -> ActionDefinition {
    action(
        "disconnect",
        "Stop this SCIM client",
        vec![],
        json!({"type":"disconnect"}),
    )
}
fn actions() -> Vec<ActionDefinition> {
    vec![
        list_action(),
        get_action(),
        create_action(),
        replace_action(),
        patch_action(),
        delete_action(),
        disconnect_action(),
    ]
}

pub static CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new("scim_connected", "The service's ServiceProviderConfig and ResourceTypes were read", list_action().example.clone())
        .with_parameters(vec![
            parameter("resource_types", "array", "[{name, endpoint, schema}] the service offers", true),
            parameter("features", "object", "What ServiceProviderConfig says is supported: {patch, filter, sort, bulk, etag, changePassword}", true),
        ])
        .with_actions(actions())
});
pub static RESPONSE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "scim_response",
        "The service's answer to the last operation",
        disconnect_action().example.clone(),
    )
    .with_parameters(vec![
        parameter(
            "operation",
            "string",
            "list, get, create, replace, patch or delete",
            true,
        ),
        parameter(
            "status",
            "number",
            "HTTP status of the answer: 200, 201 created, 204 no content, or the error status",
            true,
        ),
        parameter(
            "resource",
            "object",
            "The resource returned by get, create, replace or patch",
            false,
        ),
        parameter("total_results", "number", "For list: totalResults", false),
        parameter(
            "resources",
            "array",
            "For list: the page of resources",
            false,
        ),
        parameter(
            "error",
            "object",
            "SCIM error: {status, scim_type, detail}",
            false,
        ),
    ])
    .with_actions(actions())
});

impl Protocol for ScimClientProtocol {
    fn protocol_name(&self) -> &'static str {
        "SCIM"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>HTTP>SCIM"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["scim", "scim2", "provisioning client"]
    }
    fn description(&self) -> &'static str {
        "SCIM 2.0 client: discovers a service, then lists, reads, creates, replaces, patches and deletes Users and Groups"
    }
    fn get_async_actions(&self, _: &crate::state::app_state::AppState) -> Vec<ActionDefinition> {
        actions()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![CONNECTED_EVENT.clone(), RESPONSE_EVENT.clone()]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        let p =
            |name: &str, kind: &str, description: &str, example: Value, default: Option<Value>| {
                ParameterDefinition {
                    name: name.into(),
                    type_hint: kind.into(),
                    description: description.into(),
                    required: false,
                    example,
                    default,
                }
            };
        vec![
            p(
                "scheme",
                "string",
                "URL scheme to reach the service with: https (default) or http",
                json!("http"),
                Some(json!(super::DEFAULT_SCHEME)),
            ),
            p(
                "base_path",
                "string",
                "Path the service's SCIM endpoints live under (empty for the root)",
                json!("/scim/v2"),
                Some(json!(crate::server::scim::DEFAULT_BASE_PATH)),
            ),
            p(
                "bearer_token",
                "string",
                "Token sent as Authorization: Bearer",
                json!("s3cr3t"),
                None,
            ),
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation("Shared http_fetch client (reqwest natively, no redirects); application/scim+json; ServiceProviderConfig and ResourceTypes discovery; filters and PATCH paths checked with the server's own parser; ListResponse and SCIM errors parsed")
            .llm_control("Which resources to query, create, change or delete, and what to do with each answer")
            .e2e_testing("tests/client/scim: scim2-server 0.4.0 (independent) answers discovery, create, filtered and sorted lists, get, PATCH, PUT, a uniqueness conflict and delete")
            .notes("No Bulk or /Me; one request at a time; 1 MiB answers.")
            .max_inbound_bytes(model_bounds::MAX_BODY_BYTES)
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Provision user bjensen into the SCIM service at 127.0.0.1:8080 and add her to Engineering"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let llm = json!({"type":"open_client","protocol":"scim","remote_addr":"127.0.0.1:8080","instruction":"List all users","startup_params":{"scheme":"http"}});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([
            {"event_pattern":"scim_connected","handler":{"type":"static","actions":[list_action().example]}},
            {"event_pattern":"scim_response","handler":{"type":"static","actions":[]}}
        ]);
        let mut scripted = static_example.clone();
        scripted["event_handlers"][1]["handler"] = json!({"type":"script","language":"python","code":"import json\nprint(json.dumps({'actions':[]}))"});
        crate::llm::actions::StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Authentication"
    }
}

impl Client for ScimClientProtocol {
    fn connect(
        &self,
        ctx: ConnectContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::connect(ctx))
    }
    fn execute_action(&self, v: Value) -> Result<ClientActionResult> {
        let ty = v["type"].as_str().unwrap_or_default();
        if ty == "disconnect" {
            return Ok(ClientActionResult::Disconnect);
        }
        ensure!(
            matches!(
                ty,
                "scim_list"
                    | "scim_get"
                    | "scim_create"
                    | "scim_replace"
                    | "scim_patch"
                    | "scim_delete"
            ),
            "Unknown SCIM client action"
        );
        let rt = v["resource_type"]
            .as_str()
            .context("resource_type is required")?;
        ensure!(
            !rt.is_empty() && rt.len() <= 64 && rt.bytes().all(|b| b.is_ascii_alphanumeric()),
            "resource_type is an endpoint name like Users"
        );
        ensure!(
            model_bounds::budget_ok(&v),
            "action exceeds the SCIM bounds"
        );
        if matches!(
            ty,
            "scim_get" | "scim_replace" | "scim_patch" | "scim_delete"
        ) {
            ensure!(
                v["id"]
                    .as_str()
                    .is_some_and(|i| !i.is_empty() && i.len() <= 256 && !i.contains('/')),
                "id is required"
            );
        }
        match ty {
            "scim_list" => {
                if let Some(f) = v["filter"].as_str() {
                    query::parse_filter(f)?;
                }
                if let Some(s) = v["sort_by"].as_str() {
                    query::AttrPath::parse(s)?;
                }
                query::parse_list(v["attributes"].as_str())?;
                if let Some(o) = v["sort_order"].as_str() {
                    ensure!(
                        o == "ascending" || o == "descending",
                        "sort_order is ascending or descending"
                    );
                }
            }
            "scim_create" | "scim_replace" => {
                ensure!(v["resource"].is_object(), "resource must be an object")
            }
            "scim_patch" => {
                let ops = v["operations"]
                    .as_array()
                    .filter(|o| !o.is_empty() && o.len() <= model_bounds::MAX_PATCH_OPERATIONS)
                    .context("operations must hold 1..64 operations")?;
                for o in ops {
                    let op = o["op"]
                        .as_str()
                        .map(str::to_ascii_lowercase)
                        .context("each operation needs op")?;
                    ensure!(
                        matches!(op.as_str(), "add" | "remove" | "replace"),
                        "op is add, remove or replace"
                    );
                    if let Some(p) = o["path"].as_str() {
                        query::PatchPath::parse(p)?;
                    } else if op == "remove" {
                        bail!("remove needs a path");
                    }
                }
            }
            _ => {}
        }
        Ok(ClientActionResult::Custom {
            name: ty.into(),
            data: v,
        })
    }
}
