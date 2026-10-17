use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, ParameterDefinition,
};
use crate::protocol::{ConnectContext, EventType};
use crate::server::redfish::actions::{action, parameter};
use crate::server::redfish::model;
use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

#[derive(Default)]
pub struct RedfishClientProtocol;
impl RedfishClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

fn path_param() -> crate::llm::actions::Parameter {
    parameter(
        "path",
        "string",
        "Resource path under /redfish/v1, e.g. /redfish/v1/Systems/1",
        true,
    )
}
fn get_action() -> ActionDefinition {
    action(
        "redfish_get",
        "Read a resource or collection (GET)",
        vec![path_param()],
        json!({"type":"redfish_get","path":"/redfish/v1/Systems"}),
    )
}
fn patch_action() -> ActionDefinition {
    action(
        "redfish_patch",
        "Change writable properties of a resource (PATCH); a 202 task is followed to its end",
        vec![
            path_param(),
            parameter(
                "body",
                "object",
                "Properties to change, e.g. {\"AssetTag\": \"rack-7\"}",
                true,
            ),
            parameter(
                "if_match",
                "string",
                "Optional ETag to send as If-Match",
                false,
            ),
        ],
        json!({"type":"redfish_patch","path":"/redfish/v1/Systems/1","body":{"AssetTag":"rack-7"}}),
    )
}
fn post_action() -> ActionDefinition {
    action(
        "redfish_post",
        "POST a body to a collection (create) or an action target; a 202 task is followed to its end",
        vec![
            path_param(),
            parameter("body", "object", "Request body, e.g. {\"UserName\": \"ops\", \"Password\": \"...\", \"RoleId\": \"Operator\"}", true),
        ],
        json!({"type":"redfish_post","path":"/redfish/v1/AccountService/Accounts","body":{"UserName":"ops","Password":"changeme","RoleId":"Operator"}}),
    )
}
fn delete_action() -> ActionDefinition {
    action(
        "redfish_delete",
        "Delete a resource (DELETE)",
        vec![path_param()],
        json!({"type":"redfish_delete","path":"/redfish/v1/AccountService/Accounts/3"}),
    )
}
fn invoke_action() -> ActionDefinition {
    action(
        "redfish_action",
        "Invoke an action a resource advertises: Rust reads the resource, finds the action's target in its Actions and POSTs the parameters there",
        vec![
            parameter("resource_path", "string", "The resource owning the action, e.g. /redfish/v1/Systems/1", true),
            parameter("action", "string", "Action name without the #, e.g. ComputerSystem.Reset", true),
            parameter("parameters", "object", "Action parameters, e.g. {\"ResetType\": \"ForceRestart\"}", false),
        ],
        json!({"type":"redfish_action","resource_path":"/redfish/v1/Systems/1","action":"ComputerSystem.Reset","parameters":{"ResetType":"GracefulRestart"}}),
    )
}
fn disconnect_action() -> ActionDefinition {
    action(
        "disconnect",
        "Log out (deleting the session) and stop this Redfish client",
        vec![],
        json!({"type":"disconnect"}),
    )
}
fn actions() -> Vec<ActionDefinition> {
    vec![
        get_action(),
        patch_action(),
        post_action(),
        delete_action(),
        invoke_action(),
        disconnect_action(),
    ]
}

pub static CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "redfish_connected",
        "The service root was read (and the client logged in when credentials were given)",
        get_action().example.clone(),
    )
    .with_parameters(vec![
        parameter(
            "redfish_version",
            "string",
            "RedfishVersion from the service root",
            false,
        ),
        parameter("product", "string", "Product from the service root", false),
        parameter("vendor", "string", "Vendor from the service root", false),
        parameter(
            "links",
            "object",
            "Top-level resources the service root links to, name → path",
            true,
        ),
        parameter("authenticated", "string", "session, basic or none", true),
    ])
    .with_actions(actions())
});
pub static RESPONSE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "redfish_response",
        "The service's answer to the last request",
        disconnect_action().example.clone(),
    )
    .with_parameters(vec![
        parameter("method", "string", "HTTP method sent", true),
        parameter(
            "path",
            "string",
            "Path the request went to (the action target for redfish_action)",
            true,
        ),
        parameter(
            "status",
            "number",
            "HTTP status (the final one when a task was followed)",
            true,
        ),
        parameter("body", "object", "Response body, when there was one", false),
        parameter(
            "location",
            "string",
            "Location header (created resource or task monitor)",
            false,
        ),
        parameter(
            "error",
            "object",
            "Redfish error: {message_id, message} from the error body",
            false,
        ),
        parameter(
            "task",
            "object",
            "The followed task: {state, messages, monitor}",
            false,
        ),
    ])
    .with_actions(actions())
});

impl Protocol for RedfishClientProtocol {
    fn protocol_name(&self) -> &'static str {
        "Redfish"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>HTTP>Redfish"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["redfish", "bmc", "dmtf", "redfish client"]
    }
    fn description(&self) -> &'static str {
        "Redfish client: reads the service root, logs in, reads and changes resources, invokes actions and follows tasks"
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
                "https (BMCs) or http",
                json!("http"),
                Some(json!(super::DEFAULT_SCHEME)),
            ),
            p(
                "username",
                "string",
                "Account to log in with; without it the client stays anonymous",
                json!("admin"),
                None,
            ),
            p(
                "password",
                "string",
                "Password for username",
                json!("secret"),
                None,
            ),
            p(
                "auth_method",
                "string",
                "session (POST SessionService/Sessions, X-Auth-Token) or basic",
                json!("basic"),
                Some(json!(super::DEFAULT_AUTH_METHOD)),
            ),
            p(
                "insecure",
                "boolean",
                "Accept a self-signed BMC certificate over https",
                json!(true),
                Some(json!(super::DEFAULT_INSECURE)),
            ),
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation("Shared http_fetch client (reqwest natively, no redirects); service root, session or Basic auth, OData-Version 4.0, Redfish error bodies parsed, action targets read from the resource, 202 task monitors polled to completion")
            .llm_control("Which resources to read, what to change, which actions to invoke and what to do with each answer")
            .e2e_testing("tests/client/redfish: DMTF Redfish-Mockup-Server 1.3.0 (independent) with its public-rackmount1 mockup: login, systems, a PATCH, a reset action, a 404")
            .notes("No $expand/$select, ETag caching or event subscriptions. disconnect deletes the session; a client stopped from outside leaves it to expire. 1 MiB answers; task monitors are followed for up to 60 s.")
            .max_inbound_bytes(model::MAX_BODY_BYTES)
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Log in to the BMC at 10.0.0.5 as admin and power-cycle Systems/1"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let llm = json!({"type":"open_client","protocol":"redfish","remote_addr":"10.0.0.5:443","instruction":"List the systems and their power state","startup_params":{"username":"admin","password":"secret","insecure":true}});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([
            {"event_pattern":"redfish_connected","handler":{"type":"static","actions":[get_action().example]}},
            {"event_pattern":"redfish_response","handler":{"type":"static","actions":[]}}
        ]);
        let mut scripted = static_example.clone();
        scripted["event_handlers"][1]["handler"] = json!({"type":"script","language":"python","code":"import json\nprint(json.dumps({'actions':[]}))"});
        crate::llm::actions::StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Network Management"
    }
}

impl Client for RedfishClientProtocol {
    fn connect(
        &self,
        ctx: ConnectContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::connect(ctx))
    }
    fn execute_action(&self, v: Value) -> Result<ClientActionResult> {
        let path = |k: &str| -> Result<()> {
            let p = v[k].as_str().with_context(|| format!("{k} is required"))?;
            ensure!(
                model::normalize(p).is_some(),
                "{k} must be a path under /redfish/v1"
            );
            Ok(())
        };
        match v["type"].as_str() {
            Some("redfish_get" | "redfish_delete") => path("path")?,
            Some("redfish_patch" | "redfish_post") => {
                path("path")?;
                ensure!(
                    v["body"].is_object() && model::budget_ok(&v["body"]),
                    "body must be a JSON object within bounds"
                );
                if let Some(e) = v.get("if_match").filter(|e| !e.is_null()) {
                    ensure!(
                        e.as_str().is_some_and(
                            |e| e.len() <= 256 && !crate::utils::sanitize::has_controls(&e)
                        ),
                        "if_match must be text"
                    );
                }
            }
            Some("redfish_action") => {
                path("resource_path")?;
                let a = v["action"].as_str().context("action is required")?;
                ensure!(
                    a.split('.').count() == 2
                        && a.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.'),
                    "action is Namespace.Action, e.g. ComputerSystem.Reset"
                );
                if let Some(p) = v.get("parameters").filter(|p| !p.is_null()) {
                    ensure!(
                        p.is_object() && model::budget_ok(p),
                        "parameters must be a JSON object"
                    );
                }
            }
            Some("disconnect") => return Ok(ClientActionResult::Disconnect),
            _ => bail!("Unknown Redfish client action"),
        }
        Ok(ClientActionResult::Custom {
            name: v["type"].as_str().unwrap_or_default().into(),
            data: v,
        })
    }
}
