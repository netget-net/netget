use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, Parameter, ParameterDefinition,
};
use crate::protocol::{ConnectContext, EventType};
use crate::server::restconf::actions::{action, parameter};
use crate::server::restconf::path;
use anyhow::{bail, ensure, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

#[derive(Default)]
pub struct RestconfClientProtocol;
impl RestconfClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

fn path_param() -> Parameter {
    parameter(
        "path",
        "string",
        "Data resource under data/, e.g. example:car/tire=1 (empty for the whole datastore)",
        true,
    )
}
fn data_param() -> Parameter {
    parameter(
        "data",
        "object",
        "YANG JSON body, e.g. {\"example:speed\": 30}",
        true,
    )
}

pub fn all_actions() -> Vec<ActionDefinition> {
    vec![
        action(
            "restconf_get",
            "Read a data resource",
            vec![
                path_param(),
                parameter(
                    "depth",
                    "string",
                    "Subtree depth, 1-65535 or unbounded",
                    false,
                ),
                parameter("content", "string", "all, config or nonconfig", false),
                parameter(
                    "fields",
                    "string",
                    "Fields selector, e.g. speed;tire/pos",
                    false,
                ),
            ],
            json!({"type": "restconf_get", "path": "example:car"}),
        ),
        action(
            "restconf_put",
            "Create or replace a data resource",
            vec![path_param(), data_param()],
            json!({"type": "restconf_put", "path": "example:car/speed", "data": {"example:speed": 30}}),
        ),
        action(
            "restconf_post",
            "Create a child of a data resource",
            vec![path_param(), data_param()],
            json!({"type": "restconf_post", "path": "example:car", "data": {"example:tire": [{"pos": 4}]}}),
        ),
        action(
            "restconf_patch",
            "Merge into a data resource",
            vec![path_param(), data_param()],
            json!({"type": "restconf_patch", "path": "example:car", "data": {"example:car": {"speed": 40}}}),
        ),
        action(
            "restconf_delete",
            "Delete a data resource",
            vec![path_param()],
            json!({"type": "restconf_delete", "path": "example:car/tire=4"}),
        ),
        action(
            "restconf_invoke",
            "Invoke an RPC under operations/",
            vec![
                parameter(
                    "operation",
                    "string",
                    "module:rpc, e.g. example:reset",
                    true,
                ),
                parameter(
                    "input",
                    "object",
                    "The input leaves (Rust wraps them as module:input)",
                    false,
                ),
            ],
            json!({"type": "restconf_invoke", "operation": "example:reset", "input": {"speed": 0}}),
        ),
        action(
            "disconnect",
            "Stop the client",
            vec![],
            json!({"type": "disconnect"}),
        ),
    ]
}

pub static CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "restconf_connected",
        "Discovered the RESTCONF root and its YANG library",
        json!({"type": "restconf_get", "path": ""}),
    )
    .with_parameters(vec![
        parameter(
            "root",
            "string",
            "The RESTCONF root found through host-meta, e.g. /restconf",
            true,
        ),
        parameter(
            "yang_library_version",
            "string",
            "The server's yang-library-version",
            false,
        ),
        parameter(
            "modules",
            "array",
            "The modules the server implements: [{name, revision, namespace}]",
            true,
        ),
    ])
    .with_actions(all_actions())
});
pub static RESPONSE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "restconf_response",
        "The server answered a request",
        json!({"type": "restconf_get", "path": ""}),
    )
    .with_parameters(vec![
        parameter("method", "string", "The HTTP method sent", true),
        parameter("path", "string", "The resource or operation", true),
        parameter("status", "number", "The HTTP status", true),
        parameter(
            "data",
            "object",
            "The YANG JSON body of a successful answer",
            false,
        ),
        parameter(
            "errors",
            "array",
            "The RFC 8040 errors: [{error-type, error-tag, error-message, error-path}]",
            false,
        ),
        parameter(
            "location",
            "string",
            "Location of a created resource",
            false,
        ),
    ])
    .with_actions(all_actions())
});

impl Protocol for RestconfClientProtocol {
    fn protocol_name(&self) -> &'static str {
        "RESTCONF"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>HTTP>RESTCONF"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["restconf", "restconf client", "rfc8040", "yang"]
    }
    fn description(&self) -> &'static str {
        "RESTCONF client: discovers a server's root and YANG library, reads and edits data resources and invokes operations"
    }
    fn get_async_actions(&self, _: &crate::state::app_state::AppState) -> Vec<ActionDefinition> {
        all_actions()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![CONNECTED_EVENT.clone(), RESPONSE_EVENT.clone()]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "username".into(),
                type_hint: "string".into(),
                description: "HTTP Basic user, if the server needs one".into(),
                required: false,
                example: json!("admin"),
                default: None,
            },
            ParameterDefinition {
                name: "password".into(),
                type_hint: "string".into(),
                description: "HTTP Basic password".into(),
                required: false,
                example: json!("secret"),
                default: None,
            },
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation("RFC 8040 over the shared HTTP fetch client: host-meta discovery (XRD or JSON), the API root, yang-library-version and ietf-yang-library modules-state, JSON data requests and operations with RFC 8040 errors decoded")
            .llm_control("Which resources to read and edit and which operations to invoke")
            .e2e_testing("tests/client/restconf: a FreeCONF RESTCONF server (independent, Go) serving its car example: reads, edits, a missing resource and an operation")
            .notes("Plain HTTP only; JSON only; no event streams.")
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Read example:car from the RESTCONF server at 127.0.0.1:8080"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let llm = json!({"type":"open_client","protocol":"restconf","remote_addr":"127.0.0.1:8080","instruction":"Read the car's speed"});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([{"event_pattern":"restconf_connected","handler":{"type":"static","actions":[{"type":"restconf_get","path":"example:car"}]}}]);
        let mut scripted = llm.clone();
        scripted["event_handlers"] = json!([{"event_pattern":"restconf_connected","handler":{"type":"script","language":"python","code":"import json,sys\ne=json.load(sys.stdin)['event']\nm=e['modules'][0]['name'] if e['modules'] else 'example'\nprint(json.dumps({'actions':[{'type':'restconf_get','path':m+':'}]}))"}}]);
        crate::llm::actions::StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Network Management"
    }
}

/// A path as the client will put it in a URL: parseable, and free of characters a URL would
/// need escaped outside key values.
pub fn check_path(p: &str, allow_empty: bool) -> Result<()> {
    if p.is_empty() {
        ensure!(allow_empty, "path names a resource");
        return Ok(());
    }
    path::parse(p)?;
    ensure!(
        !p.contains(['?', '#', ' ']) && !crate::utils::sanitize::has_controls(&p),
        "path has no ?, # or spaces (percent-encode key values)"
    );
    Ok(())
}

impl Client for RestconfClientProtocol {
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
            Some("restconf_get") => check_path(v["path"].as_str().unwrap_or_default(), true)?,
            Some("restconf_delete") => check_path(v["path"].as_str().unwrap_or_default(), false)?,
            Some("restconf_put" | "restconf_post" | "restconf_patch") => {
                check_path(
                    v["path"].as_str().unwrap_or_default(),
                    v["type"] == "restconf_post",
                )?;
                ensure!(v["data"].is_object(), "data is a YANG JSON object");
            }
            Some("restconf_invoke") => {
                let op = v["operation"].as_str().unwrap_or_default();
                ensure!(
                    path::parse(op).is_ok_and(|s| s.len() == 1 && s[0].keys.is_none()),
                    "operation is module:rpc"
                );
                ensure!(
                    v.get("input").is_none_or(|i| i.is_null() || i.is_object()),
                    "input is an object"
                );
            }
            _ => bail!("Unknown RESTCONF client action"),
        }
        Ok(ClientActionResult::Custom {
            name: v["type"].as_str().unwrap_or_default().into(),
            data: v,
        })
    }
}
