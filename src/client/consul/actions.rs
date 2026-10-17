use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, ParameterDefinition, StartupExamples,
};
use crate::protocol::{ConnectContext, EventType};
use crate::server::consul::{
    actions::{action, parameter},
    wire,
};
use crate::state::app_state::AppState;
use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

#[derive(Default)]
pub struct ConsulClientProtocol;
impl ConsulClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

fn get_action() -> ActionDefinition {
    action(
        "consul_kv_get",
        "Read a key (or every key under a prefix with recurse, or only key names with keys_only).",
        vec![
            parameter("key", "string", "The key or prefix, e.g. app/config", true),
            parameter(
                "recurse",
                "boolean",
                "Read every entry under the prefix",
                false,
            ),
            parameter(
                "keys_only",
                "boolean",
                "List only the key names under the prefix",
                false,
            ),
        ],
        json!({"type":"consul_kv_get","key":"app/config"}),
        "-> Consul GET kv/{key}",
    )
}

fn put_action() -> ActionDefinition {
    action(
        "consul_kv_put",
        "Write a key; with cas, only if its modify index matches (0: only if absent).",
        vec![
            parameter("key", "string", "The key to write", true),
            parameter(
                "value",
                "string",
                "The value, as text (or hex with encoding hex)",
                true,
            ),
            parameter("encoding", "string", "utf8 (default) or hex", false),
            parameter(
                "flags",
                "number",
                "Opaque flags stored with the value",
                false,
            ),
            parameter("cas", "number", "Check-and-set modify index", false),
        ],
        json!({"type":"consul_kv_put","key":"app/config","value":"hello"}),
        "-> Consul PUT kv/{key}",
    )
}

fn delete_action() -> ActionDefinition {
    action(
        "consul_kv_delete",
        "Delete a key, or everything under a prefix with recurse.",
        vec![
            parameter("key", "string", "The key or prefix to delete", true),
            parameter(
                "recurse",
                "boolean",
                "Delete everything under the prefix",
                false,
            ),
        ],
        json!({"type":"consul_kv_delete","key":"app/config"}),
        "-> Consul DELETE kv/{key}",
    )
}

fn catalog_action() -> ActionDefinition {
    action(
        "consul_catalog",
        "Ask about services: services (all names and tags), service or health (one service's instances), nodes, agent_services.",
        vec![
            parameter("endpoint", "string", "services, service, health, nodes or agent_services", true),
            parameter("name", "string", "The service, for service and health", false),
        ],
        json!({"type":"consul_catalog","endpoint":"services"}),
        "-> Consul catalog {endpoint}",
    )
}

fn register_action() -> ActionDefinition {
    action(
        "consul_register_service",
        "Register a service with the agent.",
        vec![
            parameter(
                "name",
                "string",
                "The name the service is registered under",
                true,
            ),
            parameter("id", "string", "Service ID (defaults to the name)", false),
            parameter(
                "address",
                "string",
                "The address the service listens on",
                false,
            ),
            parameter("port", "number", "The port the service listens on", false),
            parameter(
                "tags",
                "array",
                "Tags to attach to the service, e.g. [\"v1\"]",
                false,
            ),
        ],
        json!({"type":"consul_register_service","name":"web","port":8080,"tags":["v1"]}),
        "-> Consul register {name}",
    )
}

fn deregister_action() -> ActionDefinition {
    action(
        "consul_deregister_service",
        "Remove a service registration from the agent.",
        vec![parameter("id", "string", "The service ID to remove", true)],
        json!({"type":"consul_deregister_service","id":"web"}),
        "-> Consul deregister {id}",
    )
}

fn disconnect_action() -> ActionDefinition {
    action(
        "disconnect",
        "End this Consul client session.",
        vec![],
        json!({"type":"disconnect"}),
        "-> Consul disconnect",
    )
}

pub fn actions() -> Vec<ActionDefinition> {
    vec![
        get_action(),
        put_action(),
        delete_action(),
        catalog_action(),
        register_action(),
        deregister_action(),
        disconnect_action(),
    ]
}

pub static CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "consul_connected",
        "The client is ready; each request opens its own HTTP connection.",
        get_action().example.clone(),
    )
    .with_parameters(vec![parameter(
        "remote_addr",
        "string",
        "The Consul agent's HTTP origin",
        true,
    )])
    .with_actions(actions())
});

pub static RESPONSE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new("consul_response", "The agent answered a request.", catalog_action().example.clone())
        .with_parameters(vec![
            parameter("operation", "string", "The action that was performed", true),
            parameter("status", "number", "The HTTP status the agent answered with", true),
            parameter("result", "any", "KV entries {key, value, encoding, flags, modify_index}, key names, true/false, services or instances", true),
            parameter("index", "number", "X-Consul-Index of the answer", true),
            parameter("message", "string", "The agent's error text, when the status is not 200", true),
        ])
        .with_actions(actions())
});

impl Protocol for ConsulClientProtocol {
    fn protocol_name(&self) -> &'static str {
        "Consul"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>HTTP>Consul"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["consul", "consul kv", "service discovery"]
    }
    fn description(&self) -> &'static str {
        "Consul HTTP API client: KV, catalog, health and service registration"
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        actions()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![CONNECTED_EVENT.clone(), RESPONSE_EVENT.clone()]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation("HTTP/1.1 via hyper, one connection per request: /v1/kv get/put/delete, catalog, health, agent service register/deregister; base64 values decoded for the handler")
            .llm_control("Which keys to read and write, which services to look up or register, and what to do with each answer")
            .e2e_testing("tests/client/consul: NetGet's own agent; the official consul agent (-dev), read back with the consul CLI")
            .notes("No blocking queries, sessions, ACL tokens or TLS. Answers are capped at 1 MiB. A handler chain stops after 8 follow-ups.")
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Write app/config=hello to the Consul agent at 127.0.0.1:8500 and list its services"
    }
    fn get_startup_examples(&self) -> StartupExamples {
        let llm = json!({"type":"open_client","protocol":"consul","remote_addr":"127.0.0.1:8500","instruction":"Store app/config=hello, then read it back"});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([{"event_pattern":"consul_connected","handler":{"type":"static","actions":[{"type":"consul_kv_put","key":"app/config","value":"hello"}]}}]);
        let mut scripted = llm.clone();
        scripted["event_handlers"] = json!([{"event_pattern":"consul_response","handler":{"type":"script","language":"python","code":"import json,sys\ne=json.load(sys.stdin)['event']\na=[{'type':'consul_kv_get','key':'app/config'}] if e['operation']=='consul_kv_put' else []\nprint(json.dumps({'actions':a}))"}}]);
        StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Network Services"
    }
}

/// The request one action makes: method, path and body.
pub fn request(v: &Value) -> Result<(&'static str, String, Option<Vec<u8>>)> {
    let enc = |s: &str| urlencoding::encode(s).into_owned().replace("%2F", "/");
    let key = || -> Result<String> {
        let k = v["key"].as_str().context("key required")?;
        wire::check_key(k)?;
        ensure!(
            !k.is_empty() || v["recurse"] == true || v["keys_only"] == true,
            "key required"
        );
        Ok(enc(k))
    };
    Ok(match v["type"].as_str().unwrap_or_default() {
        "consul_kv_get" => {
            let mut p = format!("/v1/kv/{}", key()?);
            if v["keys_only"] == true {
                p.push_str("?keys");
            } else if v["recurse"] == true {
                p.push_str("?recurse");
            }
            ("GET", p, None)
        }
        "consul_kv_put" => {
            let mut q = Vec::new();
            if let Some(f) = v["flags"].as_u64() {
                q.push(format!("flags={f}"));
            }
            if let Some(c) = v["cas"].as_u64() {
                q.push(format!("cas={c}"));
            }
            let mut p = format!("/v1/kv/{}", key()?);
            if !q.is_empty() {
                p.push('?');
                p.push_str(&q.join("&"));
            }
            ("PUT", p, Some(wire::value_bytes(v)?))
        }
        "consul_kv_delete" => {
            let mut p = format!("/v1/kv/{}", key()?);
            if v["recurse"] == true {
                p.push_str("?recurse");
            }
            ("DELETE", p, None)
        }
        "consul_catalog" => {
            let name = || -> Result<String> {
                let n = v["name"]
                    .as_str()
                    .context("name required for this endpoint")?;
                ensure!(!n.is_empty(), "name required");
                Ok(enc(n))
            };
            let p = match v["endpoint"].as_str().unwrap_or_default() {
                "services" => "/v1/catalog/services".to_string(),
                "nodes" => "/v1/catalog/nodes".to_string(),
                "agent_services" => "/v1/agent/services".to_string(),
                "service" => format!("/v1/catalog/service/{}", name()?),
                "health" => format!("/v1/health/service/{}", name()?),
                e => bail!("unknown endpoint {e}"),
            };
            ("GET", p, None)
        }
        "consul_register_service" => {
            let i = wire::instance(v)?;
            let body = json!({"ID": i.id, "Name": i.name, "Address": i.address, "Port": i.port, "Tags": i.tags});
            (
                "PUT",
                "/v1/agent/service/register".into(),
                Some(body.to_string().into_bytes()),
            )
        }
        "consul_deregister_service" => {
            let id = v["id"].as_str().context("id required")?;
            ensure!(!id.is_empty(), "id required");
            (
                "PUT",
                format!("/v1/agent/service/deregister/{}", enc(id)),
                None,
            )
        }
        t => bail!("Unknown Consul client action {t}"),
    })
}

impl Client for ConsulClientProtocol {
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
        request(&v)?;
        Ok(ClientActionResult::Custom { name, data: v })
    }
}
