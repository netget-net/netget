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

use super::wire;

#[derive(Default)]
pub struct ConsulProtocol;
impl ConsulProtocol {
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

fn entries_action() -> ActionDefinition {
    action(
        "consul_kv_entries",
        "Answer a KV read with the entries under the key (one for a plain read; every key under the prefix when recurse or keys_only).",
        vec![parameter("entries", "array", "Each {key, value (text), encoding? utf8|hex, flags?, modify_index?}", true)],
        json!({"type":"consul_kv_entries","entries":[{"key":"app/config","value":"hello world"}]}),
        "-> Consul KV {preview(entries,100)}",
    )
}

fn not_found_action() -> ActionDefinition {
    action(
        "consul_not_found",
        "The key (or nothing under the prefix) does not exist: 404.",
        vec![],
        json!({"type":"consul_not_found"}),
        "-> Consul 404",
    )
}

fn ok_action() -> ActionDefinition {
    action(
        "consul_ok",
        "Accept the write, delete or registration (Consul answers true / 200).",
        vec![],
        json!({"type":"consul_ok"}),
        "-> Consul ok",
    )
}

fn refuse_action() -> ActionDefinition {
    action(
        "consul_refuse",
        "Refuse a KV write or delete the way Consul refuses a failed check-and-set: 200 with false.",
        vec![],
        json!({"type":"consul_refuse"}),
        "-> Consul false",
    )
}

fn error_action() -> ActionDefinition {
    action(
        "consul_error",
        "Fail the request with an HTTP status and a plain-text message.",
        vec![
            parameter("status", "number", "400, 403, 404 or 500", true),
            parameter(
                "message",
                "string",
                "Plain-text explanation, at most 1024 bytes",
                true,
            ),
        ],
        json!({"type":"consul_error","status":403,"message":"Permission denied"}),
        "-> Consul {status} {message}",
    )
}

fn services_action() -> ActionDefinition {
    action(
        "consul_services",
        "Answer /v1/catalog/services with every service name and its tags.",
        vec![parameter(
            "services",
            "object",
            "Service name to its tags, e.g. {\"web\": [\"v1\"]}",
            true,
        )],
        json!({"type":"consul_services","services":{"web":["v1"],"db":[]}}),
        "-> Consul services {preview(services,100)}",
    )
}

fn instances_action() -> ActionDefinition {
    action(
        "consul_instances",
        "Answer a service query with its instances; node, datacenter and health fields are filled in.",
        vec![parameter("instances", "array", "Each {id?, name, address?, port?, tags?, meta?}", true)],
        json!({"type":"consul_instances","instances":[{"id":"web1","name":"web","address":"127.0.0.1","port":8080,"tags":["v1"]}]}),
        "-> Consul instances {preview(instances,100)}",
    )
}

pub static KV_READ_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "consul_kv_read",
        "A client read the KV store (GET /v1/kv/<key>). NetGet stores nothing: answer from what you hold.",
        entries_action().example.clone(),
    )
    .with_parameters(vec![
        parameter("key", "string", "The key, or the prefix with recurse/keys_only", true),
        parameter("recurse", "boolean", "Every entry under the prefix is wanted", true),
        parameter("keys_only", "boolean", "Only the keys under the prefix are wanted", true),
    ])
    .with_actions(vec![entries_action(), not_found_action(), error_action()])
});

pub static KV_WRITE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "consul_kv_write",
        "A client wrote a key (PUT /v1/kv/<key>). Remember it and accept, or refuse.",
        ok_action().example.clone(),
    )
    .with_parameters(vec![
        parameter("key", "string", "The key written", true),
        parameter(
            "value",
            "string",
            "The value (text, or hex per value_encoding)",
            true,
        ),
        parameter(
            "value_encoding",
            "string",
            "How value is shown: utf8 or hex",
            true,
        ),
        parameter(
            "flags",
            "number",
            "Opaque client flags stored with the value",
            true,
        ),
        parameter(
            "cas",
            "number",
            "Check-and-set index: write only if the key's modify index is this (0: only if absent)",
            false,
        ),
    ])
    .with_actions(vec![ok_action(), refuse_action(), error_action()])
});

pub static KV_DELETE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "consul_kv_delete",
        "A client deleted a key or prefix (DELETE /v1/kv/<key>).",
        ok_action().example.clone(),
    )
    .with_parameters(vec![
        parameter("key", "string", "The key or prefix deleted", true),
        parameter(
            "recurse",
            "boolean",
            "Everything under the prefix goes",
            true,
        ),
        parameter("cas", "number", "Check-and-set index, if given", false),
    ])
    .with_actions(vec![ok_action(), refuse_action(), error_action()])
});

pub static CATALOG_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "consul_catalog",
        "A client asked about services: services (all names), service or health (one service's instances), agent_services (this agent's).",
        instances_action().example.clone(),
    )
    .with_parameters(vec![
        parameter("endpoint", "string", "services, service, health or agent_services", true),
        parameter("name", "string", "The service asked about, for service and health", false),
    ])
    .with_actions(vec![services_action(), instances_action(), error_action()])
});

pub static REGISTER_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "consul_register",
        "A client registered (or deregistered) a service with the agent.",
        ok_action().example.clone(),
    )
    .with_parameters(vec![
        parameter("operation", "string", "register or deregister", true),
        parameter(
            "service",
            "object",
            "For register: {id, name, address, port, tags, meta}",
            false,
        ),
        parameter("id", "string", "For deregister: the service ID", false),
    ])
    .with_actions(vec![ok_action(), error_action()])
});

pub fn check_error(v: &Value) -> Result<()> {
    let status = v["status"].as_u64().context("status required")?;
    ensure!(
        [400, 403, 404, 500].contains(&status),
        "status must be 400, 403, 404 or 500"
    );
    let m = v["message"].as_str().context("message required")?;
    ensure!(
        m.len() <= 1024 && !crate::utils::sanitize::has_controls(m),
        "message at most 1024 bytes without control characters"
    );
    Ok(())
}

impl Protocol for ConsulProtocol {
    fn protocol_name(&self) -> &'static str {
        "Consul"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>HTTP>Consul"
    }
    fn description(&self) -> &'static str {
        "Consul agent HTTP API: KV store, catalog, health and service registration, answered by the handler"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "consul",
            "service discovery",
            "consul kv",
            "hashicorp consul",
        ]
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            entries_action(),
            not_found_action(),
            ok_action(),
            refuse_action(),
            error_action(),
            services_action(),
            instances_action(),
        ]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            KV_READ_EVENT.clone(),
            KV_WRITE_EVENT.clone(),
            KV_DELETE_EVENT.clone(),
            CATALOG_EVENT.clone(),
            REGISTER_EVENT.clone(),
        ]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .well_known_port(8500)
            .implementation("HTTP/1.1 via hyper: /v1/kv (get, recurse, keys, raw, put with flags and cas, delete), /v1/catalog/services|service|nodes|datacenters, /v1/health/service, /v1/agent/self|services|service/register|service/deregister, /v1/status/leader|peers; Consul's JSON shapes, base64 values and X-Consul-Index")
            .llm_control("Every KV answer and write decision, every catalog and health answer, and every service registration — NetGet stores nothing")
            .e2e_testing("tests/server/consul: the official consul CLI (Go api client) and py-consul as independent clients; raw HTTP for bounds and refusals")
            .notes("No blocking queries (a wait returns at once), no sessions or locks, no ACLs, no Connect, no DNS interface, no watches. Bodies are capped at 512 KiB (Consul's own KV value limit), listings at 10 000 entries. One request per connection. A handler failure is a 500 with a generic message, never a fabricated value.")
            .request_only("Every response answers an HTTP request")
            .answers_on_failure()
            .max_inbound_bytes(wire::MAX_VALUE_BYTES)
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Consul agent on port 8500 holding service registrations and KV config in memory"
    }
    fn get_startup_examples(&self) -> StartupExamples {
        let llm = json!({"type":"open_server","base_stack":"consul","port":8500,"instruction":"Keep KV and services in memory; app/config is 'hello'"});
        let mut scripted = llm.clone();
        scripted["event_handlers"] = json!([{"event_pattern":"consul_kv_read","handler":{"type":"script","language":"python","code":"import json,sys\ne=json.load(sys.stdin)['event']\na={'type':'consul_kv_entries','entries':[{'key':e['key'],'value':'hello'}]}\nprint(json.dumps({'actions':[a]}))"}}]);
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([{"event_pattern":"consul_kv_write","handler":{"type":"static","actions":[{"type":"consul_ok"}]}}]);
        StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Network Services"
    }
}

impl Server for ConsulProtocol {
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
            "consul_not_found" | "consul_ok" | "consul_refuse" => {}
            "consul_error" => check_error(&v)?,
            "consul_kv_entries" => {
                let entries = v["entries"]
                    .as_array()
                    .context("entries must be an array")?;
                ensure!(entries.len() <= wire::MAX_ENTRIES, "too many entries");
                for e in entries {
                    wire::kv_entry(e, 1)?;
                }
            }
            "consul_services" => ensure!(v["services"].is_object(), "services must be an object"),
            "consul_instances" => {
                let list = v["instances"]
                    .as_array()
                    .context("instances must be an array")?;
                ensure!(list.len() <= wire::MAX_ENTRIES, "too many instances");
                for i in list {
                    wire::instance(i)?;
                }
            }
            _ => bail!("Unknown Consul server action"),
        }
        Ok(ActionResult::Custom { name, data: v })
    }
}
