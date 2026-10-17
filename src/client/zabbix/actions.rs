//! What the model does as a Zabbix client: query an agent's item (what `zabbix_get` does) and
//! send values to a server or proxy trapper (what `zabbix_sender` does). Each is one ZBXD
//! request on its own connection, as Zabbix itself does it.
use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, Parameter, ParameterDefinition, StartupExamples,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::{ConnectContext, EventType};
use crate::server::zabbix::wire::MAX_ITEMS;
use crate::state::app_state::AppState;
use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

pub const GET: &str = "zabbix_get";
pub const SEND: &str = "zabbix_send";
/// A key or host at most, in bytes (Zabbix's own item key limit is 2048).
pub const MAX_KEY: usize = 2048;

#[derive(Default)]
pub struct ZabbixClientProtocol;
impl ZabbixClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

fn p(name: &str, kind: &str, description: &str, required: bool) -> Parameter {
    Parameter {
        name: name.into(),
        type_hint: kind.into(),
        description: description.into(),
        required,
    }
}

fn action(
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
        log_template: Some(LogTemplate::new().with_info(format!("-> Zabbix {name}"))),
    }
}

pub fn actions() -> Vec<ActionDefinition> {
    vec![
        action(GET, "Ask a Zabbix agent for an item's value (a passive check, as zabbix_get does).",
            vec![p("key", "string", "Item key, e.g. agent.ping, system.hostname, vfs.fs.size[/,free]", true)],
            json!({"type": GET, "key": "system.hostname"})),
        action(SEND, "Send values to a Zabbix server or proxy trapper (as zabbix_sender does); it answers how many it processed.",
            vec![p("values", "array", "[{host, key, value, clock?}]: the monitored host, the trapper item's key, the value as text, and optionally Unix seconds", true)],
            json!({"type": SEND, "values": [{"host": "web01", "key": "netget.status", "value": "ok"}]})),
        action("disconnect", "Stop the client (Zabbix keeps no connection open between requests).", vec![], json!({"type": "disconnect"})),
    ]
}

fn event(id: &str, description: &str, params: Vec<Parameter>) -> EventType {
    EventType::new(id, description, json!({"type": GET, "key": "agent.ping"}))
        .with_parameters(params)
        .with_actions(actions())
}

pub static READY_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event(
        "zabbix_ready",
        "The client is ready; nothing is sent until an action asks.",
        vec![p(
            "remote_addr",
            "string",
            "The agent, server or proxy every request goes to",
            true,
        )],
    )
});

pub static VALUE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event(
        "zabbix_value",
        "An agent answered a zabbix_get.",
        vec![
            p("key", "string", "The item key asked for", true),
            p(
                "supported",
                "boolean",
                "False when the agent answered ZBX_NOTSUPPORTED",
                true,
            ),
            p(
                "value",
                "string",
                "The item's value as the agent wrote it",
                false,
            ),
            p(
                "error",
                "string",
                "Why the agent could not answer, or why the request failed",
                false,
            ),
        ],
    )
});

pub static SENT_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event(
        "zabbix_sent",
        "A server or proxy answered a zabbix_send.",
        vec![
            p(
                "response",
                "string",
                "success or failed, as the trapper said",
                true,
            ),
            p("processed", "number", "Values the trapper accepted", false),
            p(
                "failed",
                "number",
                "Values it refused (unknown host or item, wrong type)",
                false,
            ),
            p("total", "number", "Values it received", false),
            p("info", "string", "The trapper's own summary line", false),
            p(
                "error",
                "string",
                "Why the request failed before an answer",
                false,
            ),
        ],
    )
});

pub fn check(v: &Value) -> Result<()> {
    match v["type"].as_str().unwrap_or_default() {
        GET => {
            let k = v["key"].as_str().context("key is required")?;
            ensure!(
                !k.is_empty() && k.len() <= MAX_KEY && !k.contains('\n'),
                "key must be 1-{MAX_KEY} bytes on one line"
            );
        }
        SEND => {
            let values = v["values"].as_array().context("values must be a list")?;
            ensure!(
                !values.is_empty() && values.len() <= MAX_ITEMS,
                "values must hold 1-{MAX_ITEMS} entries"
            );
            for x in values {
                for field in ["host", "key"] {
                    let s = x[field]
                        .as_str()
                        .with_context(|| format!("each value needs a {field}"))?;
                    ensure!(
                        !s.is_empty() && s.len() <= MAX_KEY,
                        "{field} must be 1-{MAX_KEY} bytes"
                    );
                }
                ensure!(
                    matches!(
                        x["value"],
                        Value::String(_) | Value::Number(_) | Value::Bool(_)
                    ),
                    "value must be text or a number"
                );
                if !x["clock"].is_null() {
                    ensure!(x["clock"].is_u64(), "clock is Unix seconds");
                }
            }
        }
        other => bail!("Unknown Zabbix client action {other:?}"),
    }
    Ok(())
}

impl Protocol for ZabbixClientProtocol {
    fn protocol_name(&self) -> &'static str {
        "Zabbix"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>Zabbix"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "zabbix",
            "zabbix_get",
            "zabbix_sender",
            "zabbix agent",
            "zabbix trapper",
        ]
    }
    fn description(&self) -> &'static str {
        "Zabbix client: queries agents' items (zabbix_get) and sends values to trappers (zabbix_sender)"
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        actions()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![READY_EVENT.clone(), VALUE_EVENT.clone(), SENT_EVENT.clone()]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![ParameterDefinition {
            name: "timeout_secs".into(),
            type_hint: "number".into(),
            description: "Seconds one request may take, connect to answer (1..=300)".into(),
            required: false,
            example: json!(10),
            default: Some(json!(super::TIMEOUT.as_secs())),
        }]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation("Tokio TCP, one connection per request, with the trapper server's ZBXD framing: passive checks as the plain item key, sender data as JSON; answers read through the declared length and capped at 1 MiB")
            .llm_control("Which items to ask agents for and which values to send to trappers")
            .e2e_testing("tests/client/zabbix: Zabbix 7.0's own zabbix_agentd (passive checks, including an unsupported key) and zabbix_proxy with SQLite (sender data, whose log names the host and item it was sent)")
            .notes("No TLS or PSK, no compression, no active-agent protocol. A handler chain stops after 8 follow-ups.")
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Ask the Zabbix agent at 127.0.0.1:10050 for its hostname and send it to the server at 127.0.0.1:10051"
    }
    fn get_startup_examples(&self) -> StartupExamples {
        let llm = json!({"type":"open_client","protocol":"zabbix","remote_addr":"127.0.0.1:10050",
            "instruction":"Ask the agent whether it is alive and what its hostname is"});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([{"event_pattern":"zabbix_ready","handler":{"type":"static","actions":[{"type":GET,"key":"agent.ping"}]}}]);
        let mut scripted = llm.clone();
        scripted["event_handlers"] = json!([{"event_pattern":"*","handler":{"type":"script","language":"python",
            "code":"import json,sys\ni=json.load(sys.stdin); t=i['event_type_id']\na=[{'type':'zabbix_get','key':'system.hostname'}] if t=='zabbix_ready' else []\nprint(json.dumps({'actions':a}))"}}]);
        StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Application"
    }
}

impl Client for ZabbixClientProtocol {
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
        check(&v)?;
        Ok(ClientActionResult::Custom { name, data: v })
    }
}
