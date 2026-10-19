//! What the model does as a Pulsar client: publish messages, subscribe and hear what arrives,
//! unsubscribe. Lookups, producers, permits and acknowledgements are Rust's.
use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, ParameterDefinition, StartupExamples,
};
use crate::protocol::{ConnectContext, EventType};
use crate::server::pulsar::actions::{action, check_message, message_params, p};
use crate::server::pulsar::wire;
use crate::state::app_state::AppState;
use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

pub const PRODUCE: &str = "pulsar_produce";
pub const SUBSCRIBE: &str = "pulsar_subscribe";
pub const UNSUBSCRIBE: &str = "pulsar_unsubscribe";

#[derive(Default)]
pub struct PulsarClientProtocol;
impl PulsarClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

fn topic_sub() -> Vec<crate::llm::actions::Parameter> {
    vec![
        p(
            "topic",
            "string",
            "Topic name, e.g. orders or persistent://public/default/orders",
            true,
        ),
        p(
            "subscription",
            "string",
            "Subscription name; consumers sharing it share its messages",
            true,
        ),
    ]
}

pub fn actions() -> Vec<ActionDefinition> {
    let mut sub = topic_sub();
    sub.push(p(
        "sub_type",
        "string",
        "Exclusive (default), Shared, Failover or Key_Shared",
        false,
    ));
    sub.push(p(
        "initial_position",
        "string",
        "Where a new subscription starts: latest (default) or earliest",
        false,
    ));
    vec![
        action(PRODUCE, "Publish a message to a topic; the broker's receipt (or refusal) arrives as pulsar_produced.",
            message_params(), json!({"type": PRODUCE, "topic": "orders", "payload": "order 42 shipped", "properties": {"source": "netget"}})),
        action(SUBSCRIBE, "Subscribe to a topic; every message that arrives is a pulsar_message event and is acknowledged once handled.",
            sub, json!({"type": SUBSCRIBE, "topic": "orders", "subscription": "netget"})),
        action(UNSUBSCRIBE, "Delete a subscription this client holds.",
            topic_sub(), json!({"type": UNSUBSCRIBE, "topic": "orders", "subscription": "netget"})),
        action("disconnect", "Close the connection to the broker.", vec![], json!({"type": "disconnect"})),
    ]
}

fn event(id: &str, description: &str, params: Vec<crate::llm::actions::Parameter>) -> EventType {
    EventType::new(
        id,
        description,
        json!({"type": PRODUCE, "topic": "orders", "payload": "hello"}),
    )
    .with_parameters(params)
    .with_actions(actions())
}

pub static CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event(
        "pulsar_connected",
        "Connected to the broker (CONNECT answered).",
        vec![
            p(
                "server_version",
                "string",
                "What the broker said it is",
                true,
            ),
            p(
                "protocol_version",
                "number",
                "The protocol version agreed",
                true,
            ),
            p(
                "max_message_size",
                "number",
                "The largest message the broker takes, in bytes",
                false,
            ),
        ],
    )
});

pub static PRODUCED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event(
        "pulsar_produced",
        "The broker answered a published message.",
        vec![
            p("topic", "string", "The full topic name", true),
            p("ok", "boolean", "Whether the broker stored it", true),
            p(
                "message_id",
                "object",
                "Its id {ledger_id, entry_id} when stored",
                false,
            ),
            p(
                "error",
                "string",
                "Why the broker refused it (or the producer)",
                false,
            ),
        ],
    )
});

pub static SUBSCRIBED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event(
        "pulsar_subscribed",
        "The broker answered a subscribe or unsubscribe.",
        vec![
            p("topic", "string", "The full topic name", true),
            p("subscription", "string", "The subscription name", true),
            p("operation", "string", "subscribe or unsubscribe", true),
            p("ok", "boolean", "Whether it succeeded", true),
            p("error", "string", "Why the broker refused", false),
        ],
    )
});

pub static MESSAGE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event(
        "pulsar_message",
        "A message arrived on a subscription (it is acknowledged once this event is handled).",
        vec![
            p("topic", "string", "The full topic name", true),
            p(
                "subscription",
                "string",
                "The subscription it arrived on",
                true,
            ),
            p(
                "payload",
                "string",
                "The message body as text, or hex when encoding is hex",
                true,
            ),
            p(
                "encoding",
                "string",
                "How payload is written: utf8, or hex when the body is not printable text",
                true,
            ),
            p(
                "properties",
                "object",
                "The message's string properties",
                true,
            ),
            p("key", "string", "The message key, if any", false),
            p(
                "producer_name",
                "string",
                "Which producer published it",
                true,
            ),
            p("message_id", "object", "Its id {ledger_id, entry_id}", true),
            p(
                "redelivery_count",
                "number",
                "How many times it was delivered before",
                true,
            ),
        ],
    )
});

pub fn check(v: &Value) -> Result<()> {
    match v["type"].as_str().unwrap_or_default() {
        PRODUCE => check_message(v),
        SUBSCRIBE | UNSUBSCRIBE => {
            wire::full_topic(v["topic"].as_str().context("topic is required")?)?;
            let s = v["subscription"]
                .as_str()
                .context("subscription is required")?;
            ensure!(
                !s.is_empty() && s.len() <= 256,
                "subscription must be 1-256 bytes"
            );
            if let Some(t) = v["sub_type"].as_str() {
                ensure!(
                    wire::SUB_TYPES.contains(&t),
                    "sub_type must be one of {:?}",
                    wire::SUB_TYPES
                );
            }
            if let Some(p) = v["initial_position"].as_str() {
                ensure!(
                    matches!(p, "latest" | "earliest"),
                    "initial_position must be latest or earliest"
                );
            }
            Ok(())
        }
        other => bail!("Unknown Pulsar client action {other:?}"),
    }
}

impl Protocol for PulsarClientProtocol {
    fn protocol_name(&self) -> &'static str {
        "Apache Pulsar"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>Pulsar"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "pulsar",
            "apache pulsar",
            "pulsar client",
            "pulsar producer",
            "pulsar consumer",
        ]
    }
    fn description(&self) -> &'static str {
        "Apache Pulsar client (binary protocol): publishes, subscribes and hears messages as the model directs"
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        actions()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            CONNECTED_EVENT.clone(),
            PRODUCED_EVENT.clone(),
            SUBSCRIBED_EVENT.clone(),
            MESSAGE_EVENT.clone(),
        ]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        Vec::new()
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation("The Pulsar binary protocol over Tokio TCP, sharing the broker role's prost messages and framing: CONNECT, LOOKUP before each producer and subscription, PRODUCER/SEND with CRC32C, SUBSCRIBE/FLOW with permits topped up, MESSAGE (batches split) acknowledged after the handler runs, PING answered")
            .llm_control("What to publish where, which topics to subscribe to, and what to do with each message")
            .e2e_testing("tests/client/pulsar: Apache Pulsar 4.0.6 standalone; the official Python client reads what NetGet publishes and publishes what NetGet receives")
            .notes("A lookup that redirects to another broker is reported, not followed. No partitioned topics, schemas, compression, encryption, transactions or TLS; acknowledgement is automatic. A handler chain stops after 8 follow-ups.")
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            // Messages delivered while the model answers wait in the dispatcher queue and are
            // answered in one call, one event each, then acknowledged (`client/pulsar/mod.rs`).
            .batching(crate::protocol::metadata::BatchingMode::On)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Connect to the Pulsar broker at 127.0.0.1:6650, subscribe to orders and echo each one to receipts"
    }
    fn get_startup_examples(&self) -> StartupExamples {
        let llm = json!({"type":"open_client","protocol":"pulsar","remote_addr":"127.0.0.1:6650",
            "instruction":"Subscribe to orders and publish a receipt to receipts for each order"});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([{"event_pattern":"pulsar_connected","handler":{"type":"static","actions":[{"type":SUBSCRIBE,"topic":"orders","subscription":"netget"}]}}]);
        let mut scripted = llm.clone();
        scripted["event_handlers"] = json!([{"event_pattern":"*","handler":{"type":"script","language":"python",
            "code":"import json,sys\ni=json.load(sys.stdin); t=i['event_type_id']; e=i['event']\na=[]\nif t=='pulsar_connected': a=[{'type':'pulsar_subscribe','topic':'orders','subscription':'netget'}]\nelif t=='pulsar_message': a=[{'type':'pulsar_produce','topic':'receipts','payload':'got '+e['payload']}]\nprint(json.dumps({'actions':a}))"}}]);
        StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Application"
    }
}

impl Client for PulsarClientProtocol {
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
