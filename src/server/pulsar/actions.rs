//! What the model decides as a Pulsar broker: which producers and subscriptions it allows,
//! and whether each published message is accepted (and delivered to the topic's
//! subscriptions) or refused. Rust owns the sessions, lookups, flow control, delivery and
//! acknowledgement.
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

pub const ACCEPT: &str = "pulsar_accept";
pub const REJECT: &str = "pulsar_reject";
pub const PUBLISH: &str = "pulsar_publish";
/// Properties one message may carry.
pub const MAX_PROPERTIES: usize = 64;

#[derive(Default)]
pub struct PulsarProtocol;
impl PulsarProtocol {
    pub fn new() -> Self {
        Self
    }
}

pub fn p(name: &str, kind: &str, description: &str, required: bool) -> Parameter {
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
        log_template: Some(LogTemplate::new().with_info(format!("-> Pulsar {name}"))),
    }
}

fn accept() -> ActionDefinition {
    action(ACCEPT, "Allow the producer or subscription, or accept the message (it is stored for and delivered to the topic's subscriptions).",
        vec![], json!({"type": ACCEPT}))
}

fn reject() -> ActionDefinition {
    action(REJECT, "Refuse the producer, subscription or message; the client gets an authorization or not-allowed error with this text.",
        vec![p("message", "string", "Why, as the client will see it", true)],
        json!({"type": REJECT, "message": "not allowed on this topic"}))
}

/// The parameters a message is described with, in both roles.
pub fn message_params() -> Vec<Parameter> {
    vec![
        p(
            "topic",
            "string",
            "Topic name, e.g. orders or persistent://public/default/orders",
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
            "How payload is written: utf8 (default) or hex",
            false,
        ),
        p(
            "properties",
            "object",
            "String properties, e.g. {\"source\": \"netget\"}",
            false,
        ),
        p("key", "string", "The message key (partition key)", false),
    ]
}

pub fn publish() -> ActionDefinition {
    action(PUBLISH, "Publish a message to a topic as producer netget, delivered to its subscriptions like any other.",
        message_params(), json!({"type": PUBLISH, "topic": "replies", "payload": "got it", "properties": {"source": "netget"}}))
}

pub fn all_actions() -> Vec<ActionDefinition> {
    vec![accept(), reject(), publish()]
}

fn event(id: &str, description: &str, params: Vec<Parameter>) -> EventType {
    EventType::new(id, description, json!({"type": ACCEPT}))
        .with_parameters(params)
        .with_actions(all_actions())
}

pub static PRODUCER_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event(
        "pulsar_producer",
        "A client asked to publish to a topic. Accept or reject the producer.",
        vec![
            p("topic", "string", "The full topic name", true),
            p(
                "producer_name",
                "string",
                "The producer's name (NetGet assigns one when the client gives none)",
                true,
            ),
            p(
                "access_mode",
                "string",
                "Shared, Exclusive, WaitForExclusive or ExclusiveWithFencing",
                true,
            ),
            p(
                "remote_addr",
                "string",
                "The client's address and port",
                true,
            ),
        ],
    )
});

pub static SUBSCRIBE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event(
        "pulsar_subscribe",
        "A client asked to consume from a topic. Accept or reject the subscription.",
        vec![
            p("topic", "string", "The full topic name", true),
            p("subscription", "string", "The subscription name", true),
            p(
                "sub_type",
                "string",
                "Exclusive, Shared, Failover or Key_Shared",
                true,
            ),
            p(
                "consumer_name",
                "string",
                "The consumer's name, if it gave one",
                false,
            ),
            p(
                "remote_addr",
                "string",
                "The client's address and port",
                true,
            ),
        ],
    )
});

pub static MESSAGE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    let mut params = vec![
        p("producer_name", "string", "Which producer sent it", true),
        p(
            "sequence_id",
            "number",
            "The producer's sequence number for it",
            true,
        ),
        p(
            "event_time",
            "number",
            "Event time in Unix milliseconds, if the producer set one",
            false,
        ),
        p(
            "remote_addr",
            "string",
            "The client's address and port",
            true,
        ),
    ];
    params.extend(message_params());
    event("pulsar_message", "A producer published a message. Accept it (it is delivered to the topic's subscriptions) or reject it.", params)
});

pub fn check_message(v: &Value) -> Result<()> {
    super::wire::full_topic(v["topic"].as_str().context("topic is required")?)?;
    let payload = v["payload"].as_str().context("payload is required")?;
    let bytes = super::wire::bytes(payload, v["encoding"].as_str())?;
    ensure!(
        bytes.len() <= super::wire::MAX_FRAME / 2,
        "payload too large"
    );
    if let Some(props) = v.get("properties").filter(|x| !x.is_null()) {
        let o = props
            .as_object()
            .context("properties must be an object of strings")?;
        ensure!(
            o.len() <= MAX_PROPERTIES,
            "at most {MAX_PROPERTIES} properties"
        );
        ensure!(
            o.values().all(Value::is_string),
            "property values must be strings"
        );
    }
    if let Some(k) = v.get("key").filter(|x| !x.is_null()) {
        ensure!(k.is_string(), "key must be a string");
    }
    Ok(())
}

pub fn check(v: &Value) -> Result<()> {
    match v["type"].as_str().unwrap_or_default() {
        ACCEPT => Ok(()),
        REJECT => {
            let m = v["message"].as_str().context("message is required")?;
            ensure!(
                !m.is_empty() && m.len() <= 512,
                "message must be 1-512 bytes"
            );
            Ok(())
        }
        PUBLISH => check_message(v),
        other => bail!("Unknown Pulsar action {other:?}"),
    }
}

impl Protocol for PulsarProtocol {
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
            "pulsar broker",
            "pub/sub",
            "message broker",
        ]
    }
    fn description(&self) -> &'static str {
        "Apache Pulsar broker (binary protocol): the model allows producers and subscriptions and accepts or refuses each message; Rust delivers to subscriptions"
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        Vec::new()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        all_actions()
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            PRODUCER_EVENT.clone(),
            SUBSCRIBE_EVENT.clone(),
            MESSAGE_EVENT.clone(),
        ]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![ParameterDefinition {
            name: "idle_timeout_secs".into(),
            type_hint: "number".into(),
            description: "Seconds a client may send nothing (clients ping every 30) before it is disconnected (1..=86400)".into(),
            required: false,
            example: json!(600),
            default: Some(json!(super::IDLE_TIMEOUT.as_secs())),
        }]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .well_known_port(6650)
            .implementation("The Pulsar binary protocol over Tokio TCP with hand-declared prost messages: CONNECT, PARTITIONED_METADATA (non-partitioned), LOOKUP (to itself), PRODUCER, SEND (CRC32C-checked, batches split), SUBSCRIBE (Exclusive, Shared, Failover, Key_Shared as Shared), FLOW, MESSAGE, ACK (individual, cumulative, with receipts), REDELIVER_UNACKNOWLEDGED_MESSAGES, UNSUBSCRIBE, CLOSE_*, GET_LAST_MESSAGE_ID, PING/PONG")
            .llm_control("Which producers and subscriptions are allowed, whether each message is accepted, and messages it publishes itself")
            .e2e_testing("tests/server/pulsar: the official Python client (pulsar-client, the C++ library) and the Java CLI from Pulsar 4.0.6 produce and consume through NetGet; raw frames for checksums, bounds and a failed handler")
            .notes("Messages live in memory while the server runs: a subscription keeps a bounded backlog (10000) for consumers without permits, and a new subscription starts at the latest message whatever position it asks for. No persistence, partitions, schemas, compression, encryption, chunking, transactions, authentication or TLS. Frames are capped at 5 MiB.")
            .request_only("Every command answers a client's request, except MESSAGE frames delivered to consumers")
            .answers_on_failure()
            .max_inbound_bytes(super::wire::MAX_FRAME)
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Pulsar broker on port 6650 that refuses messages containing passwords"
    }
    fn get_startup_examples(&self) -> StartupExamples {
        let llm = json!({"type":"open_server","base_stack":"pulsar","port":6650,
            "instruction":"Allow every producer and subscription; refuse messages whose payload mentions a password"});
        let mut static_example = llm.clone();
        static_example["event_handlers"] =
            json!([{"event_pattern":"*","handler":{"type":"static","actions":[{"type":ACCEPT}]}}]);
        let mut scripted = llm.clone();
        scripted["event_handlers"] = json!([{"event_pattern":"*","handler":{"type":"script","language":"python",
            "code":"import json,sys\ni=json.load(sys.stdin); e=i['event']\nbad=i['event_type_id']=='pulsar_message' and 'password' in e['payload']\nprint(json.dumps({'actions':[{'type':'pulsar_reject','message':'no secrets'} if bad else {'type':'pulsar_accept'}]}))"}}]);
        StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Application"
    }
}

impl Server for PulsarProtocol {
    fn spawn(
        &self,
        ctx: SpawnContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::spawn(ctx))
    }
    fn execute_action(&self, action: Value) -> Result<ActionResult> {
        check(&action)?;
        Ok(ActionResult::Custom {
            name: action["type"].as_str().unwrap_or_default().to_string(),
            data: action,
        })
    }
}
