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
pub struct MqttSnProtocol;
impl MqttSnProtocol {
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
        log_template: Some(LogTemplate::new().with_info(format!("MQTT-SN {name}"))),
    }
}

fn accept() -> ActionDefinition {
    action(
        "mqttsn_accept",
        "Accept: let the client connect, relay its message to subscribers, or grant its subscription",
        vec![parameter("qos", "number", "For a subscription, the QoS granted (0-2; default the requested QoS)", false)],
        json!({"type": "mqttsn_accept"}),
    )
}

fn reject() -> ActionDefinition {
    action(
        "mqttsn_reject",
        "Refuse with an MQTT-SN return code: the client sees CONNACK, PUBACK or SUBACK carrying it",
        vec![parameter(
            "return_code",
            "string",
            "congestion (try later), invalid_topic_id or not_supported",
            true,
        )],
        json!({"type": "mqttsn_reject", "return_code": "not_supported"}),
    )
}

pub fn publish() -> ActionDefinition {
    action(
        "mqttsn_publish",
        "Publish a message from the gateway: to every matching subscriber, or only to client_id; Rust registers topic ids and runs QoS 1/2 flows, holding messages for sleeping clients",
        vec![
            parameter("topic", "string", "Topic name (no wildcards)", true),
            parameter("payload", "string", "Message text, or hex when encoding is hex", true),
            parameter("encoding", "string", "utf8 (default) or hex", false),
            parameter("qos", "number", "0 (default), 1 or 2", false),
            parameter("retain", "boolean", "Mark the message retained", false),
            parameter("client_id", "string", "Deliver only to this connected client", false),
        ],
        json!({"type": "mqttsn_publish", "topic": "sensors/cmd", "payload": "reboot", "qos": 1}),
    )
}

fn disconnect() -> ActionDefinition {
    action(
        "disconnect",
        "Send this client DISCONNECT and end its session",
        vec![],
        json!({"type": "disconnect"}),
    )
}

fn answers() -> Vec<ActionDefinition> {
    vec![accept(), reject(), publish()]
}

pub static CONNECT_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "mqttsn_connect",
        "A client wants to connect (after its will, if any, was collected)",
        accept().example.clone(),
    )
    .with_parameters(vec![
        parameter("client_id", "string", "The client identifier", true),
        parameter("address", "string", "The client's UDP address", true),
        parameter(
            "clean_session",
            "boolean",
            "Whether the client asked for a clean session",
            true,
        ),
        parameter(
            "keep_alive_secs",
            "number",
            "The client's keep-alive duration",
            true,
        ),
        parameter(
            "will",
            "object",
            "{topic, message, qos, retain} published if the client is lost",
            false,
        ),
        parameter(
            "forwarder_node",
            "string",
            "Wireless node id (hex) when the client came through a forwarder",
            false,
        ),
    ])
    .with_actions(answers())
});

pub static MESSAGE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "mqttsn_message",
        "A client published a message; accept relays it to matching subscribers",
        accept().example.clone(),
    )
    .with_parameters(vec![
        parameter(
            "client_id",
            "string",
            "The publisher, or null for a QoS -1 publish without a connection",
            false,
        ),
        parameter(
            "topic",
            "string",
            "The topic name (resolved from its id)",
            true,
        ),
        parameter(
            "payload",
            "string",
            "The message, as text or hex per payload_encoding",
            true,
        ),
        parameter(
            "payload_encoding",
            "string",
            "utf8 when the payload is text, hex when it is not UTF-8",
            true,
        ),
        parameter(
            "qos",
            "number",
            "The publish QoS: -1 (no connection), 0, 1 or 2",
            true,
        ),
        parameter("retain", "boolean", "The retain flag", true),
        parameter(
            "subscribers",
            "number",
            "How many sessions accepting would deliver it to",
            true,
        ),
    ])
    .with_actions(answers())
});

pub static SUBSCRIBE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "mqttsn_subscribe",
        "A client wants to subscribe; accept grants it (and any mqttsn_publish in the answer is delivered, e.g. a retained value)",
        accept().example.clone(),
    )
    .with_parameters(vec![
        parameter("client_id", "string", "The client id of the client asking to subscribe", true),
        parameter("topic", "string", "The topic filter (may contain + and #)", true),
        parameter("qos", "number", "The QoS requested", true),
    ])
    .with_actions(answers())
});

impl Protocol for MqttSnProtocol {
    fn protocol_name(&self) -> &'static str {
        "MQTT-SN"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>UDP>MQTT-SN"
    }
    fn description(&self) -> &'static str {
        "MQTT-SN 1.2 gateway over UDP: sensors connect, register topics, publish and subscribe; sleeping clients get held messages on wake"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "mqtt-sn",
            "mqttsn",
            "mqtt for sensor networks",
            "sensor gateway",
        ]
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        vec![publish(), disconnect()]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        answers()
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            CONNECT_EVENT.clone(),
            MESSAGE_EVENT.clone(),
            SUBSCRIBE_EVENT.clone(),
        ]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "gateway_id".into(),
                type_hint: "number".into(),
                description: "Gateway id (0-255) sent in GWINFO answers to SEARCHGW".into(),
                required: false,
                example: json!(7),
                default: Some(json!(super::DEFAULT_GATEWAY_ID)),
            },
            ParameterDefinition {
                name: "predefined_topics".into(),
                type_hint: "object".into(),
                description: "Predefined topic ids clients may use without registering, e.g. {\"1\": \"sensors/temp\"}".into(),
                required: false,
                example: json!({"1": "sensors/temp"}),
                default: None,
            },
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .well_known_udp_port(1883)
            .implementation("Native MQTT-SN 1.2 codec and gateway over one Tokio UDP socket: sessions per address (and forwarder node), will exchange, topic registry, predefined and short topics, QoS -1/0/1/2 in both directions, keep-alive, sleeping clients, forwarder encapsulation")
            .llm_control("Which clients may connect, which messages are relayed, which subscriptions are granted, and messages the gateway publishes")
            .e2e_testing("tests/server/mqtt_sn: mqtt-sn-tools (independent C clients) publish and subscribe through NetGet with QoS -1/0/1, predefined and short topics, forwarder encapsulation and a sleeping subscriber")
            .notes("The gateway is the broker: no MQTT broker behind it and no retained-message store (answer a subscription with mqttsn_publish to deliver one). 256 sessions, 10 000 topic ids, 100 held messages per session, one outstanding QoS 1/2 delivery per client retried 3 times.")
            .answers_on_failure()
            .max_inbound_bytes(65_535)
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "MQTT-SN gateway on UDP 1883 that relays every sensor reading"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let llm = json!({"type":"open_server","base_stack":"mqtt_sn","port":1883,"instruction":"Accept every client and relay every message"});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([{"event_pattern":"*","handler":{"type":"static","actions":[{"type":"mqttsn_accept"}]}}]);
        let mut scripted = llm.clone();
        scripted["event_handlers"] = json!([{"event_pattern":"*","handler":{"type":"script","language":"python","code":"import json,sys\ni=json.load(sys.stdin)\ne=i['event']\nok=not str(e.get('topic','')).startswith('admin/')\nprint(json.dumps({'actions':[{'type':'mqttsn_accept'} if ok else {'type':'mqttsn_reject','return_code':'not_supported'}]}))"}}]);
        crate::llm::actions::StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "IoT"
    }
}

/// A gateway-originated message, validated.
pub fn publish_from(v: &Value) -> Result<(String, Vec<u8>, i8, bool)> {
    let topic = v["topic"].as_str().context("topic is a topic name")?;
    ensure!(
        super::packet::valid_topic(topic),
        "topic is a topic name without wildcards"
    );
    let payload = v["payload"].as_str().context("payload is text")?;
    let data = match v.get("encoding").and_then(Value::as_str) {
        None | Some("utf8") => payload.as_bytes().to_vec(),
        Some("hex") => hex::decode(payload).context("payload is not hex")?,
        Some(e) => bail!("encoding {e:?} is utf8 or hex"),
    };
    ensure!(data.len() <= 60_000, "payload is at most 60000 bytes");
    let qos = match v.get("qos").filter(|q| !q.is_null()) {
        None => 0,
        Some(q) => match q.as_i64() {
            Some(n @ 0..=2) => n as i8,
            _ => bail!("qos is 0, 1 or 2"),
        },
    };
    let retain = match v.get("retain").filter(|r| !r.is_null()) {
        None => false,
        Some(r) => r.as_bool().context("retain is true or false")?,
    };
    Ok((topic.to_owned(), data, qos, retain))
}

impl Server for MqttSnProtocol {
    fn spawn(
        &self,
        ctx: SpawnContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::spawn(ctx))
    }
    fn execute_action(&self, v: Value) -> Result<ActionResult> {
        match v["type"].as_str() {
            Some("mqttsn_accept") => {
                if let Some(q) = v.get("qos").filter(|q| !q.is_null()) {
                    ensure!(matches!(q.as_u64(), Some(0..=2)), "qos is 0, 1 or 2");
                }
            }
            Some("mqttsn_reject") => {
                let rc = v["return_code"].as_str().unwrap_or_default();
                ensure!(
                    super::packet::return_code(rc).is_some(),
                    "return_code is congestion, invalid_topic_id or not_supported"
                );
            }
            Some("mqttsn_publish") => {
                publish_from(&v)?;
                if let Some(c) = v.get("client_id").filter(|c| !c.is_null()) {
                    ensure!(c.is_string(), "client_id is text");
                }
            }
            Some("disconnect") => return Ok(ActionResult::CloseConnection),
            _ => bail!("Unknown MQTT-SN gateway action"),
        }
        Ok(ActionResult::Custom {
            name: v["type"].as_str().unwrap_or_default().into(),
            data: v,
        })
    }
}
