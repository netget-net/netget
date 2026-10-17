use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, Parameter, ParameterDefinition,
};
use crate::protocol::{ConnectContext, EventType};
use crate::server::mqtt_sn::actions::{action, parameter};
use anyhow::{bail, ensure, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

#[derive(Default)]
pub struct MqttSnClientProtocol;
impl MqttSnClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

fn topic_param() -> Parameter {
    parameter("topic", "string", "Topic name; a two-character name is sent as a short topic, a name listed in predefined_topics by its id", true)
}

fn register() -> ActionDefinition {
    action(
        "mqttsn_register",
        "Ask the gateway for a topic id for a topic name (publishing registers automatically)",
        vec![topic_param()],
        json!({"type": "mqttsn_register", "topic": "sensors/temp"}),
    )
}
fn publish() -> ActionDefinition {
    action(
        "mqttsn_publish",
        "Publish a message; Rust registers the topic if needed and runs the QoS 1/2 exchange, then reports mqttsn_published",
        vec![
            topic_param(),
            parameter("payload", "string", "Message text, or hex when encoding is hex", true),
            parameter("encoding", "string", "utf8 (default) or hex", false),
            parameter("qos", "number", "-1 (no connection needed; short or predefined topics only), 0 (default), 1 or 2", false),
            parameter("retain", "boolean", "Ask the gateway to treat the message as retained", false),
        ],
        json!({"type": "mqttsn_publish", "topic": "sensors/temp", "payload": "21.5", "qos": 1}),
    )
}
fn subscribe() -> ActionDefinition {
    action(
        "mqttsn_subscribe",
        "Subscribe to a topic filter (+ and # allowed) and report mqttsn_subscribed with the granted QoS and topic id",
        vec![topic_param(), parameter("qos", "number", "0 (default), 1 or 2", false)],
        json!({"type": "mqttsn_subscribe", "topic": "sensors/#", "qos": 1}),
    )
}
fn unsubscribe() -> ActionDefinition {
    action(
        "mqttsn_unsubscribe",
        "Remove a subscription by its topic filter",
        vec![topic_param()],
        json!({"type": "mqttsn_unsubscribe", "topic": "sensors/#"}),
    )
}
fn sleep() -> ActionDefinition {
    action(
        "mqttsn_sleep",
        "Go to sleep: DISCONNECT with a duration; the gateway holds messages until mqttsn_wake, which must come within 1.5 x the duration",
        vec![parameter("duration_secs", "number", "Sleep duration in seconds (1-65535)", true)],
        json!({"type": "mqttsn_sleep", "duration_secs": 60}),
    )
}
fn wake() -> ActionDefinition {
    action(
        "mqttsn_wake",
        "Wake briefly: PINGREQ with the client id; the gateway sends what it held, then PINGRESP, and the client sleeps again (mqttsn_awake reports how many arrived)",
        vec![],
        json!({"type": "mqttsn_wake"}),
    )
}
fn reconnect() -> ActionDefinition {
    action(
        "mqttsn_connect",
        "Send CONNECT again to become active (leave sleep, or resume a session without clean session)",
        vec![],
        json!({"type": "mqttsn_connect"}),
    )
}
fn ping() -> ActionDefinition {
    action(
        "mqttsn_ping",
        "Send PINGREQ and wait for PINGRESP",
        vec![],
        json!({"type": "mqttsn_ping"}),
    )
}
fn disconnect() -> ActionDefinition {
    action(
        "disconnect",
        "Send DISCONNECT and close the session",
        vec![],
        json!({"type": "disconnect"}),
    )
}

pub fn all_actions() -> Vec<ActionDefinition> {
    vec![
        register(),
        publish(),
        subscribe(),
        unsubscribe(),
        sleep(),
        wake(),
        reconnect(),
        ping(),
        disconnect(),
    ]
}

fn event(id: &str, description: &str, params: Vec<Parameter>) -> EventType {
    EventType::new(id, description, publish().example.clone())
        .with_parameters(params)
        .with_actions(all_actions())
}

pub static CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event(
        "mqttsn_connected",
        "The gateway accepted the connection",
        vec![
            parameter("gateway", "string", "The gateway's address", true),
            parameter("client_id", "string", "This client's id", true),
        ],
    )
});
pub static RESULT_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event("mqttsn_result", "The gateway answered an operation", vec![
        parameter("operation", "string", "register, publish, subscribe, unsubscribe, sleep, wake, connect or ping", true),
        parameter("topic", "string", "The topic involved", false),
        parameter("topic_id", "number", "The topic id the gateway uses", false),
        parameter("return_code", "string", "accepted, congestion, invalid_topic_id, not_supported, or timeout when no answer came", true),
        parameter("granted_qos", "number", "For subscribe, the QoS granted", false),
        parameter("messages", "number", "For wake, how many held messages arrived", false),
    ])
});
pub static MESSAGE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event(
        "mqttsn_message_received",
        "The gateway delivered a message for a subscription",
        vec![
            parameter(
                "topic",
                "string",
                "The topic name the message was published to",
                true,
            ),
            parameter(
                "payload",
                "string",
                "Text, or hex per payload_encoding",
                true,
            ),
            parameter(
                "payload_encoding",
                "string",
                "utf8 when the payload is text, hex when it is not UTF-8",
                true,
            ),
            parameter("qos", "number", "The delivery QoS", true),
            parameter("retain", "boolean", "The retain flag", true),
        ],
    )
});
pub static DISCONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "mqttsn_disconnected",
        "The session ended",
        json!({"type": "disconnect"}),
    )
    .with_parameters(vec![parameter(
        "reason",
        "string",
        "Why the session ended, e.g. the gateway sent DISCONNECT",
        true,
    )])
    .with_no_actions()
});

impl Protocol for MqttSnClientProtocol {
    fn protocol_name(&self) -> &'static str {
        "MQTT-SN"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>UDP>MQTT-SN"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["mqtt-sn", "mqttsn", "mqtt-sn client", "sensor client"]
    }
    fn description(&self) -> &'static str {
        "MQTT-SN 1.2 sensor client over UDP: register, publish (QoS -1 to 2), subscribe, sleep and wake"
    }
    fn get_async_actions(&self, _: &crate::state::app_state::AppState) -> Vec<ActionDefinition> {
        all_actions()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            CONNECTED_EVENT.clone(),
            RESULT_EVENT.clone(),
            MESSAGE_EVENT.clone(),
            DISCONNECTED_EVENT.clone(),
        ]
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
                "client_id",
                "string",
                "Client id (1-23 characters); netget-<id> when omitted",
                json!("sensor-1"),
                None,
            ),
            p(
                "keep_alive_secs",
                "number",
                "Keep-alive duration announced in CONNECT",
                json!(30),
                Some(json!(super::DEFAULT_KEEP_ALIVE)),
            ),
            p(
                "clean_session",
                "boolean",
                "Ask for a clean session",
                json!(false),
                Some(json!(true)),
            ),
            p(
                "will_topic",
                "string",
                "Will topic, published by the gateway if this client is lost",
                json!("sensors/status"),
                None,
            ),
            p(
                "will_message",
                "string",
                "Will message text",
                json!("offline"),
                None,
            ),
            p(
                "predefined_topics",
                "object",
                "Predefined topic ids the gateway knows, e.g. {\"1\": \"sensors/temp\"}",
                json!({"1": "sensors/temp"}),
                None,
            ),
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation("The gateway's MQTT-SN codec over a Tokio UDP socket; one outstanding operation at a time, retried 3 times")
            .llm_control("What to register, publish, subscribe to, and when to sleep and wake")
            .e2e_testing("tests/client/mqtt_sn: the Eclipse Paho MQTT-SN Gateway (independent, C++) in front of Mosquitto; messages cross to and from mosquitto_sub and mosquitto_pub")
            .notes("No gateway discovery (connect to a known address); no forwarder encapsulation on the client side.")
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Connect to the MQTT-SN gateway at 127.0.0.1:1883 and publish 21.5 to sensors/temp"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let llm = json!({"type":"open_client","protocol":"mqtt_sn","remote_addr":"127.0.0.1:1883","instruction":"Publish 21.5 to sensors/temp with QoS 1"});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([{"event_pattern":"mqttsn_connected","handler":{"type":"static","actions":[publish().example]}}]);
        let mut scripted = llm.clone();
        scripted["event_handlers"] = json!([{"event_pattern":"mqttsn_connected","handler":{"type":"script","language":"python","code":"import json\nprint(json.dumps({'actions':[{'type':'mqttsn_subscribe','topic':'sensors/cmd','qos':1},{'type':'mqttsn_publish','topic':'sensors/temp','payload':'21.5','qos':1}]}))"}}]);
        crate::llm::actions::StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "IoT"
    }
}

impl Client for MqttSnClientProtocol {
    fn connect(
        &self,
        ctx: ConnectContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::connect(ctx))
    }
    fn execute_action(&self, v: Value) -> Result<ClientActionResult> {
        ensure!(
            crate::utils::json_budget::within_budget(&v, 256 * 1024, 10_000, 8),
            "action exceeds the MQTT-SN bounds"
        );
        let topic = || -> Result<()> {
            let t = v["topic"].as_str().unwrap_or_default();
            ensure!(
                !t.is_empty() && t.len() <= 1024,
                "topic is a topic name or filter"
            );
            Ok(())
        };
        match v["type"].as_str() {
            Some("disconnect") => return Ok(ClientActionResult::Disconnect),
            Some("mqttsn_register" | "mqttsn_unsubscribe") => topic()?,
            Some("mqttsn_subscribe") => {
                topic()?;
                if let Some(q) = v.get("qos").filter(|q| !q.is_null()) {
                    ensure!(matches!(q.as_u64(), Some(0..=2)), "qos is 0, 1 or 2");
                }
            }
            Some("mqttsn_publish") => {
                topic()?;
                ensure!(
                    v["topic"]
                        .as_str()
                        .is_some_and(crate::server::mqtt_sn::packet::valid_topic),
                    "a published topic has no wildcards"
                );
                super::payload(&v)?;
                if let Some(q) = v.get("qos").filter(|q| !q.is_null()) {
                    ensure!(matches!(q.as_i64(), Some(-1..=2)), "qos is -1, 0, 1 or 2");
                }
            }
            Some("mqttsn_sleep") => ensure!(
                matches!(v["duration_secs"].as_u64(), Some(1..=65535)),
                "duration_secs is 1-65535"
            ),
            Some("mqttsn_wake" | "mqttsn_connect" | "mqttsn_ping") => {}
            _ => bail!("Unknown MQTT-SN client action"),
        }
        Ok(ClientActionResult::Custom {
            name: v["type"].as_str().unwrap_or_default().into(),
            data: v,
        })
    }
}
