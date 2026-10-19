//! MQTT client protocol actions implementation

use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, Parameter, ParameterDefinition,
};
use crate::protocol::EventType;
use crate::state::app_state::AppState;
use anyhow::{Context, Result};
use serde_json::json;
use std::sync::LazyLock;

/// MQTT client connected event
pub static MQTT_CLIENT_CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "mqtt_connected",
        "MQTT client successfully connected to broker",
        json!({"type": "subscribe", "topics": ["sensors/#"], "qos": 1}),
    )
    .with_parameters(vec![
        Parameter {
            name: "remote_addr".to_string(),
            type_hint: "string".to_string(),
            description: "MQTT broker address".to_string(),
            required: true,
        },
        Parameter {
            name: "client_id".to_string(),
            type_hint: "string".to_string(),
            description: "MQTT client ID used for connection".to_string(),
            required: true,
        },
        Parameter {
            name: "protocol_version".to_string(),
            type_hint: "string".to_string(),
            description: "\"3.1.1\" or \"5.0\", as chosen by the protocol_version startup \
                          parameter"
                .to_string(),
            required: true,
        },
        Parameter {
            name: "properties".to_string(),
            type_hint: "object".to_string(),
            description: "MQTT 5 only: the CONNACK's properties, e.g. \
                          assigned_client_identifier, maximum_packet_size, \
                          topic_alias_maximum, user_properties"
                .to_string(),
            required: false,
        },
    ])
});

/// MQTT message received event
pub static MQTT_MESSAGE_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "mqtt_message_received",
        "Message received from MQTT broker",
        json!({"type": "placeholder", "event_id": "mqtt_message_received"}),
    )
    .with_parameters(vec![
        Parameter {
            name: "topic".to_string(),
            type_hint: "string".to_string(),
            description: "Topic where message was published".to_string(),
            required: true,
        },
        Parameter {
            name: "payload".to_string(),
            type_hint: "string".to_string(),
            description: "Message payload (UTF-8 string)".to_string(),
            required: true,
        },
        Parameter {
            name: "qos".to_string(),
            type_hint: "number".to_string(),
            description: "Quality of Service level (0, 1, or 2)".to_string(),
            required: true,
        },
        Parameter {
            name: "retain".to_string(),
            type_hint: "boolean".to_string(),
            description: "Whether this is a retained message".to_string(),
            required: true,
        },
        Parameter {
            name: "properties".to_string(),
            type_hint: "object".to_string(),
            description: "MQTT 5 only: the message's properties - response_topic and \
                          correlation_data (+ correlation_data_encoding) for request/response, \
                          content_type, message_expiry_interval, subscription_identifiers, \
                          user_properties as [[name, value], ...]"
                .to_string(),
            required: false,
        },
    ])
});

/// MQTT client protocol action handler
/// The MQTT 5 PUBLISH properties `publish` takes, under one `properties` object.
fn publish_properties_parameter() -> Parameter {
    Parameter {
        name: "properties".to_string(),
        type_hint: "object".to_string(),
        description: "MQTT 5 only (protocol_version \"5.0\"): message properties - \
                      content_type, response_topic, correlation_data (+ \
                      correlation_data_encoding \"utf8\" or \"hex\"), message_expiry_interval, \
                      payload_format_indicator, user_properties as [[name, value], ...]. To \
                      answer a request, publish to its properties.response_topic with its \
                      correlation_data."
            .to_string(),
        required: false,
    }
}

/// The MQTT 5 subscription options `subscribe` takes.
fn subscribe_option_parameters() -> Vec<Parameter> {
    vec![
        Parameter {
            name: "no_local".to_string(),
            type_hint: "boolean".to_string(),
            description: "MQTT 5 only: do not receive messages this client published itself."
                .to_string(),
            required: false,
        },
        Parameter {
            name: "retain_as_published".to_string(),
            type_hint: "boolean".to_string(),
            description: "MQTT 5 only: keep the retain flag forwarded messages were published \
                          with."
                .to_string(),
            required: false,
        },
        Parameter {
            name: "retain_handling".to_string(),
            type_hint: "integer".to_string(),
            description: "MQTT 5 only: 0 send retained messages on subscribe (default), 1 only \
                          for a new subscription, 2 never."
                .to_string(),
            required: false,
        },
    ]
}

pub struct MqttClientProtocol;

impl MqttClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for MqttClientProtocol {
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![
                ActionDefinition {
                    name: "subscribe".to_string(),
                    description: "Subscribe to one or more MQTT topics".to_string(),
                    parameters: vec![
                        Parameter {
                            name: "topics".to_string(),
                            type_hint: "array".to_string(),
                            description: "Array of topic patterns (supports wildcards: + for single level, # for multi-level)".to_string(),
                            required: true,
                        },
                        Parameter {
                            name: "qos".to_string(),
                            type_hint: "number".to_string(),
                            description: "Quality of Service level (0=AtMostOnce, 1=AtLeastOnce, 2=ExactlyOnce). Default: 0".to_string(),
                            required: false,
                        },
                    ]
                    .into_iter()
                    .chain(subscribe_option_parameters())
                    .collect(),
                    example: json!({
                        "type": "subscribe",
                        "topics": ["sensors/temperature", "sensors/+/status", "devices/#"],
                        "qos": 1
                    }),
                log_template: None,
                },
                ActionDefinition {
                    name: "publish".to_string(),
                    description: "Publish a message to an MQTT topic".to_string(),
                    parameters: vec![
                        Parameter {
                            name: "topic".to_string(),
                            type_hint: "string".to_string(),
                            description: "Topic to publish to (no wildcards allowed)".to_string(),
                            required: true,
                        },
                        Parameter {
                            name: "payload".to_string(),
                            type_hint: "string".to_string(),
                            description: "Message payload (UTF-8 string)".to_string(),
                            required: true,
                        },
                        Parameter {
                            name: "qos".to_string(),
                            type_hint: "number".to_string(),
                            description: "Quality of Service level (0, 1, or 2). Default: 0".to_string(),
                            required: false,
                        },
                        Parameter {
                            name: "retain".to_string(),
                            type_hint: "boolean".to_string(),
                            description: "Whether to retain the message on the broker. Default: false".to_string(),
                            required: false,
                        },
                        publish_properties_parameter(),
                    ],
                    example: json!({
                        "type": "publish",
                        "topic": "sensors/temperature",
                        "payload": "25.5",
                        "qos": 1,
                        "retain": false
                    }),
                log_template: None,
                },
                ActionDefinition {
                    name: "unsubscribe".to_string(),
                    description: "Unsubscribe from MQTT topics".to_string(),
                    parameters: vec![
                        Parameter {
                            name: "topics".to_string(),
                            type_hint: "array".to_string(),
                            description: "Array of topics to unsubscribe from".to_string(),
                            required: true,
                        },
                    ],
                    example: json!({
                        "type": "unsubscribe",
                        "topics": ["sensors/temperature"]
                    }),
                log_template: None,
                },
                ActionDefinition {
                    name: "disconnect".to_string(),
                    description: "Disconnect from the MQTT broker".to_string(),
                    parameters: vec![],
                    example: json!({
                        "type": "disconnect"
                    }),
                log_template: None,
                },
            ]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            ActionDefinition {
                name: "publish".to_string(),
                description: "Publish a message in response to received data".to_string(),
                parameters: vec![
                    Parameter {
                        name: "topic".to_string(),
                        type_hint: "string".to_string(),
                        description: "Topic to publish to".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "payload".to_string(),
                        type_hint: "string".to_string(),
                        description: "Message payload".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "qos".to_string(),
                        type_hint: "number".to_string(),
                        description: "Quality of Service level (0, 1, or 2)".to_string(),
                        required: false,
                    },
                    publish_properties_parameter(),
                ],
                example: json!({
                    "type": "publish",
                    "topic": "sensors/response",
                    "payload": "acknowledged",
                    "qos": 0
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "subscribe".to_string(),
                description: "Subscribe to additional topics in response to events".to_string(),
                parameters: vec![
                    Parameter {
                        name: "topics".to_string(),
                        type_hint: "array".to_string(),
                        description: "Array of topic patterns".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "qos".to_string(),
                        type_hint: "number".to_string(),
                        description: "Quality of Service level".to_string(),
                        required: false,
                    },
                ]
                .into_iter()
                .chain(subscribe_option_parameters())
                .collect(),
                example: json!({
                    "type": "subscribe",
                    "topics": ["responses/#"],
                    "qos": 1
                }),
                log_template: None,
            },
        ]
    }
    fn protocol_name(&self) -> &'static str {
        "MQTT"
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            EventType::new(
                "mqtt_connected",
                "Triggered when MQTT client connects to broker",
                json!({"type": "placeholder", "event_id": "mqtt_connected"}),
            ),
            EventType::new(
                "mqtt_message_received",
                "Triggered when MQTT client receives a published message",
                json!({"type": "placeholder", "event_id": "mqtt_message_received"}),
            ),
            EventType::new(
                "mqtt_subscribed",
                "Triggered when MQTT client successfully subscribes to topics",
                json!({"type": "placeholder", "event_id": "mqtt_subscribed"}),
            ),
        ]
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>MQTT"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["mqtt", "mqtt client", "connect to mqtt", "iot", "messaging"]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Beta)
            .implementation(
                "rumqttc async client library: its 3.1.1 stack, or its v5 stack with \
                 protocol_version 5.0",
            )
            .llm_control("Full control over subscriptions, publications, and QoS levels")
            .e2e_testing(
                "tests/client/mqtt/real_server_test.rs, 7 LLM calls, against Eclipse Mosquitto \
                 (C; shares no code with rumqttc) with mosquitto_sub and mosquitto_pub on the \
                 far side. The model's publish is read back by mosquitto_sub; Mosquitto's own \
                 log shows NetGet's client_id and the model's QoS 1 subscription; a \
                 mosquitto_pub message reaches the model with its topic and payload and the \
                 model's quoting reply comes back through the broker; a retained reading and a \
                 QoS 2 live reading on sensors/# reach the model with the granted QoS and the \
                 retain bit intact. MQTT 5.0: tests/client/mqtt/v5_real_server_test.rs, no LLM \
                 calls, against the same Mosquitto with mosquitto_sub/mosquitto_pub at -V 5 - a \
                 publish's Content Type and User Property printed by libmosquitto, a request's \
                 Response Topic and Correlation Data answered on that topic with the data \
                 echoed, and No Local honoured (NetGet never hears its own publishes). Not \
                 #[ignore]d, and a missing mosquitto fails the test rather than skipping it.",
            )
            .notes(
                "MQTT 3.1.1 (default) or 5.0 (protocol_version) over plain TCP. On v5, \
                 publish takes properties, subscribe takes No Local / Retain As Published / \
                 Retain Handling, and events carry the CONNACK's and each message's \
                 properties. Validated against Mosquitto for connect, \
                 subscribe (including wildcards), publish at QoS 0/1, and inbound delivery at \
                 the granted QoS with the retain flag. Not exercised against a real broker: \
                 TLS, username/password against a broker that enforces it, Last Will, \
                 persistent sessions (clean_session false) and reconnection.",
            )
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            // PUBLISHes that arrive while the model answers wait on the turn queue and are
            // answered in one call, one event per message (`run_model_turns` in mod.rs).
            .batching(crate::protocol::metadata::BatchingMode::On)
            .build()
    }
    fn description(&self) -> &'static str {
        "MQTT client for IoT messaging and pub/sub communication"
    }
    fn example_prompt(&self) -> &'static str {
        "Connect to MQTT broker at localhost:1883, subscribe to sensors/# and publish a test message"
    }
    fn group_name(&self) -> &'static str {
        "Messaging"
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "client_id".to_string(),
                type_hint: "string".to_string(),
                description: "MQTT client identifier (default: auto-generated)".to_string(),
                required: false,
                example: json!("netget-sensor-monitor"),
                default: None,
            },
            ParameterDefinition {
                name: "username".to_string(),
                type_hint: "string".to_string(),
                description: "MQTT authentication username (optional)".to_string(),
                required: false,
                example: json!("admin"),
                default: None,
            },
            ParameterDefinition {
                name: "password".to_string(),
                type_hint: "string".to_string(),
                description: "MQTT authentication password (optional)".to_string(),
                required: false,
                example: json!("secret"),
                default: None,
            },
            ParameterDefinition {
                name: "keep_alive".to_string(),
                type_hint: "number".to_string(),
                description: "Keep-alive interval in seconds (default: 60)".to_string(),
                required: false,
                example: json!(60),
                default: None,
            },
            ParameterDefinition {
                name: "clean_session".to_string(),
                type_hint: "boolean".to_string(),
                description: "Start with a clean session (default: true)".to_string(),
                required: false,
                example: json!(true),
                default: None,
            },
            ParameterDefinition {
                name: "protocol_version".to_string(),
                type_hint: "string".to_string(),
                description: "\"3.1.1\" (default) or \"5.0\". MQTT 5 adds reason codes and \
                              message properties: response_topic and correlation_data for \
                              request/response, content_type, user_properties."
                    .to_string(),
                required: false,
                example: json!("5.0"),
                default: Some(json!(super::DEFAULT_PROTOCOL_VERSION)),
            },
        ]
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        use serde_json::json;

        StartupExamples::new(
            // LLM mode: LLM controls MQTT pub/sub
            json!({
                "type": "open_client",
                "remote_addr": "localhost:1883",
                "base_stack": "mqtt",
                "instruction": "Subscribe to sensors/# and respond to temperature readings above 30"
            }),
            // Script mode: Code-based deterministic responses
            json!({
                "type": "open_client",
                "remote_addr": "localhost:1883",
                "base_stack": "mqtt",
                "event_handlers": [{
                    "event_pattern": "mqtt_message_received",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "<mqtt_client_handler>"
                    }
                }]
            }),
            // Static mode: Fixed MQTT subscription on connect
            json!({
                "type": "open_client",
                "remote_addr": "localhost:1883",
                "base_stack": "mqtt",
                "event_handlers": [
                    {
                        "event_pattern": "mqtt_connected",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "subscribe",
                                "topics": ["sensors/#"],
                                "qos": 1
                            }]
                        }
                    },
                    {
                        "event_pattern": "mqtt_message_received",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "publish",
                                "topic": "ack",
                                "payload": "received"
                            }]
                        }
                    }
                ]
            }),
        )
    }
}

// Implement Client trait (client-specific functionality)
impl Client for MqttClientProtocol {
    fn connect(
        &self,
        ctx: crate::protocol::ConnectContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::client::mqtt::MqttClient;
            MqttClient::connect_with_llm_actions(
                ctx.remote_addr,
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.client_id,
                ctx.startup_params,
            )
            .await
        })
    }
    fn execute_action(&self, action: serde_json::Value) -> Result<ClientActionResult> {
        let action_type = action
            .get("type")
            .and_then(|v| v.as_str())
            .context("Missing 'type' field in action")?;

        match action_type {
            "subscribe" => {
                let topics = action
                    .get("topics")
                    .and_then(|v| v.as_array())
                    .context("Missing or invalid 'topics' field")?;

                let topic_strings: Vec<String> = topics
                    .iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect();

                if topic_strings.is_empty() {
                    return Err(anyhow::anyhow!("No valid topics provided"));
                }

                let qos: u8 = crate::client::wire_values::number(&action, "qos", 0)?;
                if qos > 2 {
                    anyhow::bail!("MQTT qos must be 0, 1 or 2");
                }

                let retain_handling: u8 =
                    crate::client::wire_values::number(&action, "retain_handling", 0)?;
                if retain_handling > 2 {
                    anyhow::bail!("retain_handling must be 0, 1 or 2");
                }
                let flag = |k: &str| action.get(k).and_then(|v| v.as_bool()).unwrap_or(false);

                Ok(ClientActionResult::Custom {
                    name: "mqtt_subscribe".to_string(),
                    data: json!({
                        "topics": topic_strings,
                        "qos": qos,
                        "no_local": flag("no_local"),
                        "retain_as_published": flag("retain_as_published"),
                        "retain_handling": retain_handling,
                    }),
                })
            }
            "publish" => {
                let topic = action
                    .get("topic")
                    .and_then(|v| v.as_str())
                    .context("Missing 'topic' field")?
                    .to_string();

                let payload = action
                    .get("payload")
                    .and_then(|v| v.as_str())
                    .context("Missing 'payload' field")?
                    .to_string();

                let qos: u8 = crate::client::wire_values::number(&action, "qos", 0)?;
                if qos > 2 {
                    anyhow::bail!("MQTT qos must be 0, 1 or 2");
                }

                let retain = action
                    .get("retain")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);

                // Checked here so a malformed property is refused before anything is queued.
                let properties = match action.get("properties") {
                    None | Some(serde_json::Value::Null) => serde_json::Value::Null,
                    Some(p @ serde_json::Value::Object(_)) => {
                        validate_publish_properties(p)?;
                        p.clone()
                    }
                    Some(other) => anyhow::bail!("properties must be an object, not {other}"),
                };

                Ok(ClientActionResult::Custom {
                    name: "mqtt_publish".to_string(),
                    data: json!({
                        "topic": topic,
                        "payload": payload,
                        "qos": qos,
                        "retain": retain,
                        "properties": properties,
                    }),
                })
            }
            "unsubscribe" => {
                let topics = action
                    .get("topics")
                    .and_then(|v| v.as_array())
                    .context("Missing or invalid 'topics' field")?;

                let topic_strings: Vec<String> = topics
                    .iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect();

                Ok(ClientActionResult::Custom {
                    name: "mqtt_unsubscribe".to_string(),
                    data: json!({
                        "topics": topic_strings,
                    }),
                })
            }
            "disconnect" => Ok(ClientActionResult::Disconnect),
            _ => Err(anyhow::anyhow!(
                "Unknown MQTT client action: {}",
                action_type
            )),
        }
    }
}

/// Refuse a `properties` object the v5 PUBLISH could not carry.
fn validate_publish_properties(p: &serde_json::Value) -> Result<()> {
    use crate::server::mqtt::v5;
    const KNOWN: &[&str] = &[
        "content_type",
        "response_topic",
        "correlation_data",
        "correlation_data_encoding",
        "message_expiry_interval",
        "payload_format_indicator",
        "user_properties",
    ];
    if let Some(map) = p.as_object() {
        if let Some(unknown) = map.keys().find(|k| !KNOWN.contains(&k.as_str())) {
            anyhow::bail!(
                "unknown PUBLISH property {unknown:?}; known: {}",
                KNOWN.join(", ")
            );
        }
    }
    if let Some(topic) = p.get("response_topic").and_then(|v| v.as_str()) {
        if topic.is_empty() || topic.contains('+') || topic.contains('#') {
            anyhow::bail!("response_topic must be a topic name, without wildcards");
        }
    }
    if let Some(c) = p.get("correlation_data").and_then(|v| v.as_str()) {
        v5::text_to_binary(
            c,
            p.get("correlation_data_encoding").and_then(|e| e.as_str()),
        )
        .map_err(|e| anyhow::anyhow!("correlation_data: {e}"))?;
    }
    if let Some(v) = p.get("payload_format_indicator") {
        if !matches!(v.as_u64(), Some(0 | 1)) {
            anyhow::bail!("payload_format_indicator is 0 or 1");
        }
    }
    if let Some(v) = p.get("message_expiry_interval") {
        if v.as_u64().and_then(|n| u32::try_from(n).ok()).is_none() {
            anyhow::bail!("message_expiry_interval is a number of seconds up to 4294967295");
        }
    }
    v5::user_properties_from_json(p.get("user_properties")).map_err(|e| anyhow::anyhow!(e))?;
    Ok(())
}
