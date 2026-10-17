//! Kafka client protocol actions.
//!
//! The action vocabulary mirrors the five APIs NetGet's own broker implements
//! (`src/server/kafka/CLAUDE.md`): Metadata, Produce, Fetch and OffsetCommit, with
//! ApiVersions handled by the transport before any handler runs. There is deliberately no
//! consumer-group vocabulary — `FindCoordinator`/`JoinGroup`/`SyncGroup`/`Heartbeat` are not
//! implemented on either side, so an action offering group membership would be a promise the
//! wire cannot keep.

use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, Parameter, ParameterDefinition,
};
use crate::protocol::{ConnectContext, EventType};
use crate::state::app_state::AppState;
use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

/// Largest partition index this client will name. Mirrors `MAX_PARTITIONS` on the broker
/// side; a partition index is an `i32` on the wire and is used to size collections.
pub(crate) const MAX_PARTITION: i64 = 1024;

/// Connected event: the TCP session is up, ApiVersions has been negotiated and the first
/// Metadata request has been answered.
pub static KAFKA_CLIENT_CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "kafka_connected",
        "Connected to a Kafka broker: ApiVersions was negotiated and the cluster metadata \
         fetched. `topics` lists what the broker says exists, with the partitions you may \
         address. Reply with produce_message to publish, fetch_records to read, or \
         wait_for_more to sit on the connection.",
        json!({"type": "produce_message", "topic": "events", "value": "Hello Kafka"}),
    )
    .with_parameters(vec![
        Parameter {
            name: "remote_addr".to_string(),
            type_hint: "string".to_string(),
            description: "Broker address this client is connected to".to_string(),
            required: true,
        },
        Parameter {
            name: "cluster_id".to_string(),
            type_hint: "string".to_string(),
            description: "Cluster id reported by the broker, null below Metadata v2".to_string(),
            required: false,
        },
        Parameter {
            name: "controller_id".to_string(),
            type_hint: "number".to_string(),
            description: "Node id of the controller broker".to_string(),
            required: false,
        },
        Parameter {
            name: "brokers".to_string(),
            type_hint: "array".to_string(),
            description: "Cluster members, each with node_id, host and port".to_string(),
            required: true,
        },
        Parameter {
            name: "topics".to_string(),
            type_hint: "array".to_string(),
            description: "Topics the broker described: name, error_code, error_name and a \
                          partitions list of {partition, leader, replicas}"
                .to_string(),
            required: true,
        },
        Parameter {
            name: "api_versions".to_string(),
            type_hint: "object".to_string(),
            description: "The negotiated version of each API this client will use".to_string(),
            required: true,
        },
    ])
    .with_actions(kafka_client_actions())
});

/// Records came back from a Fetch. Only raised when at least one record was returned, so an
/// idle poll costs no model call.
pub static KAFKA_CLIENT_RECORDS_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "kafka_records_received",
        "A Fetch returned records. Each record carries its key and value as text, with \
         key_encoding/value_encoding naming how they were rendered ('utf8', or 'hex' when the \
         bytes were not printable text). `next_offset` is where this client will fetch from \
         next; pass it to commit_offset once the batch is processed.",
        json!({"type": "wait_for_more"}),
    )
    .with_parameters(vec![
        Parameter {
            name: "topic".to_string(),
            type_hint: "string".to_string(),
            description: "Topic the records came from".to_string(),
            required: true,
        },
        Parameter {
            name: "partition".to_string(),
            type_hint: "number".to_string(),
            description: "Partition index".to_string(),
            required: true,
        },
        Parameter {
            name: "high_watermark".to_string(),
            type_hint: "number".to_string(),
            description: "Offset one past the last committed record in the partition".to_string(),
            required: false,
        },
        Parameter {
            name: "next_offset".to_string(),
            type_hint: "number".to_string(),
            description: "Offset this client will fetch from next (last offset + 1)".to_string(),
            required: true,
        },
        Parameter {
            name: "record_count".to_string(),
            type_hint: "number".to_string(),
            description: "How many records the batch held (the `records` list itself is \
                          truncated for readability)"
                .to_string(),
            required: true,
        },
        Parameter {
            name: "records".to_string(),
            type_hint: "array".to_string(),
            description: "Records, each with offset, timestamp, key, key_encoding, value and \
                          value_encoding"
                .to_string(),
            required: true,
        },
        Parameter {
            name: "api_version".to_string(),
            type_hint: "number".to_string(),
            description:
                "Fetch version the request was sent at (13 and above name the topic by id)"
                    .to_string(),
            required: false,
        },
    ])
    .with_actions(kafka_client_actions())
});

/// The broker answered a Produce. Fires whether or not the write succeeded — an error code
/// is reported, never swallowed.
pub static KAFKA_CLIENT_MESSAGE_DELIVERED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "kafka_message_delivered",
        "The broker answered a Produce request. `delivered` is true only when error_code is 0; \
         a non-zero error_code means the record was NOT stored, whatever else the reply says.",
        json!({"type": "wait_for_more"}),
    )
    .with_parameters(vec![
        Parameter {
            name: "topic".to_string(),
            type_hint: "string".to_string(),
            description: "Topic the record was produced to".to_string(),
            required: true,
        },
        Parameter {
            name: "partition".to_string(),
            type_hint: "number".to_string(),
            description: "Partition index".to_string(),
            required: true,
        },
        Parameter {
            name: "base_offset".to_string(),
            type_hint: "number".to_string(),
            description: "Offset the broker assigned to the first record, -1 on failure"
                .to_string(),
            required: true,
        },
        Parameter {
            name: "error_code".to_string(),
            type_hint: "number".to_string(),
            description: "Kafka error code, 0 for success".to_string(),
            required: true,
        },
        Parameter {
            name: "error_name".to_string(),
            type_hint: "string".to_string(),
            description: "Human-readable name of the error code".to_string(),
            required: true,
        },
        Parameter {
            name: "delivered".to_string(),
            type_hint: "boolean".to_string(),
            description: "True only when the broker acknowledged the write".to_string(),
            required: true,
        },
        Parameter {
            name: "api_version".to_string(),
            type_hint: "number".to_string(),
            description: "Produce version the request was sent at".to_string(),
            required: false,
        },
    ])
    .with_actions(kafka_client_actions())
});

/// A `list_topics` action was answered.
pub static KAFKA_CLIENT_METADATA_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "kafka_metadata_received",
        "Cluster metadata returned in answer to a list_topics action. A topic with a non-zero \
         error_code does not exist or is not addressable; do not produce to it.",
        json!({"type": "wait_for_more"}),
    )
    .with_parameters(vec![
        Parameter {
            name: "cluster_id".to_string(),
            type_hint: "string".to_string(),
            description: "Cluster id reported by the broker".to_string(),
            required: false,
        },
        Parameter {
            name: "controller_id".to_string(),
            type_hint: "number".to_string(),
            description: "Node id of the controller broker".to_string(),
            required: false,
        },
        Parameter {
            name: "brokers".to_string(),
            type_hint: "array".to_string(),
            description: "Cluster members, each with node_id, host and port".to_string(),
            required: true,
        },
        Parameter {
            name: "topics".to_string(),
            type_hint: "array".to_string(),
            description: "Topics: name, error_code, error_name and partitions".to_string(),
            required: true,
        },
    ])
    .with_actions(kafka_client_actions())
});

/// Everything a Kafka client handler can answer with.
///
/// One list, returned from both `get_async_actions` and `get_sync_actions`:
/// `call_llm_for_client` (`src/llm/action_helper.rs`) builds the model's tool list from
/// `get_async_actions` alone, so an action living only in the sync list is never offered.
fn kafka_client_actions() -> Vec<ActionDefinition> {
    vec![
        ActionDefinition {
            name: "produce_message".to_string(),
            description: "Publish one record to a topic partition. The key and value are given \
                          as text; set key_encoding/value_encoding to \"hex\" to send bytes \
                          that are not printable text. Raises kafka_message_delivered with the \
                          broker's answer unless acks is 0."
                .to_string(),
            parameters: vec![
                Parameter {
                    name: "topic".to_string(),
                    type_hint: "string".to_string(),
                    description: "Topic name".to_string(),
                    required: true,
                },
                Parameter {
                    name: "value".to_string(),
                    type_hint: "string".to_string(),
                    description: "Record value".to_string(),
                    required: true,
                },
                Parameter {
                    name: "key".to_string(),
                    type_hint: "string".to_string(),
                    description: "Record key, used by brokers for partitioning".to_string(),
                    required: false,
                },
                Parameter {
                    name: "partition".to_string(),
                    type_hint: "number".to_string(),
                    description: "Partition index (default 0). This client addresses a \
                                  partition explicitly; it does not hash keys."
                        .to_string(),
                    required: false,
                },
                Parameter {
                    name: "key_encoding".to_string(),
                    type_hint: "string".to_string(),
                    description: "\"utf8\" (default) or \"hex\"".to_string(),
                    required: false,
                },
                Parameter {
                    name: "value_encoding".to_string(),
                    type_hint: "string".to_string(),
                    description: "\"utf8\" (default) or \"hex\"".to_string(),
                    required: false,
                },
                Parameter {
                    name: "acks".to_string(),
                    type_hint: "number".to_string(),
                    description: "1 (default, leader ack), -1 (all in-sync replicas) or 0 \
                                  (fire and forget - the broker sends no reply at all, so no \
                                  kafka_message_delivered event is raised)"
                        .to_string(),
                    required: false,
                },
            ],
            example: json!({
                "type": "produce_message",
                "topic": "orders",
                "key": "order-1",
                "value": "{\"item\":\"laptop\"}"
            }),
            log_template: None,
        },
        ActionDefinition {
            name: "fetch_records".to_string(),
            description: "Read records from a topic partition starting at an offset. Raises \
                          kafka_records_received when the broker returns at least one record. \
                          The partition is also added to this client's poll set, so later \
                          records arrive without asking again."
                .to_string(),
            parameters: vec![
                Parameter {
                    name: "topic".to_string(),
                    type_hint: "string".to_string(),
                    description: "Topic name".to_string(),
                    required: true,
                },
                Parameter {
                    name: "partition".to_string(),
                    type_hint: "number".to_string(),
                    description: "Partition index (default 0)".to_string(),
                    required: false,
                },
                Parameter {
                    name: "offset".to_string(),
                    type_hint: "number".to_string(),
                    description: "Offset to fetch from. Defaults to this client's tracked \
                                  position for the partition, or the configured start_offset. \
                                  There is no \"latest\"/\"earliest\": resolving those needs \
                                  ListOffsets, which is not implemented."
                        .to_string(),
                    required: false,
                },
                Parameter {
                    name: "max_bytes".to_string(),
                    type_hint: "number".to_string(),
                    description: "Maximum response bytes for this partition (default 1048576)"
                        .to_string(),
                    required: false,
                },
            ],
            example: json!({
                "type": "fetch_records",
                "topic": "orders",
                "partition": 0,
                "offset": 0
            }),
            log_template: None,
        },
        ActionDefinition {
            name: "list_topics".to_string(),
            description: "Ask the broker for cluster metadata. Omit `topics` for everything the \
                          broker will describe. Raises kafka_metadata_received."
                .to_string(),
            parameters: vec![Parameter {
                name: "topics".to_string(),
                type_hint: "array".to_string(),
                description: "Topic names to describe; omit for all topics".to_string(),
                required: false,
            }],
            example: json!({"type": "list_topics", "topics": ["orders"]}),
            log_template: None,
        },
        ActionDefinition {
            name: "commit_offset".to_string(),
            description: "Commit a consumed offset for a topic partition. Note that this client \
                          is not a consumer-group member (group coordination is not \
                          implemented), so the commit is a bare OffsetCommit request with no \
                          generation or member id."
                .to_string(),
            parameters: vec![
                Parameter {
                    name: "topic".to_string(),
                    type_hint: "string".to_string(),
                    description: "Topic name".to_string(),
                    required: true,
                },
                Parameter {
                    name: "offset".to_string(),
                    type_hint: "number".to_string(),
                    description: "Offset to commit - normally next_offset from \
                                  kafka_records_received"
                        .to_string(),
                    required: true,
                },
                Parameter {
                    name: "partition".to_string(),
                    type_hint: "number".to_string(),
                    description: "Partition index (default 0)".to_string(),
                    required: false,
                },
                Parameter {
                    name: "group_id".to_string(),
                    type_hint: "string".to_string(),
                    description: "Consumer group id to commit under (default: the client's \
                                  group_id startup parameter)"
                        .to_string(),
                    required: false,
                },
            ],
            example: json!({"type": "commit_offset", "topic": "orders", "offset": 43}),
            log_template: None,
        },
        ActionDefinition {
            name: "disconnect".to_string(),
            description: "Close the connection to the broker".to_string(),
            parameters: vec![],
            example: json!({"type": "disconnect"}),
            log_template: None,
        },
        ActionDefinition {
            name: "wait_for_more".to_string(),
            description: "Do nothing and keep the connection open".to_string(),
            parameters: vec![],
            example: json!({"type": "wait_for_more"}),
            log_template: None,
        },
    ]
}

/// Human-readable name for the Kafka error codes this client can encounter.
///
/// Reporting `error_code: 3` alone leaves a model guessing; naming it does not.
pub(crate) fn kafka_error_name(code: i16) -> &'static str {
    match code {
        -1 => "UNKNOWN_SERVER_ERROR",
        0 => "NONE",
        1 => "OFFSET_OUT_OF_RANGE",
        2 => "CORRUPT_MESSAGE",
        3 => "UNKNOWN_TOPIC_OR_PARTITION",
        5 => "LEADER_NOT_AVAILABLE",
        6 => "NOT_LEADER_OR_FOLLOWER",
        7 => "REQUEST_TIMED_OUT",
        8 => "BROKER_NOT_AVAILABLE",
        9 => "REPLICA_NOT_AVAILABLE",
        10 => "MESSAGE_TOO_LARGE",
        13 => "NETWORK_EXCEPTION",
        16 => "NOT_COORDINATOR",
        17 => "INVALID_TOPIC_EXCEPTION",
        22 => "ILLEGAL_GENERATION",
        25 => "UNKNOWN_MEMBER_ID",
        27 => "REBALANCE_IN_PROGRESS",
        35 => "UNSUPPORTED_VERSION",
        37 => "INVALID_PARTITIONS",
        _ => "UNKNOWN_ERROR_CODE",
    }
}

/// Validate a partition index from an action.
fn partition_from(action: &Value) -> Result<i32> {
    let raw = match action.get("partition") {
        None | Some(Value::Null) => 0,
        Some(v) => v.as_i64().context("'partition' must be a whole number")?,
    };
    if !(0..=MAX_PARTITION).contains(&raw) {
        bail!("'partition' must be between 0 and {MAX_PARTITION}, got {raw}");
    }
    Ok(raw as i32)
}

/// Validate an encoding name at the point the action is parsed, so a bad one is a failed
/// action rather than literal ASCII on the wire.
fn encoding_from(action: &Value, field: &str) -> Result<String> {
    match action.get(field) {
        None | Some(Value::Null) => Ok("utf8".to_string()),
        Some(Value::String(s)) if s == "utf8" || s == "hex" => Ok(s.clone()),
        Some(other) => bail!("'{field}' must be \"utf8\" or \"hex\", got {other}"),
    }
}

fn non_empty_topic(action: &Value) -> Result<String> {
    let topic = action
        .get("topic")
        .and_then(|v| v.as_str())
        .context("Missing 'topic' field")?;
    if topic.is_empty() {
        bail!("'topic' must not be empty");
    }
    Ok(topic.to_string())
}

/// Kafka client protocol action handler
pub struct KafkaClientProtocol;

impl KafkaClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

impl Default for KafkaClientProtocol {
    fn default() -> Self {
        Self::new()
    }
}

impl Protocol for KafkaClientProtocol {
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "client_id".to_string(),
                description: "Kafka client id sent in every request header".to_string(),
                type_hint: "string".to_string(),
                required: false,
                example: json!("netget-kafka-client"),
                default: None,
            },
            ParameterDefinition {
                name: "topics".to_string(),
                description: "Topics to describe at connect and then poll for records. Each is \
                              polled on the partition given by `partition`, starting at \
                              `start_offset`. Omit to connect without consuming."
                    .to_string(),
                type_hint: "array".to_string(),
                required: false,
                example: json!(["orders"]),
                default: None,
            },
            ParameterDefinition {
                name: "partition".to_string(),
                description: "Partition to poll for each topic in `topics` (default 0). This \
                              client assigns partitions manually because consumer groups are \
                              not implemented."
                    .to_string(),
                type_hint: "integer".to_string(),
                required: false,
                example: json!(0),
                default: None,
            },
            ParameterDefinition {
                name: "start_offset".to_string(),
                description: "Offset to start polling from (default 0). There is no \
                              earliest/latest resolution: that needs ListOffsets, which \
                              NetGet's broker does not implement."
                    .to_string(),
                type_hint: "integer".to_string(),
                required: false,
                example: json!(0),
                default: None,
            },
            ParameterDefinition {
                name: "poll_interval_ms".to_string(),
                description: "Delay between Fetch rounds when polling (default 1000, minimum 50)"
                    .to_string(),
                type_hint: "integer".to_string(),
                required: false,
                example: json!(1000),
                default: None,
            },
            ParameterDefinition {
                name: "group_id".to_string(),
                description: "Group id used by commit_offset when the action does not name one"
                    .to_string(),
                type_hint: "string".to_string(),
                required: false,
                example: json!("netget-consumer-group"),
                default: None,
            },
        ]
    }
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        kafka_client_actions()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        kafka_client_actions()
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            KAFKA_CLIENT_CONNECTED_EVENT.clone(),
            KAFKA_CLIENT_RECORDS_RECEIVED_EVENT.clone(),
            KAFKA_CLIENT_MESSAGE_DELIVERED_EVENT.clone(),
            KAFKA_CLIENT_METADATA_RECEIVED_EVENT.clone(),
        ]
    }
    fn protocol_name(&self) -> &'static str {
        "Kafka"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>Kafka"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "kafka",
            "kafka client",
            "connect to kafka",
            "kafka producer",
            "kafka consumer",
        ]
    }
    fn description(&self) -> &'static str {
        "Kafka client: produce records, fetch records, read cluster metadata"
    }
    fn example_prompt(&self) -> &'static str {
        "Connect to Kafka at localhost:9092 and send a message to the 'events' topic"
    }
    fn group_name(&self) -> &'static str {
        "Messaging"
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{
            DevelopmentState, PrivilegeRequirement, ProtocolMetadataV2,
        };

        ProtocolMetadataV2::builder()
            // Beta on the client bar: a real third-party broker (Apache Kafka 3.9.1, the
            // reference implementation, not the crate this client frames with), a test that
            // fails rather than skips without it, a full session, and the model's answer
            // asserted from the broker's side (tests/client/kafka/real_server_test.rs).
            .state(DevelopmentState::Beta)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation(
                "Pure-Rust Kafka client over kafka-protocol's code-generated request \
                 encoders and response decoders, reached through the `kafka_protocol` \
                 re-export the Kafka broker shares. Negotiates up to Metadata v12, Produce v11, \
                 Fetch v16 (by the topic id Metadata reported; by name at v12 when a broker \
                 reports none) and OffsetCommit v9. rdkafka/librdkafka is gone.",
            )
            .llm_control(
                "Produce records, fetch records from an explicit offset, read cluster \
                 metadata, commit offsets",
            )
            .e2e_testing(
                "Apache Kafka 3.9.1 (the official release, single-node KRaft, in a temp dir; \
                 tests/client/kafka/real_server_test.rs): kcat seeds a record, NetGet fetches it \
                 at Fetch v16, a handler produces a derived record at Produce v11 and commits \
                 the offset at OffsetCommit v9, and kcat and Kafka's own kafka-consumer-groups.sh \
                 read both back from the broker. Fails, not skips, without the broker. Also \
                 NetGet's own broker in-process (tests/client/kafka/e2e_test.rs).",
            )
            .notes(
                "No consumer groups (FindCoordinator/JoinGroup/SyncGroup/Heartbeat are \
                 implemented by neither half): partitions are assigned manually, offsets are \
                 explicit, and a commit is sent to the bootstrap broker as a simple commit \
                 (generation/epoch -1), which a single-broker cluster accepts once its offsets \
                 topic exists. No ListOffsets, so there is no earliest/latest resolution; no \
                 SSL/SASL, no transactions, no compression on the produce path (compressed \
                 batches are decoded on the fetch path).",
            )
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;

        StartupExamples::new(
            // LLM mode: the model decides what to publish and what to do with what arrives.
            json!({
                "type": "open_client",
                "remote_addr": "localhost:9092",
                "base_stack": "kafka",
                "startup_params": {
                    "topics": ["events"],
                    "partition": 0,
                    "start_offset": 0
                },
                "instruction": "Read the events topic and summarise each record into memory"
            }),
            // Script mode: deterministic handling of each batch.
            json!({
                "type": "open_client",
                "remote_addr": "localhost:9092",
                "base_stack": "kafka",
                "startup_params": {
                    "topics": ["events"],
                    "poll_interval_ms": 500
                },
                "event_handlers": [{
                    "event_pattern": "kafka_records_received",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "<kafka_client_handler>"
                    }
                }]
            }),
            // Static mode: publish one record on connect, then stop.
            json!({
                "type": "open_client",
                "remote_addr": "localhost:9092",
                "base_stack": "kafka",
                "startup_params": {"client_id": "netget-producer"},
                "event_handlers": [
                    {
                        "event_pattern": "kafka_connected",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "produce_message",
                                "topic": "events",
                                "value": "{\"event\": \"startup\"}"
                            }]
                        }
                    },
                    {
                        "event_pattern": "kafka_message_delivered",
                        "handler": {
                            "type": "static",
                            "actions": [{"type": "disconnect"}]
                        }
                    }
                ]
            }),
        )
    }
}

impl Client for KafkaClientProtocol {
    fn connect(
        &self,
        ctx: ConnectContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(async move {
            use crate::client::kafka::KafkaClient;
            KafkaClient::connect_with_llm_actions(
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

    /// Parse and validate an action.
    ///
    /// Kafka requests carry a correlation id and a negotiated API version and are answered on
    /// the same connection, so an action cannot be turned into bytes here the way a BGP
    /// KEEPALIVE can. Each one becomes a `Custom` result that `KafkaClient` performs as a
    /// request/response exchange. Everything that can be judged without the socket - a missing
    /// topic, an out-of-range partition, an unknown encoding, a negative offset - is judged
    /// here, so a malformed action fails as an action instead of reaching the wire.
    fn execute_action(&self, action: Value) -> Result<ClientActionResult> {
        let action_type = action
            .get("type")
            .and_then(|v| v.as_str())
            .context("Missing 'type' field in action")?;

        match action_type {
            "produce_message" => {
                let topic = non_empty_topic(&action)?;
                let partition = partition_from(&action)?;
                let value = action
                    .get("value")
                    .filter(|v| !v.is_null())
                    .context("Missing 'value' field (the record payload)")?
                    .clone();
                let key = action.get("key").filter(|v| !v.is_null()).cloned();
                let key_encoding = encoding_from(&action, "key_encoding")?;
                let value_encoding = encoding_from(&action, "value_encoding")?;
                let acks = match action.get("acks") {
                    None | Some(Value::Null) => 1i64,
                    Some(v) => v.as_i64().context("'acks' must be 0, 1 or -1")?,
                };
                if !matches!(acks, -1..=1) {
                    bail!("'acks' must be 0, 1 or -1, got {acks}");
                }

                Ok(ClientActionResult::Custom {
                    name: "kafka_produce".to_string(),
                    data: json!({
                        "topic": topic,
                        "partition": partition,
                        "key": key,
                        "value": value,
                        "key_encoding": key_encoding,
                        "value_encoding": value_encoding,
                        "acks": acks,
                    }),
                })
            }
            "fetch_records" => {
                let topic = non_empty_topic(&action)?;
                let partition = partition_from(&action)?;
                let offset = match action.get("offset") {
                    None | Some(Value::Null) => None,
                    Some(v) => {
                        let n = v.as_i64().context("'offset' must be a whole number")?;
                        if n < 0 {
                            bail!("'offset' must not be negative, got {n}");
                        }
                        Some(n)
                    }
                };
                let max_bytes = match action.get("max_bytes") {
                    None | Some(Value::Null) => None,
                    Some(v) => {
                        let n = v.as_i64().context("'max_bytes' must be a whole number")?;
                        if !(1..=i64::from(i32::MAX)).contains(&n) {
                            bail!("'max_bytes' must be between 1 and {}, got {n}", i32::MAX);
                        }
                        Some(n)
                    }
                };

                Ok(ClientActionResult::Custom {
                    name: "kafka_fetch".to_string(),
                    data: json!({
                        "topic": topic,
                        "partition": partition,
                        "offset": offset,
                        "max_bytes": max_bytes,
                    }),
                })
            }
            "list_topics" => {
                let topics = match action.get("topics") {
                    None | Some(Value::Null) => None,
                    Some(Value::Array(items)) => {
                        let names: Vec<String> = items
                            .iter()
                            .filter_map(|v| v.as_str())
                            .filter(|s| !s.is_empty())
                            .map(|s| s.to_string())
                            .collect();
                        if names.is_empty() {
                            bail!("'topics' was given but held no usable topic name");
                        }
                        Some(names)
                    }
                    Some(other) => bail!("'topics' must be an array of names, got {other}"),
                };

                Ok(ClientActionResult::Custom {
                    name: "kafka_metadata".to_string(),
                    data: json!({"topics": topics}),
                })
            }
            "commit_offset" => {
                let topic = non_empty_topic(&action)?;
                let partition = partition_from(&action)?;
                // No default. Committing an offset the handler did not name would acknowledge
                // consumption that may not have happened.
                let offset = action.get("offset").and_then(|v| v.as_i64()).context(
                    "commit_offset requires 'offset' (normally next_offset from \
                              kafka_records_received)",
                )?;
                if offset < 0 {
                    bail!("'offset' must not be negative, got {offset}");
                }
                let group_id = action
                    .get("group_id")
                    .and_then(|v| v.as_str())
                    .filter(|s| !s.is_empty())
                    .map(|s| s.to_string());

                Ok(ClientActionResult::Custom {
                    name: "kafka_commit".to_string(),
                    data: json!({
                        "topic": topic,
                        "partition": partition,
                        "offset": offset,
                        "group_id": group_id,
                    }),
                })
            }
            "disconnect" => Ok(ClientActionResult::Disconnect),
            "wait_for_more" => Ok(ClientActionResult::WaitForMore),
            _ => Err(anyhow::anyhow!(
                "Unknown Kafka client action: {}",
                action_type
            )),
        }
    }
}
