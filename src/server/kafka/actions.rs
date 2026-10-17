//! Kafka protocol actions and LLM integration
//!
//! Rust owns the Kafka wire format; the model owns the content. Every event declared
//! here is emitted by `src/server/kafka/mod.rs`, and every action declared here is
//! consumed there. ApiVersions is the one request the model never sees — it advertises
//! what this code can parse, which is not a content decision.

use crate::llm::actions::protocol_trait::{ActionResult, Protocol};
use crate::llm::actions::{ActionDefinition, Parameter, ParameterDefinition, Server};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::EventType;
use crate::state::app_state::AppState;
use anyhow::{anyhow, Result};
use once_cell::sync::Lazy;
use serde_json::{json, Value};

/// Event: Kafka produce request received.
///
/// Emitted once per (topic, partition) in a Produce request, after Rust has decoded and
/// decompressed the record batch. A batch that cannot be decoded never reaches the
/// model: the producer gets CORRUPT_MESSAGE.
pub static PRODUCE_REQUEST_EVENT: Lazy<EventType> = Lazy::new(|| {
    EventType::new(
        "kafka_produce_request",
        "Triggered when a Kafka producer sends records to a topic partition",
        json!({
            "type": "produce_response",
            "topic": "orders",
            "partition": 0,
            "offset": 42,
            "error_code": 0
        }),
    )
    .with_actions(vec![produce_response_action(), error_response_action()])
    .with_parameters(vec![
        Parameter {
            name: "topic".to_string(),
            type_hint: "string".to_string(),
            description: "Topic name".to_string(),
            required: true,
        },
        Parameter {
            name: "partition".to_string(),
            type_hint: "number".to_string(),
            description: "Partition number".to_string(),
            required: true,
        },
        Parameter {
            name: "record_count".to_string(),
            type_hint: "number".to_string(),
            description: "Number of records in the batch".to_string(),
            required: true,
        },
        Parameter {
            name: "first_key".to_string(),
            type_hint: "string".to_string(),
            description: "Key of the first record, null if it has none".to_string(),
            required: false,
        },
        Parameter {
            name: "first_value_preview".to_string(),
            type_hint: "string".to_string(),
            description: "Value of the first record, truncated for the prompt".to_string(),
            required: true,
        },
        Parameter {
            name: "records".to_string(),
            type_hint: "array".to_string(),
            description: "Up to 20 decoded records: [{offset, timestamp, key, key_encoding, \
                          value, value_encoding}]. `*_encoding` is \"utf8\" when the bytes were \
                          printable text and \"hex\" when they were not"
                .to_string(),
            required: true,
        },
        Parameter {
            name: "acks".to_string(),
            type_hint: "number".to_string(),
            description: "Producer's requested acknowledgement level. With acks=0 the producer \
                          is not waiting for a reply and no response is sent"
                .to_string(),
            required: false,
        },
        Parameter {
            name: "client_id".to_string(),
            type_hint: "string".to_string(),
            description: "client_id from the request header (empty if absent)".to_string(),
            required: false,
        },
        Parameter {
            name: "api_version".to_string(),
            type_hint: "number".to_string(),
            description: "Produce API version the client negotiated".to_string(),
            required: false,
        },
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("Kafka produce {topic}")
            .with_debug(
                "Kafka produce topic={topic}, partition={partition}, records={record_count}",
            )
            .with_trace("Kafka produce: {json_pretty(.)}"),
    )
});

/// Event: Kafka fetch request received.
///
/// Emitted once per (topic, partition) in a Fetch request. The broker keeps no log, so
/// the records in the reply are whatever the model, script or static handler supplies.
pub static FETCH_REQUEST_EVENT: Lazy<EventType> = Lazy::new(|| {
    EventType::new(
        "kafka_fetch_request",
        "Triggered when a Kafka consumer requests records from a topic partition",
        json!({
            "type": "fetch_response",
            "topic": "orders",
            "partition": 0,
            "records": [
                {"offset": 40, "key": "order123", "value": "{\"item\": \"laptop\"}"},
                {"offset": 41, "key": "order124", "value": "{\"item\": \"mouse\"}"}
            ]
        }),
    )
    .with_actions(vec![fetch_response_action(), error_response_action()])
    .with_parameters(vec![
        Parameter {
            name: "topic".to_string(),
            type_hint: "string".to_string(),
            description: "Topic name".to_string(),
            required: true,
        },
        Parameter {
            name: "partition".to_string(),
            type_hint: "number".to_string(),
            description: "Partition number".to_string(),
            required: true,
        },
        Parameter {
            name: "fetch_offset".to_string(),
            type_hint: "number".to_string(),
            description: "Offset the consumer wants to read from. Returned records start here"
                .to_string(),
            required: true,
        },
        Parameter {
            name: "max_bytes".to_string(),
            type_hint: "number".to_string(),
            description: "Maximum bytes the consumer will accept for this partition".to_string(),
            required: true,
        },
        Parameter {
            name: "client_id".to_string(),
            type_hint: "string".to_string(),
            description: "client_id from the request header (empty if absent)".to_string(),
            required: false,
        },
        Parameter {
            name: "api_version".to_string(),
            type_hint: "number".to_string(),
            description: "Fetch API version the client negotiated".to_string(),
            required: false,
        },
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("Kafka fetch {topic}")
            .with_debug("Kafka fetch topic={topic}, partition={partition}, offset={fetch_offset}")
            .with_trace("Kafka fetch: {json_pretty(.)}"),
    )
});

/// Event: Kafka metadata request received.
///
/// Emitted once per Metadata request. This is the request that decides whether a client
/// can do anything at all: it must learn which topics exist and which broker leads each
/// partition.
pub static METADATA_REQUEST_EVENT: Lazy<EventType> = Lazy::new(|| {
    EventType::new(
        "kafka_metadata_request",
        "Triggered when a client requests cluster/topic metadata",
        json!({
            "type": "metadata_response",
            "brokers": [{"id": 0, "host": "localhost", "port": 9092}],
            "topics": [
                {
                    "name": "orders",
                    "partitions": [{"partition": 0, "leader": 0, "replicas": [0]}]
                }
            ]
        }),
    )
    .with_actions(vec![metadata_response_action(), error_response_action()])
    .with_parameters(vec![
        Parameter {
            name: "requested_topics".to_string(),
            type_hint: "array".to_string(),
            description:
                "Topic names the client asked about. Any name here that your response \
                          does not describe is reported to the client as UNKNOWN_TOPIC_OR_PARTITION"
                    .to_string(),
            required: true,
        },
        Parameter {
            name: "all_topics".to_string(),
            type_hint: "boolean".to_string(),
            description: "True when the client asked for every topic rather than named ones"
                .to_string(),
            required: true,
        },
        Parameter {
            name: "client_id".to_string(),
            type_hint: "string".to_string(),
            description: "client_id from the request header (empty if absent)".to_string(),
            required: false,
        },
        Parameter {
            name: "api_version".to_string(),
            type_hint: "number".to_string(),
            description: "Metadata API version the client negotiated".to_string(),
            required: false,
        },
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("Kafka metadata request")
            .with_debug("Kafka metadata request, topics={requested_topics}")
            .with_trace("Kafka metadata: {json_pretty(.)}"),
    )
});

/// Event: Kafka offset commit request received.
///
/// Emitted once per (topic, partition) in an OffsetCommit request. Nothing is stored, and
/// OffsetFetch is not implemented, so an accepted commit is an acknowledgement and
/// nothing more.
pub static OFFSET_COMMIT_REQUEST_EVENT: Lazy<EventType> = Lazy::new(|| {
    EventType::new(
        "kafka_offset_commit_request",
        "Triggered when a consumer commits offsets for a topic partition",
        json!({
            "type": "offset_commit_response",
            "topic": "orders",
            "partition": 0,
            "error_code": 0
        }),
    )
    .with_actions(vec![
        offset_commit_response_action(),
        error_response_action(),
    ])
    .with_parameters(vec![
        Parameter {
            name: "group_id".to_string(),
            type_hint: "string".to_string(),
            description: "Consumer group ID".to_string(),
            required: true,
        },
        Parameter {
            name: "topic".to_string(),
            type_hint: "string".to_string(),
            description: "Topic name".to_string(),
            required: true,
        },
        Parameter {
            name: "partition".to_string(),
            type_hint: "number".to_string(),
            description: "Partition number".to_string(),
            required: true,
        },
        Parameter {
            name: "offset".to_string(),
            type_hint: "number".to_string(),
            description: "Offset the consumer wants to commit".to_string(),
            required: true,
        },
        Parameter {
            name: "client_id".to_string(),
            type_hint: "string".to_string(),
            description: "client_id from the request header (empty if absent)".to_string(),
            required: false,
        },
        Parameter {
            name: "api_version".to_string(),
            type_hint: "number".to_string(),
            description: "OffsetCommit API version the client negotiated".to_string(),
            required: false,
        },
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("Kafka offset commit {topic}")
            .with_debug("Kafka offset commit group={group_id}, topic={topic}, partition={partition}, offset={offset}")
            .with_trace("Kafka offset commit: {json_pretty(.)}"),
    )
});

/// Kafka protocol implementation
pub struct KafkaProtocol;

impl KafkaProtocol {
    pub fn new() -> Self {
        Self
    }
}

impl Default for KafkaProtocol {
    fn default() -> Self {
        Self::new()
    }
}

// Helper functions for action definitions

fn produce_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "produce_response".to_string(),
        description: "Answer a Kafka produce request: accept the records at an offset, or \
                      reject them with an error code"
            .to_string(),
        parameters: vec![
            Parameter {
                name: "topic".to_string(),
                type_hint: "string".to_string(),
                description: "Topic name (echo the topic from the event)".to_string(),
                required: true,
            },
            Parameter {
                name: "partition".to_string(),
                type_hint: "number".to_string(),
                description: "Partition number (echo the partition from the event)".to_string(),
                required: true,
            },
            Parameter {
                name: "offset".to_string(),
                type_hint: "number".to_string(),
                description: "Base offset assigned to the first record in the batch".to_string(),
                required: true,
            },
            Parameter {
                name: "error_code".to_string(),
                type_hint: "number".to_string(),
                description: "Kafka error code; 0 (default) accepts the batch".to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "produce_response",
            "topic": "orders",
            "partition": 0,
            "offset": 42,
            "error_code": 0
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> Kafka produce OK offset={offset}")
                .with_debug(
                    "Kafka produce_response: topic={topic}, partition={partition}, offset={offset}",
                ),
        ),
    }
}

fn fetch_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "fetch_response".to_string(),
        description: "Answer a Kafka fetch request with the records the consumer should see. \
                      An empty array is a valid answer meaning 'nothing new'"
            .to_string(),
        parameters: vec![
            Parameter {
                name: "topic".to_string(),
                type_hint: "string".to_string(),
                description: "Topic name (echo the topic from the event)".to_string(),
                required: true,
            },
            Parameter {
                name: "partition".to_string(),
                type_hint: "number".to_string(),
                description: "Partition number (echo the partition from the event)".to_string(),
                required: true,
            },
            Parameter {
                name: "records".to_string(),
                type_hint: "array".to_string(),
                description: "Records to return: [{offset, key, value, key_encoding, \
                              value_encoding}]. `key`/`value` are text by default; set \
                              `value_encoding` to \"hex\" to send raw bytes as a hex string. \
                              Offsets are made contiguous starting at the first record's offset, \
                              which is never lower than the request's fetch_offset"
                    .to_string(),
                required: true,
            },
        ],
        example: json!({
            "type": "fetch_response",
            "topic": "orders",
            "partition": 0,
            "records": [
                {"offset": 40, "key": "order123", "value": "{\"item\": \"laptop\"}"},
                {"offset": 41, "key": "order124", "value": "{\"item\": \"mouse\"}"}
            ]
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> Kafka fetch {records_len} records")
                .with_debug("Kafka fetch_response: topic={topic}, partition={partition}, {records_len} records"),
        ),
    }
}

fn metadata_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "metadata_response".to_string(),
        description: "Answer a Kafka metadata request: which brokers exist and which topics and \
                      partitions they lead"
            .to_string(),
        parameters: vec![
            Parameter {
                name: "brokers".to_string(),
                type_hint: "array".to_string(),
                description: "Brokers [{id, host, port}]. Omit this to advertise this NetGet \
                              server itself, which is almost always what you want — a client \
                              cannot connect to a broker address that does not exist"
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "topics".to_string(),
                type_hint: "array".to_string(),
                description: "Topics [{name, partitions: [{partition, leader, replicas}]}]. \
                              `leader` defaults to this broker's id. A topic listed with no \
                              partitions is given one partition led by this broker. Any topic \
                              the client asked about but you omit is reported as unknown"
                    .to_string(),
                required: true,
            },
        ],
        example: json!({
            "type": "metadata_response",
            "brokers": [{"id": 0, "host": "localhost", "port": 9092}],
            "topics": [
                {
                    "name": "orders",
                    "partitions": [{"partition": 0, "leader": 0, "replicas": [0]}]
                }
            ]
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> Kafka metadata {topics_len} topics")
                .with_debug("Kafka metadata_response: {brokers_len} brokers, {topics_len} topics"),
        ),
    }
}

fn offset_commit_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "offset_commit_response".to_string(),
        description: "Acknowledge (or reject) an offset commit".to_string(),
        parameters: vec![
            Parameter {
                name: "topic".to_string(),
                type_hint: "string".to_string(),
                description: "Topic name (echo the topic from the event)".to_string(),
                required: true,
            },
            Parameter {
                name: "partition".to_string(),
                type_hint: "number".to_string(),
                description: "Partition number (echo the partition from the event)".to_string(),
                required: true,
            },
            Parameter {
                name: "error_code".to_string(),
                type_hint: "number".to_string(),
                description: "Kafka error code; 0 (default) accepts the commit".to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "offset_commit_response",
            "topic": "orders",
            "partition": 0,
            "error_code": 0
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> Kafka offset commit OK")
                .with_debug("Kafka offset_commit_response: topic={topic}, partition={partition}"),
        ),
    }
}

fn error_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "error_response".to_string(),
        description: "Refuse the request. The error code is carried in the correct response type \
                      for whichever API was called, so the client sees a proper Kafka error \
                      rather than silence"
            .to_string(),
        parameters: vec![
            Parameter {
                name: "error_code".to_string(),
                type_hint: "number".to_string(),
                description: "Kafka error code, e.g. 3 = UNKNOWN_TOPIC_OR_PARTITION, \
                              -1 = UNKNOWN_SERVER_ERROR. 0 is not accepted here: an error \
                              response that says success is treated as -1"
                    .to_string(),
                required: true,
            },
            Parameter {
                name: "error_message".to_string(),
                type_hint: "string".to_string(),
                description: "Human-readable description, logged only — Kafka's wire format has \
                              no place for it in these responses"
                    .to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "error_response",
            "error_code": 3,
            "error_message": "Unknown topic or partition"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> Kafka error {error_code}")
                .with_debug("Kafka error_response: code={error_code}, message={error_message}"),
        ),
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for KafkaProtocol {
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "cluster_id".to_string(),
                type_hint: "string".to_string(),
                description: "Cluster identifier reported in Metadata responses (v2 and above; \
                              earlier Metadata versions have no such field)"
                    .to_string(),
                required: false,
                example: json!("netget-kafka-1"),
                default: None,
            },
            ParameterDefinition {
                name: "broker_id".to_string(),
                type_hint: "number".to_string(),
                description: "Broker ID reported in Metadata, and the default partition leader"
                    .to_string(),
                required: false,
                example: json!(0),
                default: None,
            },
            ParameterDefinition {
                name: "advertised_host".to_string(),
                type_hint: "string".to_string(),
                description: "Hostname advertised to clients in Metadata when the response does \
                              not name one. Defaults to the bound address, or localhost when \
                              bound to a wildcard address"
                    .to_string(),
                required: false,
                example: json!("localhost"),
                default: None,
            },
        ]
    }

    /// Kafka is strictly pull-based: a broker cannot push a record to a consumer, it can
    /// only answer a Fetch. And this broker stores nothing, so there is no topic list to
    /// create or delete against. There is therefore no useful server-initiated action —
    /// an earlier version declared `publish_message`, `create_topic`, `delete_topic` and
    /// `set_retention`, none of which had, or could have, an implementation.
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        Vec::new()
    }

    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            produce_response_action(),
            fetch_response_action(),
            metadata_response_action(),
            offset_commit_response_action(),
            error_response_action(),
        ]
    }
    fn protocol_name(&self) -> &'static str {
        "KAFKA"
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            PRODUCE_REQUEST_EVENT.clone(),
            FETCH_REQUEST_EVENT.clone(),
            METADATA_REQUEST_EVENT.clone(),
            OFFSET_COMMIT_REQUEST_EVENT.clone(),
        ]
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>KAFKA"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["kafka", "kafka broker", "via kafka"]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            // Beta since September 2026: librdkafka -- a separate C implementation, not the
            // kafka-protocol crate this server frames with -- completes a produce and a fetch
            // against it, and so do Apache Kafka's Java client and franz-go. Not Stable: the
            // other five conditions have not been worked through, and consumer groups do not
            // work at all (see notes).
            .state(DevelopmentState::Beta)
            .well_known_port(9092)
            .implementation(
                "kafka-protocol v0.14 wire format. Implements ApiVersions v0-3 (answered by Rust), \
                 Metadata v0-12, Produce v0-11, Fetch v0-16, OffsetCommit v0-9: the newest \
                 versions the crate knows, flexible (tagged-field) ones included. Topic ids \
                 (Metadata v10+, Fetch v13+) are derived from the topic name, since nothing is \
                 stored to keep an assigned one",
            )
            .llm_control(
                "Metadata, Produce, Fetch and OffsetCommit responses. The model chooses which \
                 topics and partitions exist, whether a produce is accepted and at what offset, \
                 and exactly which records a fetch returns",
            )
            .e2e_testing(
                "Three independent clients, none built on the kafka-protocol crate this server \
                 frames with. kcat 1.7 on librdkafka (tests/server/kafka/real_client_test.rs): \
                 ApiVersions -> Metadata -> Produce and a second run that Fetches and prints the \
                 key and value back, so librdkafka accepted the batch this server encoded; it \
                 negotiates Metadata v12, Produce v7 and Fetch v11. Apache Kafka's own Java \
                 client 3.9.1 and franz-go 1.18.1 (tests/server/kafka/flexible_versions_test.rs) \
                 each produce and then consume at the newest versions, Metadata v12, Produce \
                 v11 and Fetch v16 by topic id, and print a record whose value names the Fetch \
                 version it was served at. None is #[ignore]d; all fail rather than skip. Also \
                 mocked E2E against kafka-protocol's own client-side codecs, with the tshark \
                 oracle. UNPROVEN: consumer groups (the APIs do not exist here), compression, \
                 transactions, TLS/SASL, multi-broker metadata, any Fetch that must resolve an \
                 offset (ListOffsets is not implemented), and OffsetCommit v8+ from a \
                 third-party client, which would need a coordinator first.",
            )
            .notes(
                "Supports exactly five API keys: ApiVersions (18) v0-3, Metadata (3) v0-12, \
                 Produce (0) v0-11, Fetch (1) v0-16, OffsetCommit (8) v0-9. Topic ids are a \
                 hash of the name (stable across restarts); one this broker never reported gets \
                 UNKNOWN_TOPIC_ID (100), and the most recent 4096 are remembered for resolving \
                 Fetch v13+ and Metadata v12 by-id requests. Any other API key — ListOffsets, \
                 FindCoordinator, JoinGroup, SyncGroup, Heartbeat, OffsetFetch, the admin APIs \
                 — is not advertised and closes the connection with a logged error if sent, so \
                 consumer groups do not work: a consumer must assign partitions manually and \
                 fetch from an explicit offset. The broker stores nothing, so a Fetch returns \
                 only what the model supplies for that request and a committed offset is \
                 acknowledged but not remembered. When the model returns no usable action the \
                 client gets UNKNOWN_SERVER_ERROR (-1) in the correct response type, never a \
                 fabricated success.",
            )
            .max_inbound_bytes(crate::server::kafka::MAX_REQUEST_BYTES)
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn description(&self) -> &'static str {
        "Apache Kafka broker: ApiVersions, Metadata, Produce, Fetch and OffsetCommit, with the \
         LLM deciding topics, offsets and record contents"
    }
    fn example_prompt(&self) -> &'static str {
        "Start a Kafka broker on port 9092 with a topic 'orders' with one partition; accept \
         produces and return the produced records when a consumer fetches"
    }
    fn group_name(&self) -> &'static str {
        "Database"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;

        StartupExamples::new(
            // LLM mode: the model answers each request
            json!({
                "type": "open_server",
                "port": 9092,
                "base_stack": "kafka",
                "instruction": "Kafka broker with a single topic 'orders' with one partition. \
                                Accept every produce and assign sequential offsets. Return the \
                                produced records on fetch."
            }),
            // Script mode: deterministic responses, no LLM call
            json!({
                "type": "open_server",
                "port": 9092,
                "base_stack": "kafka",
                "event_handlers": [{
                    "event_pattern": "kafka_metadata_request",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "actions = [{'type': 'metadata_response', 'topics': [{'name': 'orders', 'partitions': [{'partition': 0}]}]}]"
                    }
                }]
            }),
            // Static mode: fixed responses
            json!({
                "type": "open_server",
                "port": 9092,
                "base_stack": "kafka",
                "event_handlers": [{
                    "event_pattern": "kafka_produce_request",
                    "handler": {
                        "type": "static",
                        "actions": [{
                            "type": "produce_response",
                            "topic": "orders",
                            "partition": 0,
                            "offset": 0,
                            "error_code": 0
                        }]
                    }
                }]
            }),
        )
    }
}

// Implement Server trait (server-specific functionality)
impl Server for KafkaProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(async move {
            use crate::server::kafka::KafkaServer;
            KafkaServer::spawn_with_llm_actions(
                ctx.legacy_listen_addr(),
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.server_id,
                ctx.startup_params,
            )
            .await
        })
    }
    fn execute_action(&self, action: Value) -> Result<ActionResult> {
        let action_type = action
            .get("type")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("Missing 'type' field in action"))?;

        match action_type {
            // Every one of these is consumed by src/server/kafka/mod.rs, which turns it
            // into the corresponding Kafka response body.
            "produce_response"
            | "fetch_response"
            | "metadata_response"
            | "offset_commit_response"
            | "error_response" => Ok(ActionResult::Custom {
                name: action_type.to_string(),
                data: action,
            }),
            // The dashboard's "[ disconnect this peer ]" injects a bare
            // `{"type": "close_connection"}` through the peer handle, whatever a protocol
            // calls its own close verb. Deliberately NOT advertised in `get_sync_actions`
            // or `get_async_actions`: Kafka has no close message, so the model has nothing
            // to gain from it, and adding it to the tool list would change what the model
            // sees. The generic peer-command task half-closes the write side; the reader's
            // `UnexpectedEof` path then runs the normal teardown.
            "close_connection" => Ok(ActionResult::CloseConnection),
            _ => Err(anyhow!("Unknown Kafka action type: {}", action_type)),
        }
    }
}
