//! etcd protocol action definitions

use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter, ParameterDefinition,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::EventType;
use crate::state::app_state::AppState;
use anyhow::Result;
use serde_json::{json, Value};
use std::sync::LazyLock;

/// etcd protocol handler
pub struct EtcdProtocol {}

impl EtcdProtocol {
    pub fn new() -> Self {
        Self {}
    }
}

// Event type IDs
pub static ETCD_RANGE_REQUEST_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "etcd_range_request",
        "Triggered when a client sends a Range (get) request to query keys",
        json!({
            "type": "etcd_range_response",
            "kvs": [
                {"key": "foo", "value": "bar", "create_revision": 1, "mod_revision": 1, "version": 1, "lease": 0}
            ],
            "more": false,
            "count": 1
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "key".to_string(),
            type_hint: "string".to_string(),
            description: "Key to query".to_string(),
            required: true,
        },
        Parameter {
            name: "range_end".to_string(),
            type_hint: "string".to_string(),
            description: "End of key range (for prefix/range queries)".to_string(),
            required: false,
        },
        Parameter {
            name: "limit".to_string(),
            type_hint: "number".to_string(),
            description: "Maximum number of keys to return (0 = no limit). The server truncates \
                          kvs to it and sets more, so answer with every matching key."
                .to_string(),
            required: false,
        },
        Parameter {
            name: "keys_only".to_string(),
            type_hint: "boolean".to_string(),
            description: "The client wants keys without values; the server drops the values"
                .to_string(),
            required: false,
        },
        Parameter {
            name: "count_only".to_string(),
            type_hint: "boolean".to_string(),
            description: "The client wants only the count; the server drops the pairs and \
                          keeps count"
                .to_string(),
            required: false,
        },
        Parameter {
            name: "revision".to_string(),
            type_hint: "number".to_string(),
            description: "Present only for a point-in-time read: the revision to read at"
                .to_string(),
            required: false,
        },
        Parameter {
            name: "sort_order".to_string(),
            type_hint: "string".to_string(),
            description: "Present only when sorting was asked for: ASCEND or DESCEND, by \
                          sort_target (KEY, VERSION, CREATE, MOD or VALUE). Return kvs in that \
                          order."
                .to_string(),
            required: false,
        },
    ])
    .with_actions(vec![etcd_range_response_action(), etcd_error_action()])
});

pub static ETCD_PUT_REQUEST_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "etcd_put_request",
        "Triggered when a client sends a Put request to store a key-value pair",
        json!({
            "type": "etcd_put_response",
            "revision": 2
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "key".to_string(),
            type_hint: "string".to_string(),
            description: "Key being written".to_string(),
            required: true,
        },
        Parameter {
            name: "value".to_string(),
            type_hint: "string".to_string(),
            description: "Value being written".to_string(),
            required: true,
        },
        Parameter {
            name: "lease".to_string(),
            type_hint: "number".to_string(),
            description: "Lease ID attached to the key (0 = no lease)".to_string(),
            required: false,
        },
        Parameter {
            name: "prev_kv".to_string(),
            type_hint: "boolean".to_string(),
            description: "The client asked for the key's previous value: answer with prev_kv \
                          (omit it when the key did not exist)"
                .to_string(),
            required: false,
        },
        Parameter {
            name: "ignore_value".to_string(),
            type_hint: "boolean".to_string(),
            description: "Keep the key's current value and change only its lease".to_string(),
            required: false,
        },
        Parameter {
            name: "ignore_lease".to_string(),
            type_hint: "boolean".to_string(),
            description: "Keep the key's current lease and change only its value".to_string(),
            required: false,
        },
    ])
    .with_actions(vec![etcd_put_response_action(), etcd_error_action()])
});

pub static ETCD_DELETE_REQUEST_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "etcd_delete_request",
        "Triggered when a client sends a DeleteRange request",
        json!({
            "type": "etcd_delete_range_response",
            "deleted": 1
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "key".to_string(),
            type_hint: "string".to_string(),
            description: "Key to delete".to_string(),
            required: true,
        },
        Parameter {
            name: "range_end".to_string(),
            type_hint: "string".to_string(),
            description: "End of key range for prefix/range deletes".to_string(),
            required: false,
        },
        Parameter {
            name: "prev_kv".to_string(),
            type_hint: "boolean".to_string(),
            description: "The client asked for the deleted pairs: answer with prev_kvs".to_string(),
            required: false,
        },
    ])
    .with_actions(vec![
        etcd_delete_range_response_action(),
        etcd_error_action(),
    ])
});

pub static ETCD_TXN_REQUEST_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "etcd_txn_request",
        "Triggered when a client sends a transaction request",
        json!({
            "type": "etcd_txn_response",
            "succeeded": true,
            "responses": [{}]
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "compare_count".to_string(),
            type_hint: "number".to_string(),
            description: "Number of comparison predicates in the transaction".to_string(),
            required: true,
        },
        Parameter {
            name: "success_count".to_string(),
            type_hint: "number".to_string(),
            description: "Number of operations to run if the comparisons hold".to_string(),
            required: true,
        },
        Parameter {
            name: "failure_count".to_string(),
            type_hint: "number".to_string(),
            description: "Number of operations to run if they do not".to_string(),
            required: true,
        },
        Parameter {
            name: "compares".to_string(),
            type_hint: "array".to_string(),
            description: "Comparison predicates as objects with 'key', 'range_end', 'target' \
                          (VERSION/CREATE/MOD/VALUE/LEASE), 'result' \
                          (EQUAL/GREATER/LESS/NOT_EQUAL) and 'value', the operand the key's \
                          target is compared with"
                .to_string(),
            required: true,
        },
        Parameter {
            name: "success".to_string(),
            type_hint: "array".to_string(),
            description: "The operations run when every comparison holds, in order, each with \
                          'op' (range, put or delete_range) and its key, range_end, value and \
                          flags"
                .to_string(),
            required: true,
        },
        Parameter {
            name: "failure".to_string(),
            type_hint: "array".to_string(),
            description: "The operations run when any comparison fails, in the same shape"
                .to_string(),
            required: true,
        },
    ])
    .with_actions(vec![etcd_txn_response_action(), etcd_error_action()])
});

// Action definitions
fn etcd_range_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "etcd_range_response".to_string(),
        description: "Return key-value pairs for a Range request".to_string(),
        parameters: vec![
            Parameter {
                name: "kvs".to_string(),
                type_hint: "array".to_string(),
                description: "Array of key-value objects with 'key', 'value', 'create_revision', 'mod_revision', 'version', 'lease' fields".to_string(),
                required: true,
            },
            Parameter {
                name: "more".to_string(),
                type_hint: "boolean".to_string(),
                description: "Whether there are more keys to return".to_string(),
                required: false,
            },
            Parameter {
                name: "count".to_string(),
                type_hint: "number".to_string(),
                description: "Total count of keys matching the range".to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "etcd_range_response",
            "kvs": [
                {"key": "foo", "value": "bar", "create_revision": 1, "mod_revision": 1, "version": 1, "lease": 0}
            ],
            "more": false,
            "count": 1
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> etcd range response ({kvs_len} keys)")
                .with_debug("etcd etcd_range_response: keys={kvs_len} more={more}"),
        ),
    }
}

fn etcd_put_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "etcd_put_response".to_string(),
        description: "Acknowledge a Put. The server increments its own revision counter if you \
                      omit one."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "revision".to_string(),
                type_hint: "number".to_string(),
                description: "Revision this write is recorded at. Omit to let the server \
                              increment."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "prev_kv".to_string(),
                type_hint: "object".to_string(),
                description: "Only when the request had prev_kv: the key's previous pair \
                              ('key', 'value', 'create_revision', 'mod_revision', 'version', \
                              'lease'). Omit it when the key did not exist."
                    .to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "etcd_put_response",
            "revision": 2
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> etcd put ok (rev {revision})")
                .with_debug("etcd etcd_put_response: revision={revision}"),
        ),
    }
}

fn etcd_delete_range_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "etcd_delete_range_response".to_string(),
        description: "Acknowledge a DeleteRange, reporting how many keys were removed".to_string(),
        parameters: vec![
            Parameter {
                name: "deleted".to_string(),
                type_hint: "number".to_string(),
                description: "Number of keys deleted. etcdctl prints this count.".to_string(),
                required: true,
            },
            Parameter {
                name: "prev_kvs".to_string(),
                type_hint: "array".to_string(),
                description: "Only when the request had prev_kv: the deleted pairs".to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "etcd_delete_range_response",
            "deleted": 1
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> etcd deleted {deleted} key(s)")
                .with_debug("etcd etcd_delete_range_response: deleted={deleted}"),
        ),
    }
}

fn etcd_txn_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "etcd_txn_response".to_string(),
        description: "Answer a transaction: whether its comparisons held, and one entry in \
                      responses per operation of the branch that ran, in order. A range \
                      operation's entry is {kvs, count, more}; a delete_range's is {deleted} \
                      (plus prev_kvs if it asked); a put's may be {} (plus prev_kv if it \
                      asked). A missing range or delete_range entry fails the transaction."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "succeeded".to_string(),
                type_hint: "boolean".to_string(),
                description: "True if the comparisons held and the success branch ran; false \
                              if the failure branch ran"
                    .to_string(),
                required: true,
            },
            Parameter {
                name: "responses".to_string(),
                type_hint: "array".to_string(),
                description: "One object per operation of the branch that ran, in order"
                    .to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "etcd_txn_response",
            "succeeded": false,
            "responses": [
                {"kvs": [{"key": "/lock", "value": "owner-1", "create_revision": 4,
                          "mod_revision": 4, "version": 1, "lease": 0}], "count": 1}
            ]
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> etcd txn succeeded={succeeded}")
                .with_debug("etcd etcd_txn_response: succeeded={succeeded}"),
        ),
    }
}

fn etcd_error_action() -> ActionDefinition {
    ActionDefinition {
        name: "etcd_error".to_string(),
        description: "Return an error response".to_string(),
        parameters: vec![
            Parameter {
                name: "code".to_string(),
                type_hint: "string".to_string(),
                description: "Error code (e.g., 'KEY_NOT_FOUND', 'INVALID_ARGUMENT')".to_string(),
                required: true,
            },
            Parameter {
                name: "message".to_string(),
                type_hint: "string".to_string(),
                description: "Error message".to_string(),
                required: true,
            },
        ],
        example: json!({
            "type": "etcd_error",
            "code": "KEY_NOT_FOUND",
            "message": "etcdserver: key not found"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> etcd error {code}: {message}")
                .with_debug("etcd etcd_error: code={code} message={message}"),
        ),
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for EtcdProtocol {
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        // Only parameters the server actually reads are declared. `initial_cluster_state` and
        // `max_keys` used to be declared here and were never read; `max_keys` in particular
        // advertised a key store this protocol does not and must not have.
        vec![
            ParameterDefinition {
                name: "cluster_name".to_string(),
                type_hint: "string".to_string(),
                description: "Cluster identifier name, used in log lines (default: netget-cluster)"
                    .to_string(),
                required: false,
                example: json!("my-cluster"),
                default: None,
            },
            ParameterDefinition {
                name: "first_byte_timeout_secs".to_string(),
                type_hint: "number".to_string(),
                description: "Seconds a connected peer may send nothing at all (not even the \
                              HTTP/2 preface) before the server closes it."
                    .to_string(),
                required: false,
                example: json!(30),
                default: Some(json!(super::FIRST_BYTE_READ_TIMEOUT.as_secs())),
            },
            ParameterDefinition {
                name: "idle_timeout_secs".to_string(),
                type_hint: "number".to_string(),
                description: "Seconds a connection may go with no request in flight and no \
                              frame of a request body arriving before the server closes it. A \
                              request waiting on the model or a human never counts as idle."
                    .to_string(),
                required: false,
                example: json!(900),
                default: Some(json!(super::IDLE_BETWEEN_REQUESTS_TIMEOUT.as_secs())),
            },
        ]
    }
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            etcd_range_response_action(),
            etcd_put_response_action(),
            etcd_delete_range_response_action(),
            etcd_txn_response_action(),
            etcd_error_action(),
        ]
    }
    fn protocol_name(&self) -> &'static str {
        "etcd"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>GRPC>ETCD"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["etcd", "etcd3", "etcdv3", "etcd server"]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            // Stable, 13 November 2026, against the six conditions in the root AGENTS.md; the
            // table is at the foot of src/server/etcd/AGENTS.md. The rating covers the surface
            // implemented: the five KV methods, unary, cleartext, UTF-8 keys and values.
            .state(DevelopmentState::Stable)
            .well_known_port(2379)
            .implementation(
                "hyper HTTP/2 + prost, hand-routed gRPC; etcd protobuf schemas compiled by \
                 build.rs. tonic is a dependency but this server does not use it.",
            )
            .llm_control(
                "Range, Put, DeleteRange and Txn: the key space, previous pairs, which Txn \
                 branch ran and each of its operations' results. The server applies Range's \
                 limit/keys_only/count_only and owns the revision counter, so Compact is \
                 answered from it without consulting the handler.",
            )
            .e2e_testing(
                "TWO clients independent of the server's hyper/h2/prost stack and of each \
                 other, neither #[ignore]d and both failing rather than skipping when absent: \
                 the real etcdctl binary (grpc-go, golang/protobuf) in \
                 tests/server/etcd/real_client_test.rs, and Python grpcio (gRPC C-core's \
                 chttp2, upb protobuf) in tests/server/etcd/grpcio_client_test.rs. Between \
                 them every method: Put (with prev_kv), Range (single, prefix, limit, \
                 keys_only, count_only), DeleteRange (with prev_kv), Txn with the success and \
                 the failure branch and each branch's per-operation results, Compact (success, \
                 an already-compacted and a future revision), and an etcd_error as a \
                 Trailers-Only status. etcd-client (tonic over prost) in e2e_test.rs is also \
                 driven but not counted: it shares the server's h2 and prost. etcdctl is also \
                 why trailers matter: until September 2026 a success reply put grpc-status in \
                 the initial HEADERS beside a DATA frame, which tonic tolerated and grpc-go \
                 refused on every RPC. PCAP ORACLE: every etcdctl and grpcio connection \
                 crosses a recording relay and tshark's http2/grpc dissectors read it, Txn, \
                 Compact and error replies included. FUZZ: fuzz/fuzz_targets/etcd_request.rs \
                 (unary_message and the KV prost decoders, 20 000-level TxnRequest and \
                 unknown-group bombs). BOUNDS: tests/server/etcd/bounds_test.rs drives every \
                 declared bound from the wire on both sides. NOT COVERED: Watch, Lease, Auth, \
                 Cluster, Maintenance (all UNIMPLEMENTED), nested transactions \
                 (UNIMPLEMENTED), TLS, and binary keys or values (lossy UTF-8).",
            )
            .notes(
                "KV service only: no Watch, Lease, Auth, Cluster or Maintenance, no nested Txn. \
                 No storage - the handler answers every request; the server keeps only a \
                 revision counter and the last compacted revision. Request bodies are bounded \
                 at 1.5 MiB each and 48 MiB across the server. Keys and values cross the \
                 action boundary as UTF-8 strings, so binary keys are lossy.",
            )
            .max_inbound_bytes(crate::server::etcd::MAX_REQUEST_BYTES)
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn description(&self) -> &'static str {
        "etcd v3 distributed key-value store server"
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            (*ETCD_RANGE_REQUEST_EVENT).clone(),
            (*ETCD_PUT_REQUEST_EVENT).clone(),
            (*ETCD_DELETE_REQUEST_EVENT).clone(),
            (*ETCD_TXN_REQUEST_EVENT).clone(),
        ]
    }
    fn example_prompt(&self) -> &'static str {
        r#"listen on port 2379 via etcd
    
    Store configuration under /config/ prefix.
    When clients PUT /config/database with value "localhost:5432", store it (revision 1).
    When clients GET /config/database, return "localhost:5432" with revision metadata.
    For unknown keys, return empty kvs array.
    
    Examples:
    - PUT /config/timeout = "30" → Success, increment revision
    - GET /config/timeout → Return "30" with create_revision, mod_revision, version
    - DELETE /config/timeout → Remove key, return deleted count
    - Range query /config/ → Return all keys with /config/ prefix
    
    Track revisions for MVCC."#
    }
    fn group_name(&self) -> &'static str {
        "Database"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        use serde_json::json;

        // Deterministic: answer every range read with an empty key set, no LLM
        // call.
        let script = r#"import json, sys
data = json.load(sys.stdin)
event = data["event"]
if data["event_type_id"] == "etcd_range_request":
    actions = [{"type": "etcd_range_response", "kvs": [], "count": 0}]
else:
    actions = []
print(json.dumps({"actions": actions}))"#;

        StartupExamples::new(
            // LLM mode: LLM handles all etcd responses intelligently
            json!({
                "type": "open_server",
                "port": 2379,
                "base_stack": "etcd",
                "instruction": "etcd v3 key-value store handling Range, Put, Delete operations"
            }),
            // Script mode: Code-based deterministic responses
            json!({
                "type": "open_server",
                "port": 2379,
                "base_stack": "etcd",
                "event_handlers": [{
                    "event_pattern": "etcd_range_request",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": script
                    }
                }]
            }),
            // Static mode: Fixed responses
            json!({
                "type": "open_server",
                "port": 2379,
                "base_stack": "etcd",
                "event_handlers": [{
                    "event_pattern": "etcd_range_request",
                    "handler": {
                        "type": "static",
                        "actions": [{
                            "type": "etcd_range_response",
                            "kvs": [],
                            "more": false,
                            "count": 0
                        }]
                    }
                }]
            }),
        )
    }
}

// Implement Server trait (server-specific functionality)
impl Server for EtcdProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::server::etcd::EtcdServer;
            EtcdServer::spawn_with_llm_actions(
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
            .ok_or_else(|| anyhow::anyhow!("Missing action type"))?;

        // Every declared action must be listed here. `etcd_put_response` and
        // `etcd_delete_range_response` were read by handle_put/handle_delete_range in mod.rs
        // but rejected here as unknown, so the model could never actually produce them: a Put
        // could not set its revision and a DeleteRange always reported "deleted 0".
        match action_type {
            "etcd_range_response"
            | "etcd_put_response"
            | "etcd_delete_range_response"
            | "etcd_txn_response"
            | "etcd_error" => Ok(ActionResult::Custom {
                name: action_type.to_string(),
                data: action,
            }),
            _ => anyhow::bail!("Unknown etcd action type: {}", action_type),
        }
    }
}
