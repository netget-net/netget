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
            description: "Maximum number of keys to return".to_string(),
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
            "succeeded": true
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
            description: "Comparison predicates as objects with 'key', 'target' \
                          (VERSION/CREATE/MOD/VALUE), 'result' (EQUAL/GREATER/LESS/NOT_EQUAL) \
                          and 'value' fields"
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
        parameters: vec![Parameter {
            name: "revision".to_string(),
            type_hint: "number".to_string(),
            description: "Revision this write is recorded at. Omit to let the server increment."
                .to_string(),
            required: false,
        }],
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
        parameters: vec![Parameter {
            name: "deleted".to_string(),
            type_hint: "number".to_string(),
            description: "Number of keys deleted. etcdctl prints this as 'deleted N'.".to_string(),
            required: true,
        }],
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
        description: "Report whether a transaction's comparisons held. The per-operation results \
                      are returned empty: nested Range/Put/Delete results inside a Txn are not \
                      implemented."
            .to_string(),
        parameters: vec![Parameter {
            name: "succeeded".to_string(),
            type_hint: "boolean".to_string(),
            description: "True if the comparisons held and the success branch was taken"
                .to_string(),
            required: true,
        }],
        example: json!({
            "type": "etcd_txn_response",
            "succeeded": true
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
        vec![ParameterDefinition {
            name: "cluster_name".to_string(),
            type_hint: "string".to_string(),
            description: "Cluster identifier name, used in log lines (default: netget-cluster)"
                .to_string(),
            required: false,
            example: json!("my-cluster"),
            default: None,
        }]
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
            // Beta, restored September 2026 -- and on different evidence than the rating it
            // lost. The old Beta rested on `etcd-client` alone, which is tonic-based and
            // accepts a gRPC status wherever it finds one; pointing etcd's own Go client at
            // this server showed no grpc-go client could complete a single RPC. That bug is
            // fixed (the status is in trailing HEADERS now) and BOTH clients are asserted, so
            // the `mysql`/mysql_async shape -- one lenient client agreeing with one bug -- no
            // longer applies.
            .state(DevelopmentState::Beta)
            .well_known_port(2379)
            .implementation(
                "hyper HTTP/2 + prost, hand-routed gRPC; etcd protobuf schemas compiled by \
                 build.rs. tonic is a dependency but this server does not use it.",
            )
            .llm_control(
                "Range, Put, DeleteRange and Txn. Compact is answered without consulting the \
                 handler; a Txn's nested operations are not executed, only its outcome.",
            )
            .e2e_testing(
                "TWO independent clients, neither #[ignore]d and neither skipping when \
                 anything is missing. etcd-client (the official Rust client, tonic) in \
                 tests/server/etcd/e2e_test.rs completes put, get, prefix-get and delete and \
                 asserts on the decoded key/value pairs. The real etcdctl binary (grpc-go, the \
                 reference implementation) in tests/server/etcd/real_client_test.rs does the \
                 same four verbs through the CLI and asserts on what it printed; it hard-fails \
                 when etcdctl is absent rather than skipping. \
                 The second client is there because the first was not enough: until September \
                 2026 a successful reply put `grpc-status` in the INITIAL HEADERS and then sent \
                 a DATA frame, so the stream ended with no trailing HEADERS. tonic tolerated \
                 that; grpc-go answered `server closed the stream without sending trailers` to \
                 every RPC carrying a body -- the first Put included. Error replies were \
                 unaffected because they are Trailers-Only by construction, which is precisely \
                 why the whole suite passed. The success path now emits real HTTP/2 trailers \
                 and the error path stays Trailers-Only, and removing either is a red test. \
                 UNPROVEN: Watch, Lease, Auth, Cluster and Maintenance (none are routed -- they \
                 return UNIMPLEMENTED), Txn's nested operations, and binary keys or values, \
                 which cross the action boundary as lossy UTF-8.",
            )
            .notes(
                "KV service only: no Watch, Lease, Auth, Cluster or Maintenance. No storage - \
                 the handler answers every request; the server keeps only a revision counter. \
                 Keys and values cross the action boundary as UTF-8 strings, so binary keys \
                 are lossy.",
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
