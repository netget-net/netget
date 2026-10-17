//! Elasticsearch protocol actions and event types
//!
//! Defines the actions the LLM can take in response to Elasticsearch API requests.

use crate::llm::actions::protocol_trait::{ActionResult, Protocol, Server};
use crate::llm::actions::{ActionDefinition, Parameter};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::EventType;
use crate::state::app_state::AppState;
use anyhow::Result;
use serde_json::{json, Value};
use std::sync::LazyLock;

/// Elasticsearch protocol handler
pub struct ElasticsearchProtocol {
    // Could store connection state here if needed
}

impl ElasticsearchProtocol {
    pub fn new() -> Self {
        Self {}
    }
}

/// Elasticsearch request event - triggered when an Elasticsearch API request is received
pub static ELASTICSEARCH_REQUEST_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "elasticsearch_request",
        "Elasticsearch API request received",
        json!({
            "type": "send_search_response",
            "hits": [
                {"_id": "1", "_index": "products", "_source": {"name": "Widget", "price": 19.99}},
                {"_id": "2", "_index": "products", "_source": {"name": "Gadget", "price": 29.99}}
            ],
            "total": 2,
            "took": 15
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "method".to_string(),
            type_hint: "string".to_string(),
            description: "HTTP method (GET, POST, PUT, DELETE)".to_string(),
            required: true,
        },
        Parameter {
            name: "path".to_string(),
            type_hint: "string".to_string(),
            description: "Request path (e.g., /index/_search, /_bulk)".to_string(),
            required: true,
        },
        Parameter {
            name: "operation".to_string(),
            type_hint: "string".to_string(),
            description: "Detected operation type (search, index, get, delete, bulk, etc.)"
                .to_string(),
            required: true,
        },
        Parameter {
            name: "index".to_string(),
            type_hint: "string".to_string(),
            description: "Target index name (if available)".to_string(),
            required: false,
        },
        Parameter {
            name: "doc_id".to_string(),
            type_hint: "string".to_string(),
            description: "Document ID (if available)".to_string(),
            required: false,
        },
        Parameter {
            name: "request_body".to_string(),
            type_hint: "string".to_string(),
            description: "JSON request body".to_string(),
            required: false,
        },
    ])
    .with_actions(vec![
        send_elasticsearch_response_action(),
        send_search_response_action(),
        send_index_response_action(),
        send_get_response_action(),
        send_bulk_response_action(),
        send_cluster_info_action(),
        send_cluster_health_action(),
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("Elasticsearch {client_ip} {method} {path}")
            .with_debug("Elasticsearch {method} {path} from {client_ip}:{client_port}")
            .with_trace("Elasticsearch: {json_pretty(.)}"),
    )
});

fn send_elasticsearch_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_elasticsearch_response".to_string(),
        description: "Send generic Elasticsearch JSON response with HTTP status code".to_string(),
        parameters: vec![
            Parameter {
                name: "status_code".to_string(),
                type_hint: "number".to_string(),
                description: "HTTP status code (200, 400, 404, 500, etc.)".to_string(),
                required: true,
            },
            Parameter {
                name: "body".to_string(),
                type_hint: "string".to_string(),
                description: "JSON response body".to_string(),
                required: true,
            },
        ],
        example: serde_json::json!({
            "type": "send_elasticsearch_response",
            "status_code": 200,
            "body": "{\"acknowledged\": true}"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> Elasticsearch {status_code}")
                .with_debug("Elasticsearch response: status={status_code}"),
        ),
    }
}

fn send_search_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_search_response".to_string(),
        description: "Send search results with hits array".to_string(),
        parameters: vec![
            Parameter {
                name: "hits".to_string(),
                type_hint: "array".to_string(),
                description: "Array of search result documents with _id, _index, _source"
                    .to_string(),
                required: true,
            },
            Parameter {
                name: "total".to_string(),
                type_hint: "number".to_string(),
                description: "Total number of matching documents".to_string(),
                required: false,
            },
            Parameter {
                name: "took".to_string(),
                type_hint: "number".to_string(),
                description: "Time in milliseconds the search took".to_string(),
                required: false,
            },
        ],
        example: serde_json::json!({
            "type": "send_search_response",
            "hits": [
                {"_id": "1", "_index": "products", "_source": {"name": "Widget", "price": 19.99}},
                {"_id": "2", "_index": "products", "_source": {"name": "Gadget", "price": 29.99}}
            ],
            "total": 2,
            "took": 15
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> Elasticsearch {hits_len} hits, {total} total")
                .with_debug("Elasticsearch search_response: {hits_len} hits"),
        ),
    }
}

fn send_index_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_index_response".to_string(),
        description: "Send document indexing confirmation".to_string(),
        parameters: vec![
            Parameter {
                name: "index".to_string(),
                type_hint: "string".to_string(),
                description: "Index name".to_string(),
                required: true,
            },
            Parameter {
                name: "id".to_string(),
                type_hint: "string".to_string(),
                description: "Document ID".to_string(),
                required: true,
            },
            Parameter {
                name: "result".to_string(),
                type_hint: "string".to_string(),
                description: "Result type: 'created' or 'updated'".to_string(),
                required: true,
            },
        ],
        example: serde_json::json!({
            "type": "send_index_response",
            "index": "products",
            "id": "abc123",
            "result": "created"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> Elasticsearch {result} {index}/{id}")
                .with_debug("Elasticsearch index_response: {index}/{id} {result}"),
        ),
    }
}

fn send_get_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_get_response".to_string(),
        description: "Send document retrieval response".to_string(),
        parameters: vec![
            Parameter {
                name: "found".to_string(),
                type_hint: "boolean".to_string(),
                description: "Whether the document was found".to_string(),
                required: true,
            },
            Parameter {
                name: "index".to_string(),
                type_hint: "string".to_string(),
                description: "Index name".to_string(),
                required: true,
            },
            Parameter {
                name: "id".to_string(),
                type_hint: "string".to_string(),
                description: "Document ID".to_string(),
                required: true,
            },
            Parameter {
                name: "source".to_string(),
                type_hint: "object".to_string(),
                description: "Document source data (if found)".to_string(),
                required: false,
            },
        ],
        example: serde_json::json!({
            "type": "send_get_response",
            "found": true,
            "index": "products",
            "id": "abc123",
            "source": {"name": "Widget", "price": 19.99}
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> Elasticsearch GET {index}/{id} found={found}")
                .with_debug("Elasticsearch get_response: {index}/{id}"),
        ),
    }
}

fn send_bulk_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_bulk_response".to_string(),
        description: "Send bulk operation results".to_string(),
        parameters: vec![
            Parameter {
                name: "items".to_string(),
                type_hint: "array".to_string(),
                description: "Array of operation results with status for each item".to_string(),
                required: true,
            },
            Parameter {
                name: "errors".to_string(),
                type_hint: "boolean".to_string(),
                description: "Whether any operations failed".to_string(),
                required: false,
            },
        ],
        example: serde_json::json!({
            "type": "send_bulk_response",
            "items": [
                {"index": {"_index": "products", "_id": "1", "status": 201}},
                {"delete": {"_index": "products", "_id": "2", "status": 200}}
            ],
            "errors": false
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> Elasticsearch bulk {items_len} items, errors={errors}")
                .with_debug("Elasticsearch bulk_response: {items_len} items"),
        ),
    }
}

fn send_cluster_info_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_cluster_info".to_string(),
        description: "Answer the root endpoint (GET /) with the node/version banner every \
                      Elasticsearch client fetches to identify the server. This response has \
                      no cluster health in it - answer the 'cluster_health' operation \
                      (GET /_cluster/health) with send_cluster_health instead."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "cluster_name".to_string(),
                type_hint: "string".to_string(),
                description: "Cluster name".to_string(),
                required: false,
            },
            Parameter {
                name: "version".to_string(),
                type_hint: "string".to_string(),
                description: "Elasticsearch version, e.g. '8.0.0'".to_string(),
                required: false,
            },
        ],
        example: serde_json::json!({
            "type": "send_cluster_info",
            "cluster_name": "llm-elasticsearch",
            "version": "8.0.0"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> Elasticsearch cluster {cluster_name}")
                .with_debug("Elasticsearch cluster_info: {cluster_name} v{version}"),
        ),
    }
}

fn send_cluster_health_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_cluster_health".to_string(),
        description: "Answer GET /_cluster/health (the 'cluster_health' operation) with a \
                      cluster health report. Clients and orchestration tooling poll this \
                      endpoint to decide whether the cluster is usable."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "cluster_name".to_string(),
                type_hint: "string".to_string(),
                description: "Cluster name".to_string(),
                required: false,
            },
            Parameter {
                name: "status".to_string(),
                type_hint: "string".to_string(),
                description: "Cluster status: 'green', 'yellow', or 'red'. Anything else is \
                              rejected"
                    .to_string(),
                required: true,
            },
            Parameter {
                name: "number_of_nodes".to_string(),
                type_hint: "number".to_string(),
                description: "Number of nodes in the cluster (default: 1)".to_string(),
                required: false,
            },
            Parameter {
                name: "active_shards".to_string(),
                type_hint: "number".to_string(),
                description: "Number of active shards (default: 0)".to_string(),
                required: false,
            },
        ],
        example: serde_json::json!({
            "type": "send_cluster_health",
            "cluster_name": "llm-elasticsearch",
            "status": "green",
            "number_of_nodes": 1,
            "active_shards": 5
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> Elasticsearch health {status}")
                .with_debug("Elasticsearch cluster_health: {cluster_name} status={status}"),
        ),
    }
}

/// Read and validate the model-supplied `status_code`.
///
/// The old `as u64 as u16` cast wrapped silently, and out-of-range values reached
/// `Response::builder().status()` where an `.unwrap()` turned them into a panic that
/// killed the connection task. Reject them here, where the message reaches the model.
fn parse_status_code(action: &Value) -> Result<u16> {
    let raw = action
        .get("status_code")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| anyhow::anyhow!("Missing or invalid status_code: expected a number"))?;

    if !(100..=599).contains(&raw) {
        return Err(anyhow::anyhow!(
            "Invalid status_code {raw}: must be an HTTP status between 100 and 599. \
             Elasticsearch uses 200 for success, 201 for a created document, 404 when a \
             document or index is missing and 400 for a malformed query."
        ));
    }

    Ok(raw as u16)
}

/// Did one entry of a `_bulk` response report a failure?
///
/// An item is `{"<op>": {"_index": …, "status": 201}}`, and Elasticsearch marks a failed one
/// with an `error` object and a 4xx/5xx `status`. Used only when the handler omits `errors`,
/// so the top-level flag agrees with the items beneath it rather than defaulting to "none".
fn bulk_item_failed(item: &Value) -> bool {
    let Some(obj) = item.as_object() else {
        return false;
    };
    obj.values().any(|op| {
        op.get("error").is_some_and(|e| !e.is_null())
            || op
                .get("status")
                .and_then(|s| s.as_u64())
                .is_some_and(|s| s >= 400)
    })
}

/// Serialize a response body. Serializing a `serde_json::Value` cannot fail, so the
/// fallback is unreachable - it exists only to keep this off the panic path.
fn body_of(value: &Value) -> String {
    serde_json::to_string_pretty(value).unwrap_or_else(|_| value.to_string())
}

pub fn get_elasticsearch_event_types() -> Vec<EventType> {
    vec![ELASTICSEARCH_REQUEST_EVENT.clone()]
}

// Implement Protocol trait (common functionality)
impl Protocol for ElasticsearchProtocol {
    fn get_startup_parameters(&self) -> Vec<crate::llm::actions::ParameterDefinition> {
        // Deliberately empty. `send_first` used to be declared here and was even parsed in
        // `spawn()`, but it arrived at `ElasticsearchServer::spawn_with_llm_actions` as
        // `_send_first` and was discarded - a client cannot be spoken to before it sends an
        // HTTP request anyway. Undeclaring it makes `server_startup` log an explicit
        // "does not support send_first" warning instead of silently accepting it.
        vec![]
    }
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        // No async actions for Elasticsearch currently
        vec![]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            send_elasticsearch_response_action(),
            send_search_response_action(),
            send_index_response_action(),
            send_get_response_action(),
            send_bulk_response_action(),
            send_cluster_info_action(),
            send_cluster_health_action(),
        ]
    }
    fn protocol_name(&self) -> &'static str {
        "Elasticsearch"
    }
    fn get_event_types(&self) -> Vec<EventType> {
        get_elasticsearch_event_types()
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>HTTP>ELASTICSEARCH"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["elasticsearch", "opensearch"]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .well_known_port(9200)
            .implementation("hyper v1.5 HTTP server with manual ES API")
            .llm_control("Search, index, cluster operations")
            // Neither curl nor the `elasticsearch` crate has ever been pointed at this
            // server: `tests/server/elasticsearch/e2e_test.rs` drives `reqwest`, which proves
            // an HTTP server answers — not that the Elasticsearch API on top of it is right.
            // That is exactly why this is Experimental rather than Beta.
            .e2e_testing("reqwest (a generic HTTP client); no Elasticsearch client has been used")
            .notes(
                "Virtual data (no persistence). Request bodies are bounded at 8 MiB and a \
                 larger one is refused with 413 before any model call",
            )
            .max_inbound_bytes(crate::server::elasticsearch::MAX_REQUEST_BODY_BYTES)
            .request_only("Elasticsearch is HTTP request/response; a server cannot send a peer anything unprompted")
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn description(&self) -> &'static str {
        "Elasticsearch search engine"
    }
    fn example_prompt(&self) -> &'static str {
        "Start an Elasticsearch server on port 9200"
    }
    fn group_name(&self) -> &'static str {
        "Database"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        use serde_json::json;

        // Deterministic routing: cluster info for GET /, a canned acknowledged
        // response for every other path, no LLM call.
        let script = r#"import json, sys
data = json.load(sys.stdin)
event = data["event"]
if data["event_type_id"] == "elasticsearch_request":
    if event.get("path", "/") == "/":
        actions = [{"type": "send_cluster_info",
                    "cluster_name": "netget-elasticsearch",
                    "status": "green", "version": "8.0.0"}]
    else:
        actions = [{"type": "send_elasticsearch_response", "status_code": 200,
                    "body": '{"acknowledged": true}'}]
else:
    actions = []
print(json.dumps({"actions": actions}))"#;

        StartupExamples::new(
            // LLM mode: LLM handles all Elasticsearch responses intelligently
            json!({
                "type": "open_server",
                "port": 9200,
                "base_stack": "elasticsearch",
                "instruction": "Elasticsearch search engine handling API requests"
            }),
            // Script mode: Code-based deterministic responses
            json!({
                "type": "open_server",
                "port": 9200,
                "base_stack": "elasticsearch",
                "event_handlers": [{
                    "event_pattern": "elasticsearch_request",
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
                "port": 9200,
                "base_stack": "elasticsearch",
                "event_handlers": [{
                    "event_pattern": "elasticsearch_request",
                    "handler": {
                        "type": "static",
                        "actions": [{
                            "type": "send_cluster_info",
                            "cluster_name": "netget-elasticsearch",
                            "status": "green",
                            "version": "8.0.0"
                        }]
                    }
                }]
            }),
        )
    }
}

// Implement Server trait (server-specific functionality)
impl Server for ElasticsearchProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::server::elasticsearch::ElasticsearchServer;
            ElasticsearchServer::spawn_with_llm_actions(
                ctx.legacy_listen_addr(),
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.server_id,
            )
            .await
        })
    }
    fn execute_action(&self, action: Value) -> Result<ActionResult> {
        let action_type = action
            .get("type")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("Missing action type"))?;

        match action_type {
            "send_elasticsearch_response" => {
                let status_code = parse_status_code(&action)?;

                let body = action
                    .get("body")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow::anyhow!("Missing body"))?
                    .to_string();

                Ok(ActionResult::Custom {
                    name: "elasticsearch_response".to_string(),
                    data: json!({
                        "status": status_code,
                        "body": body
                    }),
                })
            }
            "send_search_response" => {
                let hits = action
                    .get("hits")
                    .ok_or_else(|| anyhow::anyhow!("Missing hits"))?;

                let total = action
                    .get("total")
                    .and_then(|v| v.as_u64())
                    .unwrap_or_else(|| hits.as_array().map(|a| a.len() as u64).unwrap_or(0));

                let took = action.get("took").and_then(|v| v.as_u64()).unwrap_or(10);

                let response = serde_json::json!({
                    "took": took,
                    "timed_out": false,
                    "_shards": {
                        "total": 1,
                        "successful": 1,
                        "skipped": 0,
                        "failed": 0
                    },
                    "hits": {
                        "total": {
                            "value": total,
                            "relation": "eq"
                        },
                        "max_score": 1.0,
                        "hits": hits
                    }
                });

                Ok(ActionResult::Custom {
                    name: "elasticsearch_response".to_string(),
                    data: json!({
                        "status": 200,
                        "body": body_of(&response)
                    }),
                })
            }
            "send_index_response" => {
                let index = action
                    .get("index")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow::anyhow!("Missing index"))?;

                let id = action
                    .get("id")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow::anyhow!("Missing id"))?;

                // Declared `required: true`, and it decides the status: "created" answers
                // 201. Defaulting to it meant an omitted or misspelled value reported a
                // document as newly indexed that nothing said had been indexed at all.
                let result = action
                    .get("result")
                    .and_then(|v| v.as_str())
                    .filter(|s| !s.trim().is_empty())
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "send_index_response requires `result` — Elasticsearch's own \
                             values are \"created\", \"updated\", \"deleted\", \
                             \"not_found\" and \"noop\". \"created\" answers 201, so it \
                             cannot be assumed"
                        )
                    })?;

                let response = serde_json::json!({
                    "_index": index,
                    "_id": id,
                    "_version": 1,
                    "result": result,
                    "_shards": {
                        "total": 2,
                        "successful": 1,
                        "failed": 0
                    },
                    "_seq_no": 0,
                    "_primary_term": 1
                });

                Ok(ActionResult::Custom {
                    name: "elasticsearch_response".to_string(),
                    data: json!({
                        "status": if result == "created" { 201 } else { 200 },
                        "body": body_of(&response)
                    }),
                })
            }
            "send_get_response" => {
                // Declared `required: true`. It decides 200-with-a-document versus 404, so
                // either default is a claim about the index — and a mistyped `"true"` (a
                // string, not a JSON boolean) silently became "no such document".
                let found = action
                    .get("found")
                    .and_then(|v| v.as_bool())
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "send_get_response requires `found` (a JSON boolean, not a \
                             string); it decides whether the reply is the document (200) or \
                             a 404, and only the handler knows which"
                        )
                    })?;

                let index = action
                    .get("index")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow::anyhow!("Missing index"))?;

                let id = action
                    .get("id")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow::anyhow!("Missing id"))?;

                let response = if found {
                    let source = action
                        .get("source")
                        .cloned()
                        .unwrap_or_else(|| serde_json::json!({}));

                    serde_json::json!({
                        "_index": index,
                        "_id": id,
                        "_version": 1,
                        "_seq_no": 0,
                        "_primary_term": 1,
                        "found": true,
                        "_source": source
                    })
                } else {
                    serde_json::json!({
                        "_index": index,
                        "_id": id,
                        "found": false
                    })
                };

                Ok(ActionResult::Custom {
                    name: "elasticsearch_response".to_string(),
                    data: json!({
                        "status": if found { 200 } else { 404 },
                        "body": body_of(&response)
                    }),
                })
            }
            "send_bulk_response" => {
                let items = action
                    .get("items")
                    .ok_or_else(|| anyhow::anyhow!("Missing items"))?;

                // `errors` is what every client checks before deciding whether to walk
                // `items` at all, so defaulting it to `false` hid per-item failures the
                // handler had actually reported. When it is omitted, derive it from the
                // items rather than assume the happy answer: an item carrying an `error`
                // object or a 4xx/5xx `status` means errors occurred, and that is
                // observable rather than guessed.
                let errors = match action.get("errors").and_then(|v| v.as_bool()) {
                    Some(explicit) => explicit,
                    None => items
                        .as_array()
                        .map(|entries| entries.iter().any(bulk_item_failed))
                        .unwrap_or(false),
                };

                let response = serde_json::json!({
                    "took": 10,
                    "errors": errors,
                    "items": items
                });

                Ok(ActionResult::Custom {
                    name: "elasticsearch_response".to_string(),
                    data: json!({
                        "status": 200,
                        "body": body_of(&response)
                    }),
                })
            }
            "send_cluster_info" => {
                let cluster_name = action
                    .get("cluster_name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("llm-elasticsearch");

                let version = action
                    .get("version")
                    .and_then(|v| v.as_str())
                    .unwrap_or("8.0.0-llm");

                let response = serde_json::json!({
                    "name": "netget-node-1",
                    "cluster_name": cluster_name,
                    "cluster_uuid": "abcd1234",
                    "version": {
                        "number": version,
                        "build_flavor": "default",
                        "build_type": "tar",
                        "build_hash": "llm",
                        "build_date": "2025-01-01T00:00:00.000Z",
                        "build_snapshot": false,
                        "lucene_version": "9.0.0",
                        "minimum_wire_compatibility_version": "7.17.0",
                        "minimum_index_compatibility_version": "7.0.0"
                    },
                    "tagline": "You Know, for Search (powered by LLM)"
                });

                Ok(ActionResult::Custom {
                    name: "elasticsearch_response".to_string(),
                    data: json!({
                        "status": 200,
                        "body": body_of(&response)
                    }),
                })
            }
            "send_cluster_health" => {
                let cluster_name = action
                    .get("cluster_name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("llm-elasticsearch");

                // "green" is the affirmative answer — "every shard is allocated, the
                // cluster is fully healthy" — and it was what a handler that said nothing
                // produced. That is the fail-open shape: an outage reported as health.
                // There is no safe default here, because every value is an assertion, so
                // the handler has to state one.
                let status = action
                    .get("status")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "send_cluster_health requires `status`: \"green\", \"yellow\" \
                             or \"red\". It is the whole content of a health check and \
                             \"green\" is a claim that every shard is allocated"
                        )
                    })?;

                if !matches!(status, "green" | "yellow" | "red") {
                    return Err(anyhow::anyhow!(
                        "Invalid cluster health status {status:?}: Elasticsearch defines exactly \
                         three values - \"green\", \"yellow\" and \"red\". Clients branch on this \
                         string, so an unknown value is treated as an unusable cluster."
                    ));
                }

                let number_of_nodes = action
                    .get("number_of_nodes")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(1);

                let active_shards = action
                    .get("active_shards")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);

                let response = serde_json::json!({
                    "cluster_name": cluster_name,
                    "status": status,
                    "timed_out": false,
                    "number_of_nodes": number_of_nodes,
                    "number_of_data_nodes": number_of_nodes,
                    "active_primary_shards": active_shards,
                    "active_shards": active_shards,
                    "relocating_shards": 0,
                    "initializing_shards": 0,
                    "unassigned_shards": 0,
                    "delayed_unassigned_shards": 0,
                    "number_of_pending_tasks": 0,
                    "number_of_in_flight_fetch": 0,
                    "task_max_waiting_in_queue_millis": 0,
                    "active_shards_percent_as_number": 100.0
                });

                Ok(ActionResult::Custom {
                    name: "elasticsearch_response".to_string(),
                    data: json!({
                        "status": 200,
                        "body": body_of(&response)
                    }),
                })
            }
            _ => Err(anyhow::anyhow!("Unknown action type: {}", action_type)),
        }
    }
}
