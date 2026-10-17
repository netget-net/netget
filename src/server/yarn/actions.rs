//! Hadoop YARN ResourceManager REST API protocol actions and event types.
//!
//! The LLM roleplays a YARN cluster's ResourceManager: it invents the applications,
//! nodes and metrics the cluster reports. Every response an action produces is wrapped
//! in the exact JSON envelope a real YARN RM emits (see the Hadoop
//! `ResourceManagerRest` docs), so `curl` / a real YARN client parses it unchanged.
//!
//! No storage: the model supplies all cluster state per request. There is one event
//! type (`yarn_request`) and it is emitted for every LLM-handled request; the purely
//! mechanical `GET /ws/v1/cluster/info` version banner is answered statically in
//! `mod.rs` and never reaches the model.

use crate::llm::actions::protocol_trait::{ActionResult, Protocol, Server};
use crate::llm::actions::{ActionDefinition, Parameter};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::EventType;
use crate::state::app_state::AppState;
use anyhow::Result;
use serde_json::{json, Value};
use std::sync::LazyLock;

/// YARN ResourceManager protocol handler.
pub struct YarnProtocol {}

impl YarnProtocol {
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for YarnProtocol {
    fn default() -> Self {
        Self::new()
    }
}

/// Fired for every YARN RM REST request that requires an invented answer (everything
/// except the static `/ws/v1/cluster/info` banner).
pub static YARN_REQUEST_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "yarn_request",
        "Hadoop YARN ResourceManager REST request received",
        json!({
            "type": "send_yarn_apps",
            "apps": [{
                "id": "application_1476912658570_0002",
                "user": "dr.who",
                "name": "word count",
                "queue": "default",
                "state": "FINISHED",
                "finalStatus": "SUCCEEDED",
                "progress": 100.0,
                "applicationType": "MAPREDUCE"
            }]
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "method".to_string(),
            type_hint: "string".to_string(),
            description: "HTTP method (GET, POST)".to_string(),
            required: true,
        },
        Parameter {
            name: "path".to_string(),
            type_hint: "string".to_string(),
            description: "Request path, e.g. /ws/v1/cluster/apps".to_string(),
            required: true,
        },
        Parameter {
            name: "operation".to_string(),
            type_hint: "string".to_string(),
            description: "Detected operation: metrics, scheduler, apps, submit, \
                          new_application, app, nodes, node"
                .to_string(),
            required: true,
        },
        Parameter {
            name: "app_id".to_string(),
            type_hint: "string".to_string(),
            description: "Application id from the path (for the 'app' operation)".to_string(),
            required: false,
        },
        Parameter {
            name: "node_id".to_string(),
            type_hint: "string".to_string(),
            description: "Node id from the path (for the 'node' operation)".to_string(),
            required: false,
        },
        Parameter {
            name: "request_body".to_string(),
            type_hint: "string".to_string(),
            description: "JSON request body (for application submission)".to_string(),
            required: false,
        },
    ])
    .with_actions(yarn_actions())
    .with_log_template(
        LogTemplate::new()
            .with_info("YARN {client_ip} {method} {path}")
            .with_debug("YARN {method} {path} op={operation} from {client_ip}:{client_port}")
            .with_trace("YARN: {json_pretty(.)}"),
    )
});

/// The full action set the model may emit for a `yarn_request`.
fn yarn_actions() -> Vec<ActionDefinition> {
    vec![
        send_yarn_metrics_action(),
        send_yarn_scheduler_action(),
        send_yarn_apps_action(),
        send_yarn_app_action(),
        send_yarn_nodes_action(),
        send_yarn_new_application_action(),
        send_yarn_submit_response_action(),
        send_yarn_error_action(),
    ]
}

fn send_yarn_metrics_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_yarn_metrics".to_string(),
        description: "Answer GET /ws/v1/cluster/metrics with the cluster's aggregate metrics. \
                      All fields are numbers describing the (invented) cluster; keep them \
                      self-consistent (allocatedMB <= totalMB, activeNodes <= totalNodes). \
                      Wrapped in the {\"clusterMetrics\": {...}} envelope automatically."
            .to_string(),
        parameters: vec![Parameter {
            name: "metrics".to_string(),
            type_hint: "object".to_string(),
            description: "Object of clusterMetrics fields: appsSubmitted, appsRunning, \
                              appsPending, appsCompleted, appsFailed, appsKilled, totalMB, \
                              availableMB, allocatedMB, reservedMB, totalVirtualCores, \
                              availableVirtualCores, allocatedVirtualCores, containersAllocated, \
                              totalNodes, activeNodes, lostNodes, unhealthyNodes, \
                              decommissionedNodes. Any field you omit defaults to 0."
                .to_string(),
            required: true,
        }],
        example: json!({
            "type": "send_yarn_metrics",
            "metrics": {
                "appsSubmitted": 4, "appsRunning": 1, "appsCompleted": 3,
                "totalMB": 32768, "availableMB": 24576, "allocatedMB": 8192,
                "totalVirtualCores": 16, "availableVirtualCores": 12, "allocatedVirtualCores": 4,
                "containersAllocated": 4, "totalNodes": 2, "activeNodes": 2
            }
        }),
        log_template: Some(
            LogTemplate::new().with_info("-> YARN metrics {metrics.totalNodes} nodes"),
        ),
    }
}

fn send_yarn_scheduler_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_yarn_scheduler".to_string(),
        description: "Answer GET /ws/v1/cluster/scheduler with the scheduler and its queue tree. \
                      Rendered in the CapacityScheduler's own shape, {\"scheduler\": \
                      {\"schedulerInfo\": {\"type\": \"capacityScheduler\", \"queueName\": \"root\", \
                      ..., \"queues\": {\"queue\": [...]}}}}, with each queue's children nested the \
                      same way; or, with scheduler_type fifoScheduler, the FifoScheduler's flat \
                      summary. Keep it consistent with the apps you report (a queue's \
                      numApplications)."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "scheduler_type".to_string(),
                type_hint: "string".to_string(),
                description: "capacityScheduler (default) or fifoScheduler".to_string(),
                required: false,
            },
            Parameter {
                name: "root".to_string(),
                type_hint: "object".to_string(),
                description: "The root queue's (or the FIFO scheduler's) own numbers: capacity \
                              (default 100), usedCapacity (default 0), maxCapacity (default \
                              100); for fifoScheduler also qstate, numNodes, numContainers, \
                              usedNodeCapacity, availNodeCapacity, totalNodeCapacity, \
                              minQueueMemoryCapacity, maxQueueMemoryCapacity."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "queues".to_string(),
                type_hint: "array".to_string(),
                description: format!(
                    "capacityScheduler only, required: the queues under root. Each is an \
                     object with queueName (required) and capacity, usedCapacity, maxCapacity, \
                     absoluteCapacity, absoluteUsedCapacity, absoluteMaxCapacity, state \
                     (RUNNING/STOPPED), numApplications, numActiveApplications, \
                     numPendingApplications, numContainers, maxApplications, userLimit, \
                     userLimitFactor; a parent queue carries its children as a `queues` array \
                     of the same objects, at most {MAX_QUEUE_DEPTH} levels below root. \
                     queuePath is filled in from the names."
                ),
                required: false,
            },
        ],
        example: json!({
            "type": "send_yarn_scheduler",
            "root": {"capacity": 100.0, "usedCapacity": 25.0, "maxCapacity": 100.0},
            "queues": [
                {"queueName": "default", "capacity": 60.0, "usedCapacity": 0.0,
                 "maxCapacity": 100.0, "numApplications": 0},
                {"queueName": "etl", "capacity": 40.0, "usedCapacity": 62.5,
                 "maxCapacity": 100.0, "numApplications": 1,
                 "queues": [{"queueName": "nightly", "capacity": 100.0,
                             "usedCapacity": 62.5, "numApplications": 1}]}
            ]
        }),
        log_template: Some(LogTemplate::new().with_info("-> YARN scheduler {queues_len} queues")),
    }
}

fn send_yarn_apps_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_yarn_apps".to_string(),
        description: "Answer GET /ws/v1/cluster/apps with the list of applications. Supply the \
                      `apps` array (empty array = no applications, rendered as the YARN idiom \
                      \"apps\": null). Each element is an application object; wrapped as \
                      {\"apps\": {\"app\": [...]}} automatically."
            .to_string(),
        parameters: vec![Parameter {
            name: "apps".to_string(),
            type_hint: "array".to_string(),
            description: "Array of application objects. Common fields per app: id \
                          (e.g. application_1476912658570_0002), user, name, queue, state \
                          (NEW/SUBMITTED/ACCEPTED/RUNNING/FINISHED/FAILED/KILLED), finalStatus \
                          (UNDEFINED/SUCCEEDED/FAILED/KILLED), progress (0-100), \
                          applicationType (MAPREDUCE/SPARK/...), startedTime, finishedTime, \
                          elapsedTime, allocatedMB, allocatedVCores, runningContainers."
                .to_string(),
            required: true,
        }],
        example: json!({
            "type": "send_yarn_apps",
            "apps": [{
                "id": "application_1476912658570_0002", "user": "dr.who", "name": "word count",
                "queue": "default", "state": "RUNNING", "finalStatus": "UNDEFINED",
                "progress": 62.5, "applicationType": "MAPREDUCE", "allocatedMB": 4096,
                "allocatedVCores": 2, "runningContainers": 2
            }]
        }),
        log_template: Some(LogTemplate::new().with_info("-> YARN {apps_len} apps")),
    }
}

fn send_yarn_app_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_yarn_app".to_string(),
        description: "Answer GET /ws/v1/cluster/apps/{appid} with a single application. Supply \
                      the `app` object; wrapped as {\"app\": {...}} automatically. Emit \
                      send_yarn_error with status 404 if the application does not exist."
            .to_string(),
        parameters: vec![Parameter {
            name: "app".to_string(),
            type_hint: "object".to_string(),
            description: "A single application object (same fields as an element of \
                          send_yarn_apps.apps)."
                .to_string(),
            required: true,
        }],
        example: json!({
            "type": "send_yarn_app",
            "app": {
                "id": "application_1476912658570_0002", "user": "dr.who", "name": "word count",
                "queue": "default", "state": "FINISHED", "finalStatus": "SUCCEEDED",
                "progress": 100.0, "applicationType": "MAPREDUCE"
            }
        }),
        log_template: Some(LogTemplate::new().with_info("-> YARN app {app.id}")),
    }
}

fn send_yarn_nodes_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_yarn_nodes".to_string(),
        description: "Answer GET /ws/v1/cluster/nodes with the NodeManager list. Supply the \
                      `nodes` array; wrapped as {\"nodes\": {\"node\": [...]}} automatically."
            .to_string(),
        parameters: vec![Parameter {
            name: "nodes".to_string(),
            type_hint: "array".to_string(),
            description: "Array of node objects. Common fields per node: id (host:port, e.g. \
                          host.domain.com:8041), nodeHostName, nodeHTTPAddress, rack \
                          (/default-rack), state (NEW/RUNNING/UNHEALTHY/DECOMMISSIONED/LOST), \
                          healthReport, numContainers, usedMemoryMB, availMemoryMB, \
                          usedVirtualCores, availableVirtualCores, version, lastHealthUpdate."
                .to_string(),
            required: true,
        }],
        example: json!({
            "type": "send_yarn_nodes",
            "nodes": [{
                "id": "host1.example.com:8041", "nodeHostName": "host1.example.com",
                "nodeHTTPAddress": "host1.example.com:8042", "rack": "/default-rack",
                "state": "RUNNING", "healthReport": "", "numContainers": 2,
                "usedMemoryMB": 4096, "availMemoryMB": 12288, "usedVirtualCores": 2,
                "availableVirtualCores": 6, "version": "3.3.6"
            }]
        }),
        log_template: Some(LogTemplate::new().with_info("-> YARN {nodes_len} nodes")),
    }
}

fn send_yarn_new_application_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_yarn_new_application".to_string(),
        description: "Answer POST /ws/v1/cluster/apps/new-application (the first step of the \
                      submission flow) with a freshly allocated application id and the cluster's \
                      maximum resource capability."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "application_id".to_string(),
                type_hint: "string".to_string(),
                description: "Newly allocated application id, e.g. \
                              application_1476912658570_0005."
                    .to_string(),
                required: true,
            },
            Parameter {
                name: "max_memory_mb".to_string(),
                type_hint: "number".to_string(),
                description: "maximum-resource-capability memory in MB (default 8192)".to_string(),
                required: false,
            },
            Parameter {
                name: "max_vcores".to_string(),
                type_hint: "number".to_string(),
                description: "maximum-resource-capability vCores (default 4)".to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "send_yarn_new_application",
            "application_id": "application_1476912658570_0005",
            "max_memory_mb": 8192,
            "max_vcores": 4
        }),
        log_template: Some(
            LogTemplate::new().with_info("-> YARN new-application {application_id}"),
        ),
    }
}

fn send_yarn_submit_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_yarn_submit_response".to_string(),
        description: "Answer POST /ws/v1/cluster/apps (submit an application). On acceptance YARN \
                      replies 202 Accepted with an empty body and a Location header pointing at \
                      the new application; set accepted=true. To reject the submission set \
                      accepted=false and supply a message (rendered as a 400 RemoteException)."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "accepted".to_string(),
                type_hint: "boolean".to_string(),
                description: "true = 202 Accepted, false = 400 rejection".to_string(),
                required: true,
            },
            Parameter {
                name: "application_id".to_string(),
                type_hint: "string".to_string(),
                description: "The submitted application id (used to build the Location header \
                              when accepted)."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "message".to_string(),
                type_hint: "string".to_string(),
                description: "Rejection reason (when accepted=false)".to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "send_yarn_submit_response",
            "accepted": true,
            "application_id": "application_1476912658570_0005"
        }),
        log_template: Some(LogTemplate::new().with_info("-> YARN submit accepted={accepted}")),
    }
}

fn send_yarn_error_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_yarn_error".to_string(),
        description: "Return a YARN RemoteException error envelope with an explicit HTTP status. \
                      Use for a missing application/node (404), a bad request (400) or any \
                      condition without a dedicated action. status must be 100-599."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "status".to_string(),
                type_hint: "number".to_string(),
                description: "HTTP status code (400, 404, 500, ...)".to_string(),
                required: true,
            },
            Parameter {
                name: "exception".to_string(),
                type_hint: "string".to_string(),
                description: "Exception class name, e.g. NotFoundException, BadRequestException"
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "message".to_string(),
                type_hint: "string".to_string(),
                description: "Human-readable error message".to_string(),
                required: true,
            },
        ],
        example: json!({
            "type": "send_yarn_error",
            "status": 404,
            "exception": "NotFoundException",
            "message": "app with id 'application_1_0009' not found"
        }),
        log_template: Some(LogTemplate::new().with_info("-> YARN error {status} {exception}")),
    }
}

pub fn get_yarn_event_types() -> Vec<EventType> {
    vec![YARN_REQUEST_EVENT.clone()]
}

/// How many levels of queues below root `send_yarn_scheduler` renders. A CapacityScheduler
/// hierarchy is rarely more than three or four deep; the bound keeps the conversion of the
/// model-supplied tree (which recurses once per level) from following an arbitrarily deep one.
pub const MAX_QUEUE_DEPTH: usize = 8;

/// One model-supplied queue in the CapacityScheduler's shape: `queuePath` from the names, the
/// children (`queues`, an array) wrapped as `{"queue": [...]}`, `queueType` and, for a leaf,
/// the leaf queue `type` the real scheduler reports. `depth` is this queue's level below root.
fn capacity_queue(queue: &Value, parent_path: &str, depth: usize) -> Result<Value> {
    if depth > MAX_QUEUE_DEPTH {
        return Err(anyhow::anyhow!(
            "the queue tree is deeper than {MAX_QUEUE_DEPTH} levels below root"
        ));
    }
    let mut out = queue
        .as_object()
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("each queue is an object"))?;
    let name = out
        .get("queueName")
        .and_then(|v| v.as_str())
        .filter(|n| !n.is_empty())
        .ok_or_else(|| anyhow::anyhow!("each queue needs a queueName"))?
        .to_string();
    let path = format!("{parent_path}.{name}");
    out.entry("queuePath").or_insert_with(|| json!(path));
    out.entry("state").or_insert_with(|| json!("RUNNING"));
    match out.remove("queues") {
        Some(Value::Array(children)) if !children.is_empty() => {
            let children = children
                .iter()
                .map(|c| capacity_queue(c, &path, depth + 1))
                .collect::<Result<Vec<_>>>()?;
            out.insert("queueType".into(), json!("parent"));
            out.insert("queues".into(), json!({ "queue": children }));
        }
        None | Some(Value::Null) | Some(Value::Array(_)) => {
            out.insert("queueType".into(), json!("leaf"));
            out.entry("type")
                .or_insert_with(|| json!("capacitySchedulerLeafQueueInfo"));
        }
        Some(_) => return Err(anyhow::anyhow!("a queue's `queues` is an array of queues")),
    }
    Ok(Value::Object(out))
}

/// Serialize a response body without a panic path (serializing a Value cannot fail).
fn body_of(value: &Value) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| value.to_string())
}

/// Validate a model-supplied HTTP status, rejecting out-of-range values where the
/// message still reaches the model rather than panicking later.
fn parse_status(action: &Value, key: &str) -> Result<u16> {
    let raw = action
        .get(key)
        .and_then(|v| v.as_u64())
        .ok_or_else(|| anyhow::anyhow!("Missing or invalid '{key}': expected a number"))?;
    if !(100..=599).contains(&raw) {
        return Err(anyhow::anyhow!(
            "Invalid {key} {raw}: must be an HTTP status between 100 and 599"
        ));
    }
    Ok(raw as u16)
}

/// Build the YARN RemoteException envelope every client parses on error.
fn remote_exception(exception: &str, message: &str) -> Value {
    json!({
        "RemoteException": {
            "exception": exception,
            "message": message,
            "javaClassName": format!("org.apache.hadoop.yarn.webapp.{exception}"),
        }
    })
}

impl Protocol for YarnProtocol {
    fn get_startup_parameters(&self) -> Vec<crate::llm::actions::ParameterDefinition> {
        use crate::llm::actions::ParameterDefinition;
        vec![
            ParameterDefinition {
                name: "resource_manager_version".to_string(),
                type_hint: "string".to_string(),
                description: "Version string reported by the static GET /ws/v1/cluster/info \
                              banner (resourceManagerVersion / hadoopVersion). Default 3.3.6."
                    .to_string(),
                required: false,
                example: json!("3.3.6"),
                default: None,
            },
            ParameterDefinition {
                name: "cluster_id".to_string(),
                type_hint: "string".to_string(),
                description: "Numeric cluster id reported in the /ws/v1/cluster/info banner \
                              (the RM start epoch-ms). Default 1476912658570."
                    .to_string(),
                required: false,
                example: json!("1476912658570"),
                default: None,
            },
        ]
    }
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        yarn_actions()
    }
    fn protocol_name(&self) -> &'static str {
        "YARN"
    }
    fn get_event_types(&self) -> Vec<EventType> {
        get_yarn_event_types()
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>HTTP>YARN"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["yarn", "hadoop yarn", "yarn resourcemanager"]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .well_known_port(8088)
            .implementation("hyper v1 HTTP/1.1 server, manual YARN RM REST envelopes")
            .llm_control("Applications, nodes and cluster metrics invented by the LLM")
            .e2e_testing(
                "tests/server/yarn/datadog_check_test.rs runs Datadog's YARN integration \
                 (datadog_checks.yarn, integrations-core tag yarn-8.4.2) once against the server \
                 and asserts the cluster, application, node and queue metrics, tags, service \
                 checks and version it submitted from the model's answers to /metrics, /apps, \
                 /nodes and /scheduler. e2e_test.rs checks the documented envelopes with \
                 reqwest. NetGet's own YARN client is tested against real Hadoop, not against \
                 this server",
            )
            .notes(
                "Virtual cluster, no storage. GET /ws/v1/cluster/info is answered \
                    statically; metrics/scheduler/apps/nodes are LLM-driven, the scheduler in \
                    the CapacityScheduler's nested queues.queue shape (or the FifoScheduler's). \
                    Fail-closed: LLM failure returns 503/500 RemoteException, never an \
                    empty-but-200 cluster. Experimental: one independent consumer (Datadog's \
                    check), which reads the four list endpoints only; nothing third-party has \
                    driven an application or node by id, new-application or submission.",
            )
            .max_inbound_bytes(crate::server::yarn::MAX_REQUEST_BODY_BYTES)
            .request_only("The YARN REST API is HTTP request/response; a server cannot send a peer anything unprompted")
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn description(&self) -> &'static str {
        "Hadoop YARN ResourceManager REST API"
    }
    fn example_prompt(&self) -> &'static str {
        "Start a Hadoop YARN ResourceManager on port 8088 with a couple of running Spark apps"
    }
    fn group_name(&self) -> &'static str {
        "Application"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;

        // Deterministic: report fixed cluster metrics for every request, no LLM
        // call.
        let script = r#"import json, sys
data = json.load(sys.stdin)
event = data["event"]
if data["event_type_id"] == "yarn_request":
    actions = [{"type": "send_yarn_metrics",
                "metrics": {"appsRunning": 0, "availableMB": 8192}}]
else:
    actions = []
print(json.dumps({"actions": actions}))"#;

        StartupExamples::new(
            json!({
                "type": "open_server",
                "port": 8088,
                "base_stack": "yarn",
                "instruction": "Hadoop YARN ResourceManager reporting a small MapReduce cluster"
            }),
            json!({
                "type": "open_server",
                "port": 8088,
                "base_stack": "yarn",
                "event_handlers": [{
                    "event_pattern": "yarn_request",
                    "handler": { "type": "script", "language": "python", "code": script }
                }]
            }),
            json!({
                "type": "open_server",
                "port": 8088,
                "base_stack": "yarn",
                "event_handlers": [{
                    "event_pattern": "yarn_request",
                    "handler": {
                        "type": "static",
                        "actions": [{
                            "type": "send_yarn_metrics",
                            "metrics": { "totalNodes": 1, "activeNodes": 1, "totalMB": 8192,
                                         "availableMB": 8192 }
                        }]
                    }
                }]
            }),
        )
    }
}

impl Server for YarnProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            // Read the optional static-banner params before moving ctx fields.
            let rm_version = ctx
                .startup_params
                .as_ref()
                .and_then(|p| {
                    p.get_optional_string("resource_manager_version")
                        .ok()
                        .flatten()
                })
                .unwrap_or_else(|| "3.3.6".to_string());
            let cluster_id = ctx
                .startup_params
                .as_ref()
                .and_then(|p| p.get_optional_string("cluster_id").ok().flatten())
                .unwrap_or_else(|| "1476912658570".to_string());

            crate::server::yarn::YarnServer::spawn_with_llm_actions(
                ctx.legacy_listen_addr(),
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.server_id,
                rm_version,
                cluster_id,
            )
            .await
        })
    }

    fn execute_action(&self, action: Value) -> Result<ActionResult> {
        let action_type = action
            .get("type")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("Missing action type"))?;

        let custom = |status: u16, body: Value| {
            Ok(ActionResult::Custom {
                name: "yarn_response".to_string(),
                data: json!({ "status": status, "body": body_of(&body), "location": Value::Null }),
            })
        };

        match action_type {
            "send_yarn_metrics" => {
                let metrics = action
                    .get("metrics")
                    .cloned()
                    .filter(|v| v.is_object())
                    .ok_or_else(|| anyhow::anyhow!("Missing 'metrics' object"))?;
                // Fill the mandatory keys clients read so a partial object still parses.
                let mut m = metrics;
                for key in [
                    "appsSubmitted",
                    "appsCompleted",
                    "appsPending",
                    "appsRunning",
                    "appsFailed",
                    "appsKilled",
                    "reservedMB",
                    "availableMB",
                    "allocatedMB",
                    "totalMB",
                    "reservedVirtualCores",
                    "availableVirtualCores",
                    "allocatedVirtualCores",
                    "totalVirtualCores",
                    "containersAllocated",
                    "containersReserved",
                    "containersPending",
                    "totalNodes",
                    "activeNodes",
                    "lostNodes",
                    "unhealthyNodes",
                    "decommissionedNodes",
                    "decommissioningNodes",
                    "rebootedNodes",
                    "shutdownNodes",
                ] {
                    if m.get(key).is_none() {
                        m[key] = json!(0);
                    }
                }
                custom(200, json!({ "clusterMetrics": m }))
            }
            "send_yarn_scheduler" => {
                let kind = action
                    .get("scheduler_type")
                    .and_then(|v| v.as_str())
                    .unwrap_or("capacityScheduler");
                let mut info = action
                    .get("root")
                    .and_then(|v| v.as_object())
                    .cloned()
                    .unwrap_or_default();
                info.insert("type".into(), json!(kind));
                for (key, default) in [
                    ("capacity", 100.0),
                    ("usedCapacity", 0.0),
                    ("maxCapacity", 100.0),
                ] {
                    info.entry(key).or_insert_with(|| json!(default));
                }
                match kind {
                    "capacityScheduler" => {
                        let queues = action
                            .get("queues")
                            .and_then(|v| v.as_array())
                            .filter(|q| !q.is_empty())
                            .ok_or_else(|| {
                                anyhow::anyhow!(
                                    "a capacityScheduler needs a non-empty 'queues' array"
                                )
                            })?
                            .iter()
                            .map(|q| capacity_queue(q, "root", 1))
                            .collect::<Result<Vec<_>>>()?;
                        info.insert("queueName".into(), json!("root"));
                        info.insert("queuePath".into(), json!("root"));
                        info.insert("queueType".into(), json!("parent"));
                        info.insert("queues".into(), json!({ "queue": queues }));
                    }
                    "fifoScheduler" => {
                        info.entry("qstate").or_insert_with(|| json!("RUNNING"));
                    }
                    other => {
                        return Err(anyhow::anyhow!(
                            "scheduler_type {other:?}: capacityScheduler or fifoScheduler"
                        ))
                    }
                }
                custom(200, json!({ "scheduler": { "schedulerInfo": info } }))
            }
            "send_yarn_apps" => {
                let apps = action
                    .get("apps")
                    .and_then(|v| v.as_array())
                    .ok_or_else(|| anyhow::anyhow!("Missing 'apps' array"))?;
                // YARN renders an empty application list as "apps": null, not {"app": []}.
                let body = if apps.is_empty() {
                    json!({ "apps": Value::Null })
                } else {
                    json!({ "apps": { "app": apps } })
                };
                custom(200, body)
            }
            "send_yarn_app" => {
                let app = action
                    .get("app")
                    .cloned()
                    .filter(|v| v.is_object())
                    .ok_or_else(|| anyhow::anyhow!("Missing 'app' object"))?;
                custom(200, json!({ "app": app }))
            }
            "send_yarn_nodes" => {
                let nodes = action
                    .get("nodes")
                    .and_then(|v| v.as_array())
                    .ok_or_else(|| anyhow::anyhow!("Missing 'nodes' array"))?;
                let body = if nodes.is_empty() {
                    json!({ "nodes": Value::Null })
                } else {
                    json!({ "nodes": { "node": nodes } })
                };
                custom(200, body)
            }
            "send_yarn_new_application" => {
                let app_id = action
                    .get("application_id")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow::anyhow!("Missing 'application_id'"))?;
                let mem = action
                    .get("max_memory_mb")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(8192);
                let vcores = action
                    .get("max_vcores")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(4);
                custom(
                    200,
                    json!({
                        "application-id": app_id,
                        "maximum-resource-capability": { "memory": mem, "vCores": vcores }
                    }),
                )
            }
            "send_yarn_submit_response" => {
                let accepted = action
                    .get("accepted")
                    .and_then(|v| v.as_bool())
                    .ok_or_else(|| anyhow::anyhow!("Missing 'accepted' boolean"))?;
                if accepted {
                    let app_id = action
                        .get("application_id")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    // 202 Accepted with empty body + Location header, as YARN does.
                    Ok(ActionResult::Custom {
                        name: "yarn_response".to_string(),
                        data: json!({
                            "status": 202,
                            "body": "",
                            "location": format!("/ws/v1/cluster/apps/{app_id}"),
                        }),
                    })
                } else {
                    let message = action
                        .get("message")
                        .and_then(|v| v.as_str())
                        .unwrap_or("application submission rejected");
                    custom(400, remote_exception("BadRequestException", message))
                }
            }
            "send_yarn_error" => {
                let status = parse_status(&action, "status")?;
                let message = action
                    .get("message")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow::anyhow!("Missing 'message'"))?;
                let exception = action
                    .get("exception")
                    .and_then(|v| v.as_str())
                    .unwrap_or("WebApplicationException");
                custom(status, remote_exception(exception, message))
            }
            _ => Err(anyhow::anyhow!("Unknown action type: {}", action_type)),
        }
    }
}
