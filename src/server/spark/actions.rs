//! Apache Spark monitoring REST API (`/api/v1/...`) protocol actions and event types.
//!
//! The LLM roleplays a Spark application's control plane and invents the applications, jobs,
//! stages and executors it reports. Every success response is a top-level **JSON array**, the
//! exact shape Spark's monitoring REST API (and its History Server) emits, so `curl` / a real
//! client parses it unchanged.
//!
//! No storage: the model supplies all state per request. One event type (`spark_request`),
//! emitted for every LLM-handled request; the mechanical `GET /api/v1/version` banner is
//! answered statically in `mod.rs`.

use crate::llm::actions::protocol_trait::{ActionResult, Protocol, Server};
use crate::llm::actions::{ActionDefinition, Parameter};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::EventType;
use crate::state::app_state::AppState;
use anyhow::Result;
use serde_json::{json, Value};
use std::sync::LazyLock;

/// Apache Spark monitoring-API protocol handler.
pub struct SparkProtocol {}

impl SparkProtocol {
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for SparkProtocol {
    fn default() -> Self {
        Self::new()
    }
}

/// Fired for every Spark monitoring-API request that needs an invented answer (everything
/// except the static `/api/v1/version` banner).
pub static SPARK_REQUEST_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "spark_request",
        "Apache Spark monitoring REST API request received",
        json!({
            "type": "send_spark_applications",
            "applications": [{
                "id": "app-20161116163331-0000",
                "name": "Spark shell",
                "attempts": [{
                    "startTime": "2016-11-16T22:33:29.916GMT",
                    "completed": false,
                    "sparkUser": "jose",
                    "appSparkVersion": "3.5.1"
                }]
            }]
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "method".to_string(),
            type_hint: "string".to_string(),
            description: "HTTP method (GET)".to_string(),
            required: true,
        },
        Parameter {
            name: "path".to_string(),
            type_hint: "string".to_string(),
            description: "Request path, e.g. /api/v1/applications/app-1/jobs".to_string(),
            required: true,
        },
        Parameter {
            name: "operation".to_string(),
            type_hint: "string".to_string(),
            description: "Detected operation: applications (the list), application (one, \
                          GET /api/v1/applications/{id}), jobs, stages, executors, rdd \
                          (/storage/rdd), or application_resource (any other per-application \
                          path: answer it or 404 it with send_spark_error)"
                .to_string(),
            required: true,
        },
        Parameter {
            name: "app_id".to_string(),
            type_hint: "string".to_string(),
            description: "Application id from the path (for per-application operations)"
                .to_string(),
            required: false,
        },
    ])
    .with_actions(spark_actions())
    // Only fields `spark_request` actually carries. `{client_ip}` and `{client_port}` were
    // in this template and in none of the event data, and a missing field renders as the
    // empty string — so the INFO line read "Spark  GET /api/v1/applications".
    .with_log_template(
        LogTemplate::new()
            .with_info("Spark {method} {path}")
            .with_debug("Spark {method} {path} op={operation} app={app_id}")
            .with_trace("Spark: {json_pretty(.)}"),
    )
});

fn spark_actions() -> Vec<ActionDefinition> {
    vec![
        send_spark_applications_action(),
        send_spark_jobs_action(),
        send_spark_stages_action(),
        send_spark_executors_action(),
        send_spark_rdds_action(),
        send_spark_error_action(),
    ]
}

fn send_spark_rdds_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_spark_rdds".to_string(),
        description: "Answer GET /api/v1/applications/{id}/storage/rdd (operation rdd): the \
                      application's cached RDDs. Supply the `rdds` array; the response is the \
                      array itself, and an empty array means nothing is cached."
            .to_string(),
        parameters: vec![Parameter {
            name: "rdds".to_string(),
            type_hint: "array".to_string(),
            description: "Array of RDD storage objects. Common fields: id (number), name, \
                          numPartitions, numCachedPartitions, storageLevel (e.g. \"Memory \
                          Deserialized 1x Replicated\"), memoryUsed, diskUsed (bytes)."
                .to_string(),
            required: true,
        }],
        example: json!({
            "type": "send_spark_rdds",
            "rdds": [{
                "id": 3, "name": "ParallelCollectionRDD", "numPartitions": 4,
                "numCachedPartitions": 4, "storageLevel": "Memory Deserialized 1x Replicated",
                "memoryUsed": 2048, "diskUsed": 0
            }]
        }),
        log_template: Some(LogTemplate::new().with_info("-> Spark {rdds_len} cached RDDs")),
    }
}

fn send_spark_applications_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_spark_applications".to_string(),
        description: "Answer GET /api/v1/applications (list) or GET /api/v1/applications/{id} \
                      (single). Supply the `applications` array; the response is the array \
                      itself (Spark returns a bare JSON array). For the single-app endpoint \
                      (operation application) return exactly one element; it is sent as the \
                      bare object, as Spark sends it."
            .to_string(),
        parameters: vec![Parameter {
            name: "applications".to_string(),
            type_hint: "array".to_string(),
            description: "Array of application objects. Each: id (e.g. \
                          app-20161116163331-0000), name, and an `attempts` array whose \
                          elements carry startTime, endTime, lastUpdated, duration, sparkUser, \
                          completed (bool), appSparkVersion."
                .to_string(),
            required: true,
        }],
        example: json!({
            "type": "send_spark_applications",
            "applications": [{
                "id": "app-20161116163331-0000", "name": "Spark shell",
                "attempts": [{
                    "startTime": "2016-11-16T22:33:29.916GMT",
                    "endTime": "1969-12-31T23:59:59.999GMT",
                    "duration": 0, "sparkUser": "jose", "completed": false,
                    "appSparkVersion": "3.5.1"
                }]
            }]
        }),
        log_template: Some(
            LogTemplate::new().with_info("-> Spark {applications_len} applications"),
        ),
    }
}

fn send_spark_jobs_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_spark_jobs".to_string(),
        description: "Answer GET /api/v1/applications/{id}/jobs. Supply the `jobs` array; the \
                      response is the array itself."
            .to_string(),
        parameters: vec![Parameter {
            name: "jobs".to_string(),
            type_hint: "array".to_string(),
            description: "Array of job objects. Common fields: jobId (number), name, \
                          submissionTime, completionTime, stageIds (array of numbers), status \
                          (RUNNING/SUCCEEDED/FAILED/UNKNOWN), numTasks, numActiveTasks, \
                          numCompletedTasks, numSkippedTasks, numFailedTasks, numActiveStages, \
                          numCompletedStages, numFailedStages."
                .to_string(),
            required: true,
        }],
        example: json!({
            "type": "send_spark_jobs",
            "jobs": [{
                "jobId": 0, "name": "count at <console>:15", "status": "SUCCEEDED",
                "stageIds": [0], "numTasks": 8, "numActiveTasks": 0, "numCompletedTasks": 8,
                "numFailedTasks": 0, "numActiveStages": 0, "numCompletedStages": 1,
                "numFailedStages": 0
            }]
        }),
        log_template: Some(LogTemplate::new().with_info("-> Spark {jobs_len} jobs")),
    }
}

fn send_spark_stages_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_spark_stages".to_string(),
        description: "Answer GET /api/v1/applications/{id}/stages. Supply the `stages` array; \
                      the response is the array itself."
            .to_string(),
        parameters: vec![Parameter {
            name: "stages".to_string(),
            type_hint: "array".to_string(),
            description: "Array of stage objects. Common fields: status \
                          (ACTIVE/COMPLETE/PENDING/FAILED/SKIPPED), stageId (number), attemptId \
                          (number), name, numTasks, numActiveTasks, numCompleteTasks, \
                          numFailedTasks, inputBytes, outputBytes, shuffleReadBytes, \
                          shuffleWriteBytes."
                .to_string(),
            required: true,
        }],
        example: json!({
            "type": "send_spark_stages",
            "stages": [{
                "status": "COMPLETE", "stageId": 0, "attemptId": 0, "numTasks": 8,
                "numActiveTasks": 0, "numCompleteTasks": 8, "numFailedTasks": 0,
                "name": "count at <console>:15"
            }]
        }),
        log_template: Some(LogTemplate::new().with_info("-> Spark {stages_len} stages")),
    }
}

fn send_spark_executors_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_spark_executors".to_string(),
        description: "Answer GET /api/v1/applications/{id}/executors. Supply the `executors` \
                      array; the response is the array itself. There is always at least the \
                      `driver` executor."
            .to_string(),
        parameters: vec![Parameter {
            name: "executors".to_string(),
            type_hint: "array".to_string(),
            description: "Array of executor objects. Common fields: id (\"driver\" or a number \
                          as string), hostPort, isActive (bool), rddBlocks, memoryUsed, \
                          diskUsed, totalCores, maxTasks, activeTasks, failedTasks, \
                          completedTasks, totalTasks, totalDuration, maxMemory."
                .to_string(),
            required: true,
        }],
        example: json!({
            "type": "send_spark_executors",
            "executors": [{
                "id": "driver", "hostPort": "10.0.0.1:57971", "isActive": true, "rddBlocks": 0,
                "memoryUsed": 0, "diskUsed": 0, "totalCores": 8, "maxTasks": 8, "activeTasks": 0,
                "failedTasks": 0, "completedTasks": 16, "totalTasks": 16, "maxMemory": 384093388
            }]
        }),
        log_template: Some(LogTemplate::new().with_info("-> Spark {executors_len} executors")),
    }
}

fn send_spark_error_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_spark_error".to_string(),
        description: "Return an error with an explicit HTTP status. Spark's REST API sends error \
                      bodies as plain text (e.g. 404 \"unknown app: app-1\"); this action does \
                      the same. status must be 100-599."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "status".to_string(),
                type_hint: "number".to_string(),
                description: "HTTP status code (400, 404, 500, ...)".to_string(),
                required: true,
            },
            Parameter {
                name: "message".to_string(),
                type_hint: "string".to_string(),
                description: "Plain-text error message".to_string(),
                required: true,
            },
        ],
        example: json!({
            "type": "send_spark_error",
            "status": 404,
            "message": "unknown app: app-does-not-exist"
        }),
        log_template: Some(LogTemplate::new().with_info("-> Spark error {status}")),
    }
}

pub fn get_spark_event_types() -> Vec<EventType> {
    vec![SPARK_REQUEST_EVENT.clone()]
}

fn array_body(action: &Value, key: &str) -> Result<Value> {
    action
        .get(key)
        .filter(|v| v.is_array())
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("Missing '{key}' array"))
}

fn parse_status(action: &Value) -> Result<u16> {
    let raw = action
        .get("status")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| anyhow::anyhow!("Missing or invalid 'status': expected a number"))?;
    if !(100..=599).contains(&raw) {
        return Err(anyhow::anyhow!(
            "Invalid status {raw}: must be an HTTP status between 100 and 599"
        ));
    }
    Ok(raw as u16)
}

impl Protocol for SparkProtocol {
    fn get_startup_parameters(&self) -> Vec<crate::llm::actions::ParameterDefinition> {
        use crate::llm::actions::ParameterDefinition;
        vec![ParameterDefinition {
            name: "spark_version".to_string(),
            type_hint: "string".to_string(),
            description: "Version string reported by the static GET /api/v1/version banner. \
                          Default 3.5.1."
                .to_string(),
            required: false,
            example: json!("3.5.1"),
            default: None,
        }]
    }
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        spark_actions()
    }
    fn protocol_name(&self) -> &'static str {
        "Spark"
    }
    fn get_event_types(&self) -> Vec<EventType> {
        get_spark_event_types()
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>HTTP>SPARK"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["spark", "apache spark", "spark rest api"]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .well_known_port(4040)
            .implementation("hyper v1 HTTP/1.1 server, manual Spark monitoring REST arrays")
            .llm_control("Applications, jobs, stages, executors and cached RDDs invented by the LLM")
            .e2e_testing(
                "tests/server/spark/datadog_check_test.rs runs Datadog's Spark integration \
                 (datadog_checks.spark, integrations-core tag spark-7.8.0) once in driver mode \
                 against the server and asserts the metrics, tags, service checks and version it \
                 submitted from the model's answers (applications, jobs, stages, executors, \
                 storage/rdd, a streaming-statistics 404). e2e_test.rs checks the documented \
                 shapes with reqwest. NetGet's own Spark client is tested against real Spark, \
                 not against this server",
            )
            .notes(
                "Virtual application, no storage. GET /api/v1/version is answered \
                    statically; applications/jobs/stages/executors/storage-rdd are LLM-driven, \
                    and GET /api/v1/applications/{id} is sent as the one object Spark sends. \
                    Fail-closed: LLM failure returns 503/500 JSON error, never an empty-but-200 \
                    array. Experimental: one independent consumer (Datadog's check), which reads \
                    the list endpoints only; nothing has yet driven the per-job, per-stage, \
                    environment or SQL endpoints, which reach the model as \
                    application_resource.",
            )
            .max_inbound_bytes(crate::server::spark::MAX_REQUEST_BYTES)
            .request_only("The Spark REST API is HTTP request/response; a server cannot send a peer anything unprompted")
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn description(&self) -> &'static str {
        "Apache Spark monitoring REST / history API"
    }
    fn example_prompt(&self) -> &'static str {
        "Start an Apache Spark REST API on port 4040 reporting one running application"
    }
    fn group_name(&self) -> &'static str {
        "Application"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;

        // Deterministic: report one running application for every monitoring
        // API request, no LLM call.
        let script = r#"import json, sys
data = json.load(sys.stdin)
if data["event_type_id"] == "spark_request":
    actions = [{"type": "send_spark_applications",
                "applications": [{"id": "app-netget-0000", "name": "netget-app",
                    "attempts": [{"completed": False, "appSparkVersion": "3.5.1"}]}]}]
else:
    actions = []
print(json.dumps({"actions": actions}))"#;

        StartupExamples::new(
            json!({
                "type": "open_server",
                "port": 4040,
                "base_stack": "spark",
                "instruction": "Apache Spark driver monitoring API with one running job"
            }),
            json!({
                "type": "open_server",
                "port": 4040,
                "base_stack": "spark",
                "event_handlers": [{
                    "event_pattern": "spark_request",
                    "handler": { "type": "script", "language": "python", "code": script }
                }]
            }),
            json!({
                "type": "open_server",
                "port": 4040,
                "base_stack": "spark",
                "event_handlers": [{
                    "event_pattern": "spark_request",
                    "handler": {
                        "type": "static",
                        "actions": [{
                            "type": "send_spark_applications",
                            "applications": [{
                                "id": "app-netget-0000", "name": "netget-app",
                                "attempts": [{ "completed": false, "appSparkVersion": "3.5.1" }]
                            }]
                        }]
                    }
                }]
            }),
        )
    }
}

impl Server for SparkProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            let spark_version = ctx
                .startup_params
                .as_ref()
                .and_then(|p| p.get_optional_string("spark_version").ok().flatten())
                .unwrap_or_else(|| "3.5.1".to_string());

            crate::server::spark::SparkServer::spawn_with_llm_actions(
                ctx.legacy_listen_addr(),
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.server_id,
                spark_version,
            )
            .await
        })
    }

    fn execute_action(&self, action: Value) -> Result<ActionResult> {
        let action_type = action
            .get("type")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("Missing action type"))?;

        // Spark success bodies are bare JSON arrays; errors are plain text.
        let json_array = |status: u16, body: Value| {
            Ok(ActionResult::Custom {
                name: "spark_response".to_string(),
                data: json!({
                    "status": status,
                    "body": serde_json::to_string(&body).unwrap_or_else(|_| "[]".to_string()),
                    "content_type": "application/json",
                }),
            })
        };

        match action_type {
            "send_spark_applications" => json_array(200, array_body(&action, "applications")?),
            "send_spark_jobs" => json_array(200, array_body(&action, "jobs")?),
            "send_spark_stages" => json_array(200, array_body(&action, "stages")?),
            "send_spark_executors" => json_array(200, array_body(&action, "executors")?),
            "send_spark_rdds" => json_array(200, array_body(&action, "rdds")?),
            "send_spark_error" => {
                let status = parse_status(&action)?;
                let message = action
                    .get("message")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow::anyhow!("Missing 'message'"))?;
                Ok(ActionResult::Custom {
                    name: "spark_response".to_string(),
                    data: json!({
                        "status": status,
                        "body": message,
                        "content_type": "text/plain",
                    }),
                })
            }
            _ => Err(anyhow::anyhow!("Unknown action type: {}", action_type)),
        }
    }
}
