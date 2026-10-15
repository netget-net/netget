//! A monitoring-API response → the event the model reads.
//!
//! Spark answers every resource with JSON — a bare array for lists, an object for one entry —
//! and each entry carries far more than a model can use (a stage brings ~60 fields, an
//! executor a nested memory-metrics map). So each resource is **projected** onto a fixed list
//! of fields, and nothing the server adds beyond them reaches the model.
//!
//! | resource | fields kept |
//! |---|---|
//! | application | [`APPLICATION_FIELDS`], `attempts` (at most [`MAX_ATTEMPTS`]) each [`ATTEMPT_FIELDS`] |
//! | job | [`JOB_FIELDS`] |
//! | stage attempt | [`STAGE_FIELDS`] |
//! | executor | [`EXECUTOR_FIELDS`] |
//! | SQL execution | [`SQL_FIELDS`], and with a plan: `planDescription`, `nodes` as `{nodeId, nodeName}` |
//! | task summary | `quantiles` and every metric list, one level of metric groups |
//! | environment | `runtime`, `sparkProperties` as a map, the other sections counted |
//!
//! Every value kept is a scalar or a list of scalars. Text is stripped of control characters
//! (it is a peer's, and it reaches a terminal) and cut at [`MAX_TEXT_BYTES`] —
//! [`MAX_LONG_TEXT_BYTES`] for a failure reason or a plan, which are multi-line by nature. A
//! list of ids or numbers keeps at most [`MAX_SCALAR_LIST`] entries.
//!
//! Before any of that, the body is bounded: at most `MAX_RESPONSE_BYTES` are read (while
//! reading), and its bracket nesting is measured without recursion and refused past
//! [`MAX_JSON_DEPTH`] before `serde_json` sees it. Spark's deepest answer, a task summary, nests
//! four levels.

use anyhow::{bail, ensure, Result};
use serde_json::{json, Map, Value};

use crate::utils::sanitize;
use crate::utils::truncate::truncate_with_suffix;

/// Bracket nesting accepted in a response. Spark's own deepest is 4.
pub const MAX_JSON_DEPTH: usize = 32;
/// A text field, single-line.
pub const MAX_TEXT_BYTES: usize = 2048;
/// A failure reason, an error message, a plan description.
pub const MAX_LONG_TEXT_BYTES: usize = 8192;
/// A list of ids or numbers (a job's stageIds, a stage's rddIds, a metric's quantiles).
pub const MAX_SCALAR_LIST: usize = 1000;
/// Attempts kept per application.
pub const MAX_ATTEMPTS: usize = 20;
/// Plan nodes kept per SQL execution.
pub const MAX_PLAN_NODES: usize = 200;
/// Metric lists kept in a task summary.
pub const MAX_METRICS: usize = 100;

pub const APPLICATION_FIELDS: &[&str] = &[
    "id",
    "name",
    "coresGranted",
    "maxCores",
    "coresPerExecutor",
    "memoryPerExecutorMB",
];
pub const ATTEMPT_FIELDS: &[&str] = &[
    "attemptId",
    "startTime",
    "endTime",
    "lastUpdated",
    "duration",
    "sparkUser",
    "completed",
    "appSparkVersion",
];
pub const JOB_FIELDS: &[&str] = &[
    "jobId",
    "name",
    "description",
    "submissionTime",
    "completionTime",
    "stageIds",
    "jobGroup",
    "jobTags",
    "status",
    "numTasks",
    "numActiveTasks",
    "numCompletedTasks",
    "numSkippedTasks",
    "numFailedTasks",
    "numKilledTasks",
    "numCompletedIndices",
    "numActiveStages",
    "numCompletedStages",
    "numSkippedStages",
    "numFailedStages",
];
pub const STAGE_FIELDS: &[&str] = &[
    "stageId",
    "attemptId",
    "status",
    "name",
    "description",
    "numTasks",
    "numActiveTasks",
    "numCompleteTasks",
    "numFailedTasks",
    "numKilledTasks",
    "numCompletedIndices",
    "submissionTime",
    "firstTaskLaunchedTime",
    "completionTime",
    "failureReason",
    "executorDeserializeTime",
    "executorRunTime",
    "executorCpuTime",
    "resultSize",
    "jvmGcTime",
    "peakExecutionMemory",
    "inputBytes",
    "inputRecords",
    "outputBytes",
    "outputRecords",
    "shuffleReadBytes",
    "shuffleReadRecords",
    "shuffleWriteBytes",
    "shuffleWriteRecords",
    "shuffleFetchWaitTime",
    "shuffleWriteTime",
    "memoryBytesSpilled",
    "diskBytesSpilled",
    "schedulingPool",
    "rddIds",
    "resourceProfileId",
];
pub const EXECUTOR_FIELDS: &[&str] = &[
    "id",
    "hostPort",
    "isActive",
    "rddBlocks",
    "memoryUsed",
    "diskUsed",
    "totalCores",
    "maxTasks",
    "activeTasks",
    "failedTasks",
    "completedTasks",
    "totalTasks",
    "totalDuration",
    "totalGCTime",
    "totalInputBytes",
    "totalShuffleRead",
    "totalShuffleWrite",
    "isExcluded",
    "maxMemory",
    "addTime",
    "removeTime",
    "removeReason",
    "resourceProfileId",
];
pub const SQL_FIELDS: &[&str] = &[
    "id",
    "status",
    "description",
    "submissionTime",
    "duration",
    "runningJobIds",
    "successJobIds",
    "failedJobIds",
    "queryId",
    "errorMessage",
    "rootExecutionId",
];

/// Fields whose text is multi-line by nature and gets the longer bound.
const LONG_TEXT_FIELDS: &[&str] = &[
    "failureReason",
    "errorMessage",
    "planDescription",
    "removeReason",
];

/// Which resource a response is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resource {
    Applications,
    Jobs,
    Stages,
    TaskSummary,
    Executors,
    Environment,
    Sql,
    Version,
}

impl Resource {
    pub fn of(operation: &str) -> Option<Resource> {
        Some(match operation {
            "list_applications" | "get_application" => Resource::Applications,
            "list_jobs" | "get_job" => Resource::Jobs,
            "list_stages" | "get_stage" => Resource::Stages,
            "get_task_summary" => Resource::TaskSummary,
            "list_executors" => Resource::Executors,
            "get_environment" => Resource::Environment,
            "list_sql_executions" | "get_sql_execution" => Resource::Sql,
            "get_version" => Resource::Version,
            _ => return None,
        })
    }
}

/// The deepest bracket nesting in a JSON text, outside its strings. Iterative, so a hostile
/// body cannot exhaust the stack measuring it.
pub fn json_depth(bytes: &[u8]) -> usize {
    let (mut depth, mut max, mut in_string, mut escaped) = (0usize, 0usize, false, false);
    for &b in bytes {
        if in_string {
            match (escaped, b) {
                (true, _) => escaped = false,
                (false, b'\\') => escaped = true,
                (false, b'"') => in_string = false,
                _ => {}
            }
            continue;
        }
        match b {
            b'"' => in_string = true,
            b'[' | b'{' => {
                depth += 1;
                max = max.max(depth);
            }
            b']' | b'}' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    max
}

/// Parse a body, refusing one that nests deeper than [`MAX_JSON_DEPTH`] before parsing it.
pub fn parse(body: &[u8]) -> Result<Value> {
    let depth = json_depth(body);
    ensure!(
        depth <= MAX_JSON_DEPTH,
        "the response nests {depth} levels deep; at most {MAX_JSON_DEPTH} are read (Spark's own \
         answers nest at most 4)"
    );
    serde_json::from_slice(body).map_err(|e| anyhow::anyhow!("the response is not JSON: {e}"))
}

/// A peer's text, made safe to show and bounded.
pub fn text(s: &str, long: bool) -> String {
    let clean = if long {
        sanitize::multiline(s)
    } else {
        sanitize::line_field(s)
    };
    truncate_with_suffix(
        &clean,
        if long {
            MAX_LONG_TEXT_BYTES
        } else {
            MAX_TEXT_BYTES
        },
        "...",
    )
}

/// A scalar or a list of scalars, bounded; anything else is dropped (`None`).
fn scalar(key: &str, v: &Value) -> Option<Value> {
    match v {
        Value::Null | Value::Bool(_) | Value::Number(_) => Some(v.clone()),
        Value::String(s) => Some(Value::String(text(s, LONG_TEXT_FIELDS.contains(&key)))),
        Value::Array(items) => Some(Value::Array(
            items
                .iter()
                .filter(|x| !matches!(x, Value::Array(_) | Value::Object(_)))
                .take(MAX_SCALAR_LIST)
                .map(|x| match x {
                    Value::String(s) => Value::String(text(s, false)),
                    other => other.clone(),
                })
                .collect(),
        )),
        Value::Object(_) => None,
    }
}

/// `fields` of `entry`, each a scalar or a list of scalars.
pub fn project(entry: &Value, fields: &[&str]) -> Value {
    let mut out = Map::new();
    if let Some(obj) = entry.as_object() {
        for key in fields {
            if let Some(v) = obj.get(*key).and_then(|v| scalar(key, v)) {
                out.insert((*key).to_string(), v);
            }
        }
    }
    Value::Object(out)
}

fn application(entry: &Value) -> Value {
    let mut out = project(entry, APPLICATION_FIELDS);
    let attempts: Vec<Value> = entry
        .get("attempts")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .take(MAX_ATTEMPTS)
                .map(|x| project(x, ATTEMPT_FIELDS))
                .collect()
        })
        .unwrap_or_default();
    out["attempts"] = Value::Array(attempts);
    out
}

fn sql_execution(entry: &Value, with_plan: bool) -> Value {
    let mut out = project(entry, SQL_FIELDS);
    if with_plan {
        if let Some(plan) = entry.get("planDescription").and_then(Value::as_str) {
            out["planDescription"] = json!(text(plan, true));
        }
        let nodes = entry.get("nodes").and_then(Value::as_array);
        out["nodes"] = Value::Array(
            nodes
                .map(|n| {
                    n.iter()
                        .take(MAX_PLAN_NODES)
                        .map(|x| project(x, &["nodeId", "nodeName"]))
                        .collect()
                })
                .unwrap_or_default(),
        );
        out["node_count"] = json!(nodes.map(Vec::len).unwrap_or(0));
    }
    out
}

/// The entries of a list-or-one response, each required to be an object.
fn entries<'a>(value: &'a Value, what: &str) -> Result<&'a [Value]> {
    match value {
        Value::Array(items) => {
            ensure!(
                items.iter().all(Value::is_object),
                "Spark answers {what} as an array of objects; this array holds something else"
            );
            Ok(items.as_slice())
        }
        Value::Object(_) => Ok(std::slice::from_ref(value)),
        _ => bail!("Spark answers {what} as a JSON array or object; this is neither"),
    }
}

/// The first `max_items` of `items`, each through `f`, with `count`/`total`/`truncated` set.
fn take(
    out: &mut Map<String, Value>,
    key: &str,
    items: &[Value],
    max_items: usize,
    f: impl Fn(&Value) -> Value,
) {
    let total = items.len();
    let kept: Vec<Value> = items.iter().take(max_items).map(f).collect();
    out.insert("count".into(), json!(kept.len()));
    out.insert("total".into(), json!(total));
    out.insert("truncated".into(), json!(total > max_items));
    out.insert(key.into(), Value::Array(kept));
}

/// The event payload for `resource`, on top of the validated request's `context`.
pub fn decode(
    resource: Resource,
    operation: &str,
    value: &Value,
    max_items: usize,
    context: &Map<String, Value>,
) -> Result<Value> {
    let mut out = context.clone();
    out.insert("operation".into(), json!(operation));
    match resource {
        Resource::Applications => {
            let items = entries(value, "applications")?;
            take(&mut out, "applications", items, max_items, application);
        }
        Resource::Jobs => {
            let items = entries(value, "jobs")?;
            take(&mut out, "jobs", items, max_items, |x| {
                project(x, JOB_FIELDS)
            });
        }
        Resource::Stages => {
            let items = entries(value, "stages")?;
            take(&mut out, "stages", items, max_items, |x| {
                project(x, STAGE_FIELDS)
            });
        }
        Resource::Executors => {
            let items = entries(value, "executors")?;
            take(&mut out, "executors", items, max_items, |x| {
                project(x, EXECUTOR_FIELDS)
            });
        }
        Resource::Sql => {
            let with_plan = operation == "get_sql_execution";
            let items = entries(value, "SQL executions")?;
            take(&mut out, "executions", items, max_items, |x| {
                sql_execution(x, with_plan)
            });
        }
        Resource::TaskSummary => {
            let obj = value
                .as_object()
                .ok_or_else(|| anyhow::anyhow!("Spark answers a task summary as an object"))?;
            let quantiles = obj
                .get("quantiles")
                .and_then(|q| scalar("quantiles", q))
                .ok_or_else(|| anyhow::anyhow!("the task summary carries no quantiles"))?;
            let mut metrics = Map::new();
            for (key, v) in obj.iter().filter(|(k, _)| k.as_str() != "quantiles") {
                if metrics.len() >= MAX_METRICS {
                    break;
                }
                match v {
                    Value::Array(_) => {
                        if let Some(list) = scalar(key, v) {
                            metrics.insert(key.clone(), list);
                        }
                    }
                    // One level of grouping (inputMetrics, shuffleReadMetrics, ...); a group
                    // nested inside a group is not read.
                    Value::Object(group) => {
                        let mut inner = Map::new();
                        for (k, list) in group.iter().take(MAX_METRICS) {
                            if let Value::Array(_) = list {
                                if let Some(list) = scalar(k, list) {
                                    inner.insert(k.clone(), list);
                                }
                            }
                        }
                        metrics.insert(key.clone(), Value::Object(inner));
                    }
                    _ => {}
                }
            }
            let n = metrics.len();
            out.insert("quantiles".into(), quantiles);
            out.insert("metrics".into(), Value::Object(metrics));
            out.insert("count".into(), json!(n));
            out.insert("total".into(), json!(n));
            out.insert("truncated".into(), json!(false));
        }
        Resource::Environment => {
            let obj = value
                .as_object()
                .ok_or_else(|| anyhow::anyhow!("Spark answers an environment as an object"))?;
            let runtime = obj
                .get("runtime")
                .map(|r| project(r, &["javaVersion", "javaHome", "scalaVersion"]))
                .unwrap_or_else(|| json!({}));
            let props = obj
                .get("sparkProperties")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            let total = props.len();
            let mut map = Map::new();
            for pair in props.iter() {
                if map.len() >= max_items {
                    break;
                }
                if let (Some(k), Some(v)) = (
                    pair.get(0).and_then(Value::as_str),
                    pair.get(1).and_then(Value::as_str),
                ) {
                    map.insert(text(k, false), json!(text(v, false)));
                }
            }
            let count_of = |key: &str| obj.get(key).and_then(Value::as_array).map_or(0, Vec::len);
            out.insert("runtime".into(), runtime);
            out.insert("count".into(), json!(map.len()));
            out.insert("total".into(), json!(total));
            out.insert("truncated".into(), json!(total > map.len()));
            out.insert("spark_properties".into(), Value::Object(map));
            out.insert(
                "system_property_count".into(),
                json!(count_of("systemProperties")),
            );
            out.insert(
                "hadoop_property_count".into(),
                json!(count_of("hadoopProperties")),
            );
            out.insert(
                "classpath_entry_count".into(),
                json!(count_of("classpathEntries")),
            );
        }
        Resource::Version => {
            let v = value
                .get("spark")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow::anyhow!("the version answer carries no \"spark\" field"))?;
            out.insert("spark_version".into(), json!(text(v, false)));
        }
    }
    Ok(Value::Object(out))
}
