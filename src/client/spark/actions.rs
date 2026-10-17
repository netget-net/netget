//! Spark client: what the model is told and what it may do.
//!
//! Every action names a resource of Spark's monitoring REST API by structured ids — an
//! application id, a job id, a stage id and attempt, a SQL execution id — and [`request`] turns
//! it into an [`ApiCall`]: path segments under `/api/v1/` and a query string, each id checked
//! against the shape Spark gives it. The model never writes a URL or a path; the host is fixed
//! when the client connects.

use std::sync::LazyLock;

use anyhow::{bail, ensure, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use crate::llm::actions::client_trait::{Client, ClientActionResult};
use crate::llm::actions::protocol_trait::Protocol;
use crate::llm::actions::{ActionDefinition, Parameter, ParameterDefinition, StartupExamples};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::{ConnectContext, EventType};
use crate::state::app_state::AppState;

pub struct SparkClientProtocol;

impl SparkClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

impl Default for SparkClientProtocol {
    fn default() -> Self {
        Self::new()
    }
}

fn p(name: &str, type_hint: &str, description: &str, required: bool) -> Parameter {
    Parameter {
        name: name.to_string(),
        type_hint: type_hint.to_string(),
        description: description.to_string(),
        required,
    }
}

fn action(
    name: &str,
    description: &str,
    parameters: Vec<Parameter>,
    example: Value,
) -> ActionDefinition {
    ActionDefinition {
        name: name.to_string(),
        description: description.to_string(),
        parameters,
        example,
        log_template: Some(LogTemplate::new().with_info(format!("-> Spark {name} {{app_id}}"))),
    }
}

fn app_id_param() -> Parameter {
    p(
        "app_id",
        "string",
        "The application id exactly as Spark reports it (local-1792044029340, \
         app-20261015060028-0000, application_1700000000000_0001)",
        true,
    )
}

fn app_attempt_param() -> Parameter {
    p(
        "app_attempt_id",
        "string",
        "The application attempt, only for an application the History Server lists with an \
         attemptId (YARN cluster mode); omit it otherwise",
        false,
    )
}

fn max_items_param() -> Parameter {
    p(
        "max_items",
        "number",
        &format!(
            "How many entries to deliver at most (default {}, at most {}); truncated says \
             whether more existed",
            super::DEFAULT_MAX_ITEMS,
            super::MAX_ITEMS_LIMIT
        ),
        false,
    )
}

pub fn actions() -> Vec<ActionDefinition> {
    vec![
        action(
            "list_applications",
            "List the applications the server knows (GET /api/v1/applications). A live driver UI \
             knows its own application; a History Server every one in its event log directory. \
             Answered by spark_applications.",
            vec![
                p("status", "string", "completed or running", false),
                p("min_date", "string", "Started on or after: 2026-10-15 or 2026-10-15T06:00:00.000GMT", false),
                p("max_date", "string", "Started on or before, same format", false),
                p("min_end_date", "string", "Ended on or after, same format", false),
                p("max_end_date", "string", "Ended on or before, same format", false),
                p("limit", "number", "How many applications the server returns at most (1..=1000)", false),
                max_items_param(),
            ],
            json!({"type": "list_applications", "status": "completed", "limit": 20}),
        ),
        action(
            "get_application",
            "One application with its attempts (GET /api/v1/applications/{app_id}). Answered by spark_applications.",
            vec![app_id_param()],
            json!({"type": "get_application", "app_id": "local-1792044029340"}),
        ),
        action(
            "list_jobs",
            "An application's jobs, newest first (GET .../{app_id}/jobs). Answered by spark_jobs.",
            vec![
                app_id_param(),
                app_attempt_param(),
                p("status", "string|array", "Only jobs in these states (one, or a list): running, succeeded, failed, unknown", false),
                max_items_param(),
            ],
            json!({"type": "list_jobs", "app_id": "local-1792044029340", "status": "failed"}),
        ),
        action(
            "get_job",
            "One job (GET .../{app_id}/jobs/{job_id}). Answered by spark_jobs.",
            vec![app_id_param(), app_attempt_param(), p("job_id", "number", "The jobId, as list_jobs reports it", true)],
            json!({"type": "get_job", "app_id": "local-1792044029340", "job_id": 1}),
        ),
        action(
            "list_stages",
            "An application's stages, every attempt of each (GET .../{app_id}/stages). Answered by spark_stages.",
            vec![
                app_id_param(),
                app_attempt_param(),
                p("status", "string|array", "Only stages in these states (one, or a list): active, complete, pending, failed, skipped", false),
                max_items_param(),
            ],
            json!({"type": "list_stages", "app_id": "local-1792044029340", "status": "failed"}),
        ),
        action(
            "get_stage",
            "One stage: every attempt of it, or the one attempt named (GET .../{app_id}/stages/{stage_id}[/{stage_attempt_id}]). Task lists are never fetched. Answered by spark_stages.",
            vec![
                app_id_param(),
                app_attempt_param(),
                p("stage_id", "number", "The stageId, as list_jobs (stageIds) or list_stages reports it", true),
                p("stage_attempt_id", "number", "One attempt of the stage (0 is the first)", false),
            ],
            json!({"type": "get_stage", "app_id": "local-1792044029340", "stage_id": 2, "stage_attempt_id": 0}),
        ),
        action(
            "get_task_summary",
            "The distribution of task metrics in one stage attempt at the quantiles asked for (GET .../stages/{stage_id}/{stage_attempt_id}/taskSummary). Answered by spark_task_summary.",
            vec![
                app_id_param(),
                app_attempt_param(),
                p("stage_id", "number", "The stageId, as list_jobs (stageIds) or list_stages reports it", true),
                p("stage_attempt_id", "number", "The stage attempt (0 is the first)", true),
                p("quantiles", "array", "Up to 10 numbers in 0..=1 (default 0.05, 0.25, 0.5, 0.75, 0.95)", false),
            ],
            json!({"type": "get_task_summary", "app_id": "local-1792044029340", "stage_id": 2, "stage_attempt_id": 0, "quantiles": [0.5, 0.95]}),
        ),
        action(
            "list_executors",
            "An application's executors, the driver included (GET .../{app_id}/executors, or .../allexecutors with include_dead). Answered by spark_executors.",
            vec![
                app_id_param(),
                app_attempt_param(),
                p("include_dead", "boolean", "Also executors that have been removed", false),
                max_items_param(),
            ],
            json!({"type": "list_executors", "app_id": "local-1792044029340"}),
        ),
        action(
            "get_environment",
            "An application's runtime (Java, Scala) and its Spark properties, as Spark reports them with secrets already redacted (GET .../{app_id}/environment). Answered by spark_environment.",
            vec![app_id_param(), app_attempt_param(), max_items_param()],
            json!({"type": "get_environment", "app_id": "local-1792044029340"}),
        ),
        action(
            "list_sql_executions",
            "An application's SQL/DataFrame executions with the jobs each ran (GET .../{app_id}/sql). Answered by spark_sql_executions.",
            vec![
                app_id_param(),
                app_attempt_param(),
                p("offset", "number", "Skip this many executions", false),
                max_items_param(),
            ],
            json!({"type": "list_sql_executions", "app_id": "local-1792044029340"}),
        ),
        action(
            "get_sql_execution",
            "One SQL execution with its physical plan text and plan nodes (GET .../{app_id}/sql/{execution_id}). Answered by spark_sql_executions.",
            vec![
                app_id_param(),
                app_attempt_param(),
                p("execution_id", "number", "The SQL execution id", true),
            ],
            json!({"type": "get_sql_execution", "app_id": "local-1792044029340", "execution_id": 0}),
        ),
        action(
            "get_version",
            "The Spark version of the server (GET /api/v1/version). Answered by spark_version.",
            vec![],
            json!({"type": "get_version"}),
        ),
        action(
            "disconnect",
            "Stop this client. The REST API keeps no session, so nothing is sent.",
            vec![],
            json!({"type": "disconnect"}),
        ),
    ]
}

fn ev(id: &str, description: &str, params: Vec<Parameter>) -> EventType {
    EventType::new(
        id,
        description,
        json!({"type": "list_jobs", "app_id": "local-1792044029340"}),
    )
    .with_parameters(params)
    .with_actions(actions())
}

fn common(mut params: Vec<Parameter>) -> Vec<Parameter> {
    params.insert(
        0,
        p(
            "operation",
            "string",
            "The action this answers, e.g. list_jobs or get_job",
            true,
        ),
    );
    params.extend([
        p("count", "number", "How many entries are delivered", true),
        p(
            "total",
            "number",
            "How many entries the server returned",
            true,
        ),
        p(
            "truncated",
            "boolean",
            "True when the server returned more than max_items",
            true,
        ),
    ]);
    params
}

fn app_param() -> Parameter {
    p(
        "app_id",
        "string",
        "The application the entries belong to",
        true,
    )
}

pub static CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    ev(
        "spark_connected",
        "The client reached a Spark monitoring REST API (a live driver UI or a History Server) and read its version; nothing else has been asked.",
        vec![
            p("endpoint", "string", "The base URL every request goes to", true),
            p("spark_version", "string", "The version the server reported (GET /api/v1/version)", true),
        ],
    )
});

pub static APPLICATIONS_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    ev(
        "spark_applications",
        "Applications, from list_applications or get_application.",
        common(vec![
            p("applications", "array", "One {id, name, attempts: [{attemptId, startTime, endTime, lastUpdated, duration, sparkUser, completed, appSparkVersion}], coresGranted, maxCores, memoryPerExecutorMB} per application", true),
            p("filters", "object", "The filters list_applications sent", false),
        ]),
    )
});

pub static JOBS_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    ev(
        "spark_jobs",
        "Jobs, from list_jobs or get_job.",
        common(vec![
            app_param(),
            p("jobs", "array", "One {jobId, name, description, status (RUNNING/SUCCEEDED/FAILED/UNKNOWN), stageIds, jobGroup, submissionTime, completionTime, numTasks, numCompletedTasks, numFailedTasks, numSkippedTasks, numKilledTasks, numActiveStages, numCompletedStages, numSkippedStages, numFailedStages} per job", true),
        ]),
    )
});

pub static STAGES_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    ev(
        "spark_stages",
        "Stage attempts, from list_stages or get_stage.",
        common(vec![
            app_param(),
            p("stages", "array", "One {stageId, attemptId, status (ACTIVE/COMPLETE/PENDING/FAILED/SKIPPED), name, description, numTasks, numCompleteTasks, numFailedTasks, numKilledTasks, submissionTime, completionTime, failureReason, executorRunTime, inputBytes, outputBytes, shuffleReadBytes, shuffleWriteBytes, memoryBytesSpilled, diskBytesSpilled, rddIds, ...} per stage attempt", true),
        ]),
    )
});

pub static TASK_SUMMARY_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    ev(
        "spark_task_summary",
        "The task-metric distribution of one stage attempt, from get_task_summary.",
        common(vec![
            app_param(),
            p("stage_id", "number", "The stage the summary describes", true),
            p("stage_attempt_id", "number", "The stage attempt", true),
            p("quantiles", "array", "The quantiles every metric list is given at, in order", true),
            p("metrics", "object", "Metric name -> one number per quantile (duration, executorRunTime, jvmGcTime, resultSize, schedulerDelay, peakExecutionMemory, memoryBytesSpilled, diskBytesSpilled, ...); inputMetrics/outputMetrics/shuffleReadMetrics/shuffleWriteMetrics are objects of the same", true),
        ]),
    )
});

pub static EXECUTORS_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    ev(
        "spark_executors",
        "Executors, from list_executors.",
        common(vec![
            app_param(),
            p("executors", "array", "One {id (\"driver\" or a number as text), hostPort, isActive, totalCores, maxTasks, activeTasks, failedTasks, completedTasks, totalTasks, totalDuration, totalGCTime, totalInputBytes, totalShuffleRead, totalShuffleWrite, memoryUsed, maxMemory, diskUsed, rddBlocks, addTime, removeTime, removeReason} per executor", true),
        ]),
    )
});

pub static ENVIRONMENT_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    ev(
        "spark_environment",
        "An application's environment, from get_environment.",
        common(vec![
            app_param(),
            p("runtime", "object", "{javaVersion, javaHome, scalaVersion}", true),
            p("spark_properties", "object", "Spark property name -> value, as Spark reports them (it redacts secrets itself); count/total/truncated describe this map", true),
            p("system_property_count", "number", "How many JVM system properties Spark reported (not delivered)", true),
            p("hadoop_property_count", "number", "How many Hadoop properties Spark reported (not delivered)", true),
            p("classpath_entry_count", "number", "How many classpath entries Spark reported (not delivered)", true),
        ]),
    )
});

pub static SQL_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    ev(
        "spark_sql_executions",
        "SQL/DataFrame executions, from list_sql_executions or get_sql_execution.",
        common(vec![
            app_param(),
            p("executions", "array", "One {id, status (RUNNING/COMPLETED/FAILED), description, submissionTime, duration, runningJobIds, successJobIds, failedJobIds, queryId, errorMessage} per execution; get_sql_execution adds planDescription and nodes [{nodeId, nodeName}]", true),
        ]),
    )
});

pub static VERSION_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    ev(
        "spark_version",
        "The server's Spark version, from get_version.",
        vec![
            p(
                "operation",
                "string",
                "The action this answers: get_version",
                true,
            ),
            p(
                "spark_version",
                "string",
                "The version the server reported",
                true,
            ),
        ],
    )
});

pub static ERROR_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    ev(
        "spark_error",
        "A request failed: the server answered with an error status (404 unknown app or job, 400 bad filter), or the answer could not be read (not JSON, too large, too deep, not the shape Spark sends). The client is still connected.",
        vec![
            p("operation", "string", "The action that failed", true),
            p("app_id", "string", "The application it asked about, if any", false),
            p("http_status", "number", "The HTTP status of the response, when there was one", false),
            p("message", "string", "What went wrong, in the server's words (its plain-text error body) or this client's", true),
        ],
    )
});

/// One request to the monitoring API, built from a validated action. The URL is assembled from
/// `segments` (each one a path segment under `/api/v1/`, percent-encoded as one) and `query`
/// on the client's fixed base URL, and nowhere else.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ApiCall {
    /// The action this came from.
    pub operation: String,
    /// Path segments after `/api/v1/`.
    pub segments: Vec<String>,
    /// Query parameters, in order (a repeated key is a list, as Spark reads `status`).
    pub query: Vec<(String, String)>,
    /// Entries delivered at most.
    pub max_items: usize,
    /// The validated parameters, echoed into the event (app_id, job_id, filters, ...).
    pub context: Map<String, Value>,
}

/// Validate a Spark application id: the characters Spark, YARN and Kubernetes put in one.
pub fn app_id(raw: &str) -> Result<String> {
    let id = raw.trim();
    ensure!(!id.is_empty(), "app_id is empty");
    ensure!(
        id.len() <= super::MAX_ID_CHARS,
        "app_id is {} characters; at most {} are accepted",
        id.len(),
        super::MAX_ID_CHARS
    );
    ensure!(
        id.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')),
        "app_id {id:?}: only letters, digits, '-', '_' and '.' are accepted (Spark ids look \
         like local-1792044029340 or application_1700000000000_0001)"
    );
    ensure!(!id.starts_with('.'), "app_id {id:?} may not start with '.'");
    Ok(id.to_string())
}

fn attempt_id(raw: &str) -> Result<String> {
    let id = raw.trim();
    ensure!(
        !id.is_empty()
            && id.len() <= 32
            && !id.starts_with('.')
            && id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')),
        "app_attempt_id {id:?}: at most 32 letters, digits, '-', '_' and '.'"
    );
    Ok(id.to_string())
}

/// A non-negative id Spark keeps as an int or a long: a JSON number, or digits as text.
fn numeric_id(v: &Value, name: &str) -> Result<u64> {
    let n = match v {
        Value::Number(n) => n
            .as_u64()
            .with_context(|| format!("{name} is a whole number >= 0, not {n}"))?,
        Value::String(s)
            if !s.is_empty() && s.len() <= 19 && s.bytes().all(|b| b.is_ascii_digit()) =>
        {
            s.parse::<u64>()?
        }
        other => bail!("{name} is a whole number >= 0, not {other}"),
    };
    ensure!(
        n <= i64::MAX as u64,
        "{name} {n} is larger than any id Spark issues"
    );
    Ok(n)
}

fn get<'a>(v: &'a Value, key: &str) -> Option<&'a Value> {
    v.get(key).filter(|x| !x.is_null())
}

fn required_id(v: &Value, key: &str) -> Result<u64> {
    numeric_id(
        get(v, key).with_context(|| format!("{} needs {key}", op_name(v)))?,
        key,
    )
}

fn op_name(v: &Value) -> &str {
    v.get("type")
        .and_then(Value::as_str)
        .unwrap_or("the action")
}

/// A date filter in one of the two forms Spark's `SimpleDateParam` reads:
/// `yyyy-MM-dd` or `yyyy-MM-dd'T'HH:mm:ss.SSSz` (e.g. `2026-10-15T06:00:00.000GMT`).
fn date_filter(v: &Value, key: &str) -> Result<String> {
    let s = v
        .as_str()
        .with_context(|| format!("{key} is a date as text"))?
        .trim();
    let b = s.as_bytes();
    let date_ok = b.len() >= 10
        && b[..10].iter().enumerate().all(|(i, c)| match i {
            4 | 7 => *c == b'-',
            _ => c.is_ascii_digit(),
        });
    let rest_ok = b.len() == 10
        || (b.len() >= 23
            && b.len() <= 32
            && b[10] == b'T'
            && b[11..23].iter().enumerate().all(|(i, c)| match i {
                2 | 5 => *c == b':',
                8 => *c == b'.',
                _ => c.is_ascii_digit(),
            })
            && b[23..]
                .iter()
                .all(|c| c.is_ascii_alphanumeric() || *c == b'+' || *c == b'-'));
    ensure!(
        date_ok && rest_ok,
        "{key} {s:?}: Spark reads 2026-10-15 or 2026-10-15T06:00:00.000GMT"
    );
    Ok(s.to_string())
}

/// One status or a list of them, each one of `allowed`.
fn statuses(v: &Value, allowed: &[&str]) -> Result<Vec<String>> {
    let list: Vec<&Value> = match v {
        Value::Array(items) => items.iter().collect(),
        other => vec![other],
    };
    ensure!(
        !list.is_empty() && list.len() <= allowed.len(),
        "status: one to {} of {}",
        allowed.len(),
        allowed.join(", ")
    );
    let mut out = Vec::new();
    for item in list {
        let s = item
            .as_str()
            .context("status is text")?
            .trim()
            .to_ascii_lowercase();
        ensure!(
            allowed.contains(&s.as_str()),
            "status {s:?} is not one of {}",
            allowed.join(", ")
        );
        if !out.contains(&s) {
            out.push(s);
        }
    }
    Ok(out)
}

fn max_items(v: &Value) -> Result<usize> {
    let n = match get(v, "max_items") {
        None => super::DEFAULT_MAX_ITEMS as u64,
        Some(n) => n.as_u64().context("max_items is a whole number")?,
    };
    ensure!(
        (1..=super::MAX_ITEMS_LIMIT as u64).contains(&n),
        "max_items is 1..={}",
        super::MAX_ITEMS_LIMIT
    );
    Ok(n as usize)
}

/// `["applications", app_id]` plus `app_attempt_id` when given, and the context they echo.
fn app_prefix(v: &Value, ctx: &mut Map<String, Value>) -> Result<Vec<String>> {
    let id = app_id(
        get(v, "app_id")
            .and_then(Value::as_str)
            .with_context(|| format!("{} needs app_id (text)", op_name(v)))?,
    )?;
    ctx.insert("app_id".into(), json!(id));
    let mut segments = vec!["applications".to_string(), id];
    if let Some(attempt) = get(v, "app_attempt_id") {
        let attempt = attempt_id(&match attempt {
            Value::String(s) => s.clone(),
            Value::Number(n) => n.to_string(),
            other => bail!("app_attempt_id is text, not {other}"),
        })?;
        ctx.insert("app_attempt_id".into(), json!(attempt));
        segments.push(attempt);
    }
    Ok(segments)
}

/// Validate an action and return the request it becomes.
pub fn request(v: &Value) -> Result<ApiCall> {
    let kind = v
        .get("type")
        .and_then(Value::as_str)
        .context("an action needs a type")?;
    let mut context = Map::new();
    let mut query: Vec<(String, String)> = Vec::new();
    let mut items = super::DEFAULT_MAX_ITEMS;
    let segments: Vec<String> = match kind {
        "list_applications" => {
            let mut filters = Map::new();
            if let Some(s) = get(v, "status") {
                let s = statuses(s, &["completed", "running"])?;
                ensure!(s.len() == 1, "list_applications takes one status");
                filters.insert("status".into(), json!(s[0]));
                query.push(("status".into(), s[0].clone()));
            }
            for (key, param) in [
                ("min_date", "minDate"),
                ("max_date", "maxDate"),
                ("min_end_date", "minEndDate"),
                ("max_end_date", "maxEndDate"),
            ] {
                if let Some(d) = get(v, key) {
                    let d = date_filter(d, key)?;
                    filters.insert(key.into(), json!(d));
                    query.push((param.into(), d));
                }
            }
            if let Some(limit) = get(v, "limit") {
                let limit = limit.as_u64().context("limit is a whole number")?;
                ensure!((1..=1000).contains(&limit), "limit is 1..=1000");
                filters.insert("limit".into(), json!(limit));
                query.push(("limit".into(), limit.to_string()));
            }
            context.insert("filters".into(), Value::Object(filters));
            items = max_items(v)?;
            vec!["applications".into()]
        }
        "get_application" => {
            let id = app_id(
                get(v, "app_id")
                    .and_then(Value::as_str)
                    .context("get_application needs app_id (text)")?,
            )?;
            context.insert("app_id".into(), json!(id));
            vec!["applications".into(), id]
        }
        "list_jobs" => {
            let mut s = app_prefix(v, &mut context)?;
            if let Some(st) = get(v, "status") {
                let st = statuses(st, &["running", "succeeded", "failed", "unknown"])?;
                context.insert("status".into(), json!(st));
                query.extend(st.into_iter().map(|x| ("status".to_string(), x)));
            }
            items = max_items(v)?;
            s.push("jobs".into());
            s
        }
        "get_job" => {
            let mut s = app_prefix(v, &mut context)?;
            let job = required_id(v, "job_id")?;
            context.insert("job_id".into(), json!(job));
            s.extend(["jobs".to_string(), job.to_string()]);
            s
        }
        "list_stages" => {
            let mut s = app_prefix(v, &mut context)?;
            if let Some(st) = get(v, "status") {
                let st = statuses(st, &["active", "complete", "pending", "failed", "skipped"])?;
                context.insert("status".into(), json!(st));
                query.extend(st.into_iter().map(|x| ("status".to_string(), x)));
            }
            // Task lists are never asked for: one stage's can be megabytes.
            query.push(("details".into(), "false".into()));
            items = max_items(v)?;
            s.push("stages".into());
            s
        }
        "get_stage" => {
            let mut s = app_prefix(v, &mut context)?;
            let stage = required_id(v, "stage_id")?;
            context.insert("stage_id".into(), json!(stage));
            s.extend(["stages".to_string(), stage.to_string()]);
            if let Some(a) = get(v, "stage_attempt_id") {
                let a = numeric_id(a, "stage_attempt_id")?;
                context.insert("stage_attempt_id".into(), json!(a));
                s.push(a.to_string());
            }
            query.push(("details".into(), "false".into()));
            s
        }
        "get_task_summary" => {
            let mut s = app_prefix(v, &mut context)?;
            let stage = required_id(v, "stage_id")?;
            let attempt = required_id(v, "stage_attempt_id")?;
            context.insert("stage_id".into(), json!(stage));
            context.insert("stage_attempt_id".into(), json!(attempt));
            let quantiles: Vec<f64> = match get(v, "quantiles") {
                None => vec![0.05, 0.25, 0.5, 0.75, 0.95],
                Some(Value::Array(q)) => q
                    .iter()
                    .map(|x| x.as_f64().context("quantiles are numbers"))
                    .collect::<Result<_>>()?,
                Some(other) => bail!("quantiles is an array of numbers, not {other}"),
            };
            ensure!(
                !quantiles.is_empty() && quantiles.len() <= super::MAX_QUANTILES,
                "quantiles: 1 to {} numbers",
                super::MAX_QUANTILES
            );
            ensure!(
                quantiles.iter().all(|q| (0.0..=1.0).contains(q)),
                "quantiles are in 0..=1"
            );
            query.push((
                "quantiles".into(),
                quantiles
                    .iter()
                    .map(|q| q.to_string())
                    .collect::<Vec<_>>()
                    .join(","),
            ));
            s.extend([
                "stages".to_string(),
                stage.to_string(),
                attempt.to_string(),
                "taskSummary".to_string(),
            ]);
            s
        }
        "list_executors" => {
            let mut s = app_prefix(v, &mut context)?;
            let dead = match get(v, "include_dead") {
                None => false,
                Some(b) => b.as_bool().context("include_dead is true or false")?,
            };
            context.insert("include_dead".into(), json!(dead));
            items = max_items(v)?;
            s.push(if dead { "allexecutors" } else { "executors" }.into());
            s
        }
        "get_environment" => {
            let mut s = app_prefix(v, &mut context)?;
            items = max_items(v)?;
            s.push("environment".into());
            s
        }
        "list_sql_executions" => {
            let mut s = app_prefix(v, &mut context)?;
            items = max_items(v)?;
            let offset = match get(v, "offset") {
                None => 0,
                Some(o) => o.as_u64().context("offset is a whole number")?,
            };
            ensure!(offset <= i32::MAX as u64, "offset is too large");
            context.insert("offset".into(), json!(offset));
            // The plan text and graph are per-execution detail; get_sql_execution reads them.
            query.extend([
                ("details".to_string(), "false".to_string()),
                ("planDescription".to_string(), "false".to_string()),
                ("offset".to_string(), offset.to_string()),
                ("length".to_string(), items.to_string()),
            ]);
            s.push("sql".into());
            s
        }
        "get_sql_execution" => {
            let mut s = app_prefix(v, &mut context)?;
            let id = required_id(v, "execution_id")?;
            context.insert("execution_id".into(), json!(id));
            query.extend([
                ("details".to_string(), "true".to_string()),
                ("planDescription".to_string(), "true".to_string()),
            ]);
            s.extend(["sql".to_string(), id.to_string()]);
            s
        }
        "get_version" => vec!["version".into()],
        "disconnect" => Vec::new(),
        other => bail!("Unknown Spark client action: {other}"),
    };
    Ok(ApiCall {
        operation: kind.to_string(),
        segments,
        query,
        max_items: items,
        context,
    })
}

fn param(
    name: &str,
    type_hint: &str,
    description: &str,
    required: bool,
    example: Value,
    default: Option<Value>,
) -> ParameterDefinition {
    ParameterDefinition {
        name: name.into(),
        type_hint: type_hint.into(),
        description: description.into(),
        required,
        example,
        default,
    }
}

impl Protocol for SparkClientProtocol {
    fn protocol_name(&self) -> &'static str {
        "Spark"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>HTTP>SPARK"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "spark client",
            "spark history server",
            "spark rest api",
            "spark jobs",
            "spark ui",
        ]
    }
    fn description(&self) -> &'static str {
        "Apache Spark monitoring REST API client: reads applications, jobs, stages, task summaries, executors, environment and SQL executions from a live driver UI or a History Server"
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        actions()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        actions()
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            CONNECTED_EVENT.clone(),
            APPLICATIONS_EVENT.clone(),
            JOBS_EVENT.clone(),
            STAGES_EVENT.clone(),
            TASK_SUMMARY_EVENT.clone(),
            EXECUTORS_EVENT.clone(),
            ENVIRONMENT_EVENT.clone(),
            SQL_EVENT.clone(),
            VERSION_EVENT.clone(),
            ERROR_EVENT.clone(),
        ]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            param(
                "endpoint_url",
                "string",
                "The REST API's base URL, used exactly as given: http://127.0.0.1:4040 (a live driver UI) or http://127.0.0.1:18080 (a History Server), or a proxy path such as https://gateway/sparkhistory. Without it the client's remote_addr is the target (host:port means http://host:port). There is no default target",
                false,
                json!("http://127.0.0.1:18080"),
                None,
            ),
            param(
                "request_timeout_secs",
                "number",
                "Seconds one request may take (1..=600)",
                false,
                json!(30),
                Some(json!(super::REQUEST_TIMEOUT.as_secs())),
            ),
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Beta)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation("Apache Spark monitoring REST API (/api/v1) over HTTP(S), reqwest natively and the hyper transport in the browser build: GET version, applications (status/minDate/maxDate/minEndDate/maxEndDate/limit), an application, its jobs (status), a job, stages (status, details=false), a stage's attempts or one attempt (details=false), a stage attempt's taskSummary (quantiles), executors/allexecutors, environment, sql (details=false, planDescription=false, offset/length) and one SQL execution with its plan. Paths are built from validated ids, one percent-encoded segment each, on the base URL fixed at connect; redirects are not followed. Responses are bounded in size and JSON depth before parsing and projected onto a fixed set of fields per resource")
            .llm_control("Which application, job, stage, stage attempt or SQL execution to read, with which filters and how many entries; it reads the decoded entries and the server's own error text")
            .e2e_testing("tests/client/spark/real_server_test.rs runs the official Apache Spark 4.2.0 distribution (SHA-512 pinned by install_peers.sh) with the model mocked: a PySpark application with a one-stage job, a shuffled two-stage job, a DataFrame aggregation and a job that fails on purpose, read through its live driver UI (spark.ui.port) and, once it has stopped, through Spark's own History Server over the event log it wrote. Every job id, status and stage id, the stage the model picked out of a job with its task summary, the failed stage and its failure reason, the SQL execution and its jobs, the driver's task counts, the environment, the application's duration and every stage attempt (skipped ones included) are checked against what Spark itself recorded: SparkContext.statusTracker() for the live UI, the SparkListener events of the event log for the History Server. A recording TCP relay between NetGet and Spark asserts the exact request lines Spark received for the model's actions and that nothing else was sent. Spark's 404 for an unknown job, the follow-up bound and an LLM failure (Spark sees only the connect probe) run against the same peers. Fails rather than skips without NETGET_SPARK_HOME")
            .notes("Beta against the client bar: the peer is Apache Spark itself, the reference implementation, in both of the roles that serve this API (a live driver UI and the History Server); the suite fails rather than skips; each session is a real chain of reads whose later requests are built from ids the model took out of earlier answers; and that the client acts on the model's answer is asserted on the wire, from the request lines Spark received. The API is read-only, so the effect asserted is the request and Spark's answer to it; Spark keeps no request log, which is why the test relays the connection. Only Spark 4.2.0 is tested; older releases' REST API is the same documented v1 surface, and a field one of them lacks is simply absent from the projection. Not implemented: the REST submission API (/v1/submissions on a standalone master), which runs arbitrary code on a cluster and is not something a monitoring client should do on a model's say-so; task lists, RDD storage, streaming statistics, event-log download and thread dumps")
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Connect to the Spark History Server at http://127.0.0.1:18080 and tell me which jobs failed in the newest application"
    }
    fn get_startup_examples(&self) -> StartupExamples {
        let llm = json!({
            "type": "open_client",
            "protocol": "Spark",
            "remote_addr": "127.0.0.1:18080",
            "startup_params": {"request_timeout_secs": 30},
            "instruction": "Find the newest completed application and list its failed jobs"
        });
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([
            {"event_pattern": "spark_connected", "handler": {"type": "static", "actions": [
                {"type": "list_applications", "status": "completed", "limit": 5}
            ]}},
            {"event_pattern": "*", "handler": {"type": "static", "actions": []}}
        ]);
        let mut scripted = static_example.clone();
        scripted["event_handlers"][1] = json!({"event_pattern": "spark_applications", "handler": {
            "type": "script", "language": "python",
            "code": "import json,sys\ne=json.load(sys.stdin)['event']\na=[{'type':'list_jobs','app_id':x['id'],'status':'failed'} for x in e.get('applications',[])[:3]]\nprint(json.dumps({'actions':a}))"
        }});
        StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Monitoring"
    }
}

impl Client for SparkClientProtocol {
    fn connect(
        &self,
        ctx: ConnectContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::connect(ctx))
    }
    fn execute_action(&self, v: Value) -> Result<ClientActionResult> {
        let call = request(&v)?;
        if call.operation == "disconnect" {
            return Ok(ClientActionResult::Disconnect);
        }
        Ok(ClientActionResult::Custom {
            name: call.operation.clone(),
            data: serde_json::to_value(&call)?,
        })
    }
}
