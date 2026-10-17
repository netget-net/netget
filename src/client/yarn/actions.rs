//! YARN client: what the model is told and what it may do.
//!
//! Every action names a resource of the Hadoop YARN ResourceManager REST API by structured
//! values — an application id, a node id, application states, a queue, a user — and [`request`]
//! turns it into an [`ApiCall`]: path segments under `/ws/v1/cluster/`, a query string and, for
//! the one write, a fixed JSON body. Each value is checked against the shape YARN gives it. The
//! model never writes a URL, a path or a body; the host is fixed when the client connects.

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

pub struct YarnClientProtocol;

impl YarnClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

impl Default for YarnClientProtocol {
    fn default() -> Self {
        Self::new()
    }
}

/// Every application state YARN defines (`YarnApplicationState`).
pub const APP_STATES: &[&str] = &[
    "NEW",
    "NEW_SAVING",
    "SUBMITTED",
    "ACCEPTED",
    "RUNNING",
    "FINISHED",
    "FAILED",
    "KILLED",
];
/// Every final status YARN defines (`FinalApplicationStatus`).
pub const FINAL_STATUSES: &[&str] = &["UNDEFINED", "SUCCEEDED", "FAILED", "KILLED", "ENDED"];
/// Every node state YARN defines (`NodeState`).
pub const NODE_STATES: &[&str] = &[
    "NEW",
    "RUNNING",
    "UNHEALTHY",
    "DECOMMISSIONED",
    "DECOMMISSIONING",
    "LOST",
    "REBOOTED",
    "SHUTDOWN",
];

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
        log_template: Some(LogTemplate::new().with_info(format!("-> YARN {name} {{app_id}}"))),
    }
}

fn app_id_param() -> Parameter {
    p(
        "app_id",
        "string",
        "The application id exactly as YARN reports it: application_<cluster timestamp>_<sequence>, \
         e.g. application_1792047302594_0003",
        true,
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
            "get_cluster_info",
            "The ResourceManager's identity: its version, cluster id, start time, state and HA state (GET /ws/v1/cluster/info). Answered by yarn_cluster_info.",
            vec![],
            json!({"type": "get_cluster_info"}),
        ),
        action(
            "get_cluster_metrics",
            "The cluster's totals: applications by state, memory and vcores total/allocated/available, containers, nodes by state (GET /ws/v1/cluster/metrics). Answered by yarn_cluster_metrics.",
            vec![],
            json!({"type": "get_cluster_metrics"}),
        ),
        action(
            "get_scheduler",
            "The scheduler and its queues, each with capacity, used capacity and application counts (GET /ws/v1/cluster/scheduler). Answered by yarn_scheduler.",
            vec![max_items_param()],
            json!({"type": "get_scheduler"}),
        ),
        action(
            "list_applications",
            "Applications the ResourceManager knows, optionally filtered (GET /ws/v1/cluster/apps). Answered by yarn_applications.",
            vec![
                p("states", "string|array", &format!("Only applications in these states (one, or a list): {}", APP_STATES.join(", ")), false),
                p("final_status", "string", &format!("Only applications with this final status: {}", FINAL_STATUSES.join(", ")), false),
                p("queue", "string", "Only applications in this queue (default or root.default)", false),
                p("user", "string", "Only applications of this user", false),
                p("application_types", "string|array", "Only applications of these types (one, or a list): YARN, MAPREDUCE, SPARK, ...", false),
                p("limit", "number", "How many applications the server returns at most (1..=10000)", false),
                p("started_time_begin", "number", "Started at or after, epoch milliseconds", false),
                p("started_time_end", "number", "Started at or before, epoch milliseconds", false),
                p("finished_time_begin", "number", "Finished at or after, epoch milliseconds", false),
                p("finished_time_end", "number", "Finished at or before, epoch milliseconds", false),
                max_items_param(),
            ],
            json!({"type": "list_applications", "states": ["RUNNING", "ACCEPTED"], "queue": "default"}),
        ),
        action(
            "get_application",
            "One application: state, final status, progress, diagnostics, queue, resources used (GET /ws/v1/cluster/apps/{app_id}). Answered by yarn_applications.",
            vec![app_id_param()],
            json!({"type": "get_application", "app_id": "application_1792047302594_0003"}),
        ),
        action(
            "list_app_attempts",
            "An application's attempts, each with its AM container, node and state (GET /ws/v1/cluster/apps/{app_id}/appattempts). Answered by yarn_app_attempts.",
            vec![app_id_param(), max_items_param()],
            json!({"type": "list_app_attempts", "app_id": "application_1792047302594_0003"}),
        ),
        action(
            "get_app_state",
            "Just an application's state (GET /ws/v1/cluster/apps/{app_id}/state). Answered by yarn_app_state.",
            vec![app_id_param()],
            json!({"type": "get_app_state", "app_id": "application_1792047302594_0003"}),
        ),
        action(
            "get_app_queue",
            "Just the queue an application runs in (GET /ws/v1/cluster/apps/{app_id}/queue). Answered by yarn_app_queue.",
            vec![app_id_param()],
            json!({"type": "get_app_queue", "app_id": "application_1792047302594_0003"}),
        ),
        action(
            "list_nodes",
            "The cluster's NodeManagers with their state, health and resources (GET /ws/v1/cluster/nodes). Answered by yarn_nodes.",
            vec![
                p("states", "string|array", &format!("Only nodes in these states (one, or a list): {}", NODE_STATES.join(", ")), false),
                max_items_param(),
            ],
            json!({"type": "list_nodes", "states": "RUNNING"}),
        ),
        action(
            "get_node",
            "One NodeManager (GET /ws/v1/cluster/nodes/{node_id}). Answered by yarn_nodes.",
            vec![p("node_id", "string", "The node id exactly as list_nodes reports it: host:port, e.g. worker1.example.com:8041", true)],
            json!({"type": "get_node", "node_id": "worker1.example.com:8041"}),
        ),
        action(
            "kill_application",
            "Kill an application (PUT /ws/v1/cluster/apps/{app_id}/state with {\"state\": \"KILLED\"}). Refused unless the client was opened with the startup parameter allow_kill: true. YARN answers 202 with an in-progress state (KILLING, or FINAL_SAVING while it records the outcome) and 200 KILLED once done. Answered by yarn_app_state.",
            vec![app_id_param()],
            json!({"type": "kill_application", "app_id": "application_1792047302594_0003"}),
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
        json!({"type": "list_applications", "states": "RUNNING"}),
    )
    .with_parameters(params)
    .with_actions(actions())
}

fn op_param() -> Parameter {
    p(
        "operation",
        "string",
        "The action this answers, e.g. list_applications or get_application",
        true,
    )
}

fn counted(mut params: Vec<Parameter>) -> Vec<Parameter> {
    params.insert(0, op_param());
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
    p("app_id", "string", "The application asked about", true)
}

pub static CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    ev(
        "yarn_connected",
        "The client reached a YARN ResourceManager REST API and read its cluster info; nothing else has been asked.",
        vec![
            p("endpoint", "string", "The base URL every request goes to", true),
            p("resource_manager_version", "string", "The ResourceManager's version", true),
            p("cluster_id", "number", "The cluster id (the ResourceManager's start time, epoch ms)", false),
            p("state", "string", "The ResourceManager's service state (STARTED)", false),
            p("ha_state", "string", "ACTIVE or STANDBY. A standby ResourceManager redirects most requests to the active one, and this client does not follow redirects", false),
            p("kill_allowed", "boolean", "Whether kill_application is allowed on this client", true),
        ],
    )
});

pub static CLUSTER_INFO_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    ev(
        "yarn_cluster_info",
        "The ResourceManager's identity, from get_cluster_info.",
        vec![
            op_param(),
            p("cluster_info", "object", "{id, startedOn, state, haState, resourceManagerVersion, resourceManagerBuildVersion, hadoopVersion, rmStateStoreName, ...}", true),
        ],
    )
});

pub static METRICS_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    ev(
        "yarn_cluster_metrics",
        "The cluster's totals, from get_cluster_metrics.",
        vec![
            op_param(),
            p("metrics", "object", "{appsSubmitted, appsRunning, appsPending, appsCompleted, appsFailed, appsKilled, totalMB, allocatedMB, availableMB, pendingMB, totalVirtualCores, allocatedVirtualCores, availableVirtualCores, containersAllocated, containersPending, totalNodes, activeNodes, lostNodes, unhealthyNodes, decommissionedNodes, ...}", true),
        ],
    )
});

pub static SCHEDULER_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    ev(
        "yarn_scheduler",
        "The scheduler and its queues, from get_scheduler.",
        counted(vec![
            p("scheduler", "object", "{type (capacityScheduler, fairScheduler, fifoScheduler), queueName, capacity, usedCapacity, maxCapacity, ...}", true),
            p("queues", "array", "Every queue below the root, parents before their children: {queueName, queuePath, queueType (parent/leaf), state, capacity, usedCapacity, maxCapacity, absoluteCapacity, absoluteUsedCapacity, numApplications, numActiveApplications, numPendingApplications, numContainers, ...}", true),
        ]),
    )
});

pub static APPLICATIONS_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    ev(
        "yarn_applications",
        "Applications, from list_applications or get_application.",
        counted(vec![
            p("applications", "array", "One {id, name, user, queue, state, finalStatus, progress, applicationType, diagnostics, startedTime, launchTime, finishedTime, elapsedTime, allocatedMB, allocatedVCores, runningContainers, memorySeconds, vcoreSeconds, trackingUrl, amHostHttpAddress, masterNodeId, ...} per application", true),
            p("filters", "object", "The filters list_applications sent", false),
            p("app_id", "string", "The application get_application asked about", false),
        ]),
    )
});

pub static ATTEMPTS_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    ev(
        "yarn_app_attempts",
        "An application's attempts, from list_app_attempts.",
        counted(vec![
            app_param(),
            p("attempts", "array", "One {id (1, 2, ...), appAttemptId, appAttemptState, startTime, finishedTime, containerId (the AM container), nodeId, nodeHttpAddress, logsLink, diagnosticsInfo} per attempt", true),
        ]),
    )
});

pub static APP_STATE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    ev(
        "yarn_app_state",
        "An application's state, from get_app_state, or YARN's answer to kill_application (an in-progress state such as KILLING or FINAL_SAVING, then KILLED once done).",
        vec![
            op_param(),
            app_param(),
            p("state", "string", "The application's state as YARN reports it", true),
            p("http_status", "number", "For kill_application: 202 while the kill is in progress, 200 once the application is in a final state", false),
        ],
    )
});

pub static APP_QUEUE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    ev(
        "yarn_app_queue",
        "The queue an application runs in, from get_app_queue.",
        vec![
            op_param(),
            app_param(),
            p(
                "queue",
                "string",
                "The queue, as YARN names it (root.default)",
                true,
            ),
        ],
    )
});

pub static NODES_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    ev(
        "yarn_nodes",
        "NodeManagers, from list_nodes or get_node.",
        counted(vec![
            p("nodes", "array", "One {id (host:port), nodeHostName, nodeHTTPAddress, rack, state, healthReport, lastHealthUpdate, version, numContainers, usedMemoryMB, availMemoryMB, usedVirtualCores, availableVirtualCores} per node", true),
            p("node_id", "string", "The node get_node asked about", false),
        ]),
    )
});

pub static ERROR_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    ev(
        "yarn_error",
        "A request failed: the ResourceManager answered with an error status (404 unknown application or node, 400 bad filter, 403 not allowed), redirected (a standby ResourceManager), or the answer could not be read (not JSON, too large, too deep, not YARN's shape); or kill_application was refused because the client was not opened with allow_kill. The client is still connected.",
        vec![
            op_param(),
            p("app_id", "string", "The application it asked about, if any", false),
            p("node_id", "string", "The node it asked about, if any", false),
            p("http_status", "number", "The HTTP status of the response, when there was one", false),
            p("exception", "string", "YARN's exception name (NotFoundException, BadRequestException, ...), when the server sent one", false),
            p("message", "string", "What went wrong, in YARN's words (its RemoteException message) or this client's", true),
        ],
    )
});

/// One request to the REST API, built from a validated action. The URL is assembled from
/// `segments` (each one a path segment under `/ws/v1/cluster/`, percent-encoded as one) and
/// `query` on the client's fixed base URL, and nowhere else.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ApiCall {
    /// The action this came from.
    pub operation: String,
    /// `GET`, or `PUT` for kill_application.
    pub method: String,
    /// Path segments after `/ws/v1/cluster/`.
    pub segments: Vec<String>,
    /// Query parameters, in order.
    pub query: Vec<(String, String)>,
    /// The request body, for a PUT. Built here, never taken from the action.
    pub body: Option<Value>,
    /// Entries delivered at most.
    pub max_items: usize,
    /// The validated parameters, echoed into the event (app_id, node_id, filters, ...).
    pub context: Map<String, Value>,
}

/// Validate a YARN application id: `application_<cluster timestamp>_<sequence>`, as
/// `ApplicationId.fromString` reads it.
pub fn app_id(raw: &str) -> Result<String> {
    let id = raw.trim();
    let shape_ok = id
        .strip_prefix("application_")
        .and_then(|rest| rest.split_once('_'))
        .is_some_and(|(ts, seq)| {
            (1..=19).contains(&ts.len())
                && (1..=10).contains(&seq.len())
                && ts.bytes().all(|b| b.is_ascii_digit())
                && seq.bytes().all(|b| b.is_ascii_digit())
        });
    ensure!(
        shape_ok,
        "app_id {:?}: YARN application ids look like application_1792047302594_0003",
        crate::utils::sanitize::line_field(&crate::utils::truncate::truncate_with_suffix(
            id, 64, "..."
        ))
    );
    Ok(id.to_string())
}

/// Validate a node id: `host:port`, as YARN's `NodeId` prints it.
pub fn node_id(raw: &str) -> Result<String> {
    let id = raw.trim();
    let ok = id.rsplit_once(':').is_some_and(|(host, port)| {
        !host.is_empty()
            && host.len() <= 253
            && !host.starts_with(['.', '-'])
            && host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_')
            && (1..=5).contains(&port.len())
            && port.bytes().all(|b| b.is_ascii_digit())
            && port.parse::<u32>().is_ok_and(|n| n <= 65535)
    });
    ensure!(
        ok,
        "node_id {:?}: YARN node ids are host:port, e.g. worker1.example.com:8041",
        crate::utils::sanitize::line_field(&crate::utils::truncate::truncate_with_suffix(
            id, 64, "..."
        ))
    );
    Ok(id.to_string())
}

/// A name YARN accepts as a queue (`default`, `root.default`) or an application type.
fn name_filter(v: &Value, key: &str, max: usize) -> Result<String> {
    let s = v.as_str().with_context(|| format!("{key} is text"))?.trim();
    ensure!(
        !s.is_empty()
            && s.len() <= max
            && !s.starts_with('.')
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-')),
        "{key} {:?}: 1 to {max} letters, digits, '.', '_' and '-'",
        crate::utils::sanitize::line_field(&crate::utils::truncate::truncate_with_suffix(
            s, 64, "..."
        ))
    );
    Ok(s.to_string())
}

/// A user name as YARN reports it (`hadoop`, `dr.who`, `svc-etl@EXAMPLE.COM`).
fn user_filter(v: &Value) -> Result<String> {
    let s = v.as_str().context("user is text")?.trim();
    ensure!(
        !s.is_empty()
            && s.len() <= 128
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'@' | b'$')),
        "user {:?}: 1 to 128 letters, digits, '.', '_', '-', '@' and '$'",
        crate::utils::sanitize::line_field(&crate::utils::truncate::truncate_with_suffix(
            s, 64, "..."
        ))
    );
    Ok(s.to_string())
}

/// One value or a list of them, each one of `allowed` (case-insensitive, sent upper-case).
fn one_of_many(v: &Value, key: &str, allowed: &[&str]) -> Result<Vec<String>> {
    let list: Vec<&Value> = match v {
        Value::Array(items) => items.iter().collect(),
        Value::String(s) if s.contains(',') => {
            bail!("{key}: give a list rather than a comma-separated string")
        }
        other => vec![other],
    };
    ensure!(
        !list.is_empty() && list.len() <= allowed.len(),
        "{key}: one to {} of {}",
        allowed.len(),
        allowed.join(", ")
    );
    let mut out = Vec::new();
    for item in list {
        let s = item
            .as_str()
            .with_context(|| format!("{key} are text"))?
            .trim()
            .to_ascii_uppercase();
        ensure!(
            allowed.contains(&s.as_str()),
            "{key}: {:?} is not one of {}",
            crate::utils::sanitize::line_field(&crate::utils::truncate::truncate_with_suffix(
                &s, 64, "..."
            )),
            allowed.join(", ")
        );
        if !out.contains(&s) {
            out.push(s);
        }
    }
    Ok(out)
}

/// An epoch-millisecond bound: a whole number, at most `i64::MAX`.
fn epoch_ms(v: &Value, key: &str) -> Result<u64> {
    let n = v
        .as_u64()
        .with_context(|| format!("{key} is epoch milliseconds, a whole number >= 0"))?;
    ensure!(n <= i64::MAX as u64, "{key} {n} is out of range");
    Ok(n)
}

fn get<'a>(v: &'a Value, key: &str) -> Option<&'a Value> {
    v.get(key).filter(|x| !x.is_null())
}

fn op_name(v: &Value) -> &str {
    v.get("type")
        .and_then(Value::as_str)
        .unwrap_or("the action")
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

/// `["apps", app_id]`, with the id validated and echoed into the context.
fn app_segments(v: &Value, ctx: &mut Map<String, Value>) -> Result<Vec<String>> {
    let id = app_id(
        get(v, "app_id")
            .and_then(Value::as_str)
            .with_context(|| format!("{} needs app_id (text)", op_name(v)))?,
    )?;
    ctx.insert("app_id".into(), json!(id));
    Ok(vec!["apps".to_string(), id])
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
    let mut method = "GET";
    let mut body = None;
    let segments: Vec<String> = match kind {
        "get_cluster_info" => vec!["info".into()],
        "get_cluster_metrics" => vec!["metrics".into()],
        "get_scheduler" => {
            items = max_items(v)?;
            vec!["scheduler".into()]
        }
        "list_applications" => {
            let mut filters = Map::new();
            if let Some(s) = get(v, "states") {
                let s = one_of_many(s, "states", APP_STATES)?;
                filters.insert("states".into(), json!(s));
                query.push(("states".into(), s.join(",")));
            }
            if let Some(s) = get(v, "final_status") {
                let s = one_of_many(s, "final_status", FINAL_STATUSES)?;
                ensure!(s.len() == 1, "final_status is one value");
                filters.insert("final_status".into(), json!(s[0]));
                query.push(("finalStatus".into(), s[0].clone()));
            }
            if let Some(q) = get(v, "queue") {
                let q = name_filter(q, "queue", 255)?;
                filters.insert("queue".into(), json!(q));
                query.push(("queue".into(), q));
            }
            if let Some(u) = get(v, "user") {
                let u = user_filter(u)?;
                filters.insert("user".into(), json!(u));
                query.push(("user".into(), u));
            }
            if let Some(t) = get(v, "application_types") {
                let list: Vec<&Value> = match t {
                    Value::Array(items) => items.iter().collect(),
                    other => vec![other],
                };
                ensure!(
                    (1..=10).contains(&list.len()),
                    "application_types: one to 10 types"
                );
                let types = list
                    .into_iter()
                    .map(|x| name_filter(x, "application_types", 64))
                    .collect::<Result<Vec<_>>>()?;
                filters.insert("application_types".into(), json!(types));
                query.push(("applicationTypes".into(), types.join(",")));
            }
            if let Some(limit) = get(v, "limit") {
                let limit = limit.as_u64().context("limit is a whole number")?;
                ensure!((1..=10_000).contains(&limit), "limit is 1..=10000");
                filters.insert("limit".into(), json!(limit));
                query.push(("limit".into(), limit.to_string()));
            }
            for (key, param) in [
                ("started_time_begin", "startedTimeBegin"),
                ("started_time_end", "startedTimeEnd"),
                ("finished_time_begin", "finishedTimeBegin"),
                ("finished_time_end", "finishedTimeEnd"),
            ] {
                if let Some(t) = get(v, key) {
                    let t = epoch_ms(t, key)?;
                    filters.insert(key.into(), json!(t));
                    query.push((param.into(), t.to_string()));
                }
            }
            context.insert("filters".into(), Value::Object(filters));
            items = max_items(v)?;
            vec!["apps".into()]
        }
        "get_application" => app_segments(v, &mut context)?,
        "list_app_attempts" => {
            let mut s = app_segments(v, &mut context)?;
            items = max_items(v)?;
            s.push("appattempts".into());
            s
        }
        "get_app_state" => {
            let mut s = app_segments(v, &mut context)?;
            s.push("state".into());
            s
        }
        "get_app_queue" => {
            let mut s = app_segments(v, &mut context)?;
            s.push("queue".into());
            s
        }
        "kill_application" => {
            let mut s = app_segments(v, &mut context)?;
            s.push("state".into());
            method = "PUT";
            body = Some(json!({"state": "KILLED"}));
            s
        }
        "list_nodes" => {
            if let Some(s) = get(v, "states") {
                let s = one_of_many(s, "states", NODE_STATES)?;
                context.insert("states".into(), json!(s));
                query.push(("states".into(), s.join(",")));
            }
            items = max_items(v)?;
            vec!["nodes".into()]
        }
        "get_node" => {
            let id = node_id(
                get(v, "node_id")
                    .and_then(Value::as_str)
                    .context("get_node needs node_id (text)")?,
            )?;
            context.insert("node_id".into(), json!(id));
            vec!["nodes".into(), id]
        }
        "disconnect" => Vec::new(),
        other => bail!(
            "Unknown YARN client action: {}",
            crate::utils::sanitize::line_field(&crate::utils::truncate::truncate_with_suffix(
                other, 64, "..."
            ))
        ),
    };
    Ok(ApiCall {
        operation: kind.to_string(),
        method: method.to_string(),
        segments,
        query,
        body,
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

impl Protocol for YarnClientProtocol {
    fn protocol_name(&self) -> &'static str {
        "YARN"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>HTTP>YARN"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "yarn client",
            "yarn resourcemanager client",
            "hadoop yarn applications",
            "yarn rest api",
            "yarn cluster metrics",
        ]
    }
    fn description(&self) -> &'static str {
        "Hadoop YARN ResourceManager REST API client: reads cluster info and metrics, the scheduler's queues, applications (filtered by state, final status, queue, user, type), an application's attempts, state and queue, and NodeManagers; kills an application only when opened with allow_kill"
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
            CLUSTER_INFO_EVENT.clone(),
            METRICS_EVENT.clone(),
            SCHEDULER_EVENT.clone(),
            APPLICATIONS_EVENT.clone(),
            ATTEMPTS_EVENT.clone(),
            APP_STATE_EVENT.clone(),
            APP_QUEUE_EVENT.clone(),
            NODES_EVENT.clone(),
            ERROR_EVENT.clone(),
        ]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            param(
                "endpoint_url",
                "string",
                "The ResourceManager's web address, used exactly as given: http://rm.example.com:8088, or a gateway path such as https://gateway/yarn. Without it the client's remote_addr is the target (host:port means http://host:port). There is no default target",
                false,
                json!("http://127.0.0.1:8088"),
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
            param(
                "allow_kill",
                "boolean",
                "Allow kill_application on this client. Without it every kill is refused and nothing is sent; the client is read-only",
                false,
                json!(true),
                None,
            ),
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Beta)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation("Hadoop YARN ResourceManager REST API (/ws/v1/cluster) over HTTP(S), reqwest natively and the hyper transport in the browser build: GET info, metrics, scheduler (the queue tree walked iteratively), apps (states, finalStatus, queue, user, applicationTypes, limit, started/finished time bounds), one app, its appattempts, its state and its queue, nodes (states) and one node; PUT apps/{id}/state {\"state\":\"KILLED\"} only with the allow_kill startup parameter. Paths are built from validated ids, one percent-encoded segment each, on the base URL fixed at connect; the PUT body is fixed in Rust; redirects are not followed. Responses are bounded in size and JSON depth before parsing, unwrapped from YARN's envelopes and projected onto a fixed set of fields per resource")
            .llm_control("Which applications, attempts, queues and nodes to read, with which filters and how many entries, and (with allow_kill) which application to kill; it reads the decoded entries and YARN's own RemoteException text")
            .e2e_testing("tests/client/yarn/real_server_test.rs runs the official Apache Hadoop 3.5.0 distribution (SHA-512 pinned by install_peers.sh) as a single-node ResourceManager + NodeManager on loopback with the model mocked, and runs real distributed-shell applications on it: one that succeeds in queue default, one whose container exits non-zero in queue netget, and a long-running one the model then kills. Every application's id, name, type, user, queue, state and final status is checked against `yarn application -list -appStates ALL`, the failed one's start/finish times and diagnostics against `yarn application -status`, its attempt against `yarn applicationattempt -list`, the node against `yarn node -list -all`, the queues against capacity-scheduler.xml, and the kill against `yarn application -status` afterwards. A recording TCP relay between NetGet and the ResourceManager asserts the exact request lines (and the PUT body) YARN received for the model's actions and that nothing else was sent. YARN's own 404 for an unknown application, a kill refused without allow_kill (nothing on the wire), the follow-up bound and an LLM failure (the ResourceManager sees only the connect probe) run against the same peer. Fails rather than skips without NETGET_HADOOP_HOME")
            .notes("Beta against the client bar: the peer is Apache Hadoop's own ResourceManager and NodeManager, the reference implementation, with real applications run on them; the suite fails rather than skips; each session is a real chain whose later requests are built from ids the model read out of earlier answers; and the client acting on the model's answer is asserted on the wire from the request lines the ResourceManager received, and for the kill from YARN's own CLI. Only Hadoop 3.5.0 is tested; the /ws/v1 surface read here is the documented one since Hadoop 2.x, and a field an older release lacks is simply absent from the projection. Not implemented: application submission (POST /apps/new-application and POST /apps), whose am-container-spec carries the shell command YARN runs on a cluster node — arbitrary code execution on a model's say-so, which a monitoring client should not offer; queue moves, priority and timeout updates, reservations, delegation tokens and the NodeManager's own /ws/v1/node API (a different service on each node). No SPNEGO/Kerberos: on a secured cluster every request answers 401 and the client reports it")
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Connect to the YARN ResourceManager at http://127.0.0.1:8088 and tell me which applications failed today and why"
    }
    fn get_startup_examples(&self) -> StartupExamples {
        let llm = json!({
            "type": "open_client",
            "protocol": "YARN",
            "remote_addr": "127.0.0.1:8088",
            "startup_params": {"request_timeout_secs": 30},
            "instruction": "List the failed applications and read each one's diagnostics"
        });
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([
            {"event_pattern": "yarn_connected", "handler": {"type": "static", "actions": [
                {"type": "list_applications", "final_status": "FAILED", "limit": 20}
            ]}},
            {"event_pattern": "*", "handler": {"type": "static", "actions": []}}
        ]);
        let mut scripted = static_example.clone();
        scripted["event_handlers"][1] = json!({"event_pattern": "yarn_applications", "handler": {
            "type": "script", "language": "python",
            "code": "import json,sys\ne=json.load(sys.stdin)['event']\na=[{'type':'list_app_attempts','app_id':x['id']} for x in e.get('applications',[])[:3]]\nprint(json.dumps({'actions':a}))"
        }});
        StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Monitoring"
    }
}

impl Client for YarnClientProtocol {
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
