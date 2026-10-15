//! A ResourceManager REST response → the event the model reads.
//!
//! The ResourceManager answers every resource with JSON wrapped in an envelope named after it
//! (`{"apps": {"app": [...]}}`, `{"node": {...}}`, `{"clusterMetrics": {...}}`), and each entry
//! carries far more than a model can use — a node brings its resources three times over as
//! nested `resourceInformations` maps, an application its `resourceSecondsMap` and `timeouts`.
//! So each resource is **unwrapped and projected** onto a fixed list of fields, and nothing the
//! server adds beyond them reaches the model.
//!
//! | resource | envelope | fields kept |
//! |---|---|---|
//! | cluster info | `clusterInfo` | [`CLUSTER_INFO_FIELDS`] |
//! | cluster metrics | `clusterMetrics` | [`METRICS_FIELDS`] |
//! | scheduler | `scheduler.schedulerInfo` | [`SCHEDULER_FIELDS`], and every queue (at most [`MAX_QUEUES`]) as [`QUEUE_FIELDS`] |
//! | applications | `apps.app` (`null` when there are none) or `app` | [`APP_FIELDS`] |
//! | application attempts | `appAttempts.appAttempt` | [`ATTEMPT_FIELDS`] |
//! | application state / queue | `state` / `queue` | the one string |
//! | nodes | `nodes.node` (`null` when there are none) or `node` | [`NODE_FIELDS`] |
//!
//! A list the server renders as a single object rather than an array (JAXB's "natural" JSON
//! notation does that for a one-element list in some Hadoop releases) is read as a list of one.
//!
//! Every value kept is a scalar or a list of scalars. Text is stripped of control characters
//! (it is a peer's, and it reaches a terminal) and cut at [`MAX_TEXT_BYTES`] —
//! [`MAX_LONG_TEXT_BYTES`] for diagnostics and health reports, which are multi-line by nature.
//!
//! Before any of that, the body is bounded: at most `MAX_RESPONSE_BYTES` are read (while
//! reading), and its bracket nesting is measured without recursion and refused past
//! [`MAX_JSON_DEPTH`] before `serde_json` sees it. The scheduler's queue tree is walked with an
//! explicit stack, not recursion, and stops at [`MAX_QUEUES`]. No function here calls itself.

use anyhow::{bail, ensure, Result};
use serde_json::{json, Map, Value};

use crate::utils::sanitize;
use crate::utils::truncate::truncate_with_suffix;

/// Bracket nesting accepted in a response. The ResourceManager's deepest answer, the
/// CapacityScheduler's queue tree, measured 16 levels against Hadoop 3.5.0 with one level of
/// queues; each level below adds three (`queues`, `queue`, the entry), so 64 leaves room for a
/// queue hierarchy fifteen deep.
pub const MAX_JSON_DEPTH: usize = 64;
/// A text field, single-line.
pub const MAX_TEXT_BYTES: usize = 2048;
/// Diagnostics and a node's health report.
pub const MAX_LONG_TEXT_BYTES: usize = 8192;
/// A list of scalars inside one entry.
pub const MAX_SCALAR_LIST: usize = 1000;
/// Queues walked in a scheduler answer.
pub const MAX_QUEUES: usize = 500;

pub const CLUSTER_INFO_FIELDS: &[&str] = &[
    "id",
    "startedOn",
    "state",
    "haState",
    "haZooKeeperConnectionState",
    "rmStateStoreName",
    "resourceManagerVersion",
    "resourceManagerBuildVersion",
    "resourceManagerVersionBuiltOn",
    "hadoopVersion",
    "hadoopBuildVersion",
    "hadoopVersionBuiltOn",
];
pub const METRICS_FIELDS: &[&str] = &[
    "appsSubmitted",
    "appsCompleted",
    "appsPending",
    "appsRunning",
    "appsFailed",
    "appsKilled",
    "reservedMB",
    "availableMB",
    "allocatedMB",
    "pendingMB",
    "totalMB",
    "utilizedMB",
    "reservedVirtualCores",
    "availableVirtualCores",
    "allocatedVirtualCores",
    "pendingVirtualCores",
    "totalVirtualCores",
    "utilizedVirtualCores",
    "containersAllocated",
    "containersReserved",
    "containersPending",
    "totalNodes",
    "activeNodes",
    "lostNodes",
    "unhealthyNodes",
    "decommissioningNodes",
    "decommissionedNodes",
    "rebootedNodes",
    "shutdownNodes",
];
pub const SCHEDULER_FIELDS: &[&str] = &[
    "type",
    "queueName",
    "queuePath",
    "capacity",
    "usedCapacity",
    "maxCapacity",
    // FifoScheduler
    "qstate",
    "minQueueMemoryCapacity",
    "maxQueueMemoryCapacity",
    "numNodes",
    "usedNodeCapacity",
    "availNodeCapacity",
    "totalNodeCapacity",
    "numContainers",
];
pub const QUEUE_FIELDS: &[&str] = &[
    "queueName",
    "queuePath",
    "type",
    "queueType",
    "state",
    "capacity",
    "usedCapacity",
    "maxCapacity",
    "absoluteCapacity",
    "absoluteMaxCapacity",
    "absoluteUsedCapacity",
    "weight",
    "numApplications",
    "numActiveApplications",
    "numPendingApplications",
    "numContainers",
    "maxApplications",
    "maxApplicationsPerUser",
    "userLimit",
    "userLimitFactor",
    "defaultPriority",
    // FairScheduler
    "maxApps",
    "numActiveApps",
    "numPendingApps",
    "schedulingPolicy",
];
pub const APP_FIELDS: &[&str] = &[
    "id",
    "user",
    "name",
    "queue",
    "state",
    "finalStatus",
    "progress",
    "trackingUI",
    "trackingUrl",
    "diagnostics",
    "clusterId",
    "applicationType",
    "applicationTags",
    "priority",
    "startedTime",
    "launchTime",
    "finishedTime",
    "elapsedTime",
    "amContainerLogs",
    "amHostHttpAddress",
    "amRPCAddress",
    "masterNodeId",
    "allocatedMB",
    "allocatedVCores",
    "reservedMB",
    "reservedVCores",
    "runningContainers",
    "memorySeconds",
    "vcoreSeconds",
    "queueUsagePercentage",
    "clusterUsagePercentage",
    "preemptedResourceMB",
    "preemptedResourceVCores",
    "numNonAMContainerPreempted",
    "numAMContainerPreempted",
    "logAggregationStatus",
    "unmanagedApplication",
    "appNodeLabelExpression",
    "amNodeLabelExpression",
];
pub const ATTEMPT_FIELDS: &[&str] = &[
    "id",
    "appAttemptId",
    "appAttemptState",
    "startTime",
    "finishedTime",
    "containerId",
    "nodeId",
    "nodeHttpAddress",
    "logsLink",
    "blacklistedNodes",
    "nodesBlacklistedBySystem",
    "diagnosticsInfo",
];
pub const NODE_FIELDS: &[&str] = &[
    "id",
    "rack",
    "state",
    "nodeHostName",
    "nodeHTTPAddress",
    "version",
    "lastHealthUpdate",
    "healthReport",
    "numContainers",
    "usedMemoryMB",
    "availMemoryMB",
    "usedVirtualCores",
    "availableVirtualCores",
    "memUtilization",
    "cpuUtilization",
    "numRunningOpportContainers",
    "numQueuedContainers",
];

/// Fields whose text is multi-line by nature and gets the longer bound.
const LONG_TEXT_FIELDS: &[&str] = &["diagnostics", "diagnosticsInfo", "healthReport"];

/// Which resource a response is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resource {
    ClusterInfo,
    Metrics,
    Scheduler,
    Applications,
    Attempts,
    AppState,
    AppQueue,
    Nodes,
}

impl Resource {
    pub fn of(operation: &str) -> Option<Resource> {
        Some(match operation {
            "get_cluster_info" => Resource::ClusterInfo,
            "get_cluster_metrics" => Resource::Metrics,
            "get_scheduler" => Resource::Scheduler,
            "list_applications" | "get_application" => Resource::Applications,
            "list_app_attempts" => Resource::Attempts,
            "get_app_state" | "kill_application" => Resource::AppState,
            "get_app_queue" => Resource::AppQueue,
            "list_nodes" | "get_node" => Resource::Nodes,
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
        "the response nests {depth} levels deep; at most {MAX_JSON_DEPTH} are read"
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

/// The entries of a wrapped list: `{outer: {inner: [...]}}`, `{outer: {inner: {...}}}` (a list
/// of one), or `{outer: null}` / `{outer: {}}` (none). `single` names the envelope of a one-entry
/// answer (`app`, `node`), which is also accepted.
fn wrapped_list<'a>(
    value: &'a Value,
    outer: &str,
    inner: &str,
    single: Option<&str>,
) -> Result<&'a [Value]> {
    let obj = value
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("the ResourceManager answers with a JSON object"))?;
    if let Some(one) = single.and_then(|k| obj.get(k)) {
        ensure!(
            one.is_object(),
            "{:?} is not an object",
            single.unwrap_or("")
        );
        return Ok(std::slice::from_ref(one));
    }
    let wrapper = obj.get(outer).ok_or_else(|| {
        anyhow::anyhow!(
            "the answer carries no {outer:?}{}",
            single.map(|s| format!(" or {s:?}")).unwrap_or_default()
        )
    })?;
    let list = match wrapper {
        Value::Null => return Ok(&[]),
        Value::Object(w) => match w.get(inner) {
            None | Some(Value::Null) => return Ok(&[]),
            Some(list) => list,
        },
        _ => bail!("{outer:?} is neither an object nor null"),
    };
    match list {
        Value::Array(items) => {
            ensure!(
                items.iter().all(Value::is_object),
                "{outer}.{inner} holds something other than objects"
            );
            Ok(items.as_slice())
        }
        Value::Object(_) => Ok(std::slice::from_ref(list)),
        _ => bail!("{outer}.{inner} is neither an array nor an object"),
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

/// The children of one queue: the CapacityScheduler's `queues.queue`, the FairScheduler's
/// `childQueues.queue` — an array, a single object, or nothing.
fn child_queues(queue: &Value) -> Vec<&Value> {
    let mut out = Vec::new();
    for wrapper in ["queues", "childQueues"] {
        match queue.get(wrapper).and_then(|w| w.get("queue")) {
            Some(Value::Array(items)) => out.extend(items.iter().filter(|q| q.is_object())),
            Some(one @ Value::Object(_)) => out.push(one),
            _ => {}
        }
    }
    out
}

/// Every queue under `root` (root itself excluded), depth-first in the server's order, walked
/// with an explicit stack and stopped at [`MAX_QUEUES`]. Returns the projected queues and
/// whether the walk stopped early.
fn walk_queues(root: &Value) -> (Vec<Value>, bool) {
    let mut out = Vec::new();
    let mut stack: Vec<&Value> = child_queues(root).into_iter().rev().collect();
    while let Some(queue) = stack.pop() {
        if out.len() >= MAX_QUEUES {
            return (out, true);
        }
        out.push(project(queue, QUEUE_FIELDS));
        stack.extend(child_queues(queue).into_iter().rev());
    }
    (out, false)
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
        Resource::ClusterInfo => {
            let info = value
                .get("clusterInfo")
                .filter(|v| v.is_object())
                .ok_or_else(|| anyhow::anyhow!("the answer carries no \"clusterInfo\" object"))?;
            ensure!(
                info.get("resourceManagerVersion")
                    .is_some_and(Value::is_string),
                "clusterInfo carries no resourceManagerVersion"
            );
            out.insert("cluster_info".into(), project(info, CLUSTER_INFO_FIELDS));
        }
        Resource::Metrics => {
            let metrics = value
                .get("clusterMetrics")
                .filter(|v| v.is_object())
                .ok_or_else(|| {
                    anyhow::anyhow!("the answer carries no \"clusterMetrics\" object")
                })?;
            out.insert("metrics".into(), project(metrics, METRICS_FIELDS));
        }
        Resource::Scheduler => {
            let info = value
                .get("scheduler")
                .and_then(|s| s.get("schedulerInfo"))
                .filter(|v| v.is_object())
                .ok_or_else(|| {
                    anyhow::anyhow!("the answer carries no \"scheduler.schedulerInfo\" object")
                })?;
            // The FairScheduler puts its tree under rootQueue; the others at the top.
            let root = info
                .get("rootQueue")
                .filter(|r| r.is_object())
                .unwrap_or(info);
            let (queues, cut) = walk_queues(root);
            let mut summary = project(info, SCHEDULER_FIELDS);
            if let (Some(s), Some(r)) = (summary.as_object_mut(), root.as_object()) {
                for key in ["queueName", "capacity", "usedCapacity", "maxCapacity"] {
                    if let (false, Some(v)) = (s.contains_key(key), r.get(key)) {
                        if let Some(v) = scalar(key, v) {
                            s.insert(key.into(), v);
                        }
                    }
                }
            }
            out.insert("scheduler".into(), summary);
            take(&mut out, "queues", &queues, max_items, Value::clone);
            if cut {
                out.insert("truncated".into(), json!(true));
            }
        }
        Resource::Applications => {
            let items = wrapped_list(value, "apps", "app", Some("app"))?;
            take(&mut out, "applications", items, max_items, |x| {
                project(x, APP_FIELDS)
            });
        }
        Resource::Attempts => {
            let items = wrapped_list(value, "appAttempts", "appAttempt", None)?;
            take(&mut out, "attempts", items, max_items, |x| {
                project(x, ATTEMPT_FIELDS)
            });
        }
        Resource::AppState => {
            let state = value
                .get("state")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow::anyhow!("the answer carries no \"state\""))?;
            out.insert("state".into(), json!(text(state, false)));
        }
        Resource::AppQueue => {
            let queue = value
                .get("queue")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow::anyhow!("the answer carries no \"queue\""))?;
            out.insert("queue".into(), json!(text(queue, false)));
        }
        Resource::Nodes => {
            let items = wrapped_list(value, "nodes", "node", Some("node"))?;
            take(&mut out, "nodes", items, max_items, |x| {
                project(x, NODE_FIELDS)
            });
        }
    }
    Ok(Value::Object(out))
}

/// The ResourceManager's own words for an error: `RemoteException.exception` and `.message`
/// from its JSON envelope, when the body is one.
pub fn remote_exception(body: &[u8]) -> Option<(String, String)> {
    if json_depth(body) > MAX_JSON_DEPTH {
        return None;
    }
    let value: Value = serde_json::from_slice(body).ok()?;
    let e = value.get("RemoteException")?;
    let exception = e.get("exception").and_then(Value::as_str).unwrap_or("");
    let message = e.get("message").and_then(Value::as_str).unwrap_or("");
    Some((text(exception, false), text(message, false)))
}
