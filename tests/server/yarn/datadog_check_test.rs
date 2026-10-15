//! NetGet's YARN server against **Datadog's YARN integration** (`datadog_checks.yarn`,
//! DataDog/integrations-core tag `yarn-8.4.2`) — an independent consumer of the ResourceManager
//! REST API, written by people who have never seen NetGet, which reads it on every Agent run.
//! Until this test the server had only ever faced `reqwest`.
//!
//! The check runs once against the server (`datadog_check.py`, the Agent replaced by
//! `datadog_checks.base`'s own stubs) and reads, in its own order, `/ws/v1/cluster/metrics`,
//! `/apps`, `/nodes` and `/scheduler`. The model answers each from one rule that branches on the
//! request's operation. What is asserted is what the check *submitted* — metric values and tags
//! decoded from the model's answers, its service checks and the version it recorded — so a body
//! the check could not read shows up as a missing metric, a CRITICAL or a check error.
//!
//! What it found: `/ws/v1/cluster/scheduler`, which the check reads on every run, was not served
//! at all — it fell to the static 404 for unknown paths, so every run ended in a CRITICAL
//! `yarn.can_connect` and an exception, and no queue metric was ever collected. The server now
//! routes it to operation `scheduler`, answered by `send_yarn_scheduler` in the
//! CapacityScheduler's own shape (`scheduler.schedulerInfo` with `queues.queue` nested per level).
//!
//! **Fails rather than skips** without `NETGET_DATADOG_YARN` (from
//! `tests/server/yarn/install_datadog_check.sh`). LLM calls: 5.


use crate::helpers::real_server::{run_tool, InstallHint};
use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::process::Command;

const CHECK: InstallHint = InstallHint {
    brew: "python@3.12, then `sh tests/server/yarn/install_datadog_check.sh <dir>` and export \
           the NETGET_DATADOG_YARN it prints",
    apt: "python3.12-venv, then `sh tests/server/yarn/install_datadog_check.sh <dir>` and \
          export the NETGET_DATADOG_YARN it prints",
};

fn check_root() -> E2EResult<PathBuf> {
    let root = std::env::var_os("NETGET_DATADOG_YARN")
        .map(PathBuf::from)
        .ok_or(
            "NETGET_DATADOG_YARN is not set. This test drives NetGet's YARN server with \
             Datadog's YARN integration and FAILS rather than skipping without it: run \
             `sh tests/server/yarn/install_datadog_check.sh /some/dir` (needs python 3.12+) and \
             export the NETGET_DATADOG_YARN it prints.",
        )?;
    for needed in ["venv/bin/python", "check/datadog_checks/yarn/yarn.py"] {
        if !root.join(needed).is_file() {
            return Err(format!(
                "{} is missing; re-run tests/server/yarn/install_datadog_check.sh",
                root.join(needed).display()
            )
            .into());
        }
    }
    Ok(root)
}

/// Run the check once against `url` and return what it submitted.
async fn run_check(url: &str) -> E2EResult<Value> {
    let root = check_root()?;
    let mut cmd = Command::new(root.join("venv/bin/python"));
    cmd.arg("-I")
        .arg(format!(
            "{}/tests/server/yarn/datadog_check.py",
            env!("CARGO_MANIFEST_DIR")
        ))
        .arg(root.join("check"))
        .arg(url);
    let out = run_tool(cmd, "python (NETGET_DATADOG_YARN venv)", CHECK).await?;
    let last = out.trim().lines().last().unwrap_or("null").to_string();
    Ok(serde_json::from_str(&last).map_err(|e| format!("{e}: the check printed {out}"))?)
}

/// The submissions of `metric` whose tags include every one of `tags`.
fn values(report: &Value, metric: &str, tags: &[&str]) -> Vec<f64> {
    report["metrics"][metric]
        .as_array()
        .map(|subs| {
            subs.iter()
                .filter(|s| {
                    tags.iter().all(|t| {
                        s["tags"]
                            .as_array()
                            .is_some_and(|have| have.iter().any(|h| h == t))
                    })
                })
                .filter_map(|s| s["value"].as_f64())
                .collect()
        })
        .unwrap_or_default()
}

/// The statuses of `check`'s service checks whose tags include every one of `tags`.
fn statuses(report: &Value, check: &str, tags: &[&str]) -> Vec<i64> {
    report["service_checks"][check]
        .as_array()
        .map(|subs| {
            subs.iter()
                .filter(|s| {
                    tags.iter().all(|t| {
                        s["tags"]
                            .as_array()
                            .is_some_and(|have| have.iter().any(|h| h == t))
                    })
                })
                .filter_map(|s| s["status"].as_i64())
                .collect()
        })
        .unwrap_or_default()
}

/// The model's answers, YARN-shaped, keyed by the operation the server detected.
fn answer(e: &Value) -> Value {
    match e["operation"].as_str().unwrap_or_default() {
        "metrics" => json!([{"type": "send_yarn_metrics", "metrics": {
            "appsSubmitted": 7, "appsCompleted": 5, "appsRunning": 1, "appsFailed": 1,
            "totalMB": 16384, "allocatedMB": 3072, "availableMB": 13312,
            "totalVirtualCores": 8, "allocatedVirtualCores": 3, "availableVirtualCores": 5,
            "containersAllocated": 3, "totalNodes": 1, "activeNodes": 1
        }}]),
        "apps" => json!([{"type": "send_yarn_apps", "apps": [
            {"id": "application_1792047302594_0007", "name": "nightly-etl", "user": "etl",
             "queue": "root.etl.nightly", "state": "RUNNING", "finalStatus": "UNDEFINED",
             "progress": 42.5, "applicationType": "SPARK", "startedTime": 1792047400000u64,
             "finishedTime": 0, "elapsedTime": 600000, "allocatedMB": 3072,
             "allocatedVCores": 3, "runningContainers": 3, "memorySeconds": 1843200,
             "vcoreSeconds": 1800},
            {"id": "application_1792047302594_0006", "name": "hourly-rollup", "user": "etl",
             "queue": "root.default", "state": "FINISHED", "finalStatus": "FAILED",
             "progress": 100.0, "applicationType": "MAPREDUCE",
             "startedTime": 1792047300000u64, "finishedTime": 1792047360000u64,
             "elapsedTime": 60000, "allocatedMB": -1, "allocatedVCores": -1,
             "runningContainers": -1, "memorySeconds": 92160, "vcoreSeconds": 90}
        ]}]),
        "nodes" => json!([{"type": "send_yarn_nodes", "nodes": [
            {"id": "worker1.example.com:8041", "nodeHostName": "worker1.example.com",
             "nodeHTTPAddress": "worker1.example.com:8042", "rack": "/default-rack",
             "state": "RUNNING", "healthReport": "", "numContainers": 3,
             "usedMemoryMB": 3072, "availMemoryMB": 13312, "usedVirtualCores": 3,
             "availableVirtualCores": 5, "version": "3.5.0",
             "lastHealthUpdate": 1792047990000u64}
        ]}]),
        "scheduler" => json!([{"type": "send_yarn_scheduler",
        "root": {"capacity": 100.0, "usedCapacity": 18.75, "maxCapacity": 100.0},
        "queues": [
            {"queueName": "default", "capacity": 60.0, "usedCapacity": 0.0,
             "maxCapacity": 100.0, "absoluteCapacity": 60.0, "numApplications": 0,
             "numActiveApplications": 0, "numPendingApplications": 0, "numContainers": 0},
            {"queueName": "etl", "capacity": 40.0, "usedCapacity": 46.875,
             "maxCapacity": 100.0, "absoluteCapacity": 40.0, "numApplications": 1,
             "queues": [
                {"queueName": "nightly", "capacity": 100.0, "usedCapacity": 46.875,
                 "maxCapacity": 100.0, "absoluteCapacity": 40.0, "numApplications": 1,
                 "numActiveApplications": 1, "numPendingApplications": 0,
                 "numContainers": 3}
             ]}
        ]}]),
        _ => json!([{"type": "send_yarn_error", "status": 404,
                     "exception": "NotFoundException", "message": "not modelled"}]),
    }
}

#[tokio::test]
async fn datadogs_yarn_integration_reads_the_models_cluster() -> E2EResult<()> {
    // Fail before starting anything when the check is not installed.
    check_root()?;
    let config = NetGetConfig::new(
        "Start a Hadoop YARN ResourceManager on port {AVAILABLE_PORT}. YARN-DATADOG-STARTUP-TURN.",
    )
    .with_mock(|mock| {
        mock.on_instruction_containing("YARN-DATADOG-STARTUP-TURN")
            .respond_with_actions(json!([{
                "type": "open_server", "port": 0, "base_stack": "yarn",
                "instruction": "A one-node YARN cluster running the nightly ETL; the hourly rollup failed."
            }]))
            .expect_calls(1)
            .and()
            .on_event("yarn_request")
            .respond_with_actions_from_event(answer)
            .expect_calls(4)
            .and()
    });
    let server = start_netget_server(config).await?;
    let report = run_check(&format!("http://127.0.0.1:{}", server.port)).await?;
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;

    assert_eq!(report["error"], "", "the check run raised: {report}");
    let cluster = "yarn_cluster:netget";

    // Every request succeeded: one OK can_connect per endpoint, and nothing else.
    assert_eq!(
        statuses(&report, "yarn.can_connect", &[cluster]),
        vec![0, 0, 0, 0],
        "{report}"
    );

    // Cluster metrics, and a field the model omitted defaulted to 0 rather than missing.
    assert_eq!(
        values(&report, "yarn.metrics.apps_running", &[cluster]),
        vec![1.0]
    );
    assert_eq!(
        values(&report, "yarn.metrics.total_mb", &[cluster]),
        vec![16384.0]
    );
    assert_eq!(
        values(&report, "yarn.metrics.lost_nodes", &[cluster]),
        vec![0.0]
    );

    // Applications: metrics and tags decoded per application, and the status service check
    // mapping RUNNING to OK and the failed one's FINISHED (its state) to OK as YARN does.
    let etl = "app_name:nightly-etl";
    assert_eq!(
        values(
            &report,
            "yarn.apps.progress_gauge",
            &[etl, "app_queue:root.etl.nightly", "state:RUNNING"]
        ),
        vec![42.5]
    );
    assert_eq!(
        values(&report, "yarn.apps.running_containers_gauge", &[etl]),
        vec![3.0]
    );
    assert_eq!(
        values(
            &report,
            "yarn.apps.memory_seconds_gauge",
            &["app_name:hourly-rollup", "state:FINISHED"]
        ),
        vec![92160.0]
    );
    assert_eq!(
        statuses(&report, "yarn.application.status", &[etl]),
        vec![0]
    );

    // The node, and the Hadoop version the check records from it.
    let node = "node_id:worker1.example.com:8041";
    assert_eq!(
        values(&report, "yarn.node.num_containers", &[node]),
        vec![3.0]
    );
    assert_eq!(
        values(&report, "yarn.node.avail_memory_mb", &[node]),
        vec![13312.0]
    );
    assert_eq!(report["version"], "3.5.0");

    // The scheduler: the endpoint the server did not serve before. Root, queue and sub-queue
    // metrics each decoded from the CapacityScheduler shape.
    assert_eq!(
        values(
            &report,
            "yarn.queue.root.used_capacity",
            &["queue_name:root"]
        ),
        vec![18.75]
    );
    assert_eq!(
        values(&report, "yarn.queue.capacity", &["queue_name:default"]),
        vec![60.0]
    );
    assert_eq!(
        values(&report, "yarn.queue.used_capacity", &["queue_name:etl"]),
        vec![46.875]
    );
    assert_eq!(
        values(
            &report,
            "yarn.queue.num_active_applications",
            &["sub_queue_name:nightly"]
        ),
        vec![1.0]
    );
    assert_eq!(
        values(
            &report,
            "yarn.queue.num_containers",
            &["sub_queue_name:nightly"]
        ),
        vec![3.0]
    );
    Ok(())
}
