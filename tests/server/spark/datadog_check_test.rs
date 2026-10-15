//! NetGet's Spark server against **Datadog's Spark integration** (`datadog_checks.spark`,
//! DataDog/integrations-core tag `spark-7.8.0`) — an independent consumer of Spark's monitoring
//! REST API, written by people who have never seen NetGet, which reads it on every Agent run.
//! Until this test the server had only ever faced `reqwest`.
//!
//! The check runs once in `spark_driver_mode` against the server (`datadog_check.py`, the Agent
//! replaced by `datadog_checks.base`'s own stubs) and reads, in its own order: the version, the
//! application list, each application's jobs, stages, executors, cached RDDs and streaming
//! statistics, then `/metrics/json`. The model answers each from one rule that branches on the
//! request's operation. What is asserted is what the check *submitted* — metric values and tags
//! decoded from the model's answers, its service checks and the version it recorded — so a
//! body the check could not read shows up as a missing metric or a CRITICAL.
//!
//! What it found: `/storage/rdd`, which the check reads on every run, had no action the model
//! could answer it with — it fell into the generic per-application path, where the only truthful
//! answer was a 404, which the check reports as a CRITICAL application-master service check.
//! The server now routes it to operation `rdd` and `send_spark_rdds`.
//!
//! **Fails rather than skips** without `NETGET_DATADOG_SPARK` (from
//! `tests/server/spark/install_datadog_check.sh`). LLM calls: 7.


use crate::helpers::real_server::{run_tool, InstallHint};
use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::process::Command;

const CHECK: InstallHint = InstallHint {
    brew: "python@3.12, then `sh tests/server/spark/install_datadog_check.sh <dir>` and export \
           the NETGET_DATADOG_SPARK it prints",
    apt: "python3.12-venv, then `sh tests/server/spark/install_datadog_check.sh <dir>` and \
          export the NETGET_DATADOG_SPARK it prints",
};

fn check_root() -> E2EResult<PathBuf> {
    let root = std::env::var_os("NETGET_DATADOG_SPARK")
        .map(PathBuf::from)
        .ok_or(
            "NETGET_DATADOG_SPARK is not set. This test drives NetGet's Spark server with \
             Datadog's Spark integration and FAILS rather than skipping without it: run \
             `sh tests/server/spark/install_datadog_check.sh /some/dir` (needs python 3.12+) and \
             export the NETGET_DATADOG_SPARK it prints.",
        )?;
    for needed in ["venv/bin/python", "check/datadog_checks/spark/spark.py"] {
        if !root.join(needed).is_file() {
            return Err(format!(
                "{} is missing; re-run tests/server/spark/install_datadog_check.sh",
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
            "{}/tests/server/spark/datadog_check.py",
            env!("CARGO_MANIFEST_DIR")
        ))
        .arg(root.join("check"))
        .arg(url);
    let out = run_tool(cmd, "python (NETGET_DATADOG_SPARK venv)", CHECK).await?;
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

/// The model's answers, Spark-shaped, keyed by the operation the server detected.
fn answer(e: &Value) -> Value {
    let op = e["operation"].as_str().unwrap_or_default();
    let path = e["path"].as_str().unwrap_or_default();
    match op {
        "applications" => json!([{"type": "send_spark_applications", "applications": [{
            "id": "app-20261015060028-0000", "name": "nightly-etl",
            "attempts": [{"startTime": "2026-10-15T06:00:28.759GMT", "completed": false,
                          "sparkUser": "etl", "appSparkVersion": "3.5.1"}]
        }]}]),
        "jobs" => json!([{"type": "send_spark_jobs", "jobs": [
            {"jobId": 1, "name": "save at etl.py:40", "status": "FAILED", "stageIds": [2],
             "numTasks": 3, "numActiveTasks": 0, "numCompletedTasks": 2, "numSkippedTasks": 0,
             "numFailedTasks": 1, "numActiveStages": 0, "numCompletedStages": 0,
             "numSkippedStages": 0, "numFailedStages": 1},
            {"jobId": 0, "name": "count at etl.py:12", "status": "SUCCEEDED", "stageIds": [0, 1],
             "numTasks": 12, "numActiveTasks": 0, "numCompletedTasks": 12, "numSkippedTasks": 0,
             "numFailedTasks": 0, "numActiveStages": 0, "numCompletedStages": 2,
             "numSkippedStages": 0, "numFailedStages": 0}
        ]}]),
        "stages" => json!([{"type": "send_spark_stages", "stages": [
            {"status": "FAILED", "stageId": 2, "attemptId": 0, "numTasks": 3,
             "numActiveTasks": 0, "numCompleteTasks": 2, "numFailedTasks": 1,
             "executorRunTime": 300, "inputBytes": 0, "inputRecords": 0, "outputBytes": 0,
             "outputRecords": 0, "shuffleReadBytes": 0, "shuffleReadRecords": 0,
             "shuffleWriteBytes": 0, "shuffleWriteRecords": 0, "memoryBytesSpilled": 0,
             "diskBytesSpilled": 0, "name": "save at etl.py:40"},
            {"status": "COMPLETE", "stageId": 1, "attemptId": 0, "numTasks": 4,
             "numActiveTasks": 0, "numCompleteTasks": 4, "numFailedTasks": 0,
             "executorRunTime": 1200, "inputBytes": 0, "inputRecords": 0, "outputBytes": 0,
             "outputRecords": 0, "shuffleReadBytes": 4096, "shuffleReadRecords": 70,
             "shuffleWriteBytes": 0, "shuffleWriteRecords": 0, "memoryBytesSpilled": 0,
             "diskBytesSpilled": 0, "name": "count at etl.py:12"},
            {"status": "COMPLETE", "stageId": 0, "attemptId": 0, "numTasks": 8,
             "numActiveTasks": 0, "numCompleteTasks": 8, "numFailedTasks": 0,
             "executorRunTime": 2400, "inputBytes": 65536, "inputRecords": 1000,
             "outputBytes": 0, "outputRecords": 0, "shuffleReadBytes": 0,
             "shuffleReadRecords": 0, "shuffleWriteBytes": 4096, "shuffleWriteRecords": 70,
             "memoryBytesSpilled": 0, "diskBytesSpilled": 0, "name": "map at etl.py:10"}
        ]}]),
        "executors" => json!([{"type": "send_spark_executors", "executors": [
            {"id": "driver", "hostPort": "10.0.0.1:41000", "isActive": true, "rddBlocks": 0,
             "memoryUsed": 1024, "diskUsed": 0, "totalCores": 0, "maxTasks": 0,
             "activeTasks": 0, "failedTasks": 0, "completedTasks": 0, "totalTasks": 0,
             "totalDuration": 0, "totalInputBytes": 0, "totalShuffleRead": 0,
             "totalShuffleWrite": 0, "maxMemory": 455501414},
            {"id": "1", "hostPort": "10.0.0.2:42000", "isActive": true, "rddBlocks": 4,
             "memoryUsed": 2048, "diskUsed": 0, "totalCores": 4, "maxTasks": 4,
             "activeTasks": 0, "failedTasks": 1, "completedTasks": 26, "totalTasks": 27,
             "totalDuration": 3900, "totalInputBytes": 65536, "totalShuffleRead": 4096,
             "totalShuffleWrite": 4096, "maxMemory": 2147483648_u64}
        ]}]),
        "rdd" => json!([{"type": "send_spark_rdds", "rdds": [
            {"id": 3, "name": "cached-input", "numPartitions": 4, "numCachedPartitions": 4,
             "storageLevel": "Memory Deserialized 1x Replicated", "memoryUsed": 2048,
             "diskUsed": 0}
        ]}]),
        // A batch application has no streaming listener, and Spark says so with a 404.
        _ if path.ends_with("/streaming/statistics") => json!([{"type": "send_spark_error",
            "status": 404, "message": "no streaming listener attached to nightly-etl"}]),
        _ => json!([{"type": "send_spark_error", "status": 404, "message": "not modelled"}]),
    }
}

#[tokio::test]
async fn datadogs_spark_integration_reads_the_models_application() -> E2EResult<()> {
    // Fail before starting anything when the check is not installed.
    check_root()?;
    let config = NetGetConfig::new(
        "Start an Apache Spark REST API on port {AVAILABLE_PORT}. SPARK-DATADOG-STARTUP-TURN.",
    )
    .with_mock(|mock| {
        mock.on_instruction_containing("SPARK-DATADOG-STARTUP-TURN")
            .respond_with_actions(json!([{
                "type": "open_server", "port": 0, "base_stack": "spark",
                "instruction": "A Spark driver running the nightly ETL; one job failed."
            }]))
            .expect_calls(1)
            .and()
            .on_event("spark_request")
            .respond_with_actions_from_event(answer)
            .expect_calls(6)
            .and()
    });
    let server = start_netget_server(config).await?;
    let report = run_check(&format!("http://127.0.0.1:{}", server.port)).await?;
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;

    assert_eq!(report["error"], "", "the check run raised: {report}");
    // The static version banner, recorded as the check's version metadata.
    assert_eq!(report["version"], "3.5.1");

    let app = "app_name:nightly-etl";
    // Jobs: one count per job, tagged with its status, id and stage ids.
    assert_eq!(
        values(
            &report,
            "spark.job.count",
            &[
                app,
                "status:succeeded",
                "job_id:0",
                "stage_id:0",
                "stage_id:1"
            ]
        ),
        vec![1.0]
    );
    assert_eq!(
        values(
            &report,
            "spark.job.count",
            &[app, "status:failed", "job_id:1", "stage_id:2"]
        ),
        vec![1.0]
    );
    assert_eq!(
        values(&report, "spark.job.num_tasks", &["job_id:0"]),
        vec![12.0]
    );
    assert_eq!(
        values(&report, "spark.job.num_failed_tasks", &["job_id:1"]),
        vec![1.0]
    );

    // Stages.
    assert_eq!(
        values(&report, "spark.stage.count", &[app, "status:complete"]).len(),
        2
    );
    assert_eq!(
        values(&report, "spark.stage.count", &[app, "status:failed"]),
        vec![1.0]
    );
    assert_eq!(
        values(&report, "spark.stage.executor_run_time", &["stage_id:0"]),
        vec![2400.0]
    );
    assert_eq!(
        values(
            &report,
            "spark.stage.shuffle_write_records",
            &["stage_id:0"]
        ),
        vec![70.0]
    );

    // Executors: the driver's metrics and the executor's, kept apart by the check.
    assert_eq!(
        values(&report, "spark.driver.memory_used", &[app]),
        vec![1024.0]
    );
    assert_eq!(
        values(&report, "spark.executor.total_tasks", &[app]),
        vec![27.0]
    );
    assert_eq!(
        values(
            &report,
            "spark.executor.id.total_tasks",
            &[app, "executor_id:1"]
        ),
        vec![27.0]
    );
    assert_eq!(values(&report, "spark.executor.count", &[app]), vec![2.0]);

    // Cached RDDs: the endpoint the server could not answer before.
    assert_eq!(values(&report, "spark.rdd.count", &[app]), vec![1.0]);
    assert_eq!(
        values(&report, "spark.rdd.memory_used", &[app]),
        vec![2048.0]
    );
    assert_eq!(
        values(&report, "spark.rdd.num_cached_partitions", &[app]),
        vec![4.0]
    );

    // Service checks: the driver was reached, and the run ended OK (0). The CRITICALs (2) in
    // between are the streaming-statistics 404 and the absent /metrics/json, which a real
    // non-streaming Spark driver produces too.
    let driver = &report["service_checks"]["spark.driver.can_connect"];
    assert_eq!(
        driver
            .as_array()
            .map(|s| s.iter().map(|x| x["status"].clone()).collect::<Vec<_>>()),
        Some(vec![json!(0)]),
        "{report}"
    );
    let am = report["service_checks"]["spark.application_master.can_connect"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert_eq!(
        am.last().map(|s| s["status"].clone()),
        Some(json!(0)),
        "{report}"
    );
    assert!(
        am.iter().all(|s| s["status"] == 0
            || s["message"]
                .as_str()
                .is_some_and(|m| m.contains("streaming/statistics") || m.contains("metrics/json"))),
        "a CRITICAL other than streaming statistics or the metrics servlet: {am:?}"
    );
    Ok(())
}
