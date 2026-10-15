//! The Spark client with the model in the loop, against **Apache Spark itself** — never
//! NetGet's own Spark server:
//!
//! * the **live driver UI** of a running PySpark application (`spark.ui.port`), and
//! * Spark's own **History Server**, over the event log the same application writes when it is
//!   run to completion.
//!
//! The application (`evidence_app.py`) runs a one-stage job, a shuffled two-stage job, a
//! DataFrame aggregation (a SQL execution) and a job that fails on purpose, then prints what
//! Spark itself says about that work through `SparkContext.statusTracker()`. Every result the
//! client hands the model is checked against that report — for the History Server, against the
//! `SparkListener` events in the event log Spark wrote, which is Spark's own record and not the
//! REST layer under test.
//!
//! Condition 4 of the client bar — the client acts on the model's answer, asserted on the wire —
//! is asserted through [`WireTap`], a recording TCP relay between NetGet and Spark: the request
//! lines Spark received are compared with the requests the model's actions name, including the
//! stage the model picked out of a job and the SQL execution it picked out of a list.
//!
//! **No test here skips.** Without `NETGET_SPARK_HOME` (from `install_peers.sh`), or without a
//! JDK and python3, every test fails and says how to install them.
//!
//! LLM calls: 10 (live UI chain), 7 (History Server chain), 8 (follow-up bound), 1 (LLM failure).
//!
//!   sh tests/client/spark/install_peers.sh /tmp/spark-peers && export NETGET_SPARK_HOME=...
//!   ./cargo-isolated.sh test --no-default-features --features tcp,spark --test client -- client::spark:: --test-threads=4

use crate::helpers::real_server::{run_tool, InstallHint, RealServer};
use crate::helpers::*;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const SPARK: InstallHint = InstallHint {
    brew: "openjdk@21 python@3.12, then `sh tests/client/spark/install_peers.sh <dir>` and \
           export the NETGET_SPARK_HOME it prints",
    apt: "openjdk-21-jre-headless python3, then `sh tests/client/spark/install_peers.sh <dir>` \
          and export the NETGET_SPARK_HOME it prints",
};

/// The distribution `install_peers.sh` unpacked.
fn spark_home() -> E2EResult<PathBuf> {
    let home = std::env::var_os("NETGET_SPARK_HOME")
        .map(PathBuf::from)
        .ok_or(
            "NETGET_SPARK_HOME is not set. The Spark client's evidence is Apache Spark itself (a \
             live driver UI and the History Server), and this test FAILS rather than skipping \
             without it: run `sh tests/client/spark/install_peers.sh /some/dir` (needs a JDK 17 \
             or 21 and python3) and export the NETGET_SPARK_HOME it prints.",
        )?;
    if !home.join("python/lib/pyspark.zip").is_file() {
        return Err(format!(
            "{} is not a Spark binary distribution (no python/lib/pyspark.zip); re-run \
             tests/client/spark/install_peers.sh",
            home.display()
        )
        .into());
    }
    Ok(home)
}

/// `$NETGET_SPARK_HOME/bin/<name>`.
fn spark_tool(name: &str) -> E2EResult<String> {
    let path = spark_home()?.join("bin").join(name);
    if !path.is_file() {
        return Err(format!(
            "{} is missing; re-run tests/client/spark/install_peers.sh",
            path.display()
        )
        .into());
    }
    Ok(path.to_string_lossy().into_owned())
}

fn evidence_app() -> String {
    format!(
        "{}/tests/client/spark/evidence_app.py",
        env!("CARGO_MANIFEST_DIR")
    )
}

/// The `NETGET-SPARK-READY {json}` line the application prints once its work is done.
fn report_in(output: &str) -> E2EResult<Value> {
    let line = output
        .lines()
        .find_map(|l| l.split_once("NETGET-SPARK-READY ").map(|(_, r)| r))
        .ok_or("the Spark application printed no NETGET-SPARK-READY report")?;
    Ok(serde_json::from_str(line)?)
}

/// A PySpark application that has done its work and keeps its live UI up on a loopback port.
async fn start_live_app() -> E2EResult<(RealServer, Value)> {
    let app = evidence_app();
    let server = RealServer::builder(&spark_tool("spark-submit")?, SPARK)
        .args([
            "--master",
            "local[2]",
            "--conf",
            "spark.ui.port={port}",
            "--conf",
            "spark.port.maxRetries=0",
            "--conf",
            "spark.ui.showConsoleProgress=false",
            "--conf",
            "spark.driver.host=127.0.0.1",
            "--conf",
            "spark.driver.bindAddress=127.0.0.1",
            &app,
            "serve",
        ])
        .env("SPARK_LOCAL_IP", "127.0.0.1")
        .ready_when_log_matches(r"NETGET-SPARK-READY")
        .startup_timeout(Duration::from_secs(180))
        .start()
        .await?;
    let report = report_in(&server.log())?;
    Ok((server, report))
}

/// Run the application to completion with its event log in `events`, and return its report.
async fn run_completed_app(events: &Path) -> E2EResult<Value> {
    let submit = spark_tool("spark-submit")?;
    let mut cmd = Command::new(&submit);
    cmd.args(["--master", "local[2]"])
        .args(["--conf", "spark.ui.enabled=false"])
        .args(["--conf", "spark.driver.host=127.0.0.1"])
        .args(["--conf", "spark.driver.bindAddress=127.0.0.1"])
        .args(["--conf", "spark.eventLog.enabled=true"])
        .args(["--conf", "spark.eventLog.compress=false"])
        .arg("--conf")
        .arg(format!("spark.eventLog.dir=file://{}", events.display()))
        .arg(evidence_app())
        .arg("exit")
        .env("SPARK_LOCAL_IP", "127.0.0.1");
    let out = run_tool(cmd, "spark-submit", SPARK).await?;
    report_in(&out)
}

/// Spark's History Server on a loopback port, reading `events`.
async fn start_history_server(events: &Path) -> E2EResult<RealServer> {
    RealServer::builder(&spark_tool("spark-class")?, SPARK)
        .args(["org.apache.spark.deploy.history.HistoryServer"])
        .env(
            "SPARK_HISTORY_OPTS",
            &format!(
                "-Dspark.history.fs.logDirectory=file://{} -Dspark.history.ui.port={{port}} \
                 -Dspark.history.fs.update.interval=1s",
                events.display()
            ),
        )
        .env("SPARK_LOCAL_IP", "127.0.0.1")
        .ready_when_log_matches(r"Bound HistoryServer")
        .startup_timeout(Duration::from_secs(120))
        .start()
        .await
}

/// Wait until the History Server has scanned the event log and lists `app_id`. This is the
/// harness waiting for its peer, not evidence: the evidence is what NetGet reads afterwards.
async fn wait_until_listed(server: &RealServer, app_id: &str) -> E2EResult<()> {
    let url = format!("http://{}/api/v1/applications", server.addr());
    let http = reqwest::Client::builder().no_proxy().build()?;
    let deadline = std::time::Instant::now() + Duration::from_secs(90);
    loop {
        if let Ok(resp) = http.get(&url).send().await {
            if resp.text().await.unwrap_or_default().contains(app_id) {
                return Ok(());
            }
        }
        if std::time::Instant::now() >= deadline {
            return Err(format!("the History Server never listed {app_id}").into());
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

/// Every `SparkListener` event in the event log(s) under `dir`, in order.
fn event_log(dir: &Path) -> E2EResult<Vec<Value>> {
    let mut files = Vec::new();
    let mut pending = vec![dir.to_path_buf()];
    while let Some(d) = pending.pop() {
        for entry in std::fs::read_dir(&d)? {
            let path = entry?.path();
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            if path.is_dir() {
                pending.push(path);
            } else if !name.starts_with('.') && !name.starts_with("appstatus") {
                files.push(path);
            }
        }
    }
    files.sort();
    let mut events = Vec::new();
    for f in files {
        for line in std::fs::read_to_string(&f)?.lines() {
            if !line.trim().is_empty() {
                events.push(serde_json::from_str(line)?);
            }
        }
    }
    if events.is_empty() {
        return Err(format!("no event log under {}", dir.display()).into());
    }
    Ok(events)
}

/// A recording TCP relay: NetGet talks to it, it talks to Spark, and it keeps the request line
/// of every HTTP request that crossed it. Spark keeps no request log of its own, so this is
/// where "what did the client actually ask for" is read from the wire.
struct WireTap {
    addr: String,
    requests: Arc<Mutex<Vec<String>>>,
    task: tokio::task::JoinHandle<()>,
}

impl WireTap {
    async fn start(target: String) -> E2EResult<WireTap> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?.to_string();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::clone(&requests);
        let task = tokio::spawn(async move {
            let mut relays = tokio::task::JoinSet::new();
            while let Ok((mut down, _)) = listener.accept().await {
                let target = target.clone();
                let seen = Arc::clone(&seen);
                relays.spawn(async move {
                    let Ok(up) = tokio::net::TcpStream::connect(&target).await else {
                        return;
                    };
                    let (mut up_r, mut up_w) = up.into_split();
                    let (mut down_r, mut down_w) = down.split();
                    let to_spark = async {
                        let mut buf = vec![0u8; 16 * 1024];
                        let mut pending = String::new();
                        loop {
                            let n = match down_r.read(&mut buf).await {
                                Ok(0) | Err(_) => break,
                                Ok(n) => n,
                            };
                            pending.push_str(&String::from_utf8_lossy(&buf[..n]));
                            while let Some(end) = pending.find("\r\n") {
                                let line: String = pending.drain(..end + 2).collect();
                                if let Some(rest) = line.strip_prefix("GET ") {
                                    let target = rest.trim_end().trim_end_matches(" HTTP/1.1");
                                    seen.lock().unwrap().push(target.to_string());
                                }
                            }
                            if up_w.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                        let _ = up_w.shutdown().await;
                    };
                    let from_spark = tokio::io::copy(&mut up_r, &mut down_w);
                    let _ = tokio::join!(to_spark, from_spark);
                });
            }
        });
        Ok(WireTap {
            addr,
            requests,
            task,
        })
    }

    fn requests(&self) -> Vec<String> {
        self.requests.lock().unwrap().clone()
    }
}

impl Drop for WireTap {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Events the mock model saw, by `operation` (and `error` for `spark_error`).
type Seen = Arc<Mutex<BTreeMap<String, Value>>>;

fn keep(seen: &Seen, key: &str, e: &Value) {
    seen.lock().unwrap().insert(key.to_string(), e.clone());
}

fn ids(v: &Value) -> Vec<u64> {
    let mut out: Vec<u64> = v
        .as_array()
        .map(|a| a.iter().filter_map(Value::as_u64).collect())
        .unwrap_or_default();
    out.sort();
    out
}

/// The live UI: list the application, its jobs, executors, environment and SQL executions; the
/// model then picks the shuffle job's result stage (read with its task summary), the failed
/// stages, and the first SQL execution with its plan. Every answer is checked against what the
/// application itself reported, and every request against what crossed the wire.
#[tokio::test]
async fn spark_client_reads_a_live_driver_ui() -> E2EResult<()> {
    let (server, report) = start_live_app().await?;
    let result = live_chain(&server, &report).await;
    server.with_log(result)
}

async fn live_chain(server: &RealServer, report: &Value) -> E2EResult<()> {
    let tap = WireTap::start(server.addr()).await?;
    let addr = tap.addr.clone();
    let seen: Seen = Arc::default();
    let s = |key: &'static str| {
        let seen = Arc::clone(&seen);
        move |e: &Value| keep(&seen, key, e)
    };
    let (k_apps, k_jobs, k_stage, k_failed, k_summary, k_exec, k_env, k_sql, k_plan) = (
        s("list_applications"),
        s("list_jobs"),
        s("get_stage"),
        s("list_stages"),
        s("get_task_summary"),
        s("list_executors"),
        s("get_environment"),
        s("list_sql_executions"),
        s("get_sql_execution"),
    );
    let config = NetGetConfig::new(format!(
        "Look at the Spark application whose UI is at {addr}. SPARK-LIVE-STARTUP-TURN."
    ))
    .with_mock(move |mock| {
        mock.on_instruction_containing("SPARK-LIVE-STARTUP-TURN")
            .respond_with_actions(json!([{
                "type": "open_client",
                "protocol": "Spark",
                "remote_addr": addr,
                "instruction": "Find out what this Spark application did and why a job failed."
            }]))
            .expect_calls(1)
            .and()
            .on_event("spark_connected")
            .and_event_data_contains("spark_version", "4.2.0")
            .respond_with_actions(json!([{"type": "list_applications"}]))
            .expect_calls(1)
            .and()
            .on_event("spark_applications")
            .respond_with_actions_from_event(move |e| {
                k_apps(e);
                let id = e["applications"][0]["id"].clone();
                json!([
                    {"type": "list_jobs", "app_id": id},
                    {"type": "list_executors", "app_id": id},
                    {"type": "get_environment", "app_id": id},
                    {"type": "list_sql_executions", "app_id": id}
                ])
            })
            .expect_calls(1)
            .and()
            .on_event("spark_jobs")
            .respond_with_actions_from_event(move |e| {
                k_jobs(e);
                let id = e["app_id"].clone();
                let jobs = e["jobs"].as_array().cloned().unwrap_or_default();
                // The model's choice: the result stage of the job that shuffled.
                let stage = jobs
                    .iter()
                    .filter(|j| j["jobGroup"] == "netget")
                    .find(|j| j["stageIds"].as_array().map(Vec::len) == Some(2))
                    .map(|j| ids(&j["stageIds"])[1])
                    .unwrap_or(9999);
                json!([
                    {"type": "get_stage", "app_id": id, "stage_id": stage, "stage_attempt_id": 0},
                    {"type": "get_task_summary", "app_id": id, "stage_id": stage,
                     "stage_attempt_id": 0, "quantiles": [0.5, 0.95]},
                    {"type": "list_stages", "app_id": id, "status": "failed"}
                ])
            })
            .expect_calls(1)
            .and()
            .on_event("spark_stages")
            .and_event_data_contains("operation", "get_stage")
            .respond_with_actions_from_event(move |e| {
                k_stage(e);
                json!([])
            })
            .expect_calls(1)
            .and()
            .on_event("spark_stages")
            .and_event_data_contains("operation", "list_stages")
            .respond_with_actions_from_event(move |e| {
                k_failed(e);
                json!([])
            })
            .expect_calls(1)
            .and()
            .on_event("spark_task_summary")
            .respond_with_actions_from_event(move |e| {
                k_summary(e);
                json!([])
            })
            .expect_calls(1)
            .and()
            .on_event("spark_executors")
            .respond_with_actions_from_event(move |e| {
                k_exec(e);
                json!([])
            })
            .expect_calls(1)
            .and()
            .on_event("spark_environment")
            .respond_with_actions_from_event(move |e| {
                k_env(e);
                json!([])
            })
            .expect_calls(1)
            .and()
            .on_event("spark_sql_executions")
            .and_event_data_contains("operation", "list_sql_executions")
            .respond_with_actions_from_event(move |e| {
                k_sql(e);
                json!([{"type": "get_sql_execution", "app_id": e["app_id"],
                        "execution_id": e["executions"][0]["id"]}])
            })
            .expect_calls(1)
            .and()
            .on_event("spark_sql_executions")
            .and_event_data_contains("operation", "get_sql_execution")
            .respond_with_actions_from_event(move |e| {
                k_plan(e);
                json!([{"type": "disconnect"}])
            })
            .expect_calls(1)
            .and()
            .on_event("spark_error")
            .respond_with_actions(json!([]))
            .expect_calls(0)
            .and()
    });

    let client = start_netget_client(config).await?;
    client.wait_for_mocks(120).await;
    client.verify_mocks().await?;
    let seen = seen.lock().unwrap().clone();
    client.stop().await?;

    let app_id = report["app_id"].as_str().ok_or("no app_id in the report")?;
    let jobs = report["jobs"].as_array().ok_or("no jobs in the report")?;
    let stages = report["stages"]
        .as_array()
        .ok_or("no stages in the report")?;

    // The application, as the live UI lists it.
    let apps = &seen["list_applications"]["applications"];
    assert_eq!(apps.as_array().map(Vec::len), Some(1), "{apps}");
    assert_eq!(apps[0]["id"], app_id);
    assert_eq!(apps[0]["name"], "netget-evidence");
    assert_eq!(apps[0]["attempts"][0]["completed"], false);
    assert_eq!(apps[0]["attempts"][0]["appSparkVersion"], "4.2.0");

    // Every job, with Spark's own status and stage ids for it.
    let expected: BTreeMap<u64, (String, String, Vec<u64>)> = jobs
        .iter()
        .map(|j| {
            (
                j["jobId"].as_u64().unwrap(),
                (
                    j["status"].as_str().unwrap().to_string(),
                    j["group"].as_str().unwrap().to_string(),
                    ids(&j["stageIds"]),
                ),
            )
        })
        .collect();
    let got: BTreeMap<u64, (String, String, Vec<u64>)> = seen["list_jobs"]["jobs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|j| {
            (
                j["jobId"].as_u64().unwrap(),
                (
                    j["status"].as_str().unwrap_or_default().to_string(),
                    j["jobGroup"].as_str().unwrap_or_default().to_string(),
                    ids(&j["stageIds"]),
                ),
            )
        })
        .collect();
    assert_eq!(
        got, expected,
        "the jobs NetGet decoded must be the jobs Spark ran"
    );

    // The stage the model chose, and its task summary.
    let shuffle_job = jobs
        .iter()
        .find(|j| j["group"] == "netget" && ids(&j["stageIds"]).len() == 2)
        .ok_or("no two-stage job in the report")?;
    let chosen = ids(&shuffle_job["stageIds"])[1];
    let truth = stages
        .iter()
        .find(|s| s["stageId"] == chosen)
        .ok_or("the chosen stage is not in the report")?;
    let stage = &seen["get_stage"]["stages"][0];
    assert_eq!(seen["get_stage"]["count"], 1);
    assert_eq!(stage["stageId"], chosen);
    assert_eq!(stage["attemptId"], 0);
    assert_eq!(stage["status"], "COMPLETE");
    assert_eq!(stage["name"], truth["name"]);
    assert_eq!(stage["numTasks"], truth["numTasks"]);
    assert_eq!(stage["numCompleteTasks"], truth["numCompletedTasks"]);
    assert!(stage.get("tasks").is_none(), "task lists are never read");
    let summary = &seen["get_task_summary"];
    assert_eq!(summary["stage_id"], chosen);
    assert_eq!(summary["quantiles"], json!([0.5, 0.95]));
    assert_eq!(
        summary["metrics"]["executorRunTime"]
            .as_array()
            .map(Vec::len),
        Some(2)
    );
    assert!(
        summary["metrics"]["shuffleReadMetrics"]["readRecords"][1]
            .as_f64()
            .unwrap_or(0.0)
            > 0.0,
        "the result stage of a reduceByKey reads shuffled records: {summary}"
    );

    // The failed stage, with Spark's failure reason.
    let failing = jobs
        .iter()
        .find(|j| j["group"] == "netget-failing")
        .ok_or("no failing job in the report")?;
    assert_eq!(failing["status"], "FAILED");
    let failed = seen["list_stages"]["stages"].as_array().unwrap();
    assert_eq!(
        failed
            .iter()
            .map(|s| s["stageId"].as_u64().unwrap())
            .collect::<Vec<_>>(),
        ids(&failing["stageIds"])
    );
    assert!(failed.iter().all(|s| s["status"] == "FAILED"));
    assert!(
        failed[0]["failureReason"]
            .as_str()
            .unwrap_or_default()
            .contains("this task fails on purpose"),
        "{failed:?}"
    );

    // The executors: the driver ran every task Spark counted.
    let driver = seen["list_executors"]["executors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|x| x["id"] == "driver")
        .cloned()
        .ok_or("no driver executor")?;
    let completed: u64 = stages
        .iter()
        .map(|s| s["numCompletedTasks"].as_u64().unwrap())
        .sum();
    let failed_tasks: u64 = stages
        .iter()
        .map(|s| s["numFailedTasks"].as_u64().unwrap())
        .sum();
    assert_eq!(
        driver["completedTasks"].as_u64(),
        Some(completed),
        "{driver}"
    );
    assert_eq!(
        driver["failedTasks"].as_u64(),
        Some(failed_tasks),
        "{driver}"
    );

    // The environment Spark reports for itself.
    let env = &seen["get_environment"];
    assert_eq!(env["spark_properties"]["spark.app.id"], app_id);
    assert_eq!(env["spark_properties"]["spark.app.name"], "netget-evidence");
    assert_eq!(
        env["spark_properties"]["spark.ui.port"],
        server.port.to_string()
    );
    assert!(env["runtime"]["javaVersion"]
        .as_str()
        .is_some_and(|v| !v.is_empty()));
    assert!(env["system_property_count"].as_u64().unwrap_or(0) > 0);

    // The SQL execution ran exactly the jobs of the DataFrame group, and its plan aggregates.
    let sql_jobs: Vec<u64> = jobs
        .iter()
        .filter(|j| j["group"] == "netget-sql")
        .map(|j| j["jobId"].as_u64().unwrap())
        .collect();
    let execs = seen["list_sql_executions"]["executions"]
        .as_array()
        .unwrap();
    assert!(
        execs
            .iter()
            .any(|x| x["status"] == "COMPLETED" && ids(&x["successJobIds"]) == sql_jobs),
        "no SQL execution ran jobs {sql_jobs:?}: {execs:?}"
    );
    let plan = &seen["get_sql_execution"]["executions"][0];
    assert_eq!(plan["id"], execs[0]["id"]);
    assert!(plan["planDescription"]
        .as_str()
        .unwrap_or_default()
        .contains("HashAggregate"));
    assert!(plan["nodes"].as_array().is_some_and(|n| !n.is_empty()));

    // On the wire: exactly the requests the model's actions name, and nothing else.
    let base = format!("/api/v1/applications/{app_id}");
    let sql_id = execs[0]["id"].as_u64().unwrap();
    let want: BTreeSet<String> = [
        "/api/v1/version".to_string(),
        "/api/v1/applications".to_string(),
        format!("{base}/jobs"),
        format!("{base}/executors"),
        format!("{base}/environment"),
        format!("{base}/sql?details=false&planDescription=false&offset=0&length=50"),
        format!("{base}/stages/{chosen}/0?details=false"),
        format!("{base}/stages/{chosen}/0/taskSummary?quantiles=0.5%2C0.95"),
        format!("{base}/stages?status=failed&details=false"),
        format!("{base}/sql/{sql_id}?details=true&planDescription=true"),
    ]
    .into_iter()
    .collect();
    let wire = tap.requests();
    assert_eq!(wire.len(), want.len(), "requests on the wire: {wire:#?}");
    assert_eq!(wire.into_iter().collect::<BTreeSet<_>>(), want);
    Ok(())
}

/// The History Server, over the event log a completed run wrote: the completed application,
/// every job and every stage attempt (skipped ones included), the failed job read on its own,
/// and Spark's 404 for a job that does not exist — each checked against the event log.
#[tokio::test]
async fn spark_client_reads_a_history_server() -> E2EResult<()> {
    let events = tempfile::tempdir()?;
    let report = run_completed_app(events.path()).await?;
    let server = start_history_server(events.path()).await?;
    let result = history_chain(&server, &report, events.path()).await;
    server.with_log(result)
}

async fn history_chain(server: &RealServer, report: &Value, events: &Path) -> E2EResult<()> {
    let app_id = report["app_id"]
        .as_str()
        .ok_or("no app_id in the report")?
        .to_string();
    wait_until_listed(server, &app_id).await?;
    let tap = WireTap::start(server.addr()).await?;
    let addr = tap.addr.clone();
    let seen: Seen = Arc::default();
    let s = |key: &'static str| {
        let seen = Arc::clone(&seen);
        move |e: &Value| keep(&seen, key, e)
    };
    let (k_apps, k_jobs, k_job, k_stages, k_err) = (
        s("list_applications"),
        s("list_jobs"),
        s("get_job"),
        s("list_stages"),
        s("error"),
    );
    let config = NetGetConfig::new(format!(
        "Look at the Spark History Server at {addr}. SPARK-HISTORY-STARTUP-TURN."
    ))
    .with_mock(move |mock| {
        mock.on_instruction_containing("SPARK-HISTORY-STARTUP-TURN")
            .respond_with_actions(json!([{
                "type": "open_client",
                "protocol": "Spark",
                "remote_addr": addr,
                "startup_params": {"request_timeout_secs": 60},
                "instruction": "Find the failed job of the completed application."
            }]))
            .expect_calls(1)
            .and()
            .on_event("spark_connected")
            .respond_with_actions(json!([{"type": "list_applications", "status": "completed"}]))
            .expect_calls(1)
            .and()
            .on_event("spark_applications")
            .respond_with_actions_from_event(move |e| {
                k_apps(e);
                let id = e["applications"][0]["id"].clone();
                json!([
                    {"type": "list_jobs", "app_id": id},
                    {"type": "list_stages", "app_id": id},
                    {"type": "get_job", "app_id": id, "job_id": 999999}
                ])
            })
            .expect_calls(1)
            .and()
            .on_event("spark_jobs")
            .and_event_data_contains("operation", "list_jobs")
            .respond_with_actions_from_event(move |e| {
                k_jobs(e);
                let failed = e["jobs"]
                    .as_array()
                    .and_then(|j| j.iter().find(|j| j["status"] == "FAILED"))
                    .map(|j| j["jobId"].clone())
                    .unwrap_or(json!(424242));
                json!([{"type": "get_job", "app_id": e["app_id"], "job_id": failed}])
            })
            .expect_calls(1)
            .and()
            .on_event("spark_stages")
            .respond_with_actions_from_event(move |e| {
                k_stages(e);
                json!([])
            })
            .expect_calls(1)
            .and()
            .on_event("spark_error")
            .respond_with_actions_from_event(move |e| {
                k_err(e);
                json!([])
            })
            .expect_calls(1)
            .and()
            .on_event("spark_jobs")
            .and_event_data_contains("operation", "get_job")
            .respond_with_actions_from_event(move |e| {
                k_job(e);
                json!([{"type": "disconnect"}])
            })
            .expect_calls(1)
            .and()
    });

    let client = start_netget_client(config).await?;
    client.wait_for_mocks(120).await;
    client.verify_mocks().await?;
    let seen = seen.lock().unwrap().clone();
    client.stop().await?;

    // Spark's own record of the run.
    let log = event_log(events)?;
    let of = |name: &str| -> Vec<&Value> { log.iter().filter(|e| e["Event"] == name).collect() };
    let start = of("SparkListenerApplicationStart")[0];
    let end = of("SparkListenerApplicationEnd")[0];
    assert_eq!(start["App ID"], app_id.as_str());

    let app = &seen["list_applications"]["applications"][0];
    assert_eq!(seen["list_applications"]["count"], 1);
    assert_eq!(app["id"], app_id.as_str());
    assert_eq!(app["name"], start["App Name"]);
    let attempt = &app["attempts"][0];
    assert_eq!(attempt["completed"], true);
    assert_eq!(attempt["sparkUser"], start["User"]);
    assert_eq!(
        attempt["duration"].as_u64(),
        Some(end["Timestamp"].as_u64().unwrap() - start["Timestamp"].as_u64().unwrap()),
        "the duration must be ApplicationEnd - ApplicationStart from the event log"
    );

    // Jobs: JobStart's stage ids and JobEnd's result.
    let mut expected_jobs = BTreeMap::new();
    for js in of("SparkListenerJobStart") {
        let id = js["Job ID"].as_u64().unwrap();
        let result = of("SparkListenerJobEnd")
            .into_iter()
            .find(|je| je["Job ID"] == id)
            .map(|je| {
                je["Job Result"]["Result"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string()
            })
            .unwrap_or_default();
        let status = match result.as_str() {
            "JobSucceeded" => "SUCCEEDED",
            _ => "FAILED",
        };
        expected_jobs.insert(id, (status.to_string(), ids(&js["Stage IDs"])));
    }
    let got_jobs: BTreeMap<u64, (String, Vec<u64>)> = seen["list_jobs"]["jobs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|j| {
            (
                j["jobId"].as_u64().unwrap(),
                (
                    j["status"].as_str().unwrap().to_string(),
                    ids(&j["stageIds"]),
                ),
            )
        })
        .collect();
    assert_eq!(got_jobs, expected_jobs, "jobs must match the event log");
    assert_eq!(
        got_jobs.len(),
        report["jobs"].as_array().map_or(0, Vec::len),
        "and the application's own count"
    );

    // Stage attempts: completed or failed as StageCompleted says, skipped when a job listed the
    // stage and it never ran.
    let mut expected_stages: BTreeMap<(u64, u64), (String, Value, Value)> = BTreeMap::new();
    for js in of("SparkListenerJobStart") {
        for info in js["Stage Infos"].as_array().unwrap() {
            expected_stages.insert(
                (info["Stage ID"].as_u64().unwrap(), 0),
                ("SKIPPED".into(), Value::Null, Value::Null),
            );
        }
    }
    for sc in of("SparkListenerStageCompleted") {
        let info = &sc["Stage Info"];
        let key = (
            info["Stage ID"].as_u64().unwrap(),
            info["Stage Attempt ID"].as_u64().unwrap(),
        );
        let status = if info.get("Failure Reason").is_some() {
            "FAILED"
        } else {
            "COMPLETE"
        };
        expected_stages.insert(
            key,
            (
                status.into(),
                info["Stage Name"].clone(),
                info["Number of Tasks"].clone(),
            ),
        );
    }
    let got_stages: BTreeMap<(u64, u64), (String, Value, Value)> = seen["list_stages"]["stages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| {
            let status = s["status"].as_str().unwrap().to_string();
            let (name, tasks) = if status == "SKIPPED" {
                (Value::Null, Value::Null)
            } else {
                (s["name"].clone(), s["numTasks"].clone())
            };
            (
                (
                    s["stageId"].as_u64().unwrap(),
                    s["attemptId"].as_u64().unwrap(),
                ),
                (status, name, tasks),
            )
        })
        .collect();
    assert_eq!(
        got_stages, expected_stages,
        "stage attempts must match the event log"
    );

    // The failed job the model picked, read on its own.
    let job = &seen["get_job"]["jobs"][0];
    let (failed_id, (_, failed_stages)) = expected_jobs
        .iter()
        .find(|(_, (s, _))| s == "FAILED")
        .ok_or("the event log has no failed job")?;
    assert_eq!(job["jobId"].as_u64(), Some(*failed_id));
    assert_eq!(job["status"], "FAILED");
    assert_eq!(job["numFailedTasks"], 1);
    assert_eq!(ids(&job["stageIds"]), *failed_stages);

    // Spark's own 404 for a job that does not exist.
    let err = &seen["error"];
    assert_eq!(err["operation"], "get_job");
    assert_eq!(err["http_status"], 404);
    assert_eq!(err["message"], "unknown job: 999999");

    let base = format!("/api/v1/applications/{app_id}");
    let want: BTreeSet<String> = [
        "/api/v1/version".to_string(),
        "/api/v1/applications?status=completed".to_string(),
        format!("{base}/jobs"),
        format!("{base}/stages?details=false"),
        format!("{base}/jobs/999999"),
        format!("{base}/jobs/{failed_id}"),
    ]
    .into_iter()
    .collect();
    let wire = tap.requests();
    assert_eq!(wire.len(), want.len(), "requests on the wire: {wire:#?}");
    assert_eq!(wire.into_iter().collect::<BTreeSet<_>>(), want);
    Ok(())
}

/// A model that answers every result with another request stops at MAX_FOLLOWUP_DEPTH: the
/// connected turn and seven follow-ups, so Spark sees the connect probe and eight more.
#[tokio::test]
async fn followup_chain_stops_at_the_bound() -> E2EResult<()> {
    let (server, _) = start_live_app().await?;
    let result = followup_bound(&server).await;
    server.with_log(result)
}

async fn followup_bound(server: &RealServer) -> E2EResult<()> {
    let tap = WireTap::start(server.addr()).await?;
    let addr = tap.addr.clone();
    let depth = ::netget::client::spark::MAX_FOLLOWUP_DEPTH as usize;
    let config = NetGetConfig::new(format!(
        "Look at the Spark UI at {addr}. SPARK-LOOP-STARTUP-TURN."
    ))
    .with_mock(move |mock| {
        mock.on_instruction_containing("SPARK-LOOP-STARTUP-TURN")
            .respond_with_actions(json!([{
                "type": "open_client",
                "protocol": "Spark",
                "remote_addr": addr,
                "instruction": "Ask for the version forever."
            }]))
            .expect_calls(1)
            .and()
            .on_event("spark_connected")
            .respond_with_actions(json!([{"type": "get_version"}]))
            .expect_calls(1)
            .and()
            .on_event("spark_version")
            .respond_with_actions(json!([{"type": "get_version"}]))
            .expect_calls(depth - 1)
            .and()
    });
    let client = start_netget_client(config).await?;
    client.wait_for_any(&["decision=followup_depth"], 90).await;
    assert!(
        client.output_contains("decision=followup_depth").await,
        "the chain must stop at the bound and say so"
    );
    client.wait_for_mocks(30).await;
    client.verify_mocks().await?;
    let wire = tap.requests();
    assert_eq!(
        wire,
        vec!["/api/v1/version".to_string(); 1 + depth],
        "the connect probe and one request per model turn, then nothing"
    );
    client.stop().await?;
    Ok(())
}

/// When the model cannot be asked, nothing is read on its behalf: Spark sees the connect probe
/// and nothing after it.
#[tokio::test]
async fn llm_failure_reads_nothing() -> E2EResult<()> {
    let (server, _) = start_live_app().await?;
    let result = llm_failure(&server).await;
    server.with_log(result)
}

async fn llm_failure(server: &RealServer) -> E2EResult<()> {
    let tap = WireTap::start(server.addr()).await?;
    let addr = tap.addr.clone();
    let config = NetGetConfig::new(format!(
        "Look at the Spark UI at {addr}. SPARK-FAIL-STARTUP-TURN."
    ))
    .with_mock(move |mock| {
        mock.on_instruction_containing("SPARK-FAIL-STARTUP-TURN")
            .respond_with_actions(json!([{
                "type": "open_client",
                "protocol": "Spark",
                "remote_addr": addr,
                "instruction": "Read everything."
            }]))
            .expect_calls(1)
            .and()
        // No rule answers spark_connected: the mock model fails that call.
    });
    let client = start_netget_client(config).await?;
    client
        .wait_for_any(&["decision=fail_closed_llm_error"], 90)
        .await;
    assert!(
        client
            .output_contains("decision=fail_closed_llm_error")
            .await,
        "the failed turn must be logged as failing closed"
    );
    assert_eq!(
        tap.requests(),
        vec!["/api/v1/version".to_string()],
        "Spark received a request NetGet made without the model"
    );
    client.stop().await?;
    Ok(())
}
