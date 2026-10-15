# Spark client tests

Two files, both under `--features tcp,spark`:

| file | what | peer |
|---|---|---|
| `real_server_test.rs` | the client with the model mocked, against Apache Spark itself | Spark 4.2.0: a live driver UI, and the History Server |
| `request_test.rs` | action → URL, id validation, the endpoint rule, and every response bound | none, or a scripted HTTP server for the bounds |

## Peers

`install_peers.sh <root>` downloads the official `spark-4.2.0-bin-hadoop3.tgz` (from
downloads.apache.org, falling back to archive.apache.org), checks its pinned SHA-512, unpacks it
and prints `export NETGET_SPARK_HOME=…`. It needs a JDK 17 or 21 (`JAVA_HOME` or `java` on
`PATH`) and python3 ≥ 3.10; pyspark and py4j come inside the distribution, so nothing is
pip-installed. **Without `NETGET_SPARK_HOME` every real-server test fails** and names the
script; it never skips.

`evidence_app.py` is the application: a one-stage `count` and a two-stage `reduceByKey` (job
group `netget`), a DataFrame `groupBy().count()` (group `netget-sql`, also a SQL execution),
and a job whose task raises (group `netget-failing`). It prints `NETGET-SPARK-READY {json}` with
what `SparkContext.statusTracker()` says about every job and stage, then either sleeps (`serve`:
the live UI) or stops (`exit`: the event log is closed for the History Server).

* **Live UI** — `spark-submit … --conf spark.ui.port={port} evidence_app.py serve` under
  `RealServer`, ready on the report line. `spark.port.maxRetries=0` makes a lost port race exit
  rather than silently move to port+1.
* **History Server** — the same application run to completion with
  `spark.eventLog.enabled=true`, `spark.eventLog.compress=false` into a temp dir, then
  `spark-class org.apache.spark.deploy.history.HistoryServer` with
  `spark.history.fs.update.interval=1s`, ready on `Bound HistoryServer`; the harness waits until
  it lists the application before NetGet starts. Spark 4.2 writes the event log as a rolling
  `eventlog_v2_<app>/events_1_<app>` directory; `event_log()` reads every file under the dir.

## What is asserted

`WireTap` is a recording TCP relay between NetGet and Spark: it keeps the request line of every
HTTP request that crossed it, because Spark keeps no request log. Each chain asserts the **exact
set** of request lines (and their count) the model's actions name.

| test | LLM calls | asserts |
|---|---|---|
| `spark_client_reads_a_live_driver_ui` | 10 | the application; every job's status, group and stage ids = statusTracker's; the stage the model picked out of the shuffle job (name, task counts) and its task summary (shuffle records read); the failed stage and its failure reason; the driver's completed and failed task counts = the sum over stages; `spark.app.id`/`spark.app.name`/`spark.ui.port` in the environment; the SQL execution's jobs = the `netget-sql` group's; the plan (`HashAggregate`, nodes); 10 request lines |
| `spark_client_reads_a_history_server` | 7 | against the event log: app id, name, user, `duration` = ApplicationEnd − ApplicationStart; every job's stage ids (JobStart) and result (JobEnd); every stage attempt's status — COMPLETE/FAILED from StageCompleted, SKIPPED for a stage a job listed and never ran — with name and task count; the failed job read on its own; Spark's own `404 unknown job: 999999`; 6 request lines |
| `followup_chain_stops_at_the_bound` | 8 | `decision=followup_depth`, and exactly 1 + `MAX_FOLLOWUP_DEPTH` version requests on the wire |
| `llm_failure_reads_nothing` | 1 | `decision=fail_closed_llm_error`, and only the connect probe on the wire |

Mutation-checked: dropping the model's actions fails both chains; removing the follow-up bound
fails the bound test; sending a request when the model call fails fails the LLM-failure test;
splitting a path segment on `/`, allowing `/` in an app id, removing the size bound and removing
the depth bound each fail `request_test.rs`; defaulting a missing target fails the endpoint
test.

## Running

```bash
sh tests/client/spark/install_peers.sh /tmp/spark-peers
export NETGET_SPARK_HOME=/tmp/spark-peers/spark-4.2.0-bin-hadoop3
./cargo-isolated.sh test --no-default-features --features tcp,spark --test client -- client::spark:: --test-threads=4
```

Each real-server test starts its own JVM (~6 s to the report line on an M-series Mac). The
`protocol-pairs.yml` job `spark` runs the suite in CI with Temurin 21.
