# Spark server E2E tests

Two kinds of evidence:

- `datadog_check_test.rs` — **Datadog's Spark integration** (`datadog_checks.spark`,
  integrations-core tag `spark-7.8.0`), an independent consumer of the monitoring API, run once
  in `spark_driver_mode` against the server through `datadog_check.py` (the Agent replaced by
  `datadog_checks.base`'s stubs). It asserts what the check submitted: job/stage counts and
  their tags, task counts, run times, driver vs executor metrics, executor-level metrics, the
  cached RDD's metrics, the version metadata and the service checks. **Fails rather than skips**
  without `NETGET_DATADOG_SPARK` from `install_datadog_check.sh` (python 3.12+; the check's
  files are fetched at a pinned commit and SHA-256-checked). One mock rule on `spark_request`
  branches on `operation` (and on the path for `streaming/statistics`, answered 404 as a
  non-streaming Spark driver does).
- `e2e_test.rs` — `reqwest` against the documented shapes: success responses are top-level JSON
  **arrays**, and `GET /api/v1/applications/{id}` is the one **object**.

## Mock expectations

Default (mocked) mode, no Ollama. Every test ends with `server.verify_mocks().await?`. Mocks match
on the `spark_request` event's `operation` field so one server handles several endpoints.

## LLM call budget

- `datadogs_spark_integration_reads_the_models_application`: startup (1) + applications, jobs,
  stages, executors, storage/rdd, streaming/statistics (6). Version and `/metrics/json` are
  static. Total 7.
- `test_spark_version_static_and_applications`: startup (1) + applications (1) + one application
  (1). `/api/v1/version` is **static** — no LLM call. Total 3.
- `test_spark_jobs_stages_executors`: startup (1) + jobs (1) + stages (1) + executors (1). Total 4.
- `llm_failure_test`: startup (1) + one unmatched applications request forcing a 5xx. Total ~2.

Suite total ~16 LLM calls across four tests. Localhost only; never contacts external endpoints.

## What each test validates

- Static `/api/v1/version` banner (`{"spark": "..."}`) with no model round-trip.
- `/applications`, `/jobs`, `/stages`, `/executors` are top-level JSON **arrays** (asserted with
  `is_array()`), matching Spark's monitoring API.
- `llm_failure_test`: LLM failure → 5xx JSON *object* with an `error` field, never `200 []`.
  It waits for the socket by retrying the request rather than sleeping a fixed 500ms, and
  the client carries its own 25s timeout so a server that answers *nothing* fails the test
  instead of hanging it.

## Running

```bash
sh tests/server/spark/install_datadog_check.sh /tmp/dd-spark   # once; prints the export
export NETGET_DATADOG_SPARK=/tmp/dd-spark
./cargo-isolated.sh test --no-default-features --features tcp,spark \
    --test server -- spark:: --test-threads=8
```

## The `decision=` tag

`llm_failure_test.rs` asserts more than the 5xx: it requires a log line naming
`/api/v1/applications` and carrying `decision=fail_closed_`, and requires that **no** line
carries `decision=model_`. The status alone cannot carry this, because `send_spark_error` lets
the model choose a 500 or a 503 of its own — so without the tag a backend outage and a model
that decided to answer 500 are the same event in the log.

Spark's other two tagged outcomes are `decision=model_answer` / `decision=model_reject` (split
on whether the model's chosen status is < 400) and `decision=model_silent` (the model answered
with no `spark_response`). The two no-LLM paths, `/api/v1/version` and the 404, log
`decision=static_answer` / `decision=unknown_endpoint` at DEBUG, so they stay in `netget.log`
and off the status stream the harness reads.
