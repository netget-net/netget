# Spark client

NetGet as a reader of Apache Spark's monitoring REST API (`/api/v1`), which both a running
application's **live driver UI** (`spark.ui.port`, 4040 by default) and the **History Server**
(18080) serve. The model decides what to read; Rust owns the URL, the HTTP exchange, the bounds
and the decoding. Feature `spark` (shared with the server, `src/server/spark/`). **Beta** — see
Maturity below.

| file | what |
|---|---|
| `mod.rs` | `resolve_endpoint`, `api_url`, `Api` (one bounded GET → one event), `connect`, the session and turns tasks |
| `actions.rs` | actions, events, `request` (action → validated `ApiCall`), startup parameters, metadata |
| `decode.rs` | the depth check, the parse, and the per-resource projection onto fixed fields |

## The target is fixed, and the model never writes a URL

The client talks to `endpoint_url` exactly as given, else to its `remote_addr` (`host:port`
means `http://host:port`); without either it refuses to start. A base path is allowed (a
History Server behind a gateway: `https://gw/sparkhistory`); a query, a fragment, credentials
or a trailing `/api/v1` are refused. **Redirects are not followed** — a 3xx is a `spark_error`
naming where it pointed. `connect()` reads `GET /api/v1/version` before anything else and
fails the client (`decision=fail_closed_connect`) when the answer is not Spark's
`{"spark": "<version>"}`, so the model is never asked about a target that is not a Spark API.

Every action names its resource with structured ids, and `actions::request` validates each:

| id | accepted |
|---|---|
| `app_id` | 1–128 of `[A-Za-z0-9._-]`, not starting with `.` (`local-…`, `app-…-0000`, `application_…_0001`, `spark-…`) |
| `app_attempt_id` | 1–32 of the same; only for an application the History Server lists with attempts |
| `job_id`, `stage_id`, `stage_attempt_id`, `execution_id` | a whole number ≥ 0 (or its digits as text), at most `i64::MAX` |
| `status` | per resource: applications `completed`/`running`; jobs `running`/`succeeded`/`failed`/`unknown`; stages `active`/`complete`/`pending`/`failed`/`skipped` |
| dates | `2026-10-15` or `2026-10-15T06:00:00.000GMT`, the two forms Spark's `SimpleDateParam` reads |
| `quantiles` | 1–10 numbers in 0..=1 |

`api_url` then pushes each id as **one** percent-encoded path segment under `/api/v1/` on the
base, refuses an empty or dot segment, and checks the result's origin is the base's — so even a
value that skipped validation stays a segment on the target (`request_test.rs` asserts both).

## The conversation

| action | request | event |
|---|---|---|
| `list_applications` | `GET /api/v1/applications?status&minDate&maxDate&minEndDate&maxEndDate&limit` | `spark_applications` |
| `get_application` | `GET …/applications/{app}` | `spark_applications` |
| `list_jobs` | `GET …/applications/{app}[/{attempt}]/jobs?status=…` | `spark_jobs` |
| `get_job` | `…/jobs/{job}` | `spark_jobs` |
| `list_stages` | `…/stages?status=…&details=false` | `spark_stages` |
| `get_stage` | `…/stages/{stage}[/{attempt}]?details=false` | `spark_stages` |
| `get_task_summary` | `…/stages/{stage}/{attempt}/taskSummary?quantiles=…` | `spark_task_summary` |
| `list_executors` | `…/executors`, or `…/allexecutors` with `include_dead` | `spark_executors` |
| `get_environment` | `…/environment` | `spark_environment` |
| `list_sql_executions` | `…/sql?details=false&planDescription=false&offset&length` | `spark_sql_executions` |
| `get_sql_execution` | `…/sql/{id}?details=true&planDescription=true` | `spark_sql_executions` |
| `get_version` | `GET /api/v1/version` | `spark_version` |
| `disconnect` | nothing (the API keeps no session) | none; the client ends `Disconnected` |

Any failure is `spark_error` with `operation`, `app_id`, `http_status` and `message`: Spark's own
plain-text error (`unknown job: 99`, `no such app: x`), the `<title>` of an HTML error page, or
this client's reason (unreachable, timed out, too large, too deep, not Spark's shape).

`details=false` is always sent for stages: a stage with `details=true` carries its whole task
list, which for a real job is megabytes. Task lists are never read.

## Decoding

Each resource is **projected** onto a fixed list of fields (`decode.rs` names them:
`APPLICATION_FIELDS`, `ATTEMPT_FIELDS`, `JOB_FIELDS`, `STAGE_FIELDS`, `EXECUTOR_FIELDS`,
`SQL_FIELDS`); field names are Spark's own camelCase so they match Spark's documentation.
Only scalars and lists of scalars are kept — Spark's nested maps (`killedTasksSummary`,
`peakMemoryMetrics`, `accumulatorUpdates`, `executorLogs`) are dropped. The task summary keeps
`quantiles` and every metric list, one level of metric groups deep. The environment keeps
`runtime` and `sparkProperties` (as a map, values as Spark gave them — Spark redacts secrets
itself) and only counts the system properties, Hadoop properties and classpath entries.

A list response delivers its first `max_items` entries (default 50, at most 500) with `count`,
`total` and `truncated`. A response that is an object where a list is expected (a single job,
a stage attempt) is delivered as a list of one, so `get_job` and `list_jobs` share an event.

Peer text is cleaned with `crate::utils::sanitize` (`line_field` for one-line fields,
`multiline` for failure reasons, error messages and plan descriptions) and cut at 2 KiB /
8 KiB.

## Bounds

| bound | value | where |
|---|---|---|
| a response body | 8 MiB, enforced while reading | `MAX_RESPONSE_BYTES`, `FetchClient::with_max_body` |
| JSON nesting | 32, measured iteratively before parsing (Spark's deepest is 4) | `decode::MAX_JSON_DEPTH` |
| entries per event | `max_items`, default 50, at most 500 | `DEFAULT_MAX_ITEMS`, `MAX_ITEMS_LIMIT` |
| a text field / a long text field | 2 KiB / 8 KiB | `decode::MAX_TEXT_BYTES`, `MAX_LONG_TEXT_BYTES` |
| a list of ids or numbers | 1000 | `decode::MAX_SCALAR_LIST` |
| attempts per application, plan nodes, task-summary metrics | 20, 200, 100 | `decode::MAX_ATTEMPTS`, `MAX_PLAN_NODES`, `MAX_METRICS` |
| a server error kept | 1 KiB | `MAX_ERROR_BYTES` |
| one request | `request_timeout_secs`, default 30 s, at most 600 | `REQUEST_TIMEOUT` |
| model turns from one another | 8 | `MAX_FOLLOWUP_DEPTH`, `decision=followup_depth` |
| events waiting for the model | 64 | `TURNS`, `decision=turn_queue_full` |

No decoder recurses.

## Fail closed

- An unreachable target, or one that does not answer `/api/v1/version` as Spark does, fails
  `connect()`; the client never reads as connected.
- An LLM failure reads nothing: `decision=fail_closed_llm_error`, and the session waits.
- An error status, a redirect, or an answer that cannot be read becomes a `spark_error` naming
  why; no result is invented. The client stays connected.

## Evidence and maturity

`tests/client/spark/` (see its `AGENTS.md`): the official **Apache Spark 4.2.0** distribution,
SHA-512 pinned, as a live driver UI and as Spark's History Server over the event log the same
application wrote. Results are checked against `SparkContext.statusTracker()` and the event log,
and the requests the model's actions caused against the request lines Spark received.

**Beta** against the client bar: a real third-party server (Apache Spark itself, in both roles
that serve this API), a suite that fails rather than skips, real sessions whose later requests
are built from ids the model read out of earlier answers, and the model's actions asserted on
the wire. The API is read-only, so the effect asserted is the request and Spark's answer;
Spark keeps no request log, so the test relays the connection (`WireTap`) to see it.

## Not implemented

- **The REST submission API** (`POST /v1/submissions/create`, `status`, `kill` on a standalone
  master's port 6066). It is a different service on a different port, and `create` runs
  arbitrary code on a cluster — not something a monitoring client should do on a model's
  say-so. A separate client with an explicit opt-in would be the place for it.
- Task lists (`taskList`, `details=true`), RDD storage (`/storage/rdd`), streaming statistics,
  event-log download (`/logs`), thread dumps, the per-executor metrics endpoints.
- The browser build compiles this client (the `spark` feature is in `crates/netget-web`, and
  `FetchClient`'s transport serves it there), but `web/test/smoke.mjs` does not drive it.
