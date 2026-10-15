# Spark — Apache Spark monitoring REST / history API server

The LLM roleplays a Spark application's control plane and invents the applications, jobs, stages
and executors it reports (the Kubernetes/OCI "model is the control plane" pattern). NetGet owns the
HTTP stack (hyper v1, `http1::serve_connection`); the model only decides state.

**Port**: 4040 (live driver UI/REST) or 18080 (History Server). **Privilege**: `None` (both ports
unprivileged — do NOT declare `PrivilegedPort`). **Stack**: `ETH>IP>TCP>HTTP>SPARK`.
**State**: Experimental. No storage.

## Endpoints

| Method + path | Operation | Handled by |
|---|---|---|
| `GET /api/v1/version` | version | **static** (banner, no LLM) |
| `GET /api/v1/applications` | applications | LLM → `send_spark_applications` |
| `GET /api/v1/applications/{id}` | application | LLM → `send_spark_applications` (one element, sent as the object) |
| `GET /api/v1/applications/{id}/jobs` | jobs | LLM → `send_spark_jobs` |
| `GET /api/v1/applications/{id}/stages` | stages | LLM → `send_spark_stages` |
| `GET /api/v1/applications/{id}/executors` | executors | LLM → `send_spark_executors` |
| `GET /api/v1/applications/{id}/storage/rdd` | rdd | LLM → `send_spark_rdds` |
| other `/api/v1/applications/{id}/...` | application_resource | LLM (answer or 404 via `send_spark_error`) |
| anything else | unknown | **static** 404 plain text (no LLM) |

**Static vs LLM split**: `/api/v1/version` is a mechanical version string, answered directly in
`mod.rs` from the `spark_version` startup param — no model round-trip. Unrecognised paths get a
static plain-text 404. Everything describing (invented) application state is LLM-driven.

## Response shapes

Spark's monitoring API returns **top-level JSON arrays**, not objects. `execute_action` emits the
array supplied by the model directly as the body (`Content-Type: application/json`):
`[{application}]`, `[{job}]`, `[{stage}]`, `[{executor}]`, `[{rdd}]`. Two answers are objects:
`/api/v1/version`, `{"spark":"<version>"}`, and **one application**, `GET
/api/v1/applications/{id}`, which Spark answers `{id, name, attempts}` — the model answers it with
`send_spark_applications` and one element, and `mod.rs` (`single_element`) sends that element.
It used to go out as `[{...}]`, which a strict consumer reads as the wrong type. Errors are plain
text (`Content-Type: text/plain`), matching Spark
(e.g. `unknown app: app-1`) — except the fail-closed path, see below.

## Events / actions

One event type, `spark_request`, emitted for every LLM-handled request (version/unknown
short-circuit before it). It declares the full action set via `.with_actions(...)`, and every
action is reachable, so nothing is declared-but-unemitted.

Actions: `send_spark_applications`, `send_spark_jobs`, `send_spark_stages`,
`send_spark_executors`, `send_spark_rdds`, `send_spark_error`. All parameters are structured JSON arrays — never raw
bytes or base64. `spark_response` is the internal `ActionResult::Custom` name, not an emittable
action.

## Fail-closed

On an LLM error the server answers **503** (overload/retryable) or **500** with a JSON error object
`{"error": "...", "status": ...}`. When the model succeeds but emits no `spark_response`, the
server answers **500** rather than a bare `[]` with 200 — an empty array is a valid "no
applications/jobs" result and a client cannot tell it from a backend that never ran. The failure
path (a JSON *object* with an `error` field) is structurally distinct from any success array.

## Failure behaviour

**Every terminal outcome is decided inside `src/server/spark/mod.rs`.** This server does *not*
delegate to `src/server/http_common/handler.rs` — it owns its own `service_fn`, its own
`build_spark_response`/`build_spark_error`, and its own LLM call site — so the whole decision
table below lives in one file and there is no shared handler to consult.

The wire cannot carry the distinction on its own: `send_spark_error` lets the model choose a
status, so a model-chosen 500 and a fail-closed 500 are the same three digits. The `decision=`
token is where they separate.

| Outcome | On the wire | Log |
|---|---|---|
| Model returned `spark_response` with a status < 400 | that status + the model's body | INFO `decision=model_answer` |
| Model returned `spark_response` with a status ≥ 400 | that status + the model's body | INFO `decision=model_reject` |
| Model answered with no `spark_response` action | `500` + `{"error": …, "status": 500}` | WARN `decision=model_silent` |
| `call_llm` failed (unavailable) | `500` + JSON error object, `WireFailure` category text only | ERROR `decision=fail_closed_llm_error` |
| `call_llm` failed (overloaded) | `503` + JSON error object | ERROR `decision=fail_closed_llm_overloaded` |
| `GET /api/v1/version` | `200` + `{"spark": …}` | DEBUG `decision=static_answer` |
| Unrecognised path | `404` plain text | DEBUG `decision=unknown_endpoint` |

`decision=static_answer` and `decision=unknown_endpoint` are invented tokens for the two paths
the model never sees: calling either `model_answer` would credit a decision nobody made. Both
are DEBUG, so they stay in `netget.log` and off the status stream — the two LLM-failure tokens
and `model_silent` are what an operator greps.

**A narrowing cast that used to live here is fixed.** `handle_spark_request_inner` narrowed the
model's `status` with `.unwrap_or(200) as u16`, and `65736 as u16` is `200` — so a nonsense
status became the one code a client reads as success. It now goes through a local `status_or`,
the same shape `oauth2` uses: `u16::try_from` plus a 100–599 range filter, falling back to the
declared default and logging the value it refused. The payoff here was a bogus monitoring
answer rather than a credential, but a monitoring API fabricating a `200` is precisely what a
monitoring API must not do.

## Startup parameters

`spark_version` (optional, default `3.5.1`) — the version in the static `/api/v1/version` banner,
actually read in `spawn()`. `send_first` is not declared.

## Limitations

Monitoring API only (the tractable, testable core). No standalone-master submission endpoint
(`POST /v1/submissions/create`); SQL, streaming, environment, a single job or stage and every
other per-application path reach the model as `application_resource` with no action of their
own (the model answers with the closest array action or 404s); no event-log download; no
`/metrics/json` servlet (a static 404). HTTP/1.1 only. State is virtual and lives only in the model's context.

**No authentication of any kind**, and nothing about the requester reaches the model: the
`spark_request` event carries `method`, `path`, `operation` and `app_id` and nothing else, so
there is no header, credential or peer address for it to decide on. Every request is answered
unconditionally. (The event's log template used to interpolate `{client_ip}` and
`{client_port}`, which the event has never carried — a missing field renders as the empty
string, so every INFO line read `Spark  GET /api/v1/applications`.)

**Request bodies are capped** at `MAX_REQUEST_BYTES` (64 KiB) through
`http_body_util::Limited`. The monitoring API is read-only and the body is used for nothing but
a `trace!` line, but it was read with an unbounded `collect()`, which made an unauthenticated
POST of any size a way to grow the process. An over-cap body is dropped, not refused — nothing
downstream reads it and every endpoint here is a GET.

**Datadog's Spark integration is the independent consumer.** `tests/server/spark/
datadog_check_test.rs` runs `datadog_checks.spark` (integrations-core tag `spark-7.8.0`, each
file's SHA-256 pinned by `install_datadog_check.sh`) once in `spark_driver_mode` against this
server, with the Agent replaced by `datadog_checks.base`'s own stubs, and asserts what the check
*submitted* from the model's answers: job and stage counts with their status/id tags, task
counts, run times, the driver's and the executor's metrics kept apart, executor-level metrics,
the cached RDD's metrics, the version metadata from the static banner, and the service checks.
It reads, in order, the version, the applications, then per application jobs, stages,
executors, `storage/rdd` and `streaming/statistics`, then `/metrics/json`.

What it found: `storage/rdd` — read on every Agent run — had no action. It fell into the
generic per-application path, where the only truthful answer was a 404, which the check reports
as a CRITICAL `spark.application_master.can_connect`. It is now operation `rdd` with
`send_spark_rdds` (a real non-streaming driver answers `[]` there and a 404 for
`streaming/statistics`, which is what the test's model does).

**Maturity stays `Experimental`.** One independent consumer, which reads the list endpoints
only: nothing third-party has driven `/applications/{id}`, a single job or stage, the
environment or SQL. A second consumer of those is the step to Beta; NetGet's own Spark client
(`src/client/spark/`) is tested against real Spark and would be circular here.

**Request-only.** `metadata()` declares `.request_only(…)`: "The Spark REST API is HTTP
request/response; a server cannot send a peer anything unprompted". The dashboard's
`[ send message ]` on a peer is disabled and shows that reason, and MCP `send_to_peer` refuses
with it.

## References

- Spark Monitoring REST API:
  https://spark.apache.org/docs/latest/monitoring.html#rest-api

## Connection bounds

Before September 2026 this server accepted without limit and bounded no read in time, so a peer
that connected and said nothing held a socket, a connection task and an `AppState` entry forever,
pre-authentication, on a server that would happily accept a hundred more. It now declares both
halves; the constants and the reasoning live beside them in `src/server/spark/mod.rs`.

| Bound | Value | Why this number |
|---|---|---|
| `FIRST_BYTE_READ_TIMEOUT` | 30s | HTTP is client-speaks-first, so a peer that has connected and sent no byte has begun no request. 30s sits between nginx's `client_header_timeout` default of 60s and Apache's `RequestReadTimeout header=20`. Enforced with `TcpStream::peek` before the socket reaches hyper, so the request line is still there for hyper afterwards. |
| `IDLE_BETWEEN_REQUESTS_TIMEOUT` | 180s | The monitoring API is read-only and polled on a seconds-to-minutes cycle, so the silence measured is a poller that has stopped. Above any scrape interval anyone configures and more than twice nginx's `keepalive_timeout` default of 75s. |
| `MAX_CONNECTIONS` | 256 | Each admitted connection may hold one whole in-memory response body (a JSON response), so the cap turns that per-connection bound into a total one. Refusal: **HTTP/1.1 `503 Service Unavailable` with `Retry-After: 5`** — a 503 is what a monitoring client and a dashboard both already understand. Nothing of netget's reaches the wire; the reason is logged under `decision=fail_closed_connection_cap`. |

**NetGet's Spark client (`src/client/spark/`) cannot be stranded by it**: it is a reqwest
client, so it opens a socket only to send a request (the *lazy* state in
`PROTOCOL_QUALITY.md`'s three-state test), and its `connect()` sends `GET /api/v1/version`
before any model turn. A pooled connection the idle watchdog closes is simply reopened.

**The idle bound is a watchdog, not a read deadline, and that is not a stylistic choice.** hyper
owns every read once `serve_connection` starts and keeps polling the connection for new frames
*while a request is being answered*, so a deadline on those reads would fire in the middle of an
LLM round-trip. It watches `ConnectionActivity` instead, which reports a connection with work in
flight as not idle at all — so the model round-trip, and a `manual` rule parking an event for a
human (`src/state/intercepts.rs`, 300s by default), sit outside every deadline by construction.
That is the `.connectionless()` lesson in the project `AGENTS.md` read in reverse: TFTP evicted
live transfers because "idle" was measured wrongly.

**One residual, stated rather than hidden.** The first-byte bound is discharged the moment any
byte arrives, so a peer that sends one byte of a request line and then stops is bounded by the
*idle* deadline (180s) rather than by the 30s one. hyper's own `header_read_timeout` cannot
express the pair: it re-arms whenever hyper starts reading a head, an idle keep-alive connection
included, so setting it to 30s would close every pooled client between requests — collapsing the
two bounds onto one number, which is exactly what the pair exists to avoid.

`tests/server/spark/connection_bounds_test.rs` drives all three from the wire, over
`tests/helpers/http_bounds.rs`. Each was verified by **removing** the bound and watching the test
fail: with the `peek` deadline gone the silent peer still held the socket at 60s; with the idle
bound collapsed to 30s an answered connection was closed after 38s of silence; with the permit
released early the connection past the cap was served instead of refused.
