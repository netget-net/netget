# YARN — Hadoop YARN ResourceManager REST API server

The LLM roleplays a YARN cluster's ResourceManager and invents the applications, nodes and
metrics it reports (the Kubernetes/OCI "model is the control plane" pattern). NetGet owns the
HTTP stack (hyper v1, `http1::serve_connection`); the model only decides cluster state.

**Port**: 8088 (RM web UI/REST default). **Privilege**: `None` (8088 is unprivileged — do NOT
declare `PrivilegedPort`, it is > 1023 and would be dead code). **Stack**: `ETH>IP>TCP>HTTP>YARN`.
**State**: Experimental. No storage — the model supplies all state per request.

## Endpoints

| Method + path | Operation | Handled by |
|---|---|---|
| `GET /ws/v1/cluster` or `/ws/v1/cluster/info` | info | **static** (version banner, no LLM) |
| `GET /ws/v1/cluster/metrics` | metrics | LLM → `send_yarn_metrics` |
| `GET /ws/v1/cluster/scheduler` | scheduler | LLM → `send_yarn_scheduler` |
| `GET /ws/v1/cluster/apps` | apps | LLM → `send_yarn_apps` |
| `POST /ws/v1/cluster/apps/new-application` | new_application | LLM → `send_yarn_new_application` |
| `POST /ws/v1/cluster/apps` | submit | LLM → `send_yarn_submit_response` |
| `GET /ws/v1/cluster/apps/{appid}` | app | LLM → `send_yarn_app` |
| `GET /ws/v1/cluster/nodes` | nodes | LLM → `send_yarn_nodes` |
| `GET /ws/v1/cluster/nodes/{nodeid}` | node | LLM (reuse `send_yarn_nodes`/`send_yarn_error`) |
| anything else | unknown | **static** 404 RemoteException (no LLM) |

**Static vs LLM split**: `/ws/v1/cluster/info` is a purely mechanical version string, answered
directly in `mod.rs` from the `resource_manager_version` / `cluster_id` startup params — no model
round-trip. Unrecognised paths get a static 404 so scanner noise never bills the LLM. Everything
describing (invented) cluster *state* is LLM-driven.

## Response envelopes

Wrapped by `execute_action` to match the documented Hadoop `ResourceManagerRest` shapes:
`{"clusterInfo":{...}}`, `{"clusterMetrics":{...}}`,
`{"scheduler":{"schedulerInfo":{"type":"capacityScheduler","queueName":"root",...,"queues":{"queue":[...]}}}}`
(each queue's children nested the same way, `queuePath`/`queueType`/leaf `type` filled in, at
most `MAX_QUEUE_DEPTH` 8 levels below root; or the FifoScheduler's flat summary),
`{"apps":{"app":[...]}}` (empty list →
`{"apps":null}`, the real YARN idiom), `{"app":{...}}`, `{"nodes":{"node":[...]}}`,
`{"application-id":...,"maximum-resource-capability":{...}}`. Submit acceptance is `202 Accepted`
with an **empty body + `Location` header** (no Content-Type), exactly as YARN replies.

## Events / actions

One event type, `yarn_request`, emitted for every LLM-handled request (info/unknown short-circuit
before it). It declares the full action set via `.with_actions(...)`, and every action is
reachable from some operation, so nothing is declared-but-unemitted.

Actions: `send_yarn_metrics`, `send_yarn_scheduler`, `send_yarn_apps`, `send_yarn_app`,
`send_yarn_nodes`,
`send_yarn_new_application`, `send_yarn_submit_response`, `send_yarn_error`. All parameters are
structured JSON (objects/arrays/numbers) — never raw bytes or base64. `yarn_response` is the
internal `ActionResult::Custom` name, not an action the model emits.

## Fail-closed

On an LLM error the server answers **503** (`ServiceUnavailableException`, overload/retryable) or
**500** (`WebApplicationException`) with a `RemoteException` envelope. When the model succeeds but
emits no `yarn_response`, the server answers **500** rather than a success-shaped empty cluster —
an empty-but-200 `{"apps":null}` is a valid statement that the cluster is idle and a client cannot
tell it from a backend that never ran. The failure path is structurally distinct from a real empty
cluster.

## Startup parameters

Both optional and both actually read in `spawn()`:
- `resource_manager_version` (default `3.3.6`) — the version in the static info banner.
- `cluster_id` (default `1476912658570`) — the RM start epoch-ms / cluster id in the banner.

`send_first` is not declared (nothing to send before the client issues a request).

## Limitations

No app-attempts/state/queue/containers sub-resources, no kill (`PUT …/state`), no FairScheduler
shape, no RM HA failover, no auth (SPNEGO/delegation tokens). HTTP/1.1 only. Cluster state is virtual and lives only in the model's
context across a conversation.

**Request-only.** `metadata()` declares `.request_only(…)`: "The YARN REST API is HTTP
request/response; a server cannot send a peer anything unprompted". The dashboard's
`[ send message ]` on a peer is disabled and shows that reason, and MCP `send_to_peer` refuses
with it.

## Evidence and maturity

**Datadog's YARN integration is the independent consumer.** `tests/server/yarn/
datadog_check_test.rs` runs `datadog_checks.yarn` (integrations-core tag `yarn-8.4.2`, each
file's SHA-256 pinned by `install_datadog_check.sh`) once against this server, with the Agent
replaced by `datadog_checks.base`'s own stubs, and asserts what the check *submitted* from the
model's answers: cluster metrics (including a field the model omitted, defaulted to 0),
per-application gauges with their name/queue/state tags and the application status service
check, node metrics and the version metadata it takes from the node, root/queue/sub-queue
capacity metrics, and one OK `yarn.can_connect` per endpoint. It reads `/metrics`, `/apps`,
`/nodes` and `/scheduler`, in that order, on every Agent run.

What it found: **`/ws/v1/cluster/scheduler` was not served at all.** It fell to the static 404
for unknown paths, so every run of the check ended with a CRITICAL `yarn.can_connect` and an
exception, and no queue metric was ever collected. It is now operation `scheduler` with
`send_yarn_scheduler`, rendered in the shape Hadoop 3.5.0's CapacityScheduler answers with
(measured against a real ResourceManager while building the YARN client).

**Maturity stays `Experimental`.** One independent consumer, which reads the four list
endpoints only: nothing third-party has driven an application or node by id,
`new-application` or submission. A second consumer of those is the step to Beta; NetGet's own
YARN client (`src/client/yarn/`) is tested against real Hadoop and would be circular here.

## References

- Hadoop ResourceManager REST APIs:
  https://hadoop.apache.org/docs/current/hadoop-yarn/hadoop-yarn-site/ResourceManagerRest.html

## Connection bounds

Before September 2026 this server accepted without limit and bounded no read in time, so a peer
that connected and said nothing held a socket, a connection task and an `AppState` entry forever,
pre-authentication, on a server that would happily accept a hundred more. It now declares both
halves; the constants and the reasoning live beside them in `src/server/yarn/mod.rs`.

| Bound | Value | Why this number |
|---|---|---|
| `FIRST_BYTE_READ_TIMEOUT` | 30s | HTTP is client-speaks-first, so a peer that has connected and sent no byte has begun no request. 30s sits between nginx's `client_header_timeout` default of 60s and Apache's `RequestReadTimeout header=20`. Enforced with `TcpStream::peek` before the socket reaches hyper, so the request line is still there for hyper afterwards. |
| `IDLE_BETWEEN_REQUESTS_TIMEOUT` | 180s | The ResourceManager REST API is polled on a seconds-to-minutes cycle, so the silence measured is a poller that has stopped polling. Three minutes is above any scrape interval anyone configures and more than twice nginx's `keepalive_timeout` default. |
| `MAX_CONNECTIONS` | 256 | Each admitted connection may hold one whole in-memory response body (a JSON response), so the cap turns that per-connection bound into a total one. Refusal: **HTTP/1.1 `503 Service Unavailable` with `Retry-After: 5`** — a 503 is what a REST client and a dashboard both already understand. Nothing of netget's reaches the wire; the reason is logged under `decision=fail_closed_connection_cap`. |

**NetGet's own YARN client (`src/client/yarn/`) cannot be stranded by these bounds**: it is
*lazy* in `PROTOCOL_QUALITY.md`'s three-state test — reqwest opens a connection only to send a
request, so it is never a connected-and-silent peer, and reqwest's pool drops an idle
connection after 90s, inside the 180s idle bound.

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

`tests/server/yarn/connection_bounds_test.rs` drives all three from the wire, over
`tests/helpers/http_bounds.rs`. Each was verified by **removing** the bound and watching the test
fail: with the `peek` deadline gone the silent peer still held the socket at 60s; with the idle
bound collapsed to 30s an answered connection was closed after 38s of silence; with the permit
released early the connection past the cap was served instead of refused.
