# YARN client

NetGet as a reader of a Hadoop YARN **ResourceManager's REST API** (`/ws/v1/cluster`, the RM web
port, 8088 by default). The model decides what to read; Rust owns the URL, the HTTP exchange,
the bounds and the decoding. Feature `yarn` (shared with the server, `src/server/yarn/`).
**Beta** — see Maturity below.

| file | what |
|---|---|
| `mod.rs` | `resolve_endpoint`, `api_url`, `Api` (one bounded request → one event), `connect`, the session and turns tasks |
| `actions.rs` | actions, events, `request` (action → validated `ApiCall`), startup parameters, metadata |
| `decode.rs` | the depth check, the parse, unwrapping YARN's envelopes, the iterative queue walk, the per-resource projection |

## The target is fixed, and the model never writes a URL

The client talks to `endpoint_url` exactly as given, else to its `remote_addr` (`host:port`
means `http://host:port`); without either it refuses to start. A base path is allowed (an RM
behind a gateway: `https://gw/yarn`); a query, a fragment, credentials or a trailing `/ws/v1`
or `/ws/v1/cluster` are refused. `connect()` reads `GET /ws/v1/cluster/info` before anything
else and fails the client (`decision=fail_closed_connect`) when the answer is not a
`clusterInfo` carrying a `resourceManagerVersion`, so the model is never asked about a target
that is not a ResourceManager. The connected event carries the RM's version, cluster id, state
and **HA state**.

**Redirects are not followed — not even to the same host.** A standby ResourceManager in an HA
pair answers `/ws/v1/cluster/info` itself (which is why connect succeeds and reports
`ha_state: STANDBY`) and redirects every other request to the active RM, which is a different
machine. Following it would move the client's target behind the operator's back, so a 3xx is a
`yarn_error` naming where it pointed and telling the model to open a client on that address.

Every action names its resource with structured values, and `actions::request` validates each:

| value | accepted |
|---|---|
| `app_id` | `application_<1–19 digits>_<1–10 digits>`, as `ApplicationId.fromString` reads it |
| `node_id` | `host:port`, host of letters, digits, `.`, `-`, `_` (not starting with `.`/`-`), port 0–65535 |
| `states` (apps) | one or a list of `NEW NEW_SAVING SUBMITTED ACCEPTED RUNNING FINISHED FAILED KILLED`, case-insensitive, sent upper-case and comma-joined |
| `final_status` | one of `UNDEFINED SUCCEEDED FAILED KILLED ENDED` |
| `states` (nodes) | one or a list of `NEW RUNNING UNHEALTHY DECOMMISSIONED DECOMMISSIONING LOST REBOOTED SHUTDOWN` |
| `queue`, `application_types` | 1–255 / 1–64 of `[A-Za-z0-9._-]`, not starting with `.`; up to 10 types |
| `user` | 1–128 of `[A-Za-z0-9._@$-]` |
| `limit` | 1–10000; the time bounds are epoch milliseconds ≤ `i64::MAX` |

A comma-separated string where a list is meant is refused rather than split, so a value can
never smuggle a second filter. `api_url` pushes each id as **one** percent-encoded path segment
under `/ws/v1/cluster/` on the base, refuses an empty or dot segment, and checks the result's
origin is the base's — so even a value that skipped validation stays a segment on the target
(`tests/client/yarn/request_test.rs` asserts both).

## The conversation

| action | request | event |
|---|---|---|
| `get_cluster_info` | `GET /ws/v1/cluster/info` | `yarn_cluster_info` |
| `get_cluster_metrics` | `GET …/metrics` | `yarn_cluster_metrics` |
| `get_scheduler` | `GET …/scheduler` | `yarn_scheduler` |
| `list_applications` | `GET …/apps?states&finalStatus&queue&user&applicationTypes&limit&startedTimeBegin&startedTimeEnd&finishedTimeBegin&finishedTimeEnd` | `yarn_applications` |
| `get_application` | `GET …/apps/{app}` | `yarn_applications` |
| `list_app_attempts` | `GET …/apps/{app}/appattempts` | `yarn_app_attempts` |
| `get_app_state` | `GET …/apps/{app}/state` | `yarn_app_state` |
| `get_app_queue` | `GET …/apps/{app}/queue` | `yarn_app_queue` |
| `list_nodes` | `GET …/nodes?states` | `yarn_nodes` |
| `get_node` | `GET …/nodes/{node}` | `yarn_nodes` |
| `kill_application` | `PUT …/apps/{app}/state` `{"state":"KILLED"}` — **only with `allow_kill`** | `yarn_app_state` (with `http_status`: 202 KILLING, 200 KILLED) |
| `disconnect` | nothing (the API keeps no session) | none; the client ends `Disconnected` |

Any failure is `yarn_error` with `operation`, `app_id`/`node_id`, `http_status`, `exception`
and `message`: YARN's own `RemoteException` (`NotFoundException` / `app with id: … not found`,
`BadRequestException` / `Invalid application-state …`), the `<title>` of an HTML error page, or
this client's reason (unreachable, timed out, too large, too deep, not YARN's shape, redirected,
kill not allowed).

## Writes: one, opt-in; submission not at all

`kill_application` is the only write, and it is refused **before anything is sent** unless the
client was opened with `allow_kill: true` (`decision=refused_kill_not_allowed`, and a
`yarn_error` saying so). The connected event's `kill_allowed` tells the model which it has. The
body is built in Rust; nothing of the action reaches it but the validated id.

**Application submission is not implemented** (`POST /apps/new-application`, `POST /apps`). The
submission body's `am-container-spec.commands` is the shell command YARN runs on a cluster node
— arbitrary code execution — and a monitoring client should not offer that on a model's say-so,
the same decision the Spark client made about Spark's REST submission API. A separate client
with an explicit opt-in would be the place for it. Queue moves (`PUT …/queue`), priority and
timeout updates, reservations and delegation tokens are also not implemented.

## Decoding

Each resource is **unwrapped** from YARN's envelope (`apps.app`, `node`, `clusterMetrics`,
`scheduler.schedulerInfo`, `appAttempts.appAttempt`) and **projected** onto a fixed list of
fields (`decode.rs` names them: `CLUSTER_INFO_FIELDS`, `METRICS_FIELDS`, `SCHEDULER_FIELDS`,
`QUEUE_FIELDS`, `APP_FIELDS`, `ATTEMPT_FIELDS`, `NODE_FIELDS`); field names are YARN's own
camelCase so they match YARN's documentation. Only scalars and lists of scalars are kept — the
nested `resourceInformations`, `resourceSecondsMap`, `timeouts`, `resourcesUsed` and similar are
dropped. `{"apps": null}` (YARN's empty list) and `{"apps": {}}` are zero entries, and a
one-element list rendered as an object is a list of one.

The scheduler answer is a tree (CapacityScheduler `queues.queue`, FairScheduler
`rootQueue.childQueues.queue`); it is walked with an explicit stack, parents before children,
and stops at `MAX_QUEUES`. Its root's own fields are the `scheduler` summary (a FifoScheduler
has only those).

A list response delivers its first `max_items` entries (default 50, at most 500) with `count`,
`total` and `truncated`. Peer text is cleaned with `crate::utils::sanitize` (`line_field` for
one-line fields, `multiline` for diagnostics and health reports) and cut at 2 KiB / 8 KiB.

## Bounds

| bound | value | where |
|---|---|---|
| a response body | 8 MiB, enforced while reading | `MAX_RESPONSE_BYTES`, `FetchClient::with_max_body` |
| JSON nesting | 64, measured iteratively before parsing (the CapacityScheduler's tree measured 16 with one level of queues; each level below adds three: `queues`, `queue`, the entry) | `decode::MAX_JSON_DEPTH` |
| queues walked | 500 | `decode::MAX_QUEUES` |
| entries per event | `max_items`, default 50, at most 500 | `DEFAULT_MAX_ITEMS`, `MAX_ITEMS_LIMIT` |
| a text field / a long text field | 2 KiB / 8 KiB | `decode::MAX_TEXT_BYTES`, `MAX_LONG_TEXT_BYTES` |
| a list of scalars | 1000 | `decode::MAX_SCALAR_LIST` |
| a server error kept | 1 KiB | `MAX_ERROR_BYTES` |
| one request | `request_timeout_secs`, default 30 s, at most 600 | `REQUEST_TIMEOUT` |
| model turns from one another | 8 | `MAX_FOLLOWUP_DEPTH`, `decision=followup_depth` |
| events waiting for the model | 64 | `TURNS`, `decision=turn_queue_full` |

No decoder recurses.

## Fail closed

- An unreachable target, or one that does not answer `/ws/v1/cluster/info` as a ResourceManager
  does, fails `connect()`; the client never reads as connected.
- An LLM failure reads nothing: `decision=fail_closed_llm_error`, and the session waits.
- An error status, a redirect, or an answer that cannot be read becomes a `yarn_error` naming
  why; no result is invented. The client stays connected.
- A kill without `allow_kill` sends nothing.

## Evidence and maturity

`tests/client/yarn/` (see its `AGENTS.md`): the official **Apache Hadoop 3.5.0** distribution,
SHA-512 pinned, as a single-node ResourceManager + NodeManager running real distributed-shell
applications (one succeeds, one fails, one sleeps until the model kills it). Results are checked
against YARN's own RPC command line (`yarn application -list/-status`, `yarn applicationattempt
-list`, `yarn node -list`) and the configuration the test wrote; the requests the model's
actions caused, against the request lines (and the PUT body) the ResourceManager received.

**Beta** against the client bar: a real third-party server (Apache Hadoop's own RM and NM), a
suite that fails rather than skips, real sessions whose later requests are built from ids the
model read out of earlier answers, and the model's actions asserted on the wire — the reads by
the relayed request lines, the kill also by YARN's CLI reporting the application KILLED.

## Not implemented

- Submission (see above), queue moves, priority/timeout updates, reservations, delegation
  tokens, the application's containers, the scheduler's activities and the node-label APIs.
- **The NodeManager's own API** (`/ws/v1/node/…` on each node's 8042). It is a different service
  on every node; a client opened on one would be a different target with different resources.
- SPNEGO/Kerberos. On a secured cluster every request answers 401 and the client reports it.
- The browser build compiles this client (the `yarn` feature is in `crates/netget-web`, and
  `FetchClient`'s transport serves it there), but `web/test/smoke.mjs` does not drive it.
