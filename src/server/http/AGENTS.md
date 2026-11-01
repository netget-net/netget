# HTTP/1.1 Protocol Implementation

HTTP/1.1 server built on hyper v1.0. Hyper owns the protocol (parsing,
keep-alive, chunked *request* decoding, connection management); the LLM owns one
thing only — the response status, headers and text body.

**State**: Beta — human-reviewed, verified against real clients (`curl`,
`reqwest`). **Privilege**: declares `PrivilegedPort(80)`; the preflight check
fires only when the requested port is actually below 1024.
**RFC**: 7230-7235.

Shared request/response plumbing lives in `src/server/http_common/` — read
`src/server/http_common/AGENTS.md` too; the filter and response-building
contracts are documented there, not repeated here.

## What the model sees and controls

**Event**: `http_request`, one per HTTP request (not per TCP connection).

| Field | Notes |
|---|---|
| `method` | `GET`, `POST`, … |
| `path` | path only, no query string |
| `query_string` | raw string, present only when there was one |
| `query` | parsed, URL-decoded key→value object |
| `headers` | lowercase name→value object; non-UTF-8 values are dropped |
| `body` | request body decoded as UTF-8 **lossily** |
| `body_bytes` | body size in bytes before decoding |
| `body_is_binary` | present and `true` only when the body was not valid UTF-8 |

**Action**: `send_http_response` — the only one. `status` (required, 100-599),
`headers` (optional), `body` (optional; omit for 204/304).

There are no async actions: HTTP is purely reactive.

### Hard limits, stated in the action description so the model sees them too

- **One response per request, sent complete.** No chunked/streaming responses, no
  server-sent events, no way to hold the request open or send in parts.
- **No binary response bodies.** `body` is a string written as UTF-8. Images,
  gzip, protobuf cannot be produced. There is no hex/base64 escape hatch, by
  design: action parameters must not carry encoded bytes.
- **Non-UTF-8 request bodies are lossy.** The raw bytes are not exposed to the
  model in any form; `body_is_binary` tells it the text is not the real payload.
- **Request bodies are fully buffered**, bounded by
  `http_common::MAX_REQUEST_BODY_BYTES` (8 MiB), before the LLM call. A larger body is
  refused with `413` and costs no LLM call — it is refused rather than truncated,
  because a truncated body is indistinguishable from a complete one to the model.
- `Content-Length` and `Date` are set by hyper; setting them in `headers` is
  ignored or harmful. Header names/values that are not legal HTTP (e.g.
  containing CR/LF) are dropped rather than injected.

### Failure behavior

Every request ends in exactly one `decision=` line. The table is the whole contract; the
notes below it are the parts that are easy to get wrong.

| Outcome | On the wire | Log |
|---|---|---|
| Model emitted a parseable `send_http_response` | that response | INFO `decision=model_answer` |
| Model emitted none, `default_response` **is** configured | that default | WARN `decision=model_silent fallback=default_response` |
| Model emitted none, no `default_response` | `500`, body = category | WARN `decision=fail_closed_no_action` |
| Model's action was refused by the executor, `default_response` configured | that default | ERROR `decision=model_bad_action fallback=default_response` |
| Model's action was refused by the executor, no `default_response` | `500`, body = category | ERROR `decision=fail_closed_bad_action` |
| Backend saturated | `503` + `Retry-After: 1`, body = category | ERROR `decision=fail_closed_llm_overloaded` |
| Backend failed | `500`, body = category | ERROR `decision=fail_closed_llm_error` |
| Body over `MAX_REQUEST_BODY_BYTES` | `413`, no LLM call | `decision=refused_body_too_large` |
| Refused by `request_filter` | `filtered_response` (default 404), no LLM call | INFO `decision=refused_by_filter` |
| `h2c` upgrade without `HTTP2-Settings`, or with `http2` off | `400` / `501`, no LLM call | `decision=protocol_error` |

- **The peer gets a category, never the error text** (`crate::utils::WireFailure`). Overload
  becomes `503` + `Retry-After` rather than `500` so a client backs off instead of recording a
  permanent fault. This is the behaviour root `AGENTS.md` tells other protocols to copy;
  `tests/server/http/failure_semantics_test.rs` pins it.
- **A model that produced no response is refused, never answered `200`.** With no
  `send_http_response` and no `default_response`, `build_response` answers `500` with the
  `WireFailure::Unavailable` category (`netget: request could not be processed`). An empty
  `200` would make a model that said nothing — whether it chose to, or an executor refused its
  action — indistinguishable from a model that deliberately answered an empty success, and a
  client would record an unanswered request as completed. `500` rather than `503`, because
  `503` + `Retry-After` means "overloaded, retry", and retrying a request the model declines
  just asks it again; `500` is also what HTTP/2 (`h2_server.rs`) and OpenAPI answer a silent
  model with. The manual handler's "Answer with nothing" and a static handler with no actions
  reach the peer the same way, since neither produces a response. Set `default_response` (e.g.
  a 404 page) to give such requests a deliberate answer instead.
- **`default_response` is the one thing that may stand in for the model.** It is the
  operator's answer for exactly this case, so it is sent as configured and the log says whose
  silence it was: `decision=model_silent fallback=default_response`, or
  `decision=model_bad_action fallback=default_response` when the model answered with an action
  the executor refused (e.g. a status outside 100-599, dropped with a warning by
  `execute_actions()`). Those are not `fail_closed_*` tokens because the peer got the
  operator's response rather than a refusal. The executor is lenient about status/body shapes
  for this reason, see `http_common/AGENTS.md`.
  `tests/server/http/decision_tag_test.rs` covers all four outcomes from the wire.
- The `send_http_response` action and `http_request` event descriptions tell the model to
  always answer and to honor the client's `Accept` header (a matching `Content-Type`; 404 for
  an image/binary it cannot produce), and the `request_filter` param is recommended so
  favicon/preflight noise never reaches the model.
- A status or header hyper cannot represent → 500 / dropped header, never a panic.

**Where the tags live.** `decision=fail_closed_llm_*` and `decision=refused_body_too_large` are
emitted by `src/server/http_common/handler.rs`, which is shared with ipp/openapi/…; the
`model_*` and `refused_by_filter` / `protocol_error` tags are emitted at HTTP's own call sites
in `mod.rs`, because `build_response` cannot tell which protocol it is answering for. Two
consequences worth knowing: the h2c-upgraded path is served by
`src/server/http2/h2_server.rs` and carries whatever tags **that** protocol emits, not these;
and `build_error_response`'s tag reaches `netget.log` through `error!` but its status-stream
line (`✗ LLM error for …`) has no `decision=`, so the dashboard shows the failure untagged.

## Architecture

- `spawn_with_llm_actions` binds via `create_reusable_tcp_listener`, propagates
  bind failure with `?` (so `server_startup` reports `Error` rather than a
  phantom `Running`), and registers the accept-loop `JoinHandle` with
  `AppState::register_server_task()` so `stop_server` releases the socket.
- Optional TLS: `startup_params` are parsed by
  `crate::server::tls_cert_manager::extract_tls_config_from_params`; when
  present, each accepted stream goes through `tokio_rustls` before hyper. The
  server logs itself as `HTTPS` in that case. (ALPN is not advertised.)
- One `tokio` task per TCP connection; hyper's `service_fn` calls the LLM per
  request. **Each connection task is registered**, through
  `AppState::spawn_server_task`, so `stop_server` aborts in-flight requests along
  with the accept loop. This bullet claimed the opposite for a long time after
  `spawn_server_task` was adopted — `grep -n spawn_server_task src/server/http/mod.rs`
  settles it, and there are three call sites.
- Handling mode priority is the generic one: script handler → static handler →
  LLM (`call_llm` → `try_execute_event_handler`). Script and static handlers cost
  no LLM call.
- `h2c` upgrade: an `Upgrade: h2c` request with an `HTTP2-Settings` header gets
  `101 Switching Protocols` and the connection is handed to
  `http2::h2_server::handle_h2_request` (feature-gated on `http2`; without it the
  server answers `501`). The request filter is carried across the upgrade, and the
  handshake uses `http2::h2_server::bounded_h2_builder()` and a per-connection
  `BodyBudget`, so an upgraded connection advertises and enforces the same stream limit,
  windows, frame and header-list sizes and body budget as a prior-knowledge one.
- **Known defect: the upgraded request itself is never answered.** RFC 7540 §3.2 makes the
  request that carried `Upgrade: h2c` stream 1 of the new connection, half-closed from the
  client, to be answered over HTTP/2. The upgraded socket is handed to a fresh `h2` server
  handshake that knows nothing of stream 1, so a client that follows the RFC — curl
  `--http2` against `http://` — has its WINDOW_UPDATE on stream 1 answered with
  GOAWAY(PROTOCOL_ERROR) and gets no response. Seen with curl 8.22 in
  `tests/server/http2/stream_bounds_test.rs`, which asserts only the SETTINGS for that reason.
  Fixing it means answering the HTTP/1.1 request as stream 1; no method on `h2` 0.4's
  `server::Builder` or `Connection` adopts a stream opened by an upgrade, so it needs either
  that or a different framing layer.

### Connection state

One `ConnectionId` per TCP connection, added on accept and closed when the socket
closes.

`bytes_*`, `packets_*` and `last_activity` are maintained per request by the
wrapper around `handle_http_request_inner`, on **every** exit path — including
h2c upgrade and request-filter rejections, which never reach the model.
Semantics: one "packet" = one HTTP message; byte counts are **message bodies
only**, because hyper has parsed the request line and headers away before the
server sees them, and `Full<Bytes>::size_hint()` only knows the response body.
So the numbers track payload volume, not wire volume.

Two things read them, and both were broken while they stayed at zero:

- `ServerInstance::cleanup_old_connections` (`src/state/server.rs`) drops any
  connection whose `last_activity` is older than 10s; the TUI and the MCP loop
  both call it on a timer. Without the refresh, a keep-alive connection was
  evicted from the state map 10s after it opened while it was still serving, and
  every later stat update and the final `close_connection_on_server` targeted a
  connection that no longer existed.
- Connection-scoped scheduled tasks put the counters and the idle time directly
  into the model's prompt (`src/llm/prompt.rs`), so idle-timeout and
  rate-limiting instructions were reasoning about constant zeros.

The TUI's connection list shows only id/address/state
(`ConnectionDisplayInfo`, `src/ui/app.rs`), so these counters are **not** on
screen; they reach the model and the cleanup timer instead.

**Still a gap**: `ProtocolConnectionInfo` is initialized to
`{"recent_requests": []}` and is never appended to. Nothing in the codebase reads
`recent_requests`, and there is no accessor to push into it — populating it needs
a new method on `AppState`/`ServerInstance` first, or the field should be dropped.

## Request filtering

By default every request costs an LLM round-trip, including favicon probes, CORS
preflights and scanner noise. `request_filter` in `startup_params` is an
allowlist: a request reaches the LLM only if it matches at least one rule;
everything else gets `filtered_response` (default 404) with no LLM call.

```json
"startup_params": {
  "request_filter": [ { "methods": ["GET"], "headers": { "accept": "text/html" } } ],
  "filtered_response": { "status": 404, "body": "Not Found" }
}
```

That one rule covers the common noise generically — favicon requests carry
`Accept: image/*` and preflights are not `GET`. It replaced an earlier hardcoded
favicon bypass.

Full schema, matching semantics and the **fail-open** caveat (a malformed rule is
dropped, not fatal, so a typo sends *more* traffic to the LLM) are in
`src/server/http_common/AGENTS.md`. The filter is built once at spawn time; parse
problems are logged at `error!` and pushed to the status stream as
`[ERROR] HTTP request_filter: …`, so they show up in the `start_server` result. Pure unit tests: `tests/http_request_filter_test.rs`.

## Testing

- `tests/server/http/test.rs` — 7 mocked E2E scenarios (simple GET, JSON API,
  routing, headers, methods, error responses, logging) driven through the real
  binary with `reqwest`. Declared in `tests/server/http/mod.rs`.
- `tests/server/http/failure_semantics_test.rs` — 3 scenarios: 500 on backend failure,
  no internal detail in the failure body, and 413 (with no LLM call) for a body over the
  size cap.
- `tests/server/http/decision_tag_test.rs` — 4 scenarios: a backend failure is tagged
  `decision=fail_closed_llm_error` (and not as model silence); a model that answers with no
  action is refused `500` with `decision=fail_closed_no_action`; a model whose action the
  executor refuses is refused `500` with `decision=fail_closed_bad_action`; and with
  `default_response` configured a silent model gets that response, tagged
  `decision=model_silent fallback=default_response`.
- `tests/server/http/e2e_scheduled_tasks_test.rs` — scheduled-task coverage.
- `tests/http_request_filter_test.rs` — pure filter unit tests.

```bash
./cargo-isolated.sh test --no-default-features --features http \
    --test server -- server::http::test --test-threads=100
```

**Gaps**: no test covers TLS/HTTPS, the h2c upgrade path, the request filter
end-to-end through a running server (only the pure unit tests), a non-UTF-8
request body, a model response with an invalid status/header, or the `503` +
`Retry-After` branch specifically (the mock's HTTP 500 classifies as `Unavailable`,
so the tests exercise the `500` side; provoking an overload needs a saturated
rate limiter).

## Example prompts

```
listen on port 8080 via http
For GET /, return <h1>Welcome</h1>
For GET /about, return <h1>About Us</h1>
For other paths, return 404 with "Not Found"
```

```
listen on port 3000 via http
For POST /api/users, parse the JSON body and return 201 with
Content-Type: application/json and body {"status":"created","id":123}
```

```
listen on port 8080 via http
For GET /health, return 200 with body: OK
For GET /redirect, return 301 with Location: /home
For DELETE /items/*, return 204 with no body
```

For deterministic behavior prefer a static or script handler over the
instruction — same result, no LLM call:

```json
"event_handlers": [{
  "event_pattern": "http_request",
  "handler": { "type": "static", "actions": [
    { "type": "send_http_response", "status": 200,
      "headers": {"Content-Type": "text/plain"}, "body": "Hello World" }
  ]}
}]
```

## Performance

One LLM call per request unless a script/static handler matches or the request is
filtered out; 2-5 s per call with `qwen3-coder:30b`. Requests are handled
concurrently (a task each); how many model calls run at once is bounded by
`--llm-max-concurrent` (default 1, so throughput is effectively one request at a time),
with `--llm-queue-timeout` and `--llm-max-queued` bounding the wait. Do **not** reason
about this from `--ollama-lock` — that flag is accepted and inert, and its plumbing was
deleted. Keep-alive avoids repeated TCP handshakes. Everything is buffered in memory.

## Not implemented

WebSocket upgrade · streaming/chunked responses · request-body streaming ·
binary bodies · multipart/urlencoded form parsing (the body is handed over raw) ·
LLM control over keep-alive or connection close · ALPN · `recent_requests`.

**Request-only.** `metadata()` declares `.request_only(…)`: "HTTP only answers requests; a server
cannot send a peer anything unprompted". The dashboard's `[ send message ]` on a peer is disabled
and shows that reason, and MCP `send_to_peer` refuses with it.

## References

- RFC 7230-7235 (HTTP/1.1)
- [hyper](https://docs.rs/hyper/latest/hyper/)

## Connection bounds

Before September 2026 this server accepted without limit and bounded no read in time, so a peer
that connected and said nothing held a socket, a task and an `AppState` entry forever,
pre-authentication, and a hundred of them was a free denial of service on a server that would
happily accept a hundred more. It now declares both halves; the constants and the argument for
each live beside them in `src/server/http/mod.rs`.

| Bound | Value | Why this number |
|---|---|---|
| `FIRST_BYTE_READ_TIMEOUT` | 30s | HTTP is client-speaks-first, so a peer that has completed the handshake and sent no byte has asked nothing and negotiated nothing — the state carries no protocol yet, which is why this number is the same across netget's HTTP family. Apache's `mod_reqtimeout` gives the request header 20s and nginx's `client_header_timeout` 60s. Enforced with `TcpStream::peek` before the socket reaches hyper, so the request line is still there afterwards. |
| `IDLE_BETWEEN_REQUESTS_TIMEOUT` | 75s | nginx's `keepalive_timeout` default — the number the deployed web is tuned against, and the right one here because this server's clients are whatever the operator points at it, with no pooling discipline of their own to argue for more. Apache's `KeepAliveTimeout` of 5s is the other end of the range and is tuned for a front-end serving far more connections than this one admits. |
| `MAX_CONNECTIONS` | 128 | Below the shared `DEFAULT_MAX_CONNECTIONS` of 256 on purpose: each admitted connection may buffer one body of up to 8 MiB, the largest per-connection cost in netget's HTTP family, and the cap is what turns that per-connection bound into a total one. 128 holds the worst case to the same ~1 GiB ceiling the smaller-bodied servers reach at 256. Refusal: **HTTP/1.1 `503 Service Unavailable` with `Retry-After`**, written straight onto the socket — the peer has sent no request line for hyper to answer — and logged `decision=fail_closed_connection_cap`. Fixed bytes, so nothing derived from an error can reach the wire. |

**NetGet's own HTTP client is *lazy*, so it is never the silent peer this bound closes:**
`src/client/http/mod.rs` only warms its cached `reqwest::Client` at connect and opens no socket
until an action issues a request — `PROTOCOL_QUALITY.md`'s three-state test.

**The deadline covers the read and nothing else.** hyper owns every read once `serve_connection`
starts, and it keeps polling the connection for more input *while a request is being answered* —
so a deadline on those reads would be wrong here, not merely awkward. The idle bound is a
watchdog over `ConnectionActivity` instead, which reports a connection with work in flight as not
idle at all. The model round-trip, and an event a `manual` rule parked for a human
(`src/state/intercepts.rs`, 300s by default), are therefore outside every deadline by
construction: an answer that takes minutes can never close the connection it is an answer for.
That is the `.connectionless()` lesson in the project `AGENTS.md` read in reverse — TFTP evicted
live transfers because "idle" was measured wrongly.

**hyper's own `header_read_timeout` is not this bound.** Its 30-second default is inert unless
`http1::Builder::timer` is also set, which nothing here does: hyper downgrades a defaulted
duration to `None` when no timer is present and applies no deadline at all. That is why the
`peek` is not redundant.

`tests/server/http/connection_bounds_test.rs` drives all three from the wire, with three
sockets on one server whose only rule is `*` → `manual`: a silent peer must be closed after the
first-byte bound, a peer that sends a request line and then stalls (slowloris) after the idle
bound, and a peer whose request is parked for a human must **not** be closed at all. The shared
driver and the removal-verification notes are in `tests/helpers/http_bounds.rs`.
`tests/tcp_server_bounds_ratchet_test.rs` fails the build if either bound disappears.

**The h2c upgrade carries the slot with it.** An `Upgrade: h2c` request is answered with `101`
and the connection moves to a task that outlives the HTTP/1 one, so the connection permit is an
`Arc` cloned into that task rather than released when `serve_connection` returns — otherwise an
upgrade would quietly hand the slot back while the peer was still on it, which is an un-cap
reachable with one request. The upgraded connection gets its own `ConnectionActivity` and the
same `IDLE_BETWEEN_REQUESTS_TIMEOUT` watchdog around `h2_conn.accept()`, with each spawned
request holding the busy guard. This path is untested end to end (see **Gaps** above) beyond
the SETTINGS curl reads from it, and a real client's request does not complete over it (see the
known defect above).
