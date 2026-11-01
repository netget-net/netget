# http_common — shared HTTP request/response infrastructure

Not a protocol. This module holds the code that HTTP/1.1 (`src/server/http/`) and
HTTP/2 (`src/server/http2/`) must agree on: how an inbound request is turned into
event data, how a model's response action becomes bytes on the wire, and which
requests are worth an LLM call at all. There is no HTTP/3 *server* in the tree —
`src/server/quic/` serves raw QUIC streams under ALPN `h3` with no HTTP/3 framing,
and shares no code here. (The HTTP/3 *client*, `src/client/http3/`, is real HTTP/3
via the `h3` crate and likewise shares nothing with this module.)

There is no `Protocol`/`Server` impl in this module, no registry entry, and no
feature flag of its own.

So it declares no `max_inbound_bytes` either — there is no `metadata()` to declare it on.
`MAX_REQUEST_BODY_BYTES` is declared by the protocols that use it (`http`, `http2`, `pypi`),
and `tests/max_inbound_bytes_declaration_test.rs` skips any `actions.rs` with no
`fn metadata(`, with a companion test that fails if a skipped directory implements `Protocol`
or `Server` anywhere.

## Which features compile it

The `cfg` list lives in `src/server/mod.rs` and must be kept in sync with the
protocols that serve HTTP themselves:

| How it is reached | Features |
|---|---|
| Named in the `cfg` | `http`, `http2`, `oauth2`, `openid`, `saml-idp`, `saml-sp` |
| Transitively, by enabling `http` | `openapi`, `mercurial`, `pypi` |

The auth family speaks HTTP over hyper without enabling the `http` feature, so
for a long time it could not see this module at all and each of its four
protocols carried a private copy of `build_safe_response`. **If you add an HTTP
protocol that does not depend on `http`, add it to that `cfg` — do not copy
`build_safe_response`.** All the module's deps (`hyper`, `http-body-util`,
`bytes`, `regex`) are unconditional, so widening the list costs nothing.

## Files

| File | Contents |
|---|---|
| `handler.rs` | `RequestData`, `extract_request_data`, `MAX_REQUEST_BODY_BYTES`/`BodyTooLarge`/`build_payload_too_large_response`, `build_response`, `build_safe_response`, `build_error_response`, `RequestFilter` + its startup-parameter schema |
| `actions.rs` | `execute_http_response_action` — the executor behind `send_http_response` and `send_http2_response` |

## Request extraction

`extract_request_data(req, label, status_tx) -> Result<RequestData, BodyTooLarge>`
consumes a hyper
`Request<Incoming>` and returns method, `path?query`, version, a lowercase header
map, and the **fully buffered** body. It also does the dual logging (DEBUG
summary, TRACE full headers/body, JSON pretty-printed when it parses).

Two things to know:

- **The body is buffered whole, bounded by `MAX_REQUEST_BODY_BYTES` (8 MiB).** There
  is no streaming request path — the body ends up embedded in an LLM prompt, so a
  large one is cost without benefit. Over the cap, `extract_request_data` returns
  `Err(BodyTooLarge)` and the caller answers `413` via
  `build_payload_too_large_response`, spending no LLM call. It refuses rather than
  truncating on purpose: a truncated body looks identical to a complete one, and the
  model would answer a request it never saw.
- **Header values that are not valid UTF-8 are silently dropped** from the map, so
  the model does not see them. Header *names* are whatever hyper produced
  (lowercase in practice).

`RequestData` is constructed directly by `tests/http_request_filter_test.rs`;
adding a field there breaks that test's build.

## Response building

`execute_http_response_action` (actions.rs) parses the model's action into
`{status, headers, body}` and returns it as `ActionResult::Output(json)`. The
per-protocol handler then calls `build_response`, which merges every `Output`
result it received and produces the final response.

This path is deliberately lenient, because **a rejected action never reaches the
client**: `execute_actions()` (`src/llm/actions/executor.rs`) logs a warning and
drops the action, and the request then falls through to whatever the protocol does
with no response action (HTTP/1.1 and HTTP/2 alike: the server's `default_response`,
or a fail-closed `500` if none is set). A strict executor therefore turns a
slightly-off model response into a refusal rather than the answer the model meant.
So:

- `status` accepts a number or a numeric string, and must be 100-599.
- `body` is optional (absent ⇒ empty body, which is what 204/304 need) and a
  JSON object/array body is serialized to compact JSON text instead of dropped.
- non-string header values are stringified.

`build_safe_response` is the only place a `Response` is constructed from
model-supplied parts, and it cannot panic: an out-of-range status becomes 500,
and header names/values hyper rejects — notably anything containing CR/LF, i.e.
response-splitting attempts — are dropped individually with a warning. The
earlier `.body(..).unwrap()` panicked inside the connection task on exactly those
inputs. HTTP/2 has an equivalent, `build_h2_response_head` in
`http2/h2_server.rs`, because `h2` needs an `http::Response<()>` head instead.

**Bodies are UTF-8 text end to end.** There is no supported way for a model to
produce a binary response body (image, gzip, protobuf) — the action parameter is
a string and is sent verbatim. In the inbound direction a non-UTF-8 request body
is decoded lossily (U+FFFD); HTTP/1.1 flags this with `body_is_binary: true` in
the event so the model knows the text it sees is not the real payload. Neither
direction supports chunked or streamed bodies: one request in, one complete
response out.

## Request filter

`RequestFilter` is a per-server allowlist deciding which requests are worth an
LLM call. Both HTTP/1.1 and HTTP/2 build it from `startup_params` **once, at
spawn time**, so path regexes compile once for the life of the server and parse
problems are reported while the caller is still watching the start result.

```json
"startup_params": {
  "request_filter": [
    { "methods": ["GET"], "path": "^/$", "headers": { "accept": "text/html" } },
    { "methods": ["POST"], "path": "^/api/" }
  ],
  "filtered_response": { "status": 404, "body": "Not Found" }
}
```

Semantics: **rules are OR'd, conditions inside a rule are AND'd, an omitted
condition is a wildcard.**

- `methods` — array (or a bare string), compared case-insensitively.
- `path` — a **regular expression** matched against the path before `?`.
- `headers` — name → `true` (must be present) or a string (value must *contain*
  it, case-insensitively). Names are case-insensitive.

No `request_filter`, or an empty one ⇒ pass-through: every request reaches the
LLM. Requests that match no rule get `filtered_response` (default `404`, empty
body) with **no LLM call**, and are not written to the access log.

### Fail-open (important)

Parsing never fails a server start. A malformed rule — an invalid `path` regex,
a `methods` value that isn't a string/array, a non-object rule — is **dropped**,
and the remaining rules still apply. If *every* rule is malformed the filter ends
up empty, which means pass-through: a typo makes the server send **more**
requests to the LLM (slow, billable), not fewer. It never accidentally blocks
traffic, but it also never tells you loudly by failing.

Because of that, every parse problem is recorded twice: at `error!` level in
`netget.log`, and in `RequestFilter::warnings()`, which the HTTP/1.1 and HTTP/2
servers forward to the status channel as `[ERROR] ... request_filter: ...` so it
appears in the TUI/MCP stream at startup. **If you add another caller, forward
`warnings()` too** — otherwise a broken filter is invisible.

Deliberately not fail-closed: refusing to start on a bad filter would make a
cosmetic typo take down a running honeypot, and rejecting all traffic on a
partially-parsed filter would be worse than serving it. If that trade-off is ever
revisited, change it in `from_startup_params` and say so in both protocol docs.

## Adding a caller

If a new protocol reuses this module:

1. Call `extract_request_data` for logging + parsing consistency.
2. Add `request_handling_startup_parameters()` to `get_startup_parameters()` —
   `StartupParams` rejects an undeclared key, so a caller passing
   `request_filter` to a protocol that didn't declare it gets a startup error
   (and no server) rather than the behaviour it asked for.
3. Build the `RequestFilter` **once**, not per request, and forward `warnings()`.
4. Route responses through `build_safe_response` (or an equivalent that cannot
   panic). Never `unwrap()` a builder fed with model output.
5. Handle `Err(BodyTooLarge)` from `extract_request_data` with
   `build_payload_too_large_response`; do not treat it as an empty body.
6. On LLM failure use `build_error_response`, which classifies with
   `crate::utils::WireFailure` and answers 503 + `Retry-After` for overload vs 500
   otherwise, logging `decision=fail_closed_llm_overloaded` /
   `decision=fail_closed_llm_error`. The error text itself never reaches the peer.
