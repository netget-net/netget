# SSE server (server-sent events)

Hand-rolled HTTP/1.1 over Tokio TCP, one request per connection (`Connection: close` for an
ordinary answer; the stream itself is close-delimited). `wire.rs` holds the WHATWG
event-stream encoding and the parser the client uses, so both roles agree byte for byte.

## Request → model

Every GET or HEAD becomes `sse_request {method, path, query, last_event_id, accept,
user_agent, client_ip}`. Other methods are 405, a request declaring a body is 413, a head over
16 KiB is 431, all without asking the model. The answer is read as:

- `sse_respond {status, body, content_type}` → that response, connection closed (204 tells an
  EventSource to stop reconnecting).
- `sse_accept {retry_ms}` and/or `sse_event`/`sse_comment` → `200 text/event-stream`, the
  `retry:` hint, then the events in order. `sse_close` in the same answer ends it at once.
- `sse_broadcast {path?, event, id, data}` → written to every open stream (of that path) of
  this server. It is executed in `execute_action_with_state`, so it works from any request's
  answer (a `/post` endpoint) and as an async action.
- nothing → 204 (`decision=model_silent`); a failed model call → 503 with a category and
  `Retry-After` (`decision=fail_closed_llm_error`).

## Open streams

A stream is registered — under the server's bound address, which is unique among running
servers in a process where server ids are not — for broadcasts, and as a peer for injected
`sse_event`/`sse_comment`/`sse_close`, while its writer is held, so nothing written to it can
arrive before the response head. An idle stream gets `: keepalive` every `keepalive_secs`
(default 15). The stream ends when the client closes, a write fails, or `sse_close` half-closes
it (an EventSource then reconnects with `Last-Event-ID`).

Every write to a stream — the response, a broadcast, an injected event, a keepalive — must make
progress within `SUBSCRIBER_WRITE_TIMEOUT` (5 s). A subscriber that stops reading misses it,
is removed from the broadcast table and has its write side shut, so it cannot stall a
broadcast to the others or the request that issued it
(`tests/server/sse/stall_test.rs`).

Event fields are validated: `event` and `id` one line, `id` without NUL, data at most 1 MiB;
each line of `data` becomes its own `data:` line.

Not implemented: TLS, HTTP/2, request bodies, keep-alive across requests.
