# SSE client (server-sent events)

An EventSource in Rust: `GET` with `Accept: text/event-stream`, `Cache-Control: no-cache` and
`Last-Event-ID` (from the `last_event_id` startup parameter, then the stream's own), held open
over hand-rolled HTTP/1.1 (Content-Length, chunked and close-delimited bodies). The body is fed
to `server::sse::wire::Parser`, the WHATWG event-stream interpretation (CR, LF and CRLF line
ends, BOM, comments, `retry:`, `id:` without NUL, data lines joined with LF).

Events: `sse_connected {url, last_event_id, attempt}`, `sse_event_received {event, data, id}`
(id is the last event ID after it) and `sse_stream_ended {reason, status, body, error,
reconnecting_in_ms}`. Actions: `sse_reconnect {last_event_id?}` and `disconnect`.

Reconnects follow EventSource: a stream that closes is reopened after the server's retry hint
(default 3 s, clamped 100 ms–60 s), at most `max_reconnects` times (default 5); a non-200
answer or another content type is a refusal (`reason: refused`) and is not retried, and the
client then waits for the handler or an injected action to reconnect or stop. Handler-asked
reconnects with no event in between stop after 8.

Every framing line is read through a byte limit, so a server that never sends a newline costs
a bounded buffer: the response head is at most 32 KiB (`MAX_HEAD_BYTES`) and must be complete
within 30 s (`IO_TIMEOUT`); a chunk-size line and the CRLF after a chunk's data are at most
1 KiB each (`MAX_CHUNK_LINE_BYTES`). A chunk-size line may take as long as the server is idle
to begin, then has 30 s to finish; a chunk's CRLF has 30 s from the end of its data. Chunked
state lives in the body, so a line read interrupted by an injected command resumes. Broken
framing (an overlong line, a bad size, a missing CRLF, a line deadline) ends the stream with
`sse_stream_ended {reason: error, error}` and is not reconnected by itself; a transport error
(a reset) is treated as a close and reconnects like one.

Not implemented: https, redirects, custom request headers or credentials.

## Batching

`BatchingMode::On`. The body goes on being read while the model answers: each piece is parsed
into a queue of unanswered `sse_event_received` events (past `MAX_BATCH_EVENTS` waiting the
body is not read and TCP holds the server back). With batching on, everything waiting is
answered in one `call_llm_for_client_batch` call, one event each; with it off, one event per
call. An end, reset or broken framing found while reading during a call is acted on once the
events read before it are answered. `tests/client/sse/batching_test.rs` is the off/on pair.
