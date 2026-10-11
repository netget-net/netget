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

Not implemented: https, redirects, custom request headers or credentials.
