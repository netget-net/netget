# SSE client tests

`real_server_test.rs`, no LLM calls (a python chain disconnects on an event of type `bye`).
`NETGET_SSE_PYTHON` from `tests/server/sse/install_peers.py` is required.

- sse-starlette under uvicorn sends two events (one with two data lines) with a 300 ms retry
  hint and closes; NetGet reports the close with `reconnecting_in_ms: 300`, reconnects with
  `Last-Event-ID: 2` (the server's log shows it), reads the resumed event and disconnects on
  `bye`.
- aiohttp-sse does the same with its own encoder; a 404 is reported as `refused` and not
  retried (the server's log shows no further request).

Mutation-checked: dropping the model's actions leaves the client connected and fails both.

`framing_bounds_test.rs`, no LLM calls (static handlers disconnect on `sse_stream_ended`), no
peer to install: a 127.0.0.1 listener in the test never ends a line.

- `HTTP/1.1 200 ` then 1 MiB with no newline: the client stops at `MAX_HEAD_BYTES` and reports
  `sse_stream_ended {reason: error}` naming the head bound.
- A chunked event stream whose chunk-size line is 64 KiB of `f`: the client stops at
  `MAX_CHUNK_LINE_BYTES` and reports `reason: error` naming the chunk-size line, with no
  `reconnecting_in_ms`.

Both must finish within 15 s, half the client's 30 s I/O deadline, so a bound that only fired
at the deadline fails them, and both assert the server saw exactly one connection.
