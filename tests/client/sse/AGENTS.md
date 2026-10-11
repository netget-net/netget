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
