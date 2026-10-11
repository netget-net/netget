# SSE server tests

`real_client_test.rs`, no LLM calls (a python handler). Peers come from `install_peers.py`
(`NETGET_SSE_NODE_MODULES`, `NETGET_SSE_PYTHON`); the tests fail rather than skip without them.

- `eventsource_gets_broadcasts_and_resumes_with_last_event_id`: the eventsource npm package
  (WHATWG EventSource) opens /news and gets `welcome`; a request to /post broadcasts `post` to
  it (answered 202); an injected `sse_close` ends the stream, EventSource reconnects after the
  200 ms retry hint with `Last-Event-ID: 2`, and the handler's `resumed` event (id 3) arrives.
  The access log shows both /news requests with their Last-Event-ID.
- `httpx_sse_reads_a_multiline_event_and_respects_refusals`: httpx-sse reads an event whose
  data has four lines (one empty) behind a comment, a 204, and a 404 it refuses to treat as a
  stream.

The broadcast test once lost events when two servers in one test process shared server id 1
in a static table; the table is keyed by bound address for that reason.
