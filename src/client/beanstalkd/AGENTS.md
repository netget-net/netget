# Beanstalkd client

Uses the existing `beanstalkd` feature; no new dependencies. Canonical name Beanstalkd,
TCP/11300. Specification: https://github.com/beanstalkd/beanstalkd/blob/master/doc/protocol.txt

`beanstalkd_request` accepts a structured operation and fields (tube, id, body, priority,
delay, ttr, timeout_secs, count). Supported operations are put, use/watch/ignore, reserve,
reserve_job, delete/release/bury/touch, peek/peek_ready/peek_delayed/peek_buried,
kick/kick_job, stats/stats_job/stats_tube, list_tubes/list_tube_used/list_tubes_watched,
pause_tube and quit. Reserve always uses reserve-with-timeout, 0..=25s (default 0).
`disconnect` immediately closes, including while a reservation or reply is pending.

`beanstalkd_connected` and `beanstalkd_response` go through call_llm_for_client, including
static/script/manual handlers and LLM budgets. Replies contain status plus the applicable
job id/body, count, tube or structured stats/list data. Protocol refusals such as NOT_FOUND,
TIMED_OUT and NOT_IGNORED are response events; malformed replies fail the connection.

The wire encoder uses UTF-8 byte counts. Jobs are text only (non-UTF8 incoming jobs fail
explicitly), at most 65535 bytes. Response headers require CRLF and are capped at 224
bytes; counted payloads are capped at 1 MiB before allocation. YAML data is parsed as
flat scalar mappings or tube-name lists, with a 512-entry bound and independently parsed
scalar values through a scalar-only serde Visitor: collections are rejected before their
children are visited. Aliases cannot refer across records. Duplicate keys fail.
Blank YAML rows count against the row bound. Legacy 1.12 unquoted uname fields
(hostname/os/platform) are opaque text; tube/name fields and list entries preserve
valid unquoted tube names such as true or 123. Quoted 1.13 text remains YAML-decoded.

At most one transaction is in flight because the protocol has no request IDs. A tracked
I/O task owns the split socket. A separately tracked handler task allows injected actions
while the connected event is parked. During a transaction, injected disconnect remains
responsive and other injected commands receive explicit busy rejection. Both event and
handler-action queues are bounded at 16; overload fails rather than dropping an event.
Clean EOF drains final response events; client removal cancels every tracked task.
Every event carries its depth in the handler chain; an answer to an event at depth
`wire::MAX_FOLLOWUPS` (4) is logged and not sent, so a model that answers every response
with another request stops there. `tests/client/beanstalkd/real_server_test.rs` reads the
count from beanstalkd's own `stats`.
Connect/write/complete-response deadlines are 30 seconds, so a slow byte stream cannot
keep a transaction alive indefinitely.

No job storage exists in this client. No TLS or authentication is implemented (neither
belongs to the standard Beanstalkd protocol). Drain/binlog administration is outside the
advertised action set. The implementation remains Experimental; tests use a real
beanstalkd daemon and the existing NetGet server, plus raw negative/lifecycle fixtures.
