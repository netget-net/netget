# Gearman client

Feature `gearman`; canonical Gearman; TCP/4730. No new dependencies. Reuses the
existing server's binary header/NUL argument codec, with a continuous bounded Tokio
response reader. References: https://gearman.org/protocol/ and pinned gearmand 2.1.0
source at https://github.com/gearman/gearmand/tree/2.1.0 (libgearman-server/server.cc,
constants.h and docs/source/protocol/gear.rst).

Startup `role` is `submitter` (default) or `worker`. `gearman_request` supports submit
(normal/high/low and foreground/background), status/GET_STATUS, echo/ECHO_REQ and
exceptions/OPTION_REQ. Submission takes `function_name`, optional `unique_id` and
`workload`; UTF-8 byte counts and wire framing are computed by Rust. `function_name`
is deliberately different from the inbound response's `function`: the shared model
action normalizer reserves top-level `function` for tool envelopes. The advertised
static/script examples and mocked model are tested with `function_name`.

The selected worker role uses `gearman_worker`: register/CAN_DO, unregister/CANT_DO,
reset/RESET_ABILITIES, set_id/SET_CLIENT_ID, grab/GRAB_JOB, grab_unique/GRAB_JOB_UNIQ,
sleep/PRE_SLEEP and progress/data/warning/complete/fail/exception. Grab requires a
registered ability. Assignment function/type/handle must match the pending grab and
registered abilities. Work replies require a handle assigned on this connection;
complete/fail/exception remove it. Progress requires 0 <= numerator <= denominator,
denominator positive and at most u32::MAX. Sleep requires a no_job response; wait for
NOOP before grabbing again. Waking and new assignments begin fresh handler chains.
The client never executes submitted workloads as programs or completes jobs implicitly.

The existing NetGet server remains model-as-worker and refuses worker connections with
ERROR not_supported. The NetGet pair therefore uses its submitter client with that
server. Worker interoperability is verified against independent gearmand with the
gearman CLI producer, including progress/data/warning/complete/fail/exception. The
submitter is verified against independent gearmand with its CLI worker, all priorities,
background jobs, echo/status/options, and the mocked model/shared client memory.

Events: gearman_connected (role/address); gearman_response (originating request plus
job_created/status/echo/option/no_job/job_assigned response); gearman_job_update
(original submit request, handle, kind, terminal, applicable payload/progress);
gearman_worker_wakeup; gearman_error (code, text and pending request if present).
Foreground updates may interleave with another pending command and are correlated by
handle. Background jobs retain no local entry and receive no worker updates. At most
one response-producing request is pending because Gearman has no request IDs. ERROR
always closes after emitting its event; asynchronous no-reply worker failures cannot
be correlated safely. Duplicate active nonempty unique IDs for the same foreground
function are rejected before writing to avoid ambiguous handles. Unsolicited/mismatched
responses, unregistered assignments and unknown/duplicate job handles fail explicitly.

Outbound payloads are UTF-8 strings; embedded NUL is preserved in the final workload,
echo or work data argument. Binary inbound workloads/results expose payload
{text:null, bytes:<exact count>, utf8:false}, so the model can fail an assigned binary
job by handle without interpreting encoded bytes. No raw/hex/base64 actions exist.

Bounds: packet body 1 MiB before allocation; function names 1..512 bytes, unique IDs
0..64 bytes without NUL, handles 1..63 printable ASCII bytes; at most 64 abilities and
64 foreground/assigned jobs; event/frame/action queues 16. Connect, whole writes,
partial frame and pending request deadlines 15 seconds. Idle workers may sleep and
jobs may wait indefinitely, with their retained counts bounded. Disconnect interrupts
pending reads or writes; other writes may be rejected busy. A handler response chain
stops at depth 4. The command channel is registered before the connected event; the
reader, session and dispatcher are all tracked and canceled on client removal. Final
events drain after EOF. Common actions and memory updates use existing shared state.
Only correlation/lifecycle state is retained: no queue, domain database or persistence.

Plain TCP only: no TLS/authentication, reconnect,
admin protocol, scheduled/reduce jobs, timed abilities or GRAB_JOB_ALL. Existing server
Wireshark support is `gearman` (TCP decode-as); this client pass makes no new pcap or
fuzz maturity claim.

## Maturity: Beta

All four conditions of the client bar hold, on the real-server tests in `tests/client/gearman/`:

1. the peer is gearmand with the gearman CLI as producer and worker — third-party, and not a library this client is built on;
2. a missing peer fails the test, never skips it;
3. a real session, completed against that server;
4. the client acts on the model's answer, asserted from the server's side: the CLI worker transforms the workload the mocked model submitted (`CHOSEN BY MODEL` comes back only through gearmand and the worker), and a script worker answers jobs the CLI producer prints. Emptying the loop over the model's actions fails it.

Verified 1 November 2026 by running the suite against the installed peer and by that mutation. The CI job that installs the peer is in `.github/workflows/protocol-pairs.yml`.
