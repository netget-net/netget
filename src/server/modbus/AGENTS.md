# Modbus TCP Protocol Implementation

## Overview

Modbus TCP server. The LLM plays the device: it decides what a coil or register **reads as**,
whether a write is accepted, and which exception to raise when it is not. NetGet owns the wire
format, so the model never sees a transaction id, a byte count or a bit-packing rule.

**Status**: **Stable**, set 26 September 2026. See "Maturity: the six conditions" at the foot of
this file for what was checked, what was false when it was checked, and what the rating does
*not* cover. Two independent clients drive every function code the server implements:

| peer | what it is | test |
|---|---|---|
| `tokio-modbus` 0.17 | a Rust client, not linked by the server | `e2e_test.rs::test_modbus_reads_writes_and_exceptions_against_tokio_modbus` |
| `mbpoll` | a C program on libmodbus | `real_client_test.rs::test_modbus_reads_writes_and_exceptions_against_mbpoll` |

Neither is `#[ignore]`d and neither can skip: `require_mbpoll` **fails** when the binary is
absent, and `tokio-modbus` is an unconditional dev-dependency, so that evidence compiles wherever
the suite does. The blocking CI `test` job runs `tcp,http,dns,udp,redis,mcp-stdio` only, so it
executes none of this; run it yourself.
**Spec**: MODBUS Application Protocol Specification V1.1b3; MODBUS Messaging on TCP/IP
Implementation Guide V1.0b
**Port**: 502, declared as `PrivilegeRequirement::PrivilegedPort(502)`
**Feature**: `modbus` (no optional dependencies — the codec is hand-rolled)

### Why `PrivilegedPort(502)` and not `None`

502 is below 1024, so this requirement **genuinely fires** — unlike `svn`'s
`PrivilegedPort(3690)`, which was dead code. It is also not over-claiming: `server_startup.rs`
only enforces a `PrivilegedPort` requirement when the port *actually requested* is below 1024,
so an unprivileged user starting the server on 5020 (as every test and every example here does)
is unaffected.

## Library choice

**Hand-rolled**, in `codec.rs`. `tokio-modbus` has a `tcp-server` feature and was considered,
but:

- Its server API wants a `Service` returning a `Response` enum, which would put the crate's own
  encoder between the model and the wire. Using it on both sides of the tests would then mean
  testing `tokio-modbus` against itself — no evidence at all.
- The format is genuinely small: a 7-byte MBAP header and eight function codes.

`tokio-modbus` 0.17 (MIT OR Apache-2.0) is instead a **dev-dependency**, used as the independent
client in `tests/server/modbus/e2e_test.rs`. That asymmetry is the point: `grep -rn tokio_modbus
src/` finds nothing.

## What is implemented

| FC | Name | Request → response |
|---|---|---|
| 0x01 | Read Coils | start+quantity → byte count + LSB-first packed bits |
| 0x02 | Read Discrete Inputs | same |
| 0x03 | Read Holding Registers | start+quantity → byte count + big-endian u16s |
| 0x04 | Read Input Registers | same |
| 0x05 | Write Single Coil | address+0x0000/0xFF00 → request echoed |
| 0x06 | Write Single Register | address+value → request echoed |
| 0x0F | Write Multiple Coils | start+quantity+bytes → start+quantity |
| 0x10 | Write Multiple Registers | start+quantity+bytes → start+quantity |

Exception responses are `function_code | 0x80` followed by the exception code. The server itself
produces 0x01 illegal function, 0x02 illegal data address, 0x03 illegal data value, 0x04 server
device failure and 0x0B gateway target device failed to respond; the model may choose any code
the specification defines (1-6, 8, 10, 11).

**Not implemented**: Modbus RTU and ASCII (this is TCP only), FC 0x07/0x08/0x0B/0x0C/0x11/0x14/
0x15/0x16/0x17/0x18/0x2B, and Modbus Security (TLS).

## Architecture decisions

### 1. No register file — the model answers every read

There is deliberately **no storage** in this implementation: no register array, no coil bitmap,
no persistence. Every read raises an event and the model supplies the values. This is the
project rule from `AGENTS.md`, and it is also the whole point of the protocol here — an
LLM-invented tank level that drifts over successive reads is more interesting than a static
array, and it is something only a model can produce.

Continuity across requests comes from **server memory** (`set_memory` / `append_memory`, both
common actions available on every event) or, if real persistence is wanted, from the generic
SQLite facility. A protocol-local database would be the wrong answer.

### 2. Spec-determined failures never reach the model

`codec::parse_request` returns `Err(exception_code)` for everything the specification decides on
its own: an unknown function code is *always* 0x01; a quantity outside 1-2000 (bit reads),
1-125 (register reads), 1-1968 (coil writes) or 1-123 (register writes) is *always* 0x03, as is
a byte count that disagrees with the quantity, a single-coil value other than 0x0000/0xFF00, and
a PDU too short to carry its fields; a range running past 0xFFFF is *always* 0x02. Those are
answered directly from `mod.rs`, with no LLM call.

The model is only asked the questions a device actually answers: what does this read return, and
do I accept this write.

### 3. Framing is server-side, so the actions carry meaning rather than bytes

Actions return `ActionResult::Custom` with structured data — `{"registers": {"40": 1834, "41":
1450}}`, `{"bits": {"40": true}}`, `{"exception_code": 2}` — and `mod.rs` builds the PDU and the
MBAP header from the request it parsed. Consequences:

- The model cannot desynchronise a transaction id or emit a wrong byte count.
- The model never has to echo an identifier, which is exactly the failure mode that makes
  static handlers useless for DNS.
- There is no raw-bytes or base64 action parameter anywhere in this protocol, and therefore no
  encoding to get wrong. (`send_tcp_data`'s documented-but-not-decoded `hex` field is the
  cautionary case; it cannot recur here because nothing here takes encoded bytes.)

**The framing functions bound their output, and did not used to.** `encode_adu`,
`encode_bits_response` and `encode_registers_response` all return `Result<Vec<u8>, EncodeError>`
and refuse anything this codec's own parser would reject:

- `encode_adu` wrote `(pdu.len() as u16) + 1` unchecked while `try_parse_adu` refuses any MBAP
  length outside `2..=254`. A 254-octet PDU produced a length field of 255 — a frame this
  codec rejects on the way back in. Past 65534 octets the increment also overflowed, which
  panics in every debug and test build (there is no `[profile.dev]` in `Cargo.toml`, so
  `overflow-checks` is on there) and, before `[profile.release] overflow-checks` was turned on,
  wrapped silently where it shipped.
- `encode_registers_response` wrote `(values.len() * 2) as u8` and `encode_bits_response` wrote
  `byte_count as u8`. At 128 registers the declared byte count was **0** followed by 256 octets
  of data; at 2040 bits the same shape. On this protocol a register value is a plant reading,
  and a frame that lies about how many of them it carries is worse than no frame.

None of the three was reachable from the wire: `mod.rs` checks the model's value list against
the quantity `parse_request` already validated (≤2000 bits, ≤125 registers) before it encodes,
and every PDU `send_pdu` frames comes from these same bounded encoders. They were unguarded in
`pub fn`s, which is the asymmetry the property tests exist to find — a bound enforced on decode
against a hostile peer and not on encode against the model. `mod.rs` answers a refusal with
exception 0x04 and `decision=fail_closed_encode` rather than unwrapping it.

### 4. Fail closed

The server answers with exception **0x04 server device failure** and an ERROR log when:

- the LLM call itself failed (`fail_closed_llm_error`);
- the model answered with an action this event does not offer — bits for a register read, a
  write-ack for a read. Each event offers the model only its own actions, so the LLM layer treats
  such an answer as an *unknown action*, re-asks once (`MAX_UNKNOWN_ACTION_RETRIES` in
  `src/llm/conversation.rs`), and then fails the call: it arrives here as an LLM error and is
  logged `fail_closed_llm_error`, after a `LLM failed to use valid actions` line;
- no usable action came back — including an empty answer, and a `send_modbus_registers` carrying
  a value outside 0-65535, which `execute_action` refuses outright so no action survives
  (`fail_closed_no_action`);
- a static or script rule, which is not held to the event's vocabulary, answered the wrong
  *kind* (`fail_closed_wrong_shape`);
- the answer carried the wrong *number* of values for the requested quantity
  (`fail_closed_wrong_shape`).

None of those produces a plausible-looking response. A truncated register block would be worse
than an exception: the client would believe it. `tests/server/modbus/llm_failure_test.rs` drives
every clause from the wire and asserts both the PDU and the per-request `decision=` line.

**Silence is the wrong answer here, and that is not the general rule.** ~20 protocols in this
project are deliberately silent on LLM failure because every reply they define is a positive
assertion. Modbus is not one of them: it has an exception response, 0x04 means exactly "an
unrecoverable fault occurred while handling this request", and a client that receives it
retries or alarms instead of blocking until its own timeout. What must never happen is a
*value* — a fabricated register read is an assertion about plant state.

### 4b. `decision=` distinguishes the three ways 0x04 reaches the wire

The wire cannot carry the distinction: a model that deliberately refuses with exception 0x04
and a model that never answered at all both put `04` in the PDU. So every request logs a
stable `decision=` token, as `src/server/radius/` does:

| token | meaning | level |
|---|---|---|
| `model_answer` | the model supplied the values, or accepted the write | DEBUG |
| `model_reject` | the model chose an exception itself | DEBUG |
| `model_address_absent` | the model answered a read with the addresses the device has, and one asked for is not among them: exception 0x02 | DEBUG |
| `spec_reject` | `parse_request` decided; the model was never asked | DEBUG |
| `unit_mismatch` | addressed to another unit id | WARN |
| `fail_closed_llm_error` | the LLM call failed — the backend, or an answer outside the event's vocabulary | **ERROR** |
| `fail_closed_no_action` | the model was asked and returned nothing usable | **ERROR** |
| `fail_closed_wrong_shape` | wrong number of values, or a rule answered the wrong kind | **ERROR** |
| `fail_closed_encode` | an encoder refused a PDU (unreachable today; a ratchet) | **ERROR** |

Those are per request. Four more close a connection rather than answer anything:

| token | meaning | level |
|---|---|---|
| `fail_closed_framing_error` | protocol id not 0, or MBAP length outside `2..=254` | **ERROR** |
| `fail_closed_buffer_overflow` | more than `MAX_BUFFERED` octets queued | **ERROR** |
| `fail_closed_idle_timeout` | a read deadline expired | INFO |
| `fail_closed_connection_cap` | over `MAX_CONNECTIONS`, refused at accept (written by `accept_bounded`) | WARN |

`grep 'decision=fail_closed_'` finds every request the model did not actually answer and every
connection the server dropped. The error text itself never reaches the wire — only the
exception code does, or nothing.

### 4c. Model-supplied numbers are refused, never narrowed

`execute_action` rejects a register value outside 0-65535 and an `exception_code` outside the
set the specification defines (1-6, 8, 10, 11), rather than casting. `65736 as u16` is `200`,
which on this protocol is a plausible-looking tank level with no error anywhere; `0x104 as u8`
is `0x04`, a fail-closed answer manufactured out of a typo. `pdu_from_results` filters rather
than casts for the same reason, so a value that somehow arrived out of range makes the count
wrong and becomes an exception instead of a reading.

Addresses and quantities cannot wrap at all: they are `u16` straight off the wire, never
model-supplied, and `check_range` rejects `start + quantity > 0x10000` in `u32` arithmetic.
`tests/server/modbus/e2e_test.rs::test_out_of_range_model_values_are_refused_not_narrowed`
pins all of this.

### 5. Connection state machine

Copied in shape from `src/server/tcp/mod.rs`: `Idle → Processing → Accumulating`, with one
addition — the per-connection `buffer` doubles as the **framing accumulator** and as the queue
for bytes that arrive while an LLM call is in flight. `Accumulating` means "a partial ADU is
buffered"; `Processing` means "a request is with the model". A second write landing mid-call is
appended and picked up by the loop that is already running, so requests on one connection are
answered in order and never concurrently.

**That ordering holds because the reader appends.** Every read goes into the accumulator from
the reader task itself, in arrival order and under the connection lock (`admit_read`), and only
the move into `Processing` spawns the one framing-and-answering task (`answer`). The append used
to happen in a task spawned per read: the decision was one lock acquisition, but nothing orders
spawned tasks, so a later read's bytes could land ahead of an earlier read's — the back of an ADU
in front of its MBAP header, which is a framing error and a closed connection.
`tests/server/modbus/read_order_test.rs` writes each request in two halves split inside the
header, four outstanding per connection; with the append back in a spawned task it failed 200 of
200 runs under load (closed mid-stream, or an answer framed out of the wrong bytes), and it
passes 200 of 200 as it is.

The connection is registered in the map **synchronously in the accept loop**, before the reader
task is spawned, for the same reason TCP does it: a client that writes immediately after
`connect()` must not lose its first frame.

A framing error (`protocol_id != 0`, or an MBAP length outside 2..=254) closes the connection.
Neither is answerable — we no longer know where the next frame starts.

**Closing means the whole connection, reader included.** `close` mostly runs on the `answer` task
and shuts the write half, so the peer reads EOF; it also signals the connection's `closed`
`Notify`, and the reader's `select!` stops on it. Without that signal the reader went on reading
the still-open socket and held the connection-cap permit until the peer hung up or went quiet for
the idle bound — so a peer could keep a slot by sending one malformed header and holding its end
open. `bounds_test.rs::the_connection_cap_refuses_silently_and_every_close_returns_its_slot`
asserts the slot comes back while the peer is still connected.

The buffer is capped at `MAX_BUFFERED` (eight ADUs' worth), enforced **on append**, in
`admit_read`, which is the only code that grows it — the framing loop only drains. That
placement is what matters: while a request is with the model, `admit_read` appends the new
bytes and starts nothing, and the framing loop does not run until the LLM call returns, so a
loop-side check would leave the queue unbounded for the whole call (two minutes at the shipped
`--llm-queue-timeout`). Outside a model call the bound cannot be reached, since an incomplete ADU
is at most 259 octets. An overrun closes the connection rather than trimming — a peer that
overruns the queue has desynchronised anyway.

### 6. Dashboard injection (peer handle)

Every connection registers a peer handle (`peer_support::register_peer_channel` +
`spawn_peer_command_task`) right after it is tracked, and removes it on every exit path (EOF,
read error, `close()`), so the rail offers `[ disconnect this peer ]`. Byte and packet counters
are updated on every read and every write.

What is injectable is narrow, and honestly so: the four wire verbs return
`ActionResult::Custom` and are framed against the request being answered (transaction id,
quantity), so an injected `send_modbus_*` is reported as "executed (nothing to write)" — a
Modbus server never initiates, so there is nothing it *could* write unprompted. The one verb
that reaches the wire from outside is `close_connection` (an explicit arm in
`execute_action`, not offered to the model), which half-closes the socket so the peer reads
EOF. No bespoke Custom path was added.

This is deliberately **not** the redis-style refactor (encoders moved into `execute_action`
returning `Output`), and moving them would not help: the MBAP header needs the request's
transaction id and unit id, `encode_bits_response`/`encode_registers_response` validate
against the request's quantity, and `encode_write_ack` literally echoes the request — none of
which exists outside `answer`'s request context. More fundamentally, Modbus TCP has no
protocol-legal unsolicited server frame: a client matches responses to requests by
transaction id, so anything injected between exchanges would either be dropped or desync the
master. There is no fix to make; `close_connection` is the entire meaningful surface, and
`tests/server/modbus/peer_inject_test.rs` pins exactly that.

## LLM integration

### Events (all three are emitted)

| Event | Raised for | Actions offered |
|---|---|---|
| `modbus_read_bits` | FC 1, 2 | `send_modbus_bits`, `send_modbus_exception` |
| `modbus_read_registers` | FC 3, 4 | `send_modbus_registers`, `send_modbus_exception` |
| `modbus_write_request` | FC 5, 6, 15, 16 | `send_modbus_write_ack`, `send_modbus_exception` |

Every event data payload carries `unit_id`, `function_code`, `function`, `start_address`,
`quantity` and `answer_with`; reads add `bit_type` (`coil` / `discrete_input`) or `register_type`
(`holding` / `input`) so the model knows whether it is being asked about an output it can also
write or a read-only measurement; writes add `coil_values` or `register_values`.

**A read is answered with an address-keyed map, and NetGet does the address comparison.**
`send_modbus_registers {"registers": {"<address>": value}}` and `send_modbus_bits {"bits":
{"<address>": bool}}` give the addresses the device has; `mod.rs` (`read_from_map`) serves the
requested window from them in address order, ignores entries outside it, and answers
**exception 0x02 for the whole request when any requested address has no entry** — logged
`decision=model_address_absent`, which is the model's answer (its map says the device has no such
address), not a fail-closed. The positional `values` array, one value per requested address from
`start_address`, is still accepted from handlers and scripts, with its length checked as before.

`answer_with` (`actions::answer_with_for_request`) asks a read for "a registers object holding
every holding register your instructions give this device, keyed by address", names the
addresses asked for, and says NetGet answers exception 2 for any of them the object leaves out.
It asks the model to compare nothing. A write carries no values to key, so its `answer_with` keeps
the check-first wording: the addresses, a worked comparison computed from the request ("one whose
holding registers are 0 to 9 has no holding register 10"), the literal exception-2 action, then
`send_modbus_write_ack`. The hint changes nothing NetGet enforces — decision 2's
spec-determined refusals still never reach the model.

**Why the map, and what the prompt alone could not do.** Told "you are a PLC with ten holding
registers at addresses 0 to 9, all zero. There is nothing at any other address", llama3.1:8b
answers a read of 500-501 by describing the whole device: ten zeros. Its reasoning says the
device "has only holding registers 0 to 9, which is exactly what the client is asking for" — it
restates the instruction rather than comparing 500 with 0-9. Five wordings that asked it to make
the comparison (real-model eval, seed 42, 5 runs each) scored 0/5 to 1/5 on this case, with the
positional answer:

| wording (positional `values`) | illegal-address | holding-registers |
|---|---|---|
| no hint | 0/5 — `[0, 0]` every run | 5/5 |
| hint, values first, exception second | 0/5 — prose instead of JSON 4 times, `[0, 0]` once | 5/5 |
| hint, check first, exception as a literal action | 0/5 — `[0, 0]` every run | 4/5 |
| + the computed comparison, + check-first event and action descriptions | 1/5 (3/5 re-measured 29 September) | 5/5 |
| the same as a yes/no question | 0/5 — the action example's `[1834, 1450]` 4 times | 5/5 |

Keyed by address, the model's natural answer is a correct one: `{"0": 0, …, "9": 0}` has no entry
for 500, and the server answers exception 2. With the map and the no-comparison hint the case
measured **5/5**, and holding-registers stayed 5/5 (29 September 2026, same parameters). The
answer the model gives did not change; what NetGet reads it as did.

There is no event for an unsupported function code, because there is nothing to decide — see
decision 2.

### Actions

- `send_modbus_bits { bits: {"<address>": bool} }` — answers FC 1/2 from the addresses given;
  a requested address with no entry is exception 0x02. `{ values: [bool] }` (length must equal
  `quantity`) is still accepted.
- `send_modbus_registers { registers: {"<address>": int 0..65535} }` — answers FC 3/4 the same
  way. `{ values: [int 0..65535] }` (length must equal `quantity`) is still accepted. A key that
  is not a decimal address 0-65535, or a value out of range, is refused by the executor with the
  address named.
- `send_modbus_write_ack {}` — accepts a write; the echo is built from the request.
- `send_modbus_exception { exception_code }` — refuses. Accepts a number the specification
  defines (1, 2, 3, 4, 5, 6, 8, 10, 11) or a name (`"illegal_data_address"`, ...). Anything
  else is refused with a message listing the real set, because an undefined code is one no
  client can interpret.

## Startup parameters

| Name | Type | Effect |
|---|---|---|
| `unit_id` | integer 0-255, optional | When set, requests addressed to a different unit id are answered with exception 0x0B, as a Modbus/TCP gateway would. When omitted the server answers on every unit id, which is what most Modbus/TCP devices do. |
| `first_byte_timeout_secs` | integer ≥ 1, optional | Seconds a new connection may send nothing before it is closed. Default 30 (`FIRST_BYTE_READ_TIMEOUT`). |
| `idle_timeout_secs` | integer ≥ 1, optional | Seconds a connection that has sent a request may then send nothing. Default 600 (`IDLE_BETWEEN_REQUESTS_TIMEOUT`). |

All three are read in `actions.rs::spawn` and used in `mod.rs` — neither declared-but-unread nor
read-but-undeclared. An out-of-range `unit_id` or a zero timeout produces a clean `Err` from
`spawn()`, never a panic.

## Connection bounds

Modbus has **no authentication step of any kind**, so "pre-authentication" here means "anyone who
can reach the port". Before September 2026 this server accepted without limit and bounded no read
in time, so such a peer could connect, say nothing, and hold a socket, a read task, a peer handle
and an `AppState` row forever. It now declares both halves; the constants and the reasoning live
beside them in `src/server/modbus/mod.rs`.

| Bound | Value | Why this number |
|---|---|---|
| `codec::MAX_ADU_LEN`, declared as `max_inbound_bytes` | 260 octets | The specification's maximum: a 7-octet MBAP header and a 253-octet PDU. It governs the **inbound** direction through the MBAP length field — 254 is the largest legal value and 255 is refused by closing. Outbound, the encoders refuse anything past it, and every response to a legal request fits. |
| `MAX_BUFFERED` | 2080 octets | Eight ADUs' worth of bytes queued behind a request that is with the model; see decision 5. |
| `FIRST_BYTE_READ_TIMEOUT` | 30s | Modbus TCP is client-speaks-first and a client sends its first PDU inside its own connect path (`tokio-modbus` and `mbpoll` both do), so a peer that has sent nothing has begun no transaction. |
| `IDLE_BETWEEN_REQUESTS_TIMEOUT` | 600s | Modbus defines no keepalive, so there is no protocol interval to sit above; what there is, is polling, and a SCADA master polls on a sub-second to few-second cycle. The number is set by *this* server: a request is answered on its own task, so the reader keeps reading while a request is answered and a peer waiting for its own reply — including one parked on a `manual` rule for a human, 300s by default — is silent on this socket for the whole of that work. Ten minutes leaves that a factor of two. Real Modbus/TCP gateways reap an idle connection at ~60s; being ten times more patient is the deliberate price of letting a human answer. |
| `MAX_CONNECTIONS` | 256 | Refusal: **nothing**. Every Modbus server message is a reply and carries the transaction identifier, unit id and function code of a request this peer has not sent, so inventing one means inventing a transaction — worse than silence, for the same reason twenty protocols here are deliberately silent on an LLM failure. The reason lives in the log, under `decision=fail_closed_connection_cap`. |

**NetGet's own Modbus client (`src/client/modbus/`) is a peer these bounds can close.** It
sends nothing until the model or the operator asks for a read or a write — a dashboard-created
client answers its connect event with nothing — so, pointed at this server and left alone past
`first_byte_timeout_secs` (or `idle_timeout_secs` after its last request), it is closed here and
reports `Disconnected`. That is the right outcome rather than a stranding: a real Modbus/TCP
device reaps an idle master far sooner (~60s), so the client is written to report the close,
not to keep the socket alive. It frames with this module's `codec.rs` (`encode_request` and
`parse_response` sit beside the server's decoder so the two directions cannot drift).

**The deadline wraps the `read()` and nothing else**, so the model round-trip is outside it by
construction; what it measures is the peer's own silence. An idle close writes nothing and logs
`decision=fail_closed_idle_timeout`.

`tests/server/modbus/connection_bounds_test.rs` drives the two deadline defaults from the wire,
including that the refusal really is silent and that a peer that has sent one request is still
answered 38 seconds later. Replacing the `tokio::time::timeout` around the read with the bare
call makes the first test hang for its whole 70-second window and fail.
`tests/server/modbus/bounds_test.rs` drives every other bound — `MAX_ADU_LEN` at 260 and 261
octets, `MAX_BUFFERED` at exactly 2080 queued octets and one more, `MAX_CONNECTIONS` at 256 and
257 plus the slot coming back after both kinds of close, both deadline parameters, the four
quantity limits and the `unit_id` filter — and each was verified by removing the bound and
watching its test fail. `tests/tcp_server_bounds_ratchet_test.rs` fails the build if a deadline
or the cap is removed, and `tests/accept_bounded_test.rs` covers the shared helper.

## Known limitations

1. **TCP only.** No RTU, no ASCII, no serial.
2. **Data model addressing is raw.** `start_address` is the protocol address, so a client asking
   for "40001" in the classic numbering sends 0. The event parameter says so; the model is not
   asked to guess.
3. **No Observe-style push.** A Modbus server never initiates; `get_async_actions()` is
   deliberately empty.
4. **Concurrency is per-connection serial.** Pipelined requests on one socket are answered in
   order, one LLM call at a time. That is correct but not fast; use script or static handlers for
   throughput.

## Example prompts

```
listen on port 5020 via modbus
You are a water treatment PLC.
Holding register 0 is the tank level in cm, normally 170-190 and drifting slowly.
Holding register 1 is pump speed in RPM, 0 when coil 0 is off.
Coil 0 is the pump run command; accept writes to it and remember the state.
Any address above 9 does not exist: reply illegal_data_address.
```

```
listen on port 5020 via modbus
Impersonate a temperature transmitter. Input registers 0 and 1 hold a 32-bit
big-endian value which is degrees Celsius times 100. Reject every write with
illegal_function - this device is read-only.
```

## Maturity: the six conditions

The root `AGENTS.md` defines `Stable` as six conditions. Re-derived against source on
26 September 2026 rather than inherited. All six hold; three of them only after this pass
repaired something:

| # | condition | holds? |
|---|---|---|
| 1 | two independent third-party clients, no skip, no `#[ignore]` | **yes** — `tokio-modbus` 0.17 and libmodbus's `mbpoll`, each driving all eight function codes; `require_mbpoll` hard-fails; the server does not link `tokio-modbus` |
| 2 | the pcap oracle is green over its wire traffic | **yes, as of this pass** — `pcap_oracle_test.rs` runs `mbtcp` over a session of all eight function codes and an exception, both directions |
| 3 | a fuzz target exists and has run clean, with a corpus | **yes** — `modbus_adu`, 226,125 runs in 61s, clean; see below |
| 4 | every declared bound has a test | **yes, as of this pass** — `bounds_test.rs` and `connection_bounds_test.rs`, each verified by removal |
| 5 | both `AGENTS.md` files verified against source in this pass | **yes** — this file and `tests/server/modbus/AGENTS.md`; the corrections are below |
| 6 | no `#[ignore]`, no skip-when-missing gate | **yes** — `grep -rn '#\[ignore\]' tests/server/modbus/` is empty |

**Condition 1 was true of a sample, not the surface.** Both clients existed, but `tokio-modbus`
never issued FC 2, 5 or 15 and `mbpoll` never issued FC 2, 5, 15 or 16 — while `metadata()`
named `read_discrete_inputs` among the calls `tokio-modbus` had decoded. Both tests now cover all
eight, and the coil writes are accepted only if the bits each client packed reach the model
exactly as sent, so FC 15's bit field is checked by two independent packers.

**Condition 2 was satisfied by exceptions alone.** The only ADUs ever handed to `mbtcp` were
the spec-rejected ones in `test_modbus_spec_exceptions_and_mbap_framing`, because the success
paths are read by `tokio-modbus`, which never shows the test the bytes. Register blocks, packed
coil bytes and write echoes — most of what `codec.rs` writes — had never been dissected.

**Condition 4 turned up a real defect, not just missing tests.** `MAX_CONNECTIONS` was declared
and enforced at accept, but a connection the server closed for a framing error or a queue
overrun kept its permit for as long as the peer held its end open (see decision 5). The
declared bound `max_inbound_bytes(MAX_ADU_LEN)` governs the direction it reads as — inbound,
through the MBAP length field — unlike `coap`'s, which governed what it wrote; the outbound side
is `tests/codec_property_test.rs`. The idle deadline could not be tested at its ten-minute
default, which is why it is now a startup parameter as `tcp`'s is. `MAX_BUFFERED` was checked at
two sites, one of which could never fire; it is now checked at the one that can.

**Condition 5 turned up claims the code did not keep**, all now true or removed: the wrong-kind
failure was said to be logged `fail_closed_wrong_shape` and is `fail_closed_llm_error` when the
model produces it; an out-of-range register value was said to be "dropped, which makes the count
wrong" and is in fact refused whole by `execute_action`; per-connection tasks were said to be
untracked and are spawned with `spawn_server_task`; `MAX_BUFFERED` was said to be checked at two
sites; "the only" startup parameter was one of three; and the codec's line count was wrong.

**Condition 3 needs no depth bomb, and why is the point.** Modbus has no nesting: an ADU is a
flat header and a flat PDU, and nothing in `codec.rs` calls itself, so there is no recursion
class for a depth bomb to reach. What a peer controls is every length it declares, so the
corpus has a seed on each — `max_adu` (length 254), `over_max_adu` (255),
`declared_longer_than_sent`, `zero_length`, `not_modbus`, each quantity limit at its maximum,
and a byte count that disagrees with its quantity. The target also asserts three invariants the
server relies on without checking: framing round-trips through `encode_adu`, every read
`parse_request` accepts can be answered and framed, and an FC 5/6 acknowledgement parses back as
its request. Rebuild before believing it:

```bash
cd fuzz && rustup run nightly-2025-12-04 cargo fuzz run -s none modbus_adu <copy of corpus> \
    -- -max_total_time=60 -timeout=25 -rss_limit_mb=2048
```

### What Stable does *not* mean here

It means the evidence for the surface this server implements is complete. The surface is a
subset of Modbus: **TCP only (no RTU, no ASCII), eight function codes (1-6, 15, 16), no Modbus
Security, no real PLC ever pointed at it.** A master that needs FC 0x17 or device identification
(0x2B/0x0E) gets exception 0x01, correctly, and cannot use this server for that. The `openvpn`
precedent does not apply: a Modbus master can use this server for what Modbus is for — two
independent ones did, for every function code it implements, with the bytes asserted.

## References

- [MODBUS Application Protocol Specification V1.1b3](https://modbus.org/docs/Modbus_Application_Protocol_V1_1b3.pdf)
- [MODBUS Messaging on TCP/IP Implementation Guide V1.0b](https://modbus.org/docs/Modbus_Messaging_Implementation_Guide_V1_0b.pdf)
- [tokio-modbus](https://docs.rs/tokio-modbus) — the test client, not a runtime dependency
