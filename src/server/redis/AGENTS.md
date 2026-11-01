# Redis Protocol Implementation

RESP2 server (RESP3 after `HELLO 3`), with pub/sub and an optional cluster mode.
`redis-protocol` v6.0 parses inbound frames; responses are encoded by hand in `actions.rs`
(`encode_*`, the single source of truth — each reply verb's executor returns the encoded
bytes as `ActionResult::Output`). The LLM owns every reply to a data command — there is no
key space, no storage, and no command dispatch table in Rust.

What Rust does own is protocol mechanics: `HELLO` negotiation, the pub/sub subscription
registry and message fan-out between connections of one server (`pubsub.rs`), and in cluster
mode the hash-slot routing and `CLUSTER` introspection (`cluster.rs`, slot arithmetic in
`src/utils/redis_keys.rs`). The model decides policy on top: whether a subscription is
allowed, whether a published message is delivered and what the publisher is told, what the
server publishes on its own, and which node owns which slots.

**State**: Beta — **two** independent clients, sharing no code with each other or
with the `redis-protocol` crate the server parses with:

- **redis-rs** (Rust) in `tests/server/redis/e2e_test.rs`: six tests, one per
  RESP2 reply type, each deserialised into the Rust type the test asked for.
- **redis-cli** (C; the binary here is `valkey-cli`, the redis-cli-compatible
  fork) in `real_client_test.rs`: seven commands on one connection, asserted as
  one ordered list of what `--no-raw` printed. That reads the type off the wire
  rather than coercing it — a bulk string is quoted, an integer is
  `(integer) n`, a nil is `(nil)` and not an empty line, an error is `(error) …`
  — and because it is one ordered list, a reply landing against the wrong command
  fails as a mismatched line rather than passing as a same-typed value. It
  hard-fails when the binary is absent.

Not Stable: Stable additionally wants spec compliance and scripting support
reviewed, which has not been done. (This file used to say Experimental while
`actions.rs` said Beta — the code was right.)
**Port**: 6379 by default. **Privilege**: `None` (6379 > 1024).
**Stack**: `ETH>IP>TCP>Redis`. **Spec**: RESP2.

## What the model sees and controls

**Events**:

- `redis_command`, one per decoded RESP frame that Rust does not answer itself.
- `redis_subscribe` — a `SUBSCRIBE`, `PSUBSCRIBE` or `SSUBSCRIBE` that fits every bound;
  carries `command`, `channels` (the names or patterns, in order), `subscriptions` (what the
  connection already holds) and `protocol`. Answer `redis_accept_subscription` or
  `redis_error` (e.g. `NOPERM …`).
- `redis_publish` — a `PUBLISH` or `SPUBLISH` whose message fits its bound; carries
  `command`, `channel`, `message`, `receivers` (how many deliveries `redis_deliver_message`
  would make now) and `protocol`. Answer `redis_deliver_message` (deliver, reply with the
  count), `redis_integer` (reply without delivering), or `redis_error`.

`redis_command` fields:

| Field | Notes |
|---|---|
| `command` | the frame flattened to a single space-separated string, e.g. `SET mykey hello` — for display, log templates and quick matching |
| `args` | the frame's arguments, one string each, command name first: `SET k "a b c"` is `["SET", "k", "a b c"]` |
| `hex_args` | indices into `args` of the arguments given as lowercase hex because they are not valid UTF-8; usually `[]` |
| `protocol` | the connection's RESP version, `2` or `3` |

`command` cannot carry argument boundaries — `SET k "a b c"` and `SET k a b c` join to the
same string — so anything that needs the arguments reads `args`. A RESP bulk string is
binary-safe and a JSON string is not, so an argument that is not valid UTF-8 is hex-encoded
and its index listed in `hex_args`; every other argument is its literal text, even one that
happens to look like hex. The encoding is stated per argument rather than guessed, the rule
TCP's `encoding` field follows (`mod.rs::command_event_data`). In `command` such an argument
is lossily decoded (U+FFFD). There is still no key or argument-count field: the model reads
both off `args`.

**Actions** (all sync; there are no async actions):

| Action | Parameters | Wire form |
|---|---|---|
| `redis_simple_string` | `value` (required) | `+value\r\n` |
| `redis_bulk_string` | `value` (optional; `null` ⇒ nil) | `$len\r\n…\r\n` |
| `redis_integer` | `value` (required, i64) | `:value\r\n` |
| `redis_array` | `values` (required, array) | `*n\r\n…` |
| `redis_error` | `message` (required) | `-message\r\n` |
| `redis_null` | — | `$-1\r\n` |
| `close_this_connection` | — | flushes pending output, then closes |
| `redis_accept_subscription` | — | on `redis_subscribe`: the subscription is registered and one confirmation per name is sent |
| `redis_deliver_message` | — | on `redis_publish`: delivered to every matching subscription, publisher gets `:N` |
| `redis_publish_message` | `channel`, `message`, `shard` | publishes a message of the model's own; writes nothing to the current connection. **Also async** |
| `redis_cluster_set_slot` | `slots` (`"42"` / `"0-100"`), `state` (`node`/`migrating`/`importing`/`stable`), `node` | changes this server's slot map (cluster mode). **Also async** |

The two async actions reach the running server through `execute_action_with_state` and the
`RedisShared` handle `spawn` registers (`AppState::register_server_handle`), so the model can
publish, or move a slot, from a scheduled task or a conversation, not only while answering a
command.

`redis_array` element mapping, exactly as implemented in `actions.rs::encode_array`:

| JSON element | RESP2 |
|---|---|
| string | bulk string |
| integer | RESP integer (`:42\r\n`), **not** a bulk string |
| float | bulk string of its text form |
| `true` / `false` | bulk string `"1"` / `"0"` |
| `null` | nil bulk string |
| array / object | its JSON text in a bulk string |

Verified with `redis-cli --no-raw`: `["k1", 42, true, null, {"a":1}]` returns
`"k1"`, `(integer) 42`, `"1"`, `(nil)`, `"{\"a\":1}"`.

### CR and LF in a model-supplied payload

A RESP **simple** string (`+…`) and **simple error** (`-…`) are CRLF-terminated
with no length prefix, so a newline anywhere in the payload ends the frame early
and everything after it is parsed as the *next* reply. The connection is then
desynchronised permanently: every later command reads the previous one's
leftovers, and the client has no way to notice.

`redis_simple_string`'s `value` and `redis_error`'s `message` come from model
output, so `encode_simple_string` and `encode_error` map each CR and LF to a
space — which is exactly what Redis itself does
(`addReplyErrorFormat` runs `sdsmapchars(s, "\r\n", "  ", 2)`). The text
survives; only its ability to end the frame does not. A WARN names the action.

This mattered most for `redis_error`: a model asked to explain a refusal writes
multi-line prose without thinking about framing. `mod.rs` had documented the
hazard on its **own** LLM-failure path and avoided it by sending a fixed
category, but the model-facing verbs had no guard at all.

Bulk strings, arrays and integers are unaffected — a bulk string is
length-prefixed, so it can carry any bytes, newlines included.

### Failure behavior

- **No response action** → `-ERR no response produced for this command`. (Redis
  is strictly request/response; staying silent would hang the client until its
  own timeout.)
- **LLM call fails** → `-LOADING <category>` when
  `crate::llm::is_overload_error` says the backend was merely saturated,
  otherwise `-ERR <category>`. Clients already treat `LOADING` as "not ready
  yet, retry" and several retry it automatically, so an outage does not get
  recorded as a permanent fault. **The text is a
  `crate::utils::WireFailure` category, never the error itself** — see
  `redis_error_message`. Logged `decision=fail_closed_llm_overloaded` /
  `decision=fail_closed_llm_error`.
- **Model chose `redis_error`** → its own message, logged
  `decision=model_reject`. On the wire a refusal and an outage are both just
  `-…`, so as in `src/server/radius/` only the log distinguishes them; the
  no-response case above is `decision=fail_closed_no_action`.
- **`SUBSCRIBE` with no decision, or the model call failing** → refused (`-ERR no response
  produced for this command`, or the failure category), nothing registered. Logged
  `decision=fail_closed_no_action` / `fail_closed_llm_*`; a model refusal is
  `decision=model_reject`, an acceptance `decision=model_accept`.
- **`PUBLISH` with no decision, or the model call failing** → the same errors, and **nothing
  is delivered**. `decision=model_deliver` / `model_withhold` otherwise.
- **A subscription or message past a bound** → refused before the model is asked
  (`decision=fail_closed_subscription_bound` / `fail_closed_message_bound`). See "Pub/sub".
- **Action result that is `Custom` rather than `Output`** → logged at WARN and
  skipped (no Redis action returns `Custom` any more; the arm exists so a
  regression is loud); if nothing else was produced the no-response error above
  is sent.
- **Undecodable RESP** → the connection is closed.
- **Arrays nested deeper than 32** (`utils::resp::MAX_RESP_DEPTH`) →
  `-ERR Protocol error: nesting too deep`, half-close, logged
  `decision=fail_closed_resp_too_deep`. Refused as soon as the 33rd level opens,
  whether or not the rest of the frame has arrived. See "RESP nesting" below.
- **A declared length that can never complete** — `*N` past 2^20 values
  (`MAX_RESP_ELEMENTS`, also the cap on all values in one frame), or `$N` past
  `MAX_PENDING_FRAME_BYTES` → `-ERR Protocol error: invalid multibulk length` /
  `invalid bulk length` on the header line, half-close, logged
  `decision=fail_closed_resp_too_long`.
- **Incomplete frame larger than 64 MB** (`MAX_PENDING_FRAME_BYTES`) → an error
  is sent and the connection closed. Without this cap a client announcing
  `$2000000000\r\n` and stalling would grow the per-connection buffer without
  bound.

All three refusals are fixed strings — nothing from the peer's bytes or an
internal error reaches the wire.

### RESP nesting

`redis-protocol` 6.0's `resp2::decode` recurses `d_parse_frame` → `d_parse_array`
→ `nom::multi::count(d_parse_frame)` with no depth limit, and `build_owned_frame`
recurses over the result again. `*1\r\n` is four bytes per level, so 100 000
levels — 400 KB, far under the 64 MB buffer cap — overflowed the stack of the
task decoding it. A stack overflow is a `SIGSEGV` against the guard page, not a
panic: **the whole NetGet process died**, from one unauthenticated connection.

`src/utils/resp.rs::scan_resp2_frame` now walks each frame iteratively before
`decode` sees it — one counter per open array in a fixed 32-slot array, no
recursion, no allocation — and the read loop decodes only what it reports
`Complete`. It follows the decoder's grammar exactly (the same
`str::parse::<isize>` for lengths; a bulk string's two trailing bytes skipped
unchecked, as `nom_take(2)` does), so it never refuses a frame `decode` would
accept within the bounds. `Malformed` closes the connection without decoding,
as an undecodable frame always has.

A declared length was **not** an allocation bomb on its own: `nom` 7.1.3's
`count` caps its initial `Vec::with_capacity` at 64 KiB. What it did do was
let a peer announce `*4000000000` and hold the connection until 64 MB had
arrived; that is now refused on the header line.

Real Redis never nests a *request* at all (`Protocol error: expected '$', got
'*'`); 32 is kept because the same guard is meant for reply shapes too.

## Architecture

- `spawn_with_llm_actions` binds with `?`, so a bind failure surfaces as
  `ServerStatus::Error` rather than a phantom `Running`, and registers the
  accept-loop `JoinHandle` via `AppState::register_server_task()` so
  `stop_server` releases the socket.
- One task per connection, **registered with `register_server_task` as well**.
  Registering only the accept loop released the port on `stop_server` while
  leaving every in-flight session running — the socket vanished from `netstat`
  and the peer was still being served.
  `tests/server/redis/resp_framing_test.rs` pins this.
  `handle_connection` wraps `run` so the connection is always marked `Closed` in
  `AppState` on exit; `update_connection_stats` is called for bytes/packets in
  both directions.
- Read into a `Vec`, `scan_resp2_frame()` then `decode()` frames off the front,
  drain what was consumed.
  Multiple pipelined frames in one read are processed in order, each with its own
  LLM call.
- Reply verbs are encoded in `execute_action` (`actions.rs`), which returns the
  RESP bytes as `ActionResult::Output`. The read loop only concatenates `Output`
  bytes (flattening `Multiple`) and writes them; it encodes nothing itself except
  the errors it synthesises (frame cap, nesting, declared length, LLM failure,
  no-response), which call the same `actions::encode_error`.
- Responses for one command are accumulated into a single buffer and written
  once, so a `close_this_connection` issued alongside a reply still flushes.
- No per-connection state machine: commands on one connection are handled
  strictly sequentially by the read loop, so concurrent LLM calls cannot happen.

### Dashboard injection (`[ message this peer ]` / `[ disconnect this peer ]`)

Every connection registers a peer handle (`server::peer_support`) before its first read,
so a manual `*` rule parking the first command still leaves the operator able to reach
it. The stream is `tokio::io::split` and the write half is an `Arc<Mutex<..>>` shared
with the generic peer command task; the handle is removed on every exit path through the
single cleanup in `handle_connection`. Counters (`update_connection_stats`) move on every
read and every write, including the frame-cap error.

**The whole vocabulary is injectable.** All six reply verbs (`redis_simple_string`,
`redis_bulk_string`, `redis_array`, `redis_integer`, `redis_error`, `redis_null`) are
RESP-encoded inside `execute_action` and return `ActionResult::Output`, which the generic
peer task writes to the connection's write half — so an injected reply verb puts exactly
the same bytes on the wire as the read-loop path (they share the `encode_*` functions in
`actions.rs`). `close_connection` (what "disconnect this peer" sends; an explicit arm in
`execute_action`, not offered to the model — its verb is `close_this_connection`)
half-closes and the client reads EOF. This used to be the "Custom-result gap": the verbs
returned `Custom` and only the read loop could encode them, so injection reported
`Executed` without writing. `tests/server/redis/peer_inject_test.rs` pins the fixed
behavior (`Sent`, bytes at the client socket, counters moved).

Injected replies are unsolicited from the client's point of view: `redis-cli` sitting at
its prompt will parse the frame as the reply to its *next* command. That is inherent to
injecting into a strictly request/response protocol, not a NetGet bug.

## RESP3 (`resp3.rs`)

A connection starts in RESP2. `HELLO [2|3]` is answered in Rust, not by the model: it is
protocol negotiation, and the reply (`server`, `version` 7.4.0, `proto`, `id`, `mode`,
`role`, `modules`) is a map on RESP3 and a flat array on RESP2. `HELLO 4` and up is
`-NOPROTO unsupported protocol version`; a malformed option is `-ERR Syntax error in HELLO
option …`. `HELLO … AUTH user pass` carries credentials, which only the handler can judge, so
that one goes to the model as an ordinary `redis_command` and the switch waits on its answer:
an error reply (`-WRONGPASS …`) is sent as is and the connection stays where it was;
anything else accepts, and the model's reply is replaced by the HELLO map. A failed model
call fails closed the same way. `SETNAME` is accepted and ignored.

The version is per connection (`RedisProtocol::protocol_version`, shared by the read loop
and the peer-injection task) and every `redis_command` event carries it as `protocol`.

Seven RESP3 verbs: `redis_map` (an object, or `[[k, v], …]` when order matters),
`redis_set`, `redis_double` (a number, `inf`, `-inf` or `nan`), `redis_boolean`,
`redis_big_number` (decimal digits), `redis_verbatim_string` (`text`, `format` txt/mkd) and
`redis_push`. On RESP3 they are native, as are `redis_array`'s elements (a nested array is an
array, an object a map, a fraction a double, a boolean a boolean, null a null; 32 levels at
most) and every null (`_`). On RESP2 they downgrade the way Redis does: map → flat array,
set → array, double and big number → bulk string, boolean → integer 1/0, verbatim → bulk
string of its text, with `redis_array`'s RESP2 element rules unchanged. A push is refused on
RESP2 (the action fails and nothing is written for it), since RESP2 has no out-of-band frame.

Requests are RESP2 arrays in both versions, so the decoder and its depth guard are unchanged.

## Pub/sub (`pubsub.rs`)

`SUBSCRIBE` / `PSUBSCRIBE` / `SSUBSCRIBE` ask the model (`redis_subscribe`) and, if it accepts,
are registered in the server's `PubSubHub`, which queues one confirmation per name
(`subscribe <name> <count>` — channels plus patterns; shard channels counted apart, as Redis
counts them). `UNSUBSCRIBE` / `PUNSUBSCRIBE` / `SUNSUBSCRIBE` (with names, or none for all; with
nothing held, one confirmation with a null name), `PUBSUB CHANNELS | NUMSUB | NUMPAT |
SHARDCHANNELS | SHARDNUMSUB` and `RESET` are answered in Rust. `PUBLISH` / `SPUBLISH` ask the
model (`redis_publish`).

Delivery is exactly Redis's shapes: `message <channel> <payload>`, `pmessage <pattern>
<channel> <payload>`, `smessage <channel> <payload>` — an array on RESP2, a `>` push on RESP3,
encoded per subscriber for its own version. A connection subscribed to a channel and to a
matching pattern receives (and counts) twice. Patterns use Redis's glob
(`utils::redis_keys::glob_match`, a port of `stringmatchlen` that is iterative and never
backtracks past the last `*`, including Redis's quirk that `*` does not match an empty name).

**Subscribed mode**: a RESP2 connection holding any subscription may send only the pub/sub
family, `PING` (answered `["pong", <arg or "">]`), `QUIT` and `RESET`; anything else gets
Redis's `-ERR Can't execute '<cmd>': only (P|S)SUBSCRIBE / (P|S)UNSUBSCRIBE / PING / QUIT /
RESET are allowed in this context`. RESP3 allows everything. `RESET` (always answered in Rust)
drops every subscription without confirmations, returns the connection to RESP2 and answers
`+RESET`.

**One writer per connection.** Every byte the read loop writes, and every delivered message,
goes through the connection's `Outbox` to a single writer task. A subscription is registered
and its confirmations queued under the hub lock, as is every publish's fan-out, so a
subscriber always reads `subscribe` before the first message on that channel. The read loop
waits for each reply to be written before reading the next command, so a peer that stops
reading still stalls its own command stream as a direct write would. The writer is registered
with `register_server_task` and aborted when the read loop ends.

**Bounds** (each refuses the whole command; constants in `pubsub.rs`):

| Bound | Value |
|---|---|
| channel name / pattern length | 1 KiB / 256 B |
| message | 1 MiB |
| subscriptions per connection | 1024 (channels + patterns + shard channels) |
| subscriptions per server | 65 536 |
| distinct patterns per server | 1024 — each costs a matcher run per publish |
| queued, unwritten messages per subscriber | 8 MiB, then the subscriber is **disconnected** (`decision=slow_consumer_disconnected`) |

The last is Redis's `client-output-buffer-limit pubsub` hard limit, without the soft limit and
at 8 MiB rather than 32 (256 connections × 32 MiB is 8 GiB). The read loop selects on the
outbox's closing signal, so a slow consumer parked in `read()` is closed at once, and the
writer — possibly parked in a write to a peer that reads nothing — is aborted.

Not done: keyspace notifications, `CLIENT TRACKING` invalidation pushes, and cluster-wide
`PUBLISH` (in cluster mode a publish reaches this node's subscribers only — there is no bus).

## Cluster mode (`cluster.rs`)

Started with `cluster_nodes`, a server is one master of a cluster whose shape the parameter
declares: `[{"host", "port", "slots": ["0-5460", …], "id"?, "myself": true}, …]`. `myself`'s
host and port default to where the server is listening. Node ids, when not given, are derived
from `host:port`, so servers handed the same array agree on every id. A topology with no
`myself`, an overlapping slot, a slot past 16383 or a host that is not a hostname refuses to
start.

- `CLUSTER SLOTS`, `SHARDS`, `NODES`, `INFO`, `KEYSLOT`, `MYID`, and `ASKING`, `READONLY`,
  `READWRITE` are answered in Rust from the topology. Every other `CLUSTER` subcommand
  (`SETSLOT`, `COUNTKEYSINSLOT`, …) goes to the model, which can honour a `SETSLOT` with
  `redis_cluster_set_slot`. `HELLO` reports `mode: cluster`.
- Before anything else looks at a command, its keys (`utils::redis_keys::slot_keys`: Redis's
  key positions per command, the channel for `SPUBLISH`/`SSUBSCRIBE`, the first argument for an
  unknown command) are hashed — CRC16-XMODEM of the `{hashtag}` or the whole key, mod 16384 —
  and routed: `-MOVED <slot> <host:port>` for another node's slot, `-CROSSSLOT` for keys in
  different slots, `-CLUSTERDOWN Hash slot not served` for an unassigned one.
- Migration follows `CLUSTER SETSLOT`: a slot this node owns and marked `migrating` answers
  **every** key with `-ASK` (Redis does so only for keys it no longer holds; this server holds
  none); an `importing` slot is served only on the command right after `ASKING`.
- `INFO` stays the model's. `redis-cli --cluster check` refuses a node whose `INFO` lacks
  `cluster_enabled:1`, so an instruction for a cluster node should say to report it.

There is no cluster bus: `redis_cluster_set_slot` changes one server's view, so moving a slot
across a fake cluster means telling each server, and a client that reaches a server with a
different view is redirected by it.

## Not implemented

- **RESP3 attributes** (`|`), streamed strings and aggregates, and client-side caching
  (`CLIENT TRACKING`).
- **Inline commands** (`PING\r\n` typed into `nc`) — only RESP arrays decode;
  anything else closes the connection. `redis-cli` and `redis-rs` always send
  RESP arrays, so this only affects hand-typed sessions.
- **AUTH / SELECT / MULTI / EXEC / WATCH** — reach the model as ordinary
  commands with no special handling. There is no auth gate.
- **Blocking commands** (`BLPOP`), **Lua** (`EVAL`), **replication**, **persistence**,
  replicas in cluster mode, and a cluster bus.
- **TLS**.

## Testing

Twelve files, declared in `tests/server/redis/mod.rs`:

- `pubsub_test.rs` — redis-cli (RESP2 and `-3`) and redis-rs (its RESP2 `PubSub` and a RESP3
  multiplexed connection with a push sender): a message one real client publishes reaches
  real subscribers of the channel and of a matching pattern; a message the model publishes
  reaches them; a refused subscription and a withheld publish hold. Zero LLM calls.
- `pubsub_bounds_test.rs` — subscribed mode, every bound above, the slow-consumer disconnect,
  fail-closed `SUBSCRIBE`/`PUBLISH`, and the async `redis_publish_message` path, from raw
  sockets. Zero LLM calls.
- `cluster_test.rs` — three NetGet servers as one cluster, navigated by `redis-cli -c`,
  checked by `redis-cli --cluster check`, and driven by redis-rs's `ClusterClient`, including
  a slot the model moves (stale map → `MOVED` → refresh) and one it migrates (`ASK`/`ASKING`).
- `keys_oracle_test.rs` — hash slots against a real `redis-server`'s `CLUSTER KEYSLOT` and glob
  matching against its `KEYS`, over 1 500+ keys and 36 patterns.

- `e2e_test.rs` — six `redis-rs` tests, one per RESP2 reply type.
- `real_client_test.rs` — the real `redis-cli` binary, seven commands on one
  connection, asserted as one ordered list of rendered replies. Hard-fails when
  the binary is missing. Together with `e2e_test.rs` this is what the Beta rating
  rests on.
- `resp_framing_test.rs` — CR/LF in a model-supplied simple string or error
  cannot split the frame, and `stop_server` ends an in-flight connection rather
  than just the listener. Zero LLM calls.
- `llm_failure_test.rs` — the RESP error a client sees when the backend fails.
- `peer_inject_test.rs` — dashboard injection through `send_to_peer`.
- `connection_bounds_test.rs` — the read deadlines (see "Connection bounds").
- `resp3_test.rs` — redis-cli `-3` and redis-py 5 (`protocol=3`, credentials in
  `HELLO`) read every RESP3 type, a push, and the RESP2 downgrades; a wrong password in
  `HELLO` is refused and `HELLO 4` is `NOPROTO`. Zero LLM calls (a python handler).
- `resp_depth_test.rs` — a 100 000-level nesting bomb is refused and the
  server still answers a fresh connection; 32 levels answered, 33 refused;
  impossible `*N`/`$N` refused at the header. Zero LLM calls. Without the
  guard the test binary aborts with `stack overflow`.

`fuzz/fuzz_targets/resp_frame.rs` drives the guard and `decode` as a pair, with
a depth-bomb seed.

`--test` names a **target**, so `--test server::redis::e2e_test` makes cargo list
its targets and exit having run nothing — it does not fail, so it silently looks
like a pass. Filter after `--` instead:

```bash
./cargo-isolated.sh test --no-default-features --features redis \
    --test server -- server::redis --test-threads=100
```

Real-client checks used during review, via `--mcp-http` with a static handler so
no model is involved:

```bash
netget --mcp-http 18899 &
# start_server protocol=redis port=16379 event_handlers=[{redis_command → static redis_array}]
redis-cli -p 16379 --no-raw KEYS '*'
```

## Example prompts

```
Start a Redis server on port 6379. Reply PONG to PING with redis_simple_string.
For GET on a key you have not seen, use redis_null. For SET, reply OK.
```

Prefer a script or static handler for anything deterministic — every command
otherwise costs one model round-trip.

## References

- [RESP2 specification](https://redis.io/docs/reference/protocol-spec/)
- [redis-protocol crate](https://docs.rs/redis-protocol/)
- [redis-rs](https://docs.rs/redis/) — used by the E2E tests

## Connection bounds

Before September 2026 this server accepted without limit and bounded no read in time, so a peer
that connected and said nothing held a socket, a task and an `AppState` entry forever, and a
hundred of them was a free denial of service on a server that would happily accept a hundred
more. It now declares both halves; the constants and the reasoning live beside them in
`src/server/redis/mod.rs`.

| Bound | Value | Why this number |
|---|---|---|
| `FIRST_COMMAND_READ_TIMEOUT` | **300s**, overridable per server with `first_byte_timeout_secs` | Was 30s, on the argument that every real RESP client speaks immediately — `redis-cli` sends `COMMAND DOCS`, `redis-rs` sends `PING` or its configured `HELLO`/`AUTH`. True of every third-party client and **false of the one this server most often has.** NetGet's own Redis client (`src/client/redis/mod.rs`) is a bare `TcpStream::connect` that writes nothing until an action says to, and a client made with the dashboard's `[ + redis client ]` is routed `*` → manual: it connects, is answered with nothing, and waits for a person to type into `[ send message ]`. At 30s the server dropped it while the operator was still looking at it — the `tcp` defect, same shape. 300s is the window a `manual` rule gives a human (`src/state/intercepts.rs`) and is this server's own idle bound, so a hand-driven session is bounded the same way before its first command as after it. Cost: one idle stranger holds a slot for 300s rather than 30s, still capped at `MAX_CONNECTIONS` and still answered above that cap. A listener exposed to strangers should set the parameter low; 30 remains a sound choice for one. |
| `IDLE_BETWEEN_COMMANDS_TIMEOUT` | 300s, overridable per server with `idle_timeout_secs` | Real Redis ships `timeout 0` — it never closes an idle client — and every pooling client in the ecosystem depends on holding an established connection unused between bursts. Closing those at 30s would break correct clients to fix a problem they are not causing. |
| `MAX_CONNECTIONS` | 256 | Refusal: **`-ERR max number of clients reached`**, byte for byte what real Redis sends in the same situation. `redis-rs` surfaces it as `ResponseError` and `redis-cli` prints it; a simple error can never be mistaken for data, which is what makes it safe unprompted. |

**The deadline covers the read and nothing else.** The deadline wraps the `read()` call in this protocol's own loop, and everything that can legitimately take minutes happens after it returns. The LLM round-trip, and a `manual`
rule parking an event for a human (`src/state/intercepts.rs`, 300s by default), are outside
every deadline here, so an answer that takes minutes can never close the connection it is an
answer for. That is the `.connectionless()` lesson in the project `AGENTS.md` read in reverse:
TFTP evicted live transfers because "idle" was measured wrongly.

Both bounds are declared startup parameters, because the right value is a property of who is
on the other end and only the operator knows that.
`tests/server/redis/connection_bounds_test.rs` drives all three claims from a raw socket: a
short `first_byte_timeout_secs` closes a silent peer, a short `idle_timeout_secs` closes one
that has been answered (proving the loop switches bounds), and the **default** leaves a silent
peer alone for 40 seconds — past the 30 this used to be, which is the regression for the defect
above and the reason that one test is deliberately slow.

`tests/tcp_server_bounds_ratchet_test.rs` fails the build if either bound is removed;
`tests/accept_bounded_test.rs` drives the shared helper, including the guarantee that a busy
connection is never reported as idle.
