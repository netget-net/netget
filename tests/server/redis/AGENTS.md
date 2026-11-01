# Redis Protocol E2E Tests

Twelve files, all declared in `tests/server/redis/mod.rs`.

| File | Tests | What it proves | LLM calls |
|---|---|---|---|
| `connection_bounds_test.rs` | 3 | Both read deadlines, from a raw socket | 0 |
| `e2e_test.rs` | 6 | Every RESP2 reply type, through `redis-rs` | 13 |
| `real_client_test.rs` | 2 | A whole session through the real `redis-cli` binary; `redis_command`'s `args` keep a quoted multi-word argument whole, split the unquoted one, and hex-encode a non-UTF-8 one (named in `hex_args`) | 8 + 4 |
| `resp_framing_test.rs` | 3 | Model output cannot split a frame; `stop_server` stops sessions | 0 |
| `llm_failure_test.rs` | 1 | The RESP error a client sees when the backend fails | 1 |
| `peer_inject_test.rs` | 1 | Dashboard injection reaches the socket | 0 |
| `resp3_test.rs` | 2 | `HELLO 3` and every RESP3 type through redis-cli `-3` and redis-py 5, the RESP2 downgrades, a push, and credentials in `HELLO` | 0 |
| `resp_depth_test.rs` | 4 | A RESP nesting bomb or an impossible declared length is refused before the decoder, and the process survives | 0 |
| `pubsub_test.rs` | 2 | Pub/sub through redis-cli (RESP2 and `-3`) and redis-rs (RESP2 `PubSub`, RESP3 push sender) | 0 |
| `pubsub_bounds_test.rs` | 6 | Subscribed mode, every pub/sub bound, the slow-consumer disconnect, fail-closed subscribe/publish | 0 |
| `cluster_test.rs` | 2 | Three NetGet servers as a cluster, through `redis-cli -c`, `redis-cli --cluster check` and redis-rs's `ClusterClient`; a bad topology refuses to start | 0 |
| `keys_oracle_test.rs` | 1 | Hash slots and glob matching equal a real `redis-server`'s `CLUSTER KEYSLOT` and `KEYS` | 0 |

## Running

`--test` names a **target**, not a module path. `--test server::redis::e2e_test`
makes cargo list its targets and exit having run nothing — and it exits 0, so it
looks like a pass. Filter after `--`:

```bash
./cargo-isolated.sh test --no-default-features --features redis \
    --test server -- server::redis --test-threads=100
```

## What the Beta rating rests on

`e2e_test.rs` drives **redis-rs** (`redis` 0.27, a dev-dependency), an
independent implementation of RESP2 — not the `redis-protocol` crate the server
parses with, so the evidence is not circular. Six tests, module
`redis_server_tests`:

| Test | Reply type |
|---|---|
| `test_redis_ping_with_mocks` | simple string `+PONG\r\n` |
| `test_redis_get_set_with_mocks` | simple string + bulk string |
| `test_redis_integer_response_with_mocks` | `:42\r\n` |
| `test_redis_array_response_with_mocks` | `*3\r\n…` |
| `test_redis_null_response_with_mocks` | `$-1\r\n` |
| `test_redis_error_response_with_mocks` | `-ERR …\r\n` |

None is `#[ignore]`d and none skips when something is missing — redis-rs is
compiled in, so there is no binary to be absent. `llm_failure_test.rs` also reads
its assertion back through redis-rs.

### The second client, and what it is for

One client can agree with one bug, and redis-rs converts a reply into the Rust
type the *test* asked for — so a test asking for `String` cannot tell a bulk
string from a simple string. `real_client_test.rs` drives **redis-cli**, the C
client shipped with the server (the binary on this machine is `valkey-cli`
9.1.2, the redis-cli-compatible fork), which shares no code with redis-rs.

It sends seven commands on one connection — `PING`, `SET`, `GET`, `INCR`,
`KEYS *`, a `GET` of a missing key, and a command answered with an error — and
asserts the whole session as **one ordered list** of what `--no-raw` printed:

```
PONG
OK
"hello"
(integer) 7
1) "greeting"
2) "hits"
(nil)
(error) WRONGTYPE Operation against a key holding the wrong kind of value
```

Two things that gives which redis-rs does not. The rendering is the type read off
the wire: a quoted bulk string is distinguishable from the bare simple string
above it, `(nil)` from a zero-length bulk string, `(integer) 7` from a bulk
string of `"7"`. And because it is one ordered list, a reply landing against the
wrong command fails as a mismatched line rather than passing as a same-typed
value — the desynchronisation `resp_framing_test.rs` guards the *cause* of.

`redis-cli` reading commands from a pipe sends nothing of its own: no
`COMMAND DOCS`, no `HELLO`. Every LLM call the mock counts is a command the test
wrote. (Interactively it does send `COMMAND DOCS`, which is why the test does not
run it on a tty.)

**On first contact redis-cli completed a session with no server change
required** — every RESP2 reply type rendered correctly. The test was nevertheless
verified non-vacuous by breaking `encode_null` to emit `$0\r\n\r\n`: redis-cli
then printed `""` where `(nil)` belongs, and the test failed on that line.

## LLM call budget

`e2e_test.rs`: 6 servers × 1 startup + 7 command calls = **13**. That is over the
~10 guideline, and the honest reason is that each test covers a distinct RESP2
encoding and consolidating them would make a failure harder to localise.
`real_client_test.rs`: 1 startup + 7 commands = **8**, all answered by one
`respond_with_actions_from_event` rule that branches on the command. The other
three files cost **1** between them.

`resp_framing_test.rs` and `peer_inject_test.rs` build their servers directly
through `ServerForm` with a `*` static handler and point at an unreachable
backend, so an accidental model call fails the test rather than passing quietly.

Both pass **`instruction: Some(String::new())`**, which is load-bearing:
`ServerForm::create` substitutes a default instruction whenever `instruction` is
`None`, and any non-empty instruction makes `operator_wants_dynamic` true — so a
server built with `..Default::default()` consults the model whatever the test's
comments claim.

## Binary safety — the case worth knowing

`resp_framing_test.rs` exists because RESP has two kinds of string and only one
of them is safe for generated text:

- A **bulk** string is length-prefixed, so it can carry any bytes.
- A **simple** string (`+…`) and a **simple error** (`-…`) are CRLF-terminated
  with no length. A newline inside the payload ends the frame early, and
  everything after it is parsed as the next reply.

`redis_simple_string`'s `value` and `redis_error`'s `message` are model output.
Before this was guarded, one newline in a model's error prose desynchronised the
connection permanently — every later command read the previous one's leftovers,
and the client could not tell. The server now maps CR and LF to spaces, as Redis
itself does.

The decisive assertion is not that the first reply is well-formed; it is that the
**second** command gets its own reply rather than the tail of the first.

## `connection_bounds_test.rs` — deadlines, not answers

Three tests, no model: the LLM endpoint is a dead port and the instruction is empty, so a call
that escaped would fail rather than pass quietly.

| Test | Claim |
|---|---|
| `a_peer_that_connects_and_sends_no_command_is_closed_at_the_first_byte_bound` | `first_byte_timeout_secs` is read and applied — 6s here, and the close is asserted to take at least half of it so something else tearing the socket down cannot pass for the bound |
| `once_a_command_has_been_answered_the_idle_bound_governs_not_the_first_byte_one` | the loop switches bounds. The two are set the wrong way round on purpose (first-byte 60s, idle 3s), so a loop that never switched would hold the connection for a minute and fail the assertion. Its `PING` is answered by a static rule |
| `the_default_leaves_a_silent_peer_alone_for_longer_than_a_person_takes` | the **default** is no longer 30s. No startup parameters at all, a silent peer, 40 seconds |

That last one is the slowest test in this directory and cannot be made cheaper: the claim is
about a number larger than 30, so the wait has to be larger than 30 too. The other two use
short overrides for exactly the reason the parameters exist — a test asserting the 300-second
default by waiting it out would be the slowest thing in the suite.

## `resp_depth_test.rs` — the decoder never sees a frame it would die on

`redis-protocol` 6.0 recurses once per nested array with no limit, and `*1\r\n` opens a level
in four bytes, so a few hundred kilobytes from an unauthenticated peer overflowed the stack and
aborted the **whole process** — a `SIGSEGV` on the guard page, not a panic.
`src/utils/resp.rs` walks every frame iteratively first; these four tests drive it from a raw
socket with a `*` static handler answering `+PONG`, no model:

| Test | Claim |
|---|---|
| `a_nesting_bomb_is_refused_and_the_server_survives` | 100 000 levels (400 KB) get `-ERR` or a bare close — the peer is still writing when the server hangs up, so its kernel may see RST first — and never `+PONG`; then a **fresh connection** still gets `+PONG` |
| `a_small_bomb_gets_the_fixed_error_then_eof` | 40 levels fit one read, so the exact `-ERR Protocol error: nesting too deep\r\n` arrives, then EOF |
| `a_frame_at_the_depth_limit_is_answered_and_one_deeper_is_not` | 32 levels are answered, 33 refused — the bound does not refuse what it allows |
| `an_impossible_declared_length_is_refused_at_the_header` | `*4000000000` and `$4000000000` get `invalid multibulk length` / `invalid bulk length` on the header line, not after 64 MiB |

**Without the guard the first test does not fail — the test binary aborts** with
`has overflowed its stack / fatal runtime error: stack overflow` (SIGABRT), which is how the
defect was confirmed and how the guard was verified by removal. With the element and bulk
limits lifted, the last test fails on an empty read instead.

The same guard/decoder pair is fuzzed by `fuzz/fuzz_targets/resp_frame.rs`, whose corpus
carries a 65 536-level `depth_bomb`.

## Pub/sub — `pubsub_test.rs` and `pubsub_bounds_test.rs`

The model is a python handler in `pubsub_test.rs` (its policy: a channel starting `forbidden`
is refused with `NOPERM`, a publish to `withheld` is answered `42` and not delivered,
`NG.ANNOUNCE <channel> <message>` makes it publish via `redis_publish_message`) and static
rules in `pubsub_bounds_test.rs`. Subscribers are long-running `redis-cli SUBSCRIBE` processes
whose stdout is collected line by line; every wait polls a condition (`PUBSUB NUMSUB`, a
printed line), never a fixed sleep.

Two things worth knowing before extending it:

- **redis-rs 0.27's `PubSub` reports an error reply to `SUBSCRIBE` as success** — it maps the
  reply value away (`handle_message` sends `result.map(|_| ())`, and the error is an `Ok`
  value there). So the refusal is read by redis-cli, which prints `NOPERM …`; redis-rs only
  confirms nothing was registered.
- The withheld publish is proved absent by **ordering**, not by waiting: the same subscriber
  then receives a marker published after it, and must not have printed the withheld payload
  first.

`pubsub_bounds_test.rs` reads replies with the client's own `resp::read_reply`, so each
assertion is on the exact shape — `["unsubscribe", null, 0]` with nothing held, `["pong", ""]`
in subscribed mode, the exact `Can't execute` and bound errors. Every bound was verified by
mutation: removing the per-connection, distinct-pattern, server-wide, channel-length,
message-size or output-limit check makes its test fail. The slow-consumer test publishes 1 MiB
messages at a subscriber that never reads until a publish counts 0; it must take at least 8
of them (the queue limit is 8 MiB, plus whatever the kernel buffers), then `NUMSUB` is 0 and
the subscriber's socket reaches EOF.

The fail-closed test points the server at an unreachable model with only `redis_subscribe`
accepted by a rule: the `PUBLISH` gets an error, and the first thing the subscriber reads is a
marker the test publishes afterwards through the **async** action path
(`execute_actions` with the registry's stateless instance and a `server_id`), so the failed
publish delivered nothing. A `SUBSCRIBE` nobody can rule on is refused and not registered.

## Cluster — `cluster_test.rs` and `keys_oracle_test.rs`

Three servers on probed ports, each given the same three-master topology with itself marked
`myself`; each answers `GET k` with `value of k from <its port>`, so which node answered is in
the value. The model's slot changes are `redis_cluster_set_slot` actions run through
`execute_actions` on each server, exactly as a model's async action is dispatched.

`redis-cli --cluster check` refuses a node whose `INFO` lacks `cluster_enabled:1`, and `INFO`
is the model's to answer, so the handler includes it.

`keys_oracle_test.rs` is what makes the slot arithmetic and the glob matcher trustworthy: a
cluster-enabled `redis-server` (no slots needed) answers `CLUSTER KEYSLOT` for 1 500+ keys
built to hit every hashtag rule, and a standalone one answers `KEYS` for 36 patterns over the
same keys (the empty key excluded: `KEYS *` short-circuits where `stringmatchlen` does not).
Mutating the CRC polynomial, ignoring the hashtag, hashing an empty tag, dropping class
negation, or not swapping a reversed range each fails it.

## Scripting

The `e2e_test.rs` suite uses `ServerConfig::new()`, which disables scripting, so
each reply comes from an action and the action-to-wire encoding is what is under
test. A script handler would prove the script ran, not that the encoding is
right.

## Known limitations of the suite

- **RESP3 is tested in `resp3_test.rs` only**, with a python handler: redis-cli `-3`
  renders map, set, double, boolean, verbatim and null (7.0 has no case for a big number
  and stops with "Unknown reply type: 13", so redis-py carries that one), and redis-py's
  pure-Python RESP3 parser reads them all, plus a push before a reply. `redis-py` must be
  importable from `NETGET_REDIS_PYTHON` (default `python3`); the test fails otherwise.
- **Inline commands** (`PING\r\n` typed into `nc`) are not tested; only RESP
  arrays decode, and both redis-cli and redis-rs always send arrays.
- **Pipelining** — the read loop processes several frames from one read in order,
  each with its own LLM call, but no test sends two commands in one write.
- **AUTH / SELECT / MULTI** reach the model as ordinary commands with no special handling,
  and nothing asserts on them.
- **Cluster-wide `PUBLISH`** — a fake cluster has no bus, so nothing asserts a publish on one
  node reaching a subscriber on another (it does not).

## Fixed, recorded so the notes are not re-added

- *"No Response Fallback: if the LLM returns no action, client hangs
  indefinitely."* It does not: the server replies
  `-ERR no response produced for this command` and logs
  `decision=fail_closed_no_action`.
- *"redis v0.25"* — the dev-dependency is 0.27.
- Test names here omitted the `_with_mocks` suffix every one of them carries.
