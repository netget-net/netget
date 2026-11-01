# AMQP Server Testing

## Strategy

Black-box, driven by `lapin` — a real AMQP 0-9-1 client. The mocked model decides what the
broker says; `lapin` decides whether the bytes were legal. If `lapin` completes a
handshake, accepts a `Queue.Declare-Ok`, matches a `Basic.Deliver` to its consumer and
hands back the body, the framing is right at every layer, because `lapin` parses the wire
with the generated `amq-protocol` parsers rather than anything this repo wrote.

`lapin` is the wrong library for the *server* side (it is a client and its types are wired
into a client-side connection state machine), which is why `src/server/amqp/codec.rs`
exists. It is exactly the right library here.

## Tests

| Test | What would break it | LLM calls |
|---|---|---|
| `test_amqp_publish_is_delivered_to_consumer` | any framing error anywhere in the handshake, declare, consume, publish or delivery path | 5 |
| `test_amqp_connection_refused_when_handler_makes_no_decision` | a fail-open default on `amqp_connection_open` | 2 |
| `test_amqp_connection_refused_by_handler` | the handler's own reply code or text not reaching the client | 2 |
| `test_amqp_unimplemented_method_closes_the_channel` | an unimplemented method being ignored instead of answered (the client would hang) | 2 |

`codec_test.rs` (zero LLM calls, no socket) covers the field-table decoder directly, because
the e2e test cannot reach it: a real client sends a two-deep `client_properties` and nothing
else. Its four tests are about **depth**, not bounds — the parser was fully bounds-checked and
still had an unbounded recursion, which is a `SIGSEGV` rather than a panic and so killed the
whole process rather than one connection. Reachable in two writes, before authentication.
`a_deeply_nested_field_array_is_refused_rather_than_recursed_into` failing to *complete* is
itself the regression; verified by removing the bound, which aborts the test binary with
`stack overflow, aborting` and SIGABRT.

`peer_inject_test.rs` (zero LLM calls, in-process `AppState`) covers the dashboard's
injection path: a raw socket sends the protocol header, `send_to_peer` injects
`amqp_connection_close` (asserted frame-by-frame on the socket; reported `Executed`
because AMQP actions are `Custom`), counters move in both directions, `close_connection`
yields EOF, and the peer handle is released when the connection ends.

`wire_text_test.rs` (zero LLM calls, in-process `AppState`, `instruction: Some(String::new())`
so the model is genuinely never consulted) covers what a *decode* failure tells the peer. It
sends a `connection.start-ok` whose `client-properties` table declares 24 bytes and carries
two, then reads the `connection.close` back off the raw socket and asserts the `reply_text` is
the fixed category and contains none of `Decoder::take`'s vocabulary — `truncated`, `offset`,
`available`, `wanted`. Both halves are asserted deliberately: the equality alone would still
pass if someone replaced the category with a *different* interpolated string and updated the
expected value to match.

Restoring `format!("UNEXPECTED_FRAME - {}", e)` in `src/server/amqp/mod.rs` fails it with
`left: "UNEXPECTED_FRAME - AMQP payload truncated: 24 bytes wanted at offset 8, only 2
available"` — which is exactly the sentence that was reaching strangers.

Eleven calls across four `netget` processes; each test runs its own broker because the
mock rules differ per broker instruction.

### The load-bearing assertion

```rust
assert_eq!(String::from_utf8_lossy(&delivery.data), BODY);
```

Everything before it is setup that fails the test on its own if the wire format is wrong.
This one distinguishes a working broker from a listening socket: the mock instructs
`amqp_basic_deliver` with the body from the publish event, and the body has to come back
out of the `lapin` consumer stream.

Verified to be load-bearing by substituting a literal body in the mock and confirming the
test fails with `left: "WRONG BODY", right: "hello from lapin"`.

## Mock expectations

Three of the five rules in the round-trip test must be **dynamic**
(`respond_with_actions_from_event`), for the same reason DNS mocks must be:

- `amqp_queue_declare` → the queue name has to be echoed, or `lapin` rejects the
  `Declare-Ok` as belonging to a different queue;
- `amqp_basic_consume` → the consumer tag has to be echoed, or `lapin` never matches later
  deliveries to the consumer it created;
- `amqp_basic_publish` → the delivery has to name a tag from `active_consumers`; a
  hardcoded tag would break the moment the test's tag changed, and would not prove the
  event actually reports live consumers.

`amqp_connection_open` is static (`amqp_connection_open_ok` takes no parameters).

Every test ends with `test_state.verify_mocks().await?` and every rule sets
`expect_calls(1)`, so a broker that stopped consulting the model — or started consulting it
twice per method — fails the suite.

## Failure-path tests are not decoration

`test_amqp_connection_refused_when_handler_makes_no_decision` answers
`amqp_connection_open` with `notify_operator`: a perfectly valid action that is simply not a
decision. The broker must refuse the connection. It asserts on the text `"no decision"`,
while `test_amqp_connection_refused_by_handler` asserts on the handler's own
`"denied by policy"` — so the two refusal paths stay distinguishable, which is the point of
having them be distinguishable in the first place (see the fail-open warning in the root
`AGENTS.md`).

## Running

```bash
./cargo-isolated.sh test --no-default-features --features amqp \
    --test server -- --test-threads=100 amqp
```

Runs in about a second once compiled; no Ollama needed.

## Not covered

- Multiple simultaneous connections, and delivery from a publisher on one connection to a
  consumer on another (the code path is the same `amqp_basic_deliver` lookup, but the
  cross-connection case is not asserted).
- Bodies larger than one frame (`body_frames` chunking).
- Non-UTF-8 bodies and the `body_is_text: false` path.
- `amqp_basic_return`, `amqp_channel_close` as a queue refusal, `amqp_deliver_to_consumer`
  and `list_amqp_consumers`.
- Heartbeat timeout and the `IDLE_READ_TIMEOUT_SECS` fallback (both would need a test that
  idles for the interval).
- Field tables with exotic types in `client_properties` or message headers. Nesting *depth* is
  covered by `codec_test.rs`; the type ids are not.
- The cross-connection consumer-tag guard: a second connection asking for a tag the first holds
  must get a 405 `RESOURCE_LOCKED` channel error, and `Basic.Cancel` must not reach another
  connection's consumer. Both are implemented and neither is asserted.
