# NATS Client Test Strategy

`e2e_test.rs`, five tests, **13 LLM calls** across the file.

| Test | Peer | LLM calls | What it proves |
|---|---|---|---|
| `test_nats_client_parses_broker_frames` | none | 0 | the broker→client parser: partial frames, byte counts, embedded CRLF, `HMSG` header blocks, payload limits, event payload encoding, permission-error classification |
| `test_nats_client_subscribes_and_publishes_a_model_authored_reply` | hand-written broker | 3 | the **exact bytes** NetGet puts on the wire: `CONNECT`, the model's `SUB`, `PING`→`PONG` with no LLM call, and a `PUB` with the right subject and byte count |
| `test_nats_client_separates_permission_denials_from_fatal_errors` | hand-written broker | 3 | a permissions violation raises `nats_permission_error` with an operation and a subject and leaves the session up; every other `-ERR` raises `nats_error_received`. Also exercises a zero-LLM static handler reaching the client's action executor |
| `test_nats_client_completes_a_round_trip_with_the_netget_nats_server` | NetGet's NATS server | 5 | this client's `MSG` parser against the other half's `MSG` writer, and the `subscribe_subjects` startup parameter |
| `test_nats_client_round_trips_through_the_official_nats_server` | **`nats-server` + `async-nats`** | 2 | **the `Beta` rating.** Independent implementations on both sides; see below |

## The test the rating rests on

`test_nats_client_round_trips_through_the_official_nats_server` is the only test here with
independent peers at **both** ends. The official Go `nats-server` (spawned on a loopback port
through `tests/helpers/real_server.rs`) routes the traffic, and `async-nats` 0.50 is the
client that sends the request and reads the reply. NetGet is in the middle and is the only
thing under test.

In order, it proves:

1. `nats-server` accepted NetGet's `CONNECT`. It parses that document strictly — a wrongly
   typed field fails the session here and nowhere else.
2. NetGet parsed a real `INFO`, carrying a `server_id` and `max_payload` nothing in this
   project wrote.
3. `nats-server`'s routing table matched NetGet's `SUB`. The subject match is Go's, not ours.
4. NetGet framed the inbound `MSG`, asked the model, and published the answer on the reply
   subject — the round trip the client exists for, and the exact thing the "client throws the
   model's answer away" defect breaks.
5. `nats-server` routed that answer back into `async-nats`' own inbox, so our `PUB` byte count
   and reply subject were right.

The reply **quotes the request** (`"the model saw: ping from async-nats"`), built with
`respond_with_actions_from_event`, so no canned response can satisfy the assertion.

### It hard-fails when the binary is missing

`official_nats_server()` returns an `Err` naming the binary and its package. It deliberately does **not**
print `SKIP: nats-server is not installed` and return `Ok(())` — on a runner without the binary
that is a silent pass, and this client's rating would then rest on nothing. That gate is
exactly what keeps `kubernetes`, `oci_registry`, `maven` and `websocket` at Experimental;
`npm`'s real-CLI test is the shape copied here.

Consequence, and it is a real cost: **`nats-server` must be installed wherever this suite
runs**, CI included (`brew install nats-server`, or the release tarball). Verified by running
the test with `PATH=/usr/bin:/bin`, which fails with that message rather than passing.

### Determinism without sleeping

The test never sleeps waiting for NetGet to be subscribed. Instead:

1. `async-nats` connects, subscribes to `netget.ready`, and **flushes** — so that subscription
   is registered at the broker before NetGet exists.
2. NetGet's `subscribe_subjects` startup parameter writes `SUB netget.e2e 1` inside the
   handshake, and a zero-LLM static handler on `nats_connected` then publishes to
   `netget.ready`.
3. Both leave NetGet on the same connection in that order, and `nats-server` processes a
   connection's frames in order — so **the arrival of the announcement proves the subscription
   was registered first**. Only then is the request sent.

That is why the announcement is worth its two lines: it removes the one race a real broker
introduces, at zero LLM cost, and it is simultaneously the first proof that the `CONNECT` was
accepted at all.

### Process hygiene

Both real-broker tests (`e2e_test.rs` and `jetstream_test.rs`) start `nats-server` through
`RealServer`, which kills it on every exit path including a panic, retries on a fresh port if
another process took the probed one, and counts it ready only once its log says
`Server is ready` **and** a TCP connect succeeds.

`RealServer` also drains the broker's stdout and stderr for as long as it runs, and that is the
part that matters. `nats-server` is a Go program, and a Go program that writes to a closed
stderr pipe dies of SIGPIPE. A helper that reads stderr only up to
`Listening for client connections` and then drops the pipe leaves the broker to die on its next
log line — normally the `Server is ready` written microseconds later — and on CI that refused the
peer's connect in 4 of 30 `registry-audit` runs. Measured locally: with the read end closed, the first log line after it
(a `-D` connection notice) kills `nats-server` with signal 13 and the next connect is refused.
Never start a Go peer with a piped stderr that nothing reads.

## The three same-project tests, and what they are worth

`TestBroker` is hand-written in this file from the protocol description; the fourth test's peer
is NetGet's own NATS server. On their own these would be the circular-evidence class the root
`AGENTS.md` names for `webrtc_signaling` and `websocket` — they show the two halves agree with
each other, not that either matches the spec — and `TestBroker` is additionally the same class
as `dhcp`'s in-test RFC 2131 decoder: an independent *reading*, not an independent
*implementation*.

They stay because they cover what a real broker cannot:

- **Exact outbound bytes.** `nats-server` tells you a message arrived; `TestBroker` records the
  literal `PUB _INBOX.audit.1 20\r\n…` and fails on a wrong byte count.
- **Injected frames.** A real server will not emit `-ERR 'Permissions Violation …'` or an
  unsolicited `PING` on demand. Both `-ERR` paths and the keepalive are only reachable this
  way.
- **The parser in isolation** — partial frames, `HMSG` header/body counts, oversize payloads.

`PING`→`PONG` is asserted inside the hand-written-broker test, and the *absence* of a mock rule
for it is the point: if the keepalive were routed through the model there would be no matching
rule, the mock would answer HTTP 500, and no `PONG` would appear.

## Still untested

- **Headers through a real broker.** `HPUB`/`HMSG` framing is covered by the parser test and
  `TestBroker`; `nats-server` has never been asked to route one.
- **`UNSUB <sid> <max>` counting**, which only `nats-server` actually does — NetGet's own
  server records the threshold without counting, so `send_nats_request`'s auto-unsubscribe is
  proven to be *sent*, not to be *honoured*.
- **Wildcard delivery** (`orders.*` vs `orders.>`) against a real routing table.
- TLS, authentication, reconnect and cluster failover — unimplemented, so there is
  nothing to test.

`jetstream_test.rs`: the client's handlers create a stream on connect, publish three messages
and create a durable pull consumer, fetch, and ack each delivery, against `nats-server -js`
(failing when the binary is absent); the assertions are the server's own STREAM.INFO and
CONSUMER.INFO read over a raw connection (three stored, all acked), then an injected call and
the server's refusal.

## Mock rules

- Startup rules match on `THIS-IS-THE-STARTUP-TURN`, a phrase that appears only in the
  top-level prompt. Per-event calls carry the *client's* instruction, so they cannot match it —
  rules are first-match-wins and a loose startup rule would answer every event with
  `open_client`.
- `wait_for_mocks(30)` before `verify_mocks()` everywhere. The exchange finishes with the last
  LLM call it provokes, which is exactly what the expectations describe, so waiting on them
  waits on the exchange. A fixed sleep is enough alone and not at `--test-threads=100`.
- `TestBroker::wait_for` polls the recorded bytes against a deadline for the same reason —
  every wire assertion goes through it, none through a sleep.
- Static handlers with an **empty** `actions` array suppress LLM calls for `nats_connect`
  (server) and `nats_connected` (client). That genuinely costs zero calls;
  `tests/empty_static_handler_test.rs` measures it directly.

## Running

```bash
./cargo-isolated.sh test --no-default-features --features nats \
    --test client -- client::nats --test-threads=100
```

Note the invocation: `--test client` then filter, because `tests/client.rs` is the harness
binary and `client::nats::e2e_test` is a module inside it. `tests/client/nats/mod.rs` must
declare `pub mod e2e_test;` — a test directory on disk that nothing declares is silently never
compiled and never run.
