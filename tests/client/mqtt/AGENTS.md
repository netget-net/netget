# MQTT Client Testing Documentation

Two files, **7 LLM calls** in total, both needing nothing but Mosquitto installed.

| File | Peer | LLM calls | What it proves |
|---|---|---|---|
| `real_server_test.rs` | **Eclipse Mosquitto** (`mosquitto`, `mosquitto_sub`, `mosquitto_pub`) | 7 | the maturity rating — see below |
| `command_channel_test.rs` | NetGet's own MQTT broker, in-process | 0 | the dashboard's `[ send ]` path |

## `real_server_test.rs` — the evidence the rating rests on

NetGet's client is built on `rumqttc`. The broker is Mosquitto, a C implementation sharing no
code with it, spawned per test on a probed loopback port through
`tests/helpers/real_server.rs` (`listener <port> 127.0.0.1`, `allow_anonymous true`,
`persistence false`, `log_type all`). `mosquitto_sub` and `mosquitto_pub` sit on the far side of
the broker. Nothing on the wire was written by this repository except NetGet.

**It fails, never skips,** when `mosquitto`, `mosquitto_sub` or `mosquitto_pub` is missing, with
`brew install mosquitto` / `apt-get install mosquitto mosquitto-clients` in the message.

### `mqtt_client_publishes_and_answers_through_mosquitto` (3 LLM calls)

1. `mosquitto_sub` subscribes to `netget/out` before NetGet starts.
2. NetGet connects with `client_id` `netget-e2e-mqtt`. Mosquitto's connection log must name that
   id — proof it parsed NetGet's `CONNECT`.
3. On `mqtt_connected` the mocked model subscribes to `netget/in` (QoS 1) and publishes
   `hello from the model` to `netget/out`. Mosquitto's log must show the subscription
   (`netget-e2e-mqtt 1 netget/in`) and `mosquitto_sub` must print the greeting.
4. `mosquitto_pub` publishes `ping from mosquitto_pub` to `netget/in`. The mock rule matches only
   that topic and payload, and answers with a publish that quotes it.
5. `mosquitto_sub` must print `netget/out the model saw: ping from mosquitto_pub`.

### `mqtt_client_sees_wildcards_qos_and_retained_messages_from_mosquitto` (4 LLM calls)

A retained reading is published to `sensors/room1/temp` before NetGet connects. The model
subscribes to `sensors/#` at QoS 1; a live reading is then published at **QoS 2** to
`sensors/room2/humidity`. The model answers every message with a publish built from the
event's own fields, and `mosquitto_sub` must print exactly:

```
netget/ack topic=sensors/room1/temp payload=21.5C qos=1 retain=true
netget/ack topic=sensors/room2/humidity payload=40% qos=1 retain=false
```

So the wildcard match, the retain bit on a retained delivery, and the QoS **Mosquitto granted**
(2 downgraded to the subscription's 1) all reach the model intact, and its reply goes back out.

### Why this is condition 4, not just "the LLM was called"

Every assertion is on the far side of the broker: a payload the model chose, read back by
`mosquitto_sub`. Verified by mutation: replacing the loop over `result.actions` in
`src/client/mqtt/mod.rs::handle_llm_actions` with an empty iterator makes **both** tests fail
(nothing reaches `netget/out`), while the mock still records every call.

### Determinism without sleeping

- Mosquitto is ready when its log says `mosquitto version … running`, which it prints only after
  binding every listener.
- `mosquitto_sub` is ready when Mosquitto logs `Sending SUBACK to <its id>`. Its own `-d` output
  is no use: with stdout on a pipe it block-buffers the debug lines (while flushing each message
  line, which is what the assertions read).
- NetGet's subscription is known to be in place when its greeting arrives, because both requests
  leave on one connection in order and Mosquitto processes a connection's packets in order.

## `command_channel_test.rs` — the dashboard's `[ send ]`

The peer is a NetGet MQTT broker started in-process with static handlers (`mqtt_connect` →
`mqtt_connack` return_code 0, `*` → no actions), on port 0. **LLM calls: 0** — the client's LLM
URL is `http://127.0.0.1:1` so its `mqtt_connected` call fails, which is part of what the test
verifies the loop survives. It is same-project, so it is evidence for the command plumbing and
not for protocol conformance.

Asserts: the command handle exists before anything is sent (registration happens before the
event loop task even starts); an injected `publish` returns `Executed` whose detail names the
packet — **never `Sent`**, because rumqttc reports no byte count; the topic really reaches the
broker (its access log); an unknown action is `Rejected`; `disconnect` returns `Disconnected` and
leaves the client `Disconnected` with no handle (not `Error`, which is what the poll error would
otherwise have been read as).

## `keepalive_test.rs` — PINGREQ keeps flowing while a turn is parked

The peer is the **real Eclipse `mosquitto` broker** (`/opt/homebrew/sbin/mosquitto`, else
`mosquitto` on `PATH`), started per test on a free loopback port with `listener <port> 127.0.0.1`,
`allow_anonymous true` and its log in a temp file; `mosquitto_sub` verifies delivery. Both
binaries are **required** — the test panics with an install hint rather than skipping, because a
skip is a silent pass wherever the suite runs without them.

The client connects with `keep_alive: 2`; mosquitto disconnects a client silent for 1.5 × that.
Its `mqtt_connected` turn is parked on a `manual` rule for ten seconds. Then, before the turn is
answered, the broker's own log must show `Received PINGREQ from netget-keepalive-probe` and no
`exceeded timeout` line for it, and the client must still be `Connected`. The turn is answered
with a publish, and `mosquitto_sub -C 1` must print it. **LLM calls: 0.** Runtime ~10s.

Verified by removal: with the pre-split client (model turn inside the loop that polls rumqttc)
the broker logs `disconnected: exceeded timeout` three seconds into the park and the test fails
on that assertion.

## Running

```bash
./cargo-isolated.sh test --no-default-features --features mqtt --test client -- mqtt:: --test-threads=100
```

## `v5_real_server_test.rs` — MQTT 5.0 against the same Mosquitto

No LLM calls: the client is created in process (`ClientForm`) with `protocol_version` "5.0"
and a Python handler. Against Mosquitto 2 with `mosquitto_sub -V 5 -F` and `mosquitto_pub -V 5`:
the status publish's Content Type and User Property are printed by libmosquitto; a request's
Response Topic and Correlation Data reach the handler and the answer published to that topic
carries the data back; and No Local is honoured — NetGet subscribes to `v5/out/#` where it
publishes itself, and no message event for `v5/out/…` exists. Mutation-checked: dropping the
publish properties, or sending `nolocal = false`, fails it.

## Not covered

TLS, username/password against a broker that enforces it, Last Will, persistent sessions
(`clean_session: false`) and reconnection are not exercised against Mosquitto.
