# MQTT server tests

Everything below was checked against the files it describes. The version this replaced was
written while the broker was a placeholder and was never updated: it documented a "Current
Status: Placeholder tests only", a migration path through five phases of removing `#[ignore]`,
and a test named `test_mqtt_placeholder_registered` that does not exist. The broker has been a
full MQTT 3.1.1 implementation for a long time. Verify against the source, not against this
file.

## What runs

`tests/server/mqtt/mod.rs` declares every module in the directory, all gated on `feature = "mqtt"`.
None `#[ignore]`d, none able to skip.

| Test | File | What it proves |
|---|---|---|
| `test_mqtt_broker_starts` | `e2e_test.rs` | the `open_server` path binds a port |
| `test_mqtt_keyword_detection` | `e2e_test.rs` | every keyword `MqttProtocol::keywords()` advertises resolves to `MQTT` |
| `test_mqtt_basic_connect` | `e2e_test.rs` | **rumqttc** completes CONNECT → CONNACK |
| `test_mqtt_subscribe_and_receive_a_published_message` | `e2e_test.rs` | **rumqttc** completes CONNECT → SUBSCRIBE → SUBACK → PUBLISH and receives the broker's own PUBLISH back, topic and payload asserted |
| `test_mqtt_refuses_connect_when_llm_fails` | `llm_failure_test.rs` | CONNACK return code 3 and a close, not code 0; and the log carries `decision=fail_closed_llm_*`, never `decision=model_silent` (whose CONNECT default is code 0, an accepted session) |
| `test_mqtt_refuses_subscribe_when_llm_fails` | `llm_failure_test.rs` | SUBACK 0x80 per filter, tagged `decision=fail_closed_llm_*` on `mqtt_subscribe`, while the CONNECT on the same connection is tagged `decision=model_answer` |
| `injected_mqtt_publish_reaches_raw_socket_and_close_sends_eof` | `peer_inject_test.rs` | the dashboard's `[ message this peer ]` / `[ disconnect this peer ]` reach a live connection |
| `test_mqtt_pubsub_session_against_mosquitto_clients` | `real_client_test.rs` | **Eclipse Mosquitto's C clients** complete the same pub/sub session across two connections |
| `the_connection_past_the_cap_gets_connack_server_unavailable_and_the_slot_comes_back` | `connection_bounds_test.rs` | 256 admitted, the 257th reads CONNACK 3 and EOF, closing one frees one slot |
| `a_peer_that_never_sends_connect_is_closed_at_the_connect_bound` | `connection_bounds_test.rs` | no CONNECT within `first_byte_timeout_secs` → closed |
| `a_silent_session_is_closed_at_one_and_a_half_times_its_keep_alive` | `connection_bounds_test.rs` | Keep Alive 2s → closed at ~3s (3.1.1 §3.1.2.10), with both other bounds set to 120s |
| `a_session_that_keeps_pinging_is_not_closed` | `connection_bounds_test.rs` | PINGREQ every second for 8s against a 3s bound → every PINGRESP arrives, session live |
| `keep_alive_zero_falls_back_to_the_idle_bound_rather_than_to_no_bound` | `connection_bounds_test.rs` | Keep Alive 0 → closed at `idle_timeout_secs` |
| `a_packet_parked_for_a_human_keeps_its_session` | `connection_bounds_test.rs` | a SUBSCRIBE parked by a `manual` rule keeps its Keep Alive 2s session for 12s |

`test_mqtt_subscribe_and_receive_a_published_message` is the evidence behind the **Beta**
rating. `rumqttc` is an unconditional dev-dependency, so it either compiles and runs or the
suite does not build — there is no "is it installed?" gate and no `SKIP: … not installed`
branch to hide a silent pass behind.

**Since September 2026 there are two independent clients, not one**, which matters because the
Stable bar in the root `AGENTS.md` asks for exactly that: one client can agree with one bug, and
`mysql`'s Beta resting on `mysql_async` while the real `mysql` CLI cannot connect is the worked
example. `real_client_test.rs` drives `mosquitto_pub` and `mosquitto_sub` — C on libmosquitto,
a different project in a different language — and it **fails** rather than skipping when they
are absent. See "The second implementation" below.

`test_mqtt_keyword_detection` asks `ServerRegistry::parse_from_str` directly and does not spawn
NetGet. The version before it did, with no `.with_mock()`, so the LLM call always failed, no
server was ever started, and the harness returned `Expected exactly 1 server, got 0` — a string
containing neither "unknown" nor "Unknown", which was the whole assertion. It passed for any
prompt, including one naming no protocol at all, and its `else` branch would have failed the
test had the broker actually worked.

## The two mock traps this protocol sets

Both are the "rule never matches, failure surfaces two steps later" shape, and both are
encoded in `test_mqtt_subscribe_and_receive_a_published_message`:

- **`mqtt_suback` must echo `packet_id` from the event.** rumqttc blocks until a SUBACK carrying
  the id *it* chose arrives, so a hardcoded id stalls the subscribe forever. Use
  `respond_with_actions_from_event`, for the same reason the UDP-style protocols must.
- **The event `mqtt_publish` and the action `mqtt_publish` share a name and point in opposite
  directions.** The event is the client's PUBLISH arriving at the broker; the action is the
  broker sending one out. Answering the event with the action is what forwards the message.

A third: **acceptance has to be asked for.** A CONNECT whose handler cannot run is refused with
CONNACK 3, so a test with no `mqtt_connect` rule tests a broker that turns clients away. Both
rumqttc tests carry an explicit `mqtt_connect` rule for that reason.

## LLM call budget

Every subprocess test calls `wait_for_mocks(30)` then `verify_mocks()`.

| Test | Calls |
|---|---|
| `test_mqtt_broker_starts` | 1 (startup) |
| `test_mqtt_basic_connect` | 1 startup + 1 `mqtt_connect` |
| `test_mqtt_subscribe_and_receive_a_published_message` | 1 startup + 1 `mqtt_connect` + 1 `mqtt_subscribe` + 1 `mqtt_publish` |
| `test_mqtt_refuses_*` | 1 startup each; the per-packet call is *made to fail on purpose* |
| `test_mqtt_keyword_detection` | 0 — no subprocess |
| `injected_mqtt_publish_reaches_raw_socket_and_close_sends_eof` | 0 — static handlers, LLM points at an unreachable URL |
| `subscribe_is_told_to_publish_the_retained_message_and_connack_is_sent_once` | 1 startup + 1 `mqtt_connect` + 1 `mqtt_subscribe` |

`answer_with_test.rs` drives raw bytes: the CONNECT is answered with two CONNACKs and the next
packet the client reads must be its SUBACK (the second CONNACK is dropped and logged
`decision=duplicate_response_dropped`); the SUBSCRIBE rule matches only on an `answer_with`
naming the packet id and `retain true`, and the retained PUBLISH (`0x31`, topic, `19.5`) must
follow the SUBACK. This is the real-model eval's `mqtt/retained-message` shape.

Roughly 10 across the suite, which is the target.

PINGREQ, PUBREL and the malformed-packet close cost **zero** LLM calls by construction —
`dispatch_packet` answers them in Rust. A keepalive that consulted the model would be a defect,
not a slow path: the client declares the connection dead while the call is in flight.

## Not covered

TLS (8883), WebSocket transport, MQTT v5 enhanced authentication, a retained-message *store* (the model publishes a
retained message itself; `answer_with_test.rs` covers that path), wildcard subscription matching,
last-will delivery and session resume across reconnect — the broker does not implement a
subscription table or a retained-message store, so there is nothing to test. Keep-alive
reaping *is* implemented and tested (`connection_bounds_test.rs`); removing the deadline around
the read failed the connect, keep-alive and Keep Alive 0 tests, and replacing 1.5x Keep Alive
with the fallback failed the keep-alive test. See `src/server/mqtt/AGENTS.md` for why storage is absent.

## Running

```bash
export CARGO_TARGET_DIR=/Users/matus/dev/netget-shared-target
cargo test --no-default-features --features mqtt --test server -- server::mqtt --test-threads=100
```

`--test` names a *target*. `--test server::mqtt::e2e_test` lists targets and exits without
running anything.

## The second implementation: Mosquitto's C clients

`real_client_test.rs::test_mqtt_pubsub_session_against_mosquitto_clients` runs a **two-connection**
broker session, which the rumqttc test does not:

```
mosquitto_sub   CONNECT -> CONNACK,  SUBSCRIBE -> SUBACK
mosquitto_pub   CONNECT -> CONNACK,  PUBLISH
broker          PUBLISH -> mosquitto_sub, routed by client id
mosquitto_sub   prints "<topic> <payload>" and exits
```

The assertion is that `mosquitto_sub -v` printed the line `netget/real-client
payload-from-netget-broker`. Under `-v` the line carries **both** halves of the packet, so a
broker that delivered the right body on the wrong topic fails. libmosquitto prints it only
after parsing a PUBLISH whose remaining length, topic length and flags it accepted.

Because the publisher and subscriber are different connections, `to_client_id` is doing real
work here: this broker keeps no subscription table, so the model names the recipient and the
directory routes it. The rumqttc test omits `to_client_id` and the reply goes back on the same
connection, so that path was previously untested.

Three things about driving it:

- **Wait on NetGet's own `MQTT -> SUBACK` log line, not on mosquitto's `-d` narration.** The
  publish has to happen after the subscribe completes or it is delivered to a client that has
  not subscribed yet. The first version of this test parsed `-d` output for the word `SUBACK`
  and read nothing at all — libmosquitto's debug wording and stream are its business, not a
  contract. `server.wait_for_log(...)` is a real condition and is ours.
- **`-C 1`** makes `mosquitto_sub` exit after one message, so the process exiting 0 is itself
  an assertion that a message was delivered.
- **`expect_at_least(2)` on `mqtt_connect`**, because two clients connect. A CONNECT the
  backend cannot answer is refused with CONNACK 3, so an absent or under-counted rule here
  would be testing a broker that turns mosquitto away.

Unproven by either client: TLS on 8883, WebSocket transport, QoS 1/2 end to end,
retained messages, wildcard filter matching, last-will delivery, session resume and keep-alive
reaping — the broker implements no subscription table, no retained store and no keep-alive timer.

## MQTT 5.0: `v5_real_client_test.rs` and `v5_wire_test.rs`

No LLM calls in either file: a Python handler answers every event, in process (`ServerForm`),
so the access log is the record of what the handler saw.

`v5_real_client_test.rs` — two independent v5 clients, each failing rather than skipping:

- `mosquitto_v5_clients_carry_properties_and_read_reason_codes`: `mosquitto_pub -V 5` publishes
  with Content Type, Response Topic, Correlation Data, a User Property and a Message Expiry
  Interval; the handler forwards it with those properties to `mosquitto_sub -V 5`, whose `-F`
  line is asserted whole. Then a CONNECT refused with reason 0x87 (libmosquitto prints "not
  authorised") and a SUBACK 0x87 (it prints "denied").
- `paho_v5_reads_assigned_ids_reason_codes_correlation_data_and_disconnect`: paho-mqtt 2 at
  MQTTv5 with an empty client id. Asserts, from paho's callbacks: the Assigned Client
  Identifier, Maximum Packet Size and Topic Alias Maximum on the CONNACK; SUBACK `[1, 135]`
  with its Reason String (and the subscribe event's No Local / Retain Handling / Subscription
  Identifier); a request whose binary Correlation Data `00 ff 49 44` reached the model as hex
  and came back as the same four bytes; a second request sent with only a Topic Alias; PUBACK
  135; UNSUBACK `[17]`; and DISCONNECT 152 "kicked by admin".

`v5_wire_test.rs` — packets written by hand from the specification, answers compared byte for
byte, and the pcap oracle over each exchange (Wireshark decodes v5 property blocks against the
CONNECT's protocol level, so a length that disagrees with its contents is Malformed there):
the whole session, the three refusing DISCONNECTs (0x82 undefined alias, 0x94 alias past 16,
0x95 past `max_packet_size`), the fail-closed CONNACK 0x88 with a category-only Reason String
when the backend is unreachable, and one PUBLISH framed as 3.1.1 for one recipient and as v5
for another.

`install_v5_peers.py <dir>` creates a venv with paho-mqtt and prints `NETGET_MQTT_PYTHON`;
Mosquitto comes from the system packages. CI: the `mqtt-v5-pairs` job in
`.github/workflows/protocol-pairs.yml`.

Mutation-checked: sending no properties from `mqtt_publish` fails four of the six tests.

Note on running as root: `client/mqtt::keepalive_test` points Mosquitto's `log_dest file` at a
root-owned temp dir; a root-run Mosquitto drops to the `mosquitto` user and cannot write it, so
that test fails there and passes on a CI runner. The v5 tests log to stderr and are unaffected.