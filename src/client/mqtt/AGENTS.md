# MQTT Client Implementation

## Overview

The MQTT client implementation provides LLM-controlled MQTT pub/sub messaging capabilities using the `rumqttc` async
library. This allows NetGet to connect to MQTT brokers and perform publish/subscribe operations under LLM control.

## Library Choice

**Primary**: `rumqttc` v0.24 (async MQTT client)

### Why rumqttc?

- **Async-first**: Built on tokio, perfect for our async architecture
- **Full MQTT 3.1.1 support**: Complete protocol implementation
- **QoS levels**: Supports QoS 0 (AtMostOnce), QoS 1 (AtLeastOnce), QoS 2 (ExactlyOnce)
- **Mature**: Well-tested, actively maintained
- **Clean API**: Simple EventLoop pattern for handling broker events
- **Built-in reconnection**: Handles connection drops gracefully

### Alternatives Considered

- **paho-mqtt**: C bindings, less idiomatic Rust
- **mqtt-async-client**: Less mature, smaller community
- **Custom implementation**: Too complex for the value gained

## Architecture

### Connection Model

```
┌─────────────┐
│ MqttClient  │
│   (NetGet)  │
└──────┬──────┘
       │ rumqttc::AsyncClient
       │ rumqttc::EventLoop
       │
       ▼
┌─────────────┐
│ MQTT Broker │
│ (Mosquitto, │
│  HiveMQ,    │
│  etc.)      │
└─────────────┘
```

### Two tasks: the transport and the model

rumqttc's `EventLoop` does all of its I/O — writing queued requests, sending PINGREQ once per
keep-alive interval, reading PINGRESP — only while `EventLoop::poll` is being awaited. A model
turn can take minutes (a `manual` rule parks it for a human for up to 300s by default), and a
broker disconnects a client that sends nothing for 1.5 × its keep-alive (MQTT 3.1.1 §3.1.2.10).
So the client runs two tasks per connection, both registered with `spawn_client_task`:

1. **`poll_transport`** owns the `EventLoop` and never waits on the model. It sets
   `ClientStatus` (Connected / Disconnected / Error), so status stays true while a turn is
   parked, and puts the first CONNACK and every incoming PUBLISH onto the turn queue.
2. **`run_model_turns`** takes events off that queue in arrival order, asks the model, and
   applies its actions through the `AsyncClient` handle (rumqttc's request channel, drained by
   the transport task).

**Batching (`BatchingMode::On`).** With the client's batching on, a PUBLISH taken off the queue
brings every PUBLISH already waiting behind it — what the broker delivered while the model was
answering — into one `call_llm_for_client_batch` call, one event per message (at most
`MAX_BATCH_EVENTS`); a `Connected` met while draining ends the batch and is answered next. Off,
it is one message per call. QoS acks are rumqttc's, so no delivery waits on the model.
`tests/client/mqtt/batching_test.rs` holds it against a hand-written broker, off and on in one
test.

One consumer is what keeps two turns from overlapping on a connection — the per-connection
state machine rule — without a hand-rolled Idle/Processing/Accumulating enum: events that arrive
during a turn wait in the queue, exactly as they would in `Accumulating`.

**The queue is bounded and never blocks the transport.** `TURN_QUEUE_CAPACITY` is 256 events;
past that an incoming PUBLISH is dropped with a WARN carrying `decision=turn_queue_full`, because
blocking the transport task on a full queue would stop PINGREQ again. Each entry is at most one
packet of rumqttc's default 10 KiB incoming limit, so a flooding broker can pin ~2.5 MiB per
client.

When the transport ends (broker DISCONNECT, a socket error, or a `disconnect` action) it aborts
the turn task: a turn still running or parked has nothing left to answer on, and the events queued
behind it would each cost a model call for a reply that cannot be sent.

`tests/client/mqtt/keepalive_test.rs` holds this against the real `mosquitto` broker: a 2-second
keep-alive, a `mqtt_connected` turn parked for ten seconds, and then — from the broker's side —
PINGREQ seen during the park, no timeout applied, and the answered publish delivered to
`mosquitto_sub`.

## LLM Integration

### Events Sent to LLM

1. **mqtt_connected**: Fired when connection is established
    - Allows LLM to subscribe to initial topics
    - Parameters: `remote_addr`, `client_id`

2. **mqtt_message_received**: Fired when a message is published to a subscribed topic
    - Allows LLM to process message and potentially publish responses
    - Parameters: `topic`, `payload`, `qos`, `retain`

3. **mqtt_subscribed**: Fired when subscription is confirmed (optional, not currently used)
    - Could be used for complex subscription workflows
    - Parameters: `topics`

### Actions Available to LLM

**Async Actions** (user-initiated):

- `subscribe`: Subscribe to topic patterns (supports `+` and `#` wildcards)
- `publish`: Publish message to a topic with QoS and retain flag
- `unsubscribe`: Remove subscriptions
- `disconnect`: Close connection to broker

**Sync Actions** (in response to events):

- `publish`: Send response message based on received data
- `subscribe`: Dynamically subscribe to new topics

### Example LLM Flow

```
User: "Connect to MQTT broker and monitor temperature sensors"

1. Client connects → mqtt_connected event
2. LLM decides to subscribe("sensors/temperature/#", qos=1)
3. Message arrives on sensors/temperature/room1 → mqtt_message_received
4. LLM analyzes temperature, decides to publish("alerts/high_temp", "Room 1: 30°C")
5. Continue monitoring...
```

## Startup Parameters

The MQTT client supports the following startup parameters:

- **client_id**: MQTT client identifier (default: auto-generated `netget-{client_id}`)
- **username**: Optional authentication username
- **password**: Optional authentication password
- **keep_alive**: Keep-alive interval in seconds (default: 60)
- **clean_session**: Start with clean session (default: true)

Example:

```json
{
  "client_id": "netget-sensor-monitor",
  "username": "admin",
  "password": "secret",
  "keep_alive": 120,
  "clean_session": false
}
```

## Quality of Service (QoS)

MQTT supports three QoS levels:

- **QoS 0 (AtMostOnce)**: Fire and forget, no acknowledgment
- **QoS 1 (AtLeastOnce)**: At least one delivery, may duplicate
- **QoS 2 (ExactlyOnce)**: Exactly one delivery, highest overhead

The LLM can choose the appropriate QoS for each subscribe/publish action based on the use case.

## Topic Wildcards

MQTT supports topic wildcards in subscriptions:

- **+**: Single-level wildcard (e.g., `sensors/+/temperature` matches `sensors/room1/temperature`)
- **#**: Multi-level wildcard (e.g., `sensors/#` matches `sensors/room1/temperature` and `sensors/room2/humidity`)

Wildcards cannot be used in publish topics.

## Limitations

1. **No TLS support (yet)**: Currently plain TCP only. TLS support can be added via
   `rumqttc::MqttOptions::set_transport()`
2. **No will message**: Last Will and Testament not exposed to LLM (can be added)
3. **No manual acknowledgments**: QoS 1/2 acks are handled automatically by rumqttc
4. **Limited broker state**: No access to broker statistics or connection metrics
5. **Binary payloads**: Only UTF-8 string payloads are supported; binary data would need hex encoding

## Future Enhancements

1. **TLS/SSL support**: Add secure connections with certificate validation
3. **Will messages**: Allow LLM to set Last Will and Testament
4. **Retained message handling**: Better visibility into retained messages
5. **Shared subscriptions**: Support for load balancing across multiple clients

## Testing Strategy

See `tests/client/mqtt/AGENTS.md` for detailed testing documentation.

## References

- rumqttc documentation: https://docs.rs/rumqttc/
- MQTT 3.1.1 specification: https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/mqtt-v3.1.1.html
- Mosquitto broker: https://mosquitto.org/

## Command channel — the dashboard's `[ send ]`

Adopted, archetype **(a)**: `rumqttc::AsyncClient` is a cheap clonable handle to the event
loop's request channel, so the command loop holds its own clone and nothing had to be
restructured or wrapped in a `Mutex`.

- The channel is registered in `connect_with_llm_actions`, **before** the transport task starts
  and therefore before the `mqtt_connected` LLM call the turn task makes on CONNACK — a manual `*`
  rule can park that call for minutes and `[ send ]` has to work throughout.
  `tests/client/mqtt/command_channel_test.rs` guards it with `wait_for_client_handle`.
- `apply_action` is shared by the LLM path and the command path, so the mapping from
  `mqtt_publish` / `mqtt_subscribe` / `mqtt_unsubscribe` onto rumqttc calls exists once.

| Outcome | When |
|---|---|
| `Executed { detail }` | every successful action; `detail` names the packet, e.g. `PUBLISH to 'sensors/a' (5 byte payload, QoS 0, retain false) accepted by rumqttc` |
| `Rejected { error }` | `execute_action` refused it (unknown name, missing `topic`/`payload`) |
| `Disconnected` | `disconnect`; DISCONNECT was sent to the broker |
| `Err(..)` | rumqttc refused the request (the event loop is gone) |

**There is deliberately no `Sent { bytes_sent }`.** `AsyncClient::publish` returns once the
request has been accepted into the event loop's queue; the loop writes the packet afterwards and
reports no byte count. Claiming one here would be a guess, so the truthful answer is `Executed`
with a specific detail.

A `disconnect` also sets a flag the transport task reads: rumqttc surfaces the closed socket as a
poll **error**, and without the flag a deliberate hang-up was reported as
`ClientStatus::Error(...)`.

## Maturity: Beta

Rated against the four-condition client bar in the root `AGENTS.md`, on the evidence in
`tests/client/mqtt/real_server_test.rs` (see `tests/client/mqtt/AGENTS.md`):

1. **Real third-party server** — Eclipse Mosquitto (`mosquitto`, C), with `mosquitto_sub`/`mosquitto_pub` on the far side; NetGet's side is rumqttc, so no code is shared.
2. **Fails rather than skips** — a missing `mosquitto`, `mosquitto_sub` or `mosquitto_pub` is a test failure naming the brew formula and the
   Ubuntu package (`tests/helpers/real_server.rs`); nothing is `#[ignore]`d. CI's
   `registry-audit` installs the peer and runs the suite in its evidence loop.
3. **A real session** — the protocol's own exchange, with the server's answers parsed and handed
   to the model, not a connect.
4. **Acts on the model's answer, asserted on the wire** — `mosquitto_sub` prints the payloads the model published, and Mosquitto's own log records the model's subscription. Verified by mutation: dropping
   the actions the model returned makes the test fail.

Not covered by that evidence: TLS, enforced username/password, Last Will, persistent sessions and reconnection.

## MQTT 5.0 (`protocol_version: "5.0"`)

`protocol_version` (default `"3.1.1"`) picks rumqttc's stack at connect time. Two enums in
`mod.rs` are the only places that know there are two: `Broker` (the request handle every
action is applied through, so the LLM path and the injected-command path stay one code path)
and `Transport` (the event loop, reduced to a `Notice`: ConnAck, Publish, Disconnect, Other).
Everything above them — the turn queue, the model calls, the command loop — is shared.

On v5:

- `mqtt_connected` adds `reason_code` (the CONNACK's, as its wire value), `session_present`
  and `properties` (assigned_client_identifier, maximum_packet_size, topic_alias_maximum,
  user_properties, ... under the same snake_case names the broker uses).
- The client advertises no Topic Alias Maximum (0), so any PUBLISH from the broker carrying a
  `topic_alias` is a protocol violation and ends the connection: rumqttc would otherwise keep
  every alias a hostile broker sends, up to 65535 topics
  (`tests/client/mqtt/v5_topic_alias_test.rs`).
- `mqtt_message_received` adds `properties`: response_topic, correlation_data (+
  correlation_data_encoding: text when UTF-8, hex otherwise), content_type,
  message_expiry_interval, subscription_identifiers, user_properties.
- `publish` takes a `properties` object with the same names; it is validated in
  `execute_action`, so a bad one is refused before anything is queued, and refused outright on
  a 3.1.1 connection rather than silently dropped.
- `subscribe` takes `no_local`, `retain_as_published` and `retain_handling`.
- A broker DISCONNECT's reason code and Reason String reach the status line.

Request/response is the case to copy: answer a message by publishing to its
`properties.response_topic` with its `correlation_data` and `correlation_data_encoding`.