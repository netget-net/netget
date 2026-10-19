# Apache Pulsar client

Connects (`host:port`, a `pulsar://` prefix is accepted), sends CONNECT and waits for CONNECTED
before `connect` returns. Producers and consumers are created on demand, each after a LOOKUP;
a lookup that points at another broker is reported, not followed. PING is answered.

## Events

- `pulsar_connected {server_version, protocol_version, max_message_size}`.
- `pulsar_produced {topic, ok, message_id?, error?}` for every send (and for a producer the
  broker refused).
- `pulsar_subscribed {topic, subscription, operation, ok, error?}` for subscribe and
  unsubscribe.
- `pulsar_message {topic, subscription, payload, encoding, properties, key, producer_name,
  message_id, redelivery_count}`, one per message (batches split). The message is acknowledged
  after the handler has run on it.

## Actions

`pulsar_produce {topic, payload, encoding?, properties?, key?}` (sends queue behind the
producer's lookup and creation), `pulsar_subscribe {topic, subscription, sub_type?,
initial_position?}`, `pulsar_unsubscribe {topic, subscription}`, `disconnect`.

Consumers get `PERMITS` (1000), topped up by half when half are used. `MAX_PENDING` (256)
requests and sends may await the broker; a chain stops after `MAX_FOLLOWUP_DEPTH` (8).

## Batching

`BatchingMode::On`. Messages delivered while the model answers wait in the dispatcher queue;
with batching on the dispatcher drains everything waiting (up to `MAX_BATCH_EVENTS`) into one
`call_llm_for_client_batch` call, with it off one event per call. Every message in a batch is
acknowledged once the handler has run on the batch, so acknowledgement still follows the
handler. `tests/client/pulsar/batching_test.rs` is the off/on pair, and asserts all three
messages are acknowledged either way.
