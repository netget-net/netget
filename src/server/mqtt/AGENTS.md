# MQTT Protocol Implementation

MQTT 3.1.1 and 5.0 broker. Control packets are parsed and built by hand in `mod.rs` (v5
properties and reason codes in `v5.rs`); the LLM (or a script/static handler) decides every
acknowledgement and every message delivery. The version is the client's: protocol level 5 in
its CONNECT makes the connection a v5 one, anything else is answered in 3.1.1 framing.

**State**: **Beta** (August 2026) — works against a real third-party client. `rumqttc` drives
CONNECT/CONNACK in `test_mqtt_basic_connect`, and
`test_mqtt_subscribe_and_receive_a_published_message` takes it all the way through
CONNECT → SUBSCRIBE → SUBACK → PUBLISH and back to the broker's own PUBLISH arriving on the
same connection, with topic and payload asserted. Neither test is `#[ignore]`d. Also verified
with a raw-socket MQTT client driving QoS 0, 1 and 2, plus PINGREQ.

The promotion is *not* new implementation work — the broker already did all of this. What was
missing was evidence, and the reason it looked missing is worth recording: the root CLAUDE.md
listed mqtt as "`mqtt`, whose rumqttc tests are all `#[ignore]`d", and that was wrong twice
over. The four pub/sub tests were inside a `/* … */` block, so nothing compiled them and
`--include-ignored` could never have run them; and the rumqttc test that *does* run was never
ignored at all. Their `#[ignore = "MQTT broker not yet implemented"]` markers were left over
from the placeholder described below. The dead block is deleted and replaced by one real
pub/sub test.

Two things that will silently break a mock for this protocol, both of which this test
encodes: `mqtt_suback` **must** echo `packet_id` from the event (rumqttc blocks until a SUBACK
carrying the id it chose arrives, so a hardcoded id stalls the subscribe forever), and the
event `mqtt_publish` and the action `mqtt_publish` share a name while pointing in opposite
directions — the event is the client's PUBLISH arriving, the action is the broker sending one.
**Port**: 1883 by default. **Privilege**: `None` (1883 > 1024).
**Stack**: `ETH>IP>TCP>MQTT`. **Spec**: MQTT 3.1.1 (OASIS / ISO-IEC 20922).

This replaces a placeholder that returned empty vectors from `get_sync_actions()` and
`get_event_types()` while advertising itself as `Experimental`. It answered CONNECT with
a hardcoded CONNACK and PINGREQ with PINGRESP, ignored PUBLISH and SUBSCRIBE entirely,
never called the LLM, and `execute_action` errored on every input.

## Why hand-written rather than rumqttd

`rumqttd` is a dependency of the `mqtt` feature but is not used. It owns its own session,
subscription and routing model — precisely the part the LLM has to own here — and exposes
no hook for "ask something else whether this CONNECT is acceptable". MQTT 3.1.1 control
packets are a varint length, length-prefixed UTF-8 strings and a handful of fixed-size
acknowledgements, so the codec is ~200 lines and every byte is inspectable.

## What the model sees

| Event | Fired when | Must be answered with |
|---|---|---|
| `mqtt_connect` | CONNECT received | `mqtt_connack` |
| `mqtt_publish` | client published | `mqtt_puback` (QoS 1), `mqtt_pubrec` (QoS 2), nothing (QoS 0) |
| `mqtt_subscribe` | SUBSCRIBE received | `mqtt_suback` |
| `mqtt_unsubscribe` | UNSUBSCRIBE received | `mqtt_unsuback` |

`mqtt_connect` carries `client_id`, `username`, `has_password`, `clean_session`,
`keep_alive`, `protocol_name`, `protocol_level`, `will_topic`, `will_message`. The
password itself is not surfaced.

`mqtt_publish` carries `client_id`, `topic`, `payload`, `payload_is_text`,
`payload_size`, `qos`, `retain`, `duplicate`, `packet_id`, and `connected_clients` — the
list of client ids currently attached to this server, so the model can forward the
message without guessing names.

`mqtt_subscribe` carries `packet_id`, `topics` (an ordered list of
`{"filter": "...", "qos": N}`) and `answer_with`, which spells out the SUBACK for this
subscription (its packet id and one granted QoS per filter) **and** tells the model to follow
it with an `mqtt_publish`, `retain: true`, for every matching topic its instruction gives a
retained message or current value (`subscribe_answer_with` in `mod.rs`). A variant phrased
"answer with two actions: …" was measured and is worse (0/5): llama3.1:8b restated the event
data before its answer, and the reply parser took the restated `{"filter": …}` object as the
action. The real-model eval
(`mqtt/retained-message`, llama3.1:8b, seed 42) scored 0/5 without it: told a topic "holds the
retained reading 19.5", the model sent the SUBACK and nothing else, and `mosquitto_sub` waited
out its timeout. A broker that stores nothing can deliver a retained message only if the model
publishes it, so the event has to say so.

**A connection gets one CONNACK.** `execute_connack` refuses a second on the same connection
(`MqttProtocol::connack_sent`, never cleared), logged `decision=duplicate_response_dropped`; in
one eval run the model answered a CONNECT with two, and libmosquitto dropped the connection as
a protocol error. `tests/server/mqtt/answer_with_test.rs` pins both; the CONNACK guard was
verified by removing it and watching the second CONNACK reach the wire in place of the SUBACK.

### Correlation identifiers

MQTT correlates by **packet identifier**, and every acknowledgement must echo the one
from the request or the client retries forever.

- `packet_id` is exposed on `mqtt_publish`, `mqtt_subscribe` and `mqtt_unsubscribe`, so a
  static handler can echo it with `{{event.packet_id}}` — no script and no model call:

  ```json
  {"event_pattern": "mqtt_publish",
   "handler": {"type": "static",
     "actions": [{"type": "mqtt_puback", "packet_id": "{{event.packet_id}}"}]}}
  ```

- `mqtt_suback`'s `granted_qos` must have one entry per filter in the event's `topics`,
  in the same order.
- QoS 0 publishes carry no packet identifier; the event reports `packet_id: 0` and no
  acknowledgement exists.

### Payloads are text, never bytes

`payload` is the message body decoded as UTF-8. If the bytes are not valid UTF-8,
`payload_is_text` is false, `payload` holds a lossy rendering and `payload_size` gives
the true byte count. Nothing base64 or hex encoded is ever put in an event or an action —
a model cannot reliably read or write it.

## Actions

**Sync** (in response to a client packet):

| Action | Parameters |
|---|---|
| `mqtt_connack` | `return_code` (0 accept; 1-5 refuse), `session_present` |
| `mqtt_suback` | `packet_id`, `granted_qos` (0/1/2 to grant, 128 to refuse, one per filter) |
| `mqtt_puback` | `packet_id` |
| `mqtt_pubrec` | `packet_id` |
| `mqtt_unsuback` | `packet_id` |
| `mqtt_publish` | `topic`, `payload`, `qos`, `retain`, `packet_id`, `to_client_id` |
| `close_this_connection` | — |

**Async** (user-triggered, no connection context):

| Action | Parameters |
|---|---|
| `mqtt_publish_to_client` | `server_id`, `client_id` (or `"*"`), `topic`, `payload`, `qos`, `retain`, `packet_id` |
| `list_mqtt_clients` | `server_id` |

Every declared parameter is read by `execute_action`; there are no dead actions and no
undeclared executor branches. Sync actions write to the connection they were produced
for, through that connection's single writer channel, so a packet can never interleave
with one the read loop is emitting. `mqtt_publish` with `to_client_id` writes to another
client's channel instead; `"*"` fans out to every client on the server.

## Routing: the model does it, not the broker

**There is no subscription table and no retained-message store in Rust.** After a client
publishes, nothing is delivered automatically, and a retained message reaches a new subscriber
only because the subscribe event's `answer_with` asks the model to publish it. The model remembers who subscribed to what
(server memory, or a script's own state) and issues `mqtt_publish` with `to_client_id` for
each recipient. `connected_clients` in the publish event and the `list_mqtt_clients`
action give it the live client ids.

The only cross-request state the broker keeps is a directory of **live socket senders**
keyed by `(server id, client id)`, so that a named recipient can be written to. Nothing
survives a disconnect; no message, subscription, topic or retained value is stored.

## Dashboard peer injection

Every connection registers a **peer handle** (`peer_support::register_peer_channel` /
`spawn_peer_command_task`) right after it is accepted — before any CONNECT — so the
dashboard's "message this peer" / "disconnect this peer" rows work while the connection is
idle. Injected actions run through the same executor the model path uses, against the
per-connection `MqttProtocol`, so an injected `mqtt_publish` / `mqtt_puback` / … is encoded
by exactly the code the model's would be.

Two things follow from MQTT's channel-based writer (`out_tx`, drained by one writer task
that owns the shared `Arc<Mutex<WriteHalf>>`):

- **Wire verbs return `ActionResult::Custom`, not `Output`.** They write to the connection's
  own channel as a side effect and return Custom, so the generic peer task reports the
  outcome as `Executed { detail }` rather than `Sent { bytes_sent }` — but the bytes *do*
  reach the wire, and the byte counters move. This is why the peer-inject test reads the
  socket and the counters, not the outcome's byte count.
- **`close_connection` has an explicit `execute_action` arm** (returning
  `ActionResult::CloseConnection`) because "disconnect this peer" injects
  `{"type":"close_connection"}`, distinct from the model-facing `close_this_connection`
  verb. On it the generic task `shutdown()`s the shared write half → the client reads EOF.

The peer handle is removed on every exit path via `finish_connection`. It is removed
*first* there, because the peer command task holds an `Arc<MqttProtocol>` carrying an
`out_tx` clone; dropping the handle ends that task so the writer can finish draining.

**Per-connection byte and packet counters** are updated on every read (in the read loop)
and every write (in the writer task), so the rail shows live `↓/↑` counts.

## What the broker answers by itself

Two cases, both pure transport bookkeeping with no semantics to decide:

- **PINGREQ → PINGRESP** (keep-alive).
- **PUBREL → PUBCOMP**, the second half of the QoS 2 handshake, echoing the packet
  identifier.

## Batching (on by default, QoS 0 PUBLISH only)

QoS 0 PUBLISHes already waiting behind one being answered are answered in one call
(`publish_batch` in `mod.rs`): they owe the client nothing on the wire, so nothing can be
mis-acknowledged. Everything else stays one call per packet — CONNECT; QoS 1/2 PUBLISH,
SUBSCRIBE and UNSUBSCRIBE, which each owe an acknowledgement carrying their own packet id, in
arrival order (§4.6), where Rust's default ack for one the model skipped would land after the
model's acks for later ones; and everything Rust answers itself (PINGREQ, PUBREL). Collection
stops at the first packet that is not a QoS 0 PUBLISH and leaves it for the session loop. A
batch the backend fails closes the connection, as a single QoS 0 PUBLISH does.
`tests/server/mqtt/batching_test.rs` pins it against a batching-off control, including a QoS 1
PUBLISH arriving behind the batch that still gets exactly one PUBACK with its own id.

## Failure behaviour

MQTT stays on the wire on every path: it has a real refusal vocabulary (CONNACK return codes
1-5, SUBACK 0x80) and, where it has none, closing the connection is the spec's own channel for
a broker error. Nothing derived from an error is ever interpolated into a packet — MQTT 3.1.1
has no free-text field to put one in.

The distinction that matters here is **"the handler ran and declined to decide" versus "the
handler could not run"**, `LlmOutcome::Silent` versus `LlmOutcome::Failed` in `mod.rs`. They
were one outcome once, and the permissive `Silent` defaults were applied to both: an LLM outage
accepted every CONNECT (return code 0, credentials and all) and granted every SUBSCRIBE. Both
now log a distinct `decision=` token, and `run_llm` is the single place the four outcomes are
classified.

| Event | Outcome | On the wire | Log |
|---|---|---|---|
| any | handler produced the required packet | that packet | INFO `decision=model_answer` |
| any | handler produced `close_this_connection` / `close_connection` | connection closed | INFO `decision=model_reject` |
| `mqtt_connect` | handler ran, no `mqtt_connack` | **CONNACK 0 — accepted** | WARN `decision=model_silent actions=<n>` |
| `mqtt_connect` | backend failed | CONNACK 3 (server unavailable), then close (3.2.2.3) | ERROR `decision=fail_closed_llm_error` / `fail_closed_llm_overloaded` |
| `mqtt_subscribe` | handler ran, no `mqtt_suback` | SUBACK granting the QoS each filter asked for | WARN `decision=model_silent actions=<n>` |
| `mqtt_subscribe` | backend failed | SUBACK 0x80 on every filter (3.9.3) | ERROR `decision=fail_closed_llm_*` |
| `mqtt_publish` QoS 1/2 | handler ran, no ack | PUBACK / PUBREC echoing `packet_id` | WARN `decision=model_silent actions=<n>` |
| `mqtt_publish` QoS 1/2 | backend failed | **nothing** — connection closed | ERROR `decision=fail_closed_llm_*` |
| `mqtt_publish` QoS 0 | handler ran, no action at all | nothing owed | WARN `decision=model_silent actions=0` |
| `mqtt_unsubscribe` | handler ran, no `mqtt_unsuback` | UNSUBACK echoing `packet_id` | WARN `decision=model_silent actions=<n>` |
| `mqtt_unsubscribe` | backend failed | **nothing** — connection closed | ERROR `decision=fail_closed_llm_*` |
| any | malformed packet, second CONNECT, QoS 3, empty SUBSCRIBE, oversize packet | connection closed, no reply | WARN `decision=protocol_error` |

PUBLISH and UNSUBSCRIBE close rather than acknowledge on a backend failure because PUBACK and
UNSUBACK are a bare packet identifier with no failure code: sending one would tell the client
its message was taken or its subscriptions were removed. Closing leaves QoS 1/2 redelivery to
do its job.

"Produced no reply" is checked per **packet type**, not "wrote anything": a handler that
forwards a PUBLISH but forgets the PUBACK still gets the PUBACK default, and logs
`decision=model_silent actions=1` rather than `actions=0` — which is how you tell a handler
with nothing to say from one that did something else and omitted the mandatory packet.

`decision=protocol_error` is the one non-model token: those refusals are decided by the codec
before any handler is consulted.

### The one fail-open left, deliberately narrowed and **not** fixed in the tagging pass

`mqtt_connect` + `decision=model_silent` sends **CONNACK 0, an accepted session**. A model that
is asked about a CONNECT carrying a username and password and answers with nothing gets that
client admitted. That is the OAuth2 shape the root `AGENTS.md` describes, narrowed to the case
where the handler demonstrably ran — a backend failure refuses (CONNACK 3) and an explicit
refusal is `mqtt_connack` with return code 1-5, so the three are now three different log lines.

It is deliberate as far as it goes: the broker is a honeypot, CONNACK is mandatory, and a
handler that ran and said nothing is "no opinion" rather than "no answer". But the wire *can*
carry the refusal here (return code 5, "not authorized", or 3), so unlike the deliberately
silent protocols there is no wire-shaped excuse — the only thing standing between this and the
OAuth2 defect is that `Silent` and `Failed` are distinct. Anyone hardening this should change
the CONNECT `Silent` arm, not the tag.

## Limits

The fixed header allows a 268 435 455 byte remaining length; trusting it would let one
client request a 256 MiB allocation per packet. `max_packet_size` (startup parameter,
default 256 KiB, hard maximum 16 MiB) is checked before any allocation, and the
connection is closed when it is exceeded. Every parse function is bounds-checked with
`get()`/`checked_add`; no input can panic the read loop.

## Startup parameters

- `max_packet_size` (integer, optional, default 262144, clamped to 64..=16777216)
- `first_byte_timeout_secs` (integer, optional, default 30) — how long a peer may take to send
  CONNECT
- `idle_timeout_secs` (integer, optional, default 900) — silence allowed to a session whose
  client declared Keep Alive 0; a non-zero Keep Alive is not overridable (see below)

## Connection bounds

| Bound | Default | Where it comes from |
|---|---|---|
| Until CONNECT | 30s (`first_byte_timeout_secs`) | 3.1.1 §3.1.4: a server that receives no CONNECT in a reasonable time SHOULD close |
| After CONNECT, Keep Alive > 0 | **1.5 × the client's Keep Alive** | 3.1.1 §3.1.2.10, a MUST — `session_idle_bound` |
| After CONNECT, Keep Alive = 0 | 900s (`idle_timeout_secs`) | a fallback, because a bound the client can switch off in its own CONNECT is no bound |
| Connections | 256 | `accept_bounded`; the peer over the cap reads CONNACK 3 and EOF |

- **The deadline wraps the read and nothing else.** Every packet is dispatched inline, so while
  the model — or a human, through a `manual` rule — composes an answer the read is not polled and
  no clock runs against the session. PINGREQ is how an idle subscriber keeps its session, and
  the broker answers it by itself.
- **Expiry closes the socket with no packet** (3.1.1 has no server DISCONNECT) and logs
  `decision=idle_timeout` with which of the three bounds fired. The will is not published —
  see "Last will" below.
- **Which client state the connect bound faces: speaks inside `connect()`.** NetGet's own MQTT
  client is `rumqttc`, whose event loop writes CONNECT on its first poll.
- **A NetGet-client consequence worth knowing**: `src/client/mqtt/mod.rs` awaits each incoming
  PUBLISH's model turn inside the loop that polls `rumqttc`'s event loop, so while that turn is
  parked for a human the client sends no PINGREQ. Against this broker (or any conforming one) a
  park longer than 1.5 × the client's `keep_alive` ends the session. That is the client's to fix
  — polling the event loop concurrently with the model turn — not a reason to stretch a bound
  the spec makes a MUST.
- `tests/server/mqtt/connection_bounds_test.rs` drives all of these from the wire.

## Not implemented

- **MQTT 5.0 enhanced authentication** (AUTH, §4.12) — an AUTH packet is a Protocol Error
  (DISCONNECT 0x82). A CONNECT naming an `authentication_method` reaches the handler; only
  an explicit accepting `mqtt_connack` admits it. A silent handler gets CONNACK 0x8C Bad
  Authentication Method and the connection closes (`decision=fail_closed_auth_method`),
  because admitting it would skip an authentication the client asked for
  (`tests/server/mqtt/v5_property_limits_test.rs`).
- **v5 session state**: Session Expiry, Receive Maximum (the broker does not count its own
  in-flight QoS>0 publishes), Will Delay, Request Response Information, Server Keep Alive.
  Each is reported to the model where the client sent it; none changes the broker's behaviour.
- **TLS (8883) and WebSocket transport.**
- **Retained messages** — the RETAIN flag is reported inbound and settable outbound, but
  nothing is stored, so a late subscriber receives nothing automatically.
- **Last will and testament** — `will_topic` and `will_message` are surfaced, but the
  broker never publishes the will on an unclean disconnect.
- **Session persistence** (`clean_session=false`), **QoS 2 duplicate suppression**,
  **topic wildcard matching** in Rust (the model interprets `+` and `#` itself), **`$SYS` topics**,
  **clustering**, **bridging**, **authentication beyond passing the username to the
  model**.

## Testing

`tests/server/mqtt/e2e_test.rs` (declared in `tests/server/mod.rs`). Its
`test_mqtt_keyword_detection` still asserts that starting an MQTT broker fails, and its
docstring still describes a placeholder — both predate this implementation and are
outside this change.

Real-client verification used during review, via `--mcp-stdio` with static handlers so no
model is involved: a raw-socket MQTT 3.1.1 client sending CONNECT, SUBSCRIBE, PUBLISH at
QoS 0/1/2 and PINGREQ, asserting CONNACK, SUBACK with the requested QoS, PUBACK/PUBREC
echoing the packet identifier, and PINGRESP.

## References

- [MQTT 3.1.1 (OASIS)](https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html)
- [rumqttc](https://docs.rs/rumqttc/) — client used by the E2E tests
- Testing notes: `tests/server/mqtt/AGENTS.md`

## MQTT 5.0

Every v5 difference is in one of three places, and nowhere else:

- **Parsing** (`parse_connect` / `parse_publish` / `parse_subscribe` / `parse_unsubscribe`,
  each taking the connection's `v5` flag) reads the property block that follows the variable
  header — and in CONNECT the Will Properties before the will topic — through
  `v5::read_properties`. An unknown property identifier, a truncated value or ill-formed UTF-8
  is 0x81 Malformed Packet; a non-repeatable property twice is 0x82 Protocol Error (§2.2.2.2).
  A block may carry at most `MAX_USER_PROPERTIES` (128) User Properties; a Subscription
  Identifier is accepted only once in a SUBSCRIBE and never as 0 or in a client PUBLISH; a
  CONNECT Maximum Packet Size of 0 is a Protocol Error.
  The decoded block reaches the model as `properties` on every v5 event: snake_case names,
  User Properties as `[[name, value], ...]` (names may repeat), Subscription Identifiers as a
  list, and binary values (Correlation Data, Authentication Data) as text when they are UTF-8
  without controls and hex otherwise, with `<name>_encoding` saying which.
- **Encoding**: `build_connack_v5`, `build_ack_v5`, `build_suback_v5`, `build_unsuback_v5`,
  `build_publish_v5`, `build_disconnect_v5`. A broker PUBLISH is an `OutPublish`, framed per
  recipient by `encode(v5)`, because one `mqtt_publish` to `"*"` can reach clients of both
  versions; a 3.1.1 recipient gets no properties, and the action result names it under
  `properties_not_sent_to`.
- **Executors** (`actions.rs`) take both vocabularies. `mqtt_connack` takes a 3.1.1
  `return_code` or a v5 `reason_code`, mapped either way by `connack_v311_to_v5` /
  `connack_v5_to_v311` so a refusal is always a refusal; `granted_qos` takes v5 SUBACK codes
  and sends 0x80 for each on 3.1.1; `mqtt_puback` / `mqtt_pubrec` take a `reason_code` and
  **refuse** a failure code on a 3.1.1 connection (its acknowledgement means "taken" and cannot
  say otherwise); `mqtt_unsuback` takes per-filter `reason_codes`, defaulting to 0x00 for
  each filter of the UNSUBSCRIBE it answers (`note_unsubscribe` records the count);
  `close_this_connection` sends a DISCONNECT with `reason_code` first. Every v5 acknowledgement
  may carry `reason_string` and `user_properties`. `mqtt_connack` no longer defaults to
  accepting: a CONNACK with neither code is refused as an action error.

What the broker does on a v5 connection without being asked:

| | |
|---|---|
| Accepting CONNACK | Maximum Packet Size (`max_packet_size`), Topic Alias Maximum 16, and Assigned Client Identifier when the client sent an empty id (§3.2.2.3.7 makes it a MUST) |
| Topic Alias | A PUBLISH with a topic and an alias defines it; an empty topic uses it; the model always sees the topic. An undefined alias is DISCONNECT 0x82, alias 0 or past 16 is 0x94 |
| Client's Maximum Packet Size | The writer task drops any packet larger, logged `decision=dropped_over_client_max_packet_size` (§3.1.2.11.4) |
| Protocol errors | DISCONNECT with 0x81 / 0x82 / 0x95 before the close (`Session::refuse`) |
| Refusing CONNACK | The connection closes after it, on both versions (3.1.1 §3.2.2.3, 5.0 §3.2.2.2) |

**Failure paths on v5** can say more than 3.1.1's, and `LlmOutcome::Failed` carries the
`WireFailure` category so they do: CONNACK 0x89 Server Busy when the backend is saturated and
0x88 Server Unavailable otherwise; PUBLISH still closes (a PUBACK of any reason ends the
exchange and the publisher drops the message) but first sends DISCONNECT 0x89 / 0x80; SUBACK
0x80 per filter as before; UNSUBACK 0x80 per filter **instead of closing**, because v5's
UNSUBACK can say "not removed". The Reason String on each is the category text, never the error.

The cap-refusal CONNACK in `accept_bounded` is still 3.1.1 framing — it is written before any
CONNECT is read, so the client's version is unknown.

Evidence: `tests/server/mqtt/v5_real_client_test.rs` (Mosquitto's C clients at `-V 5`, Eclipse
Paho's Python client at MQTTv5) and `v5_wire_test.rs` (hand-built packets, exact bytes, the
pcap oracle). See `tests/server/mqtt/AGENTS.md`.