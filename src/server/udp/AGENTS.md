# UDP Protocol Implementation

## Overview

UDP (User Datagram Protocol) server implementing connectionless datagram handling where the LLM has full control over
UDP packet responses. This is the foundation for UDP-based protocols like DNS, DHCP, NTP, SNMP, and custom datagram
protocols.

**Status**: Beta (Core Protocol)
**RFC**: RFC 768 (User Datagram Protocol)

## Library Choices

- **tokio::net::UdpSocket** - Async UDP socket from Tokio runtime
- **Manual datagram handling** - LLM receives raw datagram bytes and constructs responses

**Rationale**: UDP is simpler than TCP - no connection management, no stream splitting. A single socket handles all
peers. The LLM directly controls datagram content.

## Architecture Decisions

### 1. Connectionless Nature

UDP has no connections, but NetGet models each datagram as a "connection" for UI consistency:

- Each received datagram creates a new `ConnectionId`
- Connection represents "recent peer" for that datagram
- No persistent state between datagrams from the same peer

This design allows the TUI to display UDP activity similar to TCP connections.

### 2. Single Socket for All Peers

Unlike TCP (one socket per connection), UDP uses a single socket for all peers:

- `UdpSocket::recv_from()` receives from any peer
- `UdpSocket::send_to(data, peer_addr)` sends to specific peer
- No need to track socket state per peer

### 3. Stateless Processing

Each datagram is processed independently:

- No state machine (unlike TCP's Idle/Processing/Accumulating)
- No data queueing (each datagram is independent)
- LLM called once per datagram
- No `wait_for_more` support (UDP is message-oriented, not stream-oriented)

### 4. Peer Tracking

Each datagram is registered as its own pseudo-connection in `AppState` with the peer as
`remote_addr`. `ProtocolConnectionInfo` is a generic `serde_json::Value` wrapper - there is no
`Udp` variant and no `recent_peers` list; this server passes `ProtocolConnectionInfo::empty()`.
Nothing prunes these entries, so a busy port accumulates one connection record per datagram.

### 5. Maximum Datagram Size

Buffer size is 65535 bytes (maximum UDP datagram size including headers):

- IP MTU typically 1500 bytes, so most datagrams are much smaller
- Large datagrams may be fragmented by network layer
- LLM receives entire datagram (no partial reads like TCP)

### 6. Dual Logging

Like TCP, all operations use dual logging:

- **DEBUG**: Datagram summary with 100-char preview
- **TRACE**: Full payload (text as string, binary as hex)
- Both go to `netget.log` and TUI Status panel

## LLM Integration

### Action-Based Response Model

The LLM responds to UDP events with actions:

**Events**:

- `udp_datagram_received` - Datagram received from peer
    - Parameters: `peer_address`, `data_length`, `data_encoding`, `data_preview`

**Available Actions**:

- `send_udp_response` - Send datagram to peer (text or hex)
- `send_to_address` - Send datagram to arbitrary address (async action)
- Common actions: `notify_operator`, `update_instruction`, etc.

### Example LLM Response

```json
{
  "actions": [
    {
      "type": "send_udp_response",
      "data": "PONG",
      "encoding": "text"
    },
    {
      "type": "notify_operator",
      "message": "Echoed PING"
    }
  ]
}
```

### Data Format

`data` is paired with an `encoding` parameter:

- `"text"` (or `"utf8"`) - the string's UTF-8 bytes, verbatim
- `"hex"` - hex-decoded; an error if the string is not valid hex
- omitted, or `"auto"` - hex if the string happens to parse as hex, otherwise text

`"utf8"` is accepted because the TCP server spells the same idea that way, and a model that has
just been writing `send_tcp_data` reaches for it here. It used to be rejected outright with
"Unknown encoding 'utf8'", losing the whole datagram over a spelling.

**`auto` is ambiguous and is only the default for backwards compatibility.** Any even-length
run of hex digits is taken as hex, so `{"data": "1234"}` puts the two bytes `0x12 0x34` on the
wire rather than the four characters `1234`. The same applies to `"abcd"`, `"DEADBEEF"` and
`"0000"`. An echo server written against the old documented behaviour ("text data sent as-is")
silently corrupted any payload that looked like hex. Always pass `encoding` explicitly.

The guess is no longer silent: whenever `auto` actually resolves to hex, `decode_payload` logs a
WARN naming the character and byte counts. **It should not be the default at all** — TCP was
given an explicit `encoding` field for exactly this reason — but flipping it breaks three
existing tests outside this protocol's tree (`tests/server/ospf/e2e_test.rs`, which starts the
generic UDP server and relies on `hex::encode(...)` being auto-detected) plus
`tests/server/udp/test.rs`. That is one small cross-cutting change, not a UDP-local one.

**Received data** arrives as `data_preview` plus `data_encoding`, which is `"text"` when the
datagram is printable ASCII and `"hex"` otherwise; reply using the same encoding. The preview
covers the first 200 bytes and is suffixed with `...` when truncated. This field previously
held `format!("{:?}", data)` on a `Vec<u8>`, i.e. the model was shown `[72, 101, 108, 108, 111]`
for `"Hello"` and had to reconstruct the payload from decimal byte codes.

## Connection Management

### Pseudo-Connection Lifecycle

1. **Receive**: `UdpSocket::recv_from()` receives datagram and peer address
2. **Register**: Create new `ConnectionId` and add to `ServerInstance`
3. **Process**: Spawn async task to call LLM and generate response
4. **Send**: Use same socket to send response via `send_to()`
5. **Track**: Connection remains in UI until pruned

### Connection Data Structure

`ProtocolConnectionInfo::empty()`. There is no `Udp` variant and no `recent_peers` list — this
section used to show a `ProtocolConnectionInfo::Udp { recent_peers }` that has never existed,
contradicting §4 three paragraphs above. Unlike TCP there is no write_half and no queued_data:
UDP is stateless here.

### State Updates

- Connection state tracked in `ServerInstance.connections`
- Each datagram creates a row with `packets_received: 1` and `bytes_received: n`
- The response calls `update_connection_stats`, so `packets_sent` / `bytes_sent` /
  `last_activity` move. They did **not** until September 2026: the row was created and never
  touched again, so the rail's `↑` column sat at zero for the entire life of every entry while
  this file claimed otherwise
- UI updates via `__UPDATE_UI__` message

## Known Limitations

### 1. No Connection Affinity

Each datagram is treated as a new "connection" with a new `ConnectionId`. There's no way to associate multiple datagrams
from the same peer unless the LLM maintains state via `update_instruction`.

### 2. No Fragmentation Handling

If a datagram exceeds network MTU and is fragmented, the OS reassembles it. NetGet sees only the complete datagram. No
visibility into fragmentation.

### 3. No Delivery Guarantees

UDP is unreliable by nature:

- No acknowledgments
- No retransmission
- Packets may be lost, duplicated, or reordered
- LLM responses may never reach the client

### 4. No Rate Limiting

Server processes every received datagram:

- No protection against UDP flood attacks
- No throttling of LLM calls
- Can be overwhelmed by high packet rates

### 5. `send_to_address` — fixed, and worth knowing as the shape of the bug

It used to parse the `address` for validation and then **discard** it: the executor returned a
plain `ActionResult::Output`, and the handler in `mod.rs` writes every Output back to the peer
that sent the current datagram — so the one action whose purpose is "send somewhere else"
behaved exactly like `send_udp_response`, with nothing in the log to say so.

It now writes the datagram itself through the server's own socket (`try_send_to`, because the
executor is synchronous) and returns `NoAction`, so `mod.rs` does not additionally echo it to
the current peer. Two consequences:

- It only works inside a running server, which is the only context that holds a socket. The
  registry's copy has none and says so, rather than pretending.
- It is therefore declared on `udp_datagram_received` as well as in `get_async_actions()`.
  `call_llm` builds a server's tool list from the *event*, so while it was only in the async
  list the model was never offered it in the one place it could have worked.

`test_send_to_address_reaches_the_named_address_only` asserts both halves: the named observer
receives the payload, and the triggering peer does not.

### 6. No Multi-packet Responses

LLM can send only one response datagram per received datagram. No built-in support for protocols that require multiple
responses (though the LLM could use `send_to_address` async action for additional sends).

### 7. Peer Tracking Never Pruned

One connection record is created per datagram and nothing removes them, so a busy port grows the AppState connection list without bound.

## Example Prompts

### Echo Server

```
listen on port 9 via udp
When you receive any data, echo it back to the sender
```

### PING/PONG Server

```
listen on port 8000 via udp
When you receive "PING", respond with "PONG"
When you receive anything else, respond with "Unknown command"
```

### Binary Protocol

```
listen on port 9001 via udp
When you receive a 4-byte big-endian integer, respond with the integer + 1
Use hex encoding for binary data
```

### Stateless Request/Response

```
listen on port 5000 via udp
Parse incoming JSON requests
Respond with JSON: {"status": "ok", "echo": <received_data>}
```

## Performance Characteristics

### Latency

- One LLM call per received datagram
- Typical latency: 2-5 seconds per datagram with qwen3-coder:30b
- No connection setup overhead (unlike TCP)

### Throughput

- Limited by LLM response time (same as TCP)
- Datagrams processed concurrently (each on separate tokio task)
- No queueing mechanism (UDP is fire-and-forget)

### Concurrency

- Unlimited concurrent datagrams (bounded by system resources)
- All datagrams share the same socket
- Ollama lock serializes LLM API calls across all datagrams

### Packet Loss

- If LLM response takes too long, client may timeout
- No retransmission - client must implement retry logic
- Lost packets have no impact on server state (stateless)

## Comparison with TCP

| Feature          | TCP                             | UDP                            |
|------------------|---------------------------------|--------------------------------|
| Connection       | Stateful, persistent            | Stateless, per-datagram        |
| State Machine    | Idle/Processing/Accumulating    | None (stateless)               |
| Data Queueing    | Yes                             | No (each datagram independent) |
| Stream Splitting | Required (ReadHalf/WriteHalf)   | Not needed (single socket)     |
| Reliability      | Guaranteed delivery             | Best effort                    |
| Order            | In-order delivery               | May be reordered               |
| Use Case         | Protocols requiring reliability | Fast, stateless protocols      |

## References

- [RFC 768: User Datagram Protocol](https://datatracker.ietf.org/doc/html/rfc768)
- [Tokio UdpSocket](https://docs.rs/tokio/latest/tokio/net/struct.UdpSocket.html)
- [UDP on Wikipedia](https://en.wikipedia.org/wiki/User_Datagram_Protocol)

## Failure behaviour: silence, deliberately

`metadata()` declares this with `.deliberately_silent()` (`FailureMode::DeliberatelySilent`),
which `tests/failure_mode_declaration_test.rs` checks; the reason is repeated in a comment beside
the call.

When `call_llm` returns `Err`, this server writes **nothing** — and unlike the rest of the
protocol tree, that is the correct answer rather than the "reset to Idle and write nothing"
defect.

Bare UDP (RFC 768) has no error frame, no transaction identifier and no application semantics.
The server does not know what the datagram meant, so any bytes it invented could be parsed as a
real reply by whatever protocol the peer is actually speaking — a worse failure than dropping
it, because the peer would act on the answer. Dropping a datagram is also ordinary UDP
behaviour that every UDP client already handles.

Protocols layered on UDP that *do* have an error form must use it, and do: DNS answers SERVFAIL,
STUN answers a 500 Binding Error Response, NTP answers a Kiss-o'-Death.

Because a silent drop is indistinguishable from the defect, it is logged loudly: ERROR on both
the tracing and status channels, naming the peer and saying explicitly that no reply is
possible, plus a WARN when `crate::llm::is_overload_error` identifies capacity exhaustion.
`tests/server/udp/llm_failure_test.rs` asserts both halves — nothing on the wire, and the log
line that explains it.

### The table

Every datagram ends in exactly one `decision=` line. Four of the six outcomes put **nothing**
on the wire, so the log is the only place they differ — which is exactly why this protocol
needs the tags most.

| Outcome | On the wire | Log |
|---|---|---|
| Model answered `send_udp_response` | that datagram | INFO `decision=model_answer` |
| Model answered `send_to_address` | a datagram to the **named** address; nothing to this peer | INFO `decision=model_answer` (names the action) |
| Model answered `ignore_datagram` | nothing | INFO `decision=model_reject` |
| Model answered with no usable action | nothing | WARN `decision=model_silent` |
| The action could not be executed | nothing | ERROR `decision=fail_closed_bad_action` |
| The reply could not be put on the socket | nothing | ERROR `decision=protocol_error` |
| Backend failed / saturated | nothing | ERROR `decision=fail_closed_llm_error` / `decision=fail_closed_llm_overloaded` |

`decision=protocol_error` is the one invented token here: nothing about the model went wrong,
the `send_to` itself did. It is kept separate from `fail_closed_*` so a `grep
decision=fail_closed` audit is not diluted by socket errors.

`tests/server/udp/decision_tag_test.rs` pins the `model_reject` and `model_silent` rows,
asserting for each that **nothing** reached the socket *and* that the right token reached the
log. Either assertion alone is meaningless: silence with no log is the defect, and a log line
with a datagram beside it would mean the tag was lying.

## Echo means sending `data_preview` back

Told to "send every datagram straight back, unchanged", llama3.1:8b sent the literal text
`datagram unchanged` or `data` (`udp/echo` 3/5 in the committed eval baseline): nothing told it
that `data_preview` *is* the datagram. `data_preview` now says it is the whole payload unless it
ends in `...`, and `send_udp_response` says an echo puts it in `data` with its `data_encoding`.
Wording only; with seed 42 `udp/echo` and `udp/fixed-reply` are 5/5.

