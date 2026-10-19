# WebRTC Client Implementation

## Overview

WebRTC (Web Real-Time Communication) client implementation for NetGet with **enhanced features**:
- **Data channels only** (no audio/video media)
- **WebSocket signaling** for automatic SDP exchange
- **Multi-channel support** for parallel data streams
- **Binary data support** with hex encoding/decoding

This implementation is well-suited for LLM control, enabling peer-to-peer messaging with automatic or manual connection setup.

## Enhancements (v2)

### 1. WebSocket Signaling Support

**Purpose**: Automatic SDP exchange via signaling server (no manual copy-paste)

**Usage**:
```bash
# Manual mode (original - user exchanges SDP)
> open_client webrtc manual "Send hello message"

# WebSocket mode (automatic - connects to signaling server)
> open_client webrtc ws://localhost:8080/alice "Send hello to bob"
```

> **WebSocket signalling mode does not complete a connection. It is unfinished, not a
> feature.** The client connects, registers, gathers ICE and then waits forever: the offer
> is stored and never sent, because the only action that would send it — `send_offer` — has
> no reachable sink (`connect_with_llm_actions` says so at the store site, and the command
> loop refuses the action). It is additionally wire-incompatible with NetGet's own `webrtc`
> *server*, whose first frame must be an `offer` while this client sends `register`.
>
> This section used to say "Automatically sends SDP offer and receives answer / No user
> intervention required", while the same file admitted the gap 460 lines further down. Use
> manual mode, or fix `send_offer`. Everything below describes the intended design, not a
> path that runs.

**How it is meant to work**:
- Client connects to WebSocket signaling server
- Registers with unique peer ID (from URL path)
- Sends SDP offer and receives answer *(not implemented — see above)*
- No user intervention required for connection setup *(not implemented — see above)*

**Events**:
- `webrtc_signaling_connected` - Triggered when connected to signaling server
- Provides `peer_id` and `server_url` to LLM

### 2. Multi-Channel Support

**Purpose**: Create multiple independent data channels per connection

**Benefits**:
- Separate streams for different data types (control, file transfer, chat, etc.)
- Per-channel message queues and answering tasks prevent crosstalk
- Isolated message queuing per channel

**Usage**:
```json
{
  "type": "create_channel",
  "channel_label": "file-transfer"
}
```

**Events**:
- `webrtc_channel_opened` - Triggered for each channel that opens
- `webrtc_message_received` - Includes `channel_label` to identify source

### 3. Binary Data Support

**Purpose**: Send true binary data (not just UTF-8 text)

**Encoding**: Hex encoding for binary payloads (like TCP client)

**Usage**:
```json
// Send text
{
  "type": "send_message",
  "message": "Hello, peer!"
}

// Send binary (hex-encoded)
{
  "type": "send_message",
  "message": "hex:48656c6c6f"  // "Hello" in hex
}

// Or use dedicated action
{
  "type": "send_binary",
  "hex_data": "48656c6c6f"
}
```

**Auto-detection**: Incoming messages are auto-detected as binary or text based on ASCII content.

## Architecture

### Core Components

1. **Peer Connection**: `RTCPeerConnection` manages the P2P connection
2. **Data Channels**: Multiple `RTCDataChannel` instances for parallel streams
3. **ICE/STUN**: Uses Google STUN server for NAT traversal
4. **Signaling**: Manual SDP exchange OR WebSocket-based automatic signaling
5. **Per-Channel Queue**: each channel queues its messages for its own answering task

### Protocol Stack

```
Application (LLM-controlled messages)
    ↓
DataChannel (SCTP)
    ↓
DTLS (encryption)
    ↓
ICE/STUN (NAT traversal)
    ↓
UDP
```

### Signaling Modes

#### Manual Mode (Original)

```
1. User opens client
2. Client generates SDP offer
3. User copies offer to peer
4. Peer generates answer
5. User pastes answer back
6. Connection established
```

#### WebSocket Mode (NEW)

```
1. User opens client with ws://server:port/peer_id
2. Client connects to signaling server
3. Client registers as peer_id
4. Client generates offer
5. Server forwards offer to target peer
6. Server forwards answer back
7. Connection established
```

## Library Choices

### webrtc-rs (v0.11)

**Rationale**: Pure Rust implementation of WebRTC stack

**Pros**:
- Complete WebRTC implementation (rewrite of Pion in Rust)
- Data channel support without media complexity
- Good API for creating/managing peer connections
- Active development

**Cons**:
- Relatively complex setup (MediaEngine, InterceptorRegistry)
- Manual SDP exchange required (unless using signaling server)
- Still in early development (v0.11)

**Alternative Considered**: `datachannel-rs` (libdatachannel C++ wrapper) - rejected due to FFI complexity

### tokio-tungstenite (v0.21)

**Rationale**: Async WebSocket client for signaling

**Pros**:
- Integrates with tokio async runtime
- Used by signaling server (consistency)
- Lightweight and efficient

**Cons**:
- Requires signaling server infrastructure

## LLM Integration

### Events

1. **`webrtc_channel_opened`** - Triggered when any data channel opens
    - Provides channel label
    - LLM can send initial message on channel
    - Supports multi-channel: each channel fires separate event

2. **`webrtc_message_received`** - Triggered when message arrives on any channel
    - Provides message text or hex-encoded binary
    - Provides channel label
    - Provides binary flag (true if hex-encoded)
    - LLM decides response action per channel

3. **`webrtc_signaling_connected`** (NEW) - Triggered when connected to signaling server
    - Provides peer_id and server_url
    - LLM can initiate offer to target peer

**`webrtc_connected` is gone, and was never deprecated — it was never emitted.** It was
declared inline in `get_event_types()` and raised by nothing, so an operator could route on a
pattern that could not fire. It escaped `event_emit_sites_test` because that scan looks for
`&CONST` emit sites and this declaration was an inline `EventType::new`, invisible to it.
`get_event_types()` now returns the same `LazyLock` statics the client actually emits, so the
two cannot drift again. Use `webrtc_channel_opened`.

### Actions

#### User-Triggered (Async)

- **`send_message`** - Send text or binary message (use "hex:" prefix)
  - Optional `channel` parameter for multi-channel
  - Example: `{"type": "send_message", "message": "hex:48656c6c6f"}`

- **`send_binary`** - Send hex-encoded binary data
  - Optional `channel` parameter
  - Example: `{"type": "send_binary", "hex_data": "48656c6c6f"}`

- **`apply_answer`** - Apply remote SDP answer (manual mode only)
  - Required: `answer_json` (SDP JSON from peer)

- **`create_channel`** (NEW) - Create additional data channel
  - Required: `channel_label`
  - Example: `{"type": "create_channel", "channel_label": "file-transfer"}`

- **`send_offer`** (NEW) - Send offer to peer via signaling server
  - Required: `target_peer` (peer ID on signaling server)
  - Example: `{"type": "send_offer", "target_peer": "bob"}`

- **`disconnect`** - Close all channels and peer connection

#### Event-Triggered (Sync)

- **`send_message`** - Send reply message on same channel
  - Optional `channel` parameter (defaults to receiving channel)
  - Supports "hex:" prefix for binary

- **`disconnect`** - Close connection
- **`wait_for_more`** - Don't respond yet

### Connection Flow (WebSocket Mode)

```
1. User opens WebRTC client with ws://server:port/peer_id
2. Client connects to signaling server
3. Client registers as peer_id
4. webrtc_signaling_connected event fires
5. Client generates SDP offer automatically
6. (LLM can trigger send_offer to target peer)
7. Server forwards offer to target peer
8. Target peer sends answer back
9. Connection established
10. Data channels open
11. webrtc_channel_opened events fire
12. Messages exchanged via send_message actions
13. webrtc_message_received events fire
```

### Connection Flow (Manual Mode)

```
1. User opens WebRTC client (manual mode)
2. Client creates offer and generates SDP
3. SDP offer displayed to user
4. User pastes SDP answer from peer
5. LLM applies answer via apply_answer action
6. Connection established
7. Data channel opens
8. webrtc_channel_opened event fires
9. Messages exchanged via send_message actions
10. webrtc_message_received events fire
```

## State Management

### Per-channel queue and batching (on by default)

webrtc-rs awaits a channel's `on_message` handler before it reads the channel again. The
handler used to call the model itself, so what the peer sent during a call stayed unread in
SCTP and its Idle/Processing "queue while processing" arm could never run. The handler now
only queues: each message (at most 1 MiB; a larger one closes the channel) goes into a bounded
per-channel queue of `MAX_BATCH_EVENTS`, and when it is full the handler waits, so webrtc-rs
stops reading and SCTP flow control holds the peer back. Each channel has an answering task
(`spawn_client_task`, holding the channel and client data weakly so it ends with the channel
or the client's shutdown token). With batching on it takes everything waiting and answers it in
one `call_llm_for_client_batch` call, one event per message; with it off, one per call.
`tests/client/webrtc/batching_test.rs` drives it with a webrtc-rs peer answering the client's
manual offer. Binary/text events use the data channel's message type flag.

### Stored Data (protocol_data)

- `sdp_offer`: Generated SDP offer (JSON)
- Peer ownership stays in Rust Arcs; no raw pointer is stored in JSON.

**Safety note, and it is a real caveat rather than a reassurance.** This claimed "Pointers are
cleaned up when client is removed". They are not, in the normal path: the only thing that
reclaims the `Arc` is the 5-second polling task, and that task is registered with
`register_client_task`, so `AppState::remove_client` **aborts it in the same write guard that
removes the client**. It therefore never observes the removal. The `Arc` is never reclaimed,
`peer_connection.close()` is never called, and webrtc-rs's internal ICE/DTLS tasks — which
nothing in NetGet owns — keep running. Known and not yet fixed; the fix is to close the peer
connection from the removal path rather than from a poller racing it.

`signaling_mode` is **not** stored as a startup parameter any more. It was declared as one and
read by nothing — the mode is derived solely from `remote_addr`'s scheme — so passing
`signaling_mode: "websocket"` with a non-`ws://` address silently gave manual mode. The
declaration is gone; the field on the client record still reflects the derived mode.

### Client Data (In-Memory)

- `memory`: LLM memory (shared across all channels)
- `channels`: HashMap of channel_label → ChannelData
  - `channel`: Arc<RTCDataChannel>

## Signaling Strategy

### Manual SDP Exchange (Original)

**Pros**:
- No infrastructure required
- Simple for two-peer connections
- Privacy (no signaling server)

**Cons**:
- User must manually exchange SDP
- Inconvenient for frequent connections
- Hard to automate

### WebSocket Signaling (NEW)

**Pros**:
- Automatic SDP exchange
- No manual copy-paste
- Scalable (many peers)
- LLM can control signaling

**Cons**:
- Requires signaling server
- Adds network dependency
- Privacy considerations (signaling server sees SDP)

**Compatibility**: untested against anything. The frame schema matches `webrtc_signaling`'s
on paper, but no test connects the two and the offer is never sent in any case (see the banner
at the top of this file). It is definitely **not** compatible with the `webrtc` *server*,
which accepts only `offer` as a first frame and answers `register` with an error this client
has no arm for. This line used to read "Works with NetGet's WebRTC signaling server".

## Limitations

1. **No Media**: Audio/video not supported (data channels only)
2. **Basic Signaling**: No ICE candidate trickling (waits for full ICE gathering)
3. **No Renegotiation**: Connection parameters fixed at offer time
4. **Basic ICE**: **no ICE server by default** — host candidates only, which is what a
   loopback or LAN peer uses. Pass `ice_servers` for STUN or TURN. The default used to be
   Google's public STUN server, so merely starting a client talked to a third party; the
   *server* side was fixed for that reason and the client was left behind. (This item used to
   say "Only Google STUN, no custom TURN servers (configurable via startup params)", which
   contradicted itself inside one sentence — the parenthetical was the true half.)
7. **`send_offer` does nothing**, so WebSocket signalling cannot complete a connection. See
   the banner at the top of this file. The injected-command path returns `Rejected`, not
   `Executed` — it used to report `Executed` with a detail string saying in as many words
   that nothing was sent, and the *variant* is what callers branch on.
8. **The peer connection is leaked on removal**, not closed. See the safety note under
   "Stored Data".
5. **Channel Lifecycle**: Channels created after connection established may have timing issues
6. **No Channel Negotiation**: Target peer must be ready to receive channels

## Security Considerations

- **DTLS Encryption**: All data encrypted by default (WebRTC requirement)
- **Peer Authentication**: No built-in peer verification (trust SDP source)
- **ICE Candidate Privacy**: Local IP addresses exposed in SDP
- **STUN Server**: Trusts Google STUN (could add custom servers)
- **Signaling Server Trust**: WebSocket mode trusts signaling server (sees SDP)

**Recommended Mitigations**:
- Use TLS/WSS for signaling server connections
- Verify peer identity through application-level authentication
- Consider using TURN servers for privacy (hide IP addresses)
- Implement challenge-response over data channel

## Testing Strategy

See `tests/client/webrtc/AGENTS.md` for testing details.

Key challenges:
- Requires two peers (NetGet + browser or two NetGet instances)
- Manual SDP exchange for E2E tests
- WebSocket mode requires running signaling server
- Could use loopback connections for automated testing

Test scenarios:
1. Manual mode: Two NetGet clients exchange SDP manually
2. WebSocket mode: Two clients via signaling server
3. Multi-channel: Create multiple channels, send on different streams
4. Binary data: Send hex-encoded data, verify decoding
5. Mixed messages: Interleave text and binary on same channel

## Performance Considerations

- **Memory**: Per-channel state (~1 KB overhead per channel)
- **CPU**: Minimal (message forwarding is fast)
- **Channels**: Recommended limit: 10-20 concurrent channels per connection
- **Bandwidth**: Depends on application (SCTP adds ~20 bytes overhead per message)
- **Latency**: P2P connection (typically < 50ms after connection established)

## Future Enhancements

1. **ICE Candidate Trickling**: Send candidates as discovered (faster connection)
2. **Connection Renegotiation**: Add/remove channels after connection established
3. **TURN Support**: Custom TURN servers for relay (privacy/NAT)
4. **Channel Lifecycle**: Better handling of dynamic channel creation
5. **Connection Stats**: Expose RTCStats for monitoring (bandwidth, latency, packet loss)
6. **Ordered/Unordered Channels**: Support unordered delivery for low-latency use cases
7. **Signaling Server Discovery**: Automatic discovery of signaling servers
8. **Multi-Peer Mesh**: Connect to multiple peers simultaneously

## Example Usage

### Manual Mode (Original)

```bash
# Open WebRTC client (generates SDP offer)
> open_client webrtc manual "Send hello message"

# SDP offer displayed - user exchanges with peer
# After peer responds, apply answer
> (LLM generates apply_answer action with pasted SDP)

# Connection established, send message
> (LLM sends message via send_message action)

# Receive messages
> (webrtc_message_received events processed by LLM)
```

### WebSocket Mode (NEW)

```bash
# Open WebRTC client with signaling server
> open_client webrtc ws://localhost:8080/alice "Connect to bob"

# Signaling connection established
> [EVENT] webrtc_signaling_connected (peer_id: "alice", server_url: "ws://localhost:8080/")

# Send offer to peer "bob"
> (LLM generates send_offer action with target_peer: "bob")

# Connection established automatically
> [EVENT] webrtc_channel_opened (channel_label: "netget")

# Send text message
> (LLM generates send_message action)

# Send binary data
> (LLM generates send_binary action with hex_data: "48656c6c6f")
```

### Multi-Channel (NEW)

```bash
# Create additional channel
> (LLM generates create_channel action with channel_label: "file-transfer")

# Channel opens
> [EVENT] webrtc_channel_opened (channel_label: "file-transfer")

# Send on specific channel
> (LLM generates send_message with channel: "file-transfer")

# Receive on specific channel
> [EVENT] webrtc_message_received (channel_label: "file-transfer", message: "...", is_binary: false)
```

## Integration with Signaling Server

The WebRTC client integrates with NetGet's WebRTC Signaling Server:

**Server Protocol**: `webrtc_signaling` (see `src/server/webrtc_signaling/AGENTS.md`)

**Message Format**: JSON messages over WebSocket
- Register: `{"type": "register", "peer_id": "alice"}`
- Offer: `{"type": "offer", "from": "alice", "to": "bob", "sdp": {...}}`
- Answer: `{"type": "answer", "from": "bob", "to": "alice", "sdp": {...}}`
- ICE Candidate: `{"type": "ice_candidate", "from": "alice", "to": "bob", "candidate": {...}}`

**Workflow**:
1. Client connects to signaling server WebSocket
2. Client sends registration message
3. Client creates SDP offer
4. Client sends offer message to server (to be forwarded to peer)
5. Server forwards offer to target peer
6. Target peer sends answer back
7. Server forwards answer to client
8. Connection established

## References

- [webrtc-rs Documentation](https://docs.rs/webrtc/latest/webrtc/)
- [webrtc-rs GitHub](https://github.com/webrtc-rs/webrtc)
- [WebRTC Data Channels MDN](https://developer.mozilla.org/en-US/docs/Web/API/WebRTC_API/Using_data_channels)
- [WebRTC Signaling MDN](https://developer.mozilla.org/en-US/docs/Web/API/WebRTC_API/Signaling_and_video_calling)
- [Perfect Negotiation Pattern](https://developer.mozilla.org/en-US/docs/Web/API/WebRTC_API/Perfect_negotiation)
- [tokio-tungstenite Documentation](https://docs.rs/tokio-tungstenite/)

---

# Command channel and ICE configuration (August 2026)

## `ice_servers` is read now

It was declared in `get_startup_parameters()` and never read — `connect_with_llm_actions` did not
take startup parameters at all — so the Google STUN server was hardcoded into every client. It is
now the default and nothing more; an explicitly empty array (`"ice_servers": []`) means host
candidates only, which is what a purely local peer wants and what
`tests/client/webrtc/command_channel_test.rs` uses so that nothing leaves the machine.

## Command channel — the dashboard's `[ send ]`

Adopted, archetype **(a)**: the `RTCPeerConnection` and every `RTCDataChannel` already live
behind `Arc`s that outlive `connect()`, so the command loop holds clones and nothing needed
restructuring. The channel is registered **before** signaling runs, because the WebSocket mode
makes an LLM call on `webrtc_signaling_connected` that a manual `*` rule can park.

| Outcome | When |
|---|---|
| `Sent { bytes_sent }` | `send_message` / `send_binary` on an open channel. Real: `RTCDataChannel::send` returns the number of bytes it wrote to the SCTP stream |
| `Executed { detail }` | `create_channel` (created on the live peer connection, opens when the connection is established), `apply_answer` (`set_remote_description` succeeded), `wait_for_more` |
| `Rejected { error }` | unknown action, an unknown channel label, or an `answer_json` that is not an SDP answer |
| `Disconnected` | `disconnect`; every channel and the peer connection are closed |
| `Err(..)` | the channel exists but is not open, or `create_data_channel` / `set_remote_description` failed. The error names the channel and its `ready_state` — a send on a channel nobody answered must fail loudly, not report a fake `Sent` |

`execute_action` folds `send_message`/`send_binary` into a bare `SendData` and drops the `channel`
parameter it declares, so the command loop reads `channel` from the action itself and defaults to
`netget`, the channel `connect()` always creates.

**Gap: `send_offer` is not executed.** It answers
`Rejected { error: "send_offer cannot be injected: …" }`; it never reports success. The signaling WebSocket sink is
owned by `websocket_signaling`'s own task and is unreachable from the command loop, and in manual
mode there is no signaling connection at all. It has never worked from the LLM path either — the
`Custom` result was dropped on the floor there — so this is a pre-existing gap now made visible
rather than a new one.

**What the test does not cover.** A data channel carrying bytes needs a real second peer and
there is none in-tree, so `Sent { bytes_sent }` is exercised by no test; what is pinned is that
the failure to send is reported rather than faked.

## Lifecycle follow-up (October 2026)

`PeerConnectionGuard` starts async peer closure when the last owning task is dropped, including
AppState task abortion. Its cancellation token interrupts pending channel callbacks before close.
Callbacks retain weak references to their channel/client data, breaking self-cycles. Signaling
setup failures close the connection and remove the command handle. The CPU regression creates
an ICE-server-free peer, aborts its owner, and waits for the real Closed state. Real NAT traversal,
remote signaling servers, and browser transport execution remain environment-specific validation.
