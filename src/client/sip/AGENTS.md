# SIP Client Protocol Implementation

## Overview

SIP (Session Initiation Protocol) client implementing RFC 3261 for VoIP signaling. The client can register with SIP
servers, initiate calls (INVITE), terminate sessions (BYE), query capabilities (OPTIONS), and cancel pending requests (
CANCEL).

**Compliance**: RFC 3261 (SIP - Session Initiation Protocol)

**Protocol Purpose**: SIP is a text-based signaling protocol for creating, modifying, and terminating multimedia
sessions. This client implementation enables NetGet to act as a SIP User Agent for testing VoIP servers, conducting
security research, or simulating SIP endpoints.

## Library Choices

**Manual Implementation** - Complete SIP protocol handling implemented from scratch

- **Why**: Matches the server implementation approach for consistency
- SIP is a text-based HTTP-like protocol, straightforward to parse and generate
- Manual implementation provides full control over request generation for LLM
- No dependency on external SIP libraries (consistent with Cargo.toml comment)

**Alternative Considered - rsip v0.3.0**:

- General-purpose SIP message parser and builder
- **Pros**: Handles SIP message parsing, URI parsing, header handling
- **Cons**: Would add dependency; manual parsing is sufficient for client needs
- **Decision**: Use manual implementation for simplicity and no-dependency approach

**Text Protocol Handling**:

- Line-based parsing (similar to HTTP)
- Headers: `Name: Value\r\n` format
- Body: Optional SDP (Session Description Protocol) after blank line
- UTF-8 text encoding

## Architecture Decisions

### UDP-Based Protocol

**Primary Transport: UDP**:

- Connectionless: Each SIP transaction is independent
- Connect to SIP server port 5060 (standard SIP UDP port)
- Single UDP socket per client
- Fast request-response pattern

**Connection Tracking**:

- Each SIP dialog (REGISTER, INVITE→ACK→BYE cycle) tracked via Call-ID
- Dialog ID = Call-ID + From tag + To tag
- Maintains CSeq counter for request sequencing
- From tag generated once per client, To tag extracted from responses

### LLM Integration

The SIP client uses the standard client LLM integration pattern:

1. **Connection Event**: When connected, LLM receives `sip_client_connected` event
2. **LLM Decides Initial Action**: Typically REGISTER or OPTIONS to establish presence
3. **Response Processing**: For each SIP response, LLM receives `sip_client_response_received` event
4. **LLM Decides Next Action**: Based on response status (200 OK, 403 Forbidden, etc.), LLM chooses next step

### SIP Request Generation

The client builds SIP requests by hand. They are well-formed and a real server accepts them, but "RFC 3261 compliant" would overstate it — there is no transaction layer, no retransmission and no digest auth (see Limitations):

**Request Structure**:

```
Method URI SIP/2.0
Via: SIP/2.0/UDP client-ip:port;rport;branch=z9hG4bK-netget-<random>
From: <sip:user@domain>;tag=<from-tag>
To: <sip:target@domain>[;tag=<to-tag>]
Call-ID: <random>@netget-client
CSeq: <sequence> <METHOD>
Contact: <sip:user@client-ip:port>
[Headers specific to method]
Content-Length: <length>

[Body if present]
```

**Critical Headers**:

- **Via**: Routing information with branch parameter (RFC 3261 magic cookie `z9hG4bK`).
  **This is the socket's own address**, read after `connect()` so it is the outbound interface
  the kernel picked rather than the `0.0.0.0` it was bound to. It used to be the literal
  `127.0.0.1:5060`, which is where an RFC 3261 server sends its response — so every reply from a
  real server went to port 5060 on the server's own loopback and this client never saw it. It
  worked only against NetGet's own SIP server, which answers the datagram's source address
  instead. `;rport` (RFC 3581) additionally asks the server to reply to the source address and
  port it observed, which is what makes this work from behind NAT. `Contact` defaults from the
  same address, for the same reason.
- **From**: Caller identity with unique tag (generated once per dialog)
- **To**: Callee identity (tag added after first response)
- **Call-ID**: Unique dialog identifier (generated per client session)
- **CSeq**: Command sequence number + method name (increments per request)
- **Contact**: Client's reachable address (for server callbacks)

**Method-Specific Headers**:

- **REGISTER**: Expires (registration lifetime)
- **INVITE**: Contact, Content-Type: application/sdp (with SDP body)
- **BYE**: None (minimal headers)
- **OPTIONS**: None (server responds with Allow header)
- **CANCEL**: Must match Via, From, To, Call-ID, CSeq of original INVITE

### Response Parsing

The client parses SIP responses (RFC 3261 Section 7):

**Status Line**: `SIP/2.0 <status-code> <reason-phrase>`

**Common Status Codes**:

- **100 Trying**: Request received, processing
- **180 Ringing**: Call is ringing
- **200 OK**: Successful request
- **401 Unauthorized**: Authentication required
- **403 Forbidden**: Request denied
- **486 Busy Here**: Callee busy
- **603 Decline**: Callee declined call

**Header Extraction**:

- Copy headers from request (Via, From, To, Call-ID, CSeq)
- Extract To tag from successful responses (used in subsequent requests)
- Parse SDP body from 200 OK responses to INVITE

### State Management

**Per-Client State** (`ClientData`):

```rust
struct ClientData {
    memory: String,                // LLM conversation memory
    call_id: Option<String>,       // Dialog Call-ID (generated once)
    from_tag: Option<String>,      // From tag (generated once)
    to_tag: Option<String>,        // To tag (from server response)
    cseq: u32,                     // Command sequence number
    local_addr: SocketAddr,        // Via and Contact
}
```

**No state machine, and no batching (declared `Unsupported`).** The client used to carry the
server's `Idle`/`Processing`/`Accumulating` machine and a `queued_data` buffer cleared after
one parse. The read loop is sequential and calls the model inline, so the queue could never
fill — and had it filled, every queued datagram but the first would have been lost. It is
gone: a response that arrives during a model call waits in the socket, one datagram each, and
is read in turn. Batching is unsupported because every event is a final response to a request
this client sent (server-initiated requests are not parsed), so nothing is pushed to pile up.
`tests/client/sip/queued_response_test.rs` pins that responses arriving during a call each
reach the model, in order.

**Dialog Lifecycle**:

1. Client connects → Generate Call-ID and From tag
2. LLM decides to REGISTER → Send REGISTER with CSeq=1
3. Receive 200 OK → Extract To tag, LLM decides next action
4. LLM decides to INVITE → Send INVITE with CSeq=2, To tag from REGISTER
5. Receive 180 Ringing → Skipped by client (provisional response), wait for final
6. Receive 200 OK → Client automatically sends ACK (RFC 3261 compliance), **before** the
   model is asked, carrying the INVITE's sequence number from the response's CSeq. It used to
   go after the model's actions, numbered from the dialog counter, so an answer of BYE went out
   first and the ACK took the BYE's CSeq (`queued_response_test.rs` covers it). **If no local
   dialog exists** — an unsolicited `200`/`CSeq: n INVITE` from a peer this client never
   INVITEd — there is nothing to acknowledge, so it is logged and nothing is sent. Both fields
   used to be read with `.unwrap()`, so that datagram panicked the read loop; the panic was
   swallowed by `tokio::spawn` and the client stayed "Connected" and permanently deaf.
   `tests/client/sip/hostile_response_test.rs` covers this and the `extract_uri` panic below
7. LLM decides to BYE → Send BYE with CSeq=3
8. Receive 200 OK → Call terminated

## LLM Control Points

The LLM controls the SIP client via actions:

### Async Actions (User-Triggered)

1. **sip_register**: Register with SIP server
    - Parameters: from, to, request_uri, contact, expires
    - Use case: Establish client presence with registrar
    - Example: Register alice@example.com for 3600 seconds

2. **sip_invite**: Initiate call
    - Parameters: from, to, request_uri, contact, sdp
    - Use case: Start voice/video session
    - Example: Call bob@example.com with SDP media offer

3. **sip_ack**: Acknowledge INVITE 200 OK (usually automatic)
    - Parameters: from, to, request_uri
    - Use case: Complete INVITE 3-way handshake (auto-sent by client)
    - Note: LLM can explicitly send ACK, but client sends it automatically
    - Example: ACK bob@example.com after receiving 200 OK to INVITE

4. **sip_bye**: Terminate active session
    - Parameters: from, to, request_uri
    - Use case: End call
    - Example: Hang up ongoing call

5. **sip_options**: Query capabilities
    - Parameters: from, to, request_uri
    - Use case: Check server/user availability
    - Example: Ping bob@example.com to check presence

6. **sip_cancel**: Cancel pending request
    - Parameters: from, to, request_uri
    - Use case: Cancel INVITE before final response
    - Example: Cancel call while ringing

### Sync Actions (Response-Based)

1. **disconnect**: Close UDP socket
2. **wait_for_more**: Keep connection open, wait for next response

### Events

**sip_client_connected**:

- Triggered: After UDP socket established
- Context: remote_addr, local_addr
- LLM decides: Typically sends REGISTER or OPTIONS

**sip_client_response_received**:

- Triggered: SIP final response (2xx-6xx) received from server
- Note: Provisional responses (1xx like 100 Trying, 180 Ringing) are logged but do NOT trigger LLM calls
- Context:
    - status_code (200, 403, 486, etc.)
    - reason_phrase ("OK", "Forbidden", "Busy Here")
    - method (REGISTER, INVITE, BYE, etc. from CSeq)
    - call_id, from, to headers
    - body (SDP if present)
- LLM decides:
    - 200 OK to REGISTER → Send INVITE or wait
    - 200 OK to INVITE → Client automatically sends ACK (LLM decides next action after)
    - 486 Busy Here → End dialog or retry
    - 403 Forbidden → Authentication or policy issue
- Automatic Behavior:
    - Client sends ACK immediately after 200 OK to INVITE (RFC 3261 requirement)
    - Responses that arrive during a model call wait in the socket and are read in turn

## SDP (Session Description Protocol)

For INVITE requests, the client must provide SDP describing media capabilities:

**Example SDP** (generated by LLM):

```
v=0
o=netget 2890844526 2890844526 IN IP4 192.0.2.1
s=NetGet Call
c=IN IP4 192.0.2.1
t=0 0
m=audio 49170 RTP/AVP 0
a=rtpmap:0 PCMU/8000
```

**SDP Fields**:

- `v=0`: SDP version
- `o=`: Originator (username, session ID, version, network type, IP)
- `s=`: Session name
- `c=`: Connection data (IP address for media)
- `t=`: Timing (0 0 = no specific start/end time)
- `m=`: Media description (audio, port, protocol, format list)
- `a=`: Attributes (codec mapping)

**LLM Generation**: LLM generates simplified SDP with plausible values. No actual RTP media streams are created (SIP is
signaling only, media would require RTP implementation).

### Dashboard injection (`[ send ]`)

`connect_with_llm_actions` registers a command channel
(`client::command_support::register_command_channel`) **before** the `sip_client_connected`
LLM call, which a manual routing rule can park for minutes. Commands are drained by a
separate `command_loop` task (registered with `register_client_task`), not by a `select!` arm
in the read loop: `recv` is cancellation-safe so an arm would be sound, but the read loop can
sit inside a multi-minute LLM call and an injected request must not queue behind it. Both
tasks write through the same `Arc<UdpSocket>` (`send` takes `&self`).

Every SIP verb yields `ClientActionResult::Custom`, so the generic
`handle_stream_client_command` cannot serve this client. `command_loop` routes the action
through `execute_sip_action` - the one function the connected-event path, the read loop and
the injected command all use, so the request encoding and the Call-ID / From-tag / CSeq
bookkeeping exist exactly once - and reports:

| Outcome | When |
|---|---|
| `Sent { bytes_sent }` | the datagram left the socket; the count is `UdpSocket::send`'s return value |
| `Rejected { error }` | `execute_action` refused it (unknown verb, missing field) |
| `Executed { detail }` | `wait_for_more`, or a `Custom` result that builds no SIP request |
| `Disconnected` | an injected `disconnect` |

SIP runs over UDP, so `disconnect` closes nothing on the wire: the command loop replies
`Disconnected`, drops the handle, marks the client disconnected and stops. The recv loop's
socket is released when the client is removed (`stop_client` aborts both registered tasks).
The handle is also removed when the read loop exits. Test:
`tests/client/sip/command_channel_test.rs` (zero LLM calls; asserts the datagram really
arrives at a peer socket and that its length matches the reported `bytes_sent`).

## Limitations

### Current Implementation

1. **UDP Only**
    - TCP/TLS transports not implemented
    - Max UDP packet size: 65535 bytes

2. **Manual SIP Parsing**
    - Not using rsip or other SIP crates
    - May have edge cases in complex headers
    - No SIP URI parser (uses simple string matching)

3. **No Authentication**
    - RFC 2617 digest authentication not implemented
    - Cannot handle 401 Unauthorized challenges
    - No nonce, realm, or response calculation

4. **Simplified SDP**
    - No actual RTP media streams
    - LLM generates plausible SDP strings
    - No codec negotiation or media handling

5. **No Retransmission**
    - No transaction layer (retransmissions, timeouts)
    - Relies on single request-response
    - Network loss causes silent failure

6. **Limited Dialog State**
    - Basic Call-ID, tags, CSeq tracking
    - No route set (Record-Route) handling
    - No early dialog vs. confirmed dialog distinction
    - Responses are processed one at a time, in arrival order

**Header parsing is hostile-input-safe as of this pass.** `extract_uri` searched the whole
header value for `<` and, independently, for `>`, then sliced between them — so a display name
containing a `>` before the URI (`"ev>il" <sip:victim@host>`) produced a slice whose start was
past its end, which panics immediately on a `&str`. It now searches for `>` *after* the `<`.
Reached from the automatic-ACK path, i.e. from any peer that can send a `200`/`INVITE`.

### Protocol Compliance Gaps

**RFC 3261 Features Implemented**:

- ACK request handling (automatic after 200 OK to INVITE) ✓
- Provisional response handling (1xx responses skipped) ✓
- Responses arriving during a model call read in turn from the socket ✓
- Basic dialog state tracking (Call-ID, tags, CSeq) ✓

**RFC 3261 Features Not Implemented**:

- Transaction layer (retransmissions, timeouts, T1/T2 timers)
- Digest authentication (401 challenges)
- TCP/TLS transports
- SIP over WebSocket (WebRTC)
- SUBSCRIBE/NOTIFY (presence)
- REFER (call transfer)
- UPDATE (session modification)
- Route set handling (proxy scenarios)

**Impact**: Suitable for basic SIP testing, security research, and simple call scenarios. Not suitable for production
SIP client use or complex call flows.

## Use Cases

### SIP Server Testing

**Test Registration**:

```
Connect to SIP server at 192.168.1.100:5060.
REGISTER as alice@example.com.
If 200 OK received, send OPTIONS to bob@example.com.
Log all responses.
```

**Test Call Flow**:

```
Connect to SIP server at 192.168.1.100:5060.
REGISTER as alice@example.com with expires 3600.
After successful registration, INVITE bob@example.com.
Include SDP with audio codec PCMU/8000.
Wait for 180 Ringing and 200 OK.
Log all responses and SDP bodies.
```

### VoIP Security Research

**Scan SIP Server**:

```
Connect to target SIP server.
Send OPTIONS to various user IDs (alice, bob, admin, etc.).
Log which users return 200 OK vs 404 Not Found.
Attempt REGISTER for discovered users.
```

**Test Unauthorized Call Attempts**:

```
Connect to SIP server without authentication.
Attempt INVITE to premium number.
Log whether server allows call (security issue).
```

### Presence Checking

**Check User Availability**:

```
Connect to SIP server.
Send OPTIONS to user@domain.
If 200 OK, user is available.
If 480 Temporarily Unavailable, user is offline.
```

## Performance Considerations

**UDP Overhead**: Minimal latency, single packet per request/response (for small messages).

**Text Parsing**: ~0.5ms per SIP message parse/build on modern hardware.

**LLM Latency**: 500ms-5s per response. Acceptable for SIP signaling (not real-time media).

**Concurrent Clients**: Each client uses one UDP socket. Hundreds of clients possible per NetGet instance.

**Memory Usage**: ~1KB per active client (state tracking).

## Example Prompts

### Basic Registration

```
Open a SIP client to 192.168.1.100:5060.
Register as alice@example.com with contact sip:alice@192.0.2.1:5060.
Use expires 3600.
Log the response.
```

### Initiate Call

```
Open a SIP client to sipserver.example.com:5060.
Register as alice@example.com.
After successful registration, initiate call to bob@example.com.
Use SDP offering PCMU audio codec on port 49170.
Wait for response and log status.
```

### Capability Query

```
Open a SIP client to 192.168.1.100:5060.
Send OPTIONS to bob@example.com to check availability.
Log the Allow header from response.
```

### Call Cancellation

```
Open a SIP client to 192.168.1.100:5060.
INVITE bob@example.com.
If 180 Ringing received, immediately CANCEL the request.
Log final status.
```

## Security Considerations

**No Authentication**: Client sends requests without credentials. Fine for testing, not for production.

**SDP Injection**: LLM-generated SDP could be crafted to test server SDP parsing vulnerabilities.

**Call Hijacking**: Without authentication, cannot guarantee identity. Suitable for testing, not secure communications.

**Eavesdropping**: UDP is unencrypted. All SIP messages visible on network. Use SIPS (TLS) for encryption (not
implemented).

## References

- RFC 3261: SIP - Session Initiation Protocol (2002)
- RFC 3665: SIP Basic Call Flow Examples
- RFC 2617: HTTP Digest Authentication (used in SIP)
- RFC 4566: SDP - Session Description Protocol
- RFC 5389: STUN (complementary protocol for NAT traversal with SIP)

## Implemented Features

**Completed** (RFC 3261 Basic Compliance):

- ✓ ACK request handling (automatic after 200 OK to INVITE)
- ✓ Provisional response handling (1xx responses skipped)
- ✓ Responses arriving during a model call read in turn from the socket
- ✓ Dialog state tracking (Call-ID, tags, CSeq)
- ✓ SIP methods: REGISTER, INVITE, ACK, BYE, OPTIONS, CANCEL

## Future Enhancements

**Priority 1** (Enhanced Reliability):

- Digest authentication (401 challenge/response)
- Retransmission handling (transaction layer)
- Error response handling improvements

**Priority 2** (Advanced Features):

- TCP transport support
- TLS (SIPS) on port 5061
- Route set tracking (Record-Route/Route headers)
- SUBSCRIBE/NOTIFY (presence)

**Priority 3** (Production-Ready):

- SIP URI parser (proper URI handling)
- Multiple concurrent dialog support
- RTP media integration (actual voice/video)
- Re-INVITE (session modification)

## Testing Strategy

**E2E Testing**: Test against NetGet SIP server (self-testing)

**Test Scenarios**:

1. **Registration Test** (< 3 LLM calls):
    - Connect client to SIP server
    - LLM sends REGISTER
    - Server responds 200 OK
    - Verify registration accepted

2. **Call Attempt Test** (< 5 LLM calls):
    - REGISTER with server
    - INVITE target user
    - Receive 180 Ringing or 200 OK
    - Verify SDP in response

3. **OPTIONS Query Test** (< 2 LLM calls):
    - Send OPTIONS to server
    - Receive 200 OK with Allow header
    - Verify supported methods listed

**LLM Call Budget**: 5-10 LLM calls total for comprehensive E2E test suite using scripting mode where possible.

**Expected Runtime**: ~10-20 seconds with scripting (setup script generation) + ~2s per test scenario.

## Migration to rsip Library

**When to Migrate**: If SIP URI parsing becomes complex or authentication support needed.

**Migration Path**:

1. Replace manual parser with `rsip::Request` and `rsip::Response`
2. Use `rsip::Uri` for proper URI handling
3. Integrate digest auth with `rsip::headers::Authorization`
4. Keep action-based API unchanged (transparent to LLM)

**Estimated Effort**: 1-2 days for rsip integration.

## Comparison to SIP Server

**Similarities**:

- Both use UDP on port 5060
- Both parse/generate SIP text messages
- Both use manual implementation (no external SIP library)
- Both have LLM-controlled actions

**Differences**:

- **Server**: Listens for requests, generates responses
- **Client**: Sends requests, parses responses
- **Server**: Stateless possible (can respond without memory)
- **Client**: Stateful required (tracks Call-ID, tags, CSeq across requests)
- **Server**: Multiple connections from different peers
- **Client**: Single connection to one server
