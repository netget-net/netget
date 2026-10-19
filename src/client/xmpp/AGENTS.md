# XMPP Client Implementation

## Overview

XMPP (Extensible Messaging and Presence Protocol), formerly known as Jabber, is an open-standard instant messaging
protocol. This client implementation allows NetGet to connect to XMPP servers, send/receive messages, manage presence,
and interact with other XMPP clients.

**Complexity:** Hard (🟠)
**Status:** Experimental - Full implementation complete

## ✅ Implementation Status

**This implementation is complete and compiles successfully** with tokio-xmpp 5.0 and xmpp-parsers 0.22.

### What's Complete:

- ✅ Full tokio-xmpp 5.0 API integration
- ✅ Protocol structure and Client trait implementation
- ✅ Event type definitions (connected, message_received, presence_received)
- ✅ Action definitions (send_message, send_presence, disconnect)
- ✅ Answering task fed by a bounded queue, with batching
- ✅ LLM integration with call_llm_for_client
- ✅ Bidirectional stanza handling (send and receive)
- ✅ Proper JID and Lang type handling for xmpp-parsers 0.22
- ✅ Channel-based architecture for concurrent send/receive
- ✅ Test infrastructure
- ✅ Documentation
- ✅ Feature flags and dependencies

## Library Choice

**Primary:** `tokio-xmpp` v5.0 + `xmpp-parsers`

### Why tokio-xmpp?

- **Async/Await Support:** Full tokio integration for non-blocking I/O
- **Modern Design:** Built for async Rust with proper error handling
- **Active Development:** Well-maintained with recent updates
- **XMPP Compliance:** Supports core XMPP RFCs (RFC 6120, 6121, 6122)
- **Parser Integration:** Works with `xmpp-parsers` for stanza construction

### Alternatives Considered

- `xmpp-rs`: Less mature, fewer features
- Raw XML parsing: Too complex, reinventing the wheel

## Architecture

### Connection Flow

```
1. Read `jid` and `password` from the startup parameters (both required). A JID with no local
   part (`example.com`) is refused here: tokio-xmpp's login would unwrap it in its own task and panic

2. Resolve the target from `remote_addr` alone (`resolve_target`)

3. Create a tokio-xmpp Client on `EndableConnector`: the STARTTLS connector with
   DnsConfig::Addr(target), no SRV lookup, refusing to dial once the client has ended

4. Register the command channel, spawn the event loop

5. Wait for tokio-xmpp's `Online` event (TCP connect, STARTTLS, SASL, bind),
   bounded by `session_timeout_secs` (default `SESSION_TIMEOUT`, 30s)

6. Online: return Ok (the startup path then marks the client Connected) and call
   the LLM with "xmpp_connected" in its own task
   No Online in time, or the stream ended first: return Err (the client is Error)

7. Incoming message and presence stanzas go to an answering task over a bounded queue;
   one consumer, so model calls never overlap (see "Batching" below)
```

### Target: `remote_addr` and nothing else

`tokio_xmpp::Client::new(jid, password)` finds its server by an SRV lookup on
`_xmpp-client._tcp.<JID domain>`, falling back to the domain's A/AAAA records. A client built
that way ignores the address it was given: pointed at a local server, it would offer the
account's password to whatever the JID's domain publishes. This client never calls it.

`resolve_target` turns `remote_addr` into one socket address — `IP:port`, `[IPv6]:port`, a
bare IP, `host:port` or a bare host, a missing port meaning 5222 — and the client is built with
`Client::new_starttls(.., DnsConfig::Addr { addr }, ..)`, a plain TCP connect to exactly that
address. A host name in `remote_addr` is resolved by the system resolver as an ordinary address
lookup, because the operator named that host; the JID's domain is never resolved and no SRV
record is ever queried. The JID still names the account and the stream's `to`, which is what
it is for.

An empty `remote_addr`, or one containing `@` (an account, not an address), is refused before
anything is dialled. That error does not echo the value, which may contain a password.

### Status: `Connected` means the server accepted the session

`cli/client_startup.rs` marks every client `Connected` as soon as `connect()` returns `Ok`.
Constructing a tokio-xmpp `Client` performs no I/O, so `connect()` waits for the library's
`Online` event before returning, bounded by `session_timeout_secs` (1..600, default
`SESSION_TIMEOUT`). Until then the client is `Connecting`. If the stream ends first, an injected
`disconnect` closes it, or the timeout runs out, `connect()` returns `Err` naming the target, and
the startup path records `Error` (or, for `ClientForm::create`, removes the client). The event
loop also sets `Connected` on every `Online`, which covers tokio-xmpp's own reconnects.

tokio-xmpp 5.0 reports no connection failure through its event stream: a refused connect, a
TLS failure or a SASL rejection is logged by the library (`Failed to connect: … Retrying in …`,
which reaches `netget.log`) and retried with backoff. So every failure before `Online` surfaces
as the session timeout, not as its specific cause.

### Batching

The event loop turns each incoming message or presence stanza into an event and hands it to an
answering task over a bounded queue (`EVENT_QUEUE` = `MAX_BATCH_EVENTS`; when full the loop
stops taking stanzas from tokio-xmpp, which holds them). The answering task answers one event
per model call with batching off; with batching on (the declared default) it takes everything
waiting and answers it in one call through `call_llm_for_client_batch`, the newest the trigger.
The event loop therefore keeps polling the stream and writing the model's stanzas while a call
is in flight; it used to await each call inline, so its Idle/Processing/Accumulating queue never
filled and nothing was written until the call ended. The memory used to be read through a guard
held across the call, which deadlocked the memory write in the same `match`; it is copied out
first now.

`tests/xmpp_client_batching_test.rs` drives both against a server written in the test that
takes tokio-xmpp through STARTTLS (a self-signed `localhost` certificate trusted through
`SSL_CERT_FILE`, which `rustls-native-certs` honours), SASL PLAIN and resource binding, then
sends chat messages during a slow call, batching off as the control. It is its own test binary
because the environment variable is process-wide.

**Per-Client Data:** `memory`, the LLM conversation memory.

**Stored in AppState:**

- `jid`: the requested Jabber ID (recorded before connecting)
- `bound_jid`: the full JID the server bound, recorded on `Online`
- XMPP client writer (for sending stanzas)

### XMPP Features Implemented

**✅ Implemented:**

1. **Authentication:** SASL authentication via tokio-xmpp
2. **Messages:** Send and receive chat messages
3. **Presence:** Send presence updates (away, chat, dnd, xa), receive presence from contacts
4. **Auto-reconnect:** Handled by tokio-xmpp, always to the same `remote_addr`, and only while
   the client has not ended (see "Ending a client" below)

**⚠️ Partially Implemented:**

5. **IQ Stanzas:** Received but not yet processed (TODO)

**❌ Not Implemented:**

6. **Roster Management:** Add/remove contacts (future enhancement)
7. **Multi-User Chat (MUC):** Join/leave chatrooms (future enhancement)
8. **File Transfer:** XEP-0096/XEP-0234 (complex, low priority)
9. **Service Discovery:** XEP-0030 (future enhancement)
10. **Message Receipts:** XEP-0184 (future enhancement)

## LLM Integration

### Events Sent to LLM

1. **xmpp_connected**
    - Triggered: on the first `Online` — stream established, SASL done, resource bound
    - Parameters: `jid` (the full JID the server bound)
    - LLM Action: Send initial presence, greet contacts, etc.

2. **xmpp_message_received**
    - Triggered: When receiving a message from another user
    - Parameters: `from`, `to`, `body`, `message_type`
    - LLM Action: Respond to message, log, ignore, etc.

3. **xmpp_presence_received**
    - Triggered: When receiving presence updates from contacts
    - Parameters: `from`, `presence_type`, `show`, `status`
    - LLM Action: Acknowledge, send message, update roster, etc.

### Actions Available to LLM

**Async Actions (user-triggered):**

- `send_message(to, body)` - Send message to a JID
- `send_presence(show?, status?)` - Update presence
- `disconnect()` - Disconnect from server

**Sync Actions (event-triggered):**

- `send_message(to, body)` - Reply to received message
- `wait_for_more()` - Accumulate more events before responding

### Action Execution

Actions return `ClientActionResult::Custom` with structured data:

```rust
ClientActionResult::Custom {
    name: "send_message",
    data: json!({
        "to": "friend@example.com",
        "body": "Hello!"
    })
}
```

The client handler parses the custom action and executes the corresponding XMPP stanza send.

## Message Flow Examples

### Example 1: Auto-Reply Bot

**Instruction:** "Auto-reply to all messages with 'I'm busy'"

**Flow:**

1. User sends message → `xmpp_message_received` event
2. LLM receives: `{"from": "alice@example.com", "body": "Hi there!"}`
3. LLM action: `send_message(to: "alice@example.com", body: "I'm busy")`
4. Client sends XMPP message stanza

### Example 2: Presence Monitor

**Instruction:** "Log when contacts come online or go offline"

**Flow:**

1. Contact changes presence → `xmpp_presence_received` event
2. LLM receives: `{"from": "bob@example.com", "presence_type": "Available", "show": "chat"}`
3. LLM action: Log to memory (no stanza sent)

## Known Limitations

### 1. No Roster Management

**Issue:** Cannot add/remove contacts programmatically
**Workaround:** Manually add contacts using XMPP client before connecting NetGet
**Future:** Implement roster management actions

### 2. IQ Stanzas Not Handled

**Issue:** IQ (Info/Query) stanzas are received but ignored
**Impact:** Cannot respond to service discovery, version queries, etc.
**Future:** Parse and respond to common IQ queries

### 3. No MUC (Multi-User Chat)

**Issue:** Cannot join group chats
**Workaround:** Use direct messages only
**Future:** Implement XEP-0045 for MUC support

### 4. No TLS Configuration, STARTTLS only

**Issue:** The transport is STARTTLS with the library's default TLS settings. A server that
does not offer `<starttls/>` (NetGet's own XMPP server among them) is refused by tokio-xmpp,
and a self-signed certificate fails verification
**Future:** Expose TLS configuration in startup params

### 5. An ended client leaves one idle library task behind

tokio-xmpp's connect-and-login loop cannot be stopped from outside (see "Ending a client"), so
once the client has ended the connector parks that loop's next attempt for good rather than
failing it. The task holds no socket and no timer and dials nothing, but it lives until the
process exits, holding a copy of the JID and password. An attempt already past the transport
(in SASL or resource binding) when the client ends runs to its end; if it succeeds, tokio-xmpp
finds the client gone and closes that stream itself.

### 6. Connection drops are not visible

tokio-xmpp's `Client` stream swallows the stanza stream's `Suspended` event and does not emit
`Disconnected`, so a session that drops and is being reconnected still shows `Connected`.

## Ending a client

Every way a client ends cancels one `CancellationToken` (`ended`):

| Path | How |
|---|---|
| session timeout, or `connect()` returning or dropped without a session | a drop guard in `connect()`, disarmed on `Online` |
| injected `disconnect` (dashboard, MCP `send_to_client`) | `command_loop` → `end_session` |
| model-produced `disconnect` (any LLM answer, connected event included) | `execute_action_result` → `end_session` |
| the XMPP stream ending | the event loop's exit path |
| the client stopped (`remove_client` aborts its tasks) | a drop guard held by the event loop task |

`end_session` is the one shutdown path for both kinds of `disconnect`: it cancels the token and
drops the command handle. The event loop selects on the token, closes the stream and runs its
normal exit (status, handle removal); actions the model listed after its `disconnect` are not
executed, and queued events are not sent to the model. The loop takes queued stanzas before the
token, so a `send_message` the model put before its `disconnect` is written first; a stanza
write still waiting when the client ends gets `STREAM_CLOSE_TIMEOUT` (5s) and is then failed.

The same token stops the dialling. tokio-xmpp 5.0 runs its connect-and-login loop in a task the
library spawns itself, retrying every failure (1s backoff doubling to 30s) until a login
succeeds, and dropping the `Client` does not reach it. Every attempt starts with
`ServerConnector::connect`, so the client is built with `Client::new_with_connector` on
`EndableConnector`, which wraps `StartTlsServerConnector`: once the token is cancelled an
attempt in its transport phase is dropped with its socket, and every later attempt waits forever
without dialling. Failing them instead would make the library log an error and retry every 30s
for the life of the process. The trait's signature names `sasl::common::ChannelBinding`, which
tokio-xmpp does not re-export, hence the direct `sasl` dependency (the 0.5.2 tokio-xmpp locks).
`tests/client/xmpp/redial_test.rs` counts connections at the target after a session timeout, an
injected `disconnect` and a stop.

## Connection Parameters

`remote_addr` is the server's address, `"host:port"`. The account goes in the startup
parameters:

| Parameter | Required | |
|---|---|---|
| `jid` | yes | the account, e.g. `alice@example.com` |
| `password` | yes | SASL password |
| `session_timeout_secs` | no | 1..600, default `SESSION_TIMEOUT` (30) |

```json
{"type": "open_client", "protocol": "xmpp", "remote_addr": "127.0.0.1:5222",
 "startup_params": {"jid": "alice@localhost", "password": "secret"},
 "instruction": "Reply to all messages"}
```

## Security Considerations

1. **TLS Encryption:** STARTTLS is mandatory; a server that does not offer it is refused
2. **Password Storage:** The password is taken from the startup parameters and moved
   straight into `tokio_xmpp::Client`; it is never written to `protocol_data`. Only the
   requested `jid` and the server's `bound_jid` are recorded there. `remote_addr` cannot
   carry credentials: one containing `@` is refused without being echoed
3. **SASL Authentication:** Uses library's SASL implementation (PLAIN, SCRAM)
4. **Target:** the password is only ever offered to `remote_addr` — see "Target" above

**⚠️ Warning:** Do not hardcode passwords in prompts or instructions. Use startup params.

## Testing Approach

### Local XMPP Server

**Option 1: Prosody (Recommended)**

```bash
# Install prosody
sudo apt install prosody

# Configure /etc/prosody/prosody.cfg.lua
# Add test user
sudo prosodyctl adduser alice@localhost

# Start server
sudo systemctl start prosody
```

**Option 2: ejabberd**

```bash
# Install ejabberd
sudo apt install ejabberd

# Add test user
sudo ejabberdctl register alice localhost password
```

### E2E Test Strategy

1. **Setup:** Start local prosody server with two test users
2. **Test 1:** Connect and send presence
3. **Test 2:** Send message to another JID
4. **Test 3:** Receive message and auto-reply
5. **Cleanup:** Disconnect

**LLM Call Budget:** < 10 calls

- 1 call for connect
- 3 calls for message send/receive
- 2 calls for presence updates

## Dependencies

```toml
tokio-xmpp = "5.0"
xmpp-parsers = "0.22"
sasl = "0.5.2"   # only for `ServerConnector`'s `ChannelBinding`; see "Ending a client"
```

**Transitive Dependencies:**

- `tokio-tls` (TLS support)
- `minidom` (XML DOM)
- `hickory-resolver` (tokio-xmpp's SRV lookups; not on this client's path, which uses
  `DnsConfig::Addr`)

## Required API Updates for tokio-xmpp 5.0

The following changes are needed to make this implementation compile with tokio-xmpp 5.0:

### 1. JID Type Mismatch

**Issue:** `xmpp_parsers::Jid` != `tokio_xmpp::Jid`
**Fix:** Use `tokio_xmpp::Jid` throughout, as tokio-xmpp 5.0 re-exports xmpp_parsers types

```rust
// Instead of:
use xmpp_parsers::Jid;

// Use:
use tokio_xmpp::Jid;
```

### 2. Client Clone Not Supported

**Issue:** `XmppClient` no longer implements `Clone`
**Fix:** Restructure to use channels or split reading/writing differently

### 3. Missing Methods

**Issues:**

- `set_reconnect()` no longer exists
- `wait_for_event()` replaced with different API
- Stanza doesn't implement `Clone`

**Fix:** Review tokio-xmpp 5.0 API and use:

- Event stream API (likely `futures::Stream`)
- Remove clone calls on stanzas

### 4. Stanza Conversion

**Issue:** `message.into()` fails for type conversion
**Fix:** Use tokio-xmpp's re-exported types:

```rust
// Instead of:
use xmpp_parsers::message::Message;
let stanza: tokio_xmpp::Stanza = message.into();  // FAILS

// Use:
use tokio_xmpp::xmpp_parsers::message::Message;
let stanza = tokio_xmpp::Stanza::from(message);  // OK
```

### 5. Event Loop Pattern

The event loop needs to be rewritten to match tokio-xmpp 5.0's async stream pattern instead of `wait_for_event()`.

## Future Enhancements

1. **Roster Management:** Add/remove/list contacts
2. **MUC Support:** Join/leave chatrooms
3. **File Transfer:** Send/receive files (XEP-0096, XEP-0234)
4. **Message Receipts:** XEP-0184 for delivery confirmation
5. **Service Discovery:** XEP-0030 for capability negotiation
6. **PubSub:** XEP-0060 for publish-subscribe
7. **Message Archiving:** XEP-0136 for history retrieval
8. **OMEMO Encryption:** End-to-end encryption support

## References

- [RFC 6120](https://www.rfc-editor.org/rfc/rfc6120.html) - XMPP Core
- [RFC 6121](https://www.rfc-editor.org/rfc/rfc6121.html) - XMPP IM
- [RFC 6122](https://www.rfc-editor.org/rfc/rfc6122.html) - XMPP Address Format
- [tokio-xmpp Documentation](https://docs.rs/tokio-xmpp/)
- [xmpp-parsers Documentation](https://docs.rs/xmpp-parsers/)
- [XMPP Extensions (XEPs)](https://xmpp.org/extensions/)

## Command channel — the dashboard's `[ send ]`

Adopted. `tokio_xmpp::Client` is not clonable and is owned by the event loop task, so the command
loop reaches the stream the way every other producer here does — through the stanza channel — but
each request now carries an optional ack:

```rust
struct StanzaRequest { stanza: Stanza, ack: Option<oneshot::Sender<Result<(), String>>> }
```

`Client::send_stanza` resolves only once the stanza **has been written to the XMPP transport**,
and the event loop sends that result back on the ack. So an injected send reports what really
happened rather than "handed to a channel". The LLM path passes `ack: None` — it has no caller to
answer and must not serialise behind the loop's next turn.

Two structural changes came with it:

- The channel is registered before the session is up, and the `xmpp_connected` LLM call runs
  in **its own task** once it is, so neither a pending session nor a parked call keeps the
  event loop from draining the stanza channel.
- An injected `disconnect` goes through `end_session`, as a model-produced one does: it cancels
  the `ended` token the event loop selects on; the loop breaks, drops the handle and then closes
  the stream (bounded by `STREAM_CLOSE_TIMEOUT`, 5s, because `close()` waits on a peer that may
  never have existed). After `Online` it sets `Disconnected`; before it, it fails the pending
  `connect()` instead, which sets `Error`. The token also stops tokio-xmpp dialling again.

| Outcome | When |
|---|---|
| `Executed { detail }` | the stanza reached the transport (`<message/> to a@b (5 byte body) written to the XMPP transport`), or the action puts nothing on the wire (`wait_for_more`) |
| `Rejected { error }` | `execute_action` refused it: unknown name, missing `to`/`body` |
| `Disconnected` | `disconnect` |
| `Err(..)` | `send_stanza` failed, or the event loop ended before the stanza could be written |

**There is deliberately no `Sent { bytes_sent }`**: tokio-xmpp serialises and writes the stanza
internally and reports no byte count.

**Gap.** `tests/client/xmpp/command_channel_test.rs` pins registration, execution, the access-log
entry and disconnect against a loopback listener that never answers, but **not** a stanza
reaching a peer. `tests/xmpp_client_batching_test.rs` shows the way to an online session in a
test (a hand-written server, `SSL_CERT_FILE`), but asserts only what reaches the model; a
stanza written to a peer is still only exercised by the `#[ignore]`d e2e test against a real
prosody/ejabberd.
