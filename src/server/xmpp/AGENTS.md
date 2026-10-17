# XMPP Protocol Implementation

## Overview

XMPP (Extensible Messaging and Presence Protocol) server implementing core XMPP protocol for instant messaging and
presence. The LLM controls XMPP stream initialization, authentication, and all stanza responses (message, presence, iq).

**Status**: Experimental (Application Protocol)
**RFC**: RFC 6120 (XMPP Core), RFC 6121 (XMPP IM), RFC 6122 (XMPP Address Format)
**Port**: 5222 (default client-to-server), 5269 (server-to-server, not implemented)

## Library Choices

- **No XMPP library** - Manual protocol implementation
    - XMPP is XML-based streaming protocol
    - Stanzas parsed from XML stream
    - Responses constructed as XML strings
    - Direct LLM control over all protocol elements
- **tokio** - Async runtime and I/O
    - `TcpListener` for accepting connections
    - `AsyncReadExt`/`AsyncWriteExt` for byte I/O
    - Persistent TCP connections with XML streaming

**Rationale**: Manual implementation gives LLM full control over XMPP stream and stanzas. XMPP is more complex than IRC
due to XML structure, but the streaming nature allows for incremental parsing. The LLM can handle XML construction and
interpretation directly.

## Architecture Decisions

### 1. Action-Based LLM Control

The LLM receives raw XML data and responds with structured actions:

- `send_stream_header` - Send XML stream header to initiate connection
- `send_stream_features` - Send available features (SASL mechanisms, etc.)
- `send_message` - Send message stanza
- `send_presence` - Send presence stanza (availability, status)
- `send_iq_result` - Send IQ result stanza
- `send_iq_error` - Send IQ error stanza
- `send_auth_success` - Send SASL authentication success
- `send_auth_failure` - Send SASL authentication failure
- `send_raw_xml` - Send custom XML (for unsupported stanzas)
- `wait_for_more` - Buffer more data before responding
- `close_stream` - Close XML stream and connection

### 2. XML Stream Processing

XMPP message flow:

1. Accept TCP connection
2. Read bytes into buffer
3. Parse XML from buffer (LLM interprets XML structure)
4. Send XML data to LLM as `xmpp_data_received` event
5. LLM returns actions (e.g., `send_stream_header`, `send_message`)
6. Execute actions (send XML responses)
7. Loop for next data

### 3. Stream Lifecycle

XMPP uses persistent XML streams:

- **Stream init**: Client sends `<stream:stream>`, server responds with own header
- **Features**: Server sends `<stream:features>` with SASL mechanisms
- **Authentication**: Client sends `<auth>`, server validates and responds
- **Stream restart**: After auth, stream restarts with new features
- **Stanza exchange**: Messages, presence, IQ stanzas exchanged
- **Stream close**: Either side sends `</stream:stream>`

### 4. No Server-Side Session State

`XmppProtocol` holds only the configured `domain`. An `XmppClientState` map (JID,
authenticated, stream id, resource) with setters used to live here, but nothing ever called
them - no JID was recorded and `authenticated` was never set - so it was removed. Session state
belongs to the model, which sees the whole stream.

The `domain` startup parameter is the server's domain and supplies the default `from` on
`send_stream_header`. It was declared but never read for a while, so a server opened with
`domain: "example.com"` still announced `localhost`.

### 4a. XML Escaping

Everything the model puts into a structured stanza - message bodies, status text, JIDs, stream
ids, SASL mechanism names - is XML-escaped. Interpolating it raw meant a body containing `&`,
`<` or an apostrophe produced a malformed stanza, and a real client's parser drops the entire
stream on the first well-formedness error rather than skipping one stanza.

`xml_escape` also **drops** every character XML 1.0's `Char` production (§2.2) excludes: the C0
controls other than tab, LF and CR, and `U+FFFE`/`U+FFFF`. No escape exists for them — `&#1;`
is forbidden too — so one in a model-composed body would end a strict client's stream (rxml
under tokio-xmpp, expat under most others). Tab, LF and CR are kept. Pinned by
`tests/server/xmpp/xml_escape_test.rs`, which also parses a `send_message` stanza carrying such
characters with `xmpp-parsers`. `send_raw_xml` and `send_iq_result`'s `payload` are not passed
through it, so they can still carry such a character.

`send_raw_xml`'s `xml` and `send_iq_result`'s `payload` are deliberately **not** escaped: they
exist so the model can emit markup. `send_iq_error`'s `condition` and `send_auth_failure`'s
`reason` become element *names*, so they are validated against `[A-Za-z0-9-]+` and rejected
rather than escaped.

### 5. Dual Logging

- **DEBUG**: Summary with byte count ("XMPP received 256 bytes on connection conn-123")
- **TRACE**: Full XML data ("XMPP data (XML): <message from='alice@localhost' to='bob@localhost'>...")
- Both go to netget.log and TUI Status panel

### 6. Connection Management

Each XMPP client gets:

- Unique `ConnectionId`
- Entry in `ServerInstance.connections` with `ProtocolConnectionInfo::empty()` (XMPP stores no
  protocol-specific connection info)
- Tracked bytes sent/received, packets sent/received
- State: Active until client closes or LLM sends `close_stream`

### Dashboard injection (`[ message this peer ]` / `[ disconnect this peer ]`)

Every connection registers a peer handle (`server::peer_support`) right after it is tracked and
*before* the first `xmpp_data_received` LLM call, so a manual `*` rule parking that call still
leaves the operator able to reach the connection. `AppState::send_to_peer` runs the action
through the same executor as the LLM path. Every XMPP wire verb returns `ActionResult::Output`
(or `Multiple`/`CloseConnection` for `close_stream`) — there is **no `Custom` gap** — so the
generic peer task covers the whole vocabulary. `[ disconnect this peer ]` injects
`close_connection`, which is **not** in the model's vocabulary; `execute_action` carries an
explicit `close_connection => ActionResult::CloseConnection` arm purely so that injected
disconnect half-closes the socket instead of answering "Unknown action" (the model's own
close verb remains `close_stream`, which also emits `</stream:stream>`). The handle is removed
on every exit path (EOF, buffer overflow, `close_stream`, read error) through the single cleanup
after the read loop, and again by the peer task itself on an injected close (idempotent). `update_connection_stats` is called on every read and every
write, so the dashboard's `↓ ↑` counters and `last_activity` are live. Test:
`tests/server/xmpp/peer_inject_test.rs` (zero LLM calls).

## LLM Integration

### Event Type

**`xmpp_data_received`** - Triggered when XMPP client sends XML data

Event parameters:

- `xml_data` (string) - The raw XML data received (may be partial stream)

### Available Actions

#### `send_stream_header`

Send XMPP stream header to initiate XML stream.

Parameters:

- `from` (optional) - Server domain name (defaults to the server's `domain` startup parameter,
  itself defaulting to "localhost")
- `stream_id` (optional) - Unique stream identifier

Example:

```json
{
  "type": "send_stream_header",
  "from": "localhost",
  "stream_id": "stream-123"
}
```

Sends:
`<?xml version='1.0'?><stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' from='localhost' id='stream-123' version='1.0'>`

#### `send_stream_features`

Send stream features (authentication mechanisms, etc.).

Parameters:

- `mechanisms` (optional array) - SASL mechanisms (default: ["PLAIN"])

Example:

```json
{
  "type": "send_stream_features",
  "mechanisms": ["PLAIN", "SCRAM-SHA-1"]
}
```

Sends:
`<stream:features><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><mechanism>PLAIN</mechanism><mechanism>SCRAM-SHA-1</mechanism></mechanisms></stream:features>`

#### `send_message`

Send XMPP message stanza.

Parameters:

- `from` (required) - Sender JID
- `to` (required) - Recipient JID
- `body` (required) - Message body text
- `message_type` (optional) - Message type: chat, groupchat, headline, normal (default: "chat")

Example:

```json
{
  "type": "send_message",
  "from": "bot@localhost",
  "to": "alice@localhost",
  "body": "Hello, Alice!"
}
```

Sends: `<message from='bot@localhost' to='alice@localhost' type='chat'><body>Hello, Alice!</body></message>`

#### `send_presence`

Send XMPP presence stanza.

Parameters:

- `from` (optional) - Sender JID
- `presence_type` (optional) - Presence type: available, unavailable, subscribe, etc.
- `show` (optional) - Availability: away, chat, dnd, xa
- `status` (optional) - Status message

Example:

```json
{
  "type": "send_presence",
  "from": "alice@localhost/desktop",
  "show": "chat",
  "status": "Ready to chat"
}
```

Sends: `<presence from='alice@localhost/desktop'><show>chat</show><status>Ready to chat</status></presence>`

#### `send_iq_result`

Send IQ result stanza.

Parameters:

- `id` (required) - IQ ID (must match request)
- `to` (optional) - Recipient JID
- `payload` (optional) - XML payload

Example:

```json
{
  "type": "send_iq_result",
  "id": "roster-1",
  "to": "alice@localhost",
  "payload": "<query xmlns='jabber:iq:roster'/>"
}
```

Sends: `<iq type='result' id='roster-1' to='alice@localhost'><query xmlns='jabber:iq:roster'/></iq>`

#### `send_auth_success`

Send SASL authentication success.

Example:

```json
{
  "type": "send_auth_success"
}
```

Sends: `<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>`

See `actions.rs` for complete action list including `send_iq_error`, `send_auth_failure`, `send_raw_xml`, etc.

## Connection Management

### Connection Lifecycle

1. **Accept**: TCP listener accepts connection
2. **Register**: Connection added to `ServerInstance` with `ProtocolConnectionInfo::empty()`
3. **Split**: Stream split into ReadHalf and WriteHalf
4. **Track**: WriteHalf stored in `Arc<Mutex<WriteHalf>>` for sending
5. **Read Loop**: Continuous byte reading and XML buffering until disconnect
6. **Close**: Connection removed when client closes or LLM sends `close_stream`

### State Management

- **No per-connection state machine.** XMPP does not implement Idle/Processing/Accumulating and
  has no `queued_data`; the read loop awaits each LLM call before reading again.
- **Batching is `Unsupported`, because there is nothing separate to batch.** An event is the
  connection's whole unconsumed byte buffer, not a stanza, so whatever arrives during a call is
  read in one go afterwards and delivered in the next single event already — and with batching
  off there would be no way to hand it over one stanza at a time either. Real batching needs
  stanza framing (a top-level-element splitter under the stream root) first.
- **Read buffer**: bytes accumulate in one `Vec<u8>` per connection. It is cleared once the
  model has acted on it, but **kept** when the model answers `wait_for_more` (that is the whole
  point of the action - clearing it unconditionally threw away the partial stanza the model
  asked to hold). An LLM failure ends the connection (see below), so the buffer dies with it.
- **Bounded**: `MAX_XMPP_BUFFER_BYTES` (256 KiB) caps it. Without a ceiling a peer that never
  completes a stanza grows it without limit and every subsequent event re-sends the whole thing
  to the model. Exceeding it logs an error and closes the connection.
- Connection stays in ServerInstance until closed

### Backend failure: the peer gets a stream error, never a diagnosis

An LLM error used to be logged and swallowed, so a client that had just sent its stream header
waited for a header that was never coming until its own timeout fired. RFC 6120 §4.9 defines the
frame for exactly this, so `stream_error_frame` (`mod.rs`) now writes a fatal `<stream:error/>`
and the connection closes.

The two `crate::utils::WireFailure` categories map onto **distinct** defined stream conditions so
a client can back off rather than record a permanent fault:

| classification | stream condition | meaning |
|---|---|---|
| `Overloaded` | `<resource-constraint/>` (§4.9.3.17) | transient, retry later |
| `Unavailable` | `<internal-server-error/>` (§4.9.3.10) | not retryable |

The `<text/>` is `WireFailure::text()`, a `&'static str`. **Nothing derived from the error
reaches the socket** - no backend URL, no model name, no `anyhow` chain; the full error goes to
`Log::warn` (netget.log + status stream) only. `tests/wire_failure_test.rs` fails the build if
that changes.

If the failure lands on the very first event the model has never answered, so nothing has opened
the stream. §4.9.1.1 requires an opening tag before the error, so one is synthesised from the
`domain` startup parameter; otherwise a real client's parser rejects the error as a second root
element.

Three outcomes stay distinguishable **in the log**, the `radius` separation:

- `decision=model_close` - the model sent `close_stream`
- `decision=model_no_actions` - the model answered with nothing (silence on the wire is the
  model's choice, and the stream stays open)
- `decision=fail_closed_llm_error class=overloaded|unavailable` - netget could not ask the model

Test: `tests/server/xmpp/llm_failure_test.rs` (zero LLM calls - the backend is a dead port).

## Known Limitations

### 1. No XML Streaming Parser

- Current implementation buffers all XML data and sends to LLM
- No incremental stanza parsing
- Large XML streams may cause buffering issues
- LLM responsible for interpreting partial/complete stanzas

**Future Enhancement**: Add minidom or quick-xml for proper XML stream parsing

### 2. No Roster Management

- Server doesn't track contact lists (rosters)
- No roster storage
- IQ roster queries return empty or LLM-generated results

**Workaround**: LLM can maintain pseudo-roster in conversation context

### 3. No Presence Distribution

- Server doesn't broadcast presence to contacts
- No presence tracking across connections
- Each connection isolated

**Workaround**: LLM can simulate presence distribution in conversation

### 4. Simplified Authentication

- Only basic SASL framework
- No actual credential verification
- LLM decides authentication success/failure
- No SCRAM-SHA-1 or other advanced mechanisms

### 5. No Server-to-Server (S2S)

- Single-server only
- No federation support
- No server-to-server protocol (port 5269)
- All JIDs must be on local domain

### 6. No Multi-User Chat (MUC)

- No groupchat support (XEP-0045)
- No room management
- Message type="groupchat" treated as regular message

### 7. No TLS/STARTTLS

- Plain TCP only
- No encryption support
- No STARTTLS negotiation

**Workaround**: Use reverse proxy (e.g., nginx) for TLS termination

### 8. No Advanced XEPs

- No file transfer (XEP-0096, XEP-0234)
- No avatars (XEP-0084)
- No PubSub (XEP-0060)
- No message carbons (XEP-0280)
- Core stanzas only (message, presence, iq)

## Example Prompts

### Basic XMPP Server

```
listen on port 5222 via xmpp
When clients connect, send stream header and features (PLAIN auth)
Accept all authentication attempts
Echo back any messages received
```

### Presence Server

```
listen on port 5222 via xmpp
Support presence stanzas (available, unavailable, away, etc.)
When clients send presence, acknowledge with presence response
Track user status in conversation
```

### Simple Messaging Bot

```
listen on port 5222 via xmpp
Act as messaging bot named "NetBot@localhost"
Respond to messages with helpful information
Support commands: help, time, joke
```

### Echo Server

```
listen on port 5222 via xmpp domain=localhost
Echo all received messages back to sender
Prefix echoed messages with "Echo: "
```

## Performance Characteristics

### Latency

- **Per Stanza (with scripting)**: Sub-millisecond
- **Per Stanza (without scripting)**: 2-5 seconds (LLM call)
- XML buffering: <1 microsecond
- Stanza formatting: <1 microsecond

### Throughput

- **With Scripting**: Thousands of stanzas per second
- **Without Scripting**: ~0.2-0.5 stanzas per second (LLM-limited)
- Concurrent connections: Unlimited (bounded by system resources)
- Each connection processes independently

### Scripting Compatibility

Good scripting candidate:

- XML-based protocol (parseable with libraries)
- Repetitive stanza patterns
- State can be maintained in script
- High message volume typical for chat

## XMPP Protocol References

### Core Stanzas

- **message** - Instant messages
- **presence** - Availability/status
- **iq** - Info/Query (request-response)

### Common IQ Namespaces

- **jabber:iq:roster** - Contact list management
- **jabber:iq:auth** - Legacy authentication (pre-SASL)
- **vcard-temp** - User profile (XEP-0054)
- **disco#info** - Service discovery (XEP-0030)

### SASL Mechanisms

- **PLAIN** - Username/password in base64
- **SCRAM-SHA-1** - Challenge-response authentication
- **ANONYMOUS** - Anonymous access
- **EXTERNAL** - Certificate-based authentication

### Stream Format

```xml
C: <stream:stream xmlns='jabber:client'
     xmlns:stream='http://etherx.jabber.org/streams'
     to='localhost' version='1.0'>

S: <?xml version='1.0'?>
   <stream:stream xmlns='jabber:client'
     xmlns:stream='http://etherx.jabber.org/streams'
     from='localhost' id='stream-id-123' version='1.0'>

S: <stream:features>
     <mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>
       <mechanism>PLAIN</mechanism>
     </mechanisms>
   </stream:features>

C: <auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN'>
     [base64-encoded credentials]
   </auth>

S: <success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>

[Stream restart after successful auth]

C: <iq type='get' id='bind-1'>
     <bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'>
       <resource>desktop</resource>
     </bind>
   </iq>

S: <iq type='result' id='bind-1'>
     <bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'>
       <jid>alice@localhost/desktop</jid>
     </bind>
   </iq>

C: <presence/>

C: <message to='bob@localhost' type='chat'>
     <body>Hello!</body>
   </message>

S: <message from='bot@localhost' to='alice@localhost' type='chat'>
     <body>Welcome!</body>
   </message>

C: </stream:stream>
S: </stream:stream>
```

## Connection bounds

A peer that connects and says nothing holds a socket, a task and an `AppState` row. Until
September 2026 it held them forever: this server had no read deadline and accepted without
limit.

| bound | default | overridable with |
|---|---|---|
| first bytes from a connected peer | 30s | `first_byte_timeout_secs` |
| further bytes on an open stream | 900s | `idle_timeout_secs` |

The deadline wraps `read_half.read(&mut temp_buf)` and nothing else, so the model round-trip
that answers a stanza — and a `manual` rule parking it for a human — sits outside it by
construction. The switch between the two bounds is `stream_opened`, which is set the moment
this server writes its first byte; on a server whose opening stream tag *is* the model's answer
to the peer's first event, that is the honest definition of an established stream.

**Why 30 for the first byte.** RFC 6120 §4.2 puts the opening `<stream:stream>` on the
initiating entity, so a peer that has sent nothing has begun no stream — and this server cannot
answer until it has one, because its first event is the peer's own bytes. ejabberd's
`negotiation_timeout` defaults to 30 seconds for the same phase. NetGet's own XMPP client is
built on `tokio-xmpp`, which sends that header from inside its connect path, so it is the
"speaks inside `connect()`" case and never the connected-and-silent one that made `tcp`,
`redis` and `whois` settle on 300. (In practice it is not a peer here at all: `XmppClient::new`
dials the JID's domain via SRV, not the `127.0.0.1:<ephemeral>` the dashboard pre-fills.)

**Why 900 for idle.** A silent XMPP session is the normal case, not a broken one: a connected
person who is not typing sends nothing, and that is what the protocol is for. Neither ejabberd
nor Prosody closes an authenticated session for idleness at all, so there is no upstream number
to copy — this bound exists so the socket is not held forever, not to enforce a session policy.
Fifteen minutes is above every keepalive interval real clients use (RFC 6120 §4.6.1 whitespace
keepalives and XEP-0199 pings run one to five minutes), so a client that intends to stay
connected refreshes it several times over.

**Connection cap**: `accept_bounded::DEFAULT_MAX_CONNECTIONS` (256), which turns the 256 KiB
`MAX_XMPP_BUFFER_BYTES` into a 64 MiB total — and with a fifteen-minute idle bound, a cap is
the only thing standing between this server and `900s × accept rate` simultaneous silent
streams. A peer over it gets a `<policy-violation/>` stream error (RFC 6120 §4.9.3.14) wrapped
in the synthesised opening and closing stream tags §4.9.1.1 requires, then the socket closes.

Tests: `tests/server/xmpp/connection_bounds_test.rs`, driven from a raw socket with a static
routing rule and zero LLM calls.

## References

- [RFC 6120: XMPP Core](https://datatracker.ietf.org/doc/html/rfc6120)
- [RFC 6121: XMPP Instant Messaging and Presence](https://datatracker.ietf.org/doc/html/rfc6121)
- [RFC 6122: XMPP Address Format](https://datatracker.ietf.org/doc/html/rfc6122)
- [XMPP Standards Foundation (XSF)](https://xmpp.org/)
- [XMPP Extensions (XEPs)](https://xmpp.org/extensions/)
