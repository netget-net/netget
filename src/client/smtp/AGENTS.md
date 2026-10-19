# SMTP Client Implementation

## Overview

The SMTP client allows LLM-controlled email sending via SMTP servers. It uses the `lettre` library for robust SMTP
protocol support including STARTTLS and authentication.

## Library Choice

**Primary: `lettre` v0.11**

- Mature, well-maintained SMTP client library
- Full STARTTLS support for secure email transmission
- Multiple authentication methods (PLAIN, LOGIN)
- Tokio-based async support
- Excellent error handling and RFC compliance

## Architecture

### Connection Model

SMTP is a **request-based protocol** (like HTTP), not a persistent stream (like Redis/TCP):

- Connection is established when client is opened
- No persistent read loop (emails are sent on-demand)
- Each `send_email` action creates a new SMTP transaction
- Connection info (server address, credentials) stored in client state

### State Management

Client state tracked in `ClientInstance.protocol_data` — only values this client derives for
itself, never anything the caller passed:

- `smtp_server`: Server hostname
- `smtp_port`: Port from `remote_addr`
- `remote_addr`: Full server address with port

The declared startup parameters (`username`, `password`, `use_tls`) do **not** live there.
They arrive on `ConnectContext::startup_params` and are held for the session in
`SmtpSettings`. `cli/client_startup.rs` leaves `protocol_data` as `Value::Null`, so anything
read from it before the client writes it is unconditionally absent.

### LLM Integration

#### Events

1. **`smtp_connected`** - Triggered when client connects to SMTP server
    - Parameters: `smtp_server` (hostname)
    - LLM decides: What email to send, authentication strategy

2. **`smtp_email_sent`** - Triggered after successful email transmission
    - Parameters: `to` (recipients), `subject`, `success` (boolean)
    - LLM decides: Send follow-up emails, update memory

#### Actions

**Async Actions** (user-triggered):

- `send_email` - Send an email via SMTP
    - Parameters: `from`, `to` (array), `subject`, `body`, `username` (optional), `password` (optional), `use_tls` (
      optional)
    - Returns: `ClientActionResult::Custom` with email data

- `disconnect` - Close SMTP client
    - Returns: `ClientActionResult::Disconnect`

**Sync Actions** (LLM response to events):

- `send_email` - Same as async action, triggered by LLM in response to events

### Email Sending Flow

```
1. User opens SMTP client → smtp_connected event
2. LLM receives event, decides to send email
3. LLM returns send_email action with email details
4. `apply_action` runs it through `SmtpClientProtocol::execute_action`
5. `deliver` builds the message and lettre sends it
6. `follow_up` raises smtp_email_sent
7. LLM processes result, may send more emails
```

## SMTP Features

### Authentication

Supports optional SMTP authentication:

- **Username/Password**: as startup parameters for the whole session, or on an individual
  `send_email` action. The action wins where it says something; the startup parameters are
  the session default. A model told nothing about credentials can therefore still deliver.
- **Credentials**: Converted to lettre `Credentials` object
- **No auth**: Leave credentials empty for open relays (testing)

### TLS/STARTTLS

- **Enabled by default**: `use_tls: true`, and that default now lives in exactly one place
  (`deliver`). `execute_action` deliberately leaves `use_tls` absent when the action omits it,
  so "the model said nothing" stays distinguishable from "the model asked for TLS" — without
  that distinction the declared `use_tls` startup parameter could never apply to any message.
- **STARTTLS**: Upgrades connection to TLS after initial handshake
- **TLS Parameters**: Configurable via lettre's `TlsParameters`
- **Certificate validation**: Enabled by default (can be disabled for testing)

### Email Composition

- **Simple emails**: Plain text body only (no HTML in initial implementation)
- **Multiple recipients**: `to` field accepts array of addresses
- **Required fields**: `from`, `to`, `subject`, `body`
- **Future**: Attachments, HTML bodies, CC/BCC (not yet implemented)

## Implementation Details

### Startup

```rust
SmtpClient::connect_with_llm_actions(
    remote_addr,      // e.g., "smtp.example.com:587"
    llm_client,
    app_state,
    status_tx,
    client_id,
    startup_params,   // username / password / use_tls, read here and nowhere else
)
```

- Parses server address
- Stores connection info in client state
- Calls LLM with `smtp_connected` event
- Spawns monitoring task for client lifecycle

### Sending Email

There is no free-standing send entry point. A `send_email` action — whether it came from the
model's answer to `smtp_connected`, from a later event, or from a command injected at the
dashboard — takes one path:

```rust
SmtpClient::apply_action(client_id, &app_state, action, &settings)
//   └─ SmtpClientProtocol::execute_action(action)
//        -> ClientActionResult::Custom { name: "smtp_send_email", data }
//   └─ SmtpClient::deliver(client_id, &app_state, &data, &settings) -> host:port
```

`deliver` reads `smtp_server` / `smtp_port` back out of client state, builds the message with
lettre's `Message` builder, configures the transport with TLS and auth, and sends on a blocking
task because lettre is sync. `apply_action` makes no LLM call of its own — `follow_up` raises
`smtp_email_sent` afterwards, so the command loop can answer an injected send before the model
reacts to it.

### Action Dispatch Integration

The action is dispatched inside this client's own connection loop, which is how every client
protocol works: `Client::execute_action` is reachable from the loop that owns the socket, and
`AppState::send_to_client` injects an action into it (`src/state/client_handles.rs`). There is
no separate central client action dispatcher, and none is needed.

## Limitations

1. **Plain text only**: No HTML email support yet
2. **No attachments**: File attachments not implemented
3. **No CC/BCC**: Only direct `to` recipients
4. **Blocking send**: Email sending uses `spawn_blocking` (lettre is sync)
5. **No SMTP pipelining**: One email at a time
6. **Action dispatch**: Async user actions need framework integration

## Example Prompts

```
"Connect to smtp.gmail.com:587 and send a test email to user@example.com"

"Send an email from sender@example.com to recipient@example.com with subject 'Test' and body 'Hello from NetGet SMTP client'"

"Connect to localhost:25 and send an email without authentication"
```

## Testing Strategy

See `tests/client/smtp/AGENTS.md` for:

- E2E test approach
- Local SMTP server setup (mailhog, fakesmtp)
- LLM call budget
- Expected runtime

## Future Enhancements

1. **HTML emails**: Add HTML body support
2. **Attachments**: File attachment support via lettre
3. **CC/BCC**: Additional recipient fields
4. **Custom headers**: X-* headers for tracking
5. **Template support**: Email template rendering
6. **Async lettre**: When lettre adds full async support
7. **DKIM signatures**: Email authentication
8. **Bounce handling**: Parse SMTP error responses

### Dashboard injection (`[ send ]`)

`connect_with_llm_actions` registers a command channel **and starts draining it** before the
`smtp_connected` LLM call. Registering the handle alone would not be enough here: that call runs
inline in `connect`, so a manual `*` rule parks creation itself and nothing would answer an
injected command until it returned.

The old 5-second `sleep` liveness loop was replaced by `idle_and_command_loop`, a `select!` over
`mpsc::Receiver::recv` and an `Interval::tick` — both cancellation-safe, so no second task is
needed.

**`send_email` was previously unreachable from every path.** The connected-event handler
discarded the model's actions (`actions: _`) and `SmtpClient::send_email` had no callers at all,
so the model could ask for a message and nothing was ever sent. Both paths now go through
`apply_action` → `deliver`, and `follow_up` raises `smtp_email_sent`.

**The port in `remote_addr` was also discarded.** `smtp_server` kept only the hostname and
`SmtpTransport::relay` then used its own default, so a client pointed at `host:2525` silently
talked to a different port. The port is stored as `smtp_port` and applied with `.port(...)`.

**Outcome semantics.** `lettre` opens its own connection per message and reports no byte count,
so a delivered message is `Executed { detail: "send_email '<subject>': accepted by <host:port>
for N recipient(s)" }` — never `Sent`. A message the server refused is an `Err`; an unknown or
malformed action is `Rejected`. An injected `disconnect` replies `Disconnected` and drops the
handle.

Test: `tests/client/smtp/command_channel_test.rs` (zero LLM calls). Its peer is a ~40-line
listener rather than a NetGet SMTP server on purpose: that server raises one event id
(`smtp_command`) for the banner *and* every command, so a `static` handler is forced to answer
`CONNECTION_ESTABLISHED`, `EHLO`, `MAIL`, `RCPT`, `DATA` and `.` with identical bytes and no
session can complete. Driving it would take a `script` handler.

### Startup parameters were declared and read by nothing

Fixed September 2026. `username`, `password` and `use_tls` are declared in
`get_startup_parameters()` and `deliver` read all three off the **action**, so what the caller
passed when opening the client was discarded entirely. It never failed loudly:

- `use_tls` — the executor's own default was `true`, so a client opened against a plaintext
  relay with `use_tls: false` demanded STARTTLS on every message and every delivery was
  refused. Only the model naming `use_tls: false` on each individual `send_email` worked.
- `username` / `password` — credentials supplied once at connect were never sent, so a server
  requiring AUTH refused every message unless the model repeated them on every action, which
  a model that was never told them cannot do.

Same shape as the `git` and `xmpp` clients, and no whole-tree ratchet can see it:
`startup_param_drift_test` asks whether a declared parameter is read *somewhere* textually,
and all three were — from the action rather than from the startup parameters.

Pinned by `tests/client/smtp/startup_params_test.rs`, whose peer offers no STARTTLS and
refuses `MAIL FROM` until a correct `AUTH PLAIN`, so a delivery that succeeds is proof on the
wire that both parameters arrived.

## Batching

Declared `BatchingMode::Unsupported`: nothing can arrive while the model is answering.
`lettre` opens a connection per message and the only event after connect is the delivery
result of the client's own `send_email`.
