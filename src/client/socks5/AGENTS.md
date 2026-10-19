# SOCKS5 Client Implementation

## Overview

The SOCKS5 client provides LLM-controlled proxy tunneling functionality, allowing connections to target servers through
a SOCKS5 proxy. The LLM can control data flow through the tunnel and interact with the ultimate destination server.

## Library Choice

**Primary Library:** `tokio-socks` (v0.5+)

**Rationale:**

- Mature, async-first SOCKS5 client implementation
- Supports SOCKS5 authentication (no auth, username/password)
- Returns a standard `TcpStream` after tunnel establishment
- Clean API: `Socks5Stream::connect()` and `Socks5Stream::connect_with_password()`
- Well-maintained with regular updates

**Alternatives Considered:**

- `async-socks5` - Less mature, fewer stars
- Manual SOCKS5 protocol implementation - Too complex, error-prone

## Architecture

### Connection Flow

```
User → NetGet SOCKS5 Client → SOCKS5 Proxy → Target Server
                ↓
              LLM decides what to send/receive
```

### Key Components

1. **Startup Parameters** (Required):
    - `target_addr`: Destination server (e.g., "example.com:80")
    - `auth_username` (optional): SOCKS5 authentication username
    - `auth_password` (optional): SOCKS5 authentication password

2. **Connection Establishment**:
    - Connect to SOCKS5 proxy server
    - Negotiate authentication method (no auth or username/password)
    - Send CONNECT command with target address
    - Extract inner `TcpStream` after handshake completes

3. **Data Flow**:
    - Once tunnel is established, data flows transparently
    - LLM sees data from/to target server (not SOCKS5 protocol internals)
    - Read on a registered reader task; see "Batching" below

### State Management

**Client Data:**

- `memory`: LLM's persistent memory across calls

## Batching (what arrives while the model is answering)

The tunnel is read on a registered task of its own (`client/inbound_queue.rs`, shared with
the other proxied byte-stream clients), feeding a bounded queue of reads (32). The answering
loop takes one read per model call with batching off, and with batching on joins everything
already waiting into one payload, as the `tcp` client does. Declared `BatchingMode::On`.
This replaced an Idle/Processing/Accumulating machine that could never leave Idle — the loop
read, called the model and wrote in sequence — and "cleared" a queue nothing filled: nothing
was lost, but what arrived during a call merged in the kernel buffer, so batching off and on
could not be told apart. A `disconnect` the model returns now ends the session (it used to
break only the loop over that answer's actions). Test: `tests/client/socks5/batching_test.rs`.

## LLM Integration

### Events

**1. `socks5_connected`** - Fired immediately after tunnel establishment

```json
{
  "proxy_addr": "127.0.0.1:1080",
  "target_addr": "example.com:80"
}
```

LLM can send initial data to target server in response.

Both events are returned from `get_event_types()` as clones of the statics `mod.rs` actually
raises. They used to be rebuilt there with `{"type": "placeholder", …}` as their example and no
parameters at all, so the copy the model is shown carried no fields and one example
`execute_action` refuses outright — the identical drift the Tor client had, fixed the identical
way. `declared_event_parameters_match_the_payload` in `tests/client/socks5/action_test.rs` holds
the declaration to what the payload carries.

**2. `socks5_data_received`** - Fired when target server sends data through tunnel

```json
{
  "data": "HTTP/1.1 200 OK\r\n\r\nhi",
  "encoding": "utf8",
  "data_length": 21
}
```

Printable ASCII arrives as itself; anything else arrives hex-encoded and `encoding` says
`"hex"`. Handing `data` and `encoding` straight back to `send_socks5_data` reproduces the
received bytes exactly. This event used to carry `data_hex` and nothing else, so the single
most likely payload on this tunnel — an HTTP response — reached the model as hex it had to
decode in its head.

### Actions

**Async Actions** (User-triggered):

- `send_socks5_data(data, encoding?)` - Send data through tunnel
- `disconnect()` - Close tunnel and proxy connection

**Sync Actions** (Response to events):

- `send_socks5_data(data, encoding?)` - Send data in response to received data
- `wait_for_more()` - Don't respond yet, wait for more data

### `data` and `encoding`, and what happened to `data_hex`

`send_socks5_data` declares two parameters: `data`, the payload, and `encoding`, which is
`"utf8"` (the default when omitted) or `"hex"`. **Nothing is sniffed.** `"48656c6c6f"` is a
perfectly good five-byte payload and a perfectly good ten-character one, and only the sender
knows which it meant — this is the `send_tcp_data` rule in the root CLAUDE.md, applied here.

The action used to declare a single `data_hex` field, so a startup example that wanted to show
`GET / HTTP/1.1\r\nHost: example.com\r\n\r\n` showed 74 hex characters instead: a request the
model could not read, could not point at another host or path, and could not check.

Backward compatibility is a decision, not an accident:

| sent | outcome |
|---|---|
| `data` (+ optional `encoding`) | the declared path |
| `data_hex` alone | still decoded as hex — an existing static handler or stored prompt keeps working |
| **both** | **refused**, naming both fields and saying that neither takes precedence |
| neither | refused, naming `data` |

`data_hex` is deliberately **not** advertised any more: re-declaring it would put hex back in
the model's vocabulary, which is the whole thing this change removed. It is executed, not
documented, and `tests/client/socks5/action_test.rs` pins every row of that table.

### Action Execution

Actions return `ClientActionResult`:

- `SendData(Vec<u8>)` - Write bytes to tunnel
- `Disconnect` - Close connection
- `WaitForMore` - No-op, continue receiving

## Protocol Details

### SOCKS5 Handshake (Transparent to LLM)

1. **Authentication Negotiation:**
   ```
   Client → Proxy: [0x05, 0x01, 0x00] (no auth) or [0x05, 0x02, 0x00, 0x02] (username/password)
   Proxy → Client: [0x05, 0x00] (method selected)
   ```

2. **Username/Password Authentication** (if used):
   ```
   Client → Proxy: [0x01, len(username), username, len(password), password]
   Proxy → Client: [0x01, 0x00] (success)
   ```

3. **CONNECT Request:**
   ```
   Client → Proxy: [0x05, 0x01, 0x00, 0x03, len(domain), domain, port_hi, port_lo]
   Proxy → Client: [0x05, 0x00, 0x00, 0x01, ...] (success)
   ```

4. **Data Transfer:**
    - After handshake, all data is forwarded transparently
    - Client reads/writes to TcpStream as if directly connected to target

The `tokio-socks` library handles all handshake details. LLM only sees application-layer data.

## Command channel (dashboard `[ send ]`)

The client registers a command channel (`command_support::register_command_channel`,
`src/client/socks5/mod.rs`), so `AppState::send_to_client` can execute an action inside the
running connection loop without the model. `tests/client/socks5/command_channel_test.rs` is
the evidence: an injected `send_socks5_data` carrying the legacy `data_hex` spelling of
`48656c6c6f` arrives as `b"Hello"` on a minimal in-test proxy — which doubles as proof that
the deprecated field really is still executed. An unknown action comes back `Rejected`, and
`disconnect` returns `Disconnected` and drops the handle. Zero LLM calls.

The three tests in `tests/client/socks5/e2e_test.rs` are all `#[ignore]`d and use a real
Ollama endpoint rather than the mock harness, so they contribute nothing to CI and call
neither `wait_for_mocks` nor `verify_mocks`.

## Error Handling

**Connection Errors:**

- Proxy unreachable → `ClientStatus::Error`
- Authentication failed → Connection error with context
- Target unreachable through proxy → SOCKS5 error code in connection failure

**Runtime Errors:**

- Read errors → Close connection, update status to `Error`
- Write errors → logged at ERROR and not fatal (the read loop continues). They used to be
  discarded entirely: the `Err` half of `if let Ok(_) = ... write_all(..)` produced no log
  line at any level, so the client reported success having put nothing on the wire.
- LLM errors → Logged, connection remains open

## Dual Logging

All events use dual logging pattern:

- `tracing::info!()` / `trace!()` → `netget.log`
- `status_tx.send()` → TUI status area

Example:

```rust
info!("SOCKS5 client {} connected through proxy", client_id);
let _ = status_tx.send(format!("[CLIENT] SOCKS5 client {} connected", client_id));
```

## Use Cases

### 1. Anonymous Web Browsing

```
User: "Connect to example.com:80 through SOCKS5 at localhost:1080 and fetch /"
LLM:
  1. Connect through proxy (socks5_connected event)
  2. Send HTTP GET request
  3. Parse response (socks5_data_received event)
```

### 2. Tor Integration

```
User: "Connect to hidden service xyz.onion:80 through Tor SOCKS at 127.0.0.1:9050"
LLM:
  1. Connect through Tor's SOCKS5 interface
  2. Interact with .onion site
```

### 3. Corporate Proxy

```
User: "Connect to internal.corp.com:443 through proxy proxy.corp.com:1080 with user:pass"
LLM:
  1. Authenticate with corporate SOCKS5 proxy
  2. Access internal resources
```

### 4. Port Forwarding Test

```
User: "Test SOCKS5 proxy by connecting to localhost:22 through it"
LLM:
  1. Connect to local SSH through proxy
  2. Verify SSH banner received
```

## Limitations

### Current Limitations:

1. **TCP Only:** Only SOCKS5 CONNECT command is supported (no BIND or UDP ASSOCIATE)
    - BIND (server-side connections) not commonly used
    - UDP ASSOCIATE requires different stream handling

2. **No Proxy Chaining:** Cannot chain multiple SOCKS5 proxies
    - Could be added by connecting first proxy → second proxy → target

3. **IPv4 Target Addresses:** `tokio-socks` primarily handles domain names and IPv4
    - IPv6 should work but not explicitly tested

4. **No SOCKS4/SOCKS4a:** Only SOCKS5 protocol version supported
    - SOCKS4 is legacy, rarely needed

### Protocol-Level Limitations:

- SOCKS5 doesn't encrypt traffic (use SSH tunnel or Tor for encryption)
- Proxy can see all traffic (application-layer encryption needed for privacy)
- Target server sees proxy's IP, not client's IP

## Future Enhancements

**Potential Additions:**

1. **UDP ASSOCIATE Support:**
    - Allow LLM to send UDP packets through SOCKS5
    - Requires separate UDP socket handling

2. **Proxy Chaining:**
    - Connect through multiple SOCKS5 proxies in sequence
    - Useful for multi-hop anonymity

3. **SOCKS4 Fallback:**
    - Auto-detect SOCKS4 proxies
    - Graceful fallback if SOCKS5 unavailable

4. **Connection Pooling:**
    - Reuse tunnels for multiple target connections
    - Requires BIND command support

5. **Proxy Auto-Detection:**
    - Parse system proxy settings
    - Auto-configure SOCKS5 from environment variables

## Security Considerations

**Authentication:**

- Username/password sent in plaintext to proxy (but not beyond)
- Use secure proxy connection (SSH tunnel) for sensitive credentials

**Data Privacy:**

- SOCKS5 proxy sees all unencrypted traffic
- Use TLS/HTTPS for end-to-end encryption with target server

**Proxy Trust:**

- Proxy server can log all connection attempts and traffic
- Malicious proxy can MITM connections
- Only use trusted SOCKS5 proxies

## Testing Strategy

See `tests/client/socks5/AGENTS.md` for E2E testing details.

**Test Server Options:**

- Dante (Linux SOCKS5 server)
- SS5 (Simple SOCKS5 server)
- SSH with dynamic forwarding (`ssh -D 1080`)
- Tor (built-in SOCKS5 on port 9050)

**Key Test Scenarios:**

1. Connect without authentication
2. Connect with username/password authentication
3. Send data through tunnel
4. Receive data from target
5. Handle proxy connection failures
6. Handle target unreachable errors

## Dependencies

```toml
tokio-socks = "0.5"
```

**Dependency Justification:**

- The pinned version is `tokio-socks = "0.5"` (`Cargo.toml`). Download counts and
  last-updated dates are not checkable from this tree and are deliberately not asserted here;
  the previous text claimed "2M+ downloads" and "last updated 2023" as current fact.
- Clean async API with tokio integration
- Handles all SOCKS5 protocol complexity
