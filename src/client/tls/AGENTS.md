# TLS Client Implementation

## Overview

The TLS client implementation provides LLM-controlled outbound TLS/SSL connections. The LLM can connect to TLS servers with full certificate validation control, send encrypted data, and interpret decrypted responses.

## Implementation Details

### Library Choice

- **tokio-rustls** - Async TLS client connector
- **rustls** - Pure Rust TLS implementation (memory-safe, no OpenSSL dependency)
- **webpki-roots** - Mozilla root CA certificates for validation
- Split stream pattern for concurrent read/write over TLS

### Architecture

```
┌────────────────────────────────────────┐
│  TlsClient::connect_with_llm_actions   │
│  - Connect TCP to remote address       │
│  - Perform TLS handshake               │
│  - Split TLS stream (read/write)       │
│  - Spawn read loop                     │
└────────────────────────────────────────┘
         │
         ├─► TLS Handshake
         │   - ClientConfig (with/without cert validation)
         │   - ServerName (SNI)
         │   - TlsConnector::connect()
         │
         ├─► Reader task → bounded queue → answering loop
         │   - Reader: read decrypted data, one queue entry per read
         │   - Answering loop: call LLM with tls_client_data_received
         │   - Execute actions (send_data, wait_for_more, disconnect)
         │
         └─► Write Half (Arc<Mutex<WriteHalf<TlsStream>>>)
             - Shared for sending encrypted data
             - Used by action execution
```

### Reading, `wait_for_more` and batching

A registered reader task reads the TLS stream and puts each read on a bounded queue
(`READ_QUEUE_CHUNKS` = `MAX_BATCH_EVENTS` reads of at most 8 KiB; past it the reader stops and
TCP holds the server back). The answering loop takes one read per model call with batching off;
with batching on (the declared default) it joins every read already waiting into one payload,
as the tcp client does, because TLS carries a byte stream whose read boundaries mean nothing.
`wait_for_more` keeps the bytes the model saw as the front of the next payload.
`tests/client/tls/batching_test.rs` drives both against a TLS listener that sends during a slow
call, batching off as the control. There used to be an Idle/Processing/Accumulating machine
here; the read loop awaited every model call inline, so nothing could arrive mid-call.

### LLM Control

**Async Actions** (user-triggered):

- `send_tls_data` - Send UTF-8 or hex-encoded encrypted data
- `disconnect` - Close TLS connection gracefully

**Sync Actions** (in response to received data):

- `send_tls_data` - Send data as response
- `wait_for_more` - Don't respond yet, accumulate data

**Events:**

- `tls_client_connected` - Fired after successful TLS handshake
  - Parameters: `remote_addr`, `server_name`
- `tls_client_data_received` - Fired when decrypted data received
  - Parameters: `data` (UTF-8 or hex), `data_length`

### Certificate Validation

**Startup Parameter: `accept_invalid_certs`**

- **false** (default) - Validate server certificates against webpki root CAs
  - Use for production HTTPS/TLS connections
  - Rejects self-signed, expired, or untrusted certificates
- **true** - Accept any certificate (custom NoVerification verifier)
  - Use for testing with NetGet TLS server (self-signed certs)
  - Use for local development/testing
  - **WARNING**: Do not use in production

**Implementation:**

```rust
let config = if accept_invalid_certs {
    ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerification))
        .with_no_client_auth()
} else {
    let root_store = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth()
};
```

### SNI (Server Name Indication)

**Startup Parameter: `server_name`**

- **Not specified** (default) - Extract hostname from `remote_addr`
  - Example: `example.com:443` → SNI: `example.com`
  - Falls back to IP if no hostname
- **Specified** - Use custom SNI hostname
  - Useful for testing or non-standard setups

### Data Encoding

**Flexible Encoding**: Data is sent as UTF-8 or hex depending on content:

- **Received**:
  - UTF-8 printable: `{"data": "Hello", "data_length": 5}`
  - Binary data: `{"data": "HEX:48656c6c6f", "data_length": 5}`

- **Sent**:
  - UTF-8: `{"type": "send_tls_data", "data": "Hello World"}`
  - Hex: `{"type": "send_tls_data", "data_hex": "48656c6c6f"}`

LLMs prefer UTF-8 for text protocols (HTTP, SMTP) and hex for binary protocols.

### Dual Logging

```rust
info!("TLS client {} connected", client_id);           // → netget.log
status_tx.send("[CLIENT] TLS client connected");      // → TUI
```

### Connection Lifecycle

1. **TCP Connect**: `TcpStream::connect(remote_addr)`
2. **TLS Handshake**: `TlsConnector::connect(server_name, tcp_stream)`
3. **Connected**: Update ClientStatus::Connected
4. **Data Flow**: Read loop processes incoming encrypted data
5. **Disconnect**: ConnectionStatus::Disconnected or Error

### Error Handling

- **Connection Failed**: Return error, client stays in Error state
- **TLS Handshake Failed**: Certificate validation failure, protocol error
- **Read Error**: Log, update status to Error, break loop
- **Write Error**: Log, connection may close
- **LLM Error**: Log, continue accepting data

## Use Cases

### 1. Generic TLS Client

Connect to any TLS server and implement custom application protocols:

```
"Connect to TLS at myserver.com:443 and send 'HELLO\\r\\n'"
```

### 2. HTTPS Client

Send HTTP requests over TLS (alternative to HTTP client):

```
"Connect to TLS at example.com:443 and send an HTTP GET request:
GET / HTTP/1.1
Host: example.com
Connection: close"
```

### 3. Testing TLS Server

Connect to NetGet TLS server with self-signed certificates:

```
"Connect to TLS at localhost:8443 (accept invalid certs) and echo data"
```

### 4. Custom Encrypted Protocols

Implement SMTP+STARTTLS, IMAP+STARTTLS, or custom protocols:

```
"Connect to TLS at mail.example.com:465 and send SMTP commands"
```

## Limitations

- **No Client Certificates** - Only server authentication (mTLS could be added)
- **No Session Resumption** - Each connection is fresh
- **No Reconnection** - Must manually reconnect via action
- **No Buffering Control** - Uses default 8KB buffer
- **No TLS Version Control** - Uses rustls defaults (TLS 1.2, 1.3)

## Differences from TCP Client

| Aspect | TCP Client | TLS Client |
|--------|-----------|------------|
| **Encryption** | None (plaintext) | TLS 1.2/1.3 |
| **Certificate Validation** | N/A | Optional (configurable) |
| **SNI Support** | N/A | Yes (automatic or custom) |
| **Handshake** | None | TLS handshake before data exchange |
| **Data Encoding** | Always hex | UTF-8 or hex (auto-detect) |
| **Use Cases** | Raw protocols | HTTPS, secure protocols |

## Testing Strategy

See `tests/client/tls/AGENTS.md` for E2E testing approach.

## Example Prompts

### Connect to Public HTTPS Server

```
"Connect to TLS at example.com:443 and send:
GET / HTTP/1.1
Host: example.com
Connection: close

Show me the HTTP response."
```

### Connect to NetGet TLS Server

```
"Connect to TLS at localhost:8443 (accept invalid certificates).
Send 'Hello TLS Server' and show the response."
```

### Custom Protocol

```
"Connect to TLS at secure.example.com:9000 and implement this protocol:
1. Send 'AUTH username password\\r\\n'
2. Wait for 'OK\\r\\n'
3. Send 'DATA\\r\\n'
4. Show any data received"
```
