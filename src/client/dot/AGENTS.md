# DoT (DNS over TLS) Client Implementation

## Overview

The DoT client provides LLM-controlled DNS query capabilities over TLS-encrypted connections, implementing RFC 7858. It
connects to DoT servers (typically on port 853) and allows the LLM to construct and send DNS queries while interpreting
responses.

## Library Choices

### hickory-proto (v0.26)

- **Purpose**: DNS message construction and parsing
- **Why**: Mature DNS library (formerly trust-dns) with excellent support for all DNS record types
- **Usage**: Creating DNS query messages, parsing responses, handling DNS wire format

### tokio-rustls (v0.26) + webpki-roots (v0.26)

- **Purpose**: TLS transport layer with certificate validation
- **Why**: Pure Rust TLS stack with async support, webpki-roots provides Mozilla's CA certificates
- **Usage**: Establishing TLS connections to DoT servers, verifying server certificates

## Architecture

### Connection Model

DoT uses persistent TCP connections over TLS (port 853 by default):

1. Establish TCP connection to DoT server
2. Perform TLS handshake with server name indication (SNI)
3. Send DNS queries as length-prefixed messages (2-byte big-endian length)
4. Receive DNS responses in the same format
5. Maintain connection for multiple queries

### Message Format

```
+---------------------+
| Length (2 bytes)    |  Big-endian uint16
+---------------------+
| DNS Message         |  Standard DNS wire format
| (variable length)   |
+---------------------+
```

### Connection Lifecycle

```
User → LLM → open_client(DoT, "dns.google:853", "query example.com")
           → TLS handshake
           → LLM receives dot_connected event
           → LLM sends send_dns_query action
           → Client sends query over TLS
           → Receive DNS response
           → LLM receives dot_response_received event
           → LLM analyzes response and decides next action
```

### Bidirectional Communication

Uses `tokio::io::split()` pattern:

- **Read half**: Dedicated task for reading DNS responses from TLS stream
- **Write half**: Wrapped in `Arc<Mutex<>>` for sending queries from LLM actions
- **State machine**: Prevents concurrent LLM calls (Idle → Processing → Accumulating)

### Dashboard command channel (injected actions)

The client registers a command channel (`command_support::register_command_channel`) right after
the TLS handshake and **before** the `dot_connected` LLM call, so `[ send_dns_query ]` /
`[ disconnect ]` on the dashboard work even while a manual rule parks that call. Because the read
loop does framed `read_exact` reads (not cancellation-safe), commands are drained by a separate
`command_loop` task registered with `register_client_task`. `send_dns_query` returns
`ClientActionResult::Custom`, so that task maps it through `apply_action` — the same function the
LLM path uses — and records an `injected_action` access-log entry; an injected `disconnect`
half-closes the TLS write side and the read loop's EOF path marks the client Disconnected.
`remove_client_handle` runs on every read-loop exit. No Custom-result gap remains.

`verify_tls` and `server_name` are now actually read (they were declared and ignored before):
`verify_tls: false` accepts any certificate, which is how a client reaches a NetGet DoT server's
self-signed cert. See `tests/client/dot/command_channel_test.rs`.

## LLM Integration

### Events

#### `dot_connected`

Triggered when TLS connection is established.

```json
{
  "event_type": "dot_connected",
  "remote_addr": "dns.google:853"
}
```

#### `dot_response_received`

Triggered when a DNS response is received.

```json
{
  "event_type": "dot_response_received",
  "query_id": 12345,
  "response_code": "NOERROR",
  "answers": [
    {
      "name": "example.com",
      "type": "A",
      "ttl": 3600,
      "data": "93.184.216.34"
    }
  ],
  "authorities": [],
  "additionals": []
}
```

### Actions

#### `send_dns_query` (async/sync)

Send a DNS query to the DoT server.

```json
{
  "type": "send_dns_query",
  "domain": "example.com",
  "query_type": "A",
  "recursive": true
}
```

Supported query types: A, AAAA, MX, TXT, CNAME, NS, SOA, PTR, SRV, CAA, etc.

#### `disconnect` (async)

Close the DoT connection.

```json
{
  "type": "disconnect"
}
```

#### `wait_for_more` (sync)

Wait for additional responses without sending a query.

```json
{
  "type": "wait_for_more"
}
```

## State Machine

### Connection States

- **Idle**: Ready to process new data
- **Processing**: LLM is processing current response
- **Accumulating**: Queuing responses while LLM is busy

### Data Flow

1. DNS response arrives → Check state
2. If Idle: Set to Processing, call LLM immediately
3. If Processing: Set to Accumulating, queue response
4. If Accumulating: Continue queuing responses
5. After LLM completes: Return to Idle, process queue

## Startup Parameters

### `verify_tls` (boolean, optional)

Enable/disable TLS certificate verification.

- Default: `true`
- Set to `false` for testing with self-signed certificates
- **Security**: Always use `true` in production

### `server_name` (string, optional)

Override TLS SNI hostname.

- Default: Extracted from remote address
- Useful when connecting by IP but need specific SNI
- Example: `"dns.google"` when connecting to `8.8.8.8:853`

## Example Prompts

### Basic Query

```
open_client DoT dns.google:853 "Query example.com A record and show me the IP address"
```

### Multiple Queries

```
open_client DoT 1.1.1.1:853 "Query example.com for all record types (A, AAAA, MX, TXT) and summarize the results"
```

### Recursive Resolution

```
open_client DoT dns.quad9.net:853 "Perform a recursive DNS lookup for www.example.com starting from the root servers"
```

### DNSSEC Validation

```
open_client DoT 8.8.8.8:853 "Query example.com with DNSSEC enabled and verify the signatures"
```

## Limitations

### 1. No DNSSEC Signature Verification

- DoT client can request DNSSEC records (RRSIG, DNSKEY, DS)
- However, cryptographic signature verification is not implemented
- LLM receives raw DNSSEC records but cannot validate them
- **Mitigation**: Use servers that perform DNSSEC validation (e.g., dns.google, cloudflare-dns.com)

### 2. No Connection Keepalive

- Connections may be closed by server due to inactivity
- Client does not send keepalive queries
- **Mitigation**: LLM can send periodic queries or reconnect as needed

### 3. Query ID Management

- Query IDs are randomly generated but not explicitly tracked
- Responses are processed in order, assuming server maintains query order
- **Risk**: Out-of-order responses could confuse the LLM
- **Mitigation**: Most DoT servers maintain query order over single connection

### 4. No Query Pipelining

- Client sends one query at a time
- Cannot send multiple queries before receiving responses
- **Impact**: Higher latency for multiple queries
- **Mitigation**: LLM can still send multiple queries sequentially

### 5. TLS Session Resumption

- No support for TLS session tickets or resumption
- Each connection performs full TLS handshake
- **Impact**: Slight overhead on reconnection
- **Mitigation**: Minimal impact for long-lived connections

## Security Considerations

### Certificate Validation

- Uses Mozilla's CA certificates via webpki-roots
- Validates server certificates by default
- Checks hostname against certificate SAN/CN
- **Important**: Always use `verify_tls: true` in production

### Privacy

- DNS queries are encrypted over TLS
- Server cannot see query contents in transit
- However, DoT server still sees all queries
- Consider using DoH (DNS over HTTPS) for additional privacy (HTTPS padding)

### DNS Spoofing

- TLS prevents man-in-the-middle DNS spoofing
- Server identity is verified via certificates
- Responses are authenticated

## Testing

### Local Testing

Use public DoT servers:

- Google: `dns.google:853` (8.8.8.8, 8.8.4.4)
- Cloudflare: `cloudflare-dns.com:853` (1.1.1.1, 1.0.0.1)
- Quad9: `dns.quad9.net:853` (9.9.9.9)

### E2E Testing Strategy

1. Connect to public DoT server
2. Send simple A record query
3. Verify response contains expected IP
4. Test multiple query types (A, AAAA, MX, TXT)
5. Test error handling (NXDOMAIN, SERVFAIL)

**LLM Call Budget**: < 10 calls per test suite

- 1 call: connection event
- 1 call: A record query response
- 1 call: AAAA record query response
- 1 call: MX record query response
- 1 call: Error handling (NXDOMAIN)
- Total: ~5 LLM calls

### Performance

- Connection establishment: ~100-500ms (TCP + TLS handshake)
- Query latency: ~20-100ms (network + server processing)
- Throughput: Limited by network, not client

## Debugging

### Trace Logging

Enable TRACE level to see hex-encoded DNS messages:

```bash
RUST_LOG=netget::client::dot=trace cargo run
```

### Common Issues

1. **TLS handshake failed**: Check server name, certificate validity
2. **Connection refused**: Verify port 853 is accessible
3. **No response**: Check server is DoT-enabled (not plain DNS on 53)
4. **Invalid query type**: Ensure query_type is valid DNS record type

## Future Improvements

1. **Query Pipelining**: Send multiple queries before receiving responses
2. **Connection Keepalive**: Periodic keepalive queries to prevent timeout
3. **Query ID Tracking**: Map query IDs to pending queries for validation
4. **DNSSEC Validation**: Cryptographic signature verification
5. **TLS Session Resumption**: Reduce handshake overhead on reconnection
6. **Connection Pooling**: Reuse connections for multiple clients
7. **DoH Upgrade**: Optionally use DNS-over-HTTPS for better privacy
