# DNS-over-TLS (DoT) Protocol E2E Tests

## Test Overview

`connection_bounds_test.rs` also sends a complete length prefix followed by an incomplete
DNS body. The server must close this session within the 10-second body deadline; no complete
query is emitted and no model is called.

Tests DoT server implementation with multiple DNS queries over a single TLS connection. Validates that DNS queries work
correctly when delivered over TLS transport.

## The maturity evidence is `real_client_test.rs`

`DevelopmentState::Beta` rests on **kdig** — Knot DNS 3.6, a C implementation sharing no code
with this tree. `kdig +tls` matches the reply's transaction id against the one it chose,
confirms the question section, decodes the RFC 7858 length prefix and renders the answer through
its own presentation writer. Two queries for different names with different addresses, so a
reply bound to the wrong question is visible rather than merely plausible. The test **fails**,
naming `brew install knot`, when kdig is absent.

**Until September 2026 there was no such test, and the evidence was half circular.** `rustls`
really is an independent TLS implementation, so the transport was proved — but the DNS message
in `e2e_test.rs` is hand-assembled over **hickory-proto, the codec this server encodes with**,
so that half proved only that our encoder agrees with our decoder. This is the `ssh`/russh shape
the project CLAUDE.md records: check what a test *drives*, not what the server links.

Verified by answering with a fixed transaction id instead of the client's. kdig then waits out
its timeout and the test fails — which is also the one thing `e2e_test.rs` could not have
caught before it started checking the id itself.

```bash
./cargo-isolated.sh test --no-default-features --features dot \
    --test server -- server::dot --test-threads=8
```

## Test Strategy

- **`real_client_test.rs`**: the real `kdig` binary over `+tls`, via `tokio::process` (a
  blocking `std::process::Command` would park the current-thread runtime's only worker and
  deadlock the harness draining netget's pipes)
- **`e2e_test.rs`**: tokio-rustls with a custom verifier that accepts the self-signed cert, and
  hickory-proto for message construction; three queries over one TLS session, which is what
  exercises connection reuse and the length-prefixed framing
- **`llm_failure_test.rs`**: what the peer gets when the backend fails
- **Mock-driven**: the model is `tests/helpers/mock_ollama.rs`, in-process. Nothing here
  contacts a real backend, and the "Python script" this section used to describe is not what
  any of these tests do

## LLM Call Budget

- `test_dot_server()`: 1 LLM call (server startup with script generation)
- Script handles all 3 DNS queries (0 additional LLM calls)
- **Total: 1 LLM call** (excellent efficiency)

**Why so efficient?**: Script-driven approach means LLM generates Python code once at startup, then all queries are
handled by the script without further LLM involvement. This is ideal for DoT since it has repetitive query/response
patterns.

## Scripting Usage

✅ **Scripting Enabled** - Python script handles all queries

**Script Logic**:

```python
import json,sys
d=json.load(sys.stdin)
print(json.dumps({"actions":[{"type":"dns_response","query_id":d['event']['query_id'],"answers":[{"name":"example.com","type":"A","ttl":300,"data":"93.184.216.34"}]}]}))
```

**Why Python?**: Simple script returns same A record for all queries. Demonstrates DoT's ability to handle scripted
responses over TLS.

## Client Library

- **tokio-rustls v0.24** - Async TLS client
    - `TlsConnector` - Initiates TLS connections
    - `ClientConfig` - TLS configuration
    - Custom `ServerCertVerifier` to accept self-signed certificates
- **hickory-proto v0.24** - DNS message handling
    - `Message::new()` - Constructs DNS queries
    - `Message::from_vec()` - Parses DNS responses
    - `Query::query()` - Creates DNS query records
- **rustls v0.23** - TLS protocol implementation
    - `CryptoProvider` - Cryptographic operations
    - `ring` provider for crypto primitives

**Why these libraries?**:

1. **TLS client needed**: DoT requires TLS transport (can't use plain TCP)
2. **Certificate verification**: Must disable verification for self-signed certs in tests
3. **DNS protocol**: hickory-proto ensures RFC-compliant DNS messages
4. **Async compatibility**: All libraries integrate with Tokio runtime

## Expected Runtime

- Model: qwen3-coder:30b
- Runtime: ~25-30 seconds for full test
    - Server startup + script generation: ~20s (1 LLM call)
    - TLS handshake: ~100ms
    - 3 DNS queries over TLS: ~10ms total (script-driven, very fast)
    - Validation: <1s

**Note**: DoT with scripting is extremely fast after initial startup. The expensive part is LLM generating the script,
not the actual DNS queries.

## Failure Rate

- **Very Low** (<1%) - Highly stable test
- Script-driven responses are deterministic
- Occasional failures: TLS handshake timeout if system is very slow
- No LLM variability in query responses (script handles all)

## Test Cases

### Test: DoT Server with Multiple Queries (`test_dot_server`)

**Comprehensive test covering**:

1. Server startup with Python script
2. TLS connection establishment
3. Multiple DNS queries over same connection
4. Length-prefixed message framing
5. Connection persistence

**Test Flow**:

1. Start NetGet server on dynamic port with DNS-over-TLS
2. Provide Python script that returns A record for all queries
3. Establish TLS connection to server (disable cert verification)
4. Send 3 DNS queries for different domains:
    - Query 1: example.com (A record)
    - Query 2: test.com (A record)
    - Query 3: foo.example.com (A record)
5. Verify each query receives DNS response with answer

**Why 3 queries?**:

- Tests connection reuse (TLS session persists)
- Tests length-prefixed framing for multiple messages
- Tests script handles different domains correctly
- All handled by script (0 LLM calls after startup)

**Validation**:

- Each response must have non-empty `answers()` section
- Script returns same A record for all domains (expected behavior)
- Connection remains open between queries

## Known Issues

### 1. Self-Signed Certificate Handling

Test uses custom `NoCertificateVerification` implementation to bypass certificate verification. This is **test-only**
code and should never be used in production.

```rust
struct NoCertificateVerification;
impl ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(...) -> Result<ServerCertVerified, Error> {
        Ok(ServerCertVerified::assertion())
    }
}
```

**Why needed?**: NetGet generates self-signed certificates, which would normally fail verification. Production DoT
clients should verify certificates properly.

### 2. No Certificate Validation Test

Test doesn't verify:

- Certificate validity period
- Certificate subject/hostname
- Certificate chain
- Certificate revocation

**Reason**: Focus is on DoT protocol correctness, not TLS certificate infrastructure.

### 3. No Error Response Tests

Test doesn't validate:

- NXDOMAIN responses
- Server failure responses
- Invalid query handling

**Future Enhancement**: Add test cases for error conditions with separate server instances.

### 4. Script Returns Same Response for All

Current script returns `example.com -> 93.184.216.34` for **all** queries, regardless of domain. This is intentional for
simplicity.

**Why acceptable?**: Tests DoT protocol mechanics (TLS transport, framing, multiple queries). Comprehensive DNS logic
testing is covered by standard DNS tests.

## Performance Notes

### TLS Handshake Overhead

- First query: ~100ms overhead (TLS handshake)
- Subsequent queries: ~1ms each (reuse session)
- Amortized overhead minimal with connection reuse

### Scripting Performance

Without scripting, DoT would require 1 LLM call per query:

- 1 startup + 3 queries = 4 LLM calls total
- Runtime: ~20s (startup) + 3×8s (queries) = 44s

With scripting:

- 1 startup only = 1 LLM call total
- Runtime: ~20s (startup) + 3×1ms (queries) = 20s
- **Performance improvement: ~50% faster runtime, 75% fewer LLM calls**

### Comparison to UDP DNS Tests

DoT tests are:

- **Slower startup**: TLS adds complexity to script generation
- **Faster queries**: Connection reuse amortizes overhead
- **More secure**: TLS encryption protects DNS queries

## Future Enhancements

### Test Coverage Gaps

1. **Connection close handling**: Test client-initiated connection close
2. **Large responses**: Test DNS responses near size limits
3. **Error responses**: Test NXDOMAIN, SERVFAIL, REFUSED
4. **Multiple record types**: Test AAAA, MX, TXT over TLS
5. **Concurrent connections**: Test multiple clients simultaneously
6. **Invalid queries**: Test malformed DNS messages

### Consolidation Opportunity

Could add more comprehensive script:

```python
import json,sys
d=json.load(sys.stdin)
domain = d['event']['domain']
if domain == 'example.com':
    # Return A record
elif domain == 'test.com':
    # Return different A record
else:
    # Return NXDOMAIN
```

This would test domain-specific responses while staying within 1 LLM call budget.

### Certificate Testing

Add test with proper certificate validation:

1. Generate CA certificate
2. Sign server certificate
3. Configure client to trust CA
4. Verify full certificate chain

**Benefit**: Tests production-like TLS setup.

## References

- [RFC 7858: DNS over TLS](https://datatracker.ietf.org/doc/html/rfc7858)
- [hickory-proto Documentation](https://docs.rs/hickory-proto/latest/hickory_proto/)
- [tokio-rustls Documentation](https://docs.rs/tokio-rustls/latest/tokio_rustls/)
- [rustls Documentation](https://docs.rs/rustls/latest/rustls/)

## Stable condition 2: the pcap oracle, decrypted

`real_client_test.rs` runs kdig with `SSLKEYLOGFILE` set (GnuTLS honours it) and through a
recording relay. The pcap oracle hands tshark the key log (`PcapOracle::tls_keylog`) and frames
the stream on port 853, where tshark's DNS dissector registers for TLS application data, so
both sessions are decrypted and the RFC 7858 length prefix and each DNS reply are read by the
`dns` dissector. `require_named("dns")` fails the oracle unless DNS appears in what the server
sent, so a key log that did not match is a failure rather than a pass on the record layer.

Condition 3 is `fuzz/fuzz_targets/dns_message.rs`, which fuzzes the `hickory_proto`
`Message::from_vec` this server calls on every query, with a `compression_pointer_loop` in its
corpus.
