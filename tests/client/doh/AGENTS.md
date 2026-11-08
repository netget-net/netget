# DoH (DNS-over-HTTPS) Client E2E Test Documentation

## Test Strategy

The DoH client E2E tests verify DNS query functionality by connecting to **public DoH servers** (Google Public DNS,
Cloudflare DNS) and making real DNS queries. These are true end-to-end tests that validate:

1. **Connection Establishment**: Client can connect to DoH servers over HTTPS
2. **DNS Query Execution**: Client can make DNS queries with LLM-controlled parameters
3. **Response Parsing**: Client receives and parses DNS responses
4. **Record Type Support**: Client can query different DNS record types (A, AAAA, MX, TXT, etc.)
5. **Multiple Queries**: Client can issue multiple sequential queries
6. **LLM Integration**: LLM controls query decisions based on responses

## Test Approach

### Public DoH Servers

Unlike other protocol tests that spin up local servers, DoH tests use **real public DoH servers**:

- **Google Public DNS**: `https://dns.google/dns-query`
    - Fast, reliable, widely available
    - Supports all standard DNS record types
    - Good for testing A, AAAA, MX, TXT queries

- **Cloudflare DNS**: `https://cloudflare-dns.com/dns-query` / `https://1.1.1.1/dns-query`
    - Privacy-focused, no logging
    - Fast global network
    - Good for testing AAAA and security-focused queries

### Why Public Servers?

1. **RFC 8484 Compliance**: Public servers are production-grade, RFC-compliant DoH implementations
2. **No Setup Required**: No need to run local DoH server (which would be complex)
3. **Real-World Testing**: Tests against actual production DoH infrastructure
4. **Network Dependency**: Acceptable for E2E tests (requires internet connection)

### Test Domains

- `example.com` - IANA reserved example domain, always resolves
- `example.org` - Another IANA reserved domain
- `gmail.com` - Real domain with MX records for mail server testing
- `cloudflare.com` - Real domain with reliable DNS records

## LLM Call Budget

**Total Budget**: 4 LLM calls (very conservative)

### Breakdown by Test

1. **test_doh_client_google_dns**: 1 LLM call
    - Single client connection with query instruction
    - LLM decides DNS query parameters

2. **test_doh_client_cloudflare_dns**: 1 LLM call
    - Single client connection to Cloudflare
    - LLM issues AAAA query

3. **test_doh_client_multiple_queries**: 1 LLM call
    - Client connection with multi-query instruction
    - LLM makes sequential queries based on single instruction

4. **test_doh_client_record_types**: 1 LLM call
    - Single MX query to test different record types
    - LLM parses MX records

**Total**: 4 LLM calls

### LLM Efficiency Strategy

- **Single Connection Instruction**: Each test uses one LLM call for client startup
- **Implicit Query Execution**: DNS queries are part of initial instruction (no separate LLM calls)
- **No Server LLM Calls**: Using public servers eliminates server-side LLM overhead
- **Fast Public DNS**: Public DoH servers respond in 20-100ms, faster than LLM scripting

## Expected Runtime

### Per Test

- **Client Startup**: ~1-2 seconds (NetGet spawn + LLM call)
- **DNS Query**: ~50-200ms (network RTT to public DoH server)
- **Response Processing**: ~10-50ms (parsing DNS response)
- **Total per test**: ~2-3 seconds

### Full Suite

- **4 tests x 3 seconds**: ~12 seconds
- **With parallelization**: ~3-5 seconds (tests can run concurrently)
- **Including test framework overhead**: ~15-20 seconds

### Comparison

- **vs Server-Based Tests**: Much faster (no server startup/LLM)
- **vs TCP/HTTP Tests**: Similar (both use public endpoints)
- **vs Redis Tests**: Faster (no Docker container overhead)

## Test Coverage

### Positive Cases

- ✅ Connect to Google Public DNS
- ✅ Connect to Cloudflare DNS
- ✅ Query A records (IPv4 addresses)
- ✅ Query AAAA records (IPv6 addresses)
- ✅ Query MX records (mail servers)
- ✅ Make multiple sequential queries
- ✅ LLM-controlled query parameters

### Not Covered (Future)

- ❌ DNSSEC validation (requires complex setup)
- ❌ Custom DoH server (would need local DoH server)
- ❌ Error cases (NXDomain, ServFail) - hard to trigger reliably
- ❌ GET vs POST methods (both work, not critical to test separately)
- ❌ Response caching (requires repeated queries with timing checks)

## Known Issues & Limitations

### 1. Network Dependency

**Issue**: Tests require internet connection to public DoH servers

**Mitigation**:

- Use well-known, reliable DoH servers (Google, Cloudflare)
- Graceful failure if network unavailable
- CI environments typically have internet access

**Impact**: Medium (acceptable for E2E tests)

### 2. DNS Propagation

**Issue**: DNS records can change over time

**Mitigation**:

- Use stable IANA reserved domains (example.com, example.org)
- Use well-known production domains (gmail.com, cloudflare.com)
- Don't assert specific IP addresses (just verify query succeeded)

**Impact**: Low (test domains are very stable)

### 3. Rate Limiting

**Issue**: Public DoH servers may rate-limit queries

**Mitigation**:

- Only 4 tests, minimal query volume
- Tests use different domains to spread load
- Google and Cloudflare have generous rate limits

**Impact**: Very Low (unlikely to hit limits)

### 4. Response Variability

**Issue**: DNS responses may vary (load balancing, geo-location)

**Mitigation**:

- Don't assert exact IP addresses
- Verify response structure, not specific values
- Check for presence of expected record types

**Impact**: Low (tests are flexible)

### 5. TLS Certificate Validation

**Issue**: Public DoH servers use production TLS certificates

**Mitigation**:

- reqwest (rustls) handles TLS validation automatically
- Tests verify HTTPS connection works
- No self-signed certificate issues

**Impact**: None (built-in support)

## Performance Characteristics

### Latency

- **Google DNS**: ~20-50ms (well-distributed globally)
- **Cloudflare DNS**: ~10-30ms (1.1.1.1 is very fast)
- **LLM Call**: ~1-3 seconds (dominates test time)

### Throughput

- **Queries per test**: 1-2 queries
- **Total queries across suite**: 5-6 queries
- **Peak QPS**: Very low (well under any rate limits)

### Resource Usage

- **Memory**: Minimal (single client connection)
- **CPU**: Low (DNS parsing is fast)
- **Network**: Lightweight (DNS queries are small packets)

## Running Tests

### Single Test

```bash
./cargo-isolated.sh test --no-default-features --features doh \
  --test client -- client::doh::e2e_test::doh_client_tests::test_doh_client_google_dns
```

### Full Suite

```bash
./cargo-isolated.sh test --no-default-features --features doh --test client -- client::doh::e2e_test
```

### Prerequisites

- Internet connection (for public DoH servers)
- Ollama running locally (for LLM calls)
- No local DoH server required

## CI/CD Considerations

### GitHub Actions

- ✅ Internet access available
- ✅ No special privileges required
- ✅ Fast execution (~15-20 seconds)
- ✅ No Docker containers needed
- ✅ No port allocation required

### Local Development

- ✅ Works on any machine with internet
- ✅ No root access required
- ✅ No firewall changes needed
- ✅ Consistent results across platforms

## Debugging Tips

### Test Failures

**Symptom**: "Connection refused" or "Connection timeout"

- **Cause**: No internet connection or public DoH server down
- **Fix**: Check internet connection, try alternative DoH server

**Symptom**: "Invalid domain" or "Parse error"

- **Cause**: LLM generated invalid domain name
- **Fix**: Review LLM instruction clarity, check model temperature

**Symptom**: "TLS error" or "Certificate validation failed"

- **Cause**: System TLS certificate store issue
- **Fix**: Update system CA certificates

### Verbose Logging

```bash
RUST_LOG=debug ./cargo-isolated.sh test --no-default-features --features doh --test client -- client::doh::e2e_test
```

### Specific DoH Server Testing

To test a specific DoH server, modify the test URL:

```rust
// Google DNS
"https://dns.google/dns-query"

// Cloudflare
"https://cloudflare-dns.com/dns-query"
"https://1.1.1.1/dns-query"

// Quad9
"https://dns.quad9.net/dns-query"
```

## Future Enhancements

1. **Local DoH Server Tests**: Add tests against NetGet's own DoH server
2. **Error Case Coverage**: Test NXDomain, ServFail, timeout scenarios
3. **Performance Benchmarks**: Measure query latency and throughput
4. **DNSSEC Testing**: Validate DNSSEC-enabled queries
5. **Concurrent Queries**: Test query multiplexing over HTTP/2
6. **Cache Testing**: Verify TTL handling and response caching

## References

- [RFC 8484: DNS Queries over HTTPS (DoH)](https://datatracker.ietf.org/doc/html/rfc8484)
- [Google Public DNS DoH](https://developers.google.com/speed/public-dns/docs/doh)
- [Cloudflare DoH](https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/)
- [hickory-proto Documentation](https://docs.rs/hickory-proto/latest/hickory_proto/)

## `command_channel_test.rs`

Covers `AppState::send_to_client` injecting an action into a running doh client (the
dashboard's `[ send ]`). **Zero LLM calls**: the client's LLM points at
`http://127.0.0.1:1`, so its connected-event call fails and the loop must tolerate that —
part of what the test verifies. It always `wait_for_client_handle`s before sending, which is
the regression guard for "register the command channel *before* the connected-event LLM
call"; register it after and a client whose connect event parks on a manual rule reads "no
command channel" for the whole park.

Asserts the exact `ClientSendOutcome` variant. A successful request is
`Executed { detail }`, **not** `Sent` — reqwest/h3 own the socket and report no wire byte
count, so a byte count would be invented; the detail carries what actually came back
instead. An unknown action must be `Rejected` (not silently swallowed), and `disconnect`
must be `Disconnected` and leave the client with no command handle.

The peer is a ~40-line in-test HTTP/1.1 stub, not NetGet's own DoH server: that server is
TLS-only with a self-signed certificate and this client builds a default `reqwest::Client`,
which correctly refuses it (see `src/client/doh/AGENTS.md`). The stub echoes the POSTed body
back — a DNS query message is itself a well-formed DNS message — so the client parses a real
response (zero answers, `NoError`) and the request counter proves exactly one query left the
process.
