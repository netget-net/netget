# DoT (DNS over TLS) Client E2E Tests

## Test Strategy

The DoT client E2E tests verify LLM-controlled DNS query functionality over TLS-encrypted connections to public DoT
servers. Tests focus on real-world scenarios using Google DNS (dns.google:853) and Cloudflare DNS (1.1.1.1:853).

## Test Approach

### Black-Box Testing

- Tests interact with public DoT servers (dns.google, cloudflare-dns.com)
- LLM receives natural language instructions to query DNS records
- Validates that queries are sent and responses are processed
- No mocking - uses real TLS connections and DNS protocol

### Prompt-Driven

Each test provides the LLM with a specific instruction:

- "Query example.com A record and tell me the IP address"
- "Query example.com for A, AAAA, and MX records"
- "Query nonexistent-domain-12345.example and tell me what error you get"

LLM interprets the prompt and generates appropriate `send_dns_query` actions.

## Record formatting (`record_display_test.rs`)

Runs offline, no model and no server. `record_json` is the one function the client's read loop
formats every answer, authority and additional record through, and it formats record data with
`crate::utils::display::try_display` rather than `format!`: hickory's `RData::OPT` returns
`fmt::Error` from `Display`, and `format!` turns that into a panic inside the read task. The
first test hands it an OPT record (which a decoded response cannot hold in a section under
hickory-proto 0.26, so it is built in memory) and asserts the record is reported by type with a
`data` saying it cannot be displayed; with `format!` back in place it panics. The second asserts
an A record still carries its address.

## Test Cases

### 1. Basic Query (`test_dot_client_basic_query`)

**Purpose**: Verify basic A record query functionality

**Setup**:

- Connect to `dns.google:853`
- Instruction: "Query example.com A record and tell me the IP address"

**Validation**:

- Client connects successfully (TLS handshake)
- LLM sends DNS query action
- Client receives DNS response
- Client status is `Connected`

**LLM Calls**: 2 (connected event, response event)

**Expected Runtime**: ~5-10 seconds

---

### 2. Multiple Queries (`test_dot_client_multiple_queries`)

**Purpose**: Verify multiple sequential DNS queries over same connection

**Setup**:

- Connect to `1.1.1.1:853` (Cloudflare)
- Instruction: "Query example.com for A, AAAA, and MX records, one at a time"

**Validation**:

- At least 3 queries sent (A, AAAA, MX)
- At least 3 responses received
- Connection remains active

**LLM Calls**: 7 (1 connected, 3 query responses, ~3 follow-up queries)

**Expected Runtime**: ~10-15 seconds

---

### 3. NXDOMAIN Handling (`test_dot_client_nxdomain_handling`)

**Purpose**: Verify client handles non-existent domain errors gracefully

**Setup**:

- Connect to `dns.google:853`
- Instruction: "Query nonexistent-domain-12345.example for A record and tell me what error you get"

**Validation**:

- Client receives DNS response (with NXDOMAIN code)
- Client does not crash or disconnect
- LLM processes error response

**LLM Calls**: 2 (connected event, error response event)

**Expected Runtime**: ~5-10 seconds

---

### 4. TLS Connection (`test_dot_client_tls_connection`)

**Purpose**: Verify TLS handshake and certificate validation

**Setup**:

- Connect to `cloudflare-dns.com:853`
- Instruction: "Query cloudflare.com A record"

**Validation**:

- TLS handshake succeeds
- Server certificate is validated
- Client status is `Connected`

**LLM Calls**: 1 (connected event)

**Expected Runtime**: ~3-5 seconds

---

## LLM Call Budget

**Total Budget**: < 10 LLM calls across all tests

**Breakdown**:

- Test 1: 2 calls
- Test 2: 7 calls (may vary based on LLM decisions)
- Test 3: 2 calls
- Test 4: 1 call

**Actual**: ~12 calls (slightly over budget due to variable LLM behavior in test 2)

**Justification**:

- Each test is independent and focused
- Test 2 accounts for most calls (testing multi-query scenario)
- Budget is reasonable for comprehensive DNS client testing

## Runtime

**Per Test**:

- Basic query: ~5-10s
- Multiple queries: ~10-15s
- NXDOMAIN handling: ~5-10s
- TLS connection: ~3-5s

**Total Suite**: ~25-40 seconds

**Factors Affecting Runtime**:

- Network latency to public DoT servers
- TLS handshake time (~100-500ms per connection)
- LLM inference time (~1-3s per call)
- DNS query RTT (~20-100ms per query)

## Known Issues

### 1. LLM Response Variability

**Issue**: LLM may send different numbers of queries based on interpretation

**Example**: In `test_dot_client_multiple_queries`, LLM might send 3-5 queries depending on how it interprets "A, AAAA,
and MX"

**Mitigation**: Test validates "at least 3" rather than exact count

---

### 2. Public DoT Server Availability

**Issue**: Tests depend on public DoT servers being available

**Affected**: All tests

**Mitigation**:

- Use reliable public servers (Google, Cloudflare)
- Tests marked as `#[ignore]` to avoid CI failures
- Run manually or in environments with internet access

---

### 3. Ollama Server Dependency

**Issue**: Tests require Ollama server running on `localhost:11434`

**Mitigation**:

- Tests marked as `#[ignore]`
- Clear documentation in test output

---

### 4. Timing Sensitivity

**Issue**: Tests use fixed timeouts (30-60s) which may be too short on slow networks

**Mitigation**:

- Generous timeouts to account for network variability
- Tests use `tokio::select!` to avoid blocking indefinitely

---

### 5. Response Content Validation

**Issue**: Tests cannot easily validate DNS response content (e.g., "did LLM correctly parse IP address?")

**Reason**: LLM output is natural language, not structured data

**Mitigation**:

- Focus on protocol-level validation (queries sent, responses received)
- Trust LLM to interpret DNS data correctly
- Manual verification of LLM output during development

## Running Tests

### Run All DoT Client Tests

```bash
./cargo-isolated.sh test --no-default-features --features dot --test client -- client::dot::e2e_test --ignored
```

### Run Specific Test

```bash
./cargo-isolated.sh test --no-default-features --features dot --test client -- client::dot::e2e_test::test_dot_client_basic_query --ignored
```

### Prerequisites

- Ollama server running on `localhost:11434`
- Model `qwen3-coder:30b` available
- Internet access to public DoT servers
- No other tests running concurrently

## Privacy & Security

### Network Privacy

- Tests connect to public DoT servers (Google, Cloudflare)
- DNS queries are encrypted over TLS
- No sensitive domains queried (only example.com, cloudflare.com)

### Data Collection

- Public DoT servers may log queries
- Tests only query safe, well-known domains
- No personally identifiable information in queries

### Local Testing

- Tests run on localhost only
- No external servers started
- All connections initiated by client (outbound only)

## Future Improvements

1. **DNSSEC Testing**: Add tests for DNSSEC-enabled queries and response validation
2. **Connection Persistence**: Test long-lived connections with multiple queries
3. **Error Handling**: More comprehensive error scenarios (SERVFAIL, REFUSED)
4. **Performance Testing**: Measure query latency and throughput
5. **Local DoT Server**: Use local DoT server for faster, more reliable tests
6. **Response Validation**: Structured assertions on DNS response content
7. **IPv6 Testing**: Test DoT over IPv6 connections
8. **TLS Versions**: Test different TLS versions (1.2, 1.3)
