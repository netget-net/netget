# DNS-over-HTTPS (DoH) Protocol E2E Tests

## Test Overview

Tests DoH server implementation with both GET and POST HTTP methods. Validates that DNS queries work correctly when
delivered over HTTPS with HTTP/2 transport.

## Test Strategy

- **Single server setup**: one NetGet instance answers all three queries in `e2e_test.rs`
- **Real HTTPS client**: reqwest (hyper + rustls) with certificate verification disabled
  (accepts NetGet's self-signed cert)
- **Real DNS client**: hickory-proto for DNS message construction/parsing
- **Both HTTP methods**: GET (base64url `?dns=`) and POST (`application/dns-message` body)
- **Mock-driven**: dynamic mocks per query, echoing the client's transaction id out of the
  event

This section described a Python-script-driven test emitting a `dns_response` action until
September 2026. There is no such action (the real name is `send_dns_response`, and it takes
hex, not an `answers` array), and the test has been mock-driven for a long time. Verify
against the file.

## LLM Call Budget

- `e2e_test::test_doh_server()`: 1 startup + 3 query calls = 4
- `llm_failure_test::test_doh_answers_servfail_when_llm_fails()`: 1 startup; the query is
  deliberately left unmatched, which is what drives `call_llm` to `Err`
- `server_advertises_h2_alpn()`: 0 - a pure unit assertion on the TLS config
- **Total: 5 LLM calls**

## Scripting Usage

❌ **Scripting disabled** - mock-driven action responses.

Dynamic mocks (`respond_with_actions_from_event`) are required rather than optional here, for
the reason `tests/server/dns/AGENTS.md` sets out at length: the transaction id is chosen at
random by the client and must be echoed, and a static handler has no access to the event.

## Client Library

- **reqwest v0.11** - Async HTTP client
    - `Client::builder()` - Configure HTTP client
    - `danger_accept_invalid_certs(true)` - Accept self-signed certificates
    - `.get()` / `.post()` - HTTP methods
    - `.query()` - URL query parameters for GET
    - `.header()` / `.body()` - Request headers/body for POST
- **hickory-proto v0.24** - DNS message handling
    - `Message::new()` - Constructs DNS queries
    - `Message::from_vec()` - Parses DNS responses
    - `Query::query()` - Creates DNS query records
- **base64 v0.21** - Base64url encoding
    - `URL_SAFE_NO_PAD` engine for RFC 8484 compliance
    - Encodes DNS query for GET method

**Why these libraries?**:

1. **HTTP client needed**: DoH requires HTTPS transport (can't use raw TCP)
2. **Certificate verification**: Must disable verification for self-signed certs in tests
3. **DNS protocol**: hickory-proto ensures RFC-compliant DNS messages
4. **Base64url encoding**: GET method requires URL-safe base64 without padding
5. **Async compatibility**: All libraries integrate with Tokio runtime

## Expected Runtime

- Model: qwen3-coder:30b
- Runtime: ~25-30 seconds for full test
    - Server startup + script generation: ~20s (1 LLM call)
    - TLS handshake: ~100ms
    - HTTP/2 connection setup: ~10ms
    - 3 DNS queries over HTTPS: ~15ms total (script-driven, very fast)
    - Validation: <1s

**Note**: DoH with scripting is extremely fast after initial startup. The expensive part is LLM generating the script,
not the actual DNS queries.

## Failure Rate

- **Very Low** (<1%) - Highly stable test
- Script-driven responses are deterministic
- Occasional failures: TLS/HTTP/2 handshake timeout if system is very slow
- No LLM variability in query responses (script handles all)

## Test Cases

### Test: DoH Server with GET and POST Methods (`test_doh_server`)

**Comprehensive test covering**:

1. Server startup with Python script
2. HTTPS connection establishment
3. HTTP/2 connection setup
4. DNS query via GET method (base64url encoding)
5. DNS query via POST method (binary body)
6. Connection reuse between methods

**Test Flow**:

1. Start NetGet server on dynamic port with DNS-over-HTTPS
2. Provide Python script that returns A record for all queries
3. Create HTTP client with self-signed certificate acceptance
4. **Query 1 (GET)**: example.com A record via GET method
    - Construct DNS query with hickory-proto
    - Encode as base64url
    - Send GET request to `/dns-query?dns={encoded}`
    - Verify response has answers
5. **Query 2 (POST)**: example.com A record via POST method
    - Construct DNS query with hickory-proto
    - Send POST request with `application/dns-message` content-type
    - Binary DNS packet in body
    - Verify response has answers
6. **Query 3 (GET)**: test.com A record via GET method (different domain)
    - Tests connection reuse
    - Verify response has answers

**Why these test cases?**:

- **GET method**: Tests base64url encoding, URL parameter extraction
- **POST method**: Tests binary DNS packet handling, content-type validation
- **Multiple queries**: Tests HTTP/2 multiplexing, connection reuse
- **Different domains**: Tests script handles various inputs (though returns same response)

**Validation**:

- HTTP status 200 and `Content-Type: application/dns-message`
- the transaction id the client chose is echoed, and so is the question
- exactly one A record, holding the address that domain's handler chose
- HTTP/2 connection persists between requests

### Connection bounds (`connection_bounds_test.rs`)

In-process (`ServerForm` + `AppState`), model-free (dead-port LLM, static or manual rules), zero
LLM calls. Four tests:

- **The cap**: 256 completed handshakes are admitted, the 257th is closed before its
  handshake completes, and closing one frees exactly one slot.
- **Silent after the handshake**: a peer that completes TLS and never sends the HTTP/2 preface
  reads EOF at the idle bound (`idle_timeout_secs`, set to 3s).
- **Quiet after an answer**: an `h2` client whose `GET /dns-query` with no `dns=` is answered
  400 by the server itself sees its connection end at the idle bound (a GOAWAY, then close).
- **Parked for a human**: a POSTed query routed to `manual` keeps its connection for four times
  the idle bound — every request holds `ConnectionActivity` busy.

Verified by removal: with the `watch_idle` arm disabled the two idle tests fail; with the
`busy()` guard removed the parked test sees its connection closed.

## Known Issues

### 1. Self-Signed Certificate Handling

Test uses `danger_accept_invalid_certs(true)` to bypass certificate verification. This is **test-only** configuration
and should never be used in production.

```rust
let client = Client::builder()
    .danger_accept_invalid_certs(true)
    .timeout(Duration::from_secs(10))
    .build()?;
```

**Why needed?**: NetGet generates self-signed certificates, which would normally fail verification. Production DoH
clients should verify certificates properly.

### 2. No Certificate Validation Test

Test doesn't verify:

- Certificate validity period
- Certificate subject/hostname
- Certificate chain
- Certificate revocation

**Reason**: Focus is on DoH protocol correctness, not TLS certificate infrastructure.

### 3. Error responses - partly covered

`llm_failure_test.rs` covers the backend-failure case, which is the one with teeth: the reply
must be a **SERVFAIL message inside a 200**, not a 5xx. RFC 8484 §4.2.1 makes 200 the status
for "this transaction carried a DNS message"; a 5xx says the resolver endpoint is broken, and
real DoH clients respond to that by marking the server down and failing over. The test asserts
the status, the Content-Type, RCODE 2, the echoed id and question, and an empty answer section.

Still uncovered: NXDOMAIN over DoH (covered for plain DNS, and the code path is shared),
HTTP 400 for a missing/undecodable `dns=` parameter, 413 for an oversized body, and 405 for a
method other than GET/POST.

### 4. Answers are asserted by value, and the domains differ

`example.com` resolves to 93.184.216.34 and `test.com` to 93.184.216.35, so a reply routed to
the wrong question is visible. Both used to return the same address and the assertion was
`!answers.is_empty()`, which passes for an executor that ignores the `ip` it was handed.

### 5. Content-Type validation - now present, in both directions

Both query helpers assert the response's `Content-Type: application/dns-message`, and the POST
helper deliberately *sends* `Application/DNS-Message; charset=utf-8`. That mixed case and the
parameter are the point: RFC 9110 §8.3 makes the media type case-insensitive and permits
parameters, and the server compared the whole header value byte-for-byte against the canonical
spelling, so a conformant client was rejected as "Invalid Content-Type".

### 6. Transaction id and question echo - now asserted

Both helpers used to leave the id at `DnsMessage::new()`'s default of 0 and never look at it
again, so a server answering with the wrong id, or with no question section, was
indistinguishable from one answering correctly - the exact defect `tests/server/dot/e2e_test.rs`
found and fixed in its own client. They now pick a random id and assert both come back.

## Performance Notes

### TLS + HTTP/2 Handshake Overhead

- First query: ~110ms overhead (TLS + HTTP/2 handshake)
- Subsequent queries: ~1-2ms each (reuse connection)
- Amortized overhead minimal with connection reuse

### Method Performance Comparison

- **GET method**: ~1-2ms (includes base64 decode)
- **POST method**: ~1-2ms (no encoding overhead)
- Performance difference negligible (microseconds)
- GET has slight overhead from URL parsing and base64 decode

### Scripting Performance

Without scripting, DoH would require 1 LLM call per query:

- 1 startup + 3 queries = 4 LLM calls total
- Runtime: ~20s (startup) + 3×8s (queries) = 44s

With scripting:

- 1 startup only = 1 LLM call total
- Runtime: ~20s (startup) + 3×1ms (queries) = 20s
- **Performance improvement: ~50% faster runtime, 75% fewer LLM calls**

### Comparison to DoT Tests

DoH tests are:

- **Similar startup time**: Both use TLS, similar script complexity
- **Slightly slower connection setup**: HTTP/2 adds overhead vs raw TLS
- **Similar query performance**: Both script-driven, sub-millisecond queries
- **More features**: Tests two HTTP methods vs DoT's single protocol

## Future Enhancements

### Test Coverage Gaps

1. **Error responses**: Test NXDOMAIN, SERVFAIL, invalid queries
2. **Multiple record types**: Test AAAA, MX, TXT over HTTPS
3. **Large queries**: Test queries near size limits
4. **Invalid content-type**: Test POST with wrong content-type (expect 400)
5. **Missing dns parameter**: Test GET without `dns=` param (expect 400)
6. **Malformed base64**: Test GET with invalid base64 (expect 400)
7. **Concurrent requests**: Test HTTP/2 multiplexing with parallel queries
8. **Cache headers**: Test HTTP cache-control headers (future feature)

### Consolidation Opportunity

Could add more comprehensive script:

```python
import json,sys
d=json.load(sys.stdin)
domain = d['event']['domain']
method = d['event']['method']
if domain == 'example.com':
    # Return A record
elif domain == 'test.com':
    # Return different A record
else:
    # Return NXDOMAIN
# Could also vary response based on HTTP method
```

This would test domain-specific and method-specific responses while staying within 1 LLM call budget.

### HTTP Method Tests

Add tests for:

- **Invalid methods**: Test PUT, DELETE, PATCH (expect 405 Method Not Allowed)
- **OPTIONS request**: Test CORS preflight (if needed)
- **HEAD request**: Test HEAD method (should return headers only)

### Certificate Testing

Add test with proper certificate validation:

1. Generate CA certificate
2. Sign server certificate
3. Configure client to trust CA
4. Verify full certificate chain

**Benefit**: Tests production-like HTTPS setup.

### Performance Benchmarking

Add test to measure:

- Queries per second with scripting
- HTTP/2 multiplexing efficiency
- Connection reuse vs new connections

## References

- [RFC 8484: DNS Queries over HTTPS (DoH)](https://datatracker.ietf.org/doc/html/rfc8484)
- [RFC 7540: HTTP/2](https://datatracker.ietf.org/doc/html/rfc7540)
- [hickory-proto Documentation](https://docs.rs/hickory-proto/latest/hickory_proto/)
- [reqwest Documentation](https://docs.rs/reqwest/latest/reqwest/)
- [base64 Documentation](https://docs.rs/base64/latest/base64/)

## The maturity evidence

**State: Beta**, on **two** independent peers as of September 2026:

| test | peer | what it proves |
|---|---|---|
| `tests/server/doh/real_client_test.rs` | `kdig` (Knot DNS 3.6, C) | a third-party resolver completes both RFC 8484 encodings, negotiating `h2` over ALPN |
| `tests/server/doh/e2e_test.rs` | `reqwest` (hyper + rustls) | the HTTP/2 and TLS transport, the 200 status and Content-Type, a mixed-case media type with a charset parameter |

Neither is `#[ignore]`d; the kdig test **fails** naming `brew install knot` rather than skipping.

**The second one alone was half circular.** reqwest proves an HTTP server answers, not that the
DNS on top is right — the root `AGENTS.md` says exactly that about generic HTTP clients — and
the DNS message is decoded with **hickory-proto, the codec this server encodes with**. ALPN was
unproven for a related reason: that client uses `http2_prior_knowledge()`, which skips ALPN
entirely, so the `h2` advertisement could have been anything.

Both are now covered, and both were verified by breaking them:

- Answering with a fixed transaction id instead of the client's → kdig discards the reply and
  the test fails.
- Advertising `http/1.1` instead of `h2` → the handshake fails with kdig's own alert,
  `TLS, handshake failed (A TLS fatal alert has been received.)`.

**Two things about driving kdig here, both of which cost a debugging cycle.** `+https` takes
`[authority][/path]`, and the authority becomes the TLS SNI as well as the `:authority` header.
An IP literal there is rejected by rustls outright, which surfaces as a fatal alert that looks
exactly like a cipher or ALPN mismatch. A *name* there instead switches kdig to a validating
profile, which a self-signed certificate cannot satisfy. Passing the path alone keeps the
opportunistic profile, which is also what the DoT test relies on.

**Unproven:** certificate validation of any kind, client auth, and record types beyond A.


## Stable condition 2: the pcap oracle, decrypted

`real_client_test.rs` runs kdig with `SSLKEYLOGFILE` set (GnuTLS honours it) and through a
recording relay. The pcap oracle hands tshark the key log (`PcapOracle::tls_keylog`), so both
sessions are decrypted; ALPN `h2` gives the plaintext to the `http2` dissector and the
`application/dns-message` body to `dns`. `require_named("http2")` and `require_named("dns")`
fail the oracle unless both appear in what the server sent, so a key log that did not match is
a failure, not a pass on the TLS record layer. Covered: the TLS handshake as the server wrote
it, HTTP/2 framing and HPACK, the POST and the GET reply's DNS message. Not covered: the GET
request's query, which travels base64url-encoded in the `:path` where no DNS dissector reads it
(the server's reply to it is covered), and certificate validation of any kind.

Condition 3 is `fuzz/fuzz_targets/dns_message.rs`, which fuzzes the `hickory_proto`
`Message::from_vec` this server calls on every request body, with a
`compression_pointer_loop` in its corpus.
