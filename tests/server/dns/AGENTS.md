# DNS Protocol E2E Tests

## Test Overview

**Nine files, 27 tests** since October 2026 (four files and 14 tests added for TCP, EDNS,
transfers and DNSSEC; see the second table). Before that it was **five files, 13 tests**, and the two that carry the maturity rating are the ones this
overview used to omit. It described only `test.rs` — "uses hickory-client (real DNS client)
for protocol correctness" — which is the circular half of the suite and the reason `dig_test.rs`
had to be written.

| file | what drives it | what it is for |
|---|---|---|
| `dig_test.rs` | ISC BIND's `dig` | independent resolver #1 — A, AAAA, CNAME, MX, TXT, NXDOMAIN, plus one query with **default** flags (EDNS offered) |
| `kdig_test.rs` | Knot DNS's `kdig` (CZ.NIC) | independent resolver #2, the same record types through a different presentation writer |
| `llm_failure_test.rs` | raw `UdpSocket` + pcap oracle | both fail-closed paths, and that `ignore_query` stays silence |
| `bounds_test.rs` | raw `UdpSocket` + the executor | every declared bound, each verified by removal; the pcap oracle over a NOERROR answer |
| `test.rs` | hickory-client | A, TXT, multi-domain, NXDOMAIN — **circular**, see "Client Library" below |

The October 2026 files run the server **in-process with a script handler** (`zone_support.rs`)
playing an authoritative server for `example.com.` — 611 records with 600 fillers, so an AXFR
needs two messages — so no model is involved and every count is exact:

| file | what drives it | what it is for |
|---|---|---|
| `transfer_test.rs` | `dig` and `kdig` | AXFR (SOA first and last, every record once, two messages), IXFR difference and "current", REFUSED for another zone, TC and the retry over TCP, the OPT record, NS/SOA/SRV/PTR via `send_dns_records`, NXDOMAIN with the SOA |
| `dnssec_test.rs` | `delv`, `drill`, `ldns-verify-zone`, `dnssec-verify` | validated positive, NXDOMAIN and NODATA answers against a trust anchor built from the served DNSKEY; a signed AXFR verified whole, one NSEC per owner name |
| `transport_bounds_test.rs` | raw UDP/TCP + pcap oracle | every new bound (the table in its header) |
| `zone_support.rs` | — | the in-process server, the zone handler, and `dig`/`kdig`/`run` helpers that fail naming the package |

`dnssec-verify` runs with `-z` because the server signs with one key (flags 257) acting as KSK
and ZSK; without it BIND reports "Missing ZSK" before checking a signature.

## Test Strategy

- **Two independent resolvers carry the rating.** `dig` and `kdig` share no code with hickory
  or with each other, and each **fails** rather than skipping when its binary is absent.
- **Isolated test servers**: each test spawns a separate NetGet instance; the resolver tests
  bundle all their queries onto one server, because each spawn is an extra startup call.
- **Protocol correctness**: the actual DNS wire protocol, not mocked responses.
- **The pcap oracle** reads the bytes with Wireshark's DNS dissector in `llm_failure_test.rs`
  and `bounds_test.rs`. It hard-fails when `tshark` is missing.
- **No scripting**: action-based LLM responses.
- **Dynamic mocks**: `.respond_with_actions_from_event()` for protocol-correct transaction ID
  matching.

## LLM Call Budget

| test | startup | events | total |
|---|---|---|---|
| `test::test_dns_a_record_query` | 1 | 1 | **2** |
| `test::test_dns_multiple_records` | 1 | 2 | **3** |
| `test::test_dns_txt_record` | 1 | 1 | **2** |
| `test::test_dns_nxdomain` | 1 | 1 | **2** |
| `dig_test::test_dns_answers_dig` | 1 | ≥6 | **≥7** |
| `kdig_test::test_dns_answers_kdig` | 1 | 6 | **7** |
| `llm_failure_test::…_servfail_when_llm_fails` | 1 | 1 (answered 500) | **2** |
| `llm_failure_test::…_black_hole` | 1 | 2 | **3** |
| `bounds_test::…_receive_buffer…` | 1 | 1 | **2** |
| `bounds_test::` (four executor tests) | 0 | 0 | **0** |
| `transfer_test`, `dnssec_test`, `transport_bounds_test` (14 tests) | 0 | script handler | **0** |

This table used to give a single total of 9 and list five tests. The count drifts every time a
file is added, which is the argument for a per-test table rather than a number: **derive it**
rather than reading it. `dig_test`'s event count is a floor (`expect_at_least`) because its
default-flags query is allowed to fall back from EDNS and re-ask.

The ~10-call guidance in the root `AGENTS.md` is about keeping a suite cheap against a *real*
model; every call here is answered by the in-process mock, so what the table is really for is
noticing a rule that fires more often than it should.

## Scripting Usage

❌ **Scripting Disabled** - Action-based responses only

**Rationale**: Tests validate that the LLM can correctly generate DNS responses using
structured actions. Scripting would bypass this validation. For production DNS servers,
scripting is highly recommended for performance.

## Dynamic Mock Pattern (CRITICAL)

Every mock rule that produces an **answer record** uses `.respond_with_actions_from_event()`,
to enable protocol-correct transaction ID matching. This line used to say "all DNS tests",
which stopped being true once `llm_failure_test.rs` arrived: its `show_message` and
`ignore_query` rules are static, and correctly so — neither produces a packet, so there is no
id to echo. The rule is about what the answer carries, not about which file it is in.

### Why Dynamic Mocks?

DNS (and all UDP protocols) require **transaction ID matching**: the `query_id` in the response must exactly match the `query_id` in the request. Static mocks cannot do this because the client generates random transaction IDs.

**Problem with static mocks:**
```rust
// ❌ WRONG - hardcoded query_id doesn't match request
.respond_with_actions(serde_json::json!([{
    "type": "send_dns_a_response",
    "query_id": 0,  // ← Static! Client expects 15073
    "domain": "example.com",
    "ip": "93.184.216.34"
}]))
```

**Solution with dynamic mocks:**
```rust
// ✅ CORRECT - extract query_id from event data
.respond_with_actions_from_event(|event_data| {
    let query_id = event_data["query_id"].as_u64().unwrap_or(0);
    serde_json::json!([{
        "type": "send_dns_a_response",
        "query_id": query_id,  // ← Dynamic! Matches request
        "domain": "example.com",
        "ip": "93.184.216.34"
    }])
})
```

### Pattern Usage

**Step 1**: Match the event type and event data:
```rust
.on_event("dns_query")
.and_event_data_contains("domain", "example.com")
.and_event_data_contains("query_type", "A")
```

**Step 2**: Use dynamic response with closure:
```rust
.respond_with_actions_from_event(|event_data| {
    // Extract dynamic values from event
    let query_id = event_data["query_id"].as_u64().unwrap_or(0);

    // Return actions using extracted values
    serde_json::json!([{
        "type": "send_dns_a_response",
        "query_id": query_id,
        "domain": "example.com",
        "ip": "93.184.216.34",
        "ttl": 300
    }])
})
```

**Step 3**: Set call expectations:
```rust
.expect_calls(1)
.and()
```

### Full Example

```rust
let config = NetGetConfig::new("listen on port {AVAILABLE_PORT} via dns. ...")
    .with_log_level("debug")
    .with_mock(|mock| {
        mock
            // Mock 1: Server startup
            .on_instruction_containing("listen on port")
            .and_instruction_containing("dns")
            .respond_with_actions(serde_json::json!([
                {"type": "open_server", "port": 0, "base_stack": "DNS", ...}
            ]))
            .expect_calls(1)
            .and()
            // Mock 2: DNS query event - DYNAMIC RESPONSE
            .on_event("dns_query")
            .and_event_data_contains("domain", "example.com")
            .and_event_data_contains("query_type", "A")
            .respond_with_actions_from_event(|event_data| {
                let query_id = event_data["query_id"].as_u64().unwrap_or(0);
                serde_json::json!([{
                    "type": "send_dns_a_response",
                    "query_id": query_id,  // ← CRITICAL: Must match request!
                    "domain": "example.com",
                    "ip": "93.184.216.34"
                }])
            })
            .expect_calls(1)
            .and()
    });

let server = helpers::start_netget_server(config).await?;

// ... send DNS query ...

server.verify_mocks().await?;  // ← CRITICAL: Verify mock expectations
```

### Key Points

1. **Extract event data inside closure**: `event_data["query_id"]`, `event_data["domain"]`, etc.
2. **Return JSON array or single object**: Normalizes automatically
3. **Closure signature**: `Fn(&serde_json::Value) -> serde_json::Value`
4. **Always call `.verify_mocks().await?`**: Ensures expectations met
5. **Dynamic mocks are NOT serializable**: Requires in-process mock server (not env var)

### Event Data Available

For `dns_query` events:
- `query_id` (number) - Transaction ID from DNS request packet
- `domain` (string) - Domain name being queried
- `query_type` (string) - Record type (A, AAAA, TXT, MX, etc.)

### Transaction ID Matching Evidence

**Correct behavior with dynamic mocks:**
```
DNS request:  0x3ae1 (15073 decimal)
Mock extracts: query_id = 15073
DNS response: 0x3ae1 (matches!)
Client accepts response ✅
```

**Broken behavior with static mocks:**
```
DNS request:  0x3ae1 (15073 decimal)
Mock returns: query_id = 0
DNS response: 0x0000 (doesn't match!)
Client ignores response ❌ timeout
```

## Client Library

- **hickory-client v0.24** - Async DNS client library
    - `AsyncClient` - High-level DNS query interface
    - `UdpClientStream` - UDP transport for DNS queries
    - Handles DNS wire protocol automatically
    - Validates response format

**Why hickory-client?**:

1. Real DNS protocol validation (not just "any UDP response")
2. Async/await compatible with Tokio

Point 3 used to read "same library family as server-side hickory-proto", listed as an
advantage. It is the opposite: hickory-client decodes with the same codec
hickory-proto encoded with, so on its own this suite proves the wire format is
self-consistent, not that it is correct. That is the circularity that kept `rss` at
Experimental until `feed-rs` did its parsing.

**`dig_test.rs` and `kdig_test.rs` are the answer to it.** ISC BIND's `dig` and Knot
DNS's `kdig` share no code with hickory or with each other, and both are stricter
than the round-trip — each checks that the transaction id it chose comes back and
that the question section matches what it asked, so a reply a real resolver would
discard fails there and passes here. Both **fail** when their binary is absent
rather than printing SKIP, per the `npm` precedent. This paragraph named only `dig`
for as long as `kdig_test.rs` has existed.

## Expected Runtime

**About 7 seconds for all 13 tests** at `--test-threads=100`, measured 16 September 2026:

```bash
./cargo-isolated.sh test --no-default-features --features dns \
    --test server -- --test-threads=100 dns
```

This section used to read "Model: qwen3-coder:30b … ~40-50 seconds … LLM response (5-8s)",
which described a `--use-ollama` run. The default mode needs no Ollama at all: the mock is an
in-process axum server and answers in microseconds, so no number here is a model's.

## Failure Rate

**Zero across repeated runs**, and the previous text is worth recording because it was
describing something these tests cannot do. It said "~2-3%, occasional LLM response issues.
Most common failure: LLM returns wrong record type or malformed IP address. NXDOMAIN test:
sometimes flaky if LLM misinterprets 'unknown domain' instruction."

There is no LLM. Every response is fixed by a mock rule, so a "wrong record type" is
impossible by construction — and, worse, the sentence framed a *test* result as something the
model might get wrong, which is the reasoning that produced the old NXDOMAIN test that accepted
every outcome (see Known Issues #1). A mocked suite that is flaky is flaky for a reason in the
code or in the harness, never because the model had an off day.

The realistic failure mode is the `dig`/`kdig` tests on a machine where the binary is absent:
they fail, loudly and by name, which is the design.

## Test Cases

The four below are `test.rs`, the hickory-client file. **They are not the evidence the maturity
rating rests on** — see the table in Test Overview. This section listed only these four for as
long as the other four files have existed, which made the circular suite look like the whole of
the coverage; the rest are summarised after them.

### 1. DNS A Record Query (`test_dns_a_record_query`)

- **Prompt**: "listen on port {port} via dns. Respond to all A record queries for example.com with IP address
  93.184.216.34"
- **Client**: Queries example.com A record using hickory-client
- **Expected**: exactly one A record holding 93.184.216.34, RCODE NOERROR
- **Purpose**: Tests basic IPv4 address resolution
- **Validation**: `answer_a()` asserts one A record by value

### 2. DNS Multiple Records (`test_dns_multiple_records`)

- **Prompt**: "listen on port {port} via dns. For example.com A records return 1.2.3.4. For mail.example.com A records
  return 5.6.7.8"
- **Client**: Queries both example.com and mail.example.com
- **Expected**: Each query returns appropriate A record
- **Purpose**: Tests multi-domain routing — two mock rules keyed on different domains, which is
  the *harness* distinguishing them, not a model. (This line said "LLM's ability to distinguish
  domains"; with mocked responses there is no such ability under test.)
- **LLM Calls**: 2 (one per domain query)

### 3. DNS TXT Record (`test_dns_txt_record`)

- **Prompt**: "listen on port {port} via dns. For TXT record queries on example.com, return 'v=spf1 include:_
  spf.example.com ~all'"
- **Client**: Queries example.com TXT record
- **Expected**: Response contains TXT record
- **Purpose**: Tests non-address record type (SPF record)
- **Validation**: Checks for TXT record in answers

### 4. DNS NXDOMAIN (`test_dns_nxdomain`)

- **Prompt**: "listen on port {port} via dns. Only respond with A records for known.example.com (1.2.3.4). For all other
  domains, return NXDOMAIN"
- **Client**: Queries unknown.example.com (should fail)
- **Expected**: RCODE 3 (NXDOMAIN), zero answer records, question echoed
- **Purpose**: Tests error handling and NXDOMAIN response
- **Note**: all three are asserted. See "Known Issues" for what this used to accept

### 5-6. The two resolvers (`dig_test.rs`, `kdig_test.rs`)

One server each, six queries each: A, TXT, AAAA, MX, CNAME and a name that does not exist.
`dig_test.rs` adds a seventh with **default flags** — EDNS offered — which is the only query in
the suite run the way a person would run it. Both hard-fail naming their package when the
binary is absent. See "Two resolvers, and why the second one exists" at the foot of this file.

### 7-8. Fail-closed (`llm_failure_test.rs`)

`test_dns_answers_servfail_when_llm_fails`: no mock rule for `dns_query`, so the mock answers
HTTP 500 and `call_llm` returns `Err`. Asserts the RCODE nibble on the raw bytes *and* through
a decoder, plus the id and question echo, plus the pcap oracle.

`test_dns_distinguishes_no_usable_action_from_a_deliberate_black_hole`: the case `call_llm`
returns **`Ok`** for and this server used to answer with silence — a model reply made only of
common actions. One server, two queries, because the assertion is that they *differ*:
`show_message` must be SERVFAIL and `ignore_query` must be silence.

### 9-13. Bounds (`bounds_test.rs`)

Every declared bound, each verified by removing it: the 4096-byte receive buffer (from a
socket), and `query_id`, MX `preference`, the 12-octet raw-message floor and the 255-octet TXT
character-string (through the executor, where the wire cannot reach them). Also the only run of
the pcap oracle over a NOERROR answer with rdata in it.

## Known Issues

### 1. NXDOMAIN Test Variability - fixed, and it was not variability

`test_dns_nxdomain` used to match on `Ok`/`Err` and print
"implementation-dependent behavior" in one arm and "server indicated domain not found"
in the other, so **every** outcome passed - including NOERROR with an empty answer
section, which tells a resolver the opposite of NXDOMAIN. Nothing here is
implementation-dependent: the mock forces `send_dns_nxdomain`, so RCODE 3 is the only
correct answer, and the test now asserts the RCODE, the empty answer section and the
echoed question. `dig_test.rs` asserts `status: NXDOMAIN` off the header line for the
same reason - an empty answer section alone does not distinguish the two.

### 2. No Record Content Validation - fixed

Tests asserted `!answers.is_empty()`, which passes for an executor that ignores the
`ip` it was handed. They now assert the address, the TXT character-string and the
RCODE by value. The old rationale - "LLM might format responses slightly differently"
- does not apply: these are mock-driven, the handler's output is fixed, and the values
are compared after hickory has decoded them into typed rdata, not as text.

### 3. No AAAA, MX, CNAME Tests — fixed

This said "A and TXT provide good coverage of address and text record types. Adding all record
types would exceed LLM call budget." Both halves were wrong. The calls are mocked, so the
budget argument cost nothing to be wrong about; and the coverage argument was the load-bearing
mistake — `send_dns_aaaa_response`, `send_dns_mx_response` and `send_dns_cname_response` are
actions the **model is offered**, so leaving them undecoded by anything independent meant three
advertised verbs whose wire format nothing had ever checked. `metadata()` said so out loud
("UNPROVEN: … record types beyond A and TXT") and it was read as a note rather than as a gap.

`dig_test.rs` and `kdig_test.rs` now query all three on the same server they already had, at a
cost of three extra mocked calls each. A 16-octet address, a `u16` followed by a domain name,
and a bare domain name are three different ways to get an encoder wrong; the MX preference is
4660 (0x1234) so a byte-swap reads 13330 rather than something plausible.

Still untested: `send_dns_response`, the raw-hex escape hatch, beyond its 12-octet floor and
hex-only check in `bounds_test.rs`. Nothing constructs a real NS/SOA/PTR/SRV message through it.

### 3b. EDNS — and the one query that is not `+noedns`

Every resolver query passes `+noedns`, for a stated and honest reason: EDNS0 is not
implemented, and a resolver that offers EDNS and gets a reply with no OPT record may fall back
and re-query, which would break `expect_calls(1)`.

That left the question the rating actually turns on unasked — does a resolver *as a person
invokes it* get an answer? `dig_test.rs` now runs one query with no flags at all and asserts
the address comes back. RFC 6891 §6.1.1: a server that does not understand EDNS answers without
an OPT record, and the requestor treats the response as non-EDNS. The A rule's expectation is
`expect_at_least` so a fallback re-query is harmless rather than a failure.

### 4. No Concurrent Query Tests

Tests send queries sequentially. No validation of concurrent query handling.

**Reason**: DNS server handles concurrent queries correctly (separate tokio tasks per query), but testing concurrency
would complicate assertions and increase LLM calls.

## Performance Notes

### Why hickory-client?

Originally considered using raw UDP sockets (like DHCP/NTP tests), but hickory-client provides several advantages:

- Validates DNS wire protocol compliance
- Automatic query ID generation and matching
- Timeout handling built-in
- Parses responses into structured Record types
- Minimal overhead (~1ms per query)

### DNS Protocol Characteristics

DNS is inherently fast:

- UDP transport (no TCP handshake)
- Small packet sizes (typically <512 bytes)
- Stateless request-response
- No authentication/encryption overhead

Without LLM overhead, NetGet DNS server could handle thousands of queries per second with scripting enabled.

## Remaining coverage gaps

Re-derived 16 September 2026. The first three entries of the old list — AAAA, MX and CNAME —
are closed; what is left is:

1. **Multiple answers**: no test of several records for one name. The action set cannot produce
   them (one record per response), so this is a limitation to test *for* rather than against —
   nothing asserts that the server does not silently drop extra answers, because it cannot be
   asked for any.
2. **SOA / NS / PTR / SRV**: reachable only through `send_dns_response`, the raw-hex escape
   hatch, which nothing drives with a real message.
3. **The 512-byte UDP limit**: still untested, and the server does not implement it — an
   oversize response is sent rather than truncated with the TC bit. The TXT character-string is
   bounded at 255 octets (`bounds_test.rs`), which makes the *common* route to a large answer
   impossible, but `send_dns_response` can still exceed 512.
4. **Malformed queries**: a datagram that does not parse is logged and dropped with no reply.
   `bounds_test.rs` covers the truncated-oversize case; a deliberately corrupt but short
   datagram is not tested, and there is no FORMERR path to assert.
5. **Concurrent queries**: sent sequentially throughout. The server handles them in separate
   tokio tasks; nothing asserts that two in flight do not cross their transaction ids.

### Consolidation opportunity

`test.rs`'s four tests could share one server, saving three startup calls and a few seconds.
The old version of this note put the saving at "~8-12 seconds" against a real model; against
the mock the whole file runs in about two, so this is tidiness rather than economy. The four
separate servers do buy clearer failure diagnosis.

### Scripting mode

A script handler for `dns_query` is what `get_startup_examples()` offers and what the protocol
is best at, and nothing here exercises it. `tests/empty_static_handler_test.rs` is the shape to
copy for the assertion that matters — a **zero** LLM-call count beside a non-zero control,
measured rather than inferred. The old note here proposed asserting a "1000x faster" throughput
improvement, which is not a thing a test can hold.

## References

- [RFC 1034: DNS Concepts](https://datatracker.ietf.org/doc/html/rfc1034)
- [RFC 1035: DNS Implementation](https://datatracker.ietf.org/doc/html/rfc1035)
- [hickory-client Documentation](https://docs.rs/hickory-client/latest/hickory_client/)
- [DNS Response Codes (IANA)](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-6)

## Two resolvers, and why the second one exists

`DevelopmentState::Stable` rests on **both**, and neither is `#[ignore]`d or skip-gated — each
fails naming its package when the binary is absent:

| test | resolver | project |
|---|---|---|
| `dig_test.rs` | `dig` | ISC BIND |
| `kdig_test.rs` | `kdig` | Knot DNS, CZ.NIC |

`test.rs` covers the same ground with hickory-client, which is useful and **circular on its
own**: hickory-client decodes with the same codec hickory-proto encoded with, so it proves the
wire format is self-consistent rather than correct.

`dig` already fixed that. The second resolver is here because **one client can agree with one
bug** — in September 2026 `etcd` and `grpc` each turned out to be doing exactly that, and in
both cases no conformant implementation could complete a successful call while every existing
test passed. Two independent resolvers agreeing with each other and with us is the strongest
evidence short of the spec; two that disagree is a finding.

Between them they decode **every record type this server can produce** — A, AAAA, CNAME, MX,
TXT and NXDOMAIN — each through that resolver's own presentation writer. Until September 2026
only A and TXT were covered, which left three actions the model is offered with nothing
independent having decoded them; `metadata()` said so and it was read as a note rather than as
a gap.

Nearly every query is run with `+noedns`, honestly rather than conveniently: this server does
not implement EDNS0, and a resolver that offers EDNS and gets a reply with no OPT record may
fall back and re-query — which would be a second `dns_query` event and would break
`expect_calls`. **One query is not**: `dig_test.rs` runs the A lookup a second time with no
flags at all, because "works against real clients" has to mean the way a person invokes the
client. RFC 6891 §6.1.1 is why it works — a server that does not understand EDNS answers with
no OPT record and the requestor treats it as non-EDNS — and `expect_at_least` on that rule is
what makes a fallback re-query harmless.

Verified by answering with a fixed transaction id instead of the client's: kdig discards the
reply and the test fails. That is the class of defect a round-trip through our own codec cannot
see, because our decoder does not care what id it reads.

**Unproven:** EDNS0, TCP transport, DNSSEC, zone transfers, and record types beyond A and TXT.

