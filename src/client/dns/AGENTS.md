# DNS Client Implementation

## Overview

DNS (Domain Name System) client for querying DNS servers. The LLM can send DNS queries for various record types and
interpret responses to make follow-up decisions.

**Status**: **Beta** since October 2026, on the client bar: ISC BIND `named` as the peer, see
`tests/client/dns/AGENTS.md`
**RFC**: RFC 1035 (Domain Names), RFC 3596 (AAAA), RFC 6891 (EDNS0), RFC 4035 (the DO bit),
RFC 5936 (AXFR), RFC 1995 (IXFR)
**Transport**: UDP for queries; a TCP connection per zone transfer

## Library Choices

- **hickory-client** (formerly trust-dns-client) - DNS client library
    - Async DNS client with UDP transport
    - Supports all standard DNS record types (A, AAAA, MX, TXT, CNAME, NS, SOA, PTR, SRV, etc.)
    - Handles DNS protocol encoding/decoding automatically
    - Provides high-level query API with RecordType enums

**Rationale**: hickory-client (part of hickory-dns ecosystem) is the de facto standard for DNS in Rust. It provides a
robust, async-first client implementation that abstracts away the DNS wire protocol complexity. The LLM only needs to
provide semantic query parameters (domain, type) and can work with structured response data (answers with type-specific
fields).

## Architecture

### 1. Query-Response Pattern

DNS client follows a simple request-response pattern:

1. LLM sends `send_dns_query` action with domain and query type
2. Client sends UDP packet to DNS server
3. Server responds with DNS answer records
4. Client parses response into structured JSON
5. LLM receives `dns_response_received` event with answers
6. LLM can send follow-up queries based on response

### 2. Event-Driven LLM Integration

Two events trigger LLM calls:

- **`dns_connected`** - Client connected to DNS server, LLM can send initial query
- **`dns_response_received`** - Response received, LLM can analyze answers and send follow-up queries

### 3. Record Type Support

Client supports all major DNS record types with structured parsing:

- **A** - IPv4 address
- **AAAA** - IPv6 address
- **CNAME** - Canonical name (alias)
- **MX** - Mail exchange (with preference)
- **TXT** - Text records
- **NS** - Name server
- **SOA** - Start of authority
- **PTR** - Pointer (reverse DNS)
- **SRV** - Service locator

Each record type is parsed into type-specific JSON fields (e.g., MX includes `exchange` and `preference`).

### 4. Recursive vs Iterative Resolution

The `recursion_desired` parameter (default: true) controls whether the DNS server should:

- **Recursive (true)**: Server resolves the full query by contacting other servers
- **Iterative (false)**: Server only provides referrals to other servers

Since October 2026 every query is a message built by hand and sent with `DnsHandle::send`,
not `ClientHandle::query`, so RD carries `recursion_desired` (it was accepted and ignored before)
and the OPT record carries the DO bit when `dnssec` is true.

### 5. Connection Model

Queries go over one UDP socket (hickory-client's `UdpClientStream`); each is independent.

A **zone transfer** (`send_dns_zone_transfer`) opens a TCP connection of its own to the same
server, sends hickory-proto's AXFR request (IXFR when given a serial) and reads the answer one
length-prefixed message at a time straight off the socket. It does not use hickory-client's
`zone_transfer`: that reads through a multiplexer which hands responses over with `try_send`
into a 32-slot channel and drops what does not fit, so a burst of messages lost most of them
and the transfer still reported success (109 of 202 in the test below). Read directly, a slow
reader only slows the server down. `XfrEnd` decides where the transfer ends with
hickory-client's own rules (the first SOA's serial; AXFR ends at the next SOA; IXFR on an even
count of SOAs closing on that serial); a transfer that does not open with an SOA, or carries
records after its closing SOA, is an error, and every message must carry the request's id.
The server address comes from the client's own `remote_addr`. A transfer is abandoned with an
error past `MAX_TRANSFER_RECORDS` (100 000), past `MAX_TRANSFER_BYTES` (64 MiB of DNS
messages), on the connection closing before the transfer ends, or after `TRANSFER_TIMEOUT`
(60 s). The byte bound is the one a hostile server meets: a record can be nearly 64 KiB, so
100 000 of them would be gigabytes. Only the first `MAX_REPORTED_RECORDS` (200) records are
kept — the rest are counted — and the model is shown those with the count, `truncated` saying
whether there were more. `tests/client/dns/transfer_bound_test.rs` drives the byte bound from a
hostile server and a 202-message burst that must arrive whole.

### 6. Action loop is iterative, not recursive (important)

`execute_dns_action` handles ONE action and *returns* whatever follow-up actions the
LLM asked for. `run_dns_actions` owns the work queue and drains it. Nothing calls
itself.

This used to be self-recursive — `execute_dns_action` awaited the LLM after a
response and then called itself for each follow-up. Each level is a separately
polled boxed future, so stack depth grew with the number of query/response rounds:
an LLM that never stopped asking for another query overflowed the stack after ~200
rounds and took the whole NetGet process down (`IMPROVEMENTS.md` item 49). With the
queue, stack depth is constant regardless of how many rounds occur.

**If you add another follow-up path here, return the actions — do not recurse.**

Convergence itself is a separate concern, handled by the per-client LLM call budget
(`src/client/llm_budget.rs`): after `NETGET_CLIENT_LLM_CALL_LIMIT` calls (default
100) `call_llm_for_client` fails instead of contacting the model, which drains the
queue and ends the session.

### 7. The conversation runs in a registered background task

`connect_with_llm_actions` spawns the connected-event LLM conversation rather than
running it inline, and registers both that task and the hickory transport driver
with `AppState::register_client_task()`. Two consequences:

- `connect()` returns as soon as the socket is up, instead of blocking until the
  LLM stops asking for queries (it previously never returned for a runaway client).
- `stop_client` / `remove_client` aborts both tasks, so the UDP socket is released
  and no further LLM calls happen.

## LLM Integration

### Available Actions

#### `send_dns_query`

Send a DNS query to the server.

**Parameters:**

- `domain` (required) - Domain name to query (e.g., "example.com")
- `query_type` (required) - Record type (A, AAAA, MX, TXT, CNAME, NS, SOA, PTR, SRV, etc.)
- `recursion_desired` (optional, default: true) - Request recursive resolution; sets RD
- `dnssec` (optional, default: false) - Set the DO bit; RRSIG and NSEC records come back in
  `answers` and `authority`

**Example:**

```json
{
  "type": "send_dns_query",
  "domain": "example.com",
  "query_type": "A",
  "recursion_desired": true
}
```

#### `send_dns_zone_transfer`

`{zone, serial?}` — AXFR, or with `serial` IXFR from that serial, over TCP. Answered by
`dns_zone_transfer_received`.

#### `disconnect`

Disconnect from the DNS server.

**Parameters:** None

### Events

#### `dns_connected`

Triggered when client connects to DNS server.

**Parameters:**

- `remote_addr` - DNS server address

#### `dns_response_received`

Triggered when DNS response is received.

**Parameters:**

- `query_id` - DNS transaction ID
- `domain` - Domain name queried
- `query_type` - Record type queried
- `answers` - Array of answer records (structured by type, each with `name` and `ttl`)
- `authority` - Authority records, when there are any (a negative answer's SOA, and with
  `dnssec` its NSEC proof)
- `response_code` - Response code (NOERROR, NXDOMAIN, SERVFAIL, etc.)
- `authenticated_data` - the AD bit; set only by a validating resolver, never by this client
- `truncated` - the TC bit

DNSSEC records are reported structurally: RRSIG as `type_covered`, `algorithm`, `key_tag`,
`signer`, `inception`, `expiration`; DNSKEY as `flags`, `algorithm`, `key_tag`,
`secure_entry_point`; NSEC as `next` and `types`; DS as `key_tag`, `algorithm`, `digest_type`.
No key or signature bytes. A type the client does not read is `TYPE<n>` with `rdata_length`.

#### `dns_zone_transfer_received`

`zone`, `transfer_type` (AXFR/IXFR), `form` — `full`, `incremental` (an IXFR difference,
recognised by RFC 1995 §4's rule that its second record is an SOA), `current` (the SOA alone)
or `none` — `serial`, `record_count`, `messages`, `records` (in transfer order), `truncated`
and `response_code`.

**Answer Structure Examples:**

A record:

```json
{
  "type": "A",
  "ip": "93.184.216.34",
  "ttl": 300
}
```

MX record:

```json
{
  "type": "MX",
  "exchange": "mail.example.com",
  "preference": 10,
  "ttl": 300
}
```

CNAME record:

```json
{
  "type": "CNAME",
  "target": "www.example.com",
  "ttl": 300
}
```

## Example Usage Scenarios

### Simple A Record Query

```
Instruction: "Query 8.8.8.8 for the A record of example.com"

Flow:
1. dns_connected event → LLM sends send_dns_query
2. dns_response_received → LLM sees {"type": "A", "ip": "93.184.216.34"}
3. LLM reports result to user
```

### Follow-the-CNAME

```
Instruction: "Resolve www.example.com and follow any CNAMEs"

Flow:
1. dns_connected → Query www.example.com A
2. dns_response_received → Answer is CNAME to cdn.example.com
3. LLM sends follow-up query for cdn.example.com A
4. dns_response_received → Answer is A record 192.0.2.1
5. LLM reports final IP
```

### MX Record Lookup

```
Instruction: "Find mail servers for example.com"

Flow:
1. dns_connected → Query example.com MX
2. dns_response_received → Multiple MX records with preferences
3. LLM sorts by preference and reports mail servers
```

### Reverse DNS

```
Instruction: "Do reverse DNS lookup for 8.8.8.8"

Flow:
1. dns_connected → Query 8.8.8.8.in-addr.arpa PTR
2. dns_response_received → PTR record points to dns.google
3. LLM reports hostname
```

## Known Limitations

### 1. Queries are UDP only

- Queries advertise a 1232-byte EDNS buffer, but a truncated answer (`truncated: true`) is
  reported, not retried over TCP. Zone transfers are TCP.

### 2. No DNSSEC Validation

- With `dnssec` the signatures and NSEC proofs are reported, not verified; `authenticated_data`
  is whatever the server said
- No TSIG on transfers

### 3. No Caching

- Client does not cache DNS responses
- Each query goes to the server (no local TTL tracking)
- LLM must manage its own caching logic if needed

### 4. Single Server Only

- Client connects to one DNS server
- No fallback to secondary servers
- No support for DNS server lists

### 5. No Query Pipelining

- Queries are executed sequentially in the LLM loop
- hickory-client supports concurrent queries internally
- But LLM must explicitly send multiple actions to parallelize

## Performance Characteristics

### Latency

- **DNS Query**: 10-100ms (depends on server and network)
- **LLM Processing**: 2-5 seconds per response
- **Total per query**: ~2-5 seconds

### Throughput

- **Limited by LLM**: ~0.2-0.5 queries per second
- hickory-client can handle thousands of QPS, but LLM is bottleneck
- Concurrent queries require LLM to generate multiple actions

### Scripting Compatibility

DNS is an excellent candidate for scripting:

- Deterministic query-response pattern
- Well-defined record types
- No complex state machine

With scripting enabled:

- Initial LLM call generates script (~1 call)
- All subsequent queries handled by script (~0 LLM calls)
- Dramatically improves throughput

## Implementation Details

### hickory-client Integration

```rust
// Create UDP client stream
let stream = UdpClientStream::<tokio::net::UdpSocket>::new(dns_server);
let (client, bg) = AsyncClient::connect(stream).await?;

// Spawn background task
tokio::spawn(bg);

// Send query
let response = client.query(name, DNSClass::IN, RecordType::A).await?;

// Parse answers
for answer in response.answers() {
    match answer.record_type() {
        RecordType::A => {
            if let Some(a) = answer.data().and_then(|d| d.as_a()) {
                println!("A: {}", a);
            }
        }
        // ... other types
    }
}
```

### Error Handling

- **Connection errors**: Reported as client status error
- **Query timeout**: hickory-client handles with default timeout (5 seconds)
- **NXDOMAIN/SERVFAIL**: Reported in response_code, not as error
- **Invalid domain**: Parsing error before query sent

### Memory Management

- Client holds `AsyncClient` in `Arc<Mutex<>>` for shared access
- Background task (`bg`) runs independently to handle I/O
- Each query creates a temporary future, no persistent state

## Testing Strategy

See `tests/client/dns/AGENTS.md` for detailed testing approach.

The evidence is `real_server_test.rs` against ISC BIND `named`; `e2e_test.rs` and
`command_channel_test.rs` use NetGet's own server and say so. Public resolvers are not used —
this repository forbids external endpoints.

## References

- [RFC 1034: Domain Names - Concepts and Facilities](https://datatracker.ietf.org/doc/html/rfc1034)
- [RFC 1035: Domain Names - Implementation and Specification](https://datatracker.ietf.org/doc/html/rfc1035)
- [hickory-dns Documentation](https://docs.rs/hickory-client/latest/hickory_client/)
- [DNS Record Types (IANA)](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4)

## Command channel (injected actions)

The client registers a `command_support` command channel, so `AppState::send_to_client` — the
dashboard's `[ send ]` — can execute an action inside the running client. The channel is
registered **before** the `dns_connected` LLM call, which a `*` → manual routing rule can park
for minutes.

The hickory `AsyncClient` moved out of the conversation task into an `Arc<Mutex<_>>` created in
`connect_with_llm_actions`, so the command loop queries through the **same** connected resolver
the LLM path uses rather than opening one of its own.

| Action | `ClientSendOutcome` |
|---|---|
| `send_dns_query` | `Executed { detail }` — see below |
| `wait_for_more` | `Executed` |
| `disconnect` | `Disconnected`; the command loop ends and the handle is dropped |
| anything else | `Rejected { error }` |

**Why a query reports `Executed` and not `Sent`.** hickory owns the wire encoding and the UDP
socket and reports no byte count, so there is no truthful number to hand back and a `Sent{n}`
here would be invented. The detail string carries what the caller actually wants instead —
`dns_query example.com A -> NOERROR with 1 answer(s)`. A network fault during the query is an
`Err`, distinct from `Rejected`, which is reserved for the model naming a verb this client does
not have.

`execute_dns_action` is now `apply_dns_action` (run the query, no LLM) plus
`report_dns_response` (hand the answers to the model, collect follow-ups). The split lets the
command loop answer its caller as soon as the resolver replies and report to the model
afterwards, so a manual rule parked on `dns_response_received` cannot hold `[ send ]` open for
its whole timeout. Follow-up actions from an injected query still go through
`run_dns_actions`, so the iterative work queue — and the stack-overflow fix it exists for —
covers the injected path too.
