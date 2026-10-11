# DNS Protocol Implementation

## Overview

DNS (Domain Name System) server implementing RFC 1035 over UDP and TCP (RFC 7766), with EDNS0
(RFC 6891), zone transfers (AXFR RFC 5936, IXFR RFC 1995) and DNSSEC signing of one zone
(RFC 4033-4035). The model answers with structured actions — single records, any number of
records of nine types, refusals, whole zones and their differences — and the server owns the
protocol around them: EDNS, truncation, transfer framing, keys, signatures and NSEC.

**Status**: **Stable**, set 16 September 2026. See "Maturity: the six conditions"
at the foot of this file for what was checked and what the rating does *not*
cover.
**RFC**: RFC 1035 (Domain Names), RFC 3596 (AAAA), RFC 1034 (Concepts), RFC 7766 (TCP),
RFC 6891 (EDNS0), RFC 5936 (AXFR), RFC 1995 (IXFR), RFC 4033-4035 (DNSSEC), RFC 9824 (compact
denial)
**Port**: 53, UDP and TCP on the same port, declared as `PrivilegeRequirement::PrivilegedPort(53)`

### What "Stable" covers here

Answers built by the structured actions are RFC 1035 responses that a real stub
resolver accepts: correct wire format, the client's transaction ID echoed, and
the question section repeated. Every record type the model can produce — A, AAAA,
CNAME, MX, TXT — plus NXDOMAIN is decoded by **two** independent resolvers, and
one query is run the way a person actually runs `dig`, with EDNS offered and no
flags.

**Since October 2026 it also covers TCP, EDNS0 with truncation, zone transfers and
DNSSEC**, each on its own evidence (see "TCP, EDNS, transfers and DNSSEC" below): `dig` and
`kdig` transfer, truncate-and-retry and decode every record type `send_dns_records` writes;
`delv` and `drill` validate signed answers; `ldns-verify-zone` and BIND's `dnssec-verify`
verify a whole signed zone received by AXFR. Until then this paragraph listed all five as
not implemented.

E2E coverage lives in `tests/server/dns/`: `test.rs` (note: `test.rs`, not
`e2e_test.rs` as most protocols use), `dig_test.rs`, `kdig_test.rs`,
`llm_failure_test.rs` and `bounds_test.rs` — **13 tests, all passing**. This
line said "six" and listed three files, which was correct before `kdig_test.rs`
and `bounds_test.rs` existed and is the sort of count that goes stale the moment
a file is added; derive it with `cargo test --features dns --test server -- dns`
rather than reading it here. (Earlier still, this file claimed the four in
`test.rs` "currently fail before they reach the DNS layer" over a
`DocumentationRequired` retry, which was already stale when it was written.)

**`dig_test.rs` and `kdig_test.rs` are what make the Stable rating mean something.**
`test.rs` drives the server with hickory-client while the server encodes with
hickory-proto - the same project, the same codec - so on its own it proves the
wire format self-consistent rather than correct. That is the circularity that
kept `rss` at Experimental until `feed-rs` did its parsing. ISC BIND's `dig` and
Knot DNS's `kdig` share no code with hickory or with each other, each checks that
the transaction id it chose comes back and that the question matches what it
asked, and each **fails rather than skipping** when its binary is absent (the
`npm` precedent). See "Two resolvers, and why the second one exists" below.

## Library Choices

- **hickory-proto** (formerly trust-dns) - DNS protocol parsing and construction
    - Used for parsing incoming DNS queries
    - Used for constructing DNS response messages
    - Handles binary DNS wire format automatically
    - Provides high-level Record, RData, Message types

**Rationale**: hickory-proto is the de facto standard for DNS in Rust. It provides robust parsing/serialization and
eliminates the need for manual binary protocol handling. The LLM doesn't need to understand DNS binary format - it just
provides semantic data (domain, IP, TTL) and the library handles encoding.

## Architecture Decisions

### 1. Action-Based LLM Control

The LLM doesn't manipulate raw DNS packets. Instead, it returns semantic actions like:

- `send_dns_a_response` - Return IPv4 address for domain
- `send_dns_aaaa_response` - Return IPv6 address for domain
- `send_dns_mx_response` - Return mail exchange record
- `send_dns_txt_response` - Return text record
- `send_dns_cname_response` - Return canonical name alias
- `send_dns_nxdomain` - Domain does not exist
- `send_dns_response` - Send raw hex packet (advanced)
- `ignore_query` - No response

Each action includes required fields (query_id, domain, record data) and optional fields (TTL).

### 2. Stateless Request-Response

Each query is answered on its own, over UDP or TCP:

- Each query is independent; a TCP connection is only a framing of several
- No state between queries but the signing key
- "Connection" in UI is one UDP query, or one TCP connection
- Query ID from client packet must be echoed in response

The server keeps `.connectionless()`: the 10-second sweep can drop a TCP connection's UI entry
while the connection waits, but nothing the connection does depends on the entry, and its
own idle timeout (decision 6) is what closes it.

### 2b. Responses Echo the Question Section

Every response built by the structured actions repeats the question it answers
(RFC 1035 §4.1.2). This is not cosmetic: real stub resolvers - glibc's,
systemd-resolved, `dig` - compare the response's question section against the
query they sent and discard responses that do not match. The question is
reconstructed in `new_response()` (`actions.rs`) from the action's `domain` plus
the record type implied by the action, so `send_dns_a_response` produces a
`domain A IN` question. `send_dns_nxdomain` and `send_dns_cname_response` accept
an optional `query_type` because the type cannot be inferred from the answer in
those two cases.

Consequence for the two ID-bearing fields the client uses to correlate a
response:

- `query_id` - taken verbatim from the action. Out-of-range values are rejected
  rather than truncated with `as u16`, because a truncated ID produces a
  response the client silently drops.
- question section - as above.

Both are why a **static** event handler cannot serve DNS answers: static
handlers emit fixed action JSON with no access to the event, so they cannot echo
either the client's random transaction ID or the queried name. Use **script**
mode for deterministic DNS; static mode is only useful here for `ignore_query`
(a DNS blackhole).

### 3. hickory-proto Integration

Parsing flow:

1. Receive UDP datagram
2. Parse with `DnsMessage::from_vec()`
3. Extract query ID, domain name, query type, query class
4. Send to LLM as `dns_query` event
5. LLM returns action with semantic data
6. Action executor builds `DnsMessage` response
7. Serialize with `message.to_vec()`
8. Send UDP datagram back to client

### 4. Dual Logging

- **DEBUG**: Query summary ("DNS query: example.com A IN")
- **TRACE**: Full hex dump of DNS packets (both request and response)
- Both go to netget.log and TUI Status panel

### 5. Connection Tracking

Each DNS query creates a "connection" entry in ServerInstance:

- Connection ID: Unique per query
- Protocol info: `ProtocolConnectionInfo::empty()` - there is no DNS-specific
  variant, so no per-query domain list is surfaced to the UI
- Tracks: bytes received/sent, packets received/sent (sent counters are updated
  via `AppState::update_connection_stats` after the response goes out)
- Status: Immediately active, no persistent state

### 6. TCP, EDNS, transfers and DNSSEC (October 2026)

**One answer path, two transports.** `mod.rs::answer` parses the query and decides; the UDP
loop sends its first message, the TCP loop (`tcp_connection`) frames every message with a
two-byte length (RFC 1035 §4.2.2) and answers queries on a connection in order. TCP binds the
port UDP got, so `port: 0` yields one port for both. A connection is closed after
`tcp_idle_timeout_secs` (default `DEFAULT_TCP_IDLE_TIMEOUT`, 10 s) with no query, and past
`MAX_TCP_CONNECTIONS` (64) a new one is closed unread (`decision=fail_closed_connection_cap`).
One address may hold at most `MAX_TCP_CONNECTIONS_PER_IP` (8, `tcp_connections_per_ip` 1-64)
of them — IPv6 counted per /64, an IPv4-mapped address as its IPv4 address — and one more from
it is closed unread too (`decision=fail_closed_per_source_cap`). Without it one host could hold
every slot, cheaply, since some messages are answered without the model.

**What happens after the model answers** (`Reply::finish`), in order:

1. **DNSSEC**, when `dnssec_zone` names a zone covering the question and the query set DO:
   every in-zone RRset in the three sections gets an RRSIG; a negative answer (NXDOMAIN, or
   NOERROR with no answers) gets the zone's SOA if the model gave none, plus a compact-denial
   NSEC at the queried name (next name `\000.<qname>`, types RRSIG and NSEC), and NXDOMAIN
   becomes NOERROR — the documented cost of compact denial.
2. **EDNS**: a query with an OPT gets one back advertising `EDNS_UDP_SIZE` (1232) and echoing
   DO; a query without one never does (RFC 6891 §6.1.1).
3. **Truncation**: over UDP, an answer larger than the client can take — 512 bytes without
   EDNS, its advertised size with, never more than `MAX_UDP_RESPONSE` (4096) — is replaced by
   header, question and OPT with TC set (`decision=truncated`), and the client retries over TCP.

**Zone transfers** raise `dns_zone_transfer {query_id, zone, transfer_type, client_serial,
transport, signed, client_ip, client_port}` — the client's serial comes from the SOA in its
query's authority section, never from the model, and its address is in the event data so the
instructions' "only to these clients" is a decision the model can make (there is no ACL in the
server; see Known Limitations). AXFR over UDP is NOTIMP without asking (RFC 5936 §4.2). The
model answers with `send_dns_zone` (the whole zone; also a legal answer to IXFR),
`send_dns_ixfr` (changes since the client's serial, or none for "current"), or
`send_dns_refused`. Neither transfer action builds wire bytes — a zone does not fit one
message — so the executor validates and hands back the action, and `transfer.rs` builds the
RFC sequence and cuts it into messages of about `TRANSFER_MESSAGE_BYTES` (16 KiB). Over UDP
`send_dns_zone` is **always** answered with the SOA alone (RFC 1995 §2's "ask again over
TCP", `decision=udp_soa_only`), however small the zone: a UDP source address can be forged,
so a full zone is never sent to one. A `send_dns_ixfr` difference goes over UDP when it fits,
and is replaced by the new SOA alone when it does not.

**Signing a zone** (`dnssec.rs`): one ECDSA P-256 key (algorithm 13) generated at startup,
flags 257, acting as KSK and ZSK — RFC 6781's single-type signing. The server answers the
zone's DNSKEY query itself (`decision=spec_reply`). An AXFR of the signed zone carries the
DNSKEY, a full NSEC chain over every owner name in canonical order, and an RRSIG for every
RRset; delegations (NS below the apex) are refused, because their glue would need to stay
unsigned. A signed zone's IXFR may be "current" but not a difference — a difference would
carry no signatures — so a `send_dns_ixfr` with changes fails closed to SERVFAIL.
Signatures run from an hour before signing to seven days after; the key lives as long as the
server, so a validator's trust anchor is built from the DNSKEY it serves.

`records.rs` is the record shape every new action shares — A, AAAA, CNAME, NS, PTR, MX, TXT
(a string or an array of up to-255-octet strings), SRV and SOA, names absolute, relative to a
zone, or `@` — and the reason NS, SOA, PTR and SRV no longer need `send_dns_response`.

## LLM Integration

### Event Type

**`dns_query`** - Triggered when DNS client sends a query

Event parameters:

- `query_id` (number) - DNS transaction ID from request packet
- `domain` (string) - Domain name being queried
- `query_type` (string) - Record type (A, AAAA, MX, TXT, CNAME, etc.)
- `transport` (string) - `udp` or `tcp`, informational
- `dnssec_ok` (boolean) - the DO bit, informational: signing is the server's
- `client_ip` (string), `client_port` (number) - where the query came from; over UDP
  unauthenticated

**`dns_zone_transfer`** - an AXFR or IXFR, carrying `client_ip` and `client_port` like
`dns_query`; see architecture decision 6. Its actions are
`send_dns_zone`, `send_dns_ixfr`, `send_dns_refused` and `ignore_query` (which, on TCP,
sends nothing and keeps the connection).

### Available Actions

#### `send_dns_a_response`

Return IPv4 address (A record).

Parameters:

- `query_id` (required) - Echo from request
- `domain` (required) - Domain name
- `ip` (required) - IPv4 address string (e.g., "192.0.2.1")
- `ttl` (optional) - Time-to-live in seconds (default: 300)

#### `send_dns_aaaa_response`

Return IPv6 address (AAAA record).

Parameters:

- `query_id` (required)
- `domain` (required)
- `ip` (required) - IPv6 address string (e.g., "2001:db8::1")
- `ttl` (optional, default: 300)

#### `send_dns_mx_response`

Return mail exchange record.

Parameters:

- `query_id` (required)
- `domain` (required)
- `exchange` (required) - Mail server domain (e.g., "mail.example.com")
- `preference` (optional) - Priority, lower = higher priority (default: 10)
- `ttl` (optional, default: 300)

#### `send_dns_txt_response`

Return text record.

Parameters:

- `query_id` (required)
- `domain` (required)
- `text` (required) - Text data to return, **at most 255 octets**: it is emitted
  as a single DNS `<character-string>`, whose length is one octet (RFC 1035
  §3.3). Longer text is refused with a message naming the limit, rather than
  split across strings or left to fail inside hickory's encoder — see Bounds
- `ttl` (optional, default: 300)

#### `send_dns_cname_response`

Return canonical name (alias).

Parameters:

- `query_id` (required)
- `domain` (required)
- `target` (required) - Target domain name
- `ttl` (optional, default: 300)

#### `send_dns_nxdomain`

Domain does not exist.

Parameters:

- `query_id` (required)
- `domain` (required)
- `query_type` (optional, default: `A`) - echoed in the question section so the
  client can match the (answer-less) response to its query

#### `send_dns_records`

Any number of records (at most `MAX_ANSWER_RECORDS`, 100) in the answer, authority and
additional sections, with any RCODE (NOERROR by default, NXDOMAIN, REFUSED, SERVFAIL, NOTIMP,
FORMERR). Types A, AAAA, CNAME, NS, PTR, MX, TXT, SRV, SOA in the shared shape of
`records.rs`; an answer record without `name` takes the queried domain.

#### `send_dns_refused`

REFUSED, echoing the question — the answer to a transfer the instructions do not allow.

#### `send_dns_zone` / `send_dns_ixfr`

Zone-transfer answers; see architecture decision 6. Offered only on `dns_zone_transfer`, and
not forwarded to DoH, DoT or DoQ, which take `DnsProtocol::query_actions()`.

#### `send_dns_response` (Escape hatch)

Send a complete, hand-assembled DNS response message, hex-encoded. Intended only
for record types neither a dedicated action nor `send_dns_records` writes (CAA, NAPTR, ...).
The bytes are parsed and go out re-encoded through the same finish as every other answer
(OPT for an EDNS query, signing, UDP truncation). Bytes that do not parse as a DNS message are
never sent: the query is answered SERVFAIL (`decision=fail_closed_unparseable_answer`, ERROR).
Sent as given they skipped truncation, and over TCP a message past 65535 octets wrapped its
two-byte length prefix.

- `data` must be valid hex and at least 12 bytes (a DNS header). Invalid hex is
  rejected with an error. There is no plain-text fallback: the earlier behaviour
  of sending the raw string bytes when hex decoding failed put non-DNS garbage
  on the wire and left clients timing out with no diagnostic.
- The caller is responsible for the transaction ID and the question section;
  nothing is filled in.

Note: this is the one DNS action that takes wire bytes as a parameter, which
runs against the project rule that action parameters carry structured data
rather than encoded bytes. It is kept because dropping it would leave the
unsupported record types unreachable, and its description steers the model to
the structured actions first.

#### `ignore_query`

Don't send any response to this query.

### Example LLM Response

```json
{
  "actions": [
    {
      "type": "send_dns_a_response",
      "query_id": 12345,
      "domain": "example.com",
      "ip": "93.184.216.34",
      "ttl": 300
    },
    {
      "type": "show_message",
      "message": "Resolved example.com to 93.184.216.34"
    }
  ]
}
```

## Connection Management

### Connection Lifecycle

1. **Query Received**: a UDP datagram, or a TCP connection accepted, on port 53
2. **Register**: New ConnectionId created for this query (UDP) or this connection (TCP)
3. **Track**: Added to ServerInstance.connections with:
    - `ProtocolConnectionInfo::empty()`
    - bytes_received, packets_received = 1
4. **Process**: Parse query, dispatch through `call_llm` (which first tries any
   configured script/static event handler and only falls back to a model call if
   none matches), execute action
5. **Respond**: Send the UDP response, or every framed message of a TCP answer
6. **Update**: Track bytes_sent, packets_sent
7. **Persist**: Connection remains in UI to show recent activity

Note: over UDP each query-response is independent; over TCP a connection lasts until the
peer closes it or it is idle for `tcp_idle_timeout_secs`.

## Bounds

Every number this server enforces, and where. `tests/server/dns/bounds_test.rs`
drives each one and each doc comment there records what the failure looked like
with the bound removed — a bound nobody tested is a comment.

| bound | value | where | how it is driven |
|---|---|---|---|
| receive buffer | 4096 | `mod.rs` | a socket: an 8 KiB query is dropped and never becomes a prompt |
| `query_id` | 0-65535 | `parse_query_id` | the executor; refused, never narrowed with `as u16` |
| MX `preference` | 0-65535 | `execute_send_dns_mx_response` | the executor |
| raw message floor | 12 octets | `execute_send_dns_response` | the executor |
| TXT character-string | 255 octets | `MAX_CHARACTER_STRING_LEN` | the executor |
| open TCP connections | 64 | `MAX_TCP_CONNECTIONS` | `transport_bounds_test.rs`: the 65th is closed unread |
| open TCP connections per address | 8, `tcp_connections_per_ip` 1-64 | `MAX_TCP_CONNECTIONS_PER_IP` | `security_test.rs`: the 9th from 127.0.0.1 is closed unread |
| full zone over UDP | the SOA alone | `build_axfr` | `security_test.rs`: a zone that fits is still not sent |
| model-supplied bytes | must parse as DNS, else SERVFAIL | `query`, `transfer` | `security_test.rs`: 12 and 70 012 unparseable bytes, UDP and TCP |
| TCP idle | 10 s, `tcp_idle_timeout_secs` 1-300 | `DEFAULT_TCP_IDLE_TIMEOUT` | `transport_bounds_test.rs` at 1 s |
| UDP answer | 512 / EDNS size / at most 4096 | `PLAIN_UDP_LIMIT`, `MAX_UDP_RESPONSE` | `transport_bounds_test.rs` |
| records in one answer | 100 | `MAX_ANSWER_RECORDS` | the executor |
| records in one transfer | 10 000 | `transfer::MAX_ZONE_RECORDS` | the executor |
| transfer message | ~16 KiB | `transfer::TRANSFER_MESSAGE_BYTES` | `split_into_messages` directly |

**DNS declares no `max_inbound_bytes`**, and that is deliberate rather than an
omission: it is a "fixed-size read" entry in
`tests/max_inbound_bytes_declaration_test.rs`'s baseline. Over UDP the allocation is a
compile-time constant; over TCP the two-byte length prefix is the ceiling (65535), which
that file calls a structural bound. Neither has a constant a declaration could move.

What the buffer guarantees is weaker than a refusal and is worth stating
plainly: `recv_from` discards whatever does not fit, so an over-large datagram is
**truncated**, then fails to parse as DNS, then is dropped with a WARN. No
allocation and no prompt scales with what the peer sent, which is the property
`max_inbound_bytes` exists for; the peer gets no diagnostic, which CoAP's 4.13
does give. There is nothing honest to echo — the truncated bytes may not even
contain a complete question section.

## Known Limitations

### 1. DNSSEC is one zone, one key, NSEC

- One `dnssec_zone` per server, signed with one ECDSA P-256 key acting as KSK and ZSK.
  `dnssec-verify` is run with `-z` for that reason.
- NSEC only: no NSEC3. Negative answers use compact denial, so NXDOMAIN reads as NOERROR.
- No delegations in a signed zone, and no DS for a child.
- The key lives as long as the process; a restart is a key rollover with no overlap.

### 2. Transfers trust whoever asks the model

- There is no TSIG and no ACL in the server: whether a client may transfer a zone is the
  model's decision (`send_dns_refused`), as everything else is. The event names the client's
  address (`client_ip`, `client_port`) so the instructions can say who is allowed; over UDP
  that address is unauthenticated, which is why a full zone never goes over UDP.
- A signed zone answers IXFR only with the full zone or "current".

### 3. `send_dns_response` is checked only for being a DNS message

- Its hand-assembled bytes must parse, and are re-encoded, signed and truncated like any other
  answer; nothing checks that they answer the question asked (the transaction ID and question
  section are the caller's).

### 4. No DNS COOKIEs (RFC 7873)

- A COOKIE option in a query is ignored and none is returned.

### 5. No Zone File Support

- No authoritative zone data storage
- LLM generates responses on-demand
- No persistent DNS database

### 6. No Recursive Resolution

- Acts only as authoritative server
- Doesn't forward queries to upstream resolvers
- Doesn't perform recursive lookups

## Example Prompts

### Simple A Record Server

```
listen on port 53 via dns
Respond to all A record queries for example.com with IP 93.184.216.34
For all other domains, return NXDOMAIN
```

### Multi-Record Server

```
listen on port 53 via dns
For example.com:
  - A record: 93.184.216.34
  - AAAA record: 2001:db8::1
  - MX record: mail.example.com with priority 10
  - TXT record: v=spf1 mx ~all
For mail.example.com:
  - A record: 93.184.216.35
For unknown domains, return NXDOMAIN
```

### Wildcard DNS

```
listen on port 53 via dns
For any subdomain of example.com, return CNAME pointing to www.example.com
For www.example.com, return A record 93.184.216.34
```

### Custom TTL

```
listen on port 53 via dns
Respond to A queries for example.com with 93.184.216.34 and TTL of 3600 seconds
```

## Performance Characteristics

### Latency

- **With Scripting**: Sub-millisecond response (script handles query directly)
- **Without Scripting**: 2-5 seconds (one LLM call per query)
- hickory-proto parsing: ~10-50 microseconds
- hickory-proto serialization: ~10-50 microseconds

### Throughput

- **With Scripting**: Thousands of queries per second (CPU-bound)
- **Without Scripting**: Limited by LLM response time (~0.2-0.5 QPS)
- Concurrent queries processed in parallel (separate tokio tasks)
- Concurrency is bounded by `--llm-max-concurrent` / `--llm-queue-timeout` /
  `--llm-max-queued`. This line used to read "Ollama lock serializes LLM API
  calls"; there is no such lock. `--ollama-lock` is parsed and read by nothing,
  its six plumbing hops were deleted, and `tests/ollama_lock_is_a_noop_test.rs`
  fails if anything starts reading it again. Do not reason about DNS concurrency
  from it.

### Scripting Compatibility

DNS protocol is excellent candidate for scripting:

- Repetitive request/response pattern
- Deterministic responses based on domain/query type
- No complex state machine
- High query volume typical use case

What that looks like in practice:

- One LLM call at startup, in which the model writes a `script` `event_handlers`
  entry for `dns_query` (see `get_startup_examples()`, which offers exactly that
  script)
- Every subsequent query is answered in-process by the script, with **zero** LLM
  calls, because `try_execute_event_handler` runs before the model is reached
- Dramatically improves throughput

This is the model choosing to write a handler, not something NetGet does on its
own. This section used to read "Server startup generates Python/JavaScript
script (1 LLM call)" as though it were automatic; `--no-scripts` /
`ScriptingMode::Off` only takes the option away, it does not mean the option is
otherwise taken.

## References

- [RFC 1034: Domain Names - Concepts and Facilities](https://datatracker.ietf.org/doc/html/rfc1034)
- [RFC 1035: Domain Names - Implementation and Specification](https://datatracker.ietf.org/doc/html/rfc1035)
- [RFC 3596: DNS Extensions to Support IPv6 (AAAA)](https://datatracker.ietf.org/doc/html/rfc3596)
- [hickory-dns Documentation](https://docs.rs/hickory-proto/latest/hickory_proto/)
- [DNS Query Types (IANA)](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4)

## Failure behaviour: SERVFAIL, never silence

A query that produces no answer is answered with **SERVFAIL (RCODE 2)** rather than dropped.
`actions::build_servfail` copies the transaction ID and the question section off the request and
clears AA; a stub resolver that gets this stops waiting and moves to the next nameserver, where
silence costs it a full per-server timeout (5s in glibc) first.

**Three paths reach it, and until September 2026 only two did.** This section said "when
`call_llm` returns `Err` — backend down, overloaded, **or no usable response**". The third
clause was false: `call_llm` returns **`Ok`** whenever the model produced a syntactically valid
answer, and `protocol_results` is empty whenever that answer was made only of *common* actions
(`show_message`) or of a DNS action `execute_action` refused — an invalid IP, an out-of-range
`query_id`, a TXT string over 255 octets. The result loop then ended having written nothing and
the `Err` arm was never reached, so the one case the sentence claimed to cover was the one that
went silent. `send_servfail` is now the single exit for all three:

| `decision=` | cause | level |
|---|---|---|
| `model_answer` | an answer was written | DEBUG |
| `model_silent` | `ignore_query` — the model chose a black hole, a real decision | DEBUG |
| `fail_closed_no_action` | the model answered with nothing this server could send | **ERROR** |
| `fail_closed_llm_error` | the backend failed | WARN |
| `fail_closed_llm_overload` | the backend was overloaded (`is_overload_error`) | WARN |

`model_silent` and `fail_closed_no_action` are the pair that has to stay distinct: both begin
as "no bytes were produced", and only the first is something the operator asked for.
`tests/server/dns/llm_failure_test.rs::test_dns_distinguishes_no_usable_action_from_a_deliberate_black_hole`
drives both against one server for that reason — a fix that answered SERVFAIL to everything
would pass half of it.

The ID and question echo are not optional decoration: a resolver discards a response that fails
either check, which turns the SERVFAIL back into silence. See §2b above — this is the same
requirement the successful actions have, and it regressed once before (`6a384617`).

Covered by `tests/server/dns/llm_failure_test.rs`, which asserts the RCODE nibble on the raw
bytes as well as through a decoder, and runs the pcap oracle over both replies.

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

## Maturity: the six conditions

(This heading read "…, and which one is missing" above a table whose every row says **yes**. It
was left over from the pass that began before condition 4 was satisfied; a reader skimming
headings would have taken the opposite of what the section says.)

The root `AGENTS.md` defines `Stable` as six conditions. Re-derived against source on
16 September 2026 rather than inherited:

| # | condition | holds? |
|---|---|---|
| 1 | two independent third-party clients, no skip, no `#[ignore]` | **yes** — `dig` (ISC BIND) and `kdig` (Knot DNS, CZ.NIC), each hard-failing by name; between them they decode every record type this server can produce, and `dig` additionally runs one query with default flags |
| 2 | the pcap oracle is green over its wire traffic | **yes** — `llm_failure_test.rs` over both SERVFAIL paths, `bounds_test.rs` over a NOERROR answer with rdata |
| 3 | a fuzz target exists and has run clean, with a corpus | **yes** — `fuzz/fuzz_targets/dns_message.rs`; 2,777,883 runs in 91s clean, corpus includes `compression_pointer_loop` |
| 4 | every declared bound has a test | **yes, as of this pass** — see Bounds above, each verified by removal |
| 5 | both `AGENTS.md` files verified against source in this pass | **yes** — this file and `tests/server/dns/AGENTS.md` |
| 6 | no `#[ignore]`, no skip-when-missing gate | **yes** — `grep -rn '#\[ignore\]' tests/server/dns/` is empty |

**The October 2026 surface — TCP, EDNS, transfers, DNSSEC — holds the same six on its own
evidence:**

| # | condition | for TCP, EDNS, transfers and DNSSEC |
|---|---|---|
| 1 | two independent clients | `dig` and `kdig` (`transfer_test.rs`): AXFR of 611 records in two messages, IXFR difference and "current", TC and the retry over TCP, the OPT record, NS/SOA/SRV/PTR. For DNSSEC two validators and two zone verifiers (`dnssec_test.rs`): `delv` (positive, NXDOMAIN, NODATA, all "fully validated") and `drill` ("Chase successful"); `ldns-verify-zone` ("Zone is verified and complete") and `dnssec-verify -z`. Each fails rather than skips |
| 2 | pcap oracle | `transport_bounds_test.rs` hands every UDP and TCP exchange to tshark |
| 3 | fuzz target | `dns_message.rs` also reads the OPT and the authority SOA, with two new seeds; the crate compiles, and the target body ran clean over 2M mutated inputs on stable (no nightly where it was written) |
| 4 | every bound tested | the Bounds table; the TCP cap, the UDP cap, the answer RRSIGs and the NSEC chain were each removed and a test failed |
| 5 | both `AGENTS.md` | rewritten with the code |
| 6 | no ignore, no skip | unchanged |

`dig_test.rs` and `kdig_test.rs` still pass `+noedns`; they predate EDNS here, and the point
they make — the original record types decode — does not depend on it. `transfer_test.rs` runs
with EDNS on.

**Two things about condition 1 were checked in this pass rather than assumed, because on the
face of it they were the reasons to withhold the rating.**

*Only A and TXT had independent evidence.* `metadata()` said so — "UNPROVEN: … record types
beyond A and TXT" — which left `send_dns_aaaa_response`, `send_dns_mx_response` and
`send_dns_cname_response` as actions the model is offered with nothing independent ever having
decoded them. A 16-octet address, a `u16` followed by a domain name, and a bare domain name are
three different ways to get an encoder wrong, and an MX preference is the only integer rdata
field in the whole action set. Both resolvers now read all three; the preference is 4660
(0x1234), so a byte-swap reads 13330 rather than something plausible.

*Every query was run with `+noedns`.* The reason given was honest but narrow — EDNS0 is not
implemented, and a resolver that offers EDNS and gets a reply with no OPT record *may* fall back
and re-query, which breaks `expect_calls(1)`. It left unasked the question that actually decides
the rating: does a resolver, invoked the way a person invokes it, get an answer at all? Every
modern resolver sends EDNS by default, so if the answer were no then "works against real
clients" would be a claim about a configuration nobody uses — the `mysql_native_password`
situation, where the rating rested on the one client permissive enough to tolerate what ships.
It is not: RFC 6891 §6.1.1 says a server that does not understand EDNS answers without an OPT
record and the requestor treats the response as coming from a non-EDNS server, and
`dig_test.rs` now runs one query with no flags to prove it. The A rule's expectation is
`expect_at_least` so a fallback re-query is harmless rather than a failure.

### What Stable does *not* mean here

It means the evidence for the implemented surface is complete. Until October 2026 that surface
was plain UDP DNS with one record per answer; it is now UDP and TCP with EDNS0, truncation,
multi-record answers, AXFR/IXFR and DNSSEC for one zone. What it still is not — NSEC3, several
signed zones, a split KSK/ZSK, delegations under signing, TSIG, COOKIEs — is in Limitations.

The `openvpn` precedent is the one to check this against, and it does not apply: openvpn stays
Experimental because it implements only the front of the protocol, so no client can use it for
what the protocol is for. A resolver can use this for what DNS is for — two of them did, over
every record type it offers, one of them with default flags.

**Condition 3 is the one to re-check before trusting this table.** Nothing in CI builds
`fuzz/` — it is deliberately its own workspace, so `cargo check` at the repository root never
sees it — and the CoAP target was found in this pass to have been uncompilable since
15 September 2026. Rebuild rather than assume:

```bash
cd fuzz && rustup run nightly-2025-12-04 cargo fuzz build dns_message
```

(`cargo +nightly fuzz` does not work on this machine: asdf's shims precede `~/.cargo/bin` on
`PATH`, so `cargo` is not the rustup proxy and `+toolchain` is read as a subcommand name.)

## Choosing the record action by `query_type`

Told to "answer text queries for hello.test with the text netget-eval-ok", llama3.1:8b once
answered the TXT query with `send_dns_a_response` (`dns/txt-record` 4/5 in the committed eval
baseline). The `query_type` event parameter now maps each type to its action, and
`send_dns_a_response` / `send_dns_txt_response` each say which query type they answer. Wording
only: no executor changed, so the Stable evidence (`e2e_testing`, the six conditions below) is
unaffected. With seed 42 the case is 5/5.

