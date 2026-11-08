# DNS-over-HTTPS (DoH) Protocol Implementation

## Overview

DNS-over-HTTPS server implementing RFC 8484 for secure DNS queries over HTTPS transport. The LLM controls DNS responses
while NetGet handles HTTPS server operations, TLS encryption, and HTTP/2 protocol.

**Status**: **Stable**, set November 2026. See "Maturity: the six conditions" at the foot of
this file for what was checked and what the rating does *not* cover.
**RFC**: RFC 8484 (DNS Queries over HTTPS), RFC 1035 (DNS), RFC 7540 (HTTP/2)
**Port**: 443 (HTTPS, typically), declared as `PrivilegeRequirement::PrivilegedPort(443)`

### What "Stable" covers here

DoH contributes the HTTPS/HTTP2 transport and the RFC 8484 request encodings; every DNS
semantic — the action set, action execution, and what is sent after the model answers — is the
DNS server's, reached through delegation and `dns::StreamQuery` (see below). Two independent
resolvers, kdig and dig, complete GET and POST sessions over ALPN-negotiated HTTP/2 and read
every record type the actions write; every bound has a test (`tests/server/doh/bounds_test.rs`,
`connection_bounds_test.rs`). Not covered: HTTP/1.1, CA-signed or custom certificates, rate
limiting, caching.

### ALPN

The listener advertises **`h2`**, via
`tls_cert_manager::generate_default_tls_config_with_alpn(&["h2"])` rather than the shared
`generate_default_tls_config()` — `dot`, `tls` and `quic` are built from that default and
document themselves as ALPN-less, so it must stay that way for them.

It advertised nothing until August 2026, and this server speaks only HTTP/2. A client that
negotiates normally therefore had no way to learn the protocol: it fell back to HTTP/1.1 and
hyper's `http2::Builder` rejected the connection with "http2 error", or it refused outright.

**The E2E test could not have caught this**, because `create_insecure_client()` uses
`http2_prior_knowledge()`, which asserts HTTP/2 out of band and skips ALPN entirely. Dropping
that option does not fix the coverage either: under `danger_accept_invalid_certs` reqwest builds
its own rustls `ClientConfig` that does not offer `h2`, so it simply sends HTTP/1.1 and fails.
`server_advertises_h2_alpn` covers the property directly instead, and also asserts the shared
default is still ALPN-less so this cannot be "fixed" by changing it under the other three.

kdig and dig both negotiate `h2` by ALPN and complete real queries (`real_client_test.rs`).

## Library Choices

- **hickory-proto** (formerly trust-dns) - DNS protocol parsing and construction
    - Reuses DNS wire format handling from standard DNS implementation
    - Parses queries and constructs responses
    - Handles all DNS record types (A, AAAA, MX, TXT, CNAME, etc.)
- **hyper** - HTTP/2 server implementation
    - Async HTTP server with HTTP/2 support
    - Handles request routing and response generation
    - Service-based architecture for request handling
- **tokio-rustls** - Async TLS server implementation
    - Provides TLS acceptor for TCP streams
    - Uses rustls for TLS protocol
    - Self-signed certificates generated automatically
- **base64** - Base64url encoding/decoding
    - Required for GET method (DNS query in URL parameter)
    - URL-safe encoding without padding

**Rationale**: DoH is DNS delivered over HTTP/2 with TLS. By combining hickory-proto (DNS), hyper (HTTP/2), and
tokio-rustls (TLS), we get a complete secure DNS over HTTPS solution. The LLM focuses on DNS semantics while libraries
handle HTTP and encryption.

## Architecture Decisions

### 1. Delegation to DNS Protocol

DoH defines **no actions of its own**. `DohProtocol` wraps a `DnsProtocol` and
forwards everything DNS-shaped to it:

- `get_sync_actions()` / `get_async_actions()` return the DNS action definitions
  verbatim
- `execute_action()` forwards to `DnsProtocol::execute_action`
- `DOH_QUERY_EVENT` is built by calling `DnsProtocol::get_sync_actions()` and
  attaching that list to the event

The only thing DoH owns is the event type (`doh_query`, one event, carrying
extra `peer_addr` and `method` fields) and the transport. So "DoH has zero
actions defined in `src/server/doh/actions.rs`" is true as a grep result and
misleading as a statement about capability: the LLM sees the full DNS action set
on every `doh_query`, and this delegation is what keeps DNS, DoT and DoH
answering identically.

### 2. HTTP/2 Transport Layer

Connection flow:

1. Accept TCP connection on port 443
2. Perform TLS handshake using self-signed certificate
3. Establish HTTP/2 connection over TLS
4. Handle HTTP requests (GET or POST) to `/dns-query` endpoint
5. Extract DNS query from request (URL param or body, the body capped at `MAX_DOH_BODY_BYTES`)
6. Screen and parse it with `dns_screen::decode_dns_message`; one that does not decode is `400`
7. Answer a query with no question FORMERR; send any other to `call_llm`
8. Turn the answer into at most one message with `dns::StreamQuery` — the DNS server's own
   rules, see "Failure behaviour" below — and return it as a `200 application/dns-message`

### 3. Two HTTP Methods Supported

#### GET Method (RFC 8484 Section 4.1)

- DNS query encoded as base64url in `dns=` query parameter
- Example: `GET /dns-query?dns=AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB`
- URL-safe base64 encoding (no padding)
- Lightweight, can be cached by HTTP proxies
- Used by web browsers via `<link>` tags

#### POST Method (RFC 8484 Section 4.1)

- DNS query sent as request body
- Content-Type: `application/dns-message`, matched per RFC 9110 §8.3 -
  case-insensitively, and ignoring any parameters after `;`. It used to be a
  byte-for-byte `!=` against the canonical spelling, so `Application/DNS-Message`
  and `application/dns-message; charset=utf-8` were both rejected as "Invalid
  Content-Type": a conformant client turned away for being conformant
- Binary DNS packet (not encoded)
- More efficient for large queries
- Used by DoH client libraries

### 4. Self-Signed Certificates

TLS configuration:

- Certificates generated by `tls_cert_manager::generate_default_tls_config()`
- Self-signed for testing/development
- Clients must disable certificate verification for testing
- Production usage requires proper CA-signed certificates

### 5. Dual Logging

- **DEBUG**: Query summary ("DoH query: example.com A via GET"), HTTP method, byte counts
- **TRACE**: Full hex dumps of DNS packets (both request and response)
- Both go to netget.log and TUI Status panel

### 6. HTTP/2 Connection Management

Unlike DoT (raw TLS) and UDP DNS:

- HTTP/2 allows multiplexed requests over single connection
- Connection pooling handled by hyper
- Each request is independent (RESTful API)
- No persistent state between requests

## LLM Integration

### Event Type

**`doh_query`** - Triggered when DNS query received over HTTPS

Event parameters:

- `query_id` (number) - DNS transaction ID from request packet
- `domain` (string) - Domain name being queried
- `query_type` (string) - Record type (A, AAAA, MX, TXT, etc.), rendered with
  `Display` rather than `{:?}` for the same reason DoT's is
- `peer_addr` (string) - Client IP address and port
- `method` (string) - HTTP method used (GET or POST)

### Available Actions

DoH offers `DnsProtocol::query_actions()`, the DNS server's query vocabulary without the
zone-transfer actions:

- `send_dns_a_response` - Return IPv4 address (A record)
- `send_dns_aaaa_response` - Return IPv6 address (AAAA record)
- `send_dns_mx_response` - Return mail exchange record
- `send_dns_txt_response` - Return text record
- `send_dns_cname_response` - Return canonical name alias
- `send_dns_nxdomain` - Domain does not exist
- `send_dns_records` - Any number of records in any section, any RCODE
- `send_dns_refused` - REFUSED, echoing the question
- `send_dns_response` - Hand-assembled response, hex-encoded (escape hatch)
- `ignore_query` - Answered as HTTP 404 rather than by dropping the request,
  since HTTP requires a response

See `src/server/dns/AGENTS.md` for detailed action documentation.

As with plain DNS, a **static** event handler cannot serve DoH answers: it
cannot echo the client's random transaction ID or the queried name. Use script
mode for deterministic answers; static mode is only useful for `ignore_query`.

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
      "type": "notify_operator",
      "message": "Resolved example.com to 93.184.216.34 over HTTPS"
    }
  ]
}
```

## Connection Management

### Startup

`DohServer::spawn` binds the `TcpListener` **before** spawning the accept loop
and returns the bound `SocketAddr`. That ordering matters: if the bind were done
inside the spawned task, a port conflict or permission error would be swallowed
by the background task while `open_server` reported the server as `Running`, and
a caller that asked for port 0 would be told the port was 0. The accept loop's
`JoinHandle` is registered with `AppState::register_server_task` so
`stop_server` can abort it and release the port.

### Connection Lifecycle

1. **Accept**: TCP listener accepts connection on port 443
2. **TLS Handshake**: `TlsAcceptor::accept()` performs TLS negotiation
3. **HTTP/2 Setup**: hyper establishes HTTP/2 connection
4. **Request Loop**: Handle multiple HTTP requests over same connection. A
   `ConnectionId` is allocated and a `ConnectionState` added to
   `ServerInstance.connections` *before* the TLS handshake, `update_connection_stats`
   is called for every query in and answer out, and `close_connection_on_server`
   runs however the connection ends. None of this existed before September 2026:
   DoH drew an empty peer list however many clients were talking to it, and
   `{client_ip}` in the `doh_query` template rendered empty because `call_llm` was
   passed `None` for the connection
5. **Close**: Connection ends when client closes, an error occurs, or it carries no query for
   `idle_timeout_secs` (default 300) — a GOAWAY, then close

### State Management

- DoH connections are stateless at application level (REST API)
- HTTP/2 manages connection multiplexing
- Each request is independent (no state between requests)
- Each connection is a `ConnectionState` in `ServerInstance.connections` (see the lifecycle
  above); no protocol-specific state is kept in it

## Known Limitations

### 1. Self-Signed Certificates Only

- No support for custom certificates
- No CA-signed certificate loading
- No certificate rotation/renewal
- Testing requires disabling certificate verification on clients

**Workaround**: For production, modify `tls_cert_manager` to load custom certificates.

### 2. No Path Routing At All

The request path is never examined. `/dns-query` is the conventional RFC 8484
endpoint and is what clients will use, but any path - `/`, `/foo` - is served
identically, and there is no way to configure or reject one. This is lenient
rather than broken (RFC 8484 treats the path as discovered from a URI template,
not fixed), but it does mean the server cannot host anything else alongside DoH.

### 3. No HTTP/1.1 Support

- Only HTTP/2 supported
- HTTP/1.1 DoH clients will fail
- Fallback not implemented

**Reason**: RFC 8484 recommends HTTP/2 for performance (multiplexing).

### 4. DNS Limitations Inherited

All limitations from standard DNS protocol apply:

- No DNSSEC signing (the DNS server's `dnssec_zone` is not offered here)
- No zone transfers
- No recursive resolution
- An EDNS query gets an OPT back; no option is acted on
- See `src/server/dns/AGENTS.md` for full list

### 5. No Rate Limiting

- No per-client request limits
- Connections are capped at 256 (`accept_bounded`) and bounded in time as below, but queries
  per connection are not

Three unbounded resources were closed in September 2026, and they were worse than
"no rate limiting":

- **The request body was read with `req.collect()`, which has no cap.** Over an
  established HTTP/2 connection a peer could POST gigabytes to `/dns-query` and
  NetGet buffered all of it before deciding it was not a DNS message. It is now
  read through `http_body_util::Limited` at `MAX_DOH_BODY_BYTES` (65535 - a DNS
  message cannot be larger) and anything over gets `413`.
- **The TLS handshake had no timeout**, so connecting and then saying nothing held
  a task open forever. Bounded at 10s.
- **Nothing bounded a connection after its handshake.** hyper applies no idle bound to an
  HTTP/2 session, so a peer that completed TLS and then never sent the preface — or sent one
  query and went quiet — held its slot for good. `IDLE_BETWEEN_QUERIES_TIMEOUT` (300s, the
  `idle_timeout_secs` startup parameter) is a `watch_idle` over a `ConnectionActivity` raced
  against `serve_connection`; every request's service future holds the connection busy, so a
  query waiting on the model or parked for a human is never idle. On expiry the connection gets
  a GOAWAY (`graceful_shutdown`). 300s stays above the 90 seconds `reqwest` — NetGet's own DoH
  client, which is lazy and never connected-and-silent — keeps an idle pooled connection.

Per-connection tasks are also registered with `AppState::register_server_task` now,
so `stop_server` aborts them; unregistered, they outlived the server.

### 6. No Caching

- No HTTP cache headers
- No query result caching
- Each request hits LLM or script

**Future Enhancement**: Add cache-control headers based on DNS TTL.

## Bounds

Every number this server enforces, and the test that fails when it is removed
(`tests/server/doh/bounds_test.rs` unless named):

| bound | value | direction | test |
|---|---|---|---|
| `MAX_CONNECTIONS` | 256 | accept | `connection_bounds_test.rs`: the 257th's handshake never starts; a closed peer's slot comes back |
| `TLS_HANDSHAKE_TIMEOUT` | 10 s | inbound | a silent peer and a half-sent ClientHello are open at 6 s and closed by 15 s |
| `idle_timeout_secs` (`IDLE_BETWEEN_QUERIES_TIMEOUT`) | 300 s | inbound | `connection_bounds_test.rs`: no preface, and an answered connection gone quiet, closed at a 3 s bound; a query parked for a human keeps its connection past it |
| `GOAWAY_DRAIN_TIMEOUT` | 5 s | **outbound** | a peer that floods PINGs and never reads is let go at the idle bound plus the drain |
| `MAX_DOH_BODY_BYTES` | 65535 | inbound | a POST of exactly 65535 octets is answered; 65536 is `413` and raises no event |
| `dns_screen` | per message | inbound | the DNS server's `compression_chain_test.rs`; here an undecodable body is `400` |
| hickory's encoder | 65535 octets | **outbound** | a ~80 KB answer is SERVFAIL in a 200 |
| one reply per query | | **outbound** | an answer with two A actions is answered with the first |

The GET `dns=` parameter rides in the request's `:path`, which hyper's HTTP/2 server bounds
with its own header-list limit (16 KiB by default); NetGet declares no number of its own for it.

## Failure behaviour: a DNS message in a 200, not a 5xx

DoH answers through `dns::StreamQuery`, which is the DNS server's own `Reply::resolve` and
`Reply::finish` with the TCP limits, so the outcomes and their `decision=` tags are the DNS
server's (`src/server/dns/AGENTS.md`, "Failure behaviour"), logged with `DoH` in place of `DNS`:

| outcome | HTTP | body | `decision=` |
|---|---|---|---|
| the first DNS message an action produced | 200 | that message, OPT echoed for an EDNS query | `model_answer` |
| `ignore_query` | 404 | `Query ignored` | `model_silent` |
| an answer with no sendable action | 200 | SERVFAIL | `fail_closed_no_action` |
| `send_dns_response` bytes that are not a DNS message | 200 | SERVFAIL | `fail_closed_unparseable_answer` |
| an answer too large to encode | 200 | SERVFAIL | `fail_closed_no_action` ("cannot encode") |
| the backend failed / was overloaded | 200 | SERVFAIL | `fail_closed_llm_error` / `fail_closed_llm_overload` |
| a query with no question | 200 | FORMERR, from the server | `spec_reply` |
| a body that does not decode, a bad `dns=` encoding, a wrong media type | 400 | text | — |
| a body over `MAX_DOH_BODY_BYTES` | 413 | text | — |

RFC 8484 §4.2.1 makes 200 the status for "this HTTP transaction carried a DNS message";
whether that message is an answer or a failure is DNS's business. A 5xx tells a DoH client the
*resolver endpoint* is broken, and real clients mark the server down and fail over — a much
heavier reaction than a transient backend hiccup. The HTTP-level failure is reserved for a
backend failure where not even a SERVFAIL could be built: `503` + `Retry-After` for
`WireFailure::Overloaded`, `500` for `Unavailable`, carrying the category text and never the
error itself.

**Until November 2026 three of those rows were different.** DoH had its own copy of the answer
loop: an answer with no sendable action got `500 "No response generated"` — the 5xx the
paragraph above argues against, for the case most likely to happen; `send_dns_response`'s bytes
went out unparsed as `application/dns-message`; and a query with no question was `400 "No DNS
queries"`, though it is a well-formed DNS message the DNS server answers FORMERR.
`bounds_test.rs` drives every row.

## Example Prompts

### Basic DoH Server

```
listen on port 443 via dns-over-https
Respond to all A record queries for example.com with IP 93.184.216.34
For all other domains, return NXDOMAIN
```

### Multi-Method DoH Server

```
listen on port 443 via doh
Support both GET and POST methods for DNS queries
For secure.example.com:
  - A record: 93.184.216.34
  - AAAA record: 2001:db8::1
For unknown domains, return NXDOMAIN
```

### Privacy-Focused DoH

```
listen on port 443 via dns-over-https
Provide DNS resolution over HTTPS for privacy
Block tracking domains by returning NXDOMAIN for:
  - doubleclick.net
  - google-analytics.com
For legitimate domains, resolve normally
```

## Performance Characteristics

### Latency

- **TLS Handshake**: ~50-100ms (one-time per connection)
- **HTTP/2 Setup**: ~10ms (one-time per connection)
- **Per Query (with scripting)**: 1-2ms (after connection setup)
- **Per Query (without scripting)**: 2-5 seconds (LLM call)
- hickory-proto parsing: ~10-50 microseconds
- Base64 decode (GET): ~1-5 microseconds

### Throughput

- **With Scripting**: Thousands of queries per second
- **Without Scripting**: ~0.2-0.5 QPS (LLM-limited)
- HTTP/2 multiplexing enables concurrent requests
- Connection reuse amortizes TLS/HTTP/2 setup

### Method Comparison

- **GET**: Slightly slower (base64 decode), but cacheable by proxies
- **POST**: Slightly faster (no encoding), better for large queries
- Performance difference negligible in practice

### Comparison to DoT and UDP DNS

- **vs DoT**: Similar performance, but HTTP/2 multiplexing better for concurrent queries
- **vs UDP DNS**: Higher latency (TLS+HTTP overhead), but encrypted and tamper-proof
- **Use Case**: Web browsers, privacy-focused DNS clients, corporate environments

### Scripting Compatibility

Excellent scripting candidate:

- Same query/response pattern as DNS/DoT
- Deterministic responses based on domain
- HTTP/2 makes scripting very efficient
- High query volume typical

## Security Considerations

### TLS + HTTP/2 Protection

- Prevents eavesdropping on DNS queries
- Prevents DNS spoofing/tampering
- Ensures query integrity
- Authenticates server (with proper certificates)
- HTTP/2 encryption provides additional layer

### Self-Signed Certificate Risks

- Default setup vulnerable to MITM attacks
- Clients must explicitly trust self-signed cert
- Not suitable for production without proper PKI

### Privacy Benefits

- ISP/network operators cannot see DNS queries
- Prevents DNS-based tracking
- Protects against DNS hijacking
- Indistinguishable from HTTPS traffic (bypasses censorship)
- Complements HTTPS for end-to-end privacy

### HTTP GET Method Considerations

- GET requests can be logged by proxies
- DNS query visible in proxy logs (base64 encoded)
- POST method preferred for sensitive queries

## References

- [RFC 8484: DNS Queries over HTTPS (DoH)](https://datatracker.ietf.org/doc/html/rfc8484)
- [RFC 7540: Hypertext Transfer Protocol Version 2 (HTTP/2)](https://datatracker.ietf.org/doc/html/rfc7540)
- [RFC 1035: Domain Names - Implementation](https://datatracker.ietf.org/doc/html/rfc1035)
- [hickory-proto Documentation](https://docs.rs/hickory-proto/latest/hickory_proto/)
- [hyper Documentation](https://docs.rs/hyper/latest/hyper/)
- [tokio-rustls Documentation](https://docs.rs/tokio-rustls/latest/tokio_rustls/)
- [Mozilla DoH Documentation](https://wiki.mozilla.org/Trusted_Recursive_Resolver)

---

## `test_doh_server`: a literal IP still goes through the system resolver (August 2026)

`test_doh_server` failed roughly **4 runs in 6** of the full suite at `--test-threads=100`,
always the same way: `reqwest ... source: TimedOut` on the first GET, against a DoH server that
had logged `DoH server listening on 127.0.0.1:<port>` and had never been asked anything — the
mock reported zero `doh_query` calls.

**Cause: `reqwest` resolves the URL host unconditionally, even when it is a dotted quad.**
`hyper-util`'s default `GaiResolver` does not special-case `127.0.0.1`, so every request made a
`getaddrinfo("127.0.0.1")` call. On macOS that goes through libinfo to mDNSResponder — one
system-wide daemon — and at 100 test threads about a hundred processes ask it simultaneously.

The measurement that pinned it, after the timing was instrumented directly:

```
!!!T!!! client built after 1.047375ms
!!!T!!! raw TCP connect took 464µs ok=true          <- same runtime, same port, immediately before
!!!T!!! GET FAILED after 10.001948584s: ... TimedOut
[STDERR] ... DoH TCP connection from 127.0.0.1:59561   <- the raw probe
[STDERR] ... DoH TCP connection from 127.0.0.1:62223   <- reqwest, 8.25s later
```

A raw `TcpStream::connect` from the same test, on the same runtime, in the same moment, reached
the server in 464µs. reqwest's connect had not reached it 8 seconds later. The machine, the
runtime, the accept loop and the TLS stack were all healthy; only the name lookup was stuck.

**Fix:** `.resolve("127.0.0.1", <addr>)` on the client builder, which bypasses the system
resolver. That took the test from 4/6 failures to **0/8** at the same machine load
(load average ~120 on 12 cores).

### What this replaces, and why the earlier reading was wrong

An earlier pass concluded the evidence "points at external machine load" and listed four ruled-out
hypotheses. Load was real and was what made the bug *visible*, but it was not the cause, and
treating it as one nearly cost the fix. Two of the earlier candidates were also tested properly
here and are genuinely not needed: a multi-threaded test runtime and building the client on
`spawn_blocking` each changed nothing once the resolver was overridden (the client builds in
~1ms), so neither was kept.

The lesson is the method rather than the finding: **when a client times out against a healthy
server, prove which step is stuck before blaming the environment.** One raw `TcpStream::connect`
next to the failing request separated "the machine cannot connect" from "this library will not
connect", and that single line is what turned an unexplained flake into a one-line fix.

**Every other e2e test that points `reqwest` at `127.0.0.1` had the same latent defect** — all
18 now carry the override. So does NetGet itself, for any endpoint configured with an IP
(`src/llm/ollama_client.rs::without_dns_for_literal_ip`); that second fix is what stopped the
`bluetooth_ble` read tests failing, whose `/api/tags` probe was spending its entire 5-second
budget in the resolver.

### The residual, and what was measured

After both fixes, `test_doh_server` still timed out about 2 runs in 6 at load ~150. reqwest now
connects in ~30ms and it is the **TLS handshake** that does not complete inside the remaining
budget. Two candidate remedies were tested rather than assumed, and the result is worth
recording because one of them is the opposite of the intuition:

| change | failures |
|---|---|
| baseline (before either DNS fix) | 4 / 6 |
| DNS fixes only | 2 / 6 |
| **+ `multi_thread` test runtime and batched harness output** | **7 / 8 — much worse** |
| + request budget raised 10s → 30s | **0 / 8** at load 161 |

Giving the test its own 4 worker threads makes it *worse*, because `--test-threads=100` already
oversubscribes a 12-core box and four workers per test multiplies the contention. That is the
reverse of what "starved runtime → add threads" suggests, and it is why the earlier pass was
right to drop it — though for the wrong reason.

The 10s budget was the only tight deadline in the file (its siblings wait 20s and 30s) and it
bounds a two-process TLS + HTTP/2 handshake, not server health. It is now 30s. **That change
was made last, deliberately.** Raising it first would have hidden both real defects, which is
exactly what nearly happened when an earlier pass concluded the cause was "machine load".


## No peer handle — `[ send message ]` / `[ disconnect ]` stay disabled

`src/server/peer_support.rs` needs an `AsyncWrite` write half that the session and the
peer-command task can share. DoH has none to give: `handle_connection` hands the socket to
hyper's `http2::Builder::serve_connection`, which owns every read and write for the life of the
connection. Bytes written alongside hyper's framing are not a message to the peer — they are
frames in the middle of an HTTP/2 stream the client is multiplexing, and the connection dies.

There is nothing useful to send either. A DoH answer is the body of a response to a specific
`POST /dns-query`, correlated by the HTTP exchange itself; an unsolicited one has no request to
belong to.

That is also why `metadata()` declares `.request_only(…)`: "DNS over HTTPS only answers
queries; a server cannot send a peer anything unprompted". The dashboard's `[ send message ]` on a
peer is disabled and shows that reason, and MCP `send_to_peer` refuses with it; `[ disconnect ]`
stays disabled with "this protocol cannot disconnect a peer from here yet".
`tests/peer_handle_coverage_ratchet_test.rs` carries
this protocol on its shrink-only baseline with the reason above, and re-derives the reason from
source on every run, so if the mechanism changes the build fails rather than the file going
quietly stale.

## Verified

| test | peer | what it proves |
|---|---|---|
| `tests/server/doh/real_client_test.rs` | `kdig` (Knot DNS 3.6, GnuTLS) | POST and GET for two names, then AAAA, MX, TXT, CNAME and NXDOMAIN, negotiating `h2` by ALPN; decrypted by the pcap oracle |
| `tests/server/doh/real_client_test.rs` | `dig` (ISC BIND 9.20, OpenSSL) | the same with dig's defaults, EDNS and a COOKIE offered; the echoed OPT read back |
| `tests/server/doh/e2e_test.rs` | reqwest (hyper + rustls) | the HTTP/2 transport, status and `Content-Type` — generic HTTP, so not DNS evidence |

Neither real-client test is `#[ignore]`d; each **fails** naming its package when the binary
is absent. Verified by breaking it: a fixed transaction id makes both resolvers discard the
reply; advertising `http/1.1` instead of `h2` fails kdig's handshake with
`TLS, handshake failed (A TLS fatal alert has been received.)`.

`+https` takes `[authority][/path]`, and the authority becomes the TLS SNI: an IP literal there
is rejected by rustls, and a name switches kdig to a validating profile a self-signed
certificate cannot pass. The tests pass the path alone.

**Unproven:** certificate validation of any kind, and client auth.

## Maturity: the six conditions

The root `AGENTS.md` defines `Stable` as six conditions. Re-derived against source in
November 2026 rather than inherited. **The rating covers the surface this server implements**:
RFC 8484 over HTTP/2 with ALPN `h2`, both request encodings, a self-signed certificate, and the
DNS server's query actions and answer rules. HTTP/1.1, certificate provisioning, client
authentication, HTTP caching headers and path routing are not implemented, and the DNS server's
DNSSEC signing and zone transfers are not offered here.

| # | condition | holds? |
|---|---|---|
| 1 | two independent third-party clients, no skip, no `#[ignore]` | **yes, as of this pass** — `kdig` (Knot DNS, GnuTLS) and `dig` (ISC BIND, OpenSSL), each negotiating `h2` by ALPN and hard-failing when absent; both encodings for two names, then AAAA, MX, TXT, CNAME and NXDOMAIN |
| 2 | the pcap oracle is green over its wire traffic | **yes** — kdig's sessions cross `recording_relay` with `SSLKEYLOGFILE`; tshark decrypts them and must dissect `http2` and `dns` |
| 3 | a fuzz target exists and has run clean, with a depth bomb | **yes, as of this pass** — `dns_message`, rebuilt this pass (nightly-2025-12-04, the `-undefined,dynamic_lookup` link flag, `fuzz/Cargo.lock` seeded from the root) and run `-max_total_time=300 -timeout=25` from the committed seeds, `pointer_chain_bomb` among them: 137 196 inputs in 301 s, clean; the corpus grew from 7 to 742 inputs (kept out of the tree). The framing around it is hyper's HTTP/2 and a base64url decode, so this decoder is the one peer bytes reach |
| 4 | every declared bound has a test | **yes, as of this pass** — the Bounds table above, each verified by removal |
| 5 | both `AGENTS.md` files verified against source in this pass | **yes** — this file and `tests/server/doh/AGENTS.md`, the latter rewritten |
| 6 | no `#[ignore]`, no skip-when-missing gate | **yes** — `grep -rn '#\[ignore' tests/server/doh/` is empty, and kdig and dig fail rather than skip |

**Condition 1 rested on one client.** "Verified" below named two peers, and the second was
reqwest — a generic HTTP client, which the root `AGENTS.md` rules out as evidence for a protocol
carried on HTTP — with the DNS decoded by hickory-proto, the server's own codec. kdig was the
only independent DoH client, for A records. `dig +https` / `+https-get` (BIND 9.20) is the
second, and both now read every record type the actions write.

**Condition 4 found two bounds nothing tested** — the handshake deadline and the GOAWAY drain —
and **condition 5 found the failure section's promise broken** for the most likely failure: a
model that answers without a sendable action got `500 "No response generated"`, the 5xx the
section explains a DoH client reads as the endpoint being down. DoH had its own answer loop;
it now answers through `dns::StreamQuery` (see "Failure behaviour"). Also corrected: the action
list, "no connection state stored in ServerInstance", the inherited-limitations list, and the
"Verified" section's claim that reqwest made a second independent peer.

**What the oracle cannot see here** is the GET request's query (base64url in `:path`) and
anything about certificate validation: neither client authenticates the self-signed certificate.
