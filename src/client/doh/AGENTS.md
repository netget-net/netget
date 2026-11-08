# DNS-over-HTTPS (DoH) Client Implementation

## Overview

DNS-over-HTTPS client implementing RFC 8484 for secure DNS queries over HTTPS transport. The LLM controls DNS query
decisions; `hickory-proto` builds and decodes the DNS messages and `reqwest` (over rustls) carries them as
`application/dns-message` HTTPS requests.

**Status**: Experimental (Client Protocol)
**RFC**: RFC 8484 (DNS Queries over HTTPS)
**Default Port**: 443 (HTTPS)

## Library Choices

### Primary: hickory-proto + reqwest

- **`hickory-proto` 0.26**: the DNS query message (`Message`, `Query`, `Name`, `RecordType`) and the
  decode of the answer, which goes through `utils::dns_screen::decode_dns_message`
- **`reqwest`** with rustls: the HTTPS transport (RFC 8484 POST/GET of `application/dns-message`),
  one cached client per endpoint and TLS setting

No hickory networking crate is involved: hickory's own DoH client is not used.

### Supporting Libraries

- **tokio**: Async runtime for DNS operations
- **rustls**: TLS implementation for secure connections

## Architecture

### Connection Model

DoH client is **stateless at the application level**:

1. Initialize HTTPS client connection to DoH server
2. Maintain persistent HTTP/2 connection for query multiplexing
3. Each DNS query is an independent HTTPS request
4. Responses trigger LLM calls for decision-making
5. LLM can issue follow-up queries based on responses

### LLM Integration Points

#### 1. Initial Connection

When client connects to DoH server:

- Event: `doh_connected` with server URL
- LLM receives connection confirmation
- Can issue immediate queries or wait for user input

#### 2. DNS Query Results

When DNS response received:

- Event: `doh_response_received` with parsed answers
- LLM analyzes response (IP addresses, CNAME chains, etc.)
- Can issue follow-up queries (e.g., resolve CNAME targets)
- Can extract and report specific information

### State Machine

DoH client uses a simplified state model:

- **Idle**: Waiting for user action
- **Querying**: DNS query in flight
- **Processing Response**: LLM analyzing results

Unlike connection-based protocols, DoH doesn't maintain persistent read loops. Queries are triggered by LLM actions.

## LLM Actions

### Async Actions (User-Triggered)

**`query_dns`** - Make a DNS query over HTTPS

- **Parameters**:
    - `domain` (string, required): Domain name to query
    - `record_type` (string, optional): DNS record type (A, AAAA, MX, TXT, CNAME, NS, SOA, PTR, SRV, etc.)
    - `use_get` (boolean, optional): Use HTTP GET instead of POST (default: false)
- **Example**:
  ```json
  {
    "type": "query_dns",
    "domain": "example.com",
    "record_type": "A",
    "use_get": false
  }
  ```

**`disconnect`** - Disconnect from DoH server

- No parameters
- Closes HTTPS connection

### Sync Actions (Response-Triggered)

**`query_dns`** - Make follow-up query based on response

- Same parameters as async version
- Allows CNAME following, MX resolution, etc.

**`wait_for_more`** - Pause and wait for user input

- Stops automatic query chain
- Returns control to user

## Events

### `doh_connected`

Triggered when DoH client successfully connects to server.

**Parameters**:

- `server_url` (string): DoH server URL

**Example**:

```json
{
  "event_type": "doh_connected",
  "server_url": "https://dns.google/dns-query"
}
```

### `doh_response_received`

Triggered when DNS response received and parsed.

**Parameters**:

- `query_id` (number): DNS query transaction ID
- `domain` (string): Domain name queried
- `query_type` (string): Record type requested
- `answers` (array): Parsed DNS answers with name, type, TTL, data
- `status` (string): Response code (NoError, NXDomain, ServFail, etc.)

**Example**:

```json
{
  "event_type": "doh_response_received",
  "query_id": 12345,
  "domain": "example.com",
  "query_type": "A",
  "answers": [
    {
      "name": "example.com.",
      "type": "A",
      "ttl": 86400,
      "data": "93.184.216.34"
    }
  ],
  "status": "NoError"
}
```

## DoH Server Providers

### Google Public DNS

- **URL**: `https://dns.google/dns-query`
- **Features**: Fast, reliable, supports both GET and POST
- **Privacy**: Logs queries with user IP

### Cloudflare DNS

- **URL**: `https://cloudflare-dns.com/dns-query`
- **Alternative**: `https://1.1.1.1/dns-query`
- **Features**: Privacy-focused, no logging
- **Performance**: Very fast

### Quad9

- **URL**: `https://dns.quad9.net/dns-query`
- **Features**: Security-focused, blocks malicious domains

### Custom/Self-Hosted

Can connect to any RFC 8484 compliant DoH server, including NetGet's own DoH server.

## Implementation Details

### DNS Record Type Support

All standard DNS record types `hickory-proto` parses:

- **A**: IPv4 address
- **AAAA**: IPv6 address
- **CNAME**: Canonical name
- **MX**: Mail exchange
- **TXT**: Text records
- **NS**: Name server
- **SOA**: Start of authority
- **PTR**: Pointer (reverse DNS)
- **SRV**: Service location
- And many more...

### HTTP Method Selection

**POST (Default)**:

- DNS query sent as binary request body
- Content-Type: `application/dns-message`
- More efficient, supports larger queries
- Recommended for programmatic use

**GET (Optional)**:

- DNS query base64url-encoded in `dns=` parameter
- URL: `/dns-query?dns=<base64url>`
- Can be cached by HTTP proxies
- Useful for browser-based queries

### Connection Management

- **Persistent Connection**: HTTP/2 connection reused for multiple queries
- **Connection Pooling**: reqwest manages connection lifecycle
- **Timeout**: 30-second query timeout (configurable)
- **Retries**: No automatic retries (LLM decides)

### Error Handling

- **Connection Errors**: Reported to LLM via status messages
- **DNS Errors**: Included in response (NXDomain, ServFail, etc.)
- **Timeout**: Reported as error, LLM can retry
- **Invalid Responses**: Logged and reported

## Known Limitations

### 1. No Response Caching

- Each query hits DoH server directly
- No local DNS cache
- LLM must manage repeated queries

**Workaround**: LLM can use memory to cache results.

### 2. Single Query at a Time

- Queries are sequential, not concurrent
- Multiple queries require multiple LLM actions

**Workaround**: LLM can issue multiple `query_dns` actions in one response.

### 3. No DNSSEC Validation

- DNSSEC signatures not validated client-side
- Trust relies on DoH server's validation

**Future Enhancement**: Validate with hickory's DNSSEC support.

### 4. Fixed Timeout

- 30-second timeout not configurable per-query
- May be too short for some use cases

**Workaround**: Modify timeout in code if needed.

### 5. No Query Cancellation

- Once query sent, cannot be cancelled
- Must wait for response or timeout

**Future Enhancement**: Add cancellation support.

### 6. Limited to Standard DNS

- No support for DNS extensions (EDNS, etc.)
- No custom DNS headers

**Reason**: the query message is built with fixed defaults.

## Example Usage Patterns

### Basic Domain Resolution

```
Connect to https://dns.google/dns-query
Query example.com A record
Report the IP address
```

LLM will:

1. Receive `doh_connected` event
2. Issue `query_dns` action for example.com
3. Receive `doh_response_received` with IP
4. Report IP to user

### CNAME Following

```
Connect to https://cloudflare-dns.com/dns-query
Resolve www.example.com and follow any CNAMEs to final IP
```

LLM will:

1. Query www.example.com (type A)
2. If CNAME returned, extract target domain
3. Issue follow-up query for CNAME target
4. Repeat until A/AAAA record found

### Mail Server Discovery

```
Connect to https://dns.quad9.net/dns-query
Find mail servers for example.com
```

LLM will:

1. Query example.com MX records
2. Parse MX records (priority, hostname)
3. Optionally resolve MX hostnames to IPs
4. Report ordered list of mail servers

### Reverse DNS Lookup

```
Connect to DoH server
Do reverse DNS lookup for 8.8.8.8
```

LLM will:

1. Convert IP to PTR format (8.8.8.8.in-addr.arpa)
2. Query PTR record
3. Report hostname

## Performance Characteristics

### Latency

- **Connection Setup**: ~100-200ms (TLS + HTTP/2 handshake)
- **Per Query**: ~20-100ms (network RTT to DoH server)
- **LLM Processing**: ~2-5 seconds (if LLM call needed)

### Throughput

- **With Scripting**: Not applicable (queries are async actions)
- **Without Scripting**: Limited by LLM call time
- **HTTP/2 Multiplexing**: Supports concurrent queries (future enhancement)

### Comparison to Traditional DNS

- **vs UDP DNS**: Higher latency (HTTPS overhead), but encrypted
- **vs DoT**: Similar performance, HTTP/2 better for multiplexing
- **vs Standard DNS Client**: More privacy, bypasses censorship

## Security Considerations

### Privacy Benefits

- **Encrypted Queries**: ISP/network cannot see DNS queries
- **HTTPS Transport**: Queries indistinguishable from web traffic
- **No DNS Spoofing**: HTTPS prevents tampering
- **Server Authentication**: TLS verifies server identity

### Trust Model

- **Trust DoH Server**: Server sees all queries
- **No Local Trust**: Local network cannot intercept
- **Public Server Risks**: Google/Cloudflare see your queries

### Recommendations

- Use privacy-focused DoH providers (Cloudflare, Quad9)
- Self-host DoH server for maximum privacy
- Combine with VPN for IP privacy

## Future Enhancements

1. **Concurrent Queries**: Issue multiple queries in parallel
2. **DNSSEC Support**: Validate DNSSEC signatures
3. **Response Caching**: Local cache to reduce queries
4. **Custom Timeout**: Per-query timeout configuration
5. **Connection Pooling**: Multiple DoH servers
6. **Fallback Support**: Automatic failover to backup servers
7. **Query Statistics**: Track query count, latency, errors

## References

- [RFC 8484: DNS Queries over HTTPS (DoH)](https://datatracker.ietf.org/doc/html/rfc8484)
- [hickory-proto Documentation](https://docs.rs/hickory-proto/)
- [Google Public DNS DoH](https://developers.google.com/speed/public-dns/docs/doh)
- [Cloudflare DoH](https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/)

## Command channel (the dashboard's `[ send ]`)

`AppState::send_to_client` injects an action into a running DoH client. The handle is
registered **before** the `doh_connected` LLM call, because a dashboard-created client
defaults to a `*` → manual rule and that call can park for minutes waiting for a human.

The query itself lives in `perform_query` (encode → HTTPS → parse → event payload), which
both the LLM chain and the command loop reach through one `apply_action`; `execute_llm_actions`
no longer inlines it.

**Outcome semantics — `Executed`, never `Sent`.** reqwest owns the socket and reports no wire
byte count, so a number would be invented. The command loop **awaits** the query and reports
`Executed { detail: "query_dns example.com A -> 1 answers (NoError)" }`; a failed query is an
`Err`, an unknown action is `Rejected`, `disconnect` is `Disconnected`. The
`doh_response_received` event fires from its own registered task, so a manual rule parking
that LLM call cannot wedge the command loop.

### 7. Talking to NetGet's own DoH server takes two deliberate choices

`src/server/doh/` is TLS-only, serves a self-signed certificate, advertises **`h2` alone** in
ALPN and answers with HTTP/2 frames regardless of what was negotiated. Reaching it needs both:

- **Trust.** `ca_cert_pem` adds one certificate to the system roots — the right answer for a
  private CA or a known self-signed peer. `insecure_skip_verify` accepts any certificate at
  all and is opt-in per client, never a default, because a DoH connection made with it is
  unauthenticated.
- **ALPN offering `h2`.** `build_http_client` calls `.use_rustls_tls()` explicitly rather than
  taking reqwest's default TLS backend. Without it no protocol is negotiated, the server sends
  HTTP/2 frames anyway, and every request dies in the client's HTTP/1.1 parser with
  `invalid HTTP version parsed` — before a single query reaches the server. That failure is
  easy to misread as a certificate problem, because it also happens on the very first request.

Related: query failures are logged with `{:#}`, not `{}`. `{}` prints only our own
`"DoH POST request failed"` context and throws away reqwest's actual cause, which is the only
part that says anything.

### Building the HTTP client is a blocking operation — treat it as one

`reqwest::Client::builder().build()` sets up the rustls stack, and that loads the platform
root certificate store. On macOS this reads the system keychain through Security.framework,
which is synchronous, syscall-heavy, and serialises across processes.

Three things follow, all of which this client got wrong at some point:

- **It must not run on the async runtime.** Called inline it parks a tokio worker for as long
  as the load takes. Under a hundred concurrent netget processes it parked long enough to
  stall the client's runtime entirely: the query logged `querying example.com` and then
  nothing — no response, and no timeout either, because the request future had not been
  created yet and so there was nothing for the timeout to apply to. It is on
  `spawn_blocking` now.
- **It must not run per query.** The client is cached by `(ca_cert_pem, insecure_skip_verify)`
  for the life of the process, so queries after the first reuse the connection pool instead of
  paying for a fresh TLS stack and a fresh handshake each time.
- **It must not load the root store at all when nothing will be checked against it.** With
  `insecure_skip_verify`, `tls_built_in_root_certs(false)` skips the keychain entirely. This
  was the single largest cost, and it bought nothing.

Together these are what took the four e2e tests from failing at `--test-threads=100` (while
passing in isolation, which reads as flakiness and was not) to passing.

`tests/client/doh/command_channel_test.rs` still uses a plain-HTTP `application/dns-message`
stub as its peer — it is testing the command channel, not TLS, and a stub keeps that test
free of certificate and ALPN concerns.
