# DHCP Protocol Implementation

## Overview

DHCP (Dynamic Host Configuration Protocol) server implementing RFC 2131 for automatic IP address assignment and network
configuration. The LLM controls DHCP DISCOVER/OFFER/REQUEST/ACK flow using structured actions.

**Status**: Beta (Core Protocol)
**RFC**: RFC 2131 (DHCP), RFC 2132 (DHCP Options)
**Port**: 67 (server), 68 (client) - UDP
**Privilege**: declares `PrivilegeRequirement::PrivilegedPort(67)`; any port above 1023 needs none.
**Test coverage**: `tests/server/dhcp/test.rs` (the file is `test.rs`, not `e2e_test.rs`) — two
mocked tests, 6 LLM calls, asserting OFFER, ACK and NAK field by field against RFC 2131 table 3
with a decoder written in the test file rather than with `dhcproto`. Until August 2026 this file
had **zero assertions**: all three tests printed `Note: DHCP OFFER timed out` and passed.

## Library Choices

- **dhcproto v0.12** - DHCP protocol parsing and construction
    - Used for parsing DHCP messages (DISCOVER, REQUEST, etc.)
    - Used for constructing DHCP responses (OFFER, ACK, NAK)
    - Handles binary DHCP wire format
    - Provides Message, Opcode, MessageType, DhcpOption types
    - Feature-gated (only compiled when `dhcp` feature enabled)

**Rationale**: dhcproto is the standard Rust library for DHCP. It handles the complex binary protocol (based on BOOTP)
and provides type-safe DHCP option handling. The LLM doesn't need to understand DHCP packet structure - it just provides
semantic data (IP, subnet mask, DNS servers) and the library handles encoding.

## Architecture Decisions

### 1. Action-Based LLM Control

The LLM responds to DHCP requests with semantic actions:

- `send_dhcp_offer` - Respond to DISCOVER with IP offer
- `send_dhcp_ack` - Respond to REQUEST with IP assignment confirmation
- `send_dhcp_nak` - Reject REQUEST (invalid configuration)
- `send_dhcp_response` - Send raw hex packet (advanced)
- `ignore_request` - No response

Each action includes network configuration parameters (IP, subnet mask, router, DNS servers, lease time).

### 2. Request Context Preservation (correlation)

DHCP responses must echo specific fields from the request:

- **Transaction ID (xid)** — the client matches replies by it and silently drops anything else, so
  a wrong xid presents as a timeout, not an error
- **Client hardware address (chaddr)** — who the reply is for
- **Relay address (giaddr)** — a relayed client only sees the reply if this comes back
- **Broadcast flag** — RFC 2131 4.1 says answer the way the client asked
- Message type — Discover → Offer, Request → Ack

**Implementation**: `DhcpRequestContext { xid, chaddr, message_type, ciaddr, giaddr, broadcast,
requested_ip }` held in an `Arc<Mutex<Option<…>>>` on the protocol instance, and **a fresh
`DhcpProtocol` instance is created per received datagram** in the socket loop.

That last part is load-bearing. The instance used to be created once per server and shared by every
request, while each request set the context and then awaited an LLM call lasting seconds — so two
overlapping clients would overwrite each other's xid and both get a reply addressed to the wrong
transaction. One instance per datagram removes the shared slot entirely.

The offer/ack/nak actions also accept explicit `xid` and `client_mac` parameters, which override the
context for replies built out of band (a script answering from stored state, say). Omitting them —
the normal case — echoes the request.

The event exposes `xid`, `client_ip` and `gateway_ip` so a script or static handler can see the
correlation values even though it does not have to supply them.

### 3. Stateless Per-Request Processing

Each DHCP message is independent:

- No persistent client state (no lease database)
- LLM decides IP assignments on-demand
- No IP address pool management
- Simplified implementation suitable for testing/honeypots

### 4. DHCP Options Support

Actions support common DHCP options:

- Subnet Mask (option 1)
- Router/Gateway (option 3)
- DNS Servers (option 6)
- Domain Name (option 15)
- Lease Time (option 51)
- Server Identifier (option 54), always set from `server_ip`
- Message (option 56), NAK only

Additional options can be added via raw `send_dhcp_response` action.

An unparseable entry in `dns_servers` is an error rather than being skipped: shipping a shorter list
than the caller asked for is worse than saying the value was wrong.

### 5. Dual Logging

- **DEBUG**: Request summary ("DHCP DISCOVER from MAC 00:11:22:33:44:55")
- **TRACE**: Full hex dump of DHCP packets (both request and response)
- Both go to netget.log and TUI Status panel

### 6. Connection Tracking

Each DHCP request creates a "connection" entry:

- Connection ID: unique per request
- Protocol info: `ProtocolConnectionInfo::empty()` — no DHCP-specific payload is attached
- Records the peer address and byte/packet counts
- Status: Active, and never reaped

### 7. Malformed-Packet Handling

`hlen` is an attacker-controlled byte and dhcproto does not validate it: `Message::chaddr()` slices
a fixed `[u8; 16]` with it, so `hlen > 16` panics inside the library. That parse happens in the
socket task, so the panic would take the whole listener down — one datagram, server gone, status
still showing `Running`. `parse_dhcp_message` therefore checks `hlen` before touching `chaddr()`
and drops the datagram with a warning. Keep any new field access behind the same check.

**A datagram that does not decode never reaches the model.** `parse_dhcp_message` returning
`None` — undecodable, bad `hlen`, or no message-type option — makes the receive loop drop the
datagram with a WARN. It used to raise `dhcp_request` anyway, with `"unknown"` in every field:
that spent an LLM round trip on an event from which no reply could be built, since `base_reply`
has no transaction id to echo and errors out. Fail closed instead.

### 8. LLM Failure: Silence Is the Correct Reply, and It Is Logged as Such

When the LLM call errors, or returns no usable action, **netget sends the client nothing** — and
that is deliberate, not the "70 of 79 protocols go silent" defect CLAUDE.md warns about.

DHCP has no "try again later" message. The only reply netget could synthesise unaided is a
DHCPNAK, and RFC 2131 4.3.2 defines a NAK as *"your notion of the network address is incorrect"* —
a statement about the client's lease, not about the server's health. A client in RENEWING or
REBINDING that receives one must drop its address and restart from INIT (4.4.5), so NAKing on an
internal error destroys a lease that was never invalid. The same section requires a server with no
knowledge of a binding to **remain silent**, which is precisely netget's position when the model
that would have decided is unreachable. Silence is also the protocol's own retry path: clients
retransmit DISCOVER/REQUEST with backoff (4.4.1), so a transient overload recovers on the retry —
which is what a 503 buys in HTTP. **Do not "fix" this by emitting a NAK.**

Nothing internal reaches the wire because nothing reaches the wire at all. The distinctions live in
the log, with a stable `decision=` token per request (the `src/server/radius/` convention):

| `decision=` | Meaning | Bytes sent |
|---|---|---|
| `model_reply` | the model's action produced a packet | yes |
| `model_no_reply` | the model answered, and chose to send nothing (`ignore_request`) | no |
| `fail_closed_no_action` | the model produced no action at all | no |
| `fail_closed_llm_error` | the LLM call errored | no |

`grep decision=fail_closed_` finds every request netget dropped on the floor. The error itself is
logged at ERROR with a `category=overloaded` / `category=unavailable` tag from
`crate::utils::wire_failure::WireFailure::classify` — DHCP cannot express the difference on the
wire, so it is kept where an operator can act on it — and each fail-closed request also logs a WARN
noting that the client will retransmit (RFC 2131 4.3.2's "MAY output a warning to the network
administrator").

## LLM Integration

### Event Type

**`dhcp_request`** - Triggered when DHCP client sends a message

Event parameters:

- `message_type` (string) - `Discover`, `Request`, `Inform`, `Release`, `Decline` … **capitalised,
  not upper case**: it is dhcproto's `MessageType` Debug spelling. A handler comparing against
  `'DISCOVER'` never matches
- `client_mac` (string) - client hardware address as lower-case hex **without separators**
  (`001122334455`, not `00:11:22:33:44:55`). Handlers and prompts that match on a MAC must use this
  form; the reply actions' own `client_mac` parameter accepts either
- `requested_ip` (string, optional) - address requested in option 50, if any
- `client_ip` (string) - ciaddr, `0.0.0.0` unless the client already holds a lease
- `xid` (number) - transaction id; echoed automatically by the reply actions
- `gateway_ip` (string) - giaddr of the relay the request came through; echoed automatically

### Available Actions

#### `send_dhcp_offer`

Send DHCP OFFER in response to DISCOVER. Proposes IP configuration.

Parameters:

- `offered_ip` (required) - IP address to offer (e.g., "192.168.1.100")
- `server_ip` (optional) - DHCP server IP (default: "0.0.0.0")
- `subnet_mask` (optional) - Subnet mask (e.g., "255.255.255.0")
- `router` (optional) - Default gateway (e.g., "192.168.1.1")
- `dns_servers` (optional) - Array of DNS IPs (e.g., ["8.8.8.8", "8.8.4.4"])
- `lease_time` (optional) - Lease duration in seconds (default: 86400 = 24 hours)

#### `send_dhcp_ack`

Send DHCP ACK in response to REQUEST. Confirms IP assignment.

Parameters: Same as `send_dhcp_offer`, but uses `assigned_ip` instead of `offered_ip`.

#### `send_dhcp_nak`

Send DHCP NAK to reject a REQUEST.

Parameters:

- `server_ip` (optional)
- `message` (optional) - Error message to include

#### `send_dhcp_response` (Advanced)

Send a complete packet as hex, at least 236 bytes. The field is decoded **strictly** as hex —
whitespace, `:` separators and a leading `0x` are stripped, anything else that fails to decode
returns an error instead of being sent as literal ASCII. Nothing is echoed into a raw packet, so the
xid at bytes 4-7 must match the request or the client ignores it.

#### `ignore_request`

Don't send any response.

### Example LLM Response

```json
{
  "actions": [
    {
      "type": "send_dhcp_offer",
      "offered_ip": "192.168.1.100",
      "subnet_mask": "255.255.255.0",
      "router": "192.168.1.1",
      "dns_servers": ["8.8.8.8", "8.8.4.4"],
      "lease_time": 86400
    },
    {
      "type": "notify_operator",
      "message": "Offered 192.168.1.100 to client 00:11:22:33:44:55"
    }
  ]
}
```

## Connection Management

### Connection Lifecycle

1. **Request Received**: UDP datagram on port 67
2. **Parse**: Extract message type, MAC address, requested IP using dhcproto
3. **Context**: Store DhcpRequestContext in protocol instance
4. **Register**: Create ConnectionId and add to ServerInstance
5. **Process**: Call LLM with `dhcp_request` event
6. **Execute**: Build DHCP response using dhcproto and context
7. **Respond**: Send UDP response to client
8. **Update**: Track bytes/packets sent/received
9. **Persist**: Connection remains in UI to show activity

### DHCP Flow

Standard DHCP follows 4-message exchange (DORA):

1. **DISCOVER** (client broadcast) → LLM sends **OFFER**
2. **REQUEST** (client requests offered IP) → LLM sends **ACK**

NetGet implements both sides but doesn't enforce state machine - LLM decides responses.

## Known Limitations

### 1. No Lease Management

- No persistent lease database
- No tracking of assigned IPs
- No IP address pool or allocation logic
- LLM decides IPs on-demand (could assign duplicates)

**Use Case**: Testing, honeypots, demonstrations. Not suitable for production DHCP server.

### 2. Partial DHCP Relay Support

- The request's `giaddr` is parsed, exposed to the LLM and echoed into every reply, so a relayed
  exchange is not broken by a zeroed field
- But the reply is still sent back to the UDP source address of the request, not to giaddr:67 as a
  real server would, and relay agent options (82) are ignored

### 3. Limited DHCP Options

Action-based interface supports common options only:

- Subnet Mask, Router, DNS, Domain Name, Lease Time, Server Identifier, Message
- Missing: NTP servers, TFTP server/boot file, WINS, renewal/rebinding times (T1/T2), vendor options
- Workaround: Use `send_dhcp_response` for custom options

### 4. No DHCP Decline/Release Tracking

- Ignores DHCPRELEASE messages
- No handling of DHCPDECLINE (address already in use)
- No conflict detection

### 5. No DHCPv6 Support

- IPv4 only (RFC 2131)
- No support for IPv6 address assignment (RFC 8415)

### 6. Feature-Gated

- DHCP parsing requires `dhcp` feature flag
- Without feature: Server accepts packets but can't parse them
- Action execution returns error if feature not enabled

## Example Prompts

### Basic DHCP Server

```
listen on port 67 via dhcp
When receiving DHCP DISCOVER, offer IP addresses from 192.168.1.100 onwards
When receiving DHCP REQUEST, acknowledge with:
  - Subnet mask: 255.255.255.0
  - Router: 192.168.1.1
  - DNS: 8.8.8.8
  - Lease time: 24 hours
```

### DHCP Server with IP Range

```
listen on port 67 via dhcp
Assign IPs in range 10.0.0.100 to 10.0.0.200
Use subnet mask 255.255.255.0, gateway 10.0.0.1, DNS 1.1.1.1
Lease time: 12 hours
```

### DHCP Server with Rejection

```
listen on port 67 via dhcp
Only assign IPs to MAC addresses starting with 00:11:22
For other clients, send DHCP NAK with message "Unauthorized device"
```

### Static IP Assignment

```
listen on port 67 via dhcp
For MAC 00:11:22:33:44:55, always assign 192.168.1.50
For MAC 00:11:22:33:44:66, always assign 192.168.1.51
For other clients, assign from 192.168.1.100 onwards
```

## Performance Characteristics

### Latency

- **With Scripting**: Sub-millisecond (script handles requests)
- **Without Scripting**: 2-5 seconds (one LLM call per request)
- dhcproto parsing: ~50-100 microseconds
- dhcproto encoding: ~50-100 microseconds

### Throughput

- **With Scripting**: Thousands of requests per second
- **Without Scripting**: Limited by LLM (~0.2-0.5 requests/sec)
- DHCP traffic is typically low volume (client requests IP once)

### Scripting Compatibility

DHCP is good candidate for scripting:

- Repetitive request/response pattern
- Deterministic IP assignment logic
- Simple state machine (DISCOVER→OFFER, REQUEST→ACK)

When scripting enabled:

- Server startup generates script (1 LLM call)
- All requests handled by script (0 LLM calls)
- Script can implement IP pool logic, static assignments, etc.

## References

- [RFC 2131: Dynamic Host Configuration Protocol](https://datatracker.ietf.org/doc/html/rfc2131)
- [RFC 2132: DHCP Options and BOOTP Vendor Extensions](https://datatracker.ietf.org/doc/html/rfc2132)
- [dhcproto Documentation](https://docs.rs/dhcproto/latest/dhcproto/)
- [DHCP Message Types (IANA)](https://www.iana.org/assignments/bootp-dhcp-parameters/bootp-dhcp-parameters.xhtml)
- [DHCP Options (IANA)](https://www.iana.org/assignments/bootp-dhcp-parameters/bootp-dhcp-parameters.xhtml#options)
