# BOOTP Protocol Implementation

## Overview

BOOTP (Bootstrap Protocol) server implementing RFC 951 for automatic IP address assignment and boot file configuration.
The LLM controls BOOTREQUEST/BOOTREPLY flow using structured actions.

**Status**: Experimental
**RFC**: RFC 951 (BOOTP), RFC 1542 (BOOTP Extensions)
**Port**: 67 (server), 68 (client) - UDP
**Privilege**: declares `PrivilegeRequirement::PrivilegedPort(67)`; any port above 1023 needs none.
**Test coverage**: `tests/server/bootp/e2e_test.rs`, mocked.

## Library Choices

- **dhcproto v0.12** - DHCP/BOOTP protocol parsing and construction
    - Used for parsing BOOTP messages (BOOTREQUEST)
    - Used for constructing BOOTP responses (BOOTREPLY)
    - Handles binary BOOTP wire format (same as DHCP base format)
    - Provides Message, Opcode types
    - Feature-gated (only compiled when `bootp` feature enabled)

**Rationale**: BOOTP uses the same packet format as DHCP (DHCP evolved from BOOTP), so dhcproto is the natural choice.
The library handles the complex binary protocol structure. BOOTP is simpler than DHCP - it doesn't use DHCP options for
subnet mask, DNS, etc. Instead, these are typically configured via other means (TFTP config files, etc.).

## Architecture Decisions

### 1. Action-Based LLM Control

The LLM responds to BOOTP requests with semantic actions:

- `send_bootp_reply` - Respond to BOOTREQUEST with IP assignment and boot file location
- `send_bootp_response` - Send raw hex packet (advanced)
- `ignore_request` - No response

Each action includes network configuration parameters (IP, server IP, boot file, server hostname, gateway).

### 2. Request Context Preservation (correlation)

BOOTP responses must echo specific fields from the request:

- **Transaction ID (xid)** — the client matches replies by it and discards anything else, so a wrong
  xid looks exactly like a timeout
- **Client hardware address (chaddr)** — who the reply is for
- **Relay address (giaddr)** — defaulted into the reply so a relayed client still receives it
- Operation code — BOOTREQUEST → BOOTREPLY

**Implementation**: `BootpRequestContext { xid, chaddr, op, ciaddr, giaddr, sname, file }` held in an
`Arc<Mutex<Option<…>>>` on the protocol instance, and **a fresh `BootpProtocol` instance is created
per received datagram** in the socket loop.

The per-datagram instance is the fix for a real race: the instance used to be shared by the whole
server while each request set the context and then awaited an LLM call lasting seconds, so two
overlapping clients overwrote each other's transaction id.

`send_bootp_reply` also accepts explicit `xid` and `client_mac` parameters that override the context
for replies built out of band; omitting them (the normal case) echoes the request. The event exposes
`xid` and `gateway_ip` so a handler can see the correlation values.

### 3. Stateless Per-Request Processing

Each BOOTP message is independent:

- No persistent client state
- LLM decides IP assignments on-demand
- No IP address pool management
- Simplified implementation suitable for testing/honeypots/PXE environments

### 4. Boot Configuration Support

BOOTP's primary purpose is network boot configuration:

- **Boot file name** (file field, 128 bytes) - Path to boot image on TFTP server
- **Server hostname** (sname field, 64 bytes) - Name of boot server
- **Server IP** (siaddr field) - IP address of boot/TFTP server
- **Gateway IP** (giaddr field) - For BOOTP relay agents

### 5. Dual Logging

- **DEBUG**: Request summary ("BOOTP BootRequest from MAC 00:11:22:33:44:55")
- **TRACE**: Full hex dump of BOOTP packets (both request and response)
- Both go to netget.log and TUI Status panel

### 6. Connection Tracking

Each BOOTP request creates a "connection" entry:

- Connection ID: unique per request
- Protocol info: `ProtocolConnectionInfo::empty()` — no BOOTP-specific payload is attached
- Records the peer address and byte/packet counts
- Status: Active, and never reaped

### 7. Malformed-Packet Handling

Two panics are reachable here and both are guarded:

- `hlen` comes straight off the wire and dhcproto does not validate it, while
  `Message::chaddr()` slices a fixed `[u8; 16]` with it — `hlen > 16` panics inside the library.
  That parse runs in the socket task, so one datagram would kill the listener while the server still
  reported `Running`. `parse_bootp_message` rejects such datagrams before touching `chaddr()`
- `set_fname_str` / `set_sname_str` `assert!` on values longer than 128 / 64 bytes, and those values
  come from the LLM. `send_bootp_reply` checks the lengths and returns an error instead

### 8. Backend Failure — Deliberate Silence

**When the LLM call fails, this server sends nothing, and that is the protocol-correct answer.**

RFC 951 defines exactly two operations, BOOTREQUEST and BOOTREPLY. There is no NAK — DHCPNAK is a
DHCP message-type *option*, which BOOTP does not have — and no status field anywhere in the frame.
The only thing that could go on the wire on failure is a BOOTREPLY, and a BOOTREPLY is an offer: the
client reads `yiaddr`, `siaddr` and `file` and boots from them. A reply carrying 0.0.0.0 is either
discarded as garbage or, on a lenient client, ends the retransmit loop and strands a machine that the
next retry (or another BOOTP server on the segment) would have served.

Silence is already what the protocol means by "not me". RFC 951 §7.1 has the client retransmit with
backoff precisely so that a busy or absent server costs nothing, so a transient backend failure
resolves itself on the client's next attempt — the same outcome the `Overloaded` category buys in
protocols that can express it.

The three outcomes are therefore distinguished **in the log only**, by `decision=`
(`BootpServer::log_silence`):

| `decision=` | Meaning |
|---|---|
| `model_decline` | The model ran `ignore_request` — it looked at the request and chose not to serve this client |
| `no_answer` | The model produced no action at all |
| `fail_closed_overloaded` | The LLM call errored and `WireFailure::classify` called it saturation |
| `fail_closed_unavailable` | The LLM call errored otherwise |

The error itself goes to `tracing::error!` and the TUI status stream. **Nothing derived from it ever
reaches a datagram** — see `src/utils/wire_failure.rs` and `tests/wire_failure_test.rs`.

## LLM Integration

### Event Type

**`bootp_request`** - Triggered when BOOTP client sends a BOOTREQUEST

Event parameters:

- `op_code` (string) - `BootRequest` or `BootReply` (dhcproto's `Opcode` Debug spelling — match it
  case-sensitively)
- `client_mac` (string) - client hardware address as lower-case hex **without separators**
  (`001122334455`, not `00:11:22:33:44:55`). Handlers and prompts that match on a MAC must use this
  form; `send_bootp_reply`'s own `client_mac` parameter accepts either
- `client_ip` (string) - ciaddr, usually `0.0.0.0` initially
- `xid` (number) - transaction id; `send_bootp_reply` echoes it automatically
- `gateway_ip` (string) - giaddr of the relay the request came through; echoed automatically

### Available Actions

#### `send_bootp_reply`

Send BOOTP REPLY in response to BOOTREQUEST. Provides IP and boot configuration.

Parameters:

- `assigned_ip` (required) - IP address to assign (e.g., "192.168.1.100")
- `server_ip` (optional) - BOOTP/TFTP server IP (default: "0.0.0.0")
- `boot_file` (optional) - Boot file path (e.g., "boot/pxeboot.n12"), at most 128 bytes
- `server_hostname` (optional) - Server hostname (e.g., "bootserver.local"), at most 64 bytes
- `gateway_ip` (optional) - Gateway/relay IP (default: the request's giaddr)
- `xid` (optional) - transaction id override; omit to echo the request
- `client_mac` (optional) - hardware address override; omit to echo the request

#### `send_bootp_response` (Advanced)

Send a complete packet as hex, at least 236 bytes. The field is decoded **strictly** as hex —
whitespace, `:` separators and a leading `0x` are stripped, anything else that fails to decode
returns an error instead of being sent as literal ASCII. Nothing is echoed into a raw packet, so the
xid at bytes 4-7 must match the request.

#### `ignore_request`

Don't send any response.

### Example LLM Response

```json
{
  "actions": [
    {
      "type": "send_bootp_reply",
      "assigned_ip": "192.168.1.100",
      "server_ip": "192.168.1.1",
      "boot_file": "boot/pxeboot.n12",
      "server_hostname": "bootserver.local"
    },
    {
      "type": "notify_operator",
      "message": "Assigned 192.168.1.100 to client 00:11:22:33:44:55"
    }
  ]
}
```

## Connection Management

### Connection Lifecycle

1. **Request Received**: UDP datagram on port 67
2. **Parse**: Extract operation code, MAC address, existing IP using dhcproto
3. **Context**: Store BootpRequestContext in protocol instance
4. **Register**: Create ConnectionId and add to ServerInstance
5. **Process**: Call LLM with `bootp_request` event
6. **Execute**: Build BOOTP response using dhcproto and context
7. **Respond**: Send UDP response to client
8. **Update**: Track bytes/packets sent/received
9. **Persist**: Connection remains in UI to show activity

### BOOTP Flow

Standard BOOTP follows simple 2-message exchange:

1. **BOOTREQUEST** (client broadcast on port 68 → server port 67) - Client requests IP and boot info
2. **BOOTREPLY** (server port 67 → client port 68) - Server provides IP and boot file location

NetGet implements the server side (listens for BOOTREQUEST, sends BOOTREPLY).

## Differences from DHCP

### What BOOTP Has:

- Basic IP assignment (yiaddr field)
- Boot file name (file field, 128 bytes)
- Server name (sname field, 64 bytes)
- Server IP (siaddr field)
- Gateway/relay support (giaddr field)

### What BOOTP Lacks (compared to DHCP):

- No DHCP options (subnet mask, DNS, lease time, etc.)
- No DISCOVER/OFFER/REQUEST/ACK state machine (just REQUEST/REPLY)
- No dynamic lease management
- No address renewal or release
- No vendor-specific options

**Migration Note**: DHCP extended BOOTP by adding the options field. A BOOTP packet is valid DHCP, but DHCP adds rich
configuration via options.

## Known Limitations

### 1. No Subnet/DNS Configuration

- BOOTP doesn't include subnet mask, DNS servers, or lease time
- These are typically configured via TFTP config files after boot
- Workaround: Use DHCP instead for full network configuration

### 2. No Relay Agent State

- Basic relay support via giaddr field
- No advanced relay agent options
- Assumes simple network topology

### 3. No IP Pool Management

- No persistent IP assignment tracking
- LLM decides IPs on-demand (could assign duplicates)
- No conflict detection

**Use Case**: Testing, honeypots, PXE boot environments, demonstrations. Not suitable for production BOOTP server.

### 4. No Boot File Validation

- Server doesn't verify boot file exists
- No TFTP integration (separate protocol)
- LLM specifies file path, but file must exist on TFTP server

### 5. Feature-Gated

- BOOTP parsing requires `bootp` feature flag
- Without feature: Server accepts packets but can't parse them
- Action execution returns error if feature not enabled

## Example Prompts

### PXE Boot Server

```
listen on port 67 via bootp
When receiving BOOTREQUEST, assign IP addresses from 192.168.1.100 onwards
Respond with:
  - Server IP: 192.168.1.1
  - Boot file: boot/pxeboot.n12
  - Server hostname: pxeserver.local
```

### Static IP Assignment by MAC

```
listen on port 67 via bootp
For MAC 00:11:22:33:44:55, always assign 192.168.1.50 with boot file "linux/vmlinuz"
For MAC 00:11:22:33:44:66, always assign 192.168.1.51 with boot file "windows/bootmgr.efi"
For other clients, assign from 192.168.1.100 onwards with default boot file "boot/default.pxe"
```

### Network Boot with Gateway

```
listen on port 67 via bootp
Assign IPs in range 10.0.0.100 to 10.0.0.200
Use server IP 10.0.0.1, gateway 10.0.0.1
Boot file: tftp/netboot.img
Server hostname: netboot.example.com
```

### Honeypot Mode

```
listen on port 67 via bootp
Accept all BOOTREQUEST messages but respond with fake boot configurations
Assign random IPs in 10.255.0.0/16 range
Use boot file "honeypot/trap.bin" and server IP 10.255.255.1
Log all MAC addresses for analysis
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
- BOOTP traffic is typically low volume (diskless clients boot once)

### Scripting Compatibility

BOOTP is excellent candidate for scripting:

- Simple request/response pattern
- Deterministic IP assignment logic
- PXE environments often have static MAC-to-IP mappings

When scripting enabled:

- Server startup generates script (1 LLM call)
- All requests handled by script (0 LLM calls)
- Script can implement MAC-based static assignments, IP pools, etc.

## Use Cases

### 1. PXE Boot Environment

BOOTP is commonly used with PXE (Preboot Execution Environment):

- Client broadcasts BOOTREQUEST
- BOOTP server responds with IP and boot file name
- Client downloads boot file via TFTP
- Client boots network OS

### 2. Diskless Workstations

Historical use case (1980s-1990s):

- Workstations with no local storage
- Boot OS entirely from network
- BOOTP provides initial network configuration

### 3. Network Boot Testing

Modern use case:

- Testing PXE boot configurations
- Validating boot file paths
- Simulating boot servers for QA

### 4. Honeypots

Security research:

- Attract network boot scans
- Log unauthorized boot attempts
- Analyze attacker boot file requests

## References

- [RFC 951: Bootstrap Protocol (BOOTP)](https://datatracker.ietf.org/doc/html/rfc951)
- [RFC 1542: Clarifications and Extensions for BOOTP](https://datatracker.ietf.org/doc/html/rfc1542)
- [dhcproto Documentation](https://docs.rs/dhcproto/latest/dhcproto/)
- [BOOTP vs DHCP Comparison](https://www.ietf.org/rfc/rfc2131.txt)
- [PXE Specification (Intel)](https://www.intel.com/content/www/us/en/architecture-and-technology/preboot-execution-environment.html)
