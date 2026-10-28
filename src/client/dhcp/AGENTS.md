# DHCP Client Protocol Implementation

## Overview

DHCP (Dynamic Host Configuration Protocol) client implementing RFC 2131 for IP address discovery and network
configuration testing. The LLM controls DHCP DISCOVER/REQUEST/INFORM flow using structured actions.

**Status**: Medium Complexity
**RFC**: RFC 2131 (DHCP), RFC 2132 (DHCP Options)
**Port**: 68 (client), 67 (server) - UDP
**Use Case**: DHCP testing, network diagnostics, IP address discovery (NOT for managing OS network stack)

## Library Choices

- **dhcproto v0.11** - DHCP protocol parsing and construction
    - Used for encoding DHCP requests (DISCOVER, REQUEST, INFORM)
    - Used for parsing DHCP responses (OFFER, ACK, NAK)
    - Handles binary DHCP wire format
    - Provides Message, Opcode, MessageType, DhcpOption types
    - Feature-gated (only compiled when `dhcp` feature enabled)
- **rand** - For generating random transaction IDs (xid)
- **tokio::net::UdpSocket** - UDP networking for DHCP communication

**Rationale**: dhcproto is the standard Rust library for DHCP. It handles the complex binary protocol (based on BOOTP)
and provides type-safe DHCP option handling. The LLM doesn't need to understand DHCP packet structure - it just provides
semantic data (MAC address, requested IP) and the library handles encoding.

## Architecture Decisions

### 1. Action-Based LLM Control

The LLM sends DHCP requests with semantic actions:

- `dhcp_discover` - Send DHCP DISCOVER to find DHCP servers
- `dhcp_request` - Send DHCP REQUEST to request specific IP
- `dhcp_inform` - Send DHCP INFORM to query network configuration
- `disconnect` - Close DHCP client
- `wait_for_more` - Wait for more responses before acting

Each action includes parameters like MAC address, requested IP, broadcast flag.

### 2. UDP Socket Binding

DHCP clients bind to port 68:

- Requires elevated privileges on most systems (port < 1024)
- Broadcast mode enabled for sending to 255.255.255.255:67
- Unicast mode supported for targeting specific DHCP servers
- Receives responses from DHCP servers on port 67

### 3. Connection State Machine

Each client maintains state (Idle/Processing):

- **Idle**: Ready to process new responses
- **Processing**: LLM is analyzing response, queue incoming data

This prevents concurrent LLM calls on the same client.

### 4. DHCP Message Construction

Actions trigger packet construction:

- **DISCOVER**: Broadcast to find DHCP servers, optionally request specific IP
- **REQUEST**: Request IP from specific server (after OFFER received)
- **INFORM**: Query network configuration for already-configured interface

Each message includes:

- Transaction ID (xid) - Random 32-bit value
- Client MAC address (chaddr) - 16 bytes (6 bytes MAC + 10 bytes padding)
- DHCP options (message type, requested IP, server identifier)

### 5. DHCP Response Parsing

Responses are parsed to extract:

- Message type (OFFER, ACK, NAK)
- Offered/assigned IP address (yiaddr field)
- Server IP (option 54)
- Subnet mask (option 1)
- Router/gateway (option 3)
- DNS servers (option 6)
- Lease time (option 51)

Parsed data is sent to LLM as structured JSON.

### 6. Dual Logging

- **DEBUG**: Request/response summaries ("DHCP sent DISCOVER", "DHCP received OFFER")
- **TRACE**: Full hex dump of DHCP packets (both requests and responses)
- Both go to netget.log and TUI Status panel

## LLM Integration

### Event Types

#### `dhcp_connected`

Triggered when DHCP client initializes.

Event parameters:

- `server_addr` (string) - DHCP server address being targeted
- `local_addr` (string) - Local address bound to port 68

#### `dhcp_response_received`

Triggered when DHCP server sends a response.

Event parameters:

- `message_type` (string) - OFFER, ACK, NAK, etc.
- `details` (object) - Parsed response details:
    - `transaction_id` - Transaction ID (hex)
    - `client_mac` - Client MAC address (hex)
    - `offered_ip` - IP address offered/assigned
    - `server_ip` - DHCP server IP
    - `subnet_mask` - Subnet mask
    - `router` - Default gateway
    - `dns_servers` - Array of DNS server IPs
    - `lease_time` - Lease duration in seconds

### Available Actions

#### `dhcp_discover`

Send DHCP DISCOVER message to find DHCP servers.

Parameters:

- `mac_address` (optional) - Client MAC address (e.g., "00:11:22:33:44:55")
- `requested_ip` (optional) - Requested IP address
- `broadcast` (optional) - Send as broadcast (default: true)

#### `dhcp_request`

Send DHCP REQUEST message to request IP address.

Parameters:

- `requested_ip` (required) - IP address to request
- `server_ip` (optional) - DHCP server IP address
- `mac_address` (optional) - Client MAC address
- `broadcast` (optional) - Send as broadcast (default: true)

#### `dhcp_inform`

Send DHCP INFORM message to query network configuration.

Parameters:

- `current_ip` (required) - Current IP address of the client
- `mac_address` (optional) - Client MAC address

#### `disconnect`

Disconnect from DHCP server.

#### `wait_for_more`

Wait for more DHCP responses before taking action.

### Example LLM Response

```json
{
  "actions": [
    {
      "type": "dhcp_discover",
      "mac_address": "00:11:22:33:44:55",
      "broadcast": true
    }
  ]
}
```

After receiving OFFER:

```json
{
  "actions": [
    {
      "type": "dhcp_request",
      "requested_ip": "192.168.1.100",
      "server_ip": "192.168.1.1",
      "mac_address": "00:11:22:33:44:55",
      "broadcast": true
    }
  ]
}
```

## Connection Management

### Connection Lifecycle

1. **Initialize**: Bind to UDP port 68 (client port)
2. **Connect Event**: Call LLM with `dhcp_connected` event
3. **LLM Action**: LLM sends `dhcp_discover` or `dhcp_request`
4. **Send**: Construct and send DHCP packet to server
5. **Receive**: Wait for DHCP response from server
6. **Parse**: Extract message type and options using dhcproto
7. **Process**: Call LLM with `dhcp_response_received` event
8. **Execute**: LLM decides next action (request, inform, wait, disconnect)
9. **Persist**: Connection remains active until disconnect

### DHCP Flow (DORA)

Standard DHCP follows 4-message exchange:

1. **DISCOVER** (client broadcast) → Server responds with OFFER
2. **REQUEST** (client requests offered IP) → Server responds with ACK

NetGet implements client side of this exchange.

### Broadcast vs Unicast

- **Broadcast**: Send to 255.255.255.255:67 (default)
- **Unicast**: Send to specific server IP:67
- LLM controls via `broadcast` parameter

## Known Limitations

### 1. Does NOT Configure OS Network Stack

- This is for DHCP **testing and monitoring** only
- Does NOT configure network interfaces
- Does NOT assign IP addresses to OS
- Does NOT update routing tables or DNS configuration
- The OS DHCP client continues to manage actual network configuration

**Use Case**: Testing DHCP servers, monitoring DHCP traffic, network diagnostics.

### 2. Requires Elevated Privileges

- Binding to port 68 requires root/administrator privileges
- May fail on systems with restrictive permissions
- Error message: "Failed to bind to DHCP client port 68"

**Workaround**: Run NetGet with sudo/administrator privileges.

### 3. No Lease Management

- No persistent lease database
- No tracking of assigned IPs
- No lease renewal or expiration handling
- LLM decides actions on-demand

### 4. Limited DHCP Options

Client supports common options only:

- Message Type, Requested IP, Server Identifier
- Missing: Parameter Request List, Client Identifier, Vendor Class, etc.
- Responses parse: Subnet Mask, Router, DNS, Lease Time

**Workaround**: For advanced options, use raw packet construction (future enhancement).

### 5. No DHCP Release Tracking

- Doesn't send DHCPRELEASE on disconnect
- No handling of DHCPDECLINE (address conflict)
- No renew/rebind support

### 6. No DHCPv6 Support

- IPv4 only (RFC 2131)
- No support for IPv6 address assignment (RFC 8415)

### 7. Feature-Gated

- DHCP parsing requires `dhcp` feature flag
- Without feature: Client fails to compile
- Action execution returns error if feature not enabled

## Example Prompts

### Basic DHCP Discovery

```
connect to dhcp server at 192.168.1.1
Send DHCP DISCOVER to find available IP addresses
When receiving DHCP OFFER, analyze the offered IP and network configuration
```

### DHCP Request for Specific IP

```
connect to dhcp server at 192.168.1.1
Send DHCP REQUEST for IP 192.168.1.100
Use MAC address 00:11:22:33:44:55
```

### DHCP Server Testing

```
connect to dhcp server at 10.0.0.1
Send DHCP DISCOVER with MAC 00:11:22:33:44:55
When receiving OFFER, check if offered IP is in range 10.0.0.100-10.0.0.200
If yes, send REQUEST to accept the IP
If no, log error and disconnect
```

### Multiple DHCP Server Detection

```
connect to dhcp server at 255.255.255.255 (broadcast)
Send DHCP DISCOVER to find all DHCP servers on network
Wait for multiple OFFER responses
Log all servers that respond with their offered IPs
```

## Performance Characteristics

### Latency

- DHCP message construction: ~50-100 microseconds
- DHCP parsing: ~50-100 microseconds
- LLM decision: 2-5 seconds per event
- Total per DORA exchange: ~5-10 seconds (2 LLM calls)

### Throughput

- Limited by LLM response time (~0.2-0.5 requests/sec)
- DHCP is typically low-volume (client requests IP once)
- Good for testing and diagnostics, not for high-volume simulation

### Scripting Compatibility

DHCP client is NOT a good candidate for scripting:

- Scripting is for server-side request handling
- Clients don't have "scripting mode" (each connection is interactive)

## Security Considerations

### DHCP Spoofing/Testing

- Can send DHCP requests with arbitrary MAC addresses
- Can request specific IP addresses
- **Use responsibly** - only for authorized testing

### Privilege Requirements

- Requires root/administrator to bind port 68
- Broadcast messages may be visible to network
- DHCP traffic is unencrypted (as per protocol)

## References

- [RFC 2131: Dynamic Host Configuration Protocol](https://datatracker.ietf.org/doc/html/rfc2131)
- [RFC 2132: DHCP Options and BOOTP Vendor Extensions](https://datatracker.ietf.org/doc/html/rfc2132)
- [dhcproto Documentation](https://docs.rs/dhcproto/latest/dhcproto/)
- [DHCP Message Types (IANA)](https://www.iana.org/assignments/bootp-dhcp-parameters/bootp-dhcp-parameters.xhtml)
- [DHCP Options (IANA)](https://www.iana.org/assignments/bootp-dhcp-parameters/bootp-dhcp-parameters.xhtml#options)
- [CLIENT_PROTOCOL_FEASIBILITY.md](../../../docs/planning/CLIENT_PROTOCOL_FEASIBILITY.md) - DHCP client feasibility analysis

## Command channel (dashboard `[ send ]`)

`AppState::send_to_client` can inject an action into the running client. The channel is
registered in `connect_with_llm_actions` **before** the `dhcp_client_connected` LLM call,
because a `manual` routing rule can park that event for minutes and the operator must be able
to reach the client while it waits.

`UdpSocket::recv_from` is cancellation-safe, so the command arm is a `tokio::select!` arm in
the receive loop rather than a separate task.

The connect path and the receive loop used to carry two near-identical copies of the
`dhcp_discover` / `dhcp_request` / `dhcp_inform` encoding. Both now go through one
`apply_action_result`, which the command arm also calls, so an injected packet is
byte-identical to an LLM-produced one. Its `unicast_target` argument is the only difference
the two call sites ever had: the configured server on the connect path, the peer that just
answered us in the receive loop. `dhcp_inform` is always unicast (a client sending INFORM
already has an address); `dhcp_discover` / `dhcp_request` honour the action's `broadcast`
flag, default `true`.

Outcomes:

| Action | Outcome |
|---|---|
| `dhcp_discover` / `dhcp_request` / `dhcp_inform` | `Sent { bytes_sent }` — the count `send_to` returned |
| `disconnect` | `Disconnected`; the receive loop ends |
| `wait_for_more` | `Executed { detail: "wait_for_more" }` |
| unknown type / bad params | `Rejected { error }` from `execute_action` |

### Port 68 is preferred, not required

The client tried to bind `0.0.0.0:68` and returned `Err` when it could not. Port 68 is
privileged, so that made the DHCP client unusable for every unprivileged run — including the
dashboard's own `[ + new client ]` — and untestable without root. It now falls back to an
ephemeral port with a `WARN`, mirroring the BOOTP client. The cost is real: a server that
replies by broadcasting to port 68, which RFC 2131 allows when the BROADCAST flag is set,
will not be heard on an ephemeral port. Unicast replies to our source port are.
