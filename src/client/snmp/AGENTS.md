# SNMP Client Protocol Implementation

## Overview

SNMP client implementing RFC 1157 (SNMPv1) and RFC 3416 (SNMPv2c) using the rasn-snmp library. Enables LLM-controlled
SNMP operations against network devices and agents - querying OIDs, walking MIB trees, and modifying agent values. Uses
UDP transport for request/response protocol.

**Status**: Experimental (Network Management Protocol Client)
**RFC**: RFC 1157 (SNMPv1), RFC 3416 (SNMPv2c)
**Port**: 161 (agent), 162 (trap receiver)
**Transport**: UDP

## Library Choices

### Core SNMP Implementation

- **rasn-snmp v0.18** - Pure Rust SNMP protocol implementation
    - BER (Basic Encoding Rules) encoding/decoding
    - SNMPv1 and SNMPv2c message building and parsing
    - PDU types: GetRequest, GetNextRequest, GetBulkRequest, SetRequest, Response
    - Variable binding support (OID + value pairs)

- **rasn v0.18** - ASN.1 encoding library
    - BER encoder/decoder (used by rasn-snmp)
    - OID type representation and parsing
    - Integer, OctetString, and other ASN.1 types

**Rationale**: rasn-snmp provides clean API for both encoding requests and decoding responses. Unlike the server (which
uses manual BER encoding for responses), the client can use rasn-snmp's built-in encoding for all request types. This
simplifies request construction while maintaining full protocol compliance.

## Architecture Decisions

### 1. UDP Request/Response Model

SNMP uses UDP (connectionless):

- Each request is independent (no session state)
- Client binds to ephemeral port, connects to agent port 161
- Response matching via request ID (random i32)
- Timeout and retry logic (default: 5s timeout, 3 retries)
- No connection tracking in traditional sense

**"Connection" Semantics**:

- `connect()` binds UDP socket and sets default destination
- Socket remains bound for entire client lifetime
- Multiple requests can be sent sequentially
- Each request generates unique request ID

### 2. LLM Control Points

**Two Integration Points**:

1. **Initial Connection Event** (`snmp_connected`):
    - Triggered when client connects to agent
    - LLM can send initial queries (e.g., GET sysDescr)
    - No data received yet

2. **Response Event** (`snmp_response_received`):
    - Triggered when agent responds to request
    - Includes: request type, variables (OID/value pairs), error status
    - LLM decides: send follow-up requests, walk tree, or finish

**Request Types Controlled by LLM**:

- `send_snmp_get` - GET request for specific OIDs
- `send_snmp_getnext` - GETNEXT for walking OID tree
- `send_snmp_getbulk` - GETBULK for efficient bulk retrieval (v2c only)
- `send_snmp_set` - SET request to modify agent values
- `disconnect` - Close client

### 3. Configuration Parameters

**Startup Parameters** (optional):

- `community` - Community string (default: "public")
- `version` - SNMP version: "v1" or "v2c" (default: "v2c")
- `timeout_ms` - Request timeout in milliseconds (default: 5000)
- `retries` - Number of retries on timeout (default: 3)

**Example**:

```json
{
  "community": "private",
  "version": "v2c",
  "timeout_ms": 3000,
  "retries": 2
}
```

### 4. Request/Response Flow

**GET Request Flow**:

1. LLM generates `send_snmp_get` action with OID list
2. Client builds SNMP GetRequest PDU (random request ID)
3. Encode with rasn-snmp BER encoder
4. Send UDP packet to agent
5. Wait for response with timeout
6. Parse response and extract variables
7. Call LLM with `snmp_response_received` event
8. LLM decides follow-up actions

**GETNEXT Flow** (for MIB walking):

1. LLM sends `send_snmp_getnext` with starting OID
2. Agent returns next OID in tree
3. LLM receives response with new OID
4. LLM sends another GETNEXT with new OID
5. Repeat until end of MIB or desired subtree walked

**GETBULK Flow** (v2c only, more efficient):

1. LLM sends `send_snmp_getbulk` with starting OID and parameters
2. Agent returns multiple next OIDs in single response
3. LLM processes bulk results
4. LLM can send another GETBULK to continue

### 5. Version Support

**SNMPv1** (version=0 in packet):

- Supports: GetRequest, GetNextRequest, SetRequest, GetResponse
- No GETBULK support
- Error handling: noError, tooBig, noSuchName, badValue, readOnly, genErr
- Uses `v1::Message` and `v1::Pdu` types

**SNMPv2c** (version=1 in packet):

- Supports: GetRequest, GetNextRequest, GetBulkRequest, SetRequest, Response
- More efficient bulk operations
- Enhanced error codes: NoSuchObject, NoSuchInstance, EndOfMibView
- Uses `v2c::Message` and `v2::Pdu` types

**Version Selection**:

- Specified in startup params (default: v2c)
- Client uses appropriate request builder based on version
- Response parsing handles both v1 and v2c automatically

### 6. Timeout and Retry Logic

**Timeout Handling**:

- Default timeout: 5000ms per request
- Configurable via `timeout_ms` parameter
- Uses `tokio::time::timeout` for async timeout

**Retry Strategy**:

- Default retries: 3
- Exponential backoff NOT implemented (constant retry)
- Each retry sends same request (same request ID)
- After all retries exhausted, return error to LLM

**Error Scenarios**:

- Network timeout → Retry up to N times → Error
- Parse failure → Immediate error (no retry)
- SNMP error status (noSuchName, etc.) → Report to LLM (no retry)

### 7. OID Handling

**OID Format**: Dotted decimal notation (e.g., "1.3.6.1.2.1.1.1.0")

**Common OIDs** (LLM should know these):

- `1.3.6.1.2.1.1.1.0` - sysDescr (system description)
- `1.3.6.1.2.1.1.3.0` - sysUpTime (system uptime)
- `1.3.6.1.2.1.1.5.0` - sysName (system name)
- `1.3.6.1.2.1.2.2.1.x.N` - ifTable (interface stats for interface N)

**OID Parsing**:

- Client uses `str::parse()` with rasn OID type
- Invalid OIDs default to 0.0 (rasn-snmp handles gracefully)
- LLM receives OIDs as strings in responses

**MIB Walking**:

- GETNEXT returns next OID in lexicographic order
- LLM compares returned OID to know when to stop
- End of MIB indicated by `EndOfMibView` in v2c

### 8. Dual Logging

All operations use **dual logging**:

- **DEBUG**: Request/response summaries (request type, OIDs, error status)
- **TRACE**: Full packet hex dump (both request and response)
- **INFO**: LLM messages and high-level events
- **ERROR**: Parse failures, encoding errors, timeout errors, LLM errors
- All logs go to both `netget.log` (via tracing) and TUI Status panel (via status_tx)

## LLM Integration

### Action-Based Request Model

**Available Actions** (from LLM):

1. **send_snmp_get**:
   ```json
   {
     "type": "send_snmp_get",
     "oids": ["1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.5.0"]
   }
   ```

2. **send_snmp_getnext**:
   ```json
   {
     "type": "send_snmp_getnext",
     "oids": ["1.3.6.1.2.1.1"]
   }
   ```

3. **send_snmp_getbulk** (v2c only):
   ```json
   {
     "type": "send_snmp_getbulk",
     "oids": ["1.3.6.1.2.1.2.2.1"],
     "non_repeaters": 0,
     "max_repetitions": 10
   }
   ```

4. **send_snmp_set**:
   ```json
   {
     "type": "send_snmp_set",
     "variables": [
       {"oid": "1.3.6.1.2.1.1.5.0", "type": "string", "value": "new-hostname"}
     ]
   }
   ```

5. **disconnect**:
   ```json
   {
     "type": "disconnect"
   }
   ```

### Events Sent to LLM

1. **snmp_connected**:
   ```json
   {
     "remote_addr": "192.168.1.1:161"
   }
   ```

2. **snmp_response_received**:
   ```json
   {
     "request_type": "GetRequest",
     "variables": [
       {"oid": "1.3.6.1.2.1.1.1.0", "value": "Linux router 5.10.0"},
       {"oid": "1.3.6.1.2.1.1.5.0", "value": "router-01"}
     ],
     "error_status": 0
   }
   ```

### Example LLM Flows

**Query System Info**:

```
User: "Connect to SNMP agent at 192.168.1.1 and get system description"

LLM receives: snmp_connected event
LLM returns: send_snmp_get with oids=["1.3.6.1.2.1.1.1.0"]

LLM receives: snmp_response_received with variables
LLM returns: disconnect (if done) or more requests
```

**Walk Interface Table**:

```
User: "Walk the interface table (1.3.6.1.2.1.2.2.1) to list all interfaces"

LLM receives: snmp_connected event
LLM returns: send_snmp_getnext with oids=["1.3.6.1.2.1.2.2.1"]

LLM receives: snmp_response_received with first interface OID
LLM returns: send_snmp_getnext with returned OID (to get next)

[Repeat until OID no longer starts with 1.3.6.1.2.1.2.2.1]

LLM returns: disconnect (when walk complete)
```

## Known Limitations

### 1. SNMPv3: one USM user per client

`version: "v3"` with `v3_user` (`{name, auth_protocol, auth_password, priv_protocol,
priv_password}`) and an optional `context_name`. The crypto and the message format are
`src/server/snmp/usm.rs`'s, shared with the agent (`usm::Manager`). The agent's engine is
discovered **in `connect()`**, before the command channel or the connected event: an agent that
never answers discovery fails the start rather than leaving a client that can address nothing.
Each request is built by the v2c builders and its PDU re-wrapped (`to_v3`), so v2c and v3 put the
same PDU on the wire. A reply is believed only after its message id matches one of the last 16
sent, its engine is the discovered one, and — when authenticated — its MAC verifies; a response
must also come back at the level asked. A USM report reaches the handler as
`snmp_response_received` with `usm_report: {report, count}` and empty variables; an authenticated
`NotInTimeWindows` report resynchronises the clock first, so resending works. A clock outside
RFC 3414's `0..2147483647`, in the discovery report or in an authenticated report, is refused
rather than stored. Every reply — the discovery report included — goes through `usm::decode`,
which depth-screens the whole message and then the msgSecurityParameters contents before `rasn`
decodes either (see `src/server/snmp/AGENTS.md` §7). Passwords live only
in the localized keys and are redacted from every log by name. Not offered: AES-192/256, v3
notifications.

### 2. No Trap/Inform Sending

- Client can only send requests (GET, GETNEXT, GETBULK, SET)
- Cannot send traps or inform messages
- Agent can send traps to client, but client doesn't listen for them

**Workaround**: Use server mode to receive traps on port 162.

### 3. No Async Request Queueing

- Client processes requests sequentially (one at a time)
- Each request waits for response before sending next
- No parallel requests to same agent

**Rationale**: Simplifies request/response matching. SNMP is typically low-volume.

### 4. Fixed Timeout/Retry Strategy

- Constant timeout (no adaptive adjustment)
- No exponential backoff on retries
- Same request ID used for all retries (SNMP allows this)

**Workaround**: Adjust `timeout_ms` and `retries` in startup params.

### 5. No MIB File Loading

- No MIB file parsing
- LLM must know OIDs (can be provided in prompt)
- No OID name resolution (e.g., "sysDescr" → "1.3.6.1.2.1.1.1.0")

**Workaround**: Include common OIDs in prompt or rely on LLM's training data.

### 6. Limited Value Type Support in SET

- SET supports: string, integer
- No support for: counter, gauge, timeticks, ipaddress, etc. in SET
- GET/GETNEXT/GETBULK can receive all types

**Rationale**: Most SET operations use string or integer values. Other types less common.

## Example Prompts

### Query System Information

```
Connect to SNMP agent at 192.168.1.1:161 using community 'public'.
Query the following system OIDs:
- 1.3.6.1.2.1.1.1.0 (sysDescr)
- 1.3.6.1.2.1.1.3.0 (sysUpTime)
- 1.3.6.1.2.1.1.5.0 (sysName)
Display the results and disconnect.
```

### Walk Interface Table

```
Connect to SNMP agent at 10.0.0.1:161.
Walk the ifTable subtree (1.3.6.1.2.1.2.2.1) to discover all network interfaces.
For each interface, collect:
- ifIndex (1.3.6.1.2.1.2.2.1.1.N)
- ifDescr (1.3.6.1.2.1.2.2.1.2.N)
- ifSpeed (1.3.6.1.2.1.2.2.1.5.N)
Use GETNEXT to walk the tree. Stop when OIDs no longer start with 1.3.6.1.2.1.2.2.1.
```

### Bulk Retrieval (SNMPv2c)

```
Connect to SNMP agent at 192.168.1.254:161 using SNMPv2c.
Use GETBULK to efficiently retrieve interface statistics:
- Start at 1.3.6.1.2.1.2.2.1.10 (ifInOctets)
- non_repeaters=0, max_repetitions=20
Display the first 20 results.
```

### Set System Name

```
Connect to SNMP agent at 10.0.0.100:161 using community 'private'.
Set the system name (1.3.6.1.2.1.1.5.0) to "router-lab-01".
Verify the change by reading the OID back.
```

## Performance Characteristics

### Latency

- Build request: <1ms (BER encoding via rasn-snmp)
- Network RTT: Variable (depends on network, typically 1-50ms LAN, 50-200ms WAN)
- Parse response: <1ms (BER decoding)
- LLM processing: 2-5s (typical)
- Total per request: ~2-5s (LLM dominates)

### Throughput

- Sequential requests only (no pipelining)
- Limited by LLM response time (~2-5s per request)
- MIB walk of 100 OIDs: ~3-8 minutes (GETNEXT)
- Same walk with GETBULK (max_repetitions=10): ~30-80s (10x faster)

### Concurrency

- Single client = sequential requests
- Multiple clients (different ClientId) = parallel to different agents
- No request pipelining to same agent

### Memory

- Each request allocates small buffers (<1KB for typical request)
- Each response allocates ~65KB buffer (max UDP packet size)
- No persistent state per request (stateless protocol)

## Security Considerations

### Plaintext Protocol

- SNMPv1/v2c has no encryption
- Community string sent in cleartext (like password)
- All OID values visible to network sniffers

### Community String

- Acts as shared password
- Typically "public" for read-only, "private" for read-write
- No per-user authentication
- Easily brute-forced or sniffed

### SET Request Security

- SET requests modify agent state
- Requires write community string (typically "private")
- No authorization beyond community string
- LLM can potentially modify critical device config

**Recommendation**: Use read-only community ("public") for monitoring, require user confirmation for SET operations.

## Comparison with Server

| Aspect              | Server                                     | Client                                     |
|---------------------|--------------------------------------------|--------------------------------------------|
| **Role**            | Listens for requests, returns responses    | Sends requests, processes responses        |
| **Port**            | Binds to 161 (agent)                       | Binds to ephemeral port, sends to 161      |
| **LLM Integration** | Receives requests, LLM generates responses | LLM generates requests, receives responses |
| **Request Types**   | GET, GETNEXT, GETBULK, SET (received)      | GET, GETNEXT, GETBULK, SET (sent)          |
| **Use Case**        | SNMP agent / honeypot                      | Network monitoring / management            |
| **Encoding**        | Manual BER for responses                   | rasn-snmp encoding for requests            |
| **Decoding**        | rasn-snmp for requests                     | rasn-snmp for responses                    |

## References

- [RFC 1157: SNMP (SNMPv1)](https://datatracker.ietf.org/doc/html/rfc1157)
- [RFC 3416: SNMPv2 Protocol Operations](https://datatracker.ietf.org/doc/html/rfc3416)
- [rasn-snmp Documentation](https://docs.rs/rasn-snmp/latest/rasn_snmp/)
- [SNMP OID Reference](http://www.oid-info.com/)
- [Net-SNMP Tools](http://www.net-snmp.org/) - Command-line SNMP tools for testing

## Command channel (dashboard `[ send ]`)

`AppState::send_to_client` can inject an action into the running client. The channel is
registered **before** the `snmp_client_connected` LLM call (a `manual` routing rule can park
that event for minutes). SNMP has no standing read loop — each request awaits its own reply —
so the commands are drained by a task of their own (`command_loop`), registered with
`AppState::register_client_task`.

Two refactors make the injected path identical to the LLM path rather than a second
implementation:

- `build_request(name, data, config)` is a **pure** encoder replacing the four
  `send_*_request` helpers; both paths call it, so both put byte-identical PDUs on the wire.
- `send_request_and_handle_response` is split into the send plus `await_response`. The command
  loop reports its outcome the moment the datagram leaves and *then* awaits the reply, so an
  injected caller is not made to wait out `timeout_ms * (retries + 1)` before learning whether
  its request was sent. The response event still reaches the LLM exactly as before.

Outcomes:

| Action | Outcome |
|---|---|
| `send_snmp_get` / `getnext` / `getbulk` / `set` | `Sent { bytes_sent }` — the count `UdpSocket::send` returned |
| `disconnect` | `Disconnected`; the command loop ends |
| `wait_for_more` | `Executed { detail: "wait_for_more" }` |
| unknown type, empty `oids`, GETBULK on v1 | `Rejected { error }` |

A second command queues behind the first while its reply is awaited; the channel is bounded,
so a caller gets "client busy" rather than an unbounded backlog.
