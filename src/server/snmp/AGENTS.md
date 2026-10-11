# SNMP Protocol Implementation

## Overview

SNMP agent implementing RFC 1157 (SNMPv1) and RFC 3416 (SNMPv2c) using the rasn-snmp library. Provides network
management functionality where the LLM controls OID responses (system info, interface stats, custom MIBs). Uses UDP
transport for request/response protocol.

**Status**: Beta (Network Management Protocol)
**RFC**: RFC 1157 (SNMPv1), RFC 3416 (SNMPv2c), RFC 3584 (SNMPv2 Coexistence)
**Port**: 161 (agent), 162 (trap receiver)
**Privilege**: declares `PrivilegeRequirement::PrivilegedPort(161)`; any port above 1023 needs none.
**Test coverage**: `tests/server/snmp/test.rs` (the file is `test.rs`, not `e2e_test.rs`) drives the
agent with **Net-SNMP's own `snmpget` and `snmpgetnext`** — not the `snmp` Rust crate, which nothing
in the suite uses. Every call passes `-On -Oe`, so the assertions pin the decoded **type tag** as
well as the value (`Gauge32: 1000000000`, `Counter32: 42`, `INTEGER: 1`) and do not vary with the
MIB files installed on the machine. `tests/server/snmp/ber_depth_test.rs` covers the BER screen.

**What the Beta rating rests on, exactly**: Net-SNMP is the reference implementation and an
independent one, the tests are not `#[ignore]`d, and they **hard-fail** when the binaries are
missing (`Command::new("snmpget").output().await?` returns `NotFound`) rather than printing SKIP
and passing. The cost of that is real: Net-SNMP must exist wherever the suite runs. Note also that
**no CI job runs these tests** — the blocking `test` job compiles `tcp,http,dns,udp,redis,mcp-stdio`
and `registry-audit` is `continue-on-error` and does not run the e2e suites. A green PR says
nothing about SNMP.

## Library Choices

### Core SNMP Implementation

- **rasn-snmp v0.18** - Pure Rust SNMP protocol implementation
    - BER (Basic Encoding Rules) encoding/decoding
    - SNMPv1 and SNMPv2c message parsing
    - PDU types: GetRequest, GetNextRequest, GetBulkRequest, SetRequest, Response, Trap
    - Variable binding support (OID + value pairs)

- **rasn v0.18** - ASN.1 encoding library
    - BER encoder/decoder (used by rasn-snmp)
    - OID type representation
    - Integer, OctetString, and other ASN.1 types

- **Manual BER encoding** - Custom BER encoder for responses
    - Needed because rasn-snmp doesn't provide easy response building
    - Encodes: OID, Integer, OctetString, Counter, Gauge, TimeTicks
    - Length encoding goes through one `encode_length()` helper covering the short form and the
      0x81/0x82/0x83 long forms. This matters: the earlier per-site encoder only handled lengths
      below 256, so a sysDescr longer than 255 bytes — or simply a response with several variable
      bindings — emitted a truncated length byte and the client rejected the packet
    - Constructs complete SNMP response messages

**Rationale**: rasn-snmp is the most mature pure-Rust SNMP library with async support. However, it focuses on parsing (
client-side), not response building (server-side). We use it for parsing requests and then manually encode responses
using BER. This gives us full control over response format and allows the LLM to return simple JSON which we convert to
proper SNMP packets.

## Architecture Decisions

### 1. UDP Request/Response Model

SNMP uses UDP (stateless):

- Each request is independent
- No connection tracking (unlike TCP)
- Response must match request ID and community string
- Client may retry if no response (agent doesn't handle retries)

**Connection Tracking**:

- "Connection" = recent peer address that sent a request
- Recorded with `ProtocolConnectionInfo::empty()` — no SNMP-specific payload is attached
- Used for UI display only (not a protocol requirement)
- **A fresh entry is added per datagram**, never removed by this protocol, so `.connectionless()`
  is not merely permissible here but load-bearing: `AppState::cleanup_old_connections` is the only
  thing that reaps them, and it runs only where that flag is set. Without it the map grows for the
  life of the server. The flag is safe because SNMP genuinely has no connection concept — a
  request carries its own request-id and community and nothing in the next datagram has to be
  understood in the light of the last one, which is the actual test (TFTP was harmed by declaring
  it while carrying transfers)

### 2. LLM Control Point

Single integration point:

**SNMP Requests**:

- LLM receives `snmp_request` event with request type (GetRequest, GetNextRequest, etc.) and requested OIDs
- Returns JSON with variables array: `[{oid, type, value}, ...]`
- Server encodes JSON to BER format and sends to client

**Notifications (`notify.rs`)**:

- **Received**: a v1 Trap-PDU, a v2c SNMPv2-Trap or a v2c InformRequest on the agent's socket is
  not a request. It is decoded (rasn) into one `snmp_notification` event: `kind` (trap/inform),
  `version`, `community`, `client_ip`, v2c `trap_oid` (snmpTrapOID.0) and `uptime`
  (sysUpTime.0), v1 `enterprise`, `agent_addr`, `generic_trap`, `specific_trap` and `uptime`,
  and every other binding as `{oid, type, value}` (integer, string — `encoding: hex` when not
  printable text — oid, ipaddress, counter, gauge, timeticks, counter64, opaque, null and the
  v2 exceptions). The handler answers `acknowledge_notification` or `ignore_notification`
  (or forwards with `send_trap`). An inform gets its Response — request-id and bindings echoed —
  only on `acknowledge_notification`; ignored, silent or a failed model call
  (`decision=fail_closed_llm_error`) sends nothing, so the sender retries and gives up.
- **Sent** by `send_trap` (offered as an async action and on both events): a v2c trap (default),
  a v2c inform (`inform: true`, resent up to 3 times at 2 s until a Response with its
  request-id arrives) or a v1 trap (`version: v1`, with `enterprise`, `agent_addr`,
  `generic_trap`, `specific_trap`). v2c adds sysUpTime.0 (`uptime`, default the time since
  NetGet started) and snmpTrapOID.0 (`trap_oid`) in front of the model's bindings; at most 64
  bindings. The send runs as a registered server task beside the request that asked for it,
  and its outcome — acknowledged or not — is an `snmp_notification_sent` access-log entry.
  `target` is host or host:port, port 162 when omitted. Notifications are v1/v2c only; requests are also served over SNMPv3 (see Known Limitations §1).

### 3. JSON to BER Translation

LLM returns simple JSON, server converts to SNMP BER:

**LLM JSON Format**:

```json
{
  "variables": [
    {"oid": "1.3.6.1.2.1.1.1.0", "type": "string", "value": "NetGet SNMP Agent"},
    {"oid": "1.3.6.1.2.1.1.3.0", "type": "timeticks", "value": 12345}
  ]
}
```

**BER Encoding**:

1. Parse OID string to numeric array
2. Encode value based on type (string → OctetString, integer → Integer, etc.)
3. Wrap in SEQUENCE for variable binding
4. Build complete GetResponse PDU with request ID and community
5. Wrap in outer SEQUENCE for SNMP message

**Supported Value Types**:

- `string` - OCTET STRING (tag 0x04)
- `integer` - INTEGER (tag 0x02)
- `counter` - Counter32 (application tag 0x41)
- `gauge` - Gauge32 (application tag 0x42)
- `timeticks` - TimeTicks (application tag 0x43)
- `null` - NULL (tag 0x05)

### 4. Protocol Version Support

Supports both SNMPv1 and SNMPv2c:

**Parsing**:

- Try v2c first (ber::decode::<v2c::Message>)
- Fall back to v1 if v2c parse fails
- Extract request type, OIDs, and community string

**Response**:

- Use same version as request
- Match request ID and community string
- Encode response with appropriate PDU type (GetResponse for v1, Response for v2c)

**Version Differences**:

- v1: GetRequest, GetNextRequest, SetRequest, GetResponse, Trap
- v2c: Adds GetBulkRequest, InformRequest, Report
- Community string same for both (simple authentication)

### 5. OID Parsing and Formatting

OID handling is critical for SNMP:

**OID Format**: Dotted decimal notation (e.g., "1.3.6.1.2.1.1.1.0")

**Common OIDs**:

- `1.3.6.1.2.1.1.1.0` - sysDescr (system description)
- `1.3.6.1.2.1.1.3.0` - sysUpTime (system uptime in timeticks)
- `1.3.6.1.2.1.1.5.0` - sysName (system name)
- `1.3.6.1.2.1.2.2.1.x.N` - ifTable (interface stats for interface N)

**OID Encoding**:

1. First two components encoded specially: `first * 40 + second`
2. Remaining components encoded as base-128 (7 bits per byte, MSB=1 for continuation)
3. Example: "1.3.6" → `[0x2B, 0x06]` (43, 6)

**Validation**: `encode_oid` rejects an OID whose first component is above 2, whose second component
is 40 or more (when the first is 0 or 1), or that contains a non-numeric component. A non-numeric
component used to be dropped silently, which turned a typo into a different, valid-looking OID.

### 6. Error Handling

SNMP has built-in error responses:

**Error Status Codes**:

- 0: noError
- 1: tooBig (response too large)
- 2: noSuchName (OID not found)
- 3: badValue (invalid value in SetRequest)
- 4: readOnly (tried to set read-only OID)
- 5: genErr (generic error)

**Error Responses**:

- `send_snmp_error` takes `error_message` (logs only — SNMP has no field for text), an optional
  `error_status` given as a name (`noSuchName`, `badValue`, `readOnly`, `tooBig`, `genErr`) or as
  the matching code 0-5, and an optional 1-based `error_index`
- The reply carries that status with empty variable bindings
- Omitting `error_status` yields genErr (5), the previous fixed behaviour

### 7. Input Screening — the BER decoder is not safe to point at the network

`rasn` 0.18 decodes a *constructed* OCTET STRING by calling `ber::de::parser::parse_encoded_value`
on each of its segments, and a segment may itself be constructed — the function calls itself, with
no depth counter anywhere on the path. Both `v1::Message` and `v2c::Message` carry `community` as
an OCTET STRING, so the nesting a datagram *declares* is the recursion depth we get.

`24 80` — constructed OCTET STRING, indefinite length — costs two bytes and buys one level, and the
end-of-contents markers can be left off entirely: the decoder descends while input remains and only
notices the missing EOC on the way back up. A 64 KB UDP datagram therefore reaches ~32000 frames.
Measured: 30000 levels aborts with `fatal runtime error: stack overflow`, signal 6.

A Rust stack overflow is a guard-page SIGSEGV/SIGABRT, **not** a panic. `tokio::spawn` cannot
isolate it and `catch_unwind` cannot see it, so this was an unauthenticated remote kill switch for
every other server the NetGet process was running.

`check_ber_structure` (in `mod.rs`, `pub` so the client uses the same one) therefore walks the TLV
structure **iteratively** — an explicit stack, no recursion of its own — before rasn sees anything:

- nesting capped at `MAX_BER_DEPTH` = 16; a real SNMP message is 4 deep
  (Message > PDU > VarBindList > VarBind)
- a definite length is bounded against the **whole datagram**, not against the bytes that happen to
  remain after it — the same mistake read from the other side
- truncated tags, truncated lengths, a length-of-length past 8 octets, and an indefinite length on
  a primitive are all rejected

The client's response path has the identical exposure and calls the identical screen: the bytes
come from wherever the operator pointed it, and over UDP an off-path attacker can beat the real
agent to the reply.

### 8. Dual Logging

All operations use **dual logging**:

- **DEBUG**: Request summary (request type, OIDs, peer address)
- **TRACE**: Full packet hex dump (both request and response)
- **INFO**: LLM messages and high-level events
- **ERROR**: Parse failures, encoding errors, LLM errors
- All logs go to both `netget.log` (via tracing) and TUI Status panel (via status_tx)

**`decision=` tags**, in the shape `src/server/radius/` established. SNMP's wire format cannot carry
the difference between "the model refused this OID" and "NetGet could not reach the model" — both
are a non-zero error-status — so the distinction has to live in the log:

| tag | what happened | what the peer gets |
|---|---|---|
| `decision=model_answer` | the model returned variable bindings | Response, error-status 0 |
| `decision=model_reject` | the model called `send_snmp_error` | Response, its chosen error-status |
| `decision=model_silent` | `ignore_request`, or no action at all | nothing |
| `decision=fail_closed_llm_error` | the LLM call failed | Response, genErr(5) |
| `decision=fail_closed_llm_overload` | the LLM call failed and `is_overload_error` matched | Response, genErr(5) |
| `decision=dropped_malformed_request` | the datagram failed the BER screen or rasn | nothing |

`model_silent` matters most: on the wire it is indistinguishable from the agent being down, so
without the log line a deliberate silence and a crashed server look identical. It used to be logged
nowhere at all.

## LLM Integration

### Action-Based Response Model

The LLM responds to SNMP events with actions:

**Events**:

- `snmp_request` - SNMP request received
    - Parameters: `request_type` (`GetRequest` / `GetNextRequest` / `GetBulkRequest` /
      `SetRequest` — note the exact spelling, it is dhcproto-style CamelCase, not `GET`), `oids`,
      `answer_with`, `community`, `request_id`, `version` (`v1` / `v2c`), `client_ip`

**`answer_with`** (`actions::answer_with_for_request`) names each requested OID, with its MIB-2
meaning where it is a well-known one (`1.3.6.1.2.1.1.1.0 (sysDescr, the system description your instructions give)`,
sysName, sysUpTime, sysContact, sysLocation, sysObjectID, sysServices, ifNumber), says how many
variables to return and that nothing else belongs in the answer, and when to answer `noSuchName`.
GetNext/GetBulk and Set get their own sentence. It exists because `send_snmp_response`'s example
used to answer sysDescr with `"System Description"` and add sysName = `"hostname"`, and told
"your system description is NetGet Eval Switch 1.0", llama3.1:8b sent both example values — both
OIDs, to a one-OID `snmpget` — ten runs in ten (real-model eval, seed 42). The action and event
examples now carry one enterprise OID and a value that reads as a placeholder
(`"<the value your instructions give for this OID>"`), and the description says the example is
never data.

The sysName gloss is worded to stop rewording: with "sysName, the system's name" the model sent
`localhost` five runs in five, and with "the name your instructions give this device" it sent
"Eval Core" for `eval-core-01` five in five. "The device's name exactly as your instructions write
it - a hostname, character for character, never reworded or capitalised" got 4/5 (the miss
invented a description). Measured with the real-model eval, 5 runs each.

**Request/response correlation**: the request-id, community string and version are captured
per-request in the socket task and passed into `build_snmp_response` as plain locals — they are
never read from shared state, so overlapping requests cannot cross-contaminate. The LLM does not
need to (and cannot) set them.

**Available Actions**:

- `send_snmp_response` - Send SNMP response with variable bindings
- `send_snmp_error` - Send error response with a chosen error-status
- `ignore_request` - Don't respond (client will timeout and retry)
- `send_trap` - send a v1/v2c trap or a v2c inform (see Notifications above)
- `acknowledge_notification` / `ignore_notification` - answer an `snmp_notification`
- Common actions: `show_message`, `update_instruction`, etc.

### Example LLM Responses

**Simple GET Response**:

```json
{
  "actions": [
    {
      "type": "send_snmp_response",
      "variables": [
        {"oid": "1.3.6.1.2.1.1.1.0", "type": "string", "value": "NetGet SNMP Agent v1.0"}
      ]
    }
  ]
}
```

**Multiple OIDs (GetBulkRequest)**:

```json
{
  "actions": [
    {
      "type": "send_snmp_response",
      "variables": [
        {"oid": "1.3.6.1.2.1.1.1.0", "type": "string", "value": "NetGet SNMP Agent v1.0"},
        {"oid": "1.3.6.1.2.1.1.3.0", "type": "timeticks", "value": 12345},
        {"oid": "1.3.6.1.2.1.1.5.0", "type": "string", "value": "netget.local"}
      ]
    }
  ]
}
```

**Error Response**:

```json
{
  "actions": [
    {
      "type": "send_snmp_error",
      "error_message": "OID not found"
    }
  ]
}
```

**Trap**:

```json
{
  "actions": [
    {
      "type": "send_trap",
      "target": "192.168.1.100:162",
      "trap_oid": "1.3.6.1.6.3.1.1.5.3",
      "variables": [
        {"oid": "1.3.6.1.2.1.2.2.1.1.3", "type": "integer", "value": 3}
      ]
    }
  ]
}
```

## Connection Management

### Stateless Protocol

SNMP has no connection concept:

- Each UDP packet is independent request
- No handshake, no session, no connection state
- Community string is only "authentication" (plaintext)

### Request Processing Flow

1. Receive UDP packet on port 161
2. Parse as SNMPv2c or v1 (try v2c first)
3. Extract request type, OIDs, community string, request ID
4. Create `snmp_request` event with request data
5. Call LLM with event
6. LLM returns JSON with variables or error
7. Build BER-encoded SNMP response
8. Send UDP packet to peer address (same socket, different destination)

### Concurrent Requests

- Each request spawned in separate tokio task
- No queueing (unlike TCP protocols)
- Requests from different clients processed in parallel
- Ollama lock serializes LLM calls but not UDP I/O

## Known Limitations

### 1. SNMPv3: the USM, without VACM (`usm.rs`)

SNMPv3 is served when `v3_users` is set (`[{name, auth_protocol, auth_password, priv_protocol,
priv_password}]`); without it a v3 message is dropped (`decision=dropped_v3_not_configured`).
`usm.rs` is shared with the client and implements RFC 3412 message processing and the RFC 3414
USM:

- Keys: the megabyte password hash once per user, localized to the engine at start.
- Authentication: HMAC-MD5-96, HMAC-SHA-96 and RFC 7860's HMAC-SHA-224/256/384/512. An
  incoming MAC is checked over the bytes as received, the MAC field found by walking the BER
  (`auth_params_span`) — never over a re-encoding.
- Privacy: DES-CBC (RFC 3414 §8) and AES-128-CFB (RFC 3826). AES-192/256 are refused at
  start-up: they exist only as expired drafts with two incompatible key extensions.
- The procedure, in RFC 3414 §3.2's order, each refusal its own report and none of them
  reaching the handler: unknown engine (discovery) → `usmStatsUnknownEngineIDs`; unknown user →
  `UnknownUserNames`; a level other than the user's → `UnsupportedSecLevels`; a bad MAC →
  `WrongDigests`; boots or time outside the 150 s window → `NotInTimeWindows`, **sent
  authenticated** so the manager can believe the clock in it; undecryptable → `DecryptionErrors`.
  Each is logged `decision=usm_report`.

**A user is answered only at the level it is configured for.** An authPriv user asking at
authNoPriv gets `UnsupportedSecLevels`, not an unencrypted answer. Without VACM that is what makes
configuring keys mean anything: otherwise anyone who knew a user name could read at
noAuthNoPriv. The event carries `user`, `security_level` and `context_name`, so a handler can
decide per user what it may read or write — that is the VACM there is.

The engine: `engine_id` (hex, 5–32 bytes) or a random RFC 3411 format-5 ID (enterprise 0)
chosen at start; `engine_boots` (default 1) is a parameter because NetGet persists nothing — a
fixed `engine_id` restarted without raising it looks to managers like a clock going backwards.
Answers larger than the request's msgMaxSize become tooBig. Not served: SNMPv3 traps and
informs in either direction (a v3 Trap/Inform/Report PDU is dropped,
`decision=dropped_v3_notification`).

### 2. No SET Request Implementation

- SetRequest parsed but not fully implemented
- LLM receives event but can't modify persistent state
- Would require state management (in-memory or persistent store)

**Workaround**: LLM can acknowledge SET but won't persist changes. Useful for honeypot scenarios (log SET attempts).

### 3. Notifications are v1/v2c only

- Traps and informs both ways (see Notifications above), but no SNMPv3 notifications and no
  `snmpTrapAddress`/`snmpTrapCommunity` proxy bindings. A trap is sent from an ephemeral port,
  not the agent's own socket, and `target` may be any host — the operator's instruction is the
  only thing deciding where traps go

### 4. No MIB Loading

- No MIB file parsing
- LLM must know OIDs (can be provided in prompt)
- No OID name resolution (e.g., "sysDescr" → "1.3.6.1.2.1.1.1.0")

**Workaround**: Include common OIDs in prompt or rely on LLM's training data.

### 5. No SNMP Table Walking

- GetNextRequest supported but LLM must track "next" OID
- No automatic table iteration
- LLM must understand SNMP table structure

**Workaround**: Provide clear instructions about table structure in prompt.

### 6. No Timeout/Retry Logic

- Agent doesn't track if client retries request
- Each retry treated as new independent request
- Could result in duplicate LLM calls for same OID

**Rationale**: SNMP client handles retries, agent just responds to each request.

## Example Prompts

### Basic SNMP Agent

```
listen on port 161 via snmp
Respond to SNMP GET requests:
- 1.3.6.1.2.1.1.1.0 (sysDescr): "NetGet SNMP Agent v1.0 running on Linux"
- 1.3.6.1.2.1.1.3.0 (sysUpTime): 123456 timeticks
- 1.3.6.1.2.1.1.5.0 (sysName): "netget-server.local"
```

### Network Interface Agent

```
listen on port 161 via snmp
Simulate network interface eth0:
- 1.3.6.1.2.1.2.2.1.1.1 (ifIndex): 1
- 1.3.6.1.2.1.2.2.1.2.1 (ifDescr): "eth0"
- 1.3.6.1.2.1.2.2.1.3.1 (ifType): 6 (ethernetCsmacd)
- 1.3.6.1.2.1.2.2.1.5.1 (ifSpeed): 1000000000 (1 Gbps)
- 1.3.6.1.2.1.2.2.1.8.1 (ifOperStatus): 1 (up)
```

### Custom Enterprise MIB

```
listen on port 161 via snmp
Support custom enterprise OID tree 1.3.6.1.4.1.12345:
- 1.3.6.1.4.1.12345.1.1.0: "MyApp Server v2.3"
- 1.3.6.1.4.1.12345.1.2.0: 42 (active connections counter)
- 1.3.6.1.4.1.12345.1.3.0: "running" (server status)
For unknown OIDs, return error "noSuchName"
```

### SNMP Honeypot

```
listen on port 161 via snmp
Log all SNMP requests (community strings, OIDs queried)
Respond with realistic but fake data:
- System: "Cisco IOS Router 12.4"
- Interfaces: eth0 (1 Gbps), eth1 (1 Gbps)
- Uptime: incrementing value (starts at 1000000 timeticks)
Track which OIDs are queried most frequently
```

## Performance Characteristics

### Latency

- Parse request: <1ms (BER decoding)
- LLM processing: 2-5s (typical)
- Encode response: <1ms (BER encoding)
- Total: ~2-5s per request (LLM dominates)

### Throughput

- Limited by LLM response time
- Concurrent requests handled in parallel (each in own tokio task)
- UDP has no connection overhead (faster than TCP)

### Concurrency

- Unlimited concurrent requests (bounded by system resources)
- Each request processed independently
- Ollama lock serializes LLM calls but not UDP I/O or BER encoding

### Memory

- One 64KB receive buffer per server (reused across requests), plus a copy of each datagram
- BER encoding allocates small vectors (<1KB typical)
- No persistent state per client (stateless protocol)

## Security Considerations

### Plaintext Protocol

- SNMPv1/v2c has no encryption
- Community string sent in cleartext (like password)
- Anyone on network can sniff packets and see data

### Community String

- Acts as shared password
- Typically "public" for read-only, "private" for read-write
- No per-user authentication
- Easily brute-forced or sniffed

### Honeypot Usage

SNMP commonly targeted by attackers:

- Port 161 scanned frequently
- Default community strings ("public", "private") tried
- OIDs queried to fingerprint device type
- LLM can log attempts and adapt responses

## References

- [RFC 1157: SNMP (SNMPv1)](https://datatracker.ietf.org/doc/html/rfc1157)
- [RFC 3416: SNMPv2 Protocol Operations](https://datatracker.ietf.org/doc/html/rfc3416)
- [RFC 3584: SNMPv2 to SNMPv1 Coexistence](https://datatracker.ietf.org/doc/html/rfc3584)
- [rasn-snmp Documentation](https://docs.rs/rasn-snmp/latest/rasn_snmp/)
- [SNMP OID Reference](http://www.oid-info.com/)
- [Net-SNMP Tools](http://www.net-snmp.org/) - Command-line SNMP client for testing
