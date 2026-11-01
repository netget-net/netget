# Syslog Protocol Implementation

## Overview

Syslog server implementing RFC 3164 (BSD syslog) and RFC 5424 (modern syslog) using the syslog_loose library. Provides
log aggregation and analysis where the LLM controls message filtering, storage, forwarding, and alerting. Uses UDP
transport for message reception.

**Status**: Experimental (Network Monitoring Protocol)
**RFC**: RFC 3164 (BSD syslog), RFC 5424 (Syslog Protocol)
**Port**: 514 (standard syslog), 601 (alternative)
**Privilege**: declares `PrivilegeRequirement::PrivilegedPort(514)`, so `server_startup` preflights the
capability before binding. Any port above 1023 needs no privilege.
**Test coverage**: none. There is no `tests/server/syslog/` suite, so nothing in CI or the local
suite exercises this protocol.

## Library Choices

### Core Syslog Implementation

- **syslog_loose v0.22** - Lenient syslog message parser
    - Parses both RFC 3164 (BSD syslog) and RFC 5424 (modern syslog)
    - Handles malformed messages gracefully
    - Extracts: facility, severity, timestamp, hostname, appname, procid, message
    - No dependencies on specific datetime libraries

**Rationale**: syslog_loose is the most lenient parser, accepting both standard and non-standard syslog messages.
Real-world syslog implementations vary widely, so a strict parser would reject many valid messages. The library
automatically detects format (RFC 3164 vs 5424) and extracts fields accordingly.

## Architecture Decisions

### 1. UDP One-Way Protocol

Syslog uses UDP (stateless, no response):

- Each message is independent
- No acknowledgment or response to sender
- Client may send multiple messages rapidly
- Server only receives and processes (no reply)

**Connection Tracking**:

- "Connection" = recent peer address that sent message
- Tracked in `ProtocolConnectionInfo::Syslog` with timestamp
- Used for UI display only (not protocol requirement)

### 2. LLM Control Point

Single integration point:

**Syslog Messages**:

- LLM receives `syslog_message` event with facility, facility_code, severity, severity_code, priority,
  timestamp, hostname, appname, procid, message, source_ip and raw_message
- Returns actions: `store_syslog_message`, `forward_syslog`, `ignore_syslog_message`
- Server performs the action (records it in the access log, relays it over UDP, or drops it)

**No Response to Client**:

- Syslog is one-way (client → server only)
- No acknowledgment sent to client
- LLM cannot send data back to sender

### 3. Message Format Parsing

LLM receives structured message data, not raw format:

**Facility** (source of message) — the event carries the exact strings below in `facility`, and the
matching 0-23 number in `facility_code`:

- kern (0), user (1), mail (2), daemon (3), auth (4), syslog (5), lpr (6), news (7), uucp (8),
  cron (9), authpriv (10), ftp (11), ntp (12), audit (13), alert (14), clockd (15)
- local0 (16) - local7 (23), for custom applications

**Severity** (importance level) — `severity` holds the name, `severity_code` the number:

- emerg (0) - system unusable
- alert (1) - immediate action required
- crit (2) - critical condition
- err (3) - error condition
- warning (4) - warning condition
- notice (5) - normal but significant
- info (6) - informational
- debug (7) - debug messages

These are `syslog_loose`'s canonical short names, not its `Debug` spelling: the event says `err`,
never `SEV_ERR` or `error`. Filters that need ordering should compare `severity_code`
(`severity_code <= 3` = error or worse) rather than matching names.

**Priority Encoding**: `Priority = Facility * 8 + Severity`, exposed as `priority`

- Example: `<34>` → 34 / 8 = 4 remainder 2, i.e. facility 4 (auth), severity 2 (crit)

A datagram with no `<PRI>` header at all still produces an event: facility and severity fall back to
the RFC 5424 default of user.notice (priority 13).

**Message Components**:

- **Timestamp**: When message was generated (RFC 3339 for 5424, MMM DD HH:MM:SS for 3164)
- **Hostname**: Source device hostname or IP
- **Appname**: Application or process name
- **Procid**: Process ID (optional)
- **Message**: Actual log message text

### 4. RFC 3164 vs RFC 5424

Parser supports both formats automatically:

**RFC 3164 (BSD syslog)** - Legacy format:

```
<34>Oct 11 22:14:15 mymachine su: 'su root' failed for user on /dev/pts/8
```

- Priority in `<>`, timestamp, hostname, tag (appname), message
- Less structured, more free-form
- Widely used, especially by older systems

**RFC 5424 (Modern syslog)** - Structured format:

```
<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 [exampleSDID@32473 iut="3" eventSource="Application"] An application event log entry...
```

- Version number (1), ISO 8601 timestamp, hostname, appname, procid, msgid
- Structured data in `[key=value]` format
- More precise, better for machine parsing

**Parser Behavior**:

- syslog_loose automatically detects format
- Extracts fields into unified structure
- LLM sees same data regardless of format

### 5. Dual Logging

All operations use **dual logging**:

- **DEBUG**: Message summary (facility, severity, hostname, peer address)
- **TRACE**: Full message text
- **INFO**: LLM messages and high-level events
- **ERROR**: socket receive errors, LLM errors. Note there is no parse-failure path: `parse_message`
  is infallible, so every datagram produces an event
- All logs go to both `netget.log` (via tracing) and TUI Status panel (via status_tx)

## LLM Integration

### Action-Based Message Handling

The LLM responds to syslog events with actions:

**Events**:

- `syslog_message` - Syslog message received
    - Parameters: `facility`, `severity`, `timestamp`, `hostname`, `appname`, `message`

**Available Actions**:

- `store_syslog_message` - Store message for later analysis (sync)
- `forward_syslog` - Forward message to another syslog server (async)
- `ignore_syslog_message` - Drop message (sync). Takes an optional `reason`, written to the
  log line only, and is the event's **primary** example. Both exist because the real-model eval
  (`syslog/drop-healthchecks`) found llama3.1:8b storing a message it was told to drop in every
  run — once writing "I've ignored the message" beside the `store_syslog_message` carrying it.
  A parameterless drop listed second lost to a keep with a `message` field listed first.
- Common actions: `notify_operator`, `update_instruction`, etc.

### Example LLM Responses

**Store Critical Messages**:

```json
{
  "actions": [
    {
      "type": "store_syslog_message",
      "message": "<34>Oct 11 22:14:15 mymachine su: 'su root' failed for user on /dev/pts/8"
    },
    {
      "type": "notify_operator",
      "message": "⚠️ Critical: Failed su attempt detected from mymachine"
    }
  ]
}
```

**Forward to Central Server**:

```json
{
  "actions": [
    {
      "type": "forward_syslog",
      "target": "192.168.1.100:514",
      "message": "<165>1 2003-10-11T22:14:15.003Z mymachine evntslog - ID47 [exampleSDID@32473 iut=\"3\"] Event log entry"
    }
  ]
}
```

**Ignore Debug Messages**:

```json
{
  "actions": [
    {
      "type": "ignore_syslog_message"
    }
  ]
}
```

**Alert on Emergency**:

```json
{
  "actions": [
    {
      "type": "notify_operator",
      "message": "🚨 EMERGENCY: Kernel panic on server-01! Priority: 0 (emergency)"
    },
    {
      "type": "forward_syslog",
      "target": "192.168.1.200:514",
      "message": "<0>Oct 11 22:14:15 server-01 kernel: Kernel panic - not syncing"
    }
  ]
}
```

## Failure behaviour

Syslog is **deliberately silent** on every path, because it is one-way: RFC 5424/5426 define no
reply message, so there is nothing to answer a sender with whatever the model does. `metadata()`
declares this with `.deliberately_silent()`, which `tests/failure_mode_declaration_test.rs`
checks. The outcomes differ only in the log:

| Outcome | Log |
|---|---|
| Model handled the message | `decision=model_handled` |
| Model chose `ignore_syslog_message` | `decision=model_drop` |
| Model returned nothing usable | `decision=no_answer` |
| Backend failed (`call_llm` → `Err`) | ERROR `decision=fail_closed_llm_error category=overloaded\|unavailable` |

The error text goes to the log and the status stream only; nothing reaches the wire.

## Connection Management

### Stateless Protocol

Syslog has no connection concept:

- Each UDP packet is independent message
- No handshake, no session, no connection state
- No authentication (plaintext, anyone can send)

### Message Processing Flow

1. Receive UDP packet on port 514
2. Parse as syslog message (RFC 3164 or 5424)
3. Extract facility, severity, timestamp, hostname, appname, message
4. Create `syslog_message` event with message data
5. Call LLM with event
6. LLM returns actions (store, forward, ignore, alert)
7. Execute actions
8. No response sent to client (one-way protocol)

### Concurrent Messages

- Each message spawned in separate tokio task
- No queueing (unlike TCP protocols)
- Messages from different clients processed in parallel
- Ollama lock serializes LLM calls but not UDP I/O

## Known Limitations

### 1. No TCP Transport

- Only UDP supported (port 514)
- TCP syslog (RFC 6587) not implemented
- No TLS/SSL encryption (RFC 5425) not implemented

**Rationale**: UDP is the standard syslog transport. TCP adds complexity (connection management, framing) and is less
common.

### 2. No Message Storage

- `store_syslog_message` does not write to a database or to disk, by design: protocols must not
  implement storage (see the root CLAUDE.md)
- What it does do is make the message part of the server's access log entry for the event, readable
  afterwards with `list_access_logs` / `get_access_log`
- The action description says exactly this, so a model is not told it has a datastore it lacks

**Workaround**: for durable storage, `forward_syslog` to a real collector (rsyslog, syslog-ng), or
have the LLM open a SQLite database via the generic `create_database` / `execute_sql` actions.

### 3. Message Forwarding

- `forward_syslog` is implemented: the executor resolves `target` ("HOST:PORT"), opens an ephemeral
  UDP socket and sends `message` verbatim
- A bad target or a failed send returns an error to the action pipeline instead of silently
  succeeding
- The datagram's source address is NetGet, not the original sender; syslog has no forwarded-for
  field, so relay-style rewriting (replacing the hostname) is up to the LLM's `message`
- No retry, no TCP fallback, no delivery confirmation - it is plain UDP

### 4. No Structured Data Parsing

- RFC 5424 structured data `[key=value]` is parsed by syslog_loose but not forwarded into the event
- The LLM can still recover it from `raw_message`, which is the untouched datagram
- `msgid` is likewise parsed and dropped

### 5. No Rate Limiting

- No protection against syslog floods
- Attacker can send thousands of messages per second
- Each message triggers LLM call (expensive)

**Workaround**: Use `--llm-max-concurrent` to bound in-flight LLM calls, or a script/static handler so high-rate sources cost no LLM call at all.

### 6. No Authentication

- Syslog (RFC 3164/5424 over UDP) has no authentication
- Anyone can send messages claiming any hostname
- No way to verify message source

**Rationale**: Standard syslog has no auth. Use this as honeypot to log forged messages.

## Example Prompts

### Basic Syslog Server

```
listen on port 514 via syslog
Store all messages with severity <= warning (0-4).
Ignore debug and info messages (6-7).
Show alerts for critical and above (0-2).
```

### Security Event Collector

```
listen on port 514 via syslog
Monitor auth and authpriv facilities.
Alert on failed login attempts (message contains "failed").
Store all authentication events.
Track hostnames sending auth messages.
```

### Log Aggregator with Forwarding

```
listen on port 514 via syslog
Accept logs from all sources.
Forward critical and above (0-2) to 192.168.1.100:514.
Store error and above (0-3) locally.
Show message count every 100 messages.
```

### Honeypot Syslog Server

```
listen on port 514 via syslog
Log all syslog messages (any source, any facility).
Track unique sender IPs and hostnames.
Alert on suspicious patterns:
- Messages claiming to be from kernel but not from trusted IPs
- Unusually high message rates from single source
- Messages with emergency/alert severity from unknown hosts
```

### Application Log Monitor

```
listen on port 514 via syslog
Accept only local0-local7 facilities (custom apps).
Parse message text for keywords:
- "error", "exception", "crash" → alert
- "startup", "shutdown" → log lifecycle
Track which applications (appname) are most active.
```

## Performance Characteristics

### Latency

- Parse message: <1ms (syslog_loose parsing)
- LLM processing: 2-5s (typical)
- Total: ~2-5s per message (LLM dominates)

**Impact**: High message rates will cause backlog if LLM can't keep up.

### Throughput

- Limited by LLM response time
- Concurrent messages handled in parallel (each in own tokio task)
- UDP has no connection overhead (faster than TCP)

**Recommendation**: For production, use filtering to reduce LLM calls (e.g., only process severity ≤ warning).

### Concurrency

- Unlimited concurrent messages (bounded by system resources)
- Each message processed independently
- Ollama lock serializes LLM calls but not UDP I/O or parsing

### Memory

- Each message allocates ~65KB buffer (max UDP packet size)
- Parsing allocates small strings (<1KB typical)
- No persistent state per client (stateless protocol)

## Security Considerations

### Plaintext Protocol

- Syslog (UDP/514) has no encryption
- All messages sent in cleartext
- Anyone on network can sniff messages

### No Authentication

- No verification of sender identity
- Hostname in message can be forged
- IP address can be spoofed (UDP)

### Honeypot Usage

Syslog commonly targeted by attackers:

- Port 514 scanned frequently
- Fake messages sent to test monitoring
- LLM can log forged messages and detect patterns
- Useful for tracking reconnaissance activity

### Denial of Service

- Attacker can flood with messages
- Each triggers LLM call (expensive)
- No built-in rate limiting

**Mitigation**: match high-rate sources with a script or static handler so they never reach the model; `--llm-max-concurrent` bounds the rest.

## References

- [RFC 3164: BSD syslog Protocol](https://datatracker.ietf.org/doc/html/rfc3164)
- [RFC 5424: The Syslog Protocol](https://datatracker.ietf.org/doc/html/rfc5424)
- [RFC 5425: TLS Transport Mapping for Syslog](https://datatracker.ietf.org/doc/html/rfc5425)
- [RFC 6587: Transmission of Syslog Messages over TCP](https://datatracker.ietf.org/doc/html/rfc6587)
- [syslog_loose Documentation](https://docs.rs/syslog_loose/latest/syslog_loose/)
- [Syslog Severity Levels](https://en.wikipedia.org/wiki/Syslog#Severity_level)
- [Syslog Facility Codes](https://en.wikipedia.org/wiki/Syslog#Facility)
