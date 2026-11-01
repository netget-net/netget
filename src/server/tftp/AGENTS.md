# TFTP Server Implementation

## Overview

TFTP (Trivial File Transfer Protocol) server implementing RFC 1350 for network booting and simple file transfers. The LLM controls file read/write operations via memory-based responses (no disk storage).

**Status**: Experimental
**RFC**: RFC 1350 (TFTP)
**Port**: 69 (UDP)

## Library Choices

- **Custom TFTP packet implementation** - No external library
    - TFTP protocol is simple enough to implement directly
    - Fixed packet structure with 5 opcodes
    - Manual parsing avoids dependency overhead
    - Full control over transaction ID (TID) management

**Rationale**: TFTP packet structure is very simple (similar to NTP). Using a library would add unnecessary dependency. Custom implementation provides full control over multi-packet transfer state management and TID allocation.

**Alternatives Considered**:
- `async-tftp` v0.4.1 - Too opinionated for LLM integration
- `tftp-packet` v0.1.0 - Basic packet parsing only, still need custom state machine

## Architecture Decisions

### 1. Action-Based LLM Control

The LLM doesn't manipulate raw TFTP packets. Instead, it returns semantic actions:

**Server Actions**:
- `send_tftp_data` - Send file data block (512 bytes max)
- `send_tftp_ack` - Acknowledge received block
- `send_tftp_error` - Send error and terminate transfer

Each action includes required fields (block_number, data_hex, error_code) and validates constraints (512-byte max).

### 2. Stateful Multi-Packet Transfers

Unlike single-packet protocols (DNS, NTP), TFTP requires multi-packet state:

```rust
struct TftpTransfer {
    transfer_id: TransferId,           // Client address
    operation: TftpOperation,          // Read or Write
    filename: String,
    mode: String,                      // netascii, octet, mail
    current_block: u16,
    connection_id: ConnectionId,
    server_socket: Arc<UdpSocket>,     // Unique TID socket
}
```

**State Management**:
- Each RRQ/WRQ creates new transfer with unique transaction ID (TID)
- TID = unique UDP source port (ephemeral)
- Main socket (port 69) receives RRQ/WRQ only
- Transfer socket (random port) handles DATA/ACK exchange
- Active transfers tracked in `HashMap<TransferId, TftpTransfer>`

### 3. Transaction ID (TID) Management

TFTP uses UDP source ports as transaction IDs:

1. Client sends RRQ to server:69
2. Server creates new socket on random port (e.g., 52341)
3. Server responds from :52341 (this is the TID)
4. All subsequent packets use client:TID ↔ server:TID
5. Each transfer = separate "connection" in NetGet UI

**Benefits**:
- Supports concurrent transfers from same client
- No transaction ID collision (OS manages port allocation)
- Automatic transfer isolation

### 4. LLM Memory vs File Storage

**CRITICAL - No Disk Storage**: Following NetGet's protocol memory principle:

**For Read Requests**:
- LLM receives `tftp_read_request(filename)` event
- LLM provides file content via `send_tftp_data` actions
- Content comes from LLM's conversation memory or instruction
- Example: "Serve pxelinux.0 with hex data 4d5a9000..."

**For Write Requests**:
- LLM receives `tftp_data_block(data_hex)` events incrementally
- LLM accumulates in conversation context
- LLM processes complete file when `is_final: true`
- No persistent storage - data exists in LLM memory only

**Example Write Scenario**:
```
Block 1: LLM receives "48656c6c6f" (5 bytes)
Block 2: LLM receives "20574f524c44" (6 bytes)
Final: LLM knows complete file = "Hello WORLD"
```

### 5. Dual Logging

- **DEBUG**: Request summary ("TFTP RRQ: bootfile.bin from 192.168.1.100")
- **TRACE**: Full hex dump of packets (RRQ, DATA, ACK, ERROR)
- Both → netget.log and TUI Status panel

### 6. Connection Tracking

TFTP is UDP but is deliberately **not** declared `.connectionless()`. The flag exists for
servers whose per-remote-address records nothing ever closes, so the ten-second idle sweep in
`AppState::cleanup_old_connections` is their only cleanup. TFTP is not one of those: every
exit path - final ACK, ACK timeout, DATA timeout, ERROR, socket error - calls
`close_connection_on_server`, so there is nothing to reap. Declaring it connectionless
actively broke transfers' bookkeeping, because a connection is idle for the whole duration of
the handler's LLM call and one round-trip routinely exceeds ten seconds: the entry was
evicted mid-transfer, and the block counter and the eventual close then targeted a record
that no longer existed while the transfer went on completing over the wire.

Each TFTP transfer creates a "connection" entry:

```rust
ProtocolConnectionInfo::new(json!({
    "operation": "read",  // or "write"
    "filename": "pxelinux.0",
    "current_block": 5,
    "total_bytes": 2560
}))
```

Lifecycle:
1. **RRQ/WRQ Received**: Create connection with ConnectionId
2. **Transfer Active**: Update current_block and total_bytes
3. **Final Block/ACK**: Mark connection closed
4. **Timeout/Error**: Mark connection failed

## LLM Integration

### Event Types

**`tftp_read_request`** - Client requests to read file

Event parameters:
- `filename` (string) - Name of file being requested
- `mode` (string) - Transfer mode (netascii, octet, mail)
- `client_addr` (string) - Client socket address

**`tftp_write_request`** - Client requests to write file

Event parameters:
- `filename` (string) - Name of file to write
- `mode` (string) - Transfer mode
- `client_addr` (string) - Client socket address

**`tftp_data_block`** - Received data block (write operation)

Event parameters:
- `block_number` (number) - Block number (1-65535)
- `data_hex` (string) - Block data as hex string
- `data_length` (number) - Number of bytes in block
- `is_final` (boolean) - True if final block (< 512 bytes)

**`tftp_ack_received`** - Client acknowledged block (read operation)

Event parameters:
- `block_number` (number) - Block number acknowledged

### Available Actions

#### `send_tftp_data`

Send file data block to client.

Parameters:
- `block_number` (required) - Block number (1-65535)
- `data_hex` (required) - Data as hex string (max 512 bytes)

**Validation**: Data cannot exceed 512 bytes

**There is no `is_final`.** RFC 1350 signals the end of a transfer by the block's *length* —
exactly 512 bytes means more follow, anything shorter (including empty) is the last one — and
the DATA packet has nowhere to carry a flag. The action used to declare `is_final` as
**required** while `execute_send_tftp_data` read only `block_number` and `data_hex`, so the
model was forced to compute a field that changed nothing, and could believe `is_final: true`
on a 512-byte block had ended the transfer. Send a short or empty final block instead.

`is_final` remains on the **`tftp_data_block` event**, where it is real: there the server has
already measured the client's block and is telling the model whether the upload is complete.

#### `send_tftp_ack`

Acknowledge received data block.

Parameters:
- `block_number` (required) - Block number to acknowledge

#### `send_tftp_error`

Send error and terminate transfer. Valid at any point: refusing an RRQ or WRQ outright, and
aborting a transfer already in flight. The read continuation used to identify what it had
just sent by the packet's *length* rather than its opcode, so a mid-transfer ERROR was
mistaken for a final DATA block - the server waited five seconds for an ACK that would never
come and read the error code as a block number. It now dispatches on the opcode, as the
request path always did, and `tests/server/tftp/e2e_test.rs` covers the mid-stream abort.

Both parameters are declared required and are now enforced. They used to be defaulted to 0
and `"Error"`, so a malformed action produced a plausible ERROR packet instead of a visible
failure. `error_code` must be 0-7 (RFC 1350 defines no others) and `error_message` must not
contain a NUL, which would truncate the NUL-terminated field on the wire.

Parameters:
- `error_code` (required) - Error code:
  - 0: Not defined
  - 1: File not found
  - 2: Access violation
  - 3: Disk full
  - 4: Illegal TFTP operation
  - 5: Unknown transfer ID
  - 6: File already exists
  - 7: No such user
- `error_message` (required) - Human-readable error message

### When the LLM call itself fails

All four LLM call sites (`tftp_read_request`, `tftp_ack_received`, `tftp_write_request`,
`tftp_data_block`) answer with an ERROR packet (opcode 5) and end the transfer. Two of them
- the mid-transfer ones, `continue_read_transfer` and `receive_write_data` - used to write
nothing at all, so a client that had already received block N, or had just sent a DATA
block, sat in `recvfrom` until its own retransmit logic gave up. A transfer that simply
stops is worse than one that fails: for a PXE boot it looks like a corrupt image.

RFC 1350 defines error codes 0-7 and none of them means "try again", so both cases use code
0 ("Not defined, see error message") and the message says which:

| Condition | Message |
|---|---|
| `crate::llm::is_overload_error` is true | `Server overloaded, retry later` |
| any other LLM failure | `Internal error: LLM backend failure` |

Everything routes through `fail_transfer_on_llm_error`, which logs at **ERROR** with a
`decision=` token (tracing + status stream), sends the packet, removes the transfer from the
map and closes the connection - so no transfer state or connection entry leaks. It never
sends a plausible-looking DATA or ACK: an outage must not be indistinguishable from a
successful transfer. `tests/server/tftp/llm_failure_test.rs` covers all three failure points
against real UDP sockets.

## Failure behaviour

TFTP is **not** one of the deliberately-silent protocols. It has a real ERROR frame (opcode 5
with a code and a NUL-terminated message), so a refusal is expressible on the wire — and
because it is, the outcome that writes *nothing* is the dangerous one: the client sits
retransmitting into a socket nobody reads until its own timeout, and the transfer stays
registered until then.

Every terminal outcome of every one of the four LLM call sites is now tagged. `<stage>` is the
call site: `RRQ`, `WRQ`, `ACK continuation`, `DATA block`, so a grep says where a transfer
stopped as well as why. `Self::classify_outcome` decides the token before `protocol_results`
is consumed; `Self::log_decision` emits it at the level below.

| Outcome | On the wire | Log |
|---|---|---|
| Handler answered with `send_tftp_data` / `send_tftp_ack` | that packet; the transfer continues | INFO `TFTP <stage> from <peer> decision=model_answer` |
| Handler answered with `send_tftp_error` | ERROR packet; the transfer is torn down | INFO `decision=model_reject` |
| Handler answered with no usable action | **nothing**; the client retransmits until it times out and the transfer entry survives until then | WARN `decision=model_silent` |
| Executor refused the handler's action (bad block number, unknown action, undecodable `data_hex`) | **nothing**, same as above | ERROR `decision=fail_closed_bad_action` naming the action and the reason |
| Backend failed | ERROR code 0, `Internal error: LLM backend failure`; transfer torn down | ERROR `decision=fail_closed_llm_error` with the full error |
| Backend saturated | ERROR code 0, `Server overloaded, retry later`; transfer torn down | ERROR `decision=fail_closed_llm_overloaded` with the full error |

The two ERROR messages are byte-literals built by `llm_failure_error_packet`; nothing derived
from the error reaches the wire, which is what `tests/wire_failure_test.rs` enforces.

**Known gap, tagged rather than fixed in this pass.** `model_silent` and
`fail_closed_bad_action` write nothing, although the protocol has an ERROR frame that could
say so — the natural answers would be code 0 with a fixed message, exactly as the LLM-failure
path already does. Changing that alters what a peer sees, so it was left alone and made
greppable instead. If you close it, reuse `fail_transfer_on_llm_error`'s shape: fixed message,
tear the transfer down, keep the tag.

**TFTP is not `connectionless`, and the ERROR frame is why that matters here.** A transfer is
stateful and is idle for the whole of an LLM call, so declaring `.connectionless()` would let
the 10-second idle sweep evict live transfers out from under themselves — see the root
`AGENTS.md`. Riding UDP is not the test; having no connection concept is.

### Example LLM Responses

**Read Request**:
```json
{
  "actions": [
    {
      "type": "send_tftp_data",
      "block_number": 1,
      "data_hex": "48656c6c6f20544654502100"
    },
    {
      "type": "notify_operator",
      "message": "Sent file: 12 bytes"
    }
  ]
}
```

**Write Request Accepted**:
```json
{
  "actions": [
    {
      "type": "send_tftp_ack",
      "block_number": 0
    },
    {
      "type": "notify_operator",
      "message": "Ready to receive file"
    }
  ]
}
```

**Write Request Denied**:
```json
{
  "actions": [
    {
      "type": "send_tftp_error",
      "error_code": 2,
      "error_message": "Access violation - writes not permitted"
    }
  ]
}
```

**Data Block Received**:
```json
{
  "actions": [
    {
      "type": "send_tftp_ack",
      "block_number": 5
    },
    {
      "type": "notify_operator",
      "message": "Received block 5 (512 bytes), total: 2560 bytes"
    }
  ]
}
```

## Transfer Flows

### Read Transfer (RRQ)

```
Client:random → Server:69: RRQ filename="boot.bin" mode="octet"
Server creates TID socket :52341
LLM receives tftp_read_request event
LLM returns send_tftp_data action block #1

Server:52341 → Client:random: DATA block #1 (512 bytes)
Client:random → Server:52341: ACK block #1
LLM receives tftp_ack_received event
LLM returns send_tftp_data action block #2

Server:52341 → Client:random: DATA block #2 (512 bytes)
Client:random → Server:52341: ACK block #2
...

Server:52341 → Client:random: DATA block #N (< 512 bytes, final)
Client:random → Server:52341: ACK block #N
Transfer complete, connection closed
```

### Write Transfer (WRQ)

```
Client:random → Server:69: WRQ filename="config.txt" mode="netascii"
Server creates TID socket :52341
LLM receives tftp_write_request event
LLM returns send_tftp_ack action block #0

Server:52341 → Client:random: ACK block #0
Client:random → Server:52341: DATA block #1 (512 bytes)
LLM receives tftp_data_block event (block #1, is_final=false)
LLM returns send_tftp_ack action

Server:52341 → Client:random: ACK block #1
Client:random → Server:52341: DATA block #2 (256 bytes, final)
LLM receives tftp_data_block event (block #2, is_final=true)
LLM returns send_tftp_ack action

Server:52341 → Client:random: ACK block #2
Transfer complete, connection closed
```

## Known Limitations

### 1. RFC 1350 Only

- Standard 512-byte blocks (no RFC 7440 windowsize option)
- No RFC 2347 option negotiation (blksize, timeout, tsize)
- No RFC 2348 blocksize extension
- Basic TFTP only

### 2. No File System

- No actual file storage (by design - LLM memory pattern)
- No directory listing
- No file permissions or attributes
- LLM provides all content from instruction/memory

### 3. No Authentication

- No access control
- No username/password
- Anyone can read/write (if LLM allows)
- Security via LLM instruction: "Only serve to 192.168.1.0/24"

### 4. No Retransmission

- Server doesn't retry on timeout
- Client responsible for retransmitting requests
- Timeout causes connection close (client must reconnect)

### 5. Mode Support

- Supports `octet` (binary) and `netascii` (text) modes
- `mail` mode not implemented (obsolete)
- Mode is informational only (LLM doesn't transform data)

### 6. Concurrent Transfer Limit

- Limited by OS ephemeral port range (~28,000 ports)
- Each transfer consumes one port until complete
- Realistically supports thousands of concurrent transfers

## Example Prompts

### PXE Boot Server

```
listen on port 69 via tftp
Serve these boot files:
- pxelinux.0: hex data 4d5a90000300000004000000...
- ldlinux.c32: hex data 7f454c460201010000000000...
- pxelinux.cfg/default: text content "DEFAULT linux\nLABEL linux..."
For any other file, return error 1 (File not found)
```

### Firmware Update Server

```
listen on port 69 via tftp
Allow writes to firmware.bin in octet mode
When transfer complete, show message with total bytes received
For write request to any other file, return error 6 (File already exists)
Deny all read requests with error 2 (Access violation)
```

### Simple File Server

```
listen on port 69 via tftp
Serve file test.txt with content "Hello TFTP World!"
Deny write requests with error 2 (Access violation)
For unknown files, return error 1 (File not found)
```

### Conditional Access

```
listen on port 69 via tftp
Only serve to clients in 192.168.1.0/24
For requests from other IPs, return error 2 (Access violation)
Serve config.txt with content from your memory
```

## Performance Characteristics

### Latency

- **With Scripting**: Sub-millisecond response (script handles transfers)
- **Without Scripting**: 2-5 seconds per block (one LLM call per DATA/ACK)
- Packet construction: ~5-10 microseconds

### Throughput

- **With Scripting**: Megabytes per second (CPU-bound)
- **Without Scripting**: ~100-200 bytes/sec (limited by LLM call latency)
- Concurrent transfers processed in parallel (separate tokio tasks)
- Ollama lock serializes LLM API calls

### Scripting Compatibility

TFTP is excellent for scripting:

- Repetitive file serving pattern
- Deterministic responses based on filename
- High transfer volume typical (PXE booting hundreds of machines)
- No complex state machine (simple lockstep protocol)

When scripting enabled:
1. Server startup generates script (1 LLM call)
2. All subsequent requests handled by script (0 LLM calls)
3. Script can generate file content deterministically

## Security Considerations

### 1. No Encryption

- All data sent in cleartext
- Anyone on network can sniff files
- Not suitable for sensitive data

### 2. No Authentication

- Cannot verify client identity
- LLM can implement IP-based filtering in instructions
- "Only serve to 192.168.1.100" in instruction

### 3. Denial of Service

- Unlimited connection acceptance
- Each transfer consumes server resources (socket, memory)
- LLM can implement rate limiting: "Max 10 transfers per minute"

### 4. Resource Exhaustion

- Large files consume LLM context (hex encoding)
- 10MB file = 20MB hex string in LLM memory
- Practical limit: ~1-2MB files without context overflow

### 5. IP Spoofing

- UDP protocol vulnerable to IP spoofing
- Attacker can spoof client address to bypass IP filtering
- Not a protocol-level protection

## References

- [RFC 1350: The TFTP Protocol (Revision 2)](https://datatracker.ietf.org/doc/html/rfc1350)
- [RFC 7440: TFTP Windowsize Option](https://datatracker.ietf.org/doc/html/rfc7440)
- [RFC 2347: TFTP Option Extension](https://datatracker.ietf.org/doc/html/rfc2347)
- [RFC 2348: TFTP Blocksize Option](https://datatracker.ietf.org/doc/html/rfc2348)
- [Wikipedia: Trivial File Transfer Protocol](https://en.wikipedia.org/wiki/Trivial_File_Transfer_Protocol)
