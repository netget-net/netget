# DynamoDB Protocol Implementation

## Overview

DynamoDB-compatible server implementing the AWS DynamoDB HTTP/JSON API. The server handles DynamoDB operations (GetItem,
PutItem, Query, etc.) with full LLM control over responses. This is a "virtual" database where the LLM maintains data
through conversation context rather than persistent storage.

**Port**: 8000 (default DynamoDB local port)
**Protocol**: HTTP/1.1 with JSON payloads
**API Version**: DynamoDB_20120810
**Stack Representation**: `ETH>IP>TCP>HTTP>DYNAMODB`

## Library Choices

**hyper** (v1.5):

- HTTP/1.1 server implementation
- Async connection handling with tokio
- Service-based request routing
- Handles HTTP framing, headers, body parsing

**http-body-util**:

- Body aggregation (`BodyExt::collect()`)
- Full body type (`Full<Bytes>`)
- Efficient byte handling

**serde_json**:

- JSON request/response parsing
- DynamoDB uses JSON for all data
- No binary protocol support

**Manual API Implementation**:

- LLM controls all DynamoDB operations through action system
- No AWS SDK dependencies
- Responses manually constructed as JSON
- Request ID generation (timestamp-based)

## Architecture Decisions

### HTTP-Based Design

- Each DynamoDB request is a POST to the root endpoint
- Operation specified in `x-amz-target` header (e.g., "DynamoDB_20120810.GetItem")
- Request body is JSON with table name and parameters
- Response body is JSON with operation results
- Standard HTTP status codes (200, 400, 500)

### Stateless Operation

- Each HTTP request is independent
- No persistent storage or connection state
- LLM maintains "virtual" data through conversation context
- Server ID used but no per-connection state

### Request Processing Flow

1. Accept TCP connection
2. Parse HTTP request (method, URI, headers, body)
3. Extract operation from `x-amz-target` header
4. Parse table name from JSON body
5. Create `DYNAMO_REQUEST_EVENT` with operation, table, body
6. Call LLM via `call_llm()` with event and protocol
7. Process action result:
    - `ActionResult::Custom { name: "dynamo_response", .. }`: Build HTTP response with
      status/body
8. If no action, **fail closed**: 500 `{"__type":"InternalServerError", …}` carrying the
   `WireFailure` category. It used to return `{}`, which *is* the documented success body for
   PutItem and DeleteItem — so a declined write looked performed — and reads as "no such item"
   for GetItem.
9. The connection stays open for the next request — `http1::serve_connection` honours
   HTTP/1.1 keep-alive, and the AWS SDK reuses the connection. (This step used to say
   "close connection (HTTP/1.1 without keep-alive)", contradicting the connection-handling
   section below in the same file.)

### Failure semantics — and the `decision=` tags

Every request is logged with a stable `decision=` tag, as `src/server/radius/` does, so an
operator can tell the model's answer from netget failing to reach one:

- `decision=model_answer` / `decision=model_reject` — the model produced a `dynamo_response`;
  reject is a 4xx/5xx status it chose itself (DEBUG)
- `decision=fail_closed_no_action` — the handler ran and produced no `dynamo_response`. WARN,
  answered `500 InternalServerError` (step 8 above)
- `decision=fail_closed_body_rejected` — the request body exceeded `MAX_REQUEST_BYTES`
  (4 MiB) or could not be read. WARN, answered `413 RequestEntityTooLarge`, which is
  DynamoDB's own error for this. The request never reaches the model: a body truncated to
  nothing used to arrive as a well-formed operation with no arguments
- `decision=fail_closed_llm_error category=Overloaded|Unavailable` — netget could not reach
  a decision. WARN, and the **only** place the error text is written; it goes to
  `netget.log` and the status stream and never to the peer

On an LLM failure the peer gets a category from `crate::utils::WireFailure`, never the error
itself, and the two categories keep distinct codes: `Overloaded` → `503`
`ServiceUnavailable` + `Retry-After: 5`, which the AWS SDK's default retry policy honours,
and `Unavailable` → `500` `InternalServerError`, which is terminal. Both used to be a
hardcoded `500 {"__type":"InternalServerError","message":"Internal server error"}`, so a
transient backend saturation looked like a permanent fault and the SDK did not retry.

### Operation Detection

- Operations parsed from `x-amz-target` header
- Format: `DynamoDB_20120810.<Operation>`
- Supported operations: GetItem, PutItem, Query, Scan, CreateTable, DeleteTable, UpdateItem, DeleteItem, BatchGetItem,
  BatchWriteItem
- LLM decides how to respond to each operation

### Response Format

- Status: 200 (success), 400 (client error), 500 (server error). `send_dynamo_response`
  rejects any `status_code` outside 100-599 rather than truncating it.
- Headers:
    - `Content-Type: application/x-amz-json-1.0`
    - `x-amzn-RequestId: <hex-timestamp>`
- Body: JSON object with operation-specific fields
- Error format: `{"__type": "ErrorType", "message": "error message"}`

## LLM Integration

### Action-Based Responses

**Sync Actions** (network event context required):

- `send_dynamo_response` — parameters `status_code` (number, required) and `body` (string,
  required, a JSON document). This is the only protocol-specific action. `dynamo_response`
  is the *internal* `ActionResult::Custom` name the server matches on; it is not an action
  name the model may emit.

The generic actions (`notify_operator`, memory operations, …) are supplied centrally by
`get_network_event_common_actions()` and are available here too.

**Event Types**:

- `DYNAMO_REQUEST_EVENT`: Fired for every DynamoDB operation
    - Data: `{ "operation": "GetItem", "table_name": "Users", "request_body": "{...}" }`

### Example LLM Prompts

**GetItem operation**:

```
For GetItem on Users table with key {id: "user-123"}, use send_dynamo_response with:
status_code=200
body='{"Item":{"id":{"S":"user-123"},"name":{"S":"Alice"},"email":{"S":"alice@example.com"}}}'
```

**PutItem operation**:

```
For PutItem on Users table, use send_dynamo_response with:
status_code=200
body='{}'
```

**Query operation**:

```
For Query on Users table, use send_dynamo_response with:
status_code=200
body='{"Items":[{"id":{"S":"user-123"},"name":{"S":"Alice"}}],"Count":1,"ScannedCount":1}'
```

**Error responses**:

```
For invalid operations, use send_dynamo_response with:
status_code=400
body='{"__type":"ResourceNotFoundException","message":"Table not found"}'
```

## Connection Management

### Connection Lifecycle

1. Server accepts TCP connection on port 8000
2. Create `ConnectionId` for tracking
3. Add connection to `ServerInstance` with `ProtocolConnectionInfo::empty()` (that type is a
   generic `serde_json::Value` wrapper, not a per-protocol enum)
4. Spawn HTTP service handler
5. `http1::Builder::serve_connection` serves the connection, including keep-alive: a client
   may send several requests over one connection
6. Connection closed when the client closes it

### State Tracking

- Connection state stored in `ServerInstance.connections` HashMap
- No protocol-specific connection state is recorded (`ProtocolConnectionInfo::empty()`);
  there is no `recent_operations` list
- Tracks: remote_addr, local_addr, and `bytes_received`/`bytes_sent`, updated once per
  request/response pair so the rail's counters move
- Status: Active → Closed when the connection ends

### Concurrency

- Multiple connections handled concurrently
- Each connection is independent (stateless HTTP)
- No shared state between connections
- LLM maintains "virtual" data through conversation memory

## Limitations

### Protocol Features

- **No persistent storage** - data only exists in LLM conversation context
- **No authentication** - AWS SigV4 is neither parsed nor validated, and none of the
  signing headers (`Authorization`, `X-Amz-Date`, `X-Amz-Security-Token`) are put into
  `dynamo_request`, so the model cannot make an authentication decision either. Every
  request is served unconditionally, signed or not
- **HTTP/1.1 only** - no HTTP/2 support
- **No streaming** - full request/response buffering, capped at `MAX_REQUEST_BYTES` (4 MiB)
  in `mod.rs`; a larger body is refused with `413 RequestEntityTooLarge` and never reaches
  the model. DynamoDB itself allows 16 MiB for BatchWriteItem, so a batch that large is
  refused here — the model could not usefully read it anyway
- **Limited operations** - only common CRUD operations supported
- **No transactions** - no atomic multi-item operations
- **No TTL** - time-to-live not supported
- **No streams** - DynamoDB Streams not implemented
- **No global tables** - single-region only
- **Request-only** - `metadata()` declares `.request_only(…)`: "DynamoDB is HTTP request/response;
  a server cannot send a peer anything unprompted". The dashboard's `[ send message ]` on a peer
  is disabled and shows that reason, and MCP `send_to_peer` refuses with it

### Performance

- Each request triggers LLM call
- No query optimization or indexing
- Full request/response in memory
- Connection overhead per request

### Data Management

- **Virtual data** - LLM maintains data through conversation
- **No persistence** - data lost when LLM context is cleared
- **Consistency** - depends on LLM memory
- **Scalability** - limited by LLM context window

## Known Issues

1. **Data consistency**: LLM may forget or hallucinate data between requests
2. **Complex queries**: Advanced query expressions may confuse LLM
3. **Large responses**: Very large item sets may exceed response size limits
4. **Request ID uniqueness**: Timestamp-based IDs may collide (very rare)
5. **Error codes**: Limited AWS error code vocabulary

## Example Responses

### GetItem Success

```json
{
  "actions": [
    {
      "type": "send_dynamo_response",
      "status_code": 200,
      "body": "{\"Item\":{\"id\":{\"S\":\"user-123\"},\"name\":{\"S\":\"Alice\"}}}"
    }
  ]
}
```

### PutItem Success

```json
{
  "actions": [
    {
      "type": "send_dynamo_response",
      "status_code": 200,
      "body": "{}"
    }
  ]
}
```

### Query Response

```json
{
  "actions": [
    {
      "type": "send_dynamo_response",
      "status_code": 200,
      "body": "{\"Items\":[{\"id\":{\"S\":\"user-123\"}}],\"Count\":1}"
    }
  ]
}
```

### Error Response

```json
{
  "actions": [
    {
      "type": "send_dynamo_response",
      "status_code": 400,
      "body": "{\"__type\":\"ResourceNotFoundException\",\"message\":\"Table not found\"}"
    }
  ]
}
```

## References

- [DynamoDB API Reference](https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/)
- [DynamoDB JSON Format](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Programming.LowLevelAPI.html)
- [AWS SDK for Rust](https://github.com/awslabs/aws-sdk-rust) - for testing
- [DynamoDB Local](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/DynamoDBLocal.html)

## Connection bounds

Before September 2026 this server accepted without limit and bounded no read in time, so a peer
that connected and said nothing held a socket, a connection task and an `AppState` entry forever,
pre-authentication, on a server that would happily accept a hundred more. It now declares both
halves; the constants and the reasoning live beside them in `src/server/dynamo/mod.rs`.

| Bound | Value | Why this number |
|---|---|---|
| `FIRST_BYTE_READ_TIMEOUT` | 30s | HTTP is client-speaks-first, so a peer that has connected and sent no byte has begun no request. 30s sits between nginx's `client_header_timeout` default of 60s and Apache's `RequestReadTimeout header=20`. Enforced with `TcpStream::peek` before the socket reaches hyper, so the request line is still there for hyper afterwards. |
| `IDLE_BETWEEN_REQUESTS_TIMEOUT` | 180s | Strictly request/response over a pooled connection, and the SDKs' per-attempt read timeouts are measured in seconds, so a client still waiting on us gave up long ago. Three times the 60-second idle timeout AWS's own load balancers ship. |
| `MAX_CONNECTIONS` | 256 | Each admitted connection may hold one whole in-memory response body (a JSON response), so the cap turns that per-connection bound into a total one. Refusal: **HTTP/1.1 `503 Service Unavailable` with `Retry-After: 5`** — a 503 with `Retry-After` is what every AWS SDK's throttling path understands. Nothing of netget's reaches the wire; the reason is logged under `decision=fail_closed_connection_cap`. |

**NetGet's own DynamoDB client is *lazy*, so it is never the silent peer this bound closes:**
`src/client/dynamodb/` builds no SDK client at connect and opens no socket until an action
issues a request — `PROTOCOL_QUALITY.md`'s three-state test.

**The idle bound is a watchdog, not a read deadline, and that is not a stylistic choice.** hyper
owns every read once `serve_connection` starts and keeps polling the connection for new frames
*while a request is being answered*, so a deadline on those reads would fire in the middle of an
LLM round-trip. It watches `ConnectionActivity` instead, which reports a connection with work in
flight as not idle at all — so the model round-trip, and a `manual` rule parking an event for a
human (`src/state/intercepts.rs`, 300s by default), sit outside every deadline by construction.
That is the `.connectionless()` lesson in the project `AGENTS.md` read in reverse: TFTP evicted
live transfers because "idle" was measured wrongly.

**One residual, stated rather than hidden.** The first-byte bound is discharged the moment any
byte arrives, so a peer that sends one byte of a request line and then stops is bounded by the
*idle* deadline (180s) rather than by the 30s one. hyper's own `header_read_timeout` cannot
express the pair: it re-arms whenever hyper starts reading a head, an idle keep-alive connection
included, so setting it to 30s would close every pooled client between requests — collapsing the
two bounds onto one number, which is exactly what the pair exists to avoid.

`tests/server/dynamo/connection_bounds_test.rs` drives all three from the wire, over
`tests/helpers/http_bounds.rs`. Each was verified by **removing** the bound and watching the test
fail: with the `peek` deadline gone the silent peer still held the socket at 60s; with the idle
bound collapsed to 30s an answered connection was closed after 38s of silence; with the permit
released early the connection past the cap was served instead of refused.
