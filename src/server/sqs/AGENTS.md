# AWS SQS Protocol Implementation

## Overview

AWS SQS (Simple Queue Service) compatible server implementing the AWS SQS HTTP/JSON API. The server handles SQS queue
operations (SendMessage, ReceiveMessage, CreateQueue, etc.) with full LLM control over responses. This is a "virtual"
message queue system where the LLM maintains queues and messages through conversation context rather than persistent
storage.

**Port**: 9324 (standard SQS local port)
**Protocol**: HTTP/1.1 with JSON payloads (AWS JSON protocol)
**API Version**: AmazonSQS
**Stack Representation**: `ETH>IP>TCP>HTTP>SQS`

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
- SQS uses JSON for all API calls (AWS JSON protocol)
- No binary protocol support (Query protocol not implemented)

**Manual API Implementation**:

- LLM controls all SQS operations through action system
- No AWS SDK dependencies
- Responses manually constructed as JSON
- Request ID generation (timestamp-based)

**Rationale**:

- No suitable Rust SQS server library exists
- Manual implementation provides full LLM control
- Similar to DynamoDB implementation pattern (proven approach)
- HTTP-based protocol is well-understood and tested
- Allows LLM-controlled authentication decisions

## Architecture Decisions

### HTTP-Based Design

- Each SQS request is a POST to the root endpoint
- Operation specified in `x-amz-target` header (e.g., "AmazonSQS.SendMessage")
- Request body is JSON with operation parameters
- Response body is JSON with operation results
- Standard HTTP status codes (200, 400, 500)

### JSON Protocol Only

- Uses AWS JSON protocol (`Content-Type: application/x-amz-json-1.0`)
- 23% faster than legacy Query protocol
- Simpler parsing and generation
- Modern default for AWS
- Legacy Query protocol (form-encoded) not implemented

### Stateful Operation

- Unlike DynamoDB (stateless), SQS requires queue state across requests
- LLM maintains "virtual" queues through conversation context
- Messages persist in LLM memory between requests
- Visibility timeouts tracked with timestamps
- Receipt handles enable message deletion

### Request Processing Flow

1. Accept TCP connection
2. Parse HTTP request (method, URI, headers, body)
3. Extract operation from `x-amz-target` header
4. Parse queue URL from JSON body (if present)
5. Create `SQS_REQUEST_EVENT` with operation, queue_url, request_body
6. Call LLM via `call_llm()` (which first tries any script/static handler, so those cost no
   model call)
7. Process action result:
    - `ActionResult::Custom { name: "sqs_response", .. }`: Build HTTP response with
      status/body
8. If no action, return empty JSON `{}`
9. Keep the connection open for further requests

### Operation Detection

- Operations parsed from `x-amz-target` header
- Format: `AmazonSQS.<Operation>`
- Supported operations: SendMessage, ReceiveMessage, DeleteMessage, CreateQueue, DeleteQueue, GetQueueAttributes,
  PurgeQueue, ListQueues
- LLM decides how to respond to each operation

### Response Format

- Status: 200 (success), 400 (client error), 500 (server error). `send_sqs_response`
  rejects any `status_code` outside 100-599 rather than truncating it.
- Headers:
    - `Content-Type: application/x-amz-json-1.0`
    - `x-amzn-RequestId: <hex-timestamp>`
- Body: JSON object with operation-specific fields
- Error format: `{"__type": "ErrorType", "message": "error message"}`

### Failure semantics — and the `decision=` tags

Every request is logged with a stable `decision=` tag, as `src/server/radius/` does, so an
operator can tell the model's answer from netget failing to reach one:

- `decision=model_answer` / `decision=model_reject` — the model produced an `sqs_response`;
  reject is a 4xx/5xx status it chose itself (DEBUG)
- `decision=fail_closed_no_action` — the handler ran and produced no `sqs_response`. WARN,
  answered `500 InternalFailure`. It must not be an empty `200`: for SendMessage or
  DeleteMessage that is a successful call to any AWS SDK, so a declined send would be
  reported as delivered
- `decision=fail_closed_body_rejected` — the request body exceeded `MAX_REQUEST_BYTES`
  (4 MiB) or could not be read. WARN, answered `413 InvalidParameterValue`. The request
  never reaches the model
- `decision=fail_closed_llm_error category=Overloaded|Unavailable` — netget could not reach
  a decision. WARN, and the **only** place the error text is written; it goes to
  `netget.log` and the status stream and never to the peer

On an LLM failure the peer gets a category from `crate::utils::WireFailure`, never the
error itself, and the two categories keep distinct codes: `Overloaded` → `503`
`ServiceUnavailable` + `Retry-After: 5`, which every AWS SDK's default retry policy honours,
and `Unavailable` → `500` `InternalFailure`, which is terminal. Both used to be a hardcoded
`500 {"__type":"InternalFailure","message":"Internal server error"}`, so a transient backend
saturation looked like a permanent fault and the client did not retry.

## LLM Integration

### Action-Based Responses

**Sync Actions** (network event context required):

- `send_sqs_response` — parameters `status_code` (number, required) and `body` (string,
  required, a JSON document). This is the only protocol-specific action. `sqs_response` is
  the *internal* `ActionResult::Custom` name the server matches on; it is not an action name
  the model may emit.

The generic actions (`notify_operator`, memory operations, …) are supplied centrally by
`get_network_event_common_actions()`.

**Event Types**:

- `SQS_REQUEST_EVENT`: Fired for every SQS operation
    - Data: `{ "operation": "SendMessage", "queue_url": "http://...", "request_body": "{...}" }`

### Startup Parameters

**None.** `get_startup_parameters()` returns an empty list. `default_visibility_timeout`,
`default_message_retention` and `max_receive_count` were declared here until they were
removed: nothing ever read them, because the server holds no queue state to apply them to.
Visibility timeouts and retention are entirely the LLM's responsibility and belong in the
server instruction. Passing any of them now fails with a clear "Undeclared startup
parameter" error rather than being silently ignored.

### Example LLM Prompts

**CreateQueue operation**:

```
For CreateQueue with QueueName "orders-queue", use send_sqs_response with:
status_code=200
body='{"QueueUrl":"http://localhost:9324/queue/orders-queue"}'
```

**SendMessage operation**:

```
For SendMessage to orders-queue with body "Order #123", use send_sqs_response with:
status_code=200
body='{"MessageId":"msg-1234567890","MD5OfMessageBody":"d41d8cd98f00b204e9800998ecf8427e"}'
```

**ReceiveMessage operation**:

```
For ReceiveMessage from orders-queue, use send_sqs_response with:
status_code=200
body='{"Messages":[{"MessageId":"msg-1234567890","ReceiptHandle":"receipt-xyz","Body":"Order #123","Attributes":{"SentTimestamp":"1234567890","ApproximateReceiveCount":"1"}}]}'
```

**DeleteMessage operation**:

```
For DeleteMessage with valid receipt handle, use send_sqs_response with:
status_code=200
body='{}'
```

**Error responses**:

```
For invalid queue URL, use send_sqs_response with:
status_code=400
body='{"__type":"QueueDoesNotExist","message":"The specified queue does not exist"}'
```

## Connection Management

### Connection Lifecycle

1. Server accepts TCP connection on port 9324
2. Create `ConnectionId` for tracking
3. Add connection to `ServerInstance` with `ProtocolConnectionInfo::empty()` (that type is a
   generic `serde_json::Value` wrapper, not a per-protocol enum)
4. Spawn HTTP service handler
5. `http1::Builder::serve_connection` serves the connection, including keep-alive
6. Connection closed when the client closes it

### State Tracking

- Connection state stored in `ServerInstance.connections` HashMap
- No protocol-specific connection state is recorded; there is no `recent_operations` list
- Tracks: remote_addr, local_addr. `bytes_sent`/`bytes_received` are initialised to 0 and
  never updated
- Status: Active → Closed when the connection ends

### Concurrency

- Multiple connections handled concurrently
- Each connection is independent
- LLM maintains queue state through conversation memory
- Message visibility timeouts prevent concurrent processing

## State Management

### Virtual Queues

- **Queue Creation**: LLM "creates" queue by remembering it in conversation
- **Queue URL Format**: `http://localhost:<port>/queue/<QueueName>`
- **Queue Attributes**: Visibility timeout, message retention, ARN
- **Queue Deletion**: LLM "forgets" queue and all its messages

### Virtual Messages

- **Message Storage**: LLM maintains message list for each queue
- **Message ID Format**: `msg-<timestamp>-<random>`
- **Message Attributes**: Body, attributes, sent timestamp, receive count
- **Receipt Handle Format**: `receipt-<timestamp>-<message_id>`

### Visibility Timeout

- **In-Flight Messages**: Messages become invisible after ReceiveMessage
- **Timeout Tracking**: LLM tracks timestamp of receive operation
- **Expiration**: After visibility timeout, message becomes available again
- **Validation**: LLM checks timestamp when processing DeleteMessage

### Message Lifecycle

1. **SendMessage**: Message added to queue with unique ID and MD5
2. **ReceiveMessage**: Message marked in-flight with receipt handle and visibility timeout
3. **DeleteMessage**: Message permanently removed using receipt handle
4. **Expiration**: Message deleted after retention period

## Authentication

**Not implemented, and not visible to the LLM.** The server never inspects the
`Authorization`, `X-Amz-Date` or `X-Amz-Security-Token` headers, and none of them are put
into `SQS_REQUEST_EVENT` - its data is exactly `{operation, queue_url, request_body}`. The
LLM therefore cannot make an authentication decision, because it is never shown the
credentials. Every request is served unconditionally.

Adding LLM-controlled auth would mean carrying the parsed signature fields (access key id,
signed headers, timestamp - never the signature bytes) in the event data.

## Scripting Mode Support

SQS uses the generic handler mechanism - there is nothing SQS-specific about it. A
`script` or `static` event handler on `sqs_request` is dispatched by
`try_execute_event_handler` before any model call, so deterministic operations
(SendMessage acknowledgements, GetQueueAttributes) cost nothing.

There is **no** SQS-specific "script generation on startup" step; the earlier claim that
the LLM emits a Python/JavaScript handler when the server starts described behaviour that
does not exist. Handlers come from the caller, via `open_server`'s `event_handlers`.

## Limitations

### Protocol Features

- **No persistent storage** - queues and messages only exist in LLM conversation context
- **No authentication at all** - Signature V4 headers are neither parsed nor validated, and
  are not shown to the LLM
- **HTTP/1.1 only** - no HTTP/2 support
- **JSON protocol only** - legacy Query protocol not implemented
- **No streaming** - full request/response buffering, capped at `MAX_REQUEST_BYTES` (4 MiB)
  in `mod.rs`; a larger body is refused with `413` and never reaches the model
- **Standard queues only** - FIFO queues not implemented
- **No DLQ** - Dead Letter Queues not implemented
- **No long polling** - WaitTimeSeconds supported in design but requires async waiting
- **No message attributes** - Supported in design, LLM can include in responses
- **No batch operations** - SendMessageBatch, DeleteMessageBatch not yet implemented
- **Request-only** - `metadata()` declares `.request_only(…)`: "SQS is HTTP request/response; a
  server cannot send a peer anything unprompted". The dashboard's `[ send message ]` on a peer is
  disabled and shows that reason, and MCP `send_to_peer` refuses with it

### Performance

- Each request triggers LLM call (unless scripting enabled)
- No query optimization
- Full request/response in memory
- Connection overhead per request

### Data Management

- **Virtual data** - LLM maintains queues and messages through conversation
- **No persistence** - data lost when LLM context is cleared
- **Consistency** - depends on LLM memory
- **Scalability** - limited by LLM context window

## Known Issues

1. **Data consistency**: LLM may forget or hallucinate messages between requests
2. **Receipt handle validation**: Timestamp-based handles may be guessed (low probability)
3. **Visibility timeout accuracy**: Depends on LLM timestamp arithmetic
4. **Message ordering**: Standard queues don't guarantee order (by design)
5. **Request ID uniqueness**: Timestamp-based IDs may collide (very rare)
6. **Error codes**: Limited AWS error code vocabulary

## Example Responses

### CreateQueue Success

```json
{
  "actions": [
    {
      "type": "send_sqs_response",
      "status_code": 200,
      "body": "{\"QueueUrl\":\"http://localhost:9324/queue/orders-queue\"}"
    }
  ]
}
```

### SendMessage Success

```json
{
  "actions": [
    {
      "type": "send_sqs_response",
      "status_code": 200,
      "body": "{\"MessageId\":\"msg-123\",\"MD5OfMessageBody\":\"d41d8cd98f00b204e9800998ecf8427e\"}"
    }
  ]
}
```

### ReceiveMessage Response

```json
{
  "actions": [
    {
      "type": "send_sqs_response",
      "status_code": 200,
      "body": "{\"Messages\":[{\"MessageId\":\"msg-123\",\"ReceiptHandle\":\"receipt-xyz\",\"Body\":\"Hello\"}]}"
    }
  ]
}
```

### DeleteMessage Success

```json
{
  "actions": [
    {
      "type": "send_sqs_response",
      "status_code": 200,
      "body": "{}"
    }
  ]
}
```

### Error Response

```json
{
  "actions": [
    {
      "type": "send_sqs_response",
      "status_code": 400,
      "body": "{\"__type\":\"QueueDoesNotExist\",\"message\":\"The specified queue does not exist\"}"
    }
  ]
}
```

## Comparison to DynamoDB

### Similarities

- HTTP-based protocol with JSON payloads
- Operation specified in header (`x-amz-target`)
- LLM maintains "virtual" data in conversation context
- No authentication (simplified for testing/honeypot)
- Action-based response system
- Manual API implementation

### Differences

| Aspect                | DynamoDB                             | SQS                                     |
|-----------------------|--------------------------------------|-----------------------------------------|
| **State**             | Stateless (each request independent) | Stateful (queue persistence required)   |
| **Data Lifecycle**    | Items stored indefinitely            | Messages expire after retention period  |
| **Operations**        | CRUD (read/write operations)         | Queue operations (send/receive/delete)  |
| **Concurrency**       | Simple (no coordination)             | Complex (visibility timeout, in-flight) |
| **Temporal Behavior** | None                                 | Visibility timeouts, message expiration |
| **Header**            | `DynamoDB_20120810.Operation`        | `AmazonSQS.Operation`                   |
| **Default Port**      | 8000                                 | 9324                                    |
| **Stack Name**        | `ETH>IP>TCP>HTTP>DYNAMODB`           | `ETH>IP>TCP>HTTP>SQS`                   |

### Key Architectural Difference: State Management

**DynamoDB**: Each request is independent, no state between requests

- GetItem: LLM "retrieves" from conversation memory
- PutItem: LLM "stores" in conversation memory
- No coordination needed

**SQS**: Requires queue state across requests

- SendMessage: Message added to queue
- ReceiveMessage: Message marked in-flight with timeout
- DeleteMessage: Message removed permanently
- Requires temporal state (visibility timeouts, expiration)

**Implication**: SQS prompt must emphasize state persistence and temporal behavior more than DynamoDB.

## References

- [AWS SQS API Reference](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/)
- [SQS Developer Guide](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/)
- [AWS JSON Protocol](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-json-faqs.html)
- [AWS SDK for Rust - SQS](https://github.com/awslabs/aws-sdk-rust) - for testing
- [ElasticMQ](https://github.com/softwaremill/elasticmq) - SQS-compatible server (Scala, inspiration)

## Connection bounds

Before September 2026 this server accepted without limit and bounded no read in time, so a peer
that connected and said nothing held a socket, a connection task and an `AppState` entry forever,
pre-authentication, on a server that would happily accept a hundred more. It now declares both
halves; the constants and the reasoning live beside them in `src/server/sqs/mod.rs`.

| Bound | Value | Why this number |
|---|---|---|
| `FIRST_BYTE_READ_TIMEOUT` | 30s | HTTP is client-speaks-first, so a peer that has connected and sent no byte has begun no request. 30s sits between nginx's `client_header_timeout` default of 60s and Apache's `RequestReadTimeout header=20`. Enforced with `TcpStream::peek` before the socket reaches hyper, so the request line is still there for hyper afterwards. |
| `IDLE_BETWEEN_REQUESTS_TIMEOUT` | 180s | Long polling is the reason to say what this does *not* bound: `ReceiveMessage` with `WaitTimeSeconds` holds a request open for up to 20 seconds, and that is a request in flight, held busy, outside this clock. Three minutes is nine times SQS's maximum long-poll wait and three times AWS's 60-second load-balancer idle timeout. |
| `MAX_CONNECTIONS` | 256 | Each admitted connection may hold one whole in-memory response body (a response body), so the cap turns that per-connection bound into a total one. Refusal: **HTTP/1.1 `503 Service Unavailable` with `Retry-After: 5`** — a 503 with `Retry-After` is what every AWS SDK's throttling path understands. Nothing of netget's reaches the wire; the reason is logged under `decision=fail_closed_connection_cap`. |

**NetGet's own SQS client is *lazy*, so it is never the silent peer this bound closes:**
`src/client/sqs/mod.rs` loads an SDK config and opens no socket until an action issues a
request — `PROTOCOL_QUALITY.md`'s three-state test.

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

`tests/server/sqs/connection_bounds_test.rs` drives all three from the wire, over
`tests/helpers/http_bounds.rs`. Each was verified by **removing** the bound and watching the test
fail: with the `peek` deadline gone the silent peer still held the socket at 60s; with the idle
bound collapsed to 30s an answered connection was closed after 38s of silence; with the permit
released early the connection past the cap was served instead of refused.
