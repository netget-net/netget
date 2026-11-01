# S3 Protocol Implementation

## Overview

S3-compatible object storage server implementing the AWS S3 REST API. The server handles S3 operations (GetObject,
PutObject, ListBuckets, etc.) with full LLM control over responses. This is a "virtual" object storage where the LLM
maintains data through conversation context rather than persistent storage.

**Port**: 9000 (default MinIO convention)
**Protocol**: HTTP/1.1 with REST API
**API Version**: S3 REST API (AWS signature-compatible)
**Stack Representation**: `ETH>IP>TCP>HTTP>S3`

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

**Manual API Implementation**:

- LLM controls all S3 operations through action system
- No AWS SDK dependencies
- Responses manually constructed as XML or binary
- RESTful path parsing (bucket/key extraction)

**Why no s3s framework**: While s3s provides a complete S3 trait implementation, it adds unnecessary complexity for an
LLM-controlled virtual storage system. Manual implementation gives complete control over every aspect of S3 responses
without framework constraints.

## Architecture Decisions

### RESTful HTTP Design

S3 uses a RESTful design where resources are accessed via HTTP methods and URL paths:

**URL Format**:

- `/` - Root (ListBuckets)
- `/bucket` - Bucket operations
- `/bucket/key` - Object operations
- `/bucket/path/to/key` - Nested object paths

**HTTP Method Mapping**:

- `GET /` → ListBuckets
- `GET /bucket` → ListObjects
- `PUT /bucket` → CreateBucket
- `DELETE /bucket` → DeleteBucket
- `HEAD /bucket` → HeadBucket
- `GET /bucket/key` → GetObject
- `PUT /bucket/key` → PutObject
- `DELETE /bucket/key` → DeleteObject
- `HEAD /bucket/key` → HeadObject

### Stateless Operation

- Each HTTP request is independent
- No persistent storage or connection state
- LLM maintains "virtual" data through conversation context
- Connection tracked in ServerInstance but not used for state

### Request Processing Flow

1. Accept TCP connection on port 9000
2. Parse HTTP request (method, URI, headers, body)
3. Extract bucket/key from path using `parse_s3_path()`
4. Determine operation based on method + path structure
5. Create `S3_REQUEST_EVENT` with operation, bucket, key
6. Call LLM via `action_helper::call_llm()` (which first tries any script/static handler, so
   those cost no model call)
7. Process action result:
    - `s3_object`: Build HTTP response with object content
    - `s3_object_list`: Build ListObjects XML
    - `s3_bucket_list`: Build ListBuckets XML
    - `s3_error`: Build S3 error XML
8. Return HTTP response
9. Keep the connection open for further requests

### Response Format

**Object Content** (GetObject):

```http
HTTP/1.1 200 OK
Content-Type: text/plain
ETag: "abc123"

Hello, World!
```

**XML Responses** (ListBuckets, ListObjects):

```xml
<?xml version="1.0" encoding="UTF-8"?>
<ListAllMyBucketsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Owner>
    <DisplayName>netget</DisplayName>
    <ID>netget-user</ID>
  </Owner>
  <Buckets>
    <Bucket>
      <Name>my-bucket</Name>
      <CreationDate>2024-01-01T00:00:00.000Z</CreationDate>
    </Bucket>
  </Buckets>
</ListAllMyBucketsResult>
```

**Error Responses**:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<Error>
  <Code>NoSuchKey</Code>
  <Message>The specified key does not exist</Message>
</Error>
```

## LLM Integration

### Action-Based Responses

**Sync Actions** (network event context required):

- `send_s3_object` — `content` (string, required), `encoding` (`"utf8"` default or
  `"base64"`), `content_type`, `etag`. Answers GetObject.
- `send_s3_object_list` — `objects` (array of `{key, size, last_modified, etag}`),
  `is_truncated`. Answers ListObjects/ListObjectsV2.
- `send_s3_bucket_list` — `buckets` (array of `{name, creation_date}`). Answers ListBuckets.
- `send_s3_error` — `error_code`, `message`, `status_code`. Answers any failure.

- `send_s3_write_result` — `status_code` (200 default, 204 for DeleteObject), `etag`,
  `location`, `content_length`, `content_type`, `last_modified`, all optional. Acknowledges the
  body-less operations: PutObject, CreateBucket, DeleteObject, HeadObject.

**Why `send_s3_write_result` exists.** Those four verbs return no body, and until this action
was added the model had no way to say *yes* to them: the server answered them by falling
through to an empty `200 OK` whenever the model's answer contained no S3 action. That is the
fail-open pattern the root `AGENTS.md` calls the most dangerous in this codebase — an empty 200
is exactly what S3 returns on a successful PUT or DELETE, so a model that declined the operation
was reported to the caller as having performed it.

The fall-through could not simply be made to refuse, because doing so with no affirmative verb
makes those four operations permanently impossible rather than merely fail-closed. (An attempt
to change it in isolation was reverted for precisely that reason.) The vocabulary had to come
first. With it in place the fall-through is gone: no S3 action now means **500 InternalError**,
logged `decision=model_no_action`.

Two traps this hit, both already described in the root `AGENTS.md`, worth re-reading if you add
an action here:

- Registering it in `get_sync_actions()` is **not enough**. `call_llm` builds the model's tool
  list from `event.event_type.actions`, so an action missing from `S3_REQUEST_EVENT`'s
  `.with_actions(...)` is rejected at runtime as "Unknown action" no matter what the protocol
  advertises elsewhere.
- The E2E mocks answered these operations with `send_http_response`, which S3 cannot execute, so
  `test_s3_comprehensive` and `test_s3_put_and_list` failed inside
  `tests/helpers/mock_action_names.rs` before reaching the server at all. Both now use
  `send_s3_write_result` and pass. The ListObjects rule's `expect_calls(15)` ("rust-s3 client may
  paginate/retry") was an artefact of that breakage — every failed write sent the test's `retry`
  helper back round — and is now 1.

Use `send_s3_error` to reject any operation.

The generic actions (`notify_operator`, memory operations, …) are supplied centrally by
`get_network_event_common_actions()`.

### Binary object bodies

Object bodies are the one place in this protocol where the payload is genuinely binary, so
the general "no bytes in action parameters" rule needs a stated exception rather than a
silent one. `send_s3_object` takes an explicit `encoding` field, following the
`send_tcp_data` precedent:

- omitted, or `"utf8"` — the characters of `content` are the object bytes (text, JSON, XML)
- `"base64"` — `content` is decoded as base64, so arbitrary binary objects work
- anything else is rejected with an error naming the valid values

There is **no auto-detection**: a base64-looking string is sent literally unless `encoding`
says otherwise. Invalid base64 fails the action with a message the model sees, rather than
putting the literal base64 characters into the object body. (Before this was implemented,
`content` was documented as "will be base64-decoded if needed" and never decoded at all.)

Object bodies still travel through the model's context, so multi-MB objects remain
impractical regardless of encoding.

**Event Types**:

- `S3_REQUEST_EVENT`: Fired for every S3 API request
    - Data: `{ "operation": "GetObject", "bucket": "my-bucket", "key": "file.txt", "request_details": {...} }`

### Example LLM Prompts

**GetObject operation**:

```json
{
  "actions": [
    {
      "type": "send_s3_object",
      "content": "Hello, World!",
      "encoding": "utf8",
      "content_type": "text/plain",
      "etag": "\"d41d8cd98f00b204e9800998ecf8427e\""
    }
  ]
}
```

**PutObject operation** (acknowledge):

```json
{
  "actions": [
    {
      "type": "notify_operator",
      "message": "Stored object my-bucket/uploaded.txt"
    }
  ]
}
```

**ListObjects operation**:

```json
{
  "actions": [
    {
      "type": "send_s3_object_list",
      "objects": [
        {
          "key": "file1.txt",
          "size": 1024,
          "last_modified": "2024-01-01T00:00:00Z",
          "etag": "\"abc123\""
        },
        {
          "key": "file2.jpg",
          "size": 2048,
          "last_modified": "2024-01-02T00:00:00Z",
          "etag": "\"def456\""
        }
      ],
      "is_truncated": false
    }
  ]
}
```

**ListBuckets operation**:

```json
{
  "actions": [
    {
      "type": "send_s3_bucket_list",
      "buckets": [
        {
          "name": "my-bucket",
          "creation_date": "2024-01-01T00:00:00Z"
        },
        {
          "name": "test-bucket",
          "creation_date": "2024-01-02T00:00:00Z"
        }
      ]
    }
  ]
}
```

**Error responses**:

```json
{
  "actions": [
    {
      "type": "send_s3_error",
      "error_code": "NoSuchKey",
      "message": "The specified key does not exist",
      "status_code": 404
    }
  ]
}
```

## Connection Management

### Connection Lifecycle

1. Server accepts TCP connection on port 9000
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
- Each connection is independent (stateless HTTP)
- No shared state between connections
- LLM maintains "virtual" data through conversation memory

## Limitations

### Protocol Features

- **No persistent storage** - data only exists in LLM conversation context
- **No authentication** - AWS signature verification not implemented, and the protocol
  declares **no startup parameters**. `require_authentication`, `access_key`, `secret_key`
  and `region` were declared until they were removed: `spawn()` never read any of them, so
  they advertised authentication the server does not perform
- **HTTP/1.1 only** - no HTTP/2 support
- **No streaming** - full request/response buffering, capped at `MAX_REQUEST_BYTES` (8 MiB)
  in `mod.rs`; a larger body is refused with `413 EntityTooLarge` and never reaches the model
- **The model never sees an uploaded body.** `s3_request` carries
  `request_details.body_size`, not the bytes — so on PutObject the model knows how large the
  object was and nothing else. It acknowledges the write (`send_s3_write_result`) without
  having read it
- **Limited operations** - only common CRUD operations supported
- **No multipart uploads** - large files not supported efficiently
- **No presigned URLs** - URL signing not implemented
- **No versioning** - object versioning not supported
- **No ACLs** - access control lists not implemented
- **No lifecycle policies** - automated data management not supported
- **Request-only** - `metadata()` declares `.request_only(…)`: "S3 is HTTP request/response; a
  server cannot send a peer anything unprompted". The dashboard's `[ send message ]` on a peer is
  disabled and shows that reason, and MCP `send_to_peer` refuses with it

### XML Generation

- Manual XML construction (no library)
- **All interpolated values are XML-escaped** (`xml_escape` in `mod.rs`). They were not
  before: a single `&`, `<` or `>` in an object key, bucket name or error message produced
  a body that is not well-formed XML, and the AWS CLI silently discards an unparseable
  `<Error>` document and reports a bare HTTP status - so `NoSuchKey` arrived at the client
  as an anonymous `404`
- `ListBucketResult` carries `Name`, `Prefix`, `MaxKeys`, `KeyCount`, `IsTruncated` and a
  `StorageClass` per object
- Still no XML validation, and no pagination tokens (`ContinuationToken`, `StartAfter`)

### Data Management

- **Virtual data** - LLM maintains data through conversation
- **No persistence** - data lost when LLM context is cleared
- **Consistency** - depends on LLM memory
- **Scalability** - limited by LLM context window
- **Large objects** - impractical to return multi-MB objects through LLM

## Known Issues

1. **Data consistency**: LLM may forget or hallucinate data between requests
2. **Binary content**: supported via `"encoding": "base64"` on `send_s3_object`; the bytes
   still pass through the model context, so large objects remain impractical
3. **Large responses**: Very large object lists may exceed response size limits
4. **Path parsing**: Complex query parameters not parsed (pagination tokens, etc.)
5. **Error codes**: Limited AWS error code vocabulary

## Logging Strategy

Following NetGet's dual logging pattern (tracing macros + status_tx):

### TRACE Level

- Full HTTP request/response details
- Request path, method, headers
- XML responses (pretty-printed)
- Object content sizes

### DEBUG Level

- Operation summaries: `GET /bucket/key → 200 OK (1024 bytes)`
- Response types: "Sending S3 object 512 bytes"
- Bucket/object operations

### INFO Level

- Server lifecycle: "S3 server listening on 0.0.0.0:9000"
- Connection events: "S3 client connected from 127.0.0.1:54321"

### WARN Level — the `decision=` tags

Every request that does not produce a normal S3 response is logged with a stable
`decision=` tag, so an operator can tell the three cases apart with `grep`:

- `decision=model_answer` — the model produced `s3_object` / `s3_object_list` /
  `s3_bucket_list` (DEBUG, alongside the normal response)
- `decision=model_reject` — the model deliberately refused, via `send_s3_error` (DEBUG)
- `decision=model_no_action` — the model answered nothing this protocol can turn into a
  response, or every action it emitted failed to execute. WARN, and the wire answer is a
  **500 `InternalError`**: the empty `200 OK` fall-through this line used to describe is
  gone, because for PutObject/CreateBucket/DeleteObject/HeadObject it read to the client as
  success. The line names how many actions failed
- `decision=fail_closed_body_rejected` — the request body exceeded `MAX_REQUEST_BYTES`
  (8 MiB) or could not be read. WARN, and the peer gets `413` + `<Code>EntityTooLarge</Code>`.
  The request never reaches the model: a truncated upload used to be reported to it as a
  PutObject carrying zero bytes, which it would then acknowledge as a stored object
- `decision=fail_closed_llm_error category=Overloaded|Unavailable` — netget could not reach
  a decision at all (backend error, timeout, unusable output). WARN, and the **only** place
  the full error text is written; it goes to `netget.log` and the TUI status stream and
  never to the peer

### The LLM-failure wire response

On `Err` from `call_llm` the peer gets an S3 `<Error>` document carrying only a category
from `crate::utils::WireFailure` — never the error, the backend URL, the model name or an
`anyhow` chain:

- `WireFailure::Overloaded` → `503` + `<Code>ServiceUnavailable</Code>` + `Retry-After: 5`,
  so an SDK backs off and retries
- `WireFailure::Unavailable` → `500` + `<Code>InternalError</Code>`, a permanent fault

Keeping the two codes distinct is the point: collapsing both onto 500 makes a transient
backend saturation look permanent to every S3 client.

### ERROR Level

- Internal errors: "Dropping S3 {name} header: … is not a valid HTTP header value"

## Example Prompts

### Basic S3 Server

```
Start an S3-compatible server on port 9000. Create a bucket called 'test-bucket'
with a file 'hello.txt' containing "Hello, World!". When clients request the file,
return the content.
```

### Dynamic Content Generation

```
Start an S3 server on port 9000. When clients request any .txt file, generate
random content. For .json files, return valid JSON with a timestamp. List all
requested files in the bucket listing.
```

### Honeypot Mode

```
Start an S3 server on port 9000 that logs all requests but returns empty responses.
Pretend to have buckets called 'backups' and 'data', but return empty listings.
```

### Selective Storage

```
Start an S3 server on port 9000. Accept uploads to bucket 'uploads' and remember
the file names. When clients list the bucket, show all uploaded files. Return
"Access Denied" for other buckets.
```

## References

- [AWS S3 REST API](https://docs.aws.amazon.com/AmazonS3/latest/API/Welcome.html)
- [S3 Error Codes](https://docs.aws.amazon.com/AmazonS3/latest/API/ErrorResponses.html)
- [MinIO Documentation](https://min.io/docs/minio/linux/index.html)
- [rust-s3 client](https://docs.rs/rust-s3/) - for testing

## Connection bounds

Before September 2026 this server accepted without limit and bounded no read in time, so a peer
that connected and said nothing held a socket, a connection task and an `AppState` entry forever,
pre-authentication, on a server that would happily accept a hundred more. It now declares both
halves; the constants and the reasoning live beside them in `src/server/s3/mod.rs`.

| Bound | Value | Why this number |
|---|---|---|
| `FIRST_BYTE_READ_TIMEOUT` | 30s | HTTP is client-speaks-first, so a peer that has connected and sent no byte has begun no request. 30s sits between nginx's `client_header_timeout` default of 60s and Apache's `RequestReadTimeout header=20`. Enforced with `TcpStream::peek` before the socket reaches hyper, so the request line is still there for hyper afterwards. |
| `IDLE_BETWEEN_REQUESTS_TIMEOUT` | 300s | Deliberately more permissive than the service this mimics: AWS's own load balancers ship a 60-second idle timeout and S3 closes idle connections of its own accord, so every SDK already has the reopen path. An object body being served is not silence — the response is built under a busy guard and written by hyper. |
| `MAX_CONNECTIONS` | 256 | Each admitted connection may hold one whole in-memory response body (an object body — the largest thing this family serves), so the cap turns that per-connection bound into a total one. Refusal: **HTTP/1.1 `503 Service Unavailable` with `Retry-After: 5`** — a 503 with `Retry-After` is S3's own overload reply (`SlowDown`), which every SDK's retry path handles. Nothing of netget's reaches the wire; the reason is logged under `decision=fail_closed_connection_cap`. |

**NetGet's own S3 client is *lazy*, so it is never the silent peer this bound closes:**
`src/client/s3/mod.rs` builds a config to prove it is usable and drops it, opening no socket
until an operation runs — `PROTOCOL_QUALITY.md`'s three-state test.

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
*idle* deadline (300s) rather than by the 30s one. hyper's own `header_read_timeout` cannot
express the pair: it re-arms whenever hyper starts reading a head, an idle keep-alive connection
included, so setting it to 30s would close every pooled client between requests — collapsing the
two bounds onto one number, which is exactly what the pair exists to avoid.

`tests/server/s3/connection_bounds_test.rs` drives all three from the wire, over
`tests/helpers/http_bounds.rs`. Each was verified by **removing** the bound and watching the test
fail: with the `peek` deadline gone the silent peer still held the socket at 60s; with the idle
bound collapsed to 30s an answered connection was closed after 38s of silence; with the permit
released early the connection past the cap was served instead of refused. The real-client evidence this protocol's rating rests on — rust-s3 0.37 (`tests/server/s3/e2e_test.rs`) — still passes.
