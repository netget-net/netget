# Elasticsearch Protocol Implementation

## Overview

Elasticsearch-compatible server implementing the Elasticsearch HTTP/JSON REST API. The server handles search, indexing,
and cluster management operations with full LLM control over responses. This is a "virtual" search engine where the LLM
maintains data and search results through conversation context.

**State**: `Experimental`, and it stays there. The only e2e evidence is `reqwest`, a generic
HTTP client, which proves an HTTP server answers — not that the Elasticsearch API on top of it
is right. `metadata()` claimed "curl / elasticsearch client"; neither has ever been pointed at
this server. Promoting it means driving it with the official `elasticsearch` crate or a real
client.
**Port**: 9200 (default Elasticsearch port)
**Protocol**: HTTP/1.1 with JSON payloads
**API Version**: Elasticsearch 7.x/8.x compatible
**Stack Representation**: `ETH>IP>TCP>HTTP>ELASTICSEARCH`

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
- Elasticsearch uses JSON for all data
- No binary protocol support

**Manual API Implementation**:

- LLM controls all Elasticsearch operations through action system
- No Elasticsearch client dependencies
- Responses manually constructed as JSON
- Operation detection from HTTP method + path

## Architecture Decisions

### REST API Design

- Operations determined by HTTP method (GET, POST, PUT, DELETE) and path
- Path structure: `/{index}/_doc/{id}`, `/{index}/_search`, `/_cluster/health`, etc.
- Request body is JSON (for POST/PUT operations)
- Response body is JSON with operation results
- Standard HTTP status codes (200, 201, 404, 500)
- Custom header: `X-elastic-product: Elasticsearch`

### Request body limit

The body is bounded at `MAX_REQUEST_BODY_BYTES` (8 MiB) with `http_body_util::Limited`; a
larger one is refused with **413** and a `circuit_breaking_exception` envelope, *before* any
LLM call. `Incoming` has no default limit, so this used to buffer whatever an unauthenticated
peer chose to send — a single `POST /_bulk` was enough — and the body is then embedded whole
in an LLM prompt, so there is no legitimate large one either.

The old `Err` arm fell through with an **empty** body, which is worse than the limit being
absent: the handler was shown a request with no body and answered it as though the client had
sent none, so a truncated bulk index read as an empty one.

The constant is local rather than shared because `server::http_common` is gated on
`any(feature = "http", "http2", "oauth2", …)` and `elasticsearch` is not in that list — the
same exit `xmlrpc` takes. Adding `couchdb` and `elasticsearch` to that gate in
`src/server/mod.rs` would let both share `http_common::MAX_REQUEST_BODY_BYTES`.

### Fields that cannot be defaulted

Every default an action supplies is an assertion, and three were the affirmative one:

| Action | Field | Old default | Why it had to go |
|---|---|---|---|
| `send_index_response` | `result` | `"created"` | it is what makes the reply **201 Created**, so an omitted value reported a document as newly indexed that nothing said had been indexed |
| `send_cluster_health` | `status` | `"green"` | the whole content of a health check; a handler that said nothing reported a fully-allocated cluster. Now `required` in the declaration too |
| `send_get_response` | `found` | `false` | decides 200-with-a-document versus 404 either way, and a mistyped `"true"` (a string, not a JSON boolean) silently became "no such document" |

`send_bulk_response`'s `errors` stays optional but is no longer assumed: when it is omitted it
is **derived** from `items` — any entry carrying an `error` object or a 4xx/5xx `status` makes
it `true`. Clients check that flag before deciding whether to walk `items` at all, so
defaulting it to `false` hid per-item failures the handler had itself reported. An explicit
value still wins.

`tests/server/elasticsearch/refusal_test.rs` covers all of this plus the 413.

### Stateless Operation

- Each HTTP request is independent
- No persistent storage or connection state
- LLM maintains "virtual" indices and documents through conversation context
- Server ID used but no per-connection state

### Request Processing Flow

1. Accept TCP connection
2. Parse HTTP request (method, URI, headers, body)
3. Detect operation from method + path (e.g., GET + "/_search" → search)
4. Parse index name and document ID from path
5. Create `ELASTICSEARCH_REQUEST_EVENT` with method, path, operation, body
6. Call LLM via `call_llm()` (which first tries any script/static handler, so those cost no
   model call)
7. Process action result:
    - `ActionResult::Custom { name: "elasticsearch_response", .. }`: Build HTTP response
      with status/body
8. If no action, **fail closed**: 500 with the standard Elasticsearch error envelope
   (`type: "server_error"`) carrying the `WireFailure` category. It used to return
   `{"acknowledged": true}` — the most affirmative body in the API, sent exactly when nothing
   affirmed anything, so a declined create-index or delete-by-query read as applied.
9. Keep the connection open for further requests

### Operation Detection

- **Root endpoint** (`GET /`) → cluster_info
- **Search** (`GET|POST /_search` or `/{index}/_search`) → search
- **Index document** (`POST|PUT /{index}/_doc` or `/{index}/_doc/{id}`) → index
- **Get document** (`GET /{index}/_doc/{id}`) → get
- **Delete document** (`DELETE /{index}/_doc/{id}`) → delete
- **Bulk operations** (`POST|PUT /_bulk` or `/{index}/_bulk`) → bulk
- **Index management** (`PUT|DELETE|GET /{index}`) → create_index, delete_index, index_info
- **Cluster operations** (`GET /_cluster/health`, `/_cluster/stats`) → cluster_health
  (answer with `send_cluster_health`), cluster_stats (answer with
  `send_elasticsearch_response`)
- **Cat API** (`GET /_cat/{endpoint}`) → cat_*

### Response Format

- Status: 200 (success), 201 (created), 404 (not found), 500 (error)
- Headers:
    - `Content-Type: application/json; charset=UTF-8`
    - `X-elastic-product: Elasticsearch`
- Body: JSON object with operation-specific fields
- Error format: `{"error": {"type": "...", "reason": "..."}, "status": 500}`

## LLM Integration

### Action-Based Responses

**Sync Actions** (network event context required) — these are the action names the model
emits. `elasticsearch_response` is the *internal* `ActionResult::Custom` name every one of
them produces; it is **not** an action name the model may emit.

- `send_elasticsearch_response` — `status_code` (number, required), `body` (string,
  required). The escape hatch for endpoints with no dedicated action (`_cat/*`, index
  management, deletes). `status_code` outside 100-599 is rejected.
- `send_search_response` — `hits` (array, required), `total` (number), `took` (number).
  Wraps `hits` in the full `{took, timed_out, _shards, hits:{total:{value,relation},
  max_score, hits}}` envelope; the model supplies only the inner hit documents.
- `send_index_response` — `index`, `id`, `result` (`"created"` or `"updated"`). Emits
  `_index/_id/_version/result/_shards/_seq_no/_primary_term`, and answers 201 for
  `"created"`, 200 otherwise.
- `send_get_response` — `found` (bool, required), `index`, `id`, `source` (object).
  Emits the `_source` envelope and answers 200 when found, 404 when not.
- `send_bulk_response` — `items` (array, required), `errors` (bool). Wraps as
  `{took, errors, items}`.
- `send_cluster_info` — `cluster_name`, `version`. Answers the root endpoint (`GET /`)
  with the node/version banner. It carries **no** cluster status.
- `send_cluster_health` — `cluster_name`, `status` (`green`/`yellow`/`red`, validated),
  `number_of_nodes`, `active_shards`. Answers `GET /_cluster/health`.

The generic actions (`notify_operator`, memory operations, …) are supplied centrally by
`get_network_event_common_actions()`.

### Startup Parameters

**None.** `get_startup_parameters()` returns an empty list. `send_first` was declared here
and even parsed in `spawn()`, but arrived at the server as `_send_first` and was discarded -
there is nothing to send before a client issues an HTTP request. Passing it now produces an
explicit "does not support send_first" warning instead of being silently accepted.

**Event Types**:

- `ELASTICSEARCH_REQUEST_EVENT`: Fired for every Elasticsearch operation
    - Data:
      `{ "method": "POST", "path": "/_search", "operation": "search", "index": null, "doc_id": null, "request_body": "{...}" }`

### Example LLM Prompts

**Root endpoint** (cluster info):

```
For GET / request, use send_elasticsearch_response with:
status_code=200
body='{"name":"netget-node","cluster_name":"netget","version":{"number":"8.0.0"},"tagline":"You Know, for Search"}'
```

**Search operation**:

```
For POST /products/_search with query match_all, use send_elasticsearch_response with:
status_code=200
body='{"hits":{"total":{"value":2},"hits":[{"_index":"products","_id":"1","_source":{"name":"Widget"}},{"_index":"products","_id":"2","_source":{"name":"Gadget"}}]}}'
```

**Index document**:

```
For PUT /products/_doc/1, use send_elasticsearch_response with:
status_code=201
body='{"_index":"products","_id":"1","_version":1,"result":"created"}'
```

**Get document**:

```
For GET /products/_doc/123, use send_elasticsearch_response with:
status_code=200
body='{"_index":"products","_id":"123","found":true,"_source":{"name":"Widget","price":19.99}}'
```

**Delete document**:

```
For DELETE /products/_doc/123, use send_elasticsearch_response with:
status_code=200
body='{"_index":"products","_id":"123","_version":2,"result":"deleted"}'
```

**Error responses**:

```
For GET /products/_doc/nonexistent, use send_elasticsearch_response with:
status_code=404
body='{"_index":"products","_id":"nonexistent","found":false}'
```

## Connection Management

### Connection Lifecycle

1. Server accepts TCP connection on port 9200
2. Create `ConnectionId` for tracking
3. Add connection to `ServerInstance` with `ProtocolConnectionInfo::empty()` (that type is a
   generic `serde_json::Value` wrapper, not a per-protocol enum)
4. Spawn HTTP service handler
5. `http1::Builder::serve_connection` serves the connection, including keep-alive
6. Connection closed when the client closes it

### State Tracking

- Connection state stored in `ServerInstance.connections` HashMap
- No protocol-specific connection state is recorded; there is no `recent_requests` list
- Tracks: remote_addr, local_addr. `bytes_sent`/`bytes_received` are initialised to 0 and
  never updated
- Status: Active → Closed when the connection ends

### Concurrency

- Multiple connections handled concurrently
- Each connection is independent (stateless HTTP)
- No shared state between connections
- LLM maintains "virtual" indices and documents through conversation memory

## Limitations

### Protocol Features

- **No persistent storage** - data only exists in LLM conversation context
- **No authentication** - no security features
- **HTTP/1.1 only** - no HTTP/2 support
- **No streaming** - full request/response buffering
- **Limited operations** - only common REST API operations supported
- **No aggregations** - advanced aggregation queries not implemented
- **No scripting** - Painless scripting not supported
- **No snapshots** - backup/restore not implemented
- **No plugins** - no plugin system
- **No X-Pack features** - no ML, security, monitoring
- **Request-only** - `metadata()` declares `.request_only(…)`: "Elasticsearch is HTTP
  request/response; a server cannot send a peer anything unprompted". The dashboard's
  `[ send message ]` on a peer is disabled and shows that reason, and MCP `send_to_peer` refuses
  with it

### Performance

- Each request triggers LLM call
- No actual search indexing or ranking
- Full request/response in memory
- Connection overhead per request

### Data Management

- **Virtual data** - LLM maintains indices/documents through conversation
- **No persistence** - data lost when LLM context is cleared
- **Consistency** - depends on LLM memory
- **Scalability** - limited by LLM context window
- **No relevance scoring** - LLM simulates search results

## Known Issues

1. **Data consistency**: LLM may forget or hallucinate documents between requests
2. **Complex queries**: Advanced query DSL may confuse LLM
3. **Large responses**: Very large result sets may exceed response size limits
4. **Bulk format**: Newline-delimited JSON (NDJSON) for bulk operations requires careful parsing
5. **Search relevance**: LLM cannot perform real full-text search or scoring

## Example Responses

### Root Endpoint (Cluster Info)

```json
{
  "actions": [
    {
      "type": "send_elasticsearch_response",
      "status_code": 200,
      "body": "{\"name\":\"netget\",\"cluster_name\":\"netget-cluster\",\"version\":{\"number\":\"8.0.0\"},\"tagline\":\"You Know, for Search\"}"
    }
  ]
}
```

### Search Response

```json
{
  "actions": [
    {
      "type": "send_elasticsearch_response",
      "status_code": 200,
      "body": "{\"hits\":{\"total\":{\"value\":2},\"hits\":[{\"_id\":\"1\",\"_source\":{\"name\":\"Widget\"}}]}}"
    }
  ]
}
```

### Index Document Success

```json
{
  "actions": [
    {
      "type": "send_elasticsearch_response",
      "status_code": 201,
      "body": "{\"_index\":\"products\",\"_id\":\"1\",\"result\":\"created\"}"
    }
  ]
}
```

### Error Response

```json
{
  "actions": [
    {
      "type": "send_elasticsearch_response",
      "status_code": 404,
      "body": "{\"_index\":\"products\",\"_id\":\"999\",\"found\":false}"
    }
  ]
}
```

## References

- [Elasticsearch REST API](https://www.elastic.co/guide/en/elasticsearch/reference/current/rest-apis.html)
- [Elasticsearch Search API](https://www.elastic.co/guide/en/elasticsearch/reference/current/search-search.html)
- [Elasticsearch Document APIs](https://www.elastic.co/guide/en/elasticsearch/reference/current/docs.html)
- [Elasticsearch Query DSL](https://www.elastic.co/guide/en/elasticsearch/reference/current/query-dsl.html)

## Connection bounds

Before September 2026 this server accepted without limit and bounded no read in time, so a peer
that connected and said nothing held a socket, a task and an `AppState` entry forever,
pre-authentication, and a hundred of them was a free denial of service on a server that would
happily accept a hundred more. It now declares both halves; the constants and the argument for
each live beside them in `src/server/elasticsearch/mod.rs`.

| Bound | Value | Why this number |
|---|---|---|
| `FIRST_BYTE_READ_TIMEOUT` | 30s | HTTP is client-speaks-first, so a peer that has completed the handshake and sent no byte has asked nothing and negotiated nothing — the state carries no protocol yet, which is why this number is the same across netget's HTTP family. Apache's `mod_reqtimeout` gives the request header 20s and nginx's `client_header_timeout` 60s. Enforced with `TcpStream::peek` before the socket reaches hyper, so the request line is still there afterwards. |
| `IDLE_BETWEEN_REQUESTS_TIMEOUT` | 75s | nginx's `keepalive_timeout` default. Elasticsearch's official clients — the Java `RestClient`, `elasticsearch-py` — hold a *pool* of connections for the life of the application, which looks like an argument for minutes and is not: a scroll, a `?wait_for_completion` request or a bulk batch in progress is a request **in flight**, which the watchdog reports as not idle at all. What is left is a pooled connection with nothing outstanding, and reopening one costs a loopback handshake. |
| `MAX_CONNECTIONS` | 128 | Below the shared `DEFAULT_MAX_CONNECTIONS` of 256 on purpose: each admitted connection may buffer one body of up to 8 MiB, the largest per-connection cost in netget's HTTP family, and the cap is what turns that per-connection bound into a total one. 128 holds the worst case to the same ~1 GiB ceiling the smaller-bodied servers reach at 256. Refusal: **HTTP/1.1 `503 Service Unavailable` with `Retry-After`**, written straight onto the socket — the peer has sent no request line for hyper to answer — and logged `decision=fail_closed_connection_cap`. Fixed bytes, so nothing derived from an error can reach the wire. |

**NetGet's own Elasticsearch client is *lazy*, so it is never the silent peer this bound
closes:** `src/client/elasticsearch/` builds a `reqwest::Client` and opens no socket until an
action issues a request — `PROTOCOL_QUALITY.md`'s three-state test.

**The deadline covers the read and nothing else.** hyper owns every read once `serve_connection`
starts, and it keeps polling the connection for more input *while a request is being answered* —
so a deadline on those reads would be wrong here, not merely awkward. The idle bound is a
watchdog over `ConnectionActivity` instead, which reports a connection with work in flight as not
idle at all. The model round-trip, and an event a `manual` rule parked for a human
(`src/state/intercepts.rs`, 300s by default), are therefore outside every deadline by
construction: an answer that takes minutes can never close the connection it is an answer for.
That is the `.connectionless()` lesson in the project `AGENTS.md` read in reverse — TFTP evicted
live transfers because "idle" was measured wrongly.

**hyper's own `header_read_timeout` is not this bound.** Its 30-second default is inert unless
`http1::Builder::timer` is also set, which nothing here does: hyper downgrades a defaulted
duration to `None` when no timer is present and applies no deadline at all. That is why the
`peek` is not redundant.

`tests/server/elasticsearch/connection_bounds_test.rs` drives all three from the wire, with three
sockets on one server whose only rule is `*` → `manual`: a silent peer must be closed after the
first-byte bound, a peer that sends a request line and then stalls (slowloris) after the idle
bound, and a peer whose request is parked for a human must **not** be closed at all. The shared
driver and the removal-verification notes are in `tests/helpers/http_bounds.rs`.
`tests/tcp_server_bounds_ratchet_test.rs` fails the build if either bound disappears.
