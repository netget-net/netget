# `http` — MCP reference

Available as a **server** (`start_server`) and as a **client** (`start_client`).

## Server — `start_server`

Web server serving HTTP traffic

- **maturity**: Beta
- **privilege required**: Privileged port 80 (requires root or capabilities)
- **network stack**: ETH>IP>TCP>HTTP
- **implementation**: hyper v1.0 HTTP/1.1 server, optional TLS via rustls
- **LLM controls**: Response content (status, headers, text body) — one response per request
- **when the model cannot answer**: answers — the peer gets the protocol's own error reply carrying a category (overloaded or unavailable), never an invented success and never the error text
- **connections**: connection-oriented — each peer has a connection id (see `server_status`) that lives until either side closes it
- **history**: off by default — each event reaches the model alone (pass `history` to change it)
- **batching**: unsupported — each event is answered as it arrives
- **notes**: Text bodies only: no binary response bodies, no chunked/streaming responses, and request bodies are fully buffered before the LLM sees them

### `start_server` arguments

- `protocol` (string, **required**) — `"http"`
- `port` (number) — listen port. <normalized: resolved against this host's privilege and bound ports>
- `host` (string) — bind address. Default `"127.0.0.1"`.
- `event_handlers` (array) — **preferred**. Deterministic, in-process, no LLM call. Each entry is `{"event_pattern": "<event id>" | "*", "handler": {…}}`, matched in order, first match wins. `handler` is one of `{"type":"script","language":"python"|"javascript","code":"…"}`, `{"type":"static","actions":[…]}`, or `{"type":"llm","instruction":"…"}`. A script receives the event as JSON on stdin (fields under `data['event']`) and must print `{"actions":[…]}` to stdout. Use the event ids and field names listed below.
- `instruction` (string) — natural-language fallback. Costs one model call per event; use only when the response genuinely needs reasoning.
- `startup_params` (object) — this protocol accepts `tls_enabled`, `cert_path`, `key_path`, `common_name`, `san_dns_names`, `validity_days`, `organization`, `organizational_unit`, `request_filter`, `filtered_response`, `default_response`. Schema below. Passing a key this protocol does not declare is an error.
- `initial_memory` (string) — seeds the server's LLM memory before the first event.
- `feedback_instructions` (string) — natural-language instructions for the automatic feedback loop that adjusts the server as it runs.
- `scheduled_tasks` (array) — server-scoped recurring/delayed LLM tasks. Each entry: `{"task_id":"…","recurring":true,"interval_secs":60,"instruction":"…"}` (or `"recurring":false` with `"delay_secs"`). Removed when the server stops.
- `history` (number) — earlier exchanges on the same connection the model is shown with each event; 0 turns it off. Omit for the default above.
- `batching` (boolean) — deliver events that arrive during a call together afterwards. Omit for the default above.

### Events (`http_request`) — valid values for `event_pattern`

#### `http_request`

HTTP request received from client. Always answer with exactly one send_http_response, and match the response Content-Type to the client's Accept header (headers.accept): HTML for text/html, JSON for application/json; if the client only accepts an image or other binary type you cannot produce (e.g. a browser fetching /favicon.ico with Accept: image/*), answer 404 rather than sending text as an image.

Event data fields (a script reads these as `data['event'][…]`):

- `method` (string, **required**) — HTTP method (GET, POST, etc.)
- `path` (string, **required**) — Request path without query string (e.g., '/api/users')
- `query_string` (string, optional) — Raw query string if present (e.g., 'x=5&y=3')
- `query` (object, optional) — Parsed query parameters as key-value pairs (e.g., {"x": "5", "y": "3"})
- `headers` (object, **required**) — Request headers as key-value pairs
- `body` (string, optional) — Request body decoded as UTF-8 text (empty string when there is no body). Bytes that are not valid UTF-8 are replaced with U+FFFD, so when body_is_binary is true this field is lossy and must not be treated as the exact request payload.
- `body_bytes` (number, optional) — Size of the request body in bytes, before UTF-8 decoding.
- `body_is_binary` (boolean, optional) — Present and true only when the request body is not valid UTF-8. The body field is then a lossy decoding; the raw bytes are not available to you.

Respond with: `send_http_response`

Example handler response:

```json
{
  "actions": [
    {
      "type": "send_http_response",
      "status": 200,
      "headers": {
        "Content-Type": "text/html"
      },
      "body": "<html><body>Hello World</body></html>"
    }
  ]
}
```

Alternative:

```json
{
  "actions": [
    {
      "type": "send_http_response",
      "status": 404,
      "headers": {
        "Content-Type": "text/plain"
      },
      "body": "Not Found"
    }
  ]
}
```

Alternative:

```json
{
  "actions": [
    {
      "type": "send_http_response",
      "status": 201,
      "headers": {
        "Content-Type": "application/json"
      },
      "body": "{\"status\": \"created\"}"
    }
  ]
}
```

### Response actions

These are the action objects a handler may return (inside `{"actions":[…]}` for a script, or as `handler.actions` for a static handler).

#### `send_http_response`

Respond to the HTTP request that triggered this event. This is the ONLY action that produces an HTTP response - do NOT use generic 'send_data' or 'show_message' for that. ALWAYS emit exactly one send_http_response for every request — never return an empty action list, or the client gets a 500 error. HONOR THE CLIENT'S `Accept` REQUEST HEADER (in the event's headers.accept): return a `Content-Type` the client accepts, and a body in that format. If Accept is `text/html`, return HTML; `application/json`, return JSON; `text/plain`, return text. If the client asks ONLY for a type you cannot produce — most commonly an image (`Accept: image/*`, e.g. a browser fetching /favicon.ico) or any other binary type — respond `404` (or `204`) rather than sending text mislabeled as an image: the body is UTF-8 text only, so binary payloads (images, gzip, protobuf) cannot be produced at all. The response is sent complete, in one piece, as soon as you return; there is no way to stream or chunk it, to send it in parts, or to keep the request open.

Parameters:

- `status` (number, **required**) — HTTP status code as a number between 100 and 599 (e.g. 200, 404, 500).
- `headers` (object, optional) — Optional response headers as a flat name->value object (e.g. {"Content-Type": "text/html"}). Set Content-Type yourself; Content-Length and Date are added automatically and must not be set here. Headers whose name or value is not legal HTTP (for example one containing a newline) are dropped.
- `body` (string, optional) — Response body as text (HTML, JSON, plain text). Optional: omit it for an empty body, which is what 204 and 304 require. A JSON object or array is serialized to compact JSON text. Bytes cannot be sent - text only.

```json
{
  "type": "send_http_response",
  "status": 200,
  "headers": {
    "Content-Type": "text/html"
  },
  "body": "<html><body>Hello World</body></html>"
}
```

### `startup_params` schema

- `tls_enabled` (boolean, optional) — Enable TLS/SSL encryption (default: false for HTTP/HTTP2, always true for QUIC) Example: `true`
- `cert_path` (string, optional) — Path to TLS certificate file (PEM format). If not provided, a self-signed certificate will be generated. Example: `"/path/to/cert.pem"`
- `key_path` (string, optional) — Path to TLS private key file (PEM format). Required if cert_path is provided. Example: `"/path/to/key.pem"`
- `common_name` (string, optional) — Common Name (CN) for self-signed certificate (default: netget-dns-server) Example: `"example.com"`
- `san_dns_names` (array, optional) — Subject Alternative Names (DNS names) for self-signed certificate (default: ["localhost", "*.local"]) Example: `["example.com","*.example.com"]`
- `validity_days` (number, optional) — Positive certificate validity period in days for self-signed certificate, within the supported date range (default: 365) Example: `365`
- `organization` (string, optional) — Organization name for self-signed certificate (default: NetGet) Example: `"My Organization"`
- `organizational_unit` (string, optional) — Organizational unit for self-signed certificate Example: `"IT Department"`
- `request_filter` (array, optional) — RECOMMENDED for any HTTP server a browser or the public internet will reach: set this so you do not spend a slow LLM call on favicon.ico, CORS preflights, and scanner noise. A good default that only reasons about real page loads is [{"methods":["GET"],"headers":{"accept":"text/html"}}] — favicon and image probes carry `Accept: image/*`, and preflights are not GET, so they are auto-answered without a model call. Allowlist of request-match rules deciding which requests reach the LLM. A request is handled by the LLM only if it matches at least one rule; requests matching no rule get `filtered_response` (default 404) with NO LLM call. Omit this to send every request to the LLM. Each rule is an object; all present conditions must hold (AND), and rules are OR'd together. Conditions: `methods` (array of HTTP methods, case-insensitive; omit for any), `path` (a regular expression matched against the URL path, e.g. "^/$" or "^/api/"; omit for any), `headers` (object mapping header name to either true = must be present, or a string = value must contain that substring case-insensitively, e.g. {"accept": "text/html"}). Example filter that only sends real browser page loads to the LLM (favicon/OPTIONS/XHR are auto-404'd): [{"methods":["GET"],"headers":{"accept":"text/html"}}]. Fail-open: a malformed rule (e.g. an invalid `path` regex) is dropped with a loud error instead of failing startup, so a typo means MORE requests reach the LLM, not fewer. Check the server status output after starting. Example: `[{"methods":["GET"],"path":"^/$","headers":{"accept":"text/html"}},{"methods":["POST"],"path":"^/api/"}]`
- `filtered_response` (object, optional) — Response returned (without any LLM call) for requests that match no `request_filter` rule. Fields: `status` (number, default 404), `body` (string, default empty), `headers` (object of name→value). Ignored when no request_filter is set. Example: `{"status":404,"body":"Not Found"}`
- `default_response` (object, optional) — Response used when the model IS consulted for a request but returns no send_http_response (an empty answer). Without this, such a request is refused with a 500, because nothing answered it. Set a sensible fallback — commonly a 404 page — so a declined request gets a deliberate answer instead. Same shape as filtered_response: `status` (number), `body` (string), `headers` (object of name→value). Example: `{"status":404,"headers":{"Content-Type":"text/html"},"body":"<!doctype html><title>Not Found</title><h1>404</h1>"}`

---

## Client — `start_client`

HTTP/HTTPS client for making web requests (HTTP/1.1, HTTP/2)

- **maturity**: Beta
- **privilege required**: None
- **network stack**: ETH>IP>TCP>HTTP
- **implementation**: reqwest HTTP/HTTPS client library (HTTP/1.1, HTTP/2 via rustls); in the browser build hyper's HTTP/1.1 client over the virtual loopback (plain http:// only)
- **LLM controls**: Full control over requests (method, path, headers, body)
- **history**: the model is shown up to 40 earlier exchanges on the same connection with each event, within a 4 KB budget (pass `history` to change it; 0 turns it off)
- **batching**: unsupported — each event is answered as it arrives
- **notes**: Validated against nginx over plain HTTP/1.1. HTTPS, HTTP/2, redirects and compressed bodies are not exercised against a real server. A response body is read whole up to 8 MiB and refused past it. The browser transport (transport.rs) is exercised against NetGet's own servers only, chunked responses included.

### `start_client` arguments

- `protocol` (string, **required**) — `"http"`
- `remote_addr` (string, **required**) — the server to connect to, `host:port` (e.g. `"127.0.0.1:6379"`).
- `event_handlers` (array) — same shape as `start_server`; deterministic, no LLM call. Target the client event ids listed below.
- `instruction` (string) — natural-language fallback, one model call per event.
- `startup_params` (object) — this protocol accepts `default_headers`. Schema below.
- `initial_memory` (string) — seeds the client's LLM memory.
- `feedback_instructions` (string) — instructions for the automatic feedback loop.
- `scheduled_tasks` (array) — client-scoped recurring/delayed LLM tasks, same shape as for `start_server`.
- `history` (number) — earlier exchanges on the same connection the model is shown with each event; 0 turns it off. Omit for the default above.
- `batching` (boolean) — deliver events that arrive during a call together afterwards. Omit for the default above.

### Events (`http_connected`, `http_response_received`) — valid values for `event_pattern`

#### `http_connected`

Triggered when HTTP client is initialized

Event data: (no documented fields)

Example handler response:

```json
{
  "actions": [
    {
      "type": "show_message",
      "message": "Handled http_connected"
    }
  ]
}
```

#### `http_response_received`

Triggered when HTTP client receives a response

Event data: (no documented fields)

Example handler response:

```json
{
  "actions": [
    {
      "type": "show_message",
      "message": "Handled http_response_received"
    }
  ]
}
```

### Response actions

Action objects a client handler may return.

#### `send_http_request`

Send another HTTP request in response to received data

Parameters:

- `method` (string, **required**) — HTTP method
- `path` (string, **required**) — Request path, resolved against the client's base URL. An absolute URL is accepted only on that same origin; another host needs its own client
- `headers` (object, optional) — Request headers
- `body` (string, optional) — Request body

```json
{
  "type": "send_http_request",
  "method": "POST",
  "path": "/api/data",
  "body": "{\"key\": \"value\"}"
}
```

#### `wait_for_more`

Take no action and wait for the next response. Use when nothing should be sent yet.

Parameters: none.

```json
{
  "type": "wait_for_more"
}
```

### Client actions

What the client can do on its own initiative. The `instruction` LLM and handlers can use them, and `send_to_client` puts any of them — or of the response actions above — on the wire now.

#### `disconnect`

Disconnect from the HTTP server

Parameters: none.

```json
{
  "type": "disconnect"
}
```

### `startup_params` schema

- `default_headers` (object, optional) — Default headers to include in all requests Example: `{"User-Agent":"NetGet/1.0","Accept":"application/json"}`

