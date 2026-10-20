# Protocol Documentation

## CRITICAL: When to Use Server vs Client Mode

**Server Mode (open_server)** - Use when the user wants to HOST/SERVE content:
- Keywords: "serve", "host", "listen", "start a server", "create a server", "run a server", "open server", "provide", "respond to"
- You LISTEN on a port and RESPOND to incoming requests
- User wants to PROVIDE a service that others connect to
- Examples: "host a website", "start HTTP server", "create DNS server", "run FTP server"

**Client Mode (open_client)** - Use when the user wants to CONNECT to an existing remote server:
- Keywords: "connect to", "fetch from", "query", "access", "call", "request from", "get from", "send to", "send a"
- You CONNECT to a remote server and SEND requests to it
- User wants to ACCESS a service that someone else is running
- Examples: "connect to Redis at localhost:6379", "fetch from API", "query database"

**⚠️ IMPORTANT**: If the user says "serve", "host", or "provide" content, use `open_server` even if they mistakenly say "client".
The ACTION (serving content) matters more than the word choice.

---

# HTTP (Server Mode)

**Mode:** Server - listens for incoming connections
**Stack:** ETH>IP>TCP>HTTP
**Group:** Core
**Maturity:** Beta
**Privilege required:** Privileged port 80 (requires root or capabilities)
**Port:** omit `port` to listen on the well-known port 80 (tcp). If this process cannot bind it (below 1024 without privilege, or already in use) the server starts on an OS-assigned port and the result says so. An explicit port, `0` included, is used as given.
**When the model cannot answer:** answers — the peer gets the protocol's own error reply carrying a category (overloaded or unavailable), never an invented success and never the error text
**History:** off by default — each event reaches the model alone (pass `history` to change it)
**Batching:** unsupported — each event is answered as it arrives

## Description

Web server serving HTTP traffic

## Startup Parameters

Passed as `startup_params`; a key not listed here is an error.

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
- `default_response` (object, optional) — Response used when the model IS consulted for a request but returns no send_http_response (an empty answer). Without this, such a request gets a blank 200, which looks broken. Set a sensible fallback — commonly a 404 page — so a declined request looks intentional. Same shape as filtered_response: `status` (number), `body` (string), `headers` (object of name→value). Example: `{"status":404,"headers":{"Content-Type":"text/html"},"body":"<!doctype html><title>Not Found</title><h1>404</h1>"}`

## Example Prompt

Pretend to be a sassy HTTP server on port 8080 serving cooking recipes

## Keywords

http, http server, http stack, via http, hyper

## Notes

Text bodies only: no binary response bodies, no chunked/streaming responses, and request bodies are fully buffered before the LLM sees them

### Starting this Protocol

**LLM Mode** (LLM handles all responses intelligently):
```json
{
  "type": "open_server",
  "protocol": "http",
  "instruction": "Serve a REST API for a blog. For GET /posts return a JSON array of posts; for GET /posts/{id} return that single post, inventing a plausible title and body from the id; return 404 with a JSON error object for any unknown path. Reason about the method and path of each request."
}
```

**Script Mode** (code-based deterministic responses):
```json
{
  "type": "open_server",
  "protocol": "http",
  "event_handlers": [
    {
      "event_pattern": "http_request",
      "handler": {
        "type": "script",
        "language": "python",
        "code": "import json, sys\ndata = json.load(sys.stdin)\nevent = data[\"event\"]\nif data[\"event_type_id\"] == \"http_request\":\n    if event.get(\"path\", \"/\") == \"/health\":\n        actions = [{\"type\": \"send_http_response\", \"status\": 200,\n                    \"headers\": {\"Content-Type\": \"application/json\"},\n                    \"body\": '{\"status\": \"ok\"}'}]\n    else:\n        actions = [{\"type\": \"send_http_response\", \"status\": 404,\n                    \"headers\": {\"Content-Type\": \"text/plain\"},\n                    \"body\": \"Not Found\"}]\nelse:\n    actions = []\nprint(json.dumps({\"actions\": actions}))"
      }
    }
  ]
}
```

**Static Mode** (fixed, unchanging responses):
```json
{
  "type": "open_server",
  "protocol": "http",
  "event_handlers": [
    {
      "event_pattern": "http_request",
      "handler": {
        "type": "static",
        "actions": [
          {
            "type": "send_http_response",
            "status": 200,
            "headers": {
              "Content-Type": "text/plain"
            },
            "body": "Hello World"
          }
        ]
      }
    }
  ]
}
```

## Events (`http_request`) — valid `event_pattern` values for event handlers

### `http_request`

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

## Response Actions

The action objects that answer an event — what you, a script (inside `{"actions":[…]}`) or a static handler (`handler.actions`) return.

### `send_http_response`

Respond to the HTTP request that triggered this event. This is the ONLY action that produces an HTTP response - do NOT use generic 'send_data' or 'show_message' for that. ALWAYS emit exactly one send_http_response for every request — never return an empty action list, or the client gets a blank page. HONOR THE CLIENT'S `Accept` REQUEST HEADER (in the event's headers.accept): return a `Content-Type` the client accepts, and a body in that format. If Accept is `text/html`, return HTML; `application/json`, return JSON; `text/plain`, return text. If the client asks ONLY for a type you cannot produce — most commonly an image (`Accept: image/*`, e.g. a browser fetching /favicon.ico) or any other binary type — respond `404` (or `204`) rather than sending text mislabeled as an image: the body is UTF-8 text only, so binary payloads (images, gzip, protobuf) cannot be produced at all. The response is sent complete, in one piece, as soon as you return; there is no way to stream or chunk it, to send it in parts, or to keep the request open.

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


---

# http (Client Mode)

**Mode:** Client - connects to remote servers
**Stack:** ETH>IP>TCP>HTTP
**Group:** Core
**Maturity:** Beta
**Privilege required:** None
**History:** the model is shown up to 40 earlier exchanges on the same connection with each event, within a 4 KB budget (pass `history` to change it; 0 turns it off)
**Batching:** unsupported — each event is answered as it arrives

## Description

HTTP/HTTPS client for making web requests (HTTP/1.1, HTTP/2)

## Startup Parameters

Passed as `startup_params`; a key not listed here is an error.

- `default_headers` (object, optional) — Default headers to include in all requests Example: `{"User-Agent":"NetGet/1.0","Accept":"application/json"}`

## Example Prompt

Connect to https://example.com and fetch /api/status

## Keywords

http, http client, connect to http, https

## Notes

Validated against nginx over plain HTTP/1.1. HTTPS, HTTP/2, redirects and compressed bodies are not exercised against a real server. A response body is read whole up to 8 MiB and refused past it. The browser transport (transport.rs) is exercised against NetGet's own servers only, chunked responses included.

## Events (`http_connected`, `http_response_received`) — valid `event_pattern` values for event handlers

### `http_connected`

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

### `http_response_received`

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

## Response Actions

The action objects that answer an event — what you, a script (inside `{"actions":[…]}`) or a static handler (`handler.actions`) return.

### `send_http_request`

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

### `wait_for_more`

Take no action and wait for the next response. Use when nothing should be sent yet.

Parameters: none.

```json
{
  "type": "wait_for_more"
}
```

## Client Actions

What the client can do on its own initiative, such as sending a request.

### `disconnect`

Disconnect from the HTTP server

Parameters: none.

```json
{
  "type": "disconnect"
}
```


---

## Enabled Actions

**⚠️ BEFORE CHOOSING**: Re-read the user's request. What do they want to DO?
- If they want to SERVE/HOST/PROVIDE content → use `open_server`
- If they want to CONNECT TO/FETCH FROM a remote server → use `open_client`
- The ACTION matters, not the words. "serve recipes" = server, even if user says "client"

### open_server (For SERVING content)

Use when: User wants to HOST content, SERVE data, LISTEN for connections, or PROVIDE a service. `open_server` is now enabled for the protocols above. Leave `port` out to listen on the protocol's well-known port (its **Port** line above); give one only when the user names it.

**Example for http server:**
```json
{
  "type": "open_server",
  "protocol": "http",
  "instruction": "Handle incoming requests"
}
```

### open_client (For CONNECTING to remote servers)

Use when: User wants to CONNECT TO an existing server, FETCH data, QUERY a database, or ACCESS a remote service. `open_client` is now enabled for the protocols above. `remote_addr` is the `host:port` the user names; the examples use the protocol's well-known port on this machine.

**Example for http client:**
```json
{
  "type": "open_client",
  "protocol": "http",
  "remote_addr": "127.0.0.1:80",
  "instruction": "Connect and interact"
}
```

