# HTTP Protocol E2E Tests

## Test Overview

Tests the HTTP server implementation with comprehensive coverage of HTTP features: methods, routing, headers, status
codes, JSON APIs, and error handling. Validates that the LLM can generate correct HTTP responses for various web
application scenarios.

## Test Strategy

- **Isolated test servers**: Each test spawns a separate NetGet instance with specific instructions
- **Real HTTP client**: Uses `reqwest` async HTTP client (industry standard)
- **Comprehensive scenarios**: Tests web apps, REST APIs, routing, error codes, custom headers
- **One server per test**: Each test validates a different aspect of HTTP functionality
- **Fast validation**: 10-second default timeout per request

## LLM Call Budget

- `test_http_simple_get()`: 1 LLM call (GET request)
- `test_http_json_api()`: 1 LLM call (POST request)
- `test_http_routing()`: 3 LLM calls (3 different routes: /home, /about, /unknown)
- `test_http_headers()`: 1 LLM call (GET with custom headers)
- `test_http_methods()`: 4 LLM calls (GET, POST, PUT, DELETE)
- `test_http_error_responses()`: 3 LLM calls (403, 500, 301 redirects)
- `test_http_simple_get_with_logging()`: 1 LLM call (GET with file logging)
- `failure_semantics_test.rs` (4 tests): 1 LLM call each — only the startup instruction is
  mocked, and every `http_request` is deliberately left unmatched so the mock answers HTTP
  500 and netget reports a backend failure
- `decision_tag_test.rs` (4 tests): 1 LLM call for the backend-failure test (startup only,
  the event is deliberately unmatched), 2 each for the silent-model and `default_response`
  tests (startup + one `http_request` answered with an empty action list), and 2–6 for the
  refused-action test (startup + the refused answer, which the LLM layer may retry)
- **Total: 20 LLM calls** (above 10 target, but necessary for comprehensive HTTP testing)

**Optimization Opportunity**: Could consolidate into 2-3 comprehensive servers:

1. **Basic server**: Methods, routing, simple responses (6 calls → 1 server setup + 6 requests = 7 calls)
2. **Advanced server**: Custom headers, error codes, JSON API (5 calls → 1 server setup + 5 requests = 6 calls)
3. **Logging server**: File logging test (1 call)

This would reduce to ~14 calls (same total but better organized). However, current approach provides better isolation
and clearer failure diagnosis per feature.

**Rationale for 14 calls**: HTTP is a Beta protocol and cornerstone of NetGet. Comprehensive testing of all HTTP
features (methods, headers, status codes, routing, JSON) is critical for stability. Slightly exceeding the 10-call
guideline is acceptable for such a fundamental protocol.

## Scripting Usage

❌ **Scripting Disabled** - Action-based responses only

**Rationale**: HTTP tests use diverse prompts testing different features. Action-based responses provide flexibility for
the LLM to interpret varied instructions (routing, headers, status codes, etc.). Scripting would require more complex
setup for each test scenario.

**Future Consideration**: Scripting could be valuable for high-throughput HTTP tests (e.g., load testing) where the same
endpoints are hit repeatedly. Current tests focus on functionality breadth, not throughput.

## Client Library

- **reqwest v0.11** - Async HTTP client built on hyper
- **Features used**:
    - GET, POST, PUT, DELETE methods
    - JSON request/response parsing
    - Custom header handling
    - Redirect policy control (for 301/302 testing)
    - Status code validation

**Why reqwest?**:

1. Industry-standard HTTP client for Rust
2. Excellent async/await support with Tokio
3. Built-in JSON serialization/deserialization
4. Convenient header and redirect handling
5. Same underlying hyper library as server (protocol correctness)

## Expected Runtime

- Model: qwen3-coder:30b
- Runtime: ~2-3 minutes for full test suite (10 tests, 17 LLM calls)
- Each test includes:
    - Server startup: 2-3 seconds
    - LLM response per request: 5-8 seconds
    - Network I/O and validation: <1 second per request
- Longest test: `test_http_methods()` (~40s for 4 requests)

## Failure Rate

- **Low** (~5%) - Occasional LLM response format issues
- Common failure modes:
    - LLM returns incorrect status code (e.g., 200 instead of 404)
    - LLM adds extra text to body (test checks with `contains()` to tolerate this)
    - LLM forgets to include custom headers
    - LLM misinterprets routing instructions
- Timeout failures: Rare (<1%) - usually indicates Ollama overload

## Test Cases

### 1. Simple GET (`test_http_simple_get`)

- **Prompt**: Return HTML "Hello World" for any GET request
- **Client**: `GET /`
- **Expected**: Status 200, body contains "Hello World"
- **Purpose**: Basic HTTP GET and HTML response

### 2. JSON API (`test_http_json_api`)

- **Prompt**: POST to /api/data returns 201 with JSON body
- **Client**: `POST /api/data` with JSON payload
- **Expected**:
    - Status 201 Created
    - Content-Type: application/json
    - Body: `{"status": "created", "id": 123}`
- **Purpose**: REST API with JSON request/response

### 3. Routing (`test_http_routing`)

- **Prompt**: Different responses for /home, /about, and 404 for others
- **Client**:
    - `GET /home` → expect "Welcome" or "Home"
    - `GET /about` → expect "About"
    - `GET /unknown` → expect 404 "Not Found"
- **Expected**: Correct routing and 404 handling
- **Purpose**: Path-based routing and error responses

### 4. Custom Headers (`test_http_headers`)

- **Prompt**: Return custom headers X-API-Version and X-Custom
- **Client**: `GET /api`
- **Expected**:
    - Status 200
    - Header: `X-API-Version: 1.0`
    - Header: `X-Custom: test-value`
    - Body contains "API Response"
- **Purpose**: Custom response header generation

### 5. HTTP Methods (`test_http_methods`)

- **Prompt**: Different responses for GET, POST, PUT, DELETE
- **Client**:
    - `GET /` → expect "GET Response"
    - `POST /` → expect "POST Response"
    - `PUT /` → expect "PUT Response"
    - `DELETE /` → expect "DELETE Response"
- **Expected**: Method-based routing
- **Purpose**: HTTP method handling (REST verbs)

### 6. Error Responses (`test_http_error_responses`)

- **Prompt**: Return 403, 500, and 301 for different paths
- **Client** (with no-redirect policy):
    - `GET /forbidden` → expect 403 with "Access Denied"
    - `GET /error` → expect 500 with "Server Error"
    - `GET /redirect` → expect 301 with Location: /home
- **Expected**: Various status codes and redirect headers
- **Purpose**: Error handling, status codes, redirects

### 7. Access Logging (`test_http_simple_get_with_logging`)

- **Prompt**: Serve HTML and log requests to file "access_logs"
- **Client**: `GET /`
- **Expected**:
    - Status 200, body "Hello World"
    - Log file created: `netget_access_logs_<timestamp>_s<server id>.log`, in the process's
      working directory — the repository root, shared by the whole run. **Eleven tests use the
      output name `access_logs`, so there is no such thing as "the" access log file.** This
      test snapshots the matching files before it starts and considers only what appeared
      since; taking the first match from an unordered `read_dir` made it fail against a stale
      log the WHOIS suite had left behind, which presents as a regression in HTTP. It also
      cleans up from a `Drop` guard rather than at the end of the happy path, because a run
      that left its file behind gave the next run one more stale candidate — the failure was
      self-perpetuating, which is what made it look deterministic.
    - Log file contains at least one line
- **Purpose**: File I/O action, logging capability
- **Note**: Lenient validation - LLM may interpret logging differently

### 8-10. Failure semantics (`failure_semantics_test.rs`)

`AGENTS.md` names HTTP as the reference other protocols copy for answering a peer on LLM
failure, and nothing tested it until these. All three point the server at a mock that
answers the startup instruction and nothing else, so every `http_request` event is a
backend failure.

- `test_http_answers_500_when_the_llm_fails` — a `GET` gets **500** promptly (not silence,
  and not 503: 503 + `Retry-After` is reserved for an *overloaded* backend so a client can
  tell a retryable failure from a permanent one). The body is asserted to name `netget` and
  to contain none of the backend URL, model name, retry text or `Caused by` chain — the
  leak that hit ~25 protocols at once.
- `test_http_failure_body_is_a_category_on_post_too` — the same through a body-carrying
  method.
- `test_http_refuses_an_oversized_request_body` — a body one byte over
  `http_common::MAX_REQUEST_BODY_BYTES` (8 MiB) is answered **413**, and `expect_calls(1)`
  on the startup rule proves it cost **no** LLM call: had the request reached the model,
  the unmatched event would be a second recorded call and `verify_mocks` would fail.

### 11. Decision tags (`decision_tag_test.rs`)

Every request ends in exactly one `decision=` line, and these four tell the ways a request
can end without a model-written response apart, on the wire and in the log.

- `test_http_backend_failure_is_tagged_fail_closed` — the mock answers the startup
  instruction and nothing else, so `call_llm` returns `Err`. Asserts `500` on the wire and
  `decision=fail_closed_llm_error` in the log, **and** that no silent-model line appears: a
  dead backend must not read as the model choosing to say nothing.
- `test_http_model_silence_fails_closed_with_500` — the model *is* reached and answers
  `{"actions": []}` to a `POST /todos`. Asserts `500` with exactly the category body and
  `decision=fail_closed_no_action`. This is the regression test for the empty `200` a silent
  model used to get.
- `test_http_refused_action_fails_closed_with_500` — the model answers a
  `send_http_response` with no `status`, which the executor refuses. Asserts `500`, that the
  refused body never reaches the peer, and `decision=fail_closed_bad_action`.
- `test_http_model_silence_uses_the_configured_default_response` — the same silent model on
  a server started with `default_response` gets that response (`404 nothing here`) and
  `decision=model_silent fallback=default_response`.

## Known Issues

### 1. LLM Response Variability

The LLM may add extra text, formatting, or explanations beyond what's requested. Tests use `contains()` checks rather
than exact matching.

**Example**: Prompt says return "Welcome Home", LLM might return "Welcome Home! We're glad you're here."

**Mitigation**: Tests check for key phrases rather than exact strings.

### 2. Header Case Sensitivity

HTTP headers are case-insensitive, but LLM may use different casing:

- Prompt: `X-API-Version`, LLM might return `x-api-version` or `X-Api-Version`

**Mitigation**: Tests use lowercase header lookup (`headers.get("x-api-version")`)

### 3. Logging Test Leniency

`test_http_simple_get_with_logging` doesn't fail if log file isn't created. This is intentional - the LLM might
interpret "log to file" differently (e.g., log to stderr, use show_message, etc.).

**Rationale**: File logging is a secondary feature. Core HTTP functionality is more critical.

**Future Improvement**: Make logging requirements more explicit in prompt.

### 4. No Connection Cleanup Validation

Tests don't verify that HTTP connections are properly closed. They just stop the server process, which forcibly closes
all connections.

**Future Improvement**: Add test for Connection: close header handling.

### 5. No Request Body Validation for GET

Tests don't verify that GET requests have empty bodies (best practice). LLM might accidentally set a body on GET
responses.

**Impact**: Minimal - HTTP clients ignore GET response bodies anyway.

## Performance Notes

### Why reqwest Over Raw Sockets?

Original consideration was to use raw TCP sockets like TCP tests. Reasons for choosing reqwest:

1. **HTTP parsing complexity**: HTTP protocol is complex (headers, chunking, keep-alive)
2. **Faster test development**: reqwest handles protocol details
3. **Better error messages**: reqwest provides clear HTTP errors
4. **Industry standard**: Tests use same client that users would use
5. **JSON support**: Built-in JSON serialization saves test code

**Trade-off**: Slightly slower than raw sockets due to client overhead, but still fast enough (~5-10ms per request).

### Test Isolation vs. Consolidation

Current approach: 7 separate servers, 14 LLM calls

**Pros**:

- Clear failure isolation (if routing fails, only routing test fails)
- Easy to understand what each test validates
- Parallel test execution spreads load across tests

**Cons**:

- Slightly more LLM calls (7 server startups instead of 2-3)
- Longer total runtime (more server startup overhead)

**Verdict**: Isolation is worth the cost for a Beta protocol. Clear diagnostics are critical for stability.

### Timeout Strategy

Default 10-second timeout per request provides good balance:

- Allows for slow LLM responses (5-8s typical)
- Catches hung connections quickly
- Fails fast on misconfigured servers

## Future Enhancements

### Test Coverage Gaps

1. **Large request bodies**: covered by `test_http_refuses_an_oversized_request_body` for
   the *refusal* path only — there is no test of a large body the server accepts
2. **Chunked encoding**: No tests for chunked transfer encoding
3. **Keep-alive**: No tests verifying multiple requests on same TCP connection
4. **Concurrent requests**: No tests for multiple simultaneous clients
5. **Binary responses**: No tests for image/file downloads
6. **Query parameters**: No tests for URL query string parsing
7. **Request headers**: No tests verifying LLM sees all request headers
8. **WebSocket upgrade**: No tests for Upgrade header (out of scope)
9. **HTTP/2**: not tested from *this* suite — HTTP/2 is implemented
   (`src/server/http2/`) and has its own tests in `tests/server/http2/`. The h2c upgrade
   path in `src/server/http/mod.rs` is what nothing covers.
10. **HTTPS/TLS**: no tests here. TLS *is* implemented (`tls_enabled` and the rest of
    `tls_cert_manager`'s startup parameters); it is the coverage that is missing, not the
    feature.

### Consolidation Opportunity

All tests could be consolidated into 2 comprehensive servers:

**Server 1 - Basic HTTP**:

```
listen on port {} via http
GET / → "Hello World"
POST / → "POST Response"
PUT / → "PUT Response"
DELETE / → "DELETE Response"
GET /home → "Welcome Home"
GET /about → "About Us"
GET /unknown → 404 "Not Found"
```

7 requests = 1 startup + 7 calls = 8 total (vs. current 11 calls for these tests)

**Server 2 - Advanced HTTP**:

```
listen on port {} via http
POST /api/data → 201 with JSON {"status": "created", "id": 123}
GET /api → 200 with X-API-Version: 1.0, X-Custom: test-value
GET /forbidden → 403 "Access Denied"
GET /error → 500 "Server Error"
GET /redirect → 301 Location: /home
```

5 requests = 1 startup + 5 calls = 6 total (vs. current 6 calls for these tests)

**Total: 14 calls** (same as current, but better organized into comprehensive servers)

### Potential New Tests

1. **Stress test**: 100 concurrent requests to same endpoint (with scripting)
2. **File upload**: Multipart form data upload
3. **Range requests**: Partial content with 206 status
4. **Caching headers**: ETag, Cache-Control, If-None-Match
5. **CORS**: Cross-origin headers and preflight requests
6. **Compression**: Accept-Encoding: gzip, Content-Encoding: gzip
7. **Authentication**: Basic auth, Bearer tokens
8. **Cookie handling**: Set-Cookie and Cookie headers

## Comparison with Other Protocol Tests

| Protocol | Tests | LLM Calls | Runtime  | Rationale                                        |
|----------|-------|-----------|----------|--------------------------------------------------|
| TCP      | 5     | 5         | ~60s     | Core protocol, raw bytes                         |
| UDP      | 1     | 1         | ~10s     | Minimal (protocols like DNS tested separately)   |
| **HTTP** | **10** | **17**   | **2-3m** | **Beta protocol, comprehensive feature testing** |
| DNS      | 2     | 2         | ~25s     | Scripting enabled, fast                          |
| SSH      | 3     | ~8-10     | ~2m      | Authentication, shell, commands                  |

HTTP has the highest LLM call count because it's:

1. **Beta status** - Production-ready, needs thorough testing
2. **Widely used** - Most common protocol for NetGet users
3. **Feature-rich** - Methods, headers, status codes, routing, JSON, etc.
4. **Foundation for APIs** - Many use cases depend on HTTP correctness

## References

- [RFC 7230: HTTP/1.1 Message Syntax and Routing](https://datatracker.ietf.org/doc/html/rfc7230)
- [RFC 7231: HTTP/1.1 Semantics and Content](https://datatracker.ietf.org/doc/html/rfc7231)
- [reqwest Documentation](https://docs.rs/reqwest/latest/reqwest/)
- [Hyper Documentation](https://docs.rs/hyper/latest/hyper/)
- Related tests: TCP (raw), HTTP Proxy (proxy protocol)
