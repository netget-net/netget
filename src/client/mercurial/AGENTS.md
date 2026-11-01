# Mercurial HTTP Client Implementation Plan

## ⚠️ Status: NOT IMPLEMENTED (planning document)

**There is no Mercurial client.** `src/client/mercurial/` contains this file and
nothing else: no `mod.rs`, no `actions.rs`, no `pub mod mercurial` in
`src/client/mod.rs`, and no entry in `src/protocol/client_registry.rs`. Everything
below is a design sketch written in the present tense, including the code samples
and the "Implementation Details" sections — none of it exists. Read it as a plan,
not as documentation of behaviour. (`src/client/svn/AGENTS.md` is the same kind of
document and says so at the top; this one did not, which is why the banner is here.)

The Mercurial **server** (`src/server/mercurial/`) is real and is what the
"Evidence from Server Implementation" section below quotes.

## Overview

Mercurial HTTP client implementing the Mercurial wire protocol over HTTP (used by `hg clone http://...` and `hg pull`).
The LLM controls repository queries, branch inspection, bookmark listing, and bundle retrieval. This client complements
the existing **Mercurial server** implementation in `src/server/mercurial/`.

## Feasibility Correction

**CLIENT_PROTOCOL_FEASIBILITY.md Status**: ❌ Marked as "Unfeasible" with recommendation to use command wrappers

**Actual Status**: 🟡 **Medium Complexity** - Fully feasible with pure Rust implementation

**Why the Discrepancy?**

The feasibility document focuses on:
- `hglib` / `tokio-hglib` - Command server protocol (requires `hg` binary)
- Full Mercurial wire protocol implementation (complex)

**What We Actually Need:**

The Mercurial **HTTP wire protocol** is much simpler:
- HTTP-based (use `reqwest`)
- Text-based responses (newline/tab-separated)
- Request-response model (no complex state machine)
- No need for `hg` binary
- Server implementation in `src/server/mercurial/` proves the protocol is straightforward

**Evidence from Server Implementation:**

```rust
// From src/server/mercurial/mod.rs
// Simple HTTP GET/POST handlers with text responses
"capabilities" => build_text_response(StatusCode::OK, &capabilities),
"heads" => build_text_response(StatusCode::OK, &heads),
"branchmap" => build_text_response(StatusCode::OK, &response_text),
```

The server shows that Mercurial HTTP protocol is just:
1. HTTP GET/POST requests with `?cmd=<command>` query parameter
2. Text responses (newline-separated, tab-separated)
3. Optional binary bundles (can be treated as opaque bytes for MVP)

**Conclusion**: Mercurial client is **Medium complexity** - similar to HTTP or Redis client, NOT unfeasible.

## Protocol Version

- **Mercurial HTTP wire protocol**: Same protocol used by `hg clone http://...` and `hg pull`
- **Transport**: HTTP/1.1 GET and POST
- **Commands** (via `?cmd=<command>` query parameter):
    - `GET /?cmd=capabilities` - Query server capabilities
    - `GET /?cmd=heads` - Get repository heads (tip changesets)
    - `GET /?cmd=branchmap` - Get branch to node ID mappings
    - `GET /?cmd=listkeys&namespace=<ns>` - List keys (bookmarks, tags, phases)
    - `POST /?cmd=getbundle` - Retrieve bundle (clone/pull)
- **Format**: Text-based responses, some binary bundles

## Library Choices

### Core Dependencies

- **reqwest** (async HTTP client)
    - Chosen for: Standard NetGet HTTP client, proven reliability
    - Used for: All HTTP operations (GET/POST to Mercurial server)
- **urlencoding** - URL encoding for query parameters
    - Used for: Encoding repository names and namespaces
- **No hglib/Mercurial bindings** - Pure HTTP client implementation
    - Rationale: Protocol is simple enough, no need for `hg` binary

### Why No hg Libraries?

- **hglib/tokio-hglib** - Command server clients (require `hg` binary installed)
- **No native Rust client libraries** - Don't exist in ecosystem
- **HTTP implementation** provides:
    - No external dependencies (`hg` binary not needed)
    - Full LLM control over protocol requests
    - Works with any Mercurial HTTP server (including NetGet's own)
    - Cross-platform compatibility

## Architecture Decisions

### HTTP Request-Response Model

**No Persistent Connection** - Each operation is an independent HTTP request:

1. **Connect**: Query server capabilities (GET `?cmd=capabilities`)
2. **Operation Loop**: LLM decides next operation based on results
3. **Cleanup**: No connection state to manage

**Why Request-Response**:

- Mercurial HTTP protocol is stateless
- Each command is self-contained
- No session management needed
- Simpler than TCP-based protocols

### LLM Control Points

**Complete Repository Discovery** - LLM controls all Mercurial queries:

1. **Capabilities** (`GET /?cmd=capabilities`):
    - Client: "What can this server do?"
    - LLM: Parse capabilities list, decide what to query next

2. **Heads** (`GET /?cmd=heads`):
    - Client: "What are the repository tip changesets?"
    - LLM: Parse node IDs, decide if we need branches/bookmarks

3. **Branch Map** (`GET /?cmd=branchmap`):
    - Client: "What branches exist?"
    - LLM: Parse branch mappings, identify branches of interest

4. **List Keys** (`GET /?cmd=listkeys&namespace=...`):
    - Client: "List bookmarks/tags/phases"
    - LLM: Parse key-value pairs, decide if we need bundle

5. **Get Bundle** (`POST /?cmd=getbundle`):
    - Client: "Download changesets"
    - LLM: Construct bundle parameters, handle bundle data

6. **Error Handling**:
    - Repository not found (404)
    - Server errors (500)
    - LLM decides retry/abort strategy

### Action-Based Requests

**Available Actions**:

```json
{
  "type": "hg_query_capabilities",
  "repository": "/my-repo"
}
```

```json
{
  "type": "hg_query_heads",
  "repository": "/my-repo"
}
```

```json
{
  "type": "hg_query_branchmap",
  "repository": "/my-repo"
}
```

```json
{
  "type": "hg_query_listkeys",
  "repository": "/my-repo",
  "namespace": "bookmarks"
}
```

```json
{
  "type": "hg_request_bundle",
  "repository": "/my-repo",
  "parameters": {
    "heads": ["abc123..."],
    "common": []
  }
}
```

### Response Parsing

**Capabilities**: Newline-separated capability strings

```
batch
branchmap
getbundle
httpheader=1024
known
lookup
```

**Parsing**:
```rust
fn parse_capabilities(response: &str) -> Vec<String> {
    response.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|s| s.to_string())
        .collect()
}
```

**Heads**: Newline-separated node IDs (40-char hex)

```
a1b2c3d4e5f6789012345678901234567890abcd
1234567890abcdef1234567890abcdef12345678
```

**Parsing**:
```rust
fn parse_heads(response: &str) -> Vec<String> {
    response.lines()
        .filter(|line| line.len() == 40 && line.chars().all(|c| c.is_ascii_hexdigit()))
        .map(|s| s.to_string())
        .collect()
}
```

**Branchmap**: Format: `<branch> <node1> <node2>...`

```
default abc123...
stable def456... 789abc...
```

**Parsing**:
```rust
fn parse_branchmap(response: &str) -> HashMap<String, Vec<String>> {
    response.lines()
        .filter_map(|line| {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.is_empty() {
                return None;
            }
            let branch = parts[0].to_string();
            let nodes = parts[1..].iter().map(|s| s.to_string()).collect();
            Some((branch, nodes))
        })
        .collect()
}
```

**Listkeys**: Tab-separated key-value pairs

```
master\tabc123...
develop\tdef456...
```

**Parsing**:
```rust
fn parse_listkeys(response: &str) -> HashMap<String, String> {
    response.lines()
        .filter_map(|line| {
            let parts: Vec<&str> = line.split('\t').collect();
            if parts.len() == 2 {
                Some((parts[0].to_string(), parts[1].to_string()))
            } else {
                None
            }
        })
        .collect()
}
```

**Bundles**: Binary changegroup format (opaque bytes for MVP)

```rust
// For MVP: Just store bundle size and type
fn handle_bundle(response: Bytes) -> BundleInfo {
    BundleInfo {
        size: response.len(),
        data: response, // Store as opaque bytes
    }
}
```

### State Management

**Client State**:

```rust
pub struct MercurialClientInstance {
    server_url: String,                      // e.g., "http://localhost:8000/my-repo"
    capabilities: Vec<String>,                // Cached from initial query
    heads: Vec<String>,                       // Cached heads (40-char hex node IDs)
    branches: HashMap<String, Vec<String>>,   // Cached branchmap
    bookmarks: HashMap<String, String>,       // Cached bookmarks
    tags: HashMap<String, String>,            // Cached tags
}
```

**Connection Lifecycle**:

1. Open client → Parse server URL
2. Query capabilities → Cache result
3. LLM-driven operations (heads, branches, listkeys, bundle)
4. Each operation updates cached state
5. Close client → Cleanup

## State Machine

**Simple Sequential Operations** - No complex state:

```
Connected → Query Capabilities → [LLM Decides Next Operation] → Query Heads/Branches/Listkeys/Bundle → [Repeat] → Disconnect
```

Unlike TCP-based protocols, no Idle/Processing/Accumulating states needed - each HTTP request is atomic.

## Implementation Hardships

### 1. Bundle Format Complexity

**Challenge**: Mercurial bundle format (changegroup) is complex binary format

**Bundle Types**:
- `HG10UN` - Uncompressed
- `HG10GZ` - Gzip compressed
- `HG10BZ` - Bzip2 compressed

**Bundle Structure** (simplified):
```
[Bundle Header]
[Changegroup Header]
[Changeset Data] (multiple chunks)
[Manifest Data] (multiple chunks)
[File Data] (multiple chunks per file)
```

**MVP Solution**: Treat bundles as opaque binary data
- Download bundle bytes
- Report bundle size to LLM
- Don't parse internal structure (defer to future enhancement)

**Full Implementation** (future):
- Parse changegroup format
- Extract changeset metadata (author, date, message)
- Extract file contents
- Build revision graph

**Resources**:
- [Changegroup Format](https://www.mercurial-scm.org/wiki/ChangeGroupFormat)
- Server implementation provides bundle generation code (reverse-engineer)

### 2. URL and Repository Path Handling

**Challenge**: Repository can be specified multiple ways

**URL Formats**:
- `http://localhost:8000/` - Default repository
- `http://localhost:8000/my-repo` - Named repository
- `http://example.com:8080/nested/path/repo` - Nested path

**Query String**:
- `?cmd=capabilities` - Append to base URL
- `?cmd=listkeys&namespace=bookmarks` - Multiple parameters

**Solution**:
```rust
fn build_request_url(base_url: &str, command: &str, params: &[(&str, &str)]) -> String {
    let mut url = base_url.trim_end_matches('/').to_string();
    url.push_str("?cmd=");
    url.push_str(command);

    for (key, value) in params {
        url.push('&');
        url.push_str(key);
        url.push('=');
        url.push_str(&urlencoding::encode(value));
    }

    url
}
```

**Edge Cases**:
- Empty repository name → Use "default"
- Trailing slashes → Normalize
- URL encoding for special characters in paths

### 3. Error Response Handling

**Challenge**: Mercurial errors can be HTTP errors or text responses

**HTTP Errors**:
- `404 Not Found` - Repository doesn't exist
- `403 Forbidden` - Access denied
- `500 Internal Server Error` - Server error

**Text Errors** (in response body):
```
Error: Repository 'nonexistent' not found
```

**Solution**: Check both HTTP status and response body
```rust
async fn execute_hg_request(url: &str) -> Result<String> {
    let response = http_client.get(url).send().await?;

    if !response.status().is_success() {
        return Err(anyhow!("HTTP error: {}", response.status()));
    }

    let text = response.text().await?;

    if text.starts_with("Error:") {
        return Err(anyhow!("Mercurial error: {}", text));
    }

    Ok(text)
}
```

### 4. LLM Interpretation of Node IDs

**Challenge**: LLM must generate/parse 40-character hex node IDs

**Node ID Format**: `a1b2c3d4e5f6789012345678901234567890abcd` (40 hex chars)

**LLM Difficulties**:
- Generating valid hex strings (might include non-hex characters)
- Recognizing abbreviated node IDs (12-char short form)
- Understanding node ID relationships (parent/child)

**Solution**: Strict validation in action execution
```rust
fn validate_node_id(node_id: &str) -> Result<()> {
    if node_id.len() != 40 {
        return Err(anyhow!("Node ID must be 40 characters, got {}", node_id.len()));
    }

    if !node_id.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(anyhow!("Node ID must contain only hex characters"));
    }

    Ok(())
}
```

**LLM Guidance**: Provide clear examples in action definitions
```json
{
  "type": "hg_request_bundle",
  "parameters": {
    "heads": ["a1b2c3d4e5f6789012345678901234567890abcd"],  // EXACTLY 40 hex chars
    "common": []
  }
}
```

### 5. Sequential Operation Dependencies

**Challenge**: Some operations depend on previous results

**Dependency Chain**:
1. Must query capabilities first (to know what server supports)
2. Must get heads before requesting bundle (to know what to request)
3. May need branchmap to understand repository structure

**Problem**: LLM needs to understand operation ordering

**Solution**: Event-driven architecture with clear dependencies
```rust
// Connected event → LLM queries capabilities
Event::new("hg_client_connected", json!({
    "server_url": url
}))

// Capabilities received → LLM decides next operation
Event::new("hg_capabilities_received", json!({
    "capabilities": ["batch", "getbundle", ...]
}))

// Heads received → LLM can now request bundle
Event::new("hg_heads_received", json!({
    "heads": ["abc123..."]
}))
```

**LLM Prompt Guidance**:
```
You are connected to a Mercurial server. Available operations:
1. Query capabilities (always do this first)
2. Query heads (requires capabilities)
3. Query branchmap (requires capabilities)
4. Request bundle (requires heads)

Choose operations in logical order based on your goal.
```

### 6. Bundle Request Parameters

**Challenge**: `getbundle` requires complex parameters

**Bundle Parameters** (from Mercurial protocol):
- `heads` - List of head node IDs to fetch
- `common` - List of node IDs already possessed (optimization)
- `bundlecaps` - Client bundle capabilities
- `listkeys` - Namespaces to include in bundle
- `cg` - Include changegroup (boolean)
- `cbattempted` - Clonebundles attempted (boolean)

**LLM Challenge**: Must construct correct parameter structure

**Solution**: Provide simple action interface for common cases
```json
{
  "type": "hg_request_bundle",
  "repository": "/my-repo",
  "parameters": {
    "heads": ["abc123..."],  // Required
    "common": []             // Optional (empty = full clone)
  }
}
```

**Advanced Parameters** (future):
```json
{
  "type": "hg_request_bundle_advanced",
  "repository": "/my-repo",
  "parameters": {
    "heads": ["abc123..."],
    "common": ["def456..."],
    "bundlecaps": ["HG10GZ"],
    "listkeys": ["bookmarks", "phases"]
  }
}
```

### 7. Testing Without Real Mercurial Server

**Challenge**: Tests need to work without external dependencies

**Solution**: Mock LLM responses (no real Mercurial server needed)

**Mock Test Pattern**:
```rust
let config = NetGetConfig::new("Query capabilities")
    .with_mock(|mock| {
        mock
            .on_event("hg_client_connected")
            .respond_with_actions(json!([
                {
                    "type": "hg_query_capabilities",
                    "repository": "/test-repo"
                }
            ]))
            .expect_calls(1)
            .and()
    });
```

**Challenge**: How to test actual HTTP requests?

**Solution**: Use NetGet's own Mercurial server for E2E tests
```rust
// Start NetGet Mercurial server
server.run_command("listen on port {AVAILABLE_PORT} via mercurial").await?;

// Connect client to server
server.run_command("open client mercurial http://localhost:{AVAILABLE_PORT}/test-repo").await?;
```

**Advantage**: Tests both client and server simultaneously

### 8. Authentication Support

**Challenge**: Some Mercurial servers require HTTP Basic Auth

**Authentication Types**:
- None (public repositories)
- HTTP Basic Auth (username/password)
- Token-based auth (rare)

**MVP**: No authentication (public repositories only)

**Future Enhancement**: Add HTTP Basic Auth
```rust
let http_client = reqwest::Client::builder()
    .basic_auth(username, Some(password))
    .build()?;
```

**LLM Action**:
```json
{
  "type": "hg_set_credentials",
  "username": "user",
  "password": "pass"
}
```

### 9. Large Bundle Downloads

**Challenge**: Bundles can be very large (GB for large repositories)

**Problems**:
- Memory consumption (loading entire bundle in RAM)
- Timeout issues (reqwest default timeout)
- Progress reporting (LLM can't see download progress)

**MVP Solution**: Small timeout, in-memory buffers
```rust
let http_client = reqwest::Client::builder()
    .timeout(Duration::from_secs(300))  // 5 minute timeout
    .build()?;

let response = http_client.get(url).send().await?;
let bundle_bytes = response.bytes().await?;  // Load in memory
```

**Future Enhancement**: Streaming to disk
```rust
let mut file = tokio::fs::File::create("bundle.hg").await?;
let mut stream = response.bytes_stream();

while let Some(chunk) = stream.next().await {
    let chunk = chunk?;
    file.write_all(&chunk).await?;

    // Send progress event to LLM
    send_event("bundle_download_progress", json!({
        "bytes_downloaded": total_downloaded,
        "total_size": content_length
    }));
}
```

### 10. Protocol Version Compatibility

**Challenge**: Mercurial protocol has evolved over versions

**Protocol Versions**:
- HTTP wire protocol v1 (original)
- HTTP wire protocol v2 (new, not widely adopted)

**Capabilities Indicate Version**:
- `httpheader=1024` - HTTP header size limit
- `httppostargs` - POST arguments support
- `unbundle=HG10GZ,HG10BZ,HG10UN` - Bundle formats

**MVP**: Support only v1 (widely used, simple)

**Future**: Add v2 support if needed
```rust
fn detect_protocol_version(capabilities: &[String]) -> ProtocolVersion {
    if capabilities.contains(&"exp-http-v2-0001".to_string()) {
        ProtocolVersion::V2
    } else {
        ProtocolVersion::V1
    }
}
```

## Example Prompts and Responses

### Startup

```
open client mercurial http://localhost:8000/hello-world

Query server capabilities, list all branches and bookmarks, then report what you find.
```

### Network Event (Connected)

**Sent to LLM**:

```json
{
  "event_type": "hg_client_connected",
  "data": {
    "server_url": "http://localhost:8000/hello-world",
    "capabilities": ["batch", "branchmap", "getbundle", "httpheader=1024", "known", "lookup"]
  }
}
```

**LLM Response**:

```json
{
  "actions": [
    {
      "type": "notify_operator",
      "message": "Connected to Mercurial server. Server supports: batch, branchmap, getbundle, known, lookup"
    },
    {
      "type": "hg_query_heads",
      "repository": "/hello-world"
    }
  ]
}
```

### Network Event (Heads Received)

**Sent to LLM**:

```json
{
  "event_type": "hg_heads_received",
  "data": {
    "heads": ["1234567890abcdef1234567890abcdef12345678"]
  }
}
```

**LLM Response**:

```json
{
  "actions": [
    {
      "type": "notify_operator",
      "message": "Repository has 1 head: 1234567890abcdef1234567890abcdef12345678"
    },
    {
      "type": "hg_query_branchmap",
      "repository": "/hello-world"
    }
  ]
}
```

### Network Event (Branchmap Received)

**Sent to LLM**:

```json
{
  "event_type": "hg_branchmap_received",
  "data": {
    "branches": {
      "default": ["1234567890abcdef1234567890abcdef12345678"],
      "stable": ["abcdef1234567890abcdef1234567890abcdef12"]
    }
  }
}
```

**LLM Response**:

```json
{
  "actions": [
    {
      "type": "notify_operator",
      "message": "Found 2 branches: default, stable"
    },
    {
      "type": "hg_query_listkeys",
      "repository": "/hello-world",
      "namespace": "bookmarks"
    }
  ]
}
```

### Network Event (Listkeys Received)

**Sent to LLM**:

```json
{
  "event_type": "hg_listkeys_received",
  "data": {
    "namespace": "bookmarks",
    "keys": {
      "master": "1234567890abcdef1234567890abcdef12345678",
      "develop": "abcdef1234567890abcdef1234567890abcdef12"
    }
  }
}
```

**LLM Response**:

```json
{
  "actions": [
    {
      "type": "notify_operator",
      "message": "Found bookmarks: master (1234...), develop (abcd...)"
    },
    {
      "type": "hg_request_bundle",
      "repository": "/hello-world",
      "parameters": {
        "heads": ["1234567890abcdef1234567890abcdef12345678"],
        "common": []
      }
    }
  ]
}
```

### Network Event (Bundle Received)

**Sent to LLM**:

```json
{
  "event_type": "hg_bundle_received",
  "data": {
    "bundle_size": 4096,
    "bundle_type": "HG10UN"
  }
}
```

**LLM Response**:

```json
{
  "actions": [
    {
      "type": "notify_operator",
      "message": "Received bundle: 4096 bytes (uncompressed). Repository successfully cloned."
    },
    {
      "type": "disconnect"
    }
  ]
}
```

## Use Cases

### 1. Repository Discovery

```
open client mercurial http://unknown-server.com/

Probe the server to discover available repositories and their structure.
```

**LLM Strategy**:
1. Query capabilities
2. Try default repository path (`/`)
3. Query heads, branches, bookmarks
4. Report findings

### 2. Clone Operation

```
open client mercurial http://example.com:8000/my-project

Clone the entire repository by requesting all changesets.
```

**LLM Strategy**:
1. Query capabilities
2. Get heads (what to clone)
3. Request bundle with heads, common=[] (full clone)
4. Save bundle data

### 3. Testing NetGet Mercurial Server

```
listen on port 8000 via mercurial

In another session:

open client mercurial http://localhost:8000/test-repo

Test the server by querying capabilities, heads, and branches.
```

**LLM Strategy**:
1. Connect to localhost server
2. Verify capabilities match expected
3. Test all protocol operations
4. Report any errors

### 4. Honeypot Reconnaissance

```
open client mercurial http://suspicious-server.com/admin-secrets

Probe the server without downloading anything. Log all information.
```

**LLM Strategy**:
1. Query capabilities (what they support)
2. Query heads (repository exists?)
3. Query branchmap (repository structure)
4. Query bookmarks (interesting refs?)
5. DO NOT request bundle (avoid downloading data)
6. Report findings for analysis

### 5. Branch Comparison

```
open client mercurial http://prod-server.com/app
open client mercurial http://staging-server.com/app

Compare branches between production and staging.
```

**LLM Strategy**:
1. Query branchmap on both servers
2. Compare branch names
3. Compare head node IDs
4. Report differences

## Testing Strategy

### E2E Tests with Mocks

**Test 1: Basic Connection and Capabilities**

```rust
#[tokio::test]
async fn test_mercurial_client_capabilities_with_mocks() -> Result<()> {
    let config = NetGetConfig::new("Query server capabilities")
        .with_mock(|mock| {
            mock
                .on_event("hg_client_connected")
                .respond_with_actions(json!([
                    {
                        "type": "hg_query_capabilities",
                        "repository": "/test-repo"
                    }
                ]))
                .expect_calls(1)
                .and()
        })
        .with_mock(|mock| {
            mock
                .on_event("hg_capabilities_received")
                .and_event_data_contains("capabilities", "batch")
                .respond_with_actions(json!([
                    {
                        "type": "disconnect"
                    }
                ]))
                .expect_calls(1)
                .and()
        });

    let mut server = config.build_test_server().await?;

    // Start Mercurial server
    server.run_command("listen on port {AVAILABLE_PORT} via mercurial").await?;

    // Connect client
    server.run_command("open client mercurial http://localhost:{AVAILABLE_PORT}/test-repo").await?;

    // Verify mocks
    server.verify_mocks().await?;

    Ok(())
}
```

**Expected LLM Calls**: 2 (connected, capabilities received)

**Test 2: Full Repository Query**

```rust
#[tokio::test]
async fn test_mercurial_client_full_query_with_mocks() -> Result<()> {
    let config = NetGetConfig::new("Query everything about repository")
        .with_mock(|mock| {
            mock
                .on_event("hg_client_connected")
                .respond_with_actions(json!([
                    {"type": "hg_query_heads", "repository": "/test"}
                ]))
                .expect_calls(1)
                .and()
        })
        .with_mock(|mock| {
            mock
                .on_event("hg_heads_received")
                .respond_with_actions(json!([
                    {"type": "hg_query_branchmap", "repository": "/test"}
                ]))
                .expect_calls(1)
                .and()
        })
        .with_mock(|mock| {
            mock
                .on_event("hg_branchmap_received")
                .respond_with_actions(json!([
                    {"type": "hg_query_listkeys", "repository": "/test", "namespace": "bookmarks"}
                ]))
                .expect_calls(1)
                .and()
        })
        .with_mock(|mock| {
            mock
                .on_event("hg_listkeys_received")
                .respond_with_actions(json!([
                    {"type": "disconnect"}
                ]))
                .expect_calls(1)
                .and()
        });

    let mut server = config.build_test_server().await?;

    server.run_command("listen on port {AVAILABLE_PORT} via mercurial").await?;
    server.run_command("open client mercurial http://localhost:{AVAILABLE_PORT}/test").await?;

    server.verify_mocks().await?;

    Ok(())
}
```

**Expected LLM Calls**: 4 (connected, heads, branchmap, listkeys)

### LLM Call Budget

**Target**: < 5 LLM calls per test suite

**Breakdown**:
1. Connected (1 call)
2. Capabilities/Heads/Branchmap/Listkeys (1-4 calls depending on test)
3. Bundle request (optional, 1 call)

**Total**: 2-6 calls maximum per test

### Manual Testing

**Start NetGet Mercurial Server**:
```bash
./cargo-isolated.sh run --no-default-features --features mercurial
> listen on port 8000 via mercurial
```

**Connect Mercurial Client**:
```bash
# In same or different NetGet instance
> open client mercurial http://localhost:8000/test-repo
> Query capabilities, heads, and branches
```

**Verify with Real Mercurial Client** (optional):
```bash
# Compare with real hg client
hg clone http://localhost:8000/test-repo
```

## References

- [Mercurial Wire Protocol](https://www.mercurial-scm.org/wiki/WireProtocol)
- [HttpCommandProtocol](https://wiki.mercurial-scm.org/HttpCommandProtocol)
- [Mercurial Internals](https://hg.schlittermann.de/hg/once/help/internals.wireprotocol)
- [Changegroup Format](https://www.mercurial-scm.org/wiki/ChangeGroupFormat)
- **NetGet Mercurial Server**: `src/server/mercurial/` (reference implementation)

## Key Design Principles

1. **HTTP-First** - Use standard `reqwest`, no custom protocol handling
2. **Text-Based Parsing** - Simple line-based parsing, defer binary formats to future
3. **LLM-Driven Operations** - Each operation is an LLM decision based on previous results
4. **Stateless Requests** - Each HTTP request is independent, no complex state machine
5. **Server Complementary** - Client can test NetGet's own Mercurial server

## Future Enhancements

- **Bundle Parsing** - Decode HG10UN/HG10GZ/HG10BZ changegroup format
- **Streaming Bundles** - Download large bundles to disk with progress reporting
- **Authentication** - HTTP Basic Auth for protected repositories
- **SSH Transport** - Support `ssh://` URLs with `hg serve --stdio`
- **Protocol v2** - Support newer HTTP wire protocol v2
- **Push Support** - Implement `unbundle` command for pushing changesets
- **Batch Commands** - Use `batch` capability for multiple operations in one request
- **Clone to Filesystem** - Extract bundle contents to create working directory

## Summary

The Mercurial client is **fully feasible** as a **Medium complexity** implementation:

- **HTTP-based**: Uses `reqwest` for all operations
- **Text parsing**: Simple line-based parsing (newlines, tabs, spaces)
- **No binary dependencies**: No `hg` binary required
- **Server proven**: Existing server implementation proves protocol is straightforward
- **LLM-friendly**: Request-response model with clear operation sequencing

**Implementation Time**: 3-5 days

**Benefits**:
- Test NetGet Mercurial server
- Query external Mercurial repositories
- Honeypot reconnaissance
- Repository discovery and analysis
- No external dependencies

**Recommendation**: Implement as Medium complexity client protocol, following the same patterns as HTTP and Redis clients.
