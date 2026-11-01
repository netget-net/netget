# S3 Protocol E2E Tests

## Test Overview

Tests S3-compatible server implementation using rust-s3 client. Validates object storage operations (GetObject,
PutObject, DeleteObject, ListObjects) and bucket management (ListBuckets). Uses real S3 client library to ensure
protocol compatibility.

## Test Strategy

**rust-s3 Client Testing**: Uses rust-s3 client library instead of raw HTTP. This approach:

- Validates full S3 protocol compatibility
- Tests with real S3 client (same library users would use)
- Handles S3 REST API details (URL encoding, headers, signatures)
- Provides higher-level API (cleaner test code)

**Consolidated Tests**: Single comprehensive test covering all operations to minimize LLM calls. Additional focused
tests for specific scenarios.

**Flexible Validation**: Tests accept various response formats since LLM may return data in different valid ways. Focus
on protocol correctness rather than exact content.

## LLM Call Budget

### Test: `test_s3_comprehensive`

- **1 server startup** (comprehensive prompt covering all operations)
- **6 operations**: ListObjects, GetObject (hello.txt), PutObject, HeadObject, DeleteObject, GetObject (data.json)
- Each operation → 1 LLM call
- **Total: 7 LLM calls**

### Test: `test_s3_get_object`

- **1 server startup**
- **1 GetObject request** → LLM call
- **Total: 2 LLM calls**

### Test: `test_s3_put_and_list`

- **1 server startup**
- **2 operations** (PutObject, ListObjects) → 2 LLM calls
- **Total: 3 LLM calls**

**Total for S3 test suite: 12 LLM calls** (slightly over 10 limit, but comprehensive test alone is 7)

**Optimization**: Running only `test_s3_comprehensive` gives full coverage with 7 LLM calls.

## Scripting Usage

**Scripting Disabled**: All tests use `ServerConfig::new()` which disables scripting. S3 tests validate different
operations that benefit from action-based flexibility.

**Why no scripting?**

- S3 operations are diverse (CRUD for both buckets and objects)
- Testing benefits from LLM's ability to maintain virtual storage state
- Action-based responses provide flexibility for dynamic content

**Future Enhancement**: Could enable scripting for `test_s3_comprehensive` to reduce to ~1-2 LLM calls total, but loses
validation of LLM's ability to manage stateful data.

## Client Library

**rust-s3** v0.37:

- Async S3 client built on tokio
- Supports any S3-compatible endpoint (AWS, MinIO, custom)
- Clean async/await API
- Handles S3 REST API details automatically

**Features Used**:

- `Bucket::new()` - Create bucket client
- `bucket.get_object()` - GetObject operation
- `bucket.put_object()` - PutObject operation
- `bucket.delete_object()` - DeleteObject operation
- `bucket.list()` - ListObjects operation
- `bucket.head_object()` - HeadObject operation

**Client Setup**:

```rust
let endpoint = format!("http://127.0.0.1:{}", port);
let region = Region::Custom {
    region: "us-east-1".to_string(),
    endpoint,
};

// Credentials not validated (no auth in NetGet S3)
let credentials = Credentials::new(
    Some("test"),
    Some("test"),
    None, None, None
).unwrap();

let bucket = Bucket::new("test-bucket", region, credentials).unwrap();
```

**No Authentication**: NetGet S3 server doesn't implement AWS Signature V4 authentication. rust-s3 requires credentials
but they're not validated.

## Expected Runtime

**Model**: qwen3-coder:30b (default)
**Total Runtime**: ~40-60 seconds for all 3 tests
**Breakdown**:

- `test_s3_comprehensive`: ~25-35 seconds (7 LLM calls)
- `test_s3_get_object`: ~8-12 seconds (2 LLM calls)
- `test_s3_put_and_list`: ~10-15 seconds (3 LLM calls)

**Factors**:

- LLM response time (varies by model and load)
- HTTP request/response overhead (minimal)
- rust-s3 client processing (fast)

**Optimization**: Run only comprehensive test for ~30 second validation.

## Failure Rate

**Historical**: ~10-15% failure rate
**Causes**:

1. **Invalid XML**: LLM returns malformed XML for ListObjects/ListBuckets
2. **Missing fields**: LLM forgets required XML fields (Size, LastModified, etc.)
3. **State forgetting**: LLM forgets previously uploaded objects
4. **Wrong content-type**: LLM returns incorrect Content-Type header
5. **Empty responses**: LLM returns no action or empty body

**Mitigation**: none of the above applies in mocked mode, which is how these tests run. The
mock supplies the exact action, so there is no "different but valid format" to tolerate.

**The mocked tests assert on rust-s3's parsed result, and this is the whole of the evidence
behind the protocol's Beta rating.** Each operation is issued inside the `retry` helper and its
rule is pinned to `expect_calls(1)`: a response rust-s3 rejects makes `retry` re-issue the
request, the count goes above one, and `verify_mocks` fails. That property only holds for calls
made *through* `retry` — `head_object` and `delete_object` were issued outside it, with the
error swallowed into a `println!("[INFO] ...")`, so those two verbs were named in the rating
while being asserted by nothing. They now go through `retry` like the rest, and the suite
asserts the parsed values (bucket name and both keys from the listing, the exact object body,
`Content-Length`/`Content-Type` from HeadObject, 200 on PutObject, 204 on DeleteObject).

Do not reintroduce an `Err(e) => println!("[INFO] ...")` arm here: it converts a rejected
response into a passing test.

## Test Cases

### 1. Comprehensive Operations (`test_s3_comprehensive`)

**Validates**: Full S3 workflow with virtual storage

- **ListObjects**: Check bucket contents
- **GetObject (hello.txt)**: Retrieve pre-existing object
- **GetObject (data.json)**: Retrieve JSON object
- **PutObject**: Upload new object
- **HeadObject**: Check object existence
- **DeleteObject**: Remove object
- **Expected**: LLM maintains virtual storage across operations

### 2. GetObject (`test_s3_get_object`)

**Validates**: Object retrieval

- Operation: GET /bucket/key
- Request: Bucket="my-bucket", Key="data.txt"
- Expected: 200 status with object content
- **Expected LLM Response**: `send_s3_object` with content and content-type

### 3. PutObject and ListObjects (`test_s3_put_and_list`)

**Validates**: Object upload and listing

- PutObject: Upload file.txt to 'uploads' bucket
- ListObjects: Verify file appears in listing
- Expected: 200 status for PUT, valid XML for LIST
- **Expected LLM Response**:
    - PUT: NoAction or notify_operator
    - LIST: `send_s3_object_list` with uploaded file

## Known Issues

### LLM State Management

**Issue**: LLM may not remember uploaded objects across requests
**Symptom**: PutObject succeeds but ListObjects doesn't show the file
**Workaround**: Comprehensive prompt explicitly states "remember objects"
**Status**: Works ~85% of the time

### XML Format Complexity

**Issue**: S3 XML has specific structure with namespaces
**Symptom**: rust-s3 rejects malformed XML
**Workaround**: LLM prompt includes XML format guidance
**Status**: applies to `--use-ollama` runs only. In mocked mode the XML is built by
`build_list_objects_xml` from a fixed action, so a rejection here is a real defect in that
builder, not flakiness — the suite asserts `listing.name` and the parsed keys precisely so
such a defect fails rather than retries.

### Binary Content

**Issue**: Binary data hard to represent in LLM responses
**Symptom**: Large binary files impractical
**Workaround**: Tests use text files only
**Status**: By design limitation

### Error Code Mapping

**Issue**: S3 has many specific error codes (NoSuchKey, NoSuchBucket, etc.)
**Symptom**: LLM may return generic errors
**Workaround**: Tests accept any error response
**Status**: Not critical for protocol validation

### HTTP Keep-Alive

**Issue**: New connection per request (no keep-alive)
**Symptom**: Slower than reusing connections
**Workaround**: Acceptable for tests
**Status**: By design for simplicity

## Test Execution

```bash
# Run all S3 tests
./cargo-isolated.sh test --features s3 --test server -- server::s3

# Run only comprehensive test (best coverage, 7 LLM calls)
./cargo-isolated.sh test --features s3 --test server -- server::s3::e2e_test::test_s3_comprehensive

# Run specific test
./cargo-isolated.sh test --features s3 --test server -- server::s3::e2e_test::test_s3_get_object

# Run with output
./cargo-isolated.sh test --features s3 --test server -- server::s3::e2e_test --nocapture
```

**Important**: `--test` names a cargo *target*. The target is `server` (`tests/server.rs`);
`server::s3::e2e_test` is a module path **inside** it and belongs after `--`, as a filter.
This file used to say the opposite, and `--test server::s3::e2e_test` matches no target —
cargo prints the list of available targets and exits having run **zero** tests, which
reads as a pass. No release build is needed either: the harness uses
`CARGO_BIN_EXE_netget`, the binary cargo built for this test with these features.

## Test Output Example

```
=== Test: S3 Comprehensive Operations ===
Server started on port 54321 with stack: ETH>IP>TCP>HTTP>S3
Test 1: Listing buckets...
Test 2: Listing objects in test-bucket...
[PASS] ListObjects succeeded, found 1 results
Objects: ["hello.txt", "data.json"]
Test 3: Getting hello.txt...
[PASS] GetObject succeeded, content: Hello, World!
Test 4: Putting new object test.txt...
[PASS] PutObject succeeded with status: 200
Test 5: Checking if hello.txt exists with HeadObject...
[PASS] HeadObject succeeded with status: 200
Test 6: Deleting test.txt...
[PASS] DeleteObject succeeded with status: 200

[PASS] All S3 operations completed
Note: Some operations may return errors if LLM doesn't maintain state,
but the test verifies the protocol works correctly.
=== Test Complete ===
```

## Future Improvements

1. **Further Consolidation**: Merge all tests into single comprehensive test
    - Single server startup with all operations
    - **Target: 6-7 total LLM calls**
2. **Scripting Mode**: Enable scripting for repetitive operations
    - GetObject requests could use generated script
    - **Target: 2-3 total LLM calls**
3. **Multipart Upload**: Test large file uploads (if implemented)
4. **Bucket Operations**: Test CreateBucket, DeleteBucket explicitly
5. **Error Scenarios**: Test explicit error cases (NoSuchBucket, AccessDenied)
6. **Content Types**: Test various MIME types (images, JSON, binary)
7. **Presigned URLs**: Test URL signing (if implemented)
8. **Versioning**: Test object versioning (if implemented)

## Comparison with DynamoDB Tests

**Similarities**:

- Both use real client libraries (rust-s3 vs reqwest)
- Both test stateless HTTP protocols
- Both rely on LLM maintaining virtual data

**Differences**:

- **S3**: Uses dedicated S3 client (more realistic)
- **DynamoDB**: Uses generic HTTP client (simpler)
- **S3**: RESTful URLs (bucket/key in path)
- **DynamoDB**: RPC-style (operation in header)
- **S3**: XML responses (more complex)
- **DynamoDB**: JSON responses (simpler)

**LLM Calls**:

- S3: 12 calls (3 tests), or 7 for comprehensive only
- DynamoDB: 12 calls (5 tests)
- Both slightly over 10 target, but within acceptable range
