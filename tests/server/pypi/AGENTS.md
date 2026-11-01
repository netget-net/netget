# PyPI Protocol E2E Testing

## Test Strategy

Black-box testing using real pip and curl commands to verify PEP 503 compliance. Tests focus on:

1. Package index listing (`/simple/`)
2. Package-specific file listings (`/simple/<package>/`)
3. Package file downloads (`/packages/...`)
4. Integration with pip command (metadata fetch)

## Test Files

- `e2e_test.rs` - Main E2E test suite

## Test Cases

### test_pypi_comprehensive

Comprehensive test covering all PyPI endpoints with multiple packages:

- **Setup**: Server with 2 packages (hello-world 1.0.0, example-pkg 2.1.0)
- **Test 1**: Fetch package index with curl (verify HTML contains both packages)
- **Test 2**: Fetch hello-world package page (verify wheel file listed)
- **Test 3**: Fetch example-pkg package page (verify wheel file listed)
- **Test 4**: Test pip integration (pip index versions to query metadata)
- **Test 5**: Test 404 handling for non-existent packages

**LLM Call Budget**: Target 1-2 LLM calls

- 1 call at startup to parse instruction and set up scripting mode
- 0 calls for subsequent HTTP requests (scripting mode handles all)

**Runtime**: ~5-10 seconds

- 2s server startup
- 3-5s for curl requests
- 2-5s for the pip query

### test_pypi_single_package

Minimal test with single package for quick verification:

- **Setup**: Server with 1 package (test-pkg 0.1.0)
- **Test**: Fetch package index with curl

**LLM Call Budget**: 1 LLM call (startup only)

**Runtime**: ~3-5 seconds

## Test Clients

### curl

- **Purpose**: HTTP request verification
- **Availability**: Usually available in CI/test environments
- **Usage**: Fetch HTML pages, check status codes

### pip

- **Purpose**: Real-world PyPI client integration
- **Availability**: Required. Test 4 fails, naming the install command, when `pip` is not on
  `PATH` — a skip would report a pass for a step that asserted nothing
- **Usage**: `pip index versions` to query package metadata

## Known Issues

### 1. Wheel File Generation

**Issue**: LLMs struggle to generate valid Python wheel files (zip archives with specific structure).

**Impact**: Full `pip install` will likely fail because downloaded wheel is invalid.

**Workaround**: Tests use `pip index versions` instead of `pip install` to verify PyPI API compatibility without
requiring valid wheel contents.

### 2. HTML Format Strictness

**Issue**: LLMs may not generate perfectly PEP 503-compliant HTML (missing DOCTYPE, incorrect anchor format).

**Impact**: pip may still work if HTML is "close enough", but strict validation would fail.

**Workaround**: Tests check for package names in HTML rather than validating full HTML structure.

### 3. Hash Values

**Issue**: SHA256 hashes in package URLs must match file contents for pip to accept them.

**Impact**: pip will reject packages if hash validation is enabled.

**Workaround**: Tests don't verify hash correctness, focus on API structure instead.

## Privacy & Offline Testing

- **Network**: All tests use localhost (127.0.0.1) only
- **Dependencies**: No external package repositories contacted
- **pip configuration**: Uses `--index-url` to override default PyPI, preventing external requests
- **Offline-compatible**: Tests work without internet connection

## Running

PyPI is compiled into every native build; select the suite by module path:

```bash
./cargo-isolated.sh test --test server -- server::pypi:: --test-threads=16
```

## CI Considerations

- **curl requirement**: Tests assume curl is available (standard in most CI environments)
- **pip required**: Test 4 fails when pip is absent (`brew install python3` / `apt-get install -y python3-pip`)
- **No root required**: Tests use high ports, no privileged access needed
- **Concurrent safe**: random ports and an in-process mock LLM per test

## Future Improvements

1. **Mock wheel generation**: Pre-generate minimal valid wheel files to enable full `pip install` testing
2. **HTML validation**: Add PEP 503 HTML format validation
3. **Hash verification**: Generate real SHA256 hashes for test packages
4. **Multiple versions**: Test packages with multiple versions (e.g., 1.0.0, 1.0.1, 2.0.0)
5. **Package dependencies**: Test packages with dependencies listed in metadata
6. **twine integration**: Test package upload workflow (POST to /legacy/)

## Performance Notes

- **Fast**: Uses scripting mode for 0 LLM calls after startup
- **Lightweight**: HTTP-based, no heavy protocol overhead
- **Scalable**: Can test many packages in single server instance

## Debugging

If tests fail, check:

1. Server logs in `netget.log` (use `.with_log_level("debug")`)
2. Full HTTP request/response (add `-v` flag to curl)
3. pip verbose output (`pip -vvv index versions ...`)
4. Server actually started on expected port (check test_state.port)

## Example Manual Testing

```bash
# Start server
./target/release/netget
> listen on port 8080 via pypi
> Serve package "test-pkg" version 1.0.0

# In another terminal:
# Test with curl
curl http://localhost:8080/simple/

# Test with pip
pip index versions test-pkg --index-url http://localhost:8080/simple/

# Try download (will likely fail with invalid wheel)
pip download test-pkg --index-url http://localhost:8080/simple/ --dest ./tmp/
```
