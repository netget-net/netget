# PyPI Client Implementation

## Overview

The PyPI (Python Package Index) client protocol implementation provides LLM-controlled interaction with the Python
Package Index for searching, downloading, and querying package information.

## Library Choices

### HTTP Client: `reqwest`

- **Why**: Industry-standard async HTTP client with excellent TLS support
- **Usage**: All PyPI API interactions use HTTPS
- **Configuration**: 30-second timeout, custom User-Agent header

### URL Encoding: `urlencoding`

- **Why**: Standard URL encoding for search queries
- **Usage**: Encode search query parameters for PyPI search URLs

## Architecture

### Connection Model

PyPI client is "connectionless" - no persistent TCP connection is maintained. Each operation makes independent HTTPS
requests to the PyPI JSON API.

### State Management

- **index_url**: PyPI index URL. **There is no default** — it comes from `remote_addr` (or the
  `index_url` startup parameter, which overrides it), and a client given neither refuses to
  start rather than reaching the public index by omission. Naming it explicitly still works.
- **protocol_data**: Stores client metadata and state
- **Background task**: Monitors client lifecycle (checks every 5 seconds)

### LLM Integration

#### Event Flow

1. **Connected Event** (`pypi_connected`)
    - Triggered: When client is initialized
    - Data: index_url
    - LLM Action: Receive instruction and plan operations

2. **Package Info Event** (`pypi_package_info_received`)
    - Triggered: After fetching package metadata
    - Data: package_name, info (full JSON response)
    - LLM Action: Analyze package info, decide next steps

3. **Search Results Event** (`pypi_search_results_received`)
    - Triggered: After search operation
    - Data: query, results
    - LLM Action: Review results, select packages to explore
    - **Note**: PyPI's XML-RPC search API is deprecated, so this returns a notice message

4. **File Downloaded Event** (`pypi_file_downloaded`)
    - Triggered: After successful package download
    - Data: filename, size, package, version
    - LLM Action: Confirm download, process next steps

#### Action Types

**Async Actions** (user-triggered):

- `get_package_info(package_name)` - Fetch package metadata via JSON API
- `search_packages(query, limit)` - Search for packages (deprecated API notice)
- `download_package(package_name, version, filename)` - Download wheel or sdist
- `list_package_files(package_name, version)` - List available distribution files
- `disconnect()` - Close client

**Sync Actions** (response to events):

- `get_package_info(package_name)` - Follow-up package query

### PyPI JSON API

The client uses PyPI's JSON API (PEP 691):

#### Endpoints

1. **Package Info**: `https://pypi.org/pypi/{package}/json`
    - Returns: Full package metadata, all versions, download URLs
    - Example: `https://pypi.org/pypi/requests/json`

2. **Specific Version**: `https://pypi.org/pypi/{package}/{version}/json`
    - Returns: Metadata for specific version
    - Example: `https://pypi.org/pypi/requests/2.31.0/json`

#### Response Structure

```json
{
  "info": {
    "author": "...",
    "author_email": "...",
    "description": "...",
    "home_page": "...",
    "keywords": "...",
    "license": "...",
    "name": "requests",
    "package_url": "https://pypi.org/project/requests/",
    "project_url": "https://pypi.org/project/requests/",
    "version": "2.31.0",
    "requires_python": ">=3.7",
    "summary": "Python HTTP for Humans."
  },
  "urls": [
    {
      "filename": "requests-2.31.0-py3-none-any.whl",
      "url": "https://files.pythonhosted.org/...",
      "size": 62574,
      "packagetype": "bdist_wheel",
      "python_version": "py3",
      "digests": {...}
    },
    {
      "filename": "requests-2.31.0.tar.gz",
      "url": "https://files.pythonhosted.org/...",
      "size": 110794,
      "packagetype": "sdist",
      "python_version": "source",
      "digests": {...}
    }
  ],
  "releases": {
    "2.31.0": [...],
    "2.30.0": [...]
  }
}
```

### Download Strategy

When downloading packages:

1. Fetch package JSON to get available files
2. Select appropriate file:
    - If `filename` specified: Use exact match
    - Else: Prefer wheel (`bdist_wheel`) over sdist (`sdist`)
3. Download file via direct HTTPS GET
4. Return file metadata to LLM (filename, size)

**Note**: Files are downloaded to memory only. NetGet doesn't save to disk unless explicitly directed by LLM.

## Limitations

### API Deprecations

1. **XML-RPC Search API**: PyPI deprecated the XML-RPC search endpoint
    - Old: `pypi.python.org/pypi`
    - Current: Web-based search only
    - Impact: `search_packages` action returns notice, not results
    - Workaround: Use `get_package_info` for known package names

### Missing Features

1. **Package Upload**: Not implemented (requires authentication, multipart form upload)
2. **User Authentication**: Not supported (no API tokens or credentials)
3. **Private Indexes**: Basic support via index_url parameter
4. **File Storage**: Downloads kept in memory only

### Security Considerations

1. **HTTPS Only**: All requests use HTTPS (default reqwest behavior)
2. **No Verification**: Package signatures/digests not validated
3. **Trust on First Use**: No certificate pinning

## LLM Control Points

The LLM has full control over:

1. **Package Discovery**
    - Query specific packages by name
    - Inspect package metadata (author, license, dependencies)

2. **Version Selection**
    - List all available versions
    - Choose specific version or latest

3. **File Selection**
    - List available distribution files (wheels, sdists)
    - Choose specific file type or platform

4. **Download Decision**
    - Decide which packages to download
    - Select wheels vs source distributions

## Example LLM Prompts

### Basic Package Query

```
Connect to PyPI and get information about the 'requests' package
```

**Expected Flow**:

1. Client connects to https://pypi.org
2. LLM receives `pypi_connected` event
3. LLM executes `get_package_info("requests")`
4. LLM receives `pypi_package_info_received` with full metadata
5. LLM analyzes and reports findings

### Download Specific Version

```
Connect to PyPI and download requests version 2.31.0
```

**Expected Flow**:

1. Client connects
2. LLM executes `download_package("requests", "2.31.0")`
3. Client fetches package JSON, finds wheel file
4. Client downloads wheel
5. LLM receives `pypi_file_downloaded` event

### Explore Package Files

```
Connect to PyPI and list all available files for numpy
```

**Expected Flow**:

1. Client connects
2. LLM executes `list_package_files("numpy")`
3. Client fetches package JSON, extracts URLs array
4. LLM receives `pypi_package_info_received` with files list
5. LLM analyzes platform-specific wheels

## Testing Strategy

See `tests/client/pypi/AGENTS.md` for detailed E2E testing approach.

### Test Priorities

1. **Package Info Query**: Verify JSON API parsing
2. **File Listing**: Verify URL extraction
3. **Download**: Verify file download (small package)
4. **Error Handling**: Invalid package names

### LLM Call Budget

Target: < 5 LLM calls per test suite

## Future Enhancements

1. **Search Integration**: Use alternative search APIs or scraping
2. **Package Upload**: Support twine-like upload functionality
3. **Signature Verification**: Validate PGP signatures and hashes
4. **Warehouse API**: Use additional warehouse.pypa.io endpoints
5. **Private Registries**: Better support for devpi, artifactory, etc.

## References

- [PyPI JSON API](https://warehouse.pypa.io/api-reference/json.html)
- [PEP 503: Simple Repository API](https://peps.python.org/pep-0503/)
- [PEP 691: JSON-based Simple API](https://peps.python.org/pep-0691/)
- [Python Packaging User Guide](https://packaging.python.org/)

## Injected commands (the dashboard's `[ send ]`)

`AppState::send_to_client` injects an action into a running PyPI client and gets back a truthful `ClientSendOutcome`. See `src/client/command_support.rs` and `tests/client/pypi/command_channel_test.rs`.

- `command_support::register_command_channel` runs **before** anything that can block for a
  human (PyPI raises no connected event today, so the channel is registered as soon as the client is marked `Connected`), so `[ send ]` works even while an event is parked on a manual routing
  rule. This is the whole point of the feature: registering late means the rail reads
  "no command channel" for the length of the park.
- The command loop **replaced the old 5-second `get_client().is_none()` idle poll**. When the
  client is removed its handle is dropped, the channel closes, `recv()` returns `None` and the
  loop exits at once — the poll was strictly slower at the same job. The loop is registered
  with `register_client_task`, and it drops the handle on every exit path.
- One `apply_action` is the only place actions become traffic, shared by the command loop and any future LLM dispatch. There is
  no second wire path for injected actions to drift from.

### Outcome semantics — what `[ send ]` reports, and why

| Outcome | When |
|---|---|
| `Sent { bytes_sent }` | **Never.** `reqwest` does not report how many bytes reached the wire, and inventing a number would be a lie |
| `Executed { detail }` | The operation ran to completion; `detail` names it. `search_packages` is the interesting case: PyPI retired its search API, so the action raises `pypi_search_results` **without contacting the index at all** — its `detail` says so, and the test asserts no bytes moved. Reporting `Sent` there would be the exact dishonesty the outcome enum exists to prevent |
| `Rejected { error }` | `execute_action` refused the JSON (unknown verb, missing field) |
| `Disconnected` | `disconnect`; the loop ends, the handle is dropped and the client goes to `Disconnected` |
| `Err(...)` | The request itself failed (transport error, non-2xx). The caller sees the error rather than a false success |

**The known cost of awaiting.** `apply_action` awaits the whole operation, *including the
response event it raises*. That is what makes the outcome truthful, but it also means the
command loop is busy until that event has been handled — with a `*` -> manual rule, until the
human answers it or the intercept times out (default 300s). Injected sends queue behind it on
the bounded channel, which surfaces as "client busy" backpressure. `send_to_client`'s own
timeout protects the caller either way.

**This paragraph used to say the opposite of what the code does.** It claimed the four operations *discard* the model's actions and that `pypi_connected` is never raised; both had been fixed, and a reader trusting this file would have re-fixed a solved bug. `run_follow_ups` executes what the model answers, bounded structurally at one turn because it routes through the non-notifying `perform_*` helpers, and `connect_with_llm_actions` raises `pypi_connected` from its own registered task.

**What is true now.**

- The connected event carries `index_url`. It declares that parameter as **required** and this file documented it, but the event was raised with `{}` — so a `pypi_connected` handler could not tell which index it was talking to.
- `index_url` is declared in `get_connect`/`get_startup_parameters()` **and read**: `connect()` prefers it over `ctx.remote_addr`. It was read by nothing until now, so the advertised knob did nothing when turned.
- A `remote_addr` with no scheme is no longer discarded and replaced with the public index. It gets the `https://` it was missing. Before, an operator who typed `127.0.0.1:8080` had their requests sent to the public index with no warning.
- An **empty** address no longer falls back either. It used to return `https://pypi.org` with an INFO line, which is the class the root `AGENTS.md` calls "a client that loses its target must fail, never fall back to the real service" — milder than the DynamoDB case, since nothing here is signed with anybody's credentials, and the same shape. `resolve_index_url` returns `Result` and refuses, naming a localhost example, exactly as `openai::api_base_for` does. The protocol's own name as an address (`"pypi"`) refuses too. `tests/client/pypi/index_target_test.rs` pins both refusals **and** that an explicitly named `pypi.org` is still honoured — a guard that refused everything would satisfy the first assertion alone.
- `search_packages` builds its `search_url` from the configured index. It hardcoded `https://pypi.org/search/?q=...`, so a client pointed at a private index was handed the public one as somewhere to go.
- `download_package` **streams and counts**; it does not buffer. It used to hold an entire distribution in memory and use it for nothing but `.len()`, at a size chosen by whatever the client was pointed at. It is capped at `MAX_DOWNLOAD_BYTES` (256 MiB). Nothing is written to disk — NetGet implements no storage, so a download here is a fetch-and-report.
- One `reqwest::Client`, built once on `spawn_blocking`. Every request used to build a fresh one, and `connect()` built a further one into `_http_client` and dropped it immediately — the blocking rustls + platform-root-store cost that `AGENTS.md` records as having stalled a whole client runtime, paid per request.
- `get_event_types()` returns clones of the `LazyLock` statics the client actually raises. It used to hand-build a parallel set with no parameters and `{"type": "placeholder"}` examples, which steered the model to `notify_operator` — an action `execute_action` rejects.

## Browser build

This client is in the browser build (`crates/netget-web`). Every request goes through
`crate::client::http_fetch::FetchClient`: natively it wraps the same reqwest client as before,
so what reaches the wire is unchanged; on wasm32 it is the shared hyper HTTP/1.1 transport
(`src/client/http_fetch/transport.rs`) over the page's virtual loopback, with the same 30-second bound, `User-Agent` and a body bound of `MAX_DOWNLOAD_BYTES`. The
transport reads a response whole before `chunk()` yields it, so the streaming checks below the
round trip see one chunk. A scheme-less index address gets `https://` natively and `http://` in the browser; an explicit `https://` index is refused there with the reason. `web/test/smoke.mjs` proves it in the bundle: `[ + PyPI client ]` on NetGet's `pypi` server connects, `[ send ]` of `get_package_info` reaches the server's model, and the JSON it wrote is in the `pypi_package_info_received` event parked on the client.


The dashboard pairs NetGet servers with explicit `http://127.0.0.1:<bound-port>` URLs on both native and browser builds. Native pairing exchanges are covered in `tests/dashboard_create_flow_test.rs`.
