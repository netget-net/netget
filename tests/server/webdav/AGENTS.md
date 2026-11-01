# WebDAV Protocol E2E Tests

Six tests across three files, all declared in `tests/server/webdav/mod.rs` (which *is* wired
into `tests/server/mod.rs` — check before assuming, that is the repo's largest silent test
hole): three in `test.rs` driven by `reqwest_dav`, one in `real_client_test.rs` driven by the
real `curl` binary, and two in `decision_tag_test.rs`.

## Clients — there are two, and that is the point

One client can agree with one bug. `reqwest_dav` was the only real peer this server had ever
faced, and a rating resting on one client rests on that client's leniency — elsewhere in this
repository `etcd`, `grpc` and `mysql` were each Beta on a single client and each turned out to
be unusable by every other conformant implementation, with the *error* path accidentally
correct and the tests asserting on it.

### `reqwest_dav` (`test.rs`)

A real WebDAV client library, not hand-rolled `reqwest` requests. That matters for PROPFIND:
the body is parsed with the library's own `serde_xml_rs` schema (`ListMultiStatus` →
`ListEntity`), so a malformed multistatus, a `<D:response>` without a propstat, or a file entry
whose `getlastmodified` is missing or not an HTTP date all fail here. A test that only asserted
`207` would pass on all three.

### `curl` (`real_client_test.rs`) — the second client

**curl is a generic HTTP client and the root `AGENTS.md` rules those out — for a protocol
layered *on* HTTP.** `PROPFIND`, `MKCOL` and `COPY` are not HTTP verbs; `207 Multi-Status` is
not an HTTP status; `Depth` and `Destination` are not HTTP headers; `DAV:multistatus` is not an
HTTP document. All of those are RFC 4918's, which is the layer this server implements, so curl
issuing them is a real WebDAV client for the part that matters. Same qualification as
`curl gopher://` counting while `curl` against an HLS playlist does not.

**The test fails rather than skips** when curl is absent, and is not `#[ignore]`d.

Three things it reaches that `reqwest_dav` does not:

- **The multistatus as XML, not as a struct.** `quick-xml` parses the body into responses, so a
  body that is not well-formed fails outright rather than deserialising into whatever fields a
  fixed schema happens to recognise. (`quick-xml` is an unconditional `[dev-dependencies]`
  entry for this reason: its `[dependencies]` entry is optional and only `saml`/`xmlrpc` turn
  it on, so a test gated on `webdav` alone could not see it.)
- **`href` percent-encoding against `displayname` XML-escaping**, on one name: `notes &
  drafts.txt`. RFC 3986 wants `%20` and `%26` in the href; XML wants `&amp;` in the
  displayname, read back through `Event::unescape` as a literal `&`. Two different rules on the
  same string, each applied in its own place.
- **`COPY` with a `Destination` header.** The model echoes the destination it was handed into
  the response body, so the assertion is that the header was parsed — and it proves it, because
  the path it echoes (`/documents/notes-copy.txt`) appears nowhere in the request line. Note
  the server resolves the absolute-URI `Destination` (RFC 4918 §10.3) down to a path before the
  model sees it.

**Verified non-vacuous** by breaking `DavResource::render` twice:

| break | what curl received |
|---|---|
| `xml_escape(&self.name)` → `&self.name` for `displayname` | still `207`, body looks fine to the eye, but the bare `&` makes it invalid XML: the parse failed with `Cannot find ';' after '&'`. A status-code check — or a `body.contains("<D:href>")` check — would have passed |
| `percent_encode_path(&self.href)` → `&self.href` | a well-formed document whose href read `/documents/notes & drafts.txt`; the test failed naming the expected `/documents/notes%20%26%20drafts.txt` |

The `*_raw` methods are used throughout (`list_raw`, `put_raw`, `get_raw`, `mkcol_raw`,
`delete_raw`) rather than the checked wrappers, because the wrappers call `dav2xx()` and
collapse every non-2xx into an error — and the exact status code is the thing under test.
Plain `reqwest` is used for the one `OPTIONS` request, which `reqwest_dav` has no method for.

## Test strategy

**The model decides, and each test proves a specific consequence of that.** There is no
filesystem behind this server, so nothing can pass by accident of storage — which is exactly
how the previous suite passed against a `MemFs` the model never saw.

## LLM call budget

**Total: 15.** Every rule uses exact `expect_calls`, so an unexpected extra call fails
`verify_mocks()`.

| Test | Startup | Events |
|---|---|---|
| `test_webdav_propfind_listing` | 1 | 1 (PROPFIND) |
| `test_webdav_put_then_get_round_trip` | 1 | 2 (PUT, GET) |
| `test_webdav_write_statuses_refusal_and_options` | 1 | 3 (MKCOL, DELETE, GET) |
| `curl_completes_a_webdav_session_against_the_webdav_server` | 1 | 5 (PROPFIND, MKCOL, PUT, GET, COPY) |

Event rules are declared **before** the startup rule in each builder chain: rules match in
order, and the specific ones must win.

## Test cases

### 1. `test_webdav_propfind_listing`

Mock matches `webdav_request` with `method` PROPFIND **and `depth` "1"** — so a `Depth` header
that never reaches the event fails to match and the request 500s rather than quietly listing
the wrong thing. The mock echoes the event's `path` back into `send_webdav_listing`, the way a
model is instructed to.

Asserts: `207`; an XML content type; a `DAV:` compliance header; exactly **three**
`<D:response>` elements; and, after parsing into typed entities, that `/` and `/documents/` are
collections (note the generated trailing slash), that `/readme.txt` is a file, and that the
`size` and `content_type` the model supplied arrive as `getcontentlength` and
`getcontenttype`. Also asserts the server registered its stack as `WebDAV`.

### 2. `test_webdav_put_then_get_round_trip`

The strongest test in the suite. The mock plays a model using server memory: an
`Arc<Mutex<Option<String>>>` captures the `body` off the PUT event, and the GET mock serves it
back. If the request body never reaches the model, the GET returns the sentinel
`<the PUT body never reached the model>` and the assertion fails.

Both mocks also match on `path` == `/notes.txt`, so a broken path in the event fails the match.

Asserts: PUT answers `201` (the model's choice, not the server's); GET answers `200` with the
model's `content_type` on the wire and exactly `Hello WebDAV!` as the body.

### 3. `test_webdav_write_statuses_refusal_and_options`

Four things at once:

- MKCOL → the model's `201`.
- DELETE → the model's `403` with its explanation reaching the client verbatim.
- GET → the model answers with `notify_operator` only, i.e. **no WebDAV response action**. The
  server must fail closed with `503`. This is the fail-open regression guard; mutating that
  503 to a 200 in `build_webdav_response` fails exactly this assertion, and nothing else.
- OPTIONS → `200` with `Allow` advertising PROPFIND/MKCOL/PUT/LOCK, at **zero** LLM cost. No
  mock rule matches an OPTIONS event, so if it ever started reaching the model the mock would
  answer HTTP 500 and `verify_mocks()` would report the unexpected call.

## `decision_tag_test.rs` — who decided, not just what was answered

WebDAV can express a refusal on the wire (`403`, `409`, `423 Locked`, `507`), so `test.rs`
above can assert the model's chosen status reaches the client. What a status cannot say is
**who chose it**: `send_webdav_status` will happily send a `503` or a `500`, which are exactly
the codes the server falls back to. The `decision=` tag in `netget.log` and on the status
stream is the only place the two separate, and these two tests are a deliberate pair —

- `test_webdav_llm_failure_is_tagged_fail_closed`: the mock answers a `webdav_request` with raw
  text that is not an action, so the repair loop exhausts and `call_llm` returns `Err`. Asserts
  a 5xx with **no `multistatus` body** (an empty multistatus would be an affirmative claim that
  the collection exists and is empty), a log line carrying `decision=fail_closed_` and naming
  `PROPFIND`, and that **no** line records a `decision=model_`.
- `test_webdav_model_refusal_is_tagged_model_reject`: the model refuses a `PUT` with `423
  Locked`. Asserts the 423 reaches the client verbatim, that it is logged
  `decision=model_reject`, and that **no** line says `decision=fail_closed_` — tagging it so
  would make the documented `grep decision=fail_closed` report a backend outage that never
  happened.

Either test alone would pass against a server that tagged every outcome identically, which is
why they are written and maintained as a pair. `wait_for_any` gates both assertions; neither
sleeps.

Not covered here: the `LOCK` path, which always grants an unenforced lock and logs
`decision=protocol_synthetic_lock` — see `src/server/webdav/AGENTS.md` for why that stands.

## Expected runtime

~1.2s for the whole suite against the mock harness.

## A note on flakes

The first run after touching `src/` rebuilds the ~50MB `netget` binary (~85s here). On a
machine with several agents building at once that run can come back as
`Timeout waiting for netget startup` on every test — build contention, not a real failure. Run
`cargo build --no-default-features --features webdav` first, or simply re-run, before
concluding anything.

## Not covered

MOVE · PROPPATCH · LOCK/UNLOCK response bodies (only that OPTIONS advertises them) ·
`Depth: infinity` · non-UTF-8 PUT bodies (`body_is_binary`) · script and static handler modes ·
a model returning an out-of-range status · non-ASCII names in hrefs (ASCII names needing
percent-encoding *are* covered, by `real_client_test.rs`).

COPY and its `destination` were on this list until `real_client_test.rs` drove them; MOVE still
is.
