# OCI Registry E2E Tests

## Files

| File | LLM calls | What it covers |
|---|---|---|
| `digest_test.rs` | **0** | Pure protocol logic: digests, path parsing, descriptor rewriting, error envelopes |
| `e2e_test.rs` | **14** across 3 tests | The wire protocol over real HTTP, and a real `crane` client |

## Strategy

The property that decides whether this protocol works is not "does it return 200".
It is **does the SHA-256 of the bytes we serve equal the digest we advertised**,
because that is the one thing every real OCI client independently checks. Every
test is built around that.

Three layers of evidence, deliberately independent of each other:

1. **Known-answer digests.** `CONFIG_DIGEST` and `LAYER_DIGEST` in `digest_test.rs`
   were produced by Apple's `shasum -a 256`, not by NetGet. A test asserting
   `sha256_digest(x) == CONFIG_DIGEST` therefore checks the implementation against
   an outside oracle, not against itself.
2. **`shasum` cross-check at runtime.** `external_sha256()` in `e2e_test.rs` shells
   out to `shasum -a 256` on the exact response body and compares it with the
   `Docker-Content-Digest` header. Skipped (with a printed note) if `shasum` is
   absent; the rest of the assertions still run.
3. **`crane`.** `test_oci_registry_against_crane` drives the real
   google/go-containerregistry client, which re-hashes everything it fetches and
   errors out on a mismatch. This is the strongest available evidence and the reason
   the protocol is `Experimental` rather than `Incomplete`. It is only evidence
   because it now **fails** when crane is absent rather than skipping — see below.

## Tests

### `digest_test.rs` — 12 tests, no sockets, no model

- `sha256_matches_an_external_oracle` — known answers + the NIST empty-string vector.
- `every_documented_encoding_is_actually_decoded` — `utf8`, `hex`, `base64` each
  round-trip, unknown encodings error. This exists because of the `send_tcp_data`
  defect: an encoding that is documented but not decoded is worse than one that is
  not offered.
- `v2_paths_parse_with_slash_containing_repository_names` — `library/alpine`,
  `a/b/c`, a repository whose component is literally `manifests`, and the
  `/blobs/uploads` vs `/blobs/` ordering trap.
- `repository_names_follow_the_spec_grammar` / `digests_are_validated_…`
- **`descriptor_digests_invented_by_the_model_are_overwritten`** — the crux. The
  manifest arrives with `sha256:0000…` and `sha256:1111…`; both must be replaced by
  the real hashes, while model-authored `annotations` survive.
- `a_descriptor_with_no_supplied_content_is_reported_not_silently_trusted`
- `index_children_get_real_digests_too` — including `platform` preservation.
- `content_type_distinguishes_a_manifest_from_an_index`
- `error_envelopes_have_the_shape_clients_parse`
- `version_check_mode_rejects_typos_rather_than_defaulting`
- `resolve_blobs_rejects_a_role_it_cannot_place`

### `e2e_test.rs::test_oci_registry_pull_path` — 9 LLM calls

One server, one process, the whole pull path. The manifest rule is reused for the
GET-by-tag, the HEAD, and the GET-by-digest (3 calls), which is itself an
assertion: identical content must produce identical digests on all three.

Asserts, in order: `GET /v2/` and its API-version header · catalog JSON · tag list
echoing `name` · manifest `Content-Type`, `Docker-Content-Digest`, `ETag`, and the
`shasum` cross-check · **descriptor digests recomputed from the supplied content**
and annotations preserved · HEAD reporting the same digest and length with no body ·
by-digest fetch returning byte-identical bytes · config blob body, media type and
digest · layer blob · `NAME_UNKNOWN` for a repository the model refuses.

Then five paths that cost **no** LLM call because they are refused before the model
is asked: `POST …/blobs/uploads/` → 405 `UNSUPPORTED`, manifest `PUT` → 405,
uppercase repository → 400 `NAME_INVALID`, malformed digest → 400 `DIGEST_INVALID`,
`sha512:` → 400 `DIGEST_INVALID`, and a non-`/v2/` path → 404.

### `e2e_test.rs::test_oci_registry_refuses_mismatched_content` — 4 LLM calls

The most important test in the suite. Server started with
`startup_params: {"version_check": "llm"}`.

1. `GET /v2/` reaches the model, which returns `send_oci_auth_challenge` → 401 with a
   well-formed `WWW-Authenticate: Bearer realm=…,service=…,scope=…`.
2. The model answers a blob request with content that does **not** hash to the
   requested digest → **404 `BLOB_UNKNOWN`**, with `detail.requested` and
   `detail.computed` both present and different. The wrong bytes are never served.
3. The model answers a manifest request with `notify_operator` — a valid action, but
   not an OCI reply → **500 `UNKNOWN`**. Silence must not be able to masquerade as a
   successful pull. (Note: the action must be a *valid* common action. An earlier
   draft used a malformed `set_memory`, which sent the executor into its repair loop
   and produced a 503 LLM-failure instead — a different path from the one under test.)

### `e2e_test.rs::test_oci_registry_against_crane` — 1 LLM call

**Fails — not skips — unless both `crane` and `python3` are on `PATH`.** It used to
print "crane not installed - skipping the real-client test" and return `Ok(())`, so on
any machine without crane it was a green pass that had asserted nothing, while this
file called it "the strongest available evidence" and `metadata().e2e_testing` claimed
validation against crane. A skip-when-missing gate is a silent pass, not evidence;
`tests/server/npm/e2e_test.rs::test_npm_with_real_cli` is the shape copied here. The
cost is that crane and python3 are now requirements wherever this suite runs.

`python3` is needed for the blob-dispatching *script handler*, not by crane.

The test is `#[tokio::test(flavor = "multi_thread")]` for a reason worth keeping: every
`crane` invocation is a blocking `std::process::Command`, and the in-process mock Ollama
server is spawned onto this test's own runtime. On the default current-thread runtime a
crane call holds the only worker, so the moment any handler misses and falls through to
the model, crane waits on netget, netget waits on the mock, and the mock cannot run
because crane owns the thread. Today's handlers are all deterministic so it happens not
to deadlock; that is luck, not design.

Handlers are deterministic — static for catalog/tags/manifest, and a **python script
handler for blobs** that dispatches on `event.digest`. A static handler cannot do
that: there are two blobs with different digests and one event. So the server start
is the only model call, and crane may make as many requests as it likes.

Runs `crane catalog`, `crane ls`, `crane manifest` (by tag), `crane digest`,
`crane manifest` (by the digest crane itself computed), `crane config` and
`crane blob`. `crane config` and `crane blob` verify blob digests against the
manifest descriptors, so their success is the assertion that the digest design works.

## LLM call budget

**14 total**, above the ~10 guideline, and here is the reasoning rather than a
silent overrun: the protocol has five events and two of them (manifest, blob) have
distinct by-tag and by-digest paths, so a suite that touched each once would already
be at nine. The budget is spent where it buys coverage — 9 calls exercise 15
endpoint behaviours in one server — and the `crane` test, which makes the most
requests, costs exactly **one** call by using deterministic handlers.

Total wall time for the suite is under 2s.

## Running

```bash
# Everything
CARGO_TARGET_DIR=… ./cargo-isolated.sh test --no-default-features --features oci-registry \
    --test server -- server::oci_registry --test-threads=100

# Pure logic only (instant)
… --test server -- server::oci_registry::digest_test --test-threads=100

# See crane's output
… --test server -- server::oci_registry::e2e_test::test_oci_registry_against_crane --nocapture
```

## Pointing a real client at the registry

Registries normally require HTTPS. For plain HTTP on loopback:

| Client | How |
|---|---|
| `crane` | Nothing needed — go-containerregistry auto-detects `127.0.0.1`/`localhost` as plain HTTP. `--insecure` also works and is harmless |
| `skopeo` | `--tls-verify=false`, e.g. `skopeo inspect --tls-verify=false docker://127.0.0.1:PORT/library/alpine:latest` |
| `oras` | `--plain-http` |
| `docker` | `{"insecure-registries": ["127.0.0.1:PORT"]}` in `/etc/docker/daemon.json`, then restart the daemon. **Not used by these tests** — it needs a running daemon and a global config change, which a test must not make |

## Offline guarantee

Every request is to `127.0.0.1`. Docker Hub, GHCR and every other real registry are
never contacted, and no image is ever pulled from the network.

## Fixtures

`CONFIG_JSON` (151 bytes) and `LAYER_TEXT` (30 bytes) live in `digest_test.rs` and
are imported by `e2e_test.rs`, so the two files cannot drift. Their lengths are
asserted, so an accidental edit fails loudly rather than silently changing every
digest in the suite.

## Not covered

- Push — not implemented; only the 405 refusal is asserted.
- `skopeo` / `oras` / `docker` / `containerd` — no test drives them.
- Manifest lists / image indexes over the wire (the descriptor logic is unit-tested
  in `index_children_get_real_digests_too`, but no e2e test serves one).
- Token-auth *completion* — the 401 challenge is asserted; there is no token endpoint.
- Concurrency: no test makes overlapping requests to one server.

`schema_guard_test.rs` verifies exact action depth/node/retained boundaries,
constructed10,000-level owned action and borrowed descriptor refusal, and the
parsed string-manifest depth boundary. Separator cases include valid double
underscore/repeated hyphen and invalid repeated dot/triple underscore/mixed
separators. The full21-test server suite passes with independent crane0.22.1;
existing connection bounds remain exercised.
