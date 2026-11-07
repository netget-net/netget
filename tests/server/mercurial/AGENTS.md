# Mercurial HTTP Protocol Tests

| file | tests | what it holds |
|---|---|---|
| `real_client_test.rs` | 3 | the real `hg` 7.2.4: handshake; clone + verify + cat + log + id + clone -r + pull; a refused history |
| `changegroup_test.rs` | 12 | the history builder: every `MAX_*` bound, every refusal, lookup, changegroup selection |
| `e2e_test.rs` | 5 | the metadata commands against `reqwest` — capabilities, heads, branchmap, listkeys, not-found |
| `connection_bounds_test.rs` | 2 | the first-byte deadline and the idle watchdog, from the wire |

## The real client is the evidence

`mercurial` is Beta for clone and pull on this file alone; push, bundle2, bookmarks and tags are
not implemented and not claimed.

`real_client_test.rs` drives the `hg` binary (a Python program sharing no code with the
hand-written server). It **fails, never skips**, when `hg` is absent, naming
`brew install mercurial`. Every `hg` run sets `HGRCPATH=""` and `HGPLAIN=1`, so nothing in the
invoking user's `~/.hgrc` can change what is parsed.

- **Handshake** (`hg debugcapabilities`): `httppeer` accepts the reply only with
  `Content-Type: application/mercurial-*`; the mocked model asks for `unbundle`, `pushkey` and
  `bundle2`, and hg must see none of them.
- **Clone** (static `*` → one `hg_repository` action, so one LLM call: startup; discovery
  arrives as one `batch` of `heads` and `known`, which hg 7.x sends unadvertised): five commits
  with a named branch, a merge, a removal, an executable file, an empty file and a file starting
  with filelog's `\x01\n` marker. `hg verify` recomputes every changelog, manifest and filelog
  node from `(p1, p2, text)` — the assertion that the texts are exactly Mercurial's. `hg log`
  is compared line for line (rev, parents, branch, author, `hgdate`, first line, files), the full
  description of one commit is compared after `stripdesc`, `hg cat` and `hg manifest -v` assert
  bytes and modes, and the checked-out working copy is read back. `hg id <url>` resolves `tip`
  through `lookup`. `hg clone -r 1` then `hg pull` drives `lookup`, a non-empty `known`, and a
  partial changegroup whose first deltas start from revisions the client already holds; both
  clones must end with the same nodes.
- **Refusal** (mocked model answering `hg_capabilities` with a history naming an
  unknown parent): hg must fail with `remote error:` and the server's fixed sentence, the
  description's ids must not appear in hg's output, and the server must log
  `decision=fail_closed_invalid_repository`.

The expected timestamps are computed from the RFC 3339 dates in the description
(`2026-10-01T09:00:00+02:00` is `1790838000 -7200` — Mercurial stores the offset *west* of UTC).

## LLM call budget

All mocked; no Ollama is contacted. Each test pins its rules with `.expect_calls(...)` and ends
with `wait_for_mocks(30)` then `verify_mocks()`.

| test | model calls |
|---|---|
| `real_client_test` handshake | 2 (startup, `hg_capabilities`) |
| `real_client_test` clone | 1 (startup; every request is the static rule) |
| `real_client_test` refusal | 2 (startup, `hg_capabilities` — the history is refused at the handshake) |
| `e2e_test` | 2 per test, 3 for not-found |
| `changegroup_test` | 0 (calls the library directly) |

## What the reqwest tests are for

`e2e_test.rs` pins the per-command metadata actions and response framing (`heads` is
newline-terminated; branchmap lines; listkeys tabs; capability filtering). A generic HTTP client
proves an HTTP server answered, not that the protocol on top is right, so none of it is maturity
evidence; the real-client tests are.

## Not covered

No pcap oracle (Wireshark has no Mercurial dissector; the bytes are plain HTTP to it), no fuzz
target, and no second independent client. Push is not implemented, so nothing tests it.

## Running

```bash
./cargo-isolated.sh test --no-default-features --features mcp-stdio,mcp-http,sqlite,terminal-snapshot \
  --test server -- server::mercurial:: --test-threads=16
```
