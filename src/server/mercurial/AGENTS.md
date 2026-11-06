# Mercurial HTTP Protocol Implementation

Read-only Mercurial server speaking the HTTP wire protocol (version 1) on hyper. The model — or
a static or script handler — describes a repository **history** (commits with author, date,
message, parents, branch and text files) in one `hg_repository` action, and the server derives
everything Mercurial computes for itself: filelog, manifest and changelog texts, their revlog
nodes, and the changegroup `hg clone` / `hg pull` applies. A real `hg` clones it, and `hg verify`
passes.

**State**: Experimental. **Privilege**: none; the default port 8000 is above 1024.
**Spec**: [WireProtocol](https://www.mercurial-scm.org/wiki/WireProtocol),
[HttpCommandProtocol](https://wiki.mercurial-scm.org/HttpCommandProtocol); the formats below
were checked against the installed `hg` 7.2.4's own source (`httppeer.py`,
`wireprotov1peer.py`, `changegroup.py`, `changelog.py`, `setdiscovery.py`, `exchange.py`).

## Commands

| Request | Event | Response |
|---|---|---|
| `?cmd=capabilities` | `hg_capabilities` | newline-separated capability names |
| `?cmd=heads` | `hg_heads` | space-separated 40-hex nodes **and a trailing newline** — the client decodes `d[:-1]` |
| `?cmd=branchmap` | `hg_branchmap` | one `<url-quoted branch> <node>…` line per branch |
| `?cmd=listkeys&namespace=…` | `hg_listkeys` | `key\tvalue` per line |
| `?cmd=known&nodes=…` | `hg_known` (only when `nodes` is non-empty) | one `0`/`1` per node |
| `?cmd=lookup&key=…` | `hg_lookup` | `1 <node>\n`, or `0 <reason>\n` |
| `?cmd=batch&cmds=…` | one event per sub-command | the sub-commands' answers, `:`-escaped and joined by `;` |
| `?cmd=getbundle` (GET or POST) | `hg_getbundle` | zlib-compressed version-1 changegroup |
| `?cmd=unbundle`, `?cmd=pushkey` | — | `403`, push is not implemented |
| any other `cmd` | — | `404` |

Every response carries `Content-Type: application/mercurial-0.1`; `httppeer` refuses anything
else as "not an hg repository". With 0.1 the client **zlib-decompresses** the body of a
compressible command, and `getbundle` is one — so the changegroup is zlib-compressed and carries
no `HG10UN` header (the bundle1 `getbundle` reply is a bare cg1 stream, read by
`cg1unpacker(f, 'UN')`). Query arguments are form-decoded (`+` is a space), because the node lists
in `heads`, `common` and `nodes` are space-separated.

**`batch` is not optional.** hg 7.x sends every group of two or more batchable commands as one
`batch` request whether or not the server advertises it (`wireprotov1peer.peerexecutor
.sendcommands`), so a clone's discovery always arrives as `cmd=batch&cmds=heads ;known nodes=`.
`batch` carries `capabilities`, `heads`, `branchmap`, `listkeys`, `known` and `lookup`, at most
`MAX_BATCH_COMMANDS` (16) of them; arguments and answers use `wireprototypes`' escaping
(`:` → `::`, `,` → `:c`, `;` → `:s`, `=` → `:e`). Any other sub-command, or an empty or oversized
batch, is refused with an `application/hg-error`. Each sub-command raises its own event, and the
first one that fails decides the whole response.

## What the model sees and controls

Every event carries `repository` and `client_ip`; `hg_listkeys` adds `namespace`, `hg_known`
`nodes`, `hg_lookup` `key`, and `hg_getbundle` the raw `heads` and `common` arguments.

**`hg_repository` (`commits`) is accepted for every event**, and is what makes a clone work. One
static or script rule on `*` answering with the same history serves the whole exchange:
capabilities, `heads`, `known`, `lookup`, `branchmap` and `getbundle` are all derived from it.
Each commit is an object:

| field | meaning | default |
|---|---|---|
| `message` | required; stored as `changelog.stripdesc` stores it | — |
| `id` | a label of the caller's choice, used only to name parents | `#<index>` |
| `parents` | up to two earlier ids; `[]` is a root | the previous commit |
| `author` | `Name <email>`, one line | `NetGet <netget@localhost>` |
| `date` | RFC 3339 (`2026-10-31T12:00:00+01:00`), Unix seconds, or hg's `"<secs> <tz>"` | `1700000000` UTC |
| `branch` | letters, digits, `- _ . / +`; not `.`, `tip`, `null` or a number | `default` |
| `files` | `[{"path", "content" (text), "executable"?}]` — added or changed | `[]` |
| `removed` | paths this commit deletes | `[]` |

A commit starts from its first parent's files; a merge also keeps every path only its second
parent has, and a path both parents have keeps the first parent's version unless listed. Commits
must be listed parents-first, and their order is the revision order. The model never writes a
node id: they are SHA-1 hashes the server computes, so **the same description must be given on
every request** — a different description is a different repository, and a client asking
`getbundle` for a head an earlier `heads` reply named gets a refusal.

The per-command actions remain for metadata-only answers: `hg_capabilities` (`capabilities`),
`hg_heads` (`heads`), `hg_branchmap` (`branches`), `hg_listkeys` (`keys`), `hg_send_bundle`
(an empty changegroup), and `hg_error` (`message`, `code`). `hg_known` and `hg_lookup` accept only
`hg_repository` and `hg_error` — answering them needs the history. There are no async actions.

### How the history becomes revlogs (`changegroup.rs`)

- **Node** = `sha1(min(p1, p2) + max(p1, p2) + text)` (`storageutil.hashrevisionsha1`).
- **Filelog text** = the content, wrapped in an empty metadata block `\x01\n\x01\n` when it
  itself starts with `\x01\n` (`filelog.add`). A file whose content equals its first-parent
  revision reuses that node.
- **Manifest text** = `path\0<hex filenode>[x]\n` per file, sorted by path. Its parents are the
  parent commits' manifests; an unchanged non-merge manifest reuses its parent's node.
- **Changelog text** = `hex(manifest)\nauthor\n<secs> <tz>[ branch:<name>]\n<touched files>\n\n<message>`
  (`changelog.add`), where `tz` is seconds *west* of UTC and the touched files are those added,
  changed or removed relative to the first parent.
- **Changegroup** = cg1: a changelog group, a manifest group, then one group per file. Each chunk
  is a 4-byte length, `node p1 p2 linknode` and one delta hunk replacing the whole base (the
  previous chunk in the group, or the revision's `p1` for the first) with the full text.
  `getbundle` sends `ancestors(heads) − ancestors(common)`, and only the manifests and file
  revisions the client's changesets do not already reference; each is linked to the first
  missing changeset that uses it, which is always one that touched it.

### Bounds (all refusals, never truncation)

| constant | value |
|---|---|
| `MAX_COMMITS` | 256 |
| `MAX_CHANGES_PER_COMMIT` (`files` + `removed`) | 256 |
| `MAX_PATHS` (distinct, whole history) | 1024 |
| `MAX_PATH_BYTES` | 255 |
| `MAX_FILE_BYTES` | 1 MiB |
| `MAX_TOTAL_CONTENT_BYTES` | 8 MiB |
| `MAX_MANIFEST_BYTES` (sum of distinct manifest texts — the commits × paths cost) | 8 MiB |
| `MAX_MESSAGE_BYTES` / `MAX_AUTHOR_BYTES` / `MAX_ID_BYTES` / `MAX_BRANCH_BYTES` | 16 KiB / 512 / 64 / 64 |

The changegroup has no cap of its own: it is bounded by these (tens of MiB at the very worst),
and the peer chooses only which part of it to receive. Paths are refused when absolute, when they
contain an empty, `.` or `..` component, a `.hg` component (any case), NUL, CR, LF or a
backslash, or when a path would be both a file and a directory. Dates must fit Mercurial's 32
bits with an offset of at most 14 hours.

### The server refuses to put nonsense on the wire

- **Node IDs from per-command actions are validated.** Anything that is not exactly 40 hex
  characters is dropped with a WARN; `heads` also accepts a whitespace-separated string.
- **Capabilities are fixed** to what this server implements — `batch`, `branchmap`,
  `getbundle`, `known`, `listkeys`, `lookup` — whatever the model lists. Advertising `unbundle`
  or `pushkey` would invite a push that gets a `403`; `bundle2` would make the client negotiate a
  format this server never speaks.
- **A history the server cannot build is refused** as Mercurial's own error: `200` with
  `Content-Type: application/hg-error`, which `httppeer` raises as `OutOfBandError`, so `hg`
  prints `abort: remote error:` and a fixed sentence. The reason (which commit, which path) is
  logged as `decision=fail_closed_invalid_repository`. A `getbundle` for an unknown head is
  refused the same way (`decision=refused_unknown_head`).

### Failure behavior

| Situation | Result |
|---|---|
| `hg_error` action | that HTTP status and message; `decision=model_reject` |
| `hg_repository` the server cannot build | `application/hg-error`; `decision=fail_closed_invalid_repository` |
| Action for a different command, or no action | `500` carrying only a `WireFailure` category; `decision=fail_closed_no_action` |
| LLM/handler call fails, backend saturated | `503` + `Retry-After: 1`; `decision=fail_closed_overloaded` |
| LLM/handler call fails otherwise | `500` carrying only a category; `decision=fail_closed_llm_error` |
| Request body over `MAX_REQUEST_BODY_BYTES` (1 MiB) | `413`, nothing buffered past the cap |
| `heads` with no valid node, or an empty history | the null node `000…0` (an empty repository) |

The peer gets a category, the log gets the error: nothing derived from a failure — backend URL,
model name, anyhow chain, or the description's own ids — reaches an `hg` client.

## Implementation

`mod.rs` — hyper service, query parsing, one handler per command, all routed through
`call_llm`, so script and static `event_handlers` work. `actions.rs` — action and event
definitions and capability filtering. `changegroup.rs` — the history builder and cg1 encoder.

**No storage**: nothing is written to disk, no `.hg` directory exists, nothing shells out to
`hg`, and nothing survives a request beyond the per-connection list of repository names used for
the UI. Every request rebuilds the history from the action that answered it.

**Request bodies are bounded.** Only `getbundle` may have a body (hg uses POST only for
arguments too long for a URL), read through `http_body_util::Limited` at 1 MiB and refused with
`413` beyond that.

## Connection bounds

| Bound | Value | Why this number |
|---|---|---|
| `FIRST_BYTE_READ_TIMEOUT` | 30s | HTTP is client-speaks-first, so a peer that has sent nothing has begun no command. Enforced with `TcpStream::peek` before the socket reaches hyper, so the request line is still there afterwards. |
| `IDLE_BETWEEN_REQUESTS_TIMEOUT` | 900s | The wait *between* commands, not a bound on a transfer. A clone issues `capabilities`, `batch` (`heads` + `known`) and `getbundle` on one keep-alive connection, and each answer is a `Full<Bytes>` built before the response is returned. |
| `MAX_CONNECTIONS` | 256 | Refusal: **HTTP/1.1 `503 Service Unavailable` with `Retry-After`** — hg reports the status rather than an unexplained reset. |

**There is no NetGet Mercurial client** — `src/client/mercurial/` holds an `AGENTS.md` and no
Rust, and nothing registers it.

**The deadline bounds the silence, not the transfer.** hyper owns every read once
`serve_connection` starts, so the idle bound is a watchdog over `ConnectionActivity`, which
reports a connection with a command in flight as not idle — an LLM round-trip, or a `manual`
rule parked for a human, can never close the connection it is an answer for.
`tests/server/mercurial/connection_bounds_test.rs` drives both halves from the wire;
`tests/tcp_server_bounds_ratchet_test.rs` fails the build if either bound is removed.

## Not implemented

Push (`unbundle`, `pushkey`), bundle2 (hg 7.x still pulls bundle1 from a server that does not
advertise `bundle2`), stream clones, `clonebundles`, bookmarks and tags (hg
reads `listkeys` only from a server advertising `pushkey`; every changeset is public), copy and
rename metadata, symlinks, binary file content, obsolescence markers, largefiles,
authentication, and SSH transport.

**Request-only.** `metadata()` declares `.request_only(…)`: "Mercurial is HTTP request/response; a
server cannot send a peer anything unprompted". The dashboard's `[ send message ]` on a peer is
disabled and shows that reason, and MCP `send_to_peer` refuses with it.

## Example

```json
{"type": "open_server", "port": 8000, "base_stack": "mercurial",
 "event_handlers": [{"event_pattern": "*", "handler": {"type": "static", "actions": [
   {"type": "hg_repository", "commits": [
     {"id": "init", "date": "2026-10-01T09:00:00+00:00", "message": "Initial commit",
      "files": [{"path": "README", "content": "Hello from NetGet\n"}]},
     {"id": "docs", "date": "2026-10-02T09:00:00+00:00", "message": "Expand the README",
      "files": [{"path": "README", "content": "Hello from NetGet\nServed over hg.\n"}]}]}]}}]}
```

then `hg clone http://127.0.0.1:8000/hello-world`.

## Maturity

`tests/server/mercurial/real_client_test.rs` drives the real `hg` 7.2.4 — not `#[ignore]`d, and
it **fails**, naming `brew install mercurial`, when hg is absent:

- `hg debugcapabilities` — the handshake, and that `unbundle`/`pushkey`/`bundle2` are never
  advertised whatever the model asks for;
- `hg clone` (discovery batched as `heads ;known`) of a five-commit history (named branch, merge, removal, executable file, empty file,
  a file starting with the metadata marker), then **`hg verify`** — which recomputes every node
  from `(p1, p2, text)` — and `hg log`, `hg cat`, `hg manifest -v` asserting the exact history
  and bytes; `hg id <url>` through `lookup`; `hg clone -r 1` + `hg pull` through `lookup`, a
  non-empty `known` and a partial changegroup whose first deltas are against revisions the client
  already holds;
- a history the server refuses, reaching hg as `abort: remote error:` with the reason only in
  the log.

`tests/server/mercurial/changegroup_test.rs` covers every `MAX_*` bound at the limit and one past
it, and every refusal. That is the evidence Beta asks for (one real third-party client completing
the protocol's own exchange); the rating is the maintainer's call. Not yet there for Stable: one
client only, no pcap oracle (Wireshark has no Mercurial dissector — the bytes are HTTP to it), and
no fuzz target.
