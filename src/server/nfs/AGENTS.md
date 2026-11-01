# NFS Protocol Implementation

**Status**: `DevelopmentState::Experimental`.

NFSv3 (RFC 1813) over TCP, default port 2049. 2049 is above 1023, so no privilege is required
and `privilege_requirement` is correctly `None` — a declaration here could never fire.

`nfsserve` v0.10 owns RPC, XDR, message framing and the MOUNT protocol. `LlmNfsFileSystem`
(`src/server/nfs/mod.rs`) implements its `NFSFileSystem` trait, and every trait method turns
into one LLM round-trip.

## Robustness: framing is `nfsserve`'s, and NetGet screens it

`nfsserve` owning RPC, XDR and message framing is a real simplification, but it is **not** a
safety guarantee, and the line above reads as though it were.

`nfsserve` 0.10.2 reads a length off the wire and allocates it with no sanity limit in two
places: `rpcwire.rs` resizes its fragment buffer by the 31-bit fragment length, and `xdr.rs`
resizes the `Vec<u8>` that a `dirpath`, a `filename`, a file handle and WRITE data each
deserialise into by a 32-bit length field. A ~40-byte `MOUNTPROC3_MNT` whose `dirpath` length
is `0xFFFFFFFF` therefore asks for a multi-gigabyte zeroed allocation **before any
authentication**. A non-last fragment with the EOF bit clear appends into one buffer
indefinitely.

The MOUNT path compounds it: `nfsserve`'s default `path_to_id` splits the dirpath on `/` and
calls `lookup()` per component, and every `lookup` is one `consult_llm` round-trip. So an
unauthenticated peer can turn one MOUNT call into an unbounded sequential chain of LLM calls,
saturating `--llm-max-concurrent` for every other server in the process.

### Both are now bounded, on NetGet's side of the socket

`NFSTcpListener` owns its own `accept()` loop, so there is no seam inside the crate. **NetGet
therefore binds the public listener itself** (`spawn_with_llm_actions`) and starts `nfsserve`
on a loopback-only ephemeral port, relaying each connection through `guard::serve_screened`
(`src/server/nfs/guard.rs`).

The screen reads every four-byte record marker and decides the fragment **from the number the
peer announced, before anything is read or allocated for it**:

| bound | value | why |
|---|---|---|
| `MAX_FRAGMENT_BYTES` | 2 MiB | twice the 1 MiB `wtmax` the default `fsinfo` advertises |
| `MAX_RECORD_BYTES` | 2 MiB | all fragments of one record, summed |
| `MAX_FRAGMENTS_PER_RECORD` | 64 | zero-length non-last fragments otherwise loop forever |
| `FRAGMENT_BODY_TIMEOUT` | 30s | an announced fragment that then stalls |
| `MAX_CONCURRENT_CONNECTIONS` | 256 | what makes "bounded per connection" bounded overall |
| `MAX_PATH_COMPONENTS` | 32 | MOUNT dirpath components, i.e. LLM calls |

A refusal is **refuse, not truncate**, and it is answered in NFS's own vocabulary rather than
dropped: an accepted reply carrying the call's own xid with `accept_stat = GARBAGE_ARGS`
("procedure can't decode params"), then the connection closes. The xid is recovered by reading
four bytes of the refused record and nothing else. It is deliberately *not* a
`crate::utils::WireFailure` string — the record-marking layer has no free-text field, and
inventing one would be the leak `WireFailure` exists to prevent. Every refusal logs a stable
tag: `decision=fail_closed_oversize_fragment`, `_oversize_record`, `_fragment_flood`,
`_fragment_stalled`, `_connection_cap`.

`LlmNfsFileSystem::path_to_id` overrides the crate's default rather than wrapping it, and
refuses an over-long path outright — resolving the first 32 components of a longer path would
hand back a directory the client did not ask for. `mount_handlers` turns the `Err` into
`MNT3ERR_NOENT`, so the peer gets a definite refusal and the reason is in the log under
`decision=fail_closed_path_components`.

`tests/server/nfs/dos_guard_test.rs` drives both from the wire.

### What is still exposed

- **The XDR decoder inside an admitted record is still the unchecked one.** Every length it
  reads now lives inside a record the screen already sized, so the worst it can ask for is
  `MAX_RECORD_BYTES` — bounded, not validated.
- **The backend listener is reachable by any local process.** It binds `127.0.0.1:0`, so
  nothing off-box can skip the screen, but a process on the same machine can. That is the
  standard cost of a proxy and there is no way around it without patching the crate.
- ~~**No per-connection idle timeout.**~~ **Fixed, September 2026** — see "Connection bounds"
  below. `FIRST_RECORD_READ_TIMEOUT` and `IDLE_BETWEEN_RECORDS_TIMEOUT` bound a peer that holds
  an open connection without sending a record, which previously only the concurrency cap
  limited.
- Because `nfsserve` spawns a task per RPC message, several `consult_llm` calls can still run
  concurrently for one peer — NetGet's per-connection Idle→Processing→Accumulating state
  machine is absent here — and this server calls `update_connection_stats` nowhere, so the rail
  shows no peers and no counters for it.

## No storage — and that is the whole design

There is no file table, no directory tree, no attribute cache, no backing store of any kind.
`LlmNfsFileSystem` holds an `OllamaClient`, an `Arc<AppState>`, a `ServerId`, an
`Arc<NfsProtocol>` and a status channel. Nothing else. Every `lookup`, `getattr`, `read`,
`readdir` — all of it comes back from the model.

This is the side of the line a file protocol is supposed to be on, and it is worth contrasting
with `src/server/webdav/`, which serves a real in-process `MemFs` and is marked `Incomplete`
for exactly that reason.

The cost is pushed onto the model: **file IDs must be stable**. If `lookup(dir=1,
"readme.txt")` returns 42 once and 43 the next time, or if `getattr(42)` reports a different
size than the last call, clients cache the difference and misbehave in ways that look like
server bugs. Say so in the instruction.

## The bug that made this protocol unusable

`NFS_OPERATION_EVENT` was declared with

```rust
.with_actions(vec![
    // Include all NFS response actions
    // The LLM will choose the appropriate response based on the operation type
])
```

— a comment where the actions should have been. `call_llm` builds the model's tool list from
`event.event_type.actions`, **not** from `get_sync_actions()`, so the model was offered
`set_memory` / `notify_operator` / `append_to_log` and nothing else. Every `nfs_*_response` it
produced was rejected as an unknown action, retried twice, and failed. Every operation then
fell through to `error!("No valid nfs_..._response action in LLM response")` and returned
NFS3ERR. **No NFS operation could ever be answered.**

Worse in a dev build: `call_llm` reacts to `EventType::has_no_usable_actions()` with a
`debug_assert!(false, ...)`, so the connection task panicked — silently, while the server
still reported `Running`.

The event now carries `nfs_response_actions()`, the same list as `get_sync_actions()`.

## Events

One event type, `nfs_operation`, for all twelve procedures:

| field | meaning |
|---|---|
| `operation` | `lookup`, `getattr`, `setattr`, `read`, `write`, `create`, `mkdir`, `remove`, `rename`, `readdir`, `symlink`, `readlink` |
| `params` | operation-specific: `fileid`, `dirid`, `filename`, `offset`, `count`, `data`, `mode`, `uid`, `gid`, `start_after`, `max_entries`, ... |

The operation name is the only thing telling the model which response to send, which is why
every response action is advertised on this one event rather than split across several.

## Actions

Ten response actions, one per operation shape. All are advertised on `nfs_operation`.

| action | read back by | key fields |
|---|---|---|
| `nfs_lookup_response` | `lookup` | `fileid`, `error` |
| `nfs_getattr_response` | `getattr` | `file_type`, `mode`, `size`, `uid`, `gid`, `atime`/`mtime`/`ctime` |
| `nfs_setattr_response` | `setattr` | same attribute fields |
| `nfs_read_response` | `read`, `readlink` | `data`, `eof` |
| `nfs_write_response` | `write` | `size`, `mode`, `mtime` |
| `nfs_create_response` | `create`, `create_exclusive`, `symlink` | `fileid`, `size`, `mode` |
| `nfs_mkdir_response` | `mkdir` | `fileid`, `mode` |
| `nfs_remove_response` | `remove` | `success` (**required, and honoured** — see below) |
| `nfs_rename_response` | `rename` | `success` (**required, and honoured** — see below) |
| `nfs_readdir_response` | `readdir` | `entries[{name, fileid, attr?}]`, `eof` |

Any response may carry `"error"` instead; the mapping to NFS status is coarse — the string is
logged, not parsed, and each operation returns its own fixed code (`lookup`/`remove` →
NFS3ERR_NOENT, `read`/`write`/`setattr`/`create`/`mkdir`/`rename` → NFS3ERR_ACCES, `readdir` →
NFS3ERR_NOTDIR, `create_exclusive` → NFS3ERR_EXIST, `readlink` → NFS3ERR_INVAL). Returning
`"error": "Is a directory"` will not produce NFS3ERR_ISDIR.

### `success` on remove and rename

Both actions declare `success` as a required boolean, and for a long time **neither read it**.
Only a non-empty `error` string produced a failure, so `{"type": "nfs_remove_response",
"success": false}` — the obvious way for a model to refuse — was reported to the client as a
completed removal. Same for rename.

Now: `true` performs the operation, `false` is NFS3ERR_ACCES logged `decision=model_reject`,
and an answer that omits the flag is NFS3ERR_SERVERFAULT logged
`decision=fail_closed_no_success` rather than an assumed success. SERVERFAULT for the omission
follows the same reasoning as the table below — a definite code like NFS3ERR_NOENT would tell
the client the file is gone, which it caches and acts on.

### When the model does not answer at all

Those codes are for the model *rejecting* an operation. Two other things can happen, and both
used to be answered as if the model had rejected it:

| situation | status | why |
|---|---|---|
| `call_llm` returned `Err` (backend down, malformed response) | **NFS3ERR_SERVERFAULT** (10006) | RFC 1813's "an error occurred on the server which does not map to any of the legal NFSv3 error values" |
| `call_llm` returned `Err` and `crate::llm::is_overload_error` matches | **NFS3ERR_JUKEBOX** (10008) | "resource temporarily unavailable" — retryable, the NFS equivalent of HTTP's 503 + `Retry-After` |
| the model answered, but with no usable `nfs_*_response` | **NFS3ERR_SERVERFAULT** | silence is not a denial |

`LlmNfsFileSystem::llm_failure` and `llm_no_answer` are the only two places that produce these,
and both log at ERROR on both channels. The point is that a no-answer must never be reported as
a *definite* one: NFS3ERR_NOENT told the client the file does not exist when in truth the server
never managed to ask, and NFS3ERR_IO claimed a hard I/O error on the object. `nfsserve` builds
the RPC reply (MSG_ACCEPTED / SUCCESS, xid echoed) from whatever status is returned, so the
client gets a failed operation rather than an RPC that never completes.
`tests/server/nfs/llm_failure_test.rs` asserts exactly that on the wire.

`mode` is a **decimal** number in JSON: 420 is `0644`, 493 is `0755`.

### Removed

`mount_filesystem` and `unmount_filesystem` were declared as async actions. Both parsed a
`path`, discarded it, and returned `ActionResult::NoAction` — nothing in `nfsserve` or in
`LlmNfsFileSystem` has any notion of an export to mount. Removed.

### Field-name mismatches fixed

Two executors read fields the action definitions never documented, so a model following the
documentation always hit the default:

- `mkdir` read `action["dirid"]` while `nfs_mkdir_response` documents `fileid`. Every
  documented response produced fileid 0, and the client got a directory it could not enter.
- `readdir` read `action["end"]` while `nfs_readdir_response` documents `eof`. Listings were
  always reported complete.

Both now prefer the documented name and still accept the old one.

## Text only — the binary limitation

`nfs_read_response.data` is a `String`, and the `data` field of a write event is a `String`.
Actions must not carry raw bytes or base64 (models cannot reliably produce or parse them), and
no binary path was ever built here.

Concretely:

- **Reads**: `data.as_bytes()` goes on the wire verbatim. Any file whose bytes are not valid
  UTF-8 cannot be served.
- **Writes**: `String::from_utf8_lossy(data)`. A client writing a JPEG hands the model a string
  full of U+FFFD, and the original bytes are gone. If the model then echoes that back on the
  next read, the file is corrupt.

This is a real limitation of the design, not a gap to be filled by adding a hex field — the
project rule forbids one. Serving binary content over NFS is out of scope for this protocol.

## Performance

One model round-trip per NFS procedure. `ls -l` in a directory of ten files is a `readdir`
plus a `getattr` each: eleven calls, tens of seconds. `mount` alone costs several. This is
usable for a honeypot or a demo and unusable for anything else — reach for script handlers
(`event_pattern: "nfs_operation"`) if you need throughput.

## Startup and lifecycle

`NFSTcpListener::bind(...)` runs before the spawn and propagates with `?` and a context, so a
bind failure surfaces as a startup error rather than a server stuck in `Running`. The returned
address uses `get_listen_port()`, so an ephemeral port is reported correctly. The
`handle_forever()` task is registered with `AppState::register_server_task()`, so `stop_server`
releases the socket.

`consult_llm` passes `connection_id: None` — `nfsserve` manages its own connections and does
not expose them, so per-connection state and per-connection scheduled tasks are unavailable
here, and the access log shows no client address.

## Limitations

- NFSv3 only, TCP only. No NFSv2, no NFSv4, no UDP.
- Binary files (above).
- One LLM call per operation (above).
- No per-connection tracking (above).
- `nlink` is always 1, `fsid` always 0, `used` always equals `size`.
- Error strings map coarsely to NFS status codes (above).
- No locking (NLM), no ACLs, no extended attributes.
- Real clients probe aggressively on mount; a model that answers inconsistently will produce
  mount failures whose cause is not obvious from the client's error message.

## Manual verification

```bash
./cargo-isolated.sh run --no-default-features --features nfs --release
# "listen on port 12049 via nfs. Root directory (fileid 1) contains readme.txt (fileid 2,
#  regular file, 14 bytes, content 'Hello from NFS'). Keep file IDs stable."

showmount -e 127.0.0.1                      # exports
# Linux:
sudo mount -t nfs -o vers=3,port=12049,mountport=12049,tcp 127.0.0.1:/ /mnt/netget
# macOS:
sudo mount -o vers=3,port=12049,mountport=12049,tcp,resvport 127.0.0.1:/ /mnt/netget
ls -l /mnt/netget && cat /mnt/netget/readme.txt
```

Expect each command to take seconds, not milliseconds — that is the per-operation LLM call.
Watch `netget.log` at DEBUG to see the operation sequence the client actually issues; it is
longer than you would guess.

## Testing

`tests/server/nfs/test.rs` — connection lifecycle, port configuration, multiple connections,
stop/start, **and a mocked MOUNT + LOOKUP + READ** (`test_nfs_mount_and_lookup`), which
asserts the model'''s answers reach the wire. This section used to say the suite "does not
mount a filesystem" and call for exactly that test; it exists.

`llm_failure_test.rs` asserts SERVERFAULT on the wire when the backend fails, and that the
reply carries no trailing bytes.

`dos_guard_test.rs` — the two pre-auth denial-of-service paths. A record marker announcing
2 GiB is answered with a well-formed `GARBAGE_ARGS` reply carrying the attacker's own xid, the
connection is closed, and a fresh client still mounts afterwards (the control that would catch
a process-wide abort). A 200-component MOUNT dirpath is answered `MNT3ERR_NOENT` with the
lookup mock recording **zero** calls — the mock answers every lookup *successfully* on purpose,
so nothing but the bound stops the walk. Both were verified by removing the bound: the first
times out waiting for a reply that never comes, the second records 200 LLM calls and answers
`MNT3_OK`.

## References

- [RFC 1813: NFS Version 3](https://tools.ietf.org/html/rfc1813)
- [RFC 1831: RPC v2](https://tools.ietf.org/html/rfc1831) / [RFC 1832: XDR](https://tools.ietf.org/html/rfc1832)
- [nfsserve](https://docs.rs/nfsserve)

## Connection bounds

Before September 2026 this server accepted without limit and bounded no read in time, so a peer
that connected and said nothing held a socket, a task and an `AppState` entry forever, and a
hundred of them was a free denial of service on a server that would happily accept a hundred
more. It now declares both halves; the constants and the reasoning live beside them in
`src/server/nfs/guard.rs`.

| Bound | Value | Why this number |
|---|---|---|
| `FIRST_RECORD_READ_TIMEOUT` | 30s | ONC RPC over TCP is client-speaks-first and a real client sends NULL or MOUNT immediately. `src/server/nfs/AGENTS.md` said in as many words that no per-connection idle timeout existed; this is it. |
| `IDLE_BETWEEN_RECORDS_TIMEOUT` | 900s | Long on purpose: a mounted filesystem with no I/O is genuinely silent for long stretches, and that is the normal state of a mount rather than a symptom. The Linux client reconnects its TCP transport transparently, so a reaped idle connection costs a mount nothing observable. |
| `MAX_CONCURRENT_CONNECTIONS` | 256 | Unchanged in value — this is where `accept_bounded::DEFAULT_MAX_CONNECTIONS` came from, and the constant now *is* that one so the two cannot drift. The hand-rolled `Semaphore` is replaced by the shared helper. Refusal: **a plain close.** Every refusal this screen can express is an accepted RPC reply carrying the *call's own* xid; a peer turned away at accept has sent no call and therefore no xid. |

**NetGet's own NFS client *speaks inside `connect()`*, so it is never the silent peer this
bound closes:** `Nfs3ConnectionBuilder::mount()` issues PMAPPROC_GETPORT and MOUNTPROC3_MNT
before the first model turn — `PROTOCOL_QUALITY.md`'s three-state test.

**The deadline covers the read and nothing else.** One `lookup` here is one LLM round-trip and may be parked for a human, so the deadline must not count the wait: `awaiting_reply` is set when a record reaches the backend and cleared when the backend answers, and while it is set the deadline re-arms instead of closing. The LLM round-trip, and a `manual`
rule parking an event for a human (`src/state/intercepts.rs`, 300s by default), are outside
every deadline here, so an answer that takes minutes can never close the connection it is an
answer for. That is the `.connectionless()` lesson in the project `AGENTS.md` read in reverse:
TFTP evicted live transfers because "idle" was measured wrongly.

`tests/tcp_server_bounds_ratchet_test.rs` fails the build if either bound is removed;
`tests/accept_bounded_test.rs` drives the shared helper, including the guarantee that a busy
connection is never reported as idle.

## No peer handle — `[ message this peer ]` / `[ disconnect this peer ]` stay disabled

NFS is a **relay**, for the reason the module header explains: `NFSTcpListener` owns its own
accept loop, so NetGet binds the public listener itself and runs `nfsserve` on a loopback-only
ephemeral port behind `guard.rs`. The socket the NFS session sees belongs to the relay. A peer
handle on the public half would write bytes past the guard that decides every RPC record before
it is read; one on the backend half would address the relay rather than the client.

And an RPC reply is addressed by the xid of the call it answers — `guard.rs` goes to some trouble
to echo exactly that on a refusal. Nothing outside the exchange knows an xid the client is waiting
on, so an injected reply is not a message, it is noise the client discards.

The dashboard renders that as a dim button reading "this protocol cannot message a peer from
here yet", which is the honest rendering. `tests/peer_handle_coverage_ratchet_test.rs` carries
this protocol on its shrink-only baseline with the reason above, and re-derives the reason from
source on every run, so if the mechanism changes the build fails rather than the file going
quietly stale.
