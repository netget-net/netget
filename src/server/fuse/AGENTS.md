# FUSE local filesystem — Experimental

A directory on this machine whose every file operation the model answers. **It is a server
only: the kernel's FUSE driver is the client**, and the processes using the mount (`ls`, `cp`, an
editor, Python) are what drive it. There is no network, no port and no NetGet client role — a
"FUSE client" would be the kernel, which NetGet cannot be.

| File | What it does |
|---|---|
| `mod.rs` | settings, the fusermount3 mount (socket pair, `_FUSE_COMMFD`, SCM_RIGHTS) and the unmount guard, the `fuser::Filesystem` that answers from the tree on fuser's thread, the bounded queue and the one worker per mount that asks the model under a deadline |
| `actions.rs` | events, actions, startup parameters, metadata |
| `src/server/described_tree.rs` | the model-described tree and the overlay: description parsing (iterative, every bound), reads, every mutation as a pure function; compiled on every Unix so its tests and fuzz target run off Linux |

## Platform and crate

**Linux only** (`#[cfg(target_os = "linux")]` on the module, the registration and the Linux
half of the tests; the `ALL_KNOWN_PROTOCOLS` row says "a Linux build"). The kernel's FUSE driver
is reached through `/dev/fuse`, mounted by the setuid `fusermount3` from fuse3 — the same helper
libfuse uses — so NetGet links no C library and needs no privilege of its own.

**fuser 0.18** (MIT, July 2026, `default-features = false`). Without its `libfuse` feature its
build script selects the pure-Rust mount on Linux and links nothing. It is a dependency of
`[target.'cfg(target_os = "linux")'.dependencies]` only: on macOS the same build script requires
macFUSE through pkg-config (or the `macos-no-mount` feature, which cannot mount), so putting it
anywhere else would make every macOS build depend on a kernel extension. macFUSE and FUSE-T
would fit the system-library rule only as a new default-off library feature, and neither can be
installed on the development machine; that is the reason there is no macOS support, not a
judgement that it is unwanted.

fuser's own `Session::new` refuses `AutoUnmount` without `allow_other`, which an unprivileged
user cannot have unless `/etc/fuse.conf` says `user_allow_other`. fusermount3 itself has no such
rule (measured: fuse3 3.18.2 keeps an `auto_unmount` helper running for a plain user mount). So
`mount()` does what libfuse does — a socket pair, `fusermount3 -o …,auto_unmount -- <dir>` with
`_FUSE_COMMFD` naming one end, the `/dev/fuse` descriptor received over it with SCM_RIGHTS —
and hands the descriptor to `fuser::Session::from_fd`. fuser then does only the protocol.

`fusermount3` is declared as `ProtocolDependency::ToolInPath`, so a start on a machine without
it is refused before anything is registered, with `apt-get install fuse3` as the hint. A missing
`/dev/fuse` is refused by `spawn()` naming `modprobe fuse`.

## Startup

| Parameter | Meaning |
|---|---|
| `mount_point` (required) | an existing empty directory, or a new one in an existing directory (created, and removed again at stop — the same "clean up only what we made" rule as `named_pipe`'s FIFOs). Not empty, not a directory, or already a FUSE mount: refused |
| `read_only` | mounted `ro`: every change is EROFS from the kernel or from this server, and the model is never asked about one |
| `allow_other` | other users (root included) may use the mount, with the kernel still checking each mode (`default_permissions` is always on). Needs root or `user_allow_other` |
| `decision_timeout_secs` | how long a process waits for a description or decision before EIO (1–600, default 60) |
| `max_overlay_bytes` | the overlay's bound (default 64 MiB, at most 1 GiB) |

There is no port (`NO_WELL_KNOWN_PORT` in `tests/well_known_port_declaration_test.rs` says so),
and privilege is `None`: fusermount3 is the setuid part. `spawn()` returns only after the
kernel's INIT handshake has completed and a `stat` of the mount point shows a different device
from its parent's, so a mount that did not come up is `Err` and `ServerStatus::Error`. The
returned address is the `127.0.0.1:0` placeholder the other local servers use.

## What the model decides, and what it does not

**Directories are described lazily, once each.** The first lookup or listing inside a directory
nobody has described raises `fuse_describe_directory`; the answer (`fuse_directory`) is kept for
the life of the mount, and every lookup, getattr, readdir, read and readlink after it is Rust
reading the tree at no model cost. An answer may describe subdirectories inline (their own
`entries`), so a model that knows the whole tree describes it in one answer at the root; a
subdirectory without `entries` is asked about when first visited. This was chosen over one
description at mount because a tree is often far larger than anyone looks at, and because
`spawn()` asking the model would make a start depend on a model call. Model calls for
descriptions are bounded by the number of directories (65 536 entries) times three attempts.

`fuse_deny` to a description makes that directory read as the errno for the life of the mount
(asked once). A description that fails — backend error, deadline, silence, an answer that breaks
a bound — is EIO and is asked again on the next access, at most three times in all; after that
the directory reads as EIO without asking.

The vocabulary is the other file servers': `kind` file/dir/symlink, `mode` as a decimal number
(420 is 0644), `mtime` in Unix seconds, `entries` for a listing (9P's), `uid`/`gid`, `target` for
a symlink. File content is `src/server/described_disk.rs`'s, as NBD, iSCSI and NVMe/TCP describe
a disk: `text` (UTF-8), `hex`, or `extents` (`{offset, text}`, `{offset, hex}`, `{offset, length,
fill}`) over a `size`, with uncovered bytes reading as zeroes, and `errors` — byte ranges whose
reads fail with an errno the model names. The key names the encoding; nothing is base64.

**Every change is one decision**: `fuse_create` (open with O_CREAT; mknod, mkfifo and bind,
with `kind` saying file, fifo, socket, char or block),
`fuse_write`, `fuse_truncate` (a setattr with a size), `fuse_setattr` (chmod, chown, utimes),
`fuse_mkdir`, `fuse_unlink`, `fuse_rmdir`, `fuse_rename`, `fuse_symlink`. Each is answered
`fuse_allow` (applied to the overlay; the process gets success) or `fuse_deny` with an errno
(EACCES, EPERM, EROFS, ENOSPC, EDQUOT, …; the process gets it and nothing changes). Rust checks
first what the kernel and POSIX would refuse anyway — EEXIST, ENOENT, ENOTEMPTY, EISDIR,
ENOTDIR, EINVAL for a rename into its own subtree, ENAMETOOLONG, EFBIG, ENOSPC past a bound —
and the model is not asked about those (`decision=protocol_refusal`). A write event carries the
offset, length, size before, and the first 512 bytes as text when they are text and as hex
otherwise (`encoding` says which, `data_truncated` whether there is more). Every event carries
the requesting pid, uid, gid and process name (`/proc/<pid>/comm`).

Writes are decided per kernel write request, which is up to 128 KiB (`max_write`): `cp` of a
300 KiB file is one create and three writes. With a static or script handler that costs no
model call; with a model it is one round trip each, which is the price of "every change is a
decision" and is said in `metadata().notes`.

**The overlay is not storage in the forbidden sense.** Accepted writes are pages over the
described content (4 KiB each, counted against `max_overlay_bytes`), created entries and symlink
targets are nodes in the same in-memory tree, and all of it is discarded at unmount. Nothing
touches a disk, nothing outlives the mount, and nothing is kept that the model did not accept.
It is the state a filesystem holds between a `write` and the next `read`, the same choice the
NVMe/TCP and iSCSI targets make for a writable namespace or LUN. The `read_only` parameter
exists for an operator who wants none of it.

## Requests that wait, and the deadline

fuser's one session thread answers everything it can from the tree. A request that needs the
model — an undescribed directory, or any change — is put on a bounded queue (`MAX_PENDING`, 64;
past it the request is EBUSY at once, `decision=fail_closed_saturated`) for the mount's one
worker task, which handles them in order. Every request carries the time it arrived; its
deadline is that plus `decision_timeout_secs`, and it covers both the wait in the queue and the
model call (`tokio::time::timeout_at`). The kernel waits on us — a process doing I/O on the mount
is blocked until the daemon answers — so this is what guarantees the process an errno, never a
hang.

| Outcome | errno | `decision=` |
|---|---|---|
| allowed and applied | success | `model_answer` |
| refused by the model | its errno | `model_reject` |
| refused before asking | the POSIX errno | `protocol_refusal` |
| deadline passed (queue or call) | EIO | `fail_closed_deadline` |
| backend failed | EIO (EAGAIN when overloaded) | `fail_closed_llm_error` |
| no answer | EIO | `model_silent` |
| wrong or broken answer | EIO | `fail_closed_invalid_reply` |
| queue full | EBUSY | `fail_closed_saturated` |
| read-only mount | EROFS | `read_only` |

Batching is **`Unsupported`**: every kernel request owes its own correlated reply (an errno or a
result for that one request), which is the case `AGENTS.md` says never to batch. History is
**`Last(SESSION_HISTORY_ENTRIES)`**: the mount is registered as the server's one connection, so
the model sees the recent descriptions and decisions on this mount when it decides the next —
"you allowed /notes/a.txt to be created a moment ago" is exactly the context a write to it needs.

## Bounds

65 536 entries in the tree, 4096 in a directory and 16 384 in one answer; names of 1–255 bytes
without `/` or NUL; 64 directories deep (`MAX_TREE_DEPTH`, enforced by the description walk —
iterative, so a nested answer cannot recurse — by mkdir and by rename); files up to 1 GiB; 16
MiB of described text and hex over the whole mount; symlink targets of 4095 bytes; the overlay;
128 KiB per write request; 64 waiting requests; three description attempts per directory. A
description that breaks any of them is refused whole before anything is committed.

## Stopping

`stop_server` aborts the worker task, which owns the mount guard. Dropping it runs `fusermount3
-u`, then `fusermount3 -u -z` if the mount is busy (lazy: it leaves the tree at once and goes when
the last process lets go), closes the auto_unmount socket, and removes a mount point it created.
The session thread ends by itself when the kernel ends the connection. If the process dies
instead — SIGKILL, a crash, `std::process::exit` — no destructor runs, but the descriptor closes,
the connection aborts, and the `fusermount3` that mounted it (still running, watching the socket)
sees the mount return ENOTCONN and unmounts it. Either way the mount point is an ordinary empty
directory again and `ls` of its parent never hangs.

FIFOs, sockets and device nodes are names with a type and a device number: the kernel serves
a FIFO's or socket's I/O itself, and the mount is `nodev` (fusermount3 forces it for a user
mount), so a device node made here cannot be opened through it.

## Not implemented

Hard links (EPERM: every node has one parent and one name, which is what makes a path in an
event unambiguous), extended attributes (none are listed; setting one is ENOTSUP), byte-range locks beyond
the kernel's local ones, fallocate, `RENAME_EXCHANGE` and `RENAME_WHITEOUT` (EINVAL), and
notifications to the kernel (nothing is ever invalidated from this side, because nothing changes
without a request). macOS and every other platform (see above).

## Evidence, and why there is no pcap oracle

pjdfstest, as root on Linux 7.2 (aarch64) in a rootless container: **198 of its 238 test files
pass in full, 6854 subtests ok and 1944 not ok.** Every remaining failure is one of four things:
hard links (`link/*`, and the `rename`/`unlink` cases that count links), block and character
device nodes (the kernel refuses `mknod` of a device to root in a user namespace, so every case
that makes one fails there, and its follow-on assertions with it; a real root, as in CI, can),
`open/25.t`'s 2 GiB `pwrite` (files are bounded at 1 GiB), and `unlink/08.t`'s POSIX TODO. Two
defects it found are fixed: a lookup of a name longer than 255 bytes answered ENOENT instead of
ENAMETOOLONG, and a file unlinked while open still reported one link.


There is no wire: the kernel's FUSE driver talks to the daemon over `/dev/fuse`, so no dissector
exists to read it and none is invented. The independent peer is the kernel itself, driven by
coreutils, findutils, Python and pjdfstest — NetGet's own code is nowhere on the reading side.
`tests/server/fuse/AGENTS.md` lists what each test pins. The description parser has a fuzz
target, `fuzz/fuzz_targets/fuse_tree_description.rs`, with a depth-bomb corpus.

## Maturity

Experimental. The kernel peer is measured on Linux 7.2 (aarch64) in the podman VM, unprivileged
through fusermount3 and as root; in CI the peers run only in the `fuse` pair job, which had not
run when this landed, so the rating waits for it.
