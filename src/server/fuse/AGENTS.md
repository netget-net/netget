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

**Hard links in a description** are entries of `kind: "hardlink"` whose `target` is the absolute
path, from the mount's root, of a file (or symlink, FIFO, ...) described in the same answer or
in an earlier one: `{"name": "README.copy", "kind": "hardlink", "target": "/README.txt"}`. The
two names are then one inode — one content, one mode, one set of xattrs, `nlink` 2. A hard link
carries nothing but `name`, `kind` and `target` (everything else belongs to the inode, so a
`mode` or `text` on one is refused rather than silently ignored); it may not name a directory,
another hard-link entry, or a path into a directory nobody has described yet (resolving it must
never ask for a description). A path was chosen over an inode label because it is what the
model already uses for everything, and because it lets a lazily described directory link to a
file described long before. HDFS shares the tree and has no hard links, so its own description
check refuses `hardlink` entries (and `xattrs`), keeping its namespace exactly as it was.

**Extended attributes** ride on any entry (not a hard link) as `xattrs: [{name, text | hex}]`,
and a description's top-level `xattrs` are the described directory's own — the only way to give
the root any. Names are in `user.`, `trusted.` or `security.`; a value with neither key is empty.

**Every change is one decision**: `fuse_create` (open with O_CREAT; mknod, mkfifo and bind,
with `kind` saying file, fifo, socket, char or block),
`fuse_write`, `fuse_truncate` (a setattr with a size), `fuse_setattr` (chmod, chown, utimes),
`fuse_mkdir`, `fuse_unlink` (with `links`, the names the file has), `fuse_rmdir`,
`fuse_rename` (with `exchange` for RENAME_EXCHANGE), `fuse_symlink`, `fuse_link` (with
`existing_path` and `links`), `fuse_setxattr` (name, value previewed like a write's, `mode`
create / replace / create_or_replace, `replaces`), `fuse_removexattr`, `fuse_fallocate`
(`operation` allocate / punch_hole / zero_range, `keep_size`, offset, length). Each is answered
`fuse_allow` (applied to the overlay; the process gets success) or `fuse_deny` with an errno
(EACCES, EPERM, EROFS, ENOSPC, EDQUOT, …; the process gets it and nothing changes). Rust checks
first what the kernel and POSIX would refuse anyway — EEXIST, ENOENT, ENOTEMPTY, EISDIR,
ENOTDIR, EINVAL for a rename into its own subtree, ENAMETOOLONG, EFBIG, ENOSPC past a bound —
and the model is not asked about those (`decision=protocol_refusal`). A write event carries the
offset, length, size before, and the first 512 bytes as text when they are text and as hex
otherwise (`encoding` says which, `data_truncated` whether there is more). Every event carries
the requesting pid, uid, gid and process name (`/proc/<pid>/comm`).

**What the kernel decides before the tree does.** `link` of a directory, `user.*` on a symlink
or special file, `trusted.*` without CAP_SYS_ADMIN in the initial user namespace, `security.*`
without it in the namespace that owns the mount, values over 64 KiB (E2BIG) and names over 255
bytes (ERANGE), COLLAPSE_RANGE and INSERT_RANGE, and a rename
that asks for both EXCHANGE and NOREPLACE never reach the daemon (measured, see the tests).
What does reach it and is refused by the tree without asking: XATTR_CREATE on an existing
name (EEXIST), XATTR_REPLACE or removal of a missing one (ENODATA), a namespace other than the
three (EOPNOTSUPP), a 129th attribute or the 16 MiB budget (ENOSPC), a 1025th name (EMLINK),
a fallocate mode other than the four (EOPNOTSUPP), one past the overlay cap (ENOSPC) or the file
bound (EFBIG), RENAME_WHITEOUT (EINVAL; the kernel has let any process ask since Linux 5.8). `getxattr` and `listxattr` are answered
from the tree on fuser's thread at no model cost: a size of 0 gets the length, a buffer too
small gets ERANGE, a missing name ENODATA.

**Hard links in the overlay.** A node keeps its first name (`parent`, `name`, which every event
path uses) and its further names (`links`). Unlinking or renaming any one name moves only that
record; unlinking the first promotes the next. `nlink` is the number of names. The inode goes
with its last name — unless it is open, in which case it lives nameless with `nlink` 0 until the
last release, as before. A rename onto another name of the same inode does nothing (POSIX);
exchanging two names of one inode does nothing either.

**fallocate in the overlay.** Mode 0 and KEEP_SIZE reserve the range as overlay pages (a page
holding what the file shows there), so a later write into it costs nothing and cannot fail for
space; without KEEP_SIZE the file grows to cover it, and `st_blocks` counts reserved pages past
the end. PUNCH_HOLE|KEEP_SIZE makes the range read as zeroes: a whole page with nothing described
beneath gives its overlay page back, any other page in the range needs one (zeroed where the
range covers it) to hide the described bytes, so punching a described file costs overlay.
ZERO_RANGE (with or without KEEP_SIZE) zeroes and reserves. Every mode counts its new pages
against `max_overlay_bytes` first and is ENOSPC, changing nothing, if they do not fit.

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
128 KiB per write request; 64 waiting requests; three description attempts per directory; 1024
names per file (`MAX_LINKS`, EMLINK) and 65 536 hard links over the tree (`MAX_HARD_LINKS`,
ENOSPC); extended-attribute names of 255 bytes, values of 64 KiB, 128 per node and 16 MiB of
names and values over the tree (`MAX_XATTR_BYTES`, ENOSPC). A description that breaks any of
them is refused whole before anything is committed.

## Stopping

`stop_server` aborts the worker task, which owns the mount guard. Dropping it runs `fusermount3
-u`, then `fusermount3 -u -z` if the mount is busy (lazy: it leaves the tree at once and goes when
the last process lets go), closes the auto_unmount socket, and removes a mount point it created.
The session thread ends by itself when the kernel ends the connection. If the process dies
instead — SIGKILL, a crash, `std::process::exit` — no destructor runs, but the descriptor closes
and the connection aborts. Two things then unmount it:

- **The watchdog** (`spawn_watchdog`): `sh` in a session of its own, running as this user,
  blocked reading a pipe whose only writer is this process. The read returns at end of file
  when the process is gone and it execs `fusermount3 -u -z`. A normal stop unmounts first and
  kills the watchdog before closing the pipe, so it never unmounts anything later.
- **fusermount3's own `auto_unmount`**, which works only on fuse3 3.17 and later. Before that
  (Ubuntu 24.04 ships 3.14) its check runs as root and opens the mount point to see whether the
  daemon died; a mount without `allow_other` answers root EACCES rather than ENOTCONN, so the
  check concludes the daemon is alive and leaves the dead mount. CI's first run of the `fuse`
  job found exactly that, and it reproduces in an Ubuntu 24.04 container as an unprivileged
  user with the watchdog disabled; 3.18 added `recheck_ENOTCONN_as_owner` for it.

Either way the mount point is an ordinary empty directory again and `ls` of its parent never
hangs.

FIFOs, sockets and device nodes are names with a type and a device number: the kernel serves
a FIFO's or socket's I/O itself, and the mount is `nodev` (fusermount3 forces it for a user
mount), so a device node made here cannot be opened through it.

## Not implemented

`RENAME_WHITEOUT` (EINVAL: it is overlayfs's marker for a deleted lower entry, which this tree
has no notion of), POSIX ACLs (`system.posix_acl_*` is EOPNOTSUPP; the mount does not ask the
kernel for ACL support), fallocate's COLLAPSE_RANGE, INSERT_RANGE and UNSHARE_RANGE
(EOPNOTSUPP; the kernel's FUSE driver does not send the first two at all), byte-range locks
beyond the kernel's local ones, copy_file_range and lseek SEEK_DATA/SEEK_HOLE (the kernel falls
back to reads and writes), and notifications to the kernel (nothing is ever invalidated from this
side, because nothing changes without a request). macOS and every other platform (see above).

## Evidence, and why there is no pcap oracle

pjdfstest on Linux 7.2 (aarch64), measured twice because the result depends on whether the
kernel lets root make device nodes. **As real root (a rootful container, as CI's sudo is): 235 of
its 238 test files pass in full, 8786 subtests ok and 12 not ok.** The three left are
`open/25.t`'s 2 GiB `pwrite` (files are bounded at 1 GiB) and pjdfstest's own `# TODO` cases in
`chown/00.t` and `unlink/08.t`, which the tally counts as failures. **As root in a rootless
container: 203 pass in full**; the 32 more are every file that makes a block or character
device, which the kernel refuses to root in a user namespace (and every follow-on assertion
with it). The test holds both floors and probes which applies. Hard links were worth five files
there (`link/02`, `03`, `06`, `07`, `09`) and the rest of `link/`, `rename/` and `unlink/` once
devices can be made. The C suite has no extended-attribute tests. Two defects it found earlier
are fixed: a lookup of a name longer than 255 bytes answered ENOENT instead of ENAMETOOLONG,
and a file unlinked while open still reported one link.

There is no wire: the kernel's FUSE driver talks to the daemon over `/dev/fuse`, so no dissector
exists to read it and none is invented. The independent peer is the kernel itself, driven by
coreutils, findutils, attr, util-linux, Python (`os` and libc through `ctypes`) and pjdfstest —
NetGet's own code is nowhere on the reading side. `tests/server/fuse/AGENTS.md` lists what each
test pins. The description parser has a fuzz target, `fuzz/fuzz_targets/fuse_tree_description.rs`,
with depth-bomb, hard-link-bomb and xattr-bomb corpus entries; it also checks that every
non-directory's link count equals the names it is listed under and that unlinking one name of a
file with several keeps the inode.

## Maturity

Experimental. The kernel peer is measured on Linux 7.2 (aarch64): unprivileged through
fusermount3 in the podman VM (Fedora, fuse3 3.18) and in a rootful Ubuntu 24.04 container (fuse3
3.14), as root in a rootless container and as real root. In CI the peers run only in the `fuse`
pair job, so the rating waits for that job's verdict on its kernel.
