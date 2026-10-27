# FUSE server tests

No LLM anywhere: a python script handler (`tools_test::POLICY`) or static handlers play the
model, and the LLM endpoint is unreachable, so an event nothing covers exercises the fail-closed
path. LLM calls: zero.

The peer is the Linux kernel's FUSE driver. Everything that reads or changes the mount is a
separate process — coreutils, findutils, `sh`, Python, pjdfstest — run through `support::Mounted::sh`
with `$M` the mount point; never a `std::fs` call on the test's own runtime, because a process
doing I/O on the mount blocks until the daemon in this same process answers. Every Linux test
uses `#[tokio::test(flavor = "multi_thread")]` and a timeout on every subprocess, and prints the
mount table's FUSE lines, the tail of `dmesg` and the daemon's own log (every `decision=` line)
when it fails (`support::OnFailure`).

They fail, never skip, when `/dev/fuse` or `fusermount3` is missing (`apt-get install fuse3`,
`modprobe fuse`), and the pjdfstest test fails when `NETGET_PJDFSTEST` is unset or it is not
root.

**macOS: CI only.** The macOS suites mount through FUSE-T, which is an NFS mount, and Apple's NFS
client can panic the whole machine under attribute churn (`nfs_vinvalbuf2: ubc_msync failed!,
error 22`; FUSE-T issue #109, Apple FB23527406). Exploring this backend panicked the development
Mac once. So `support::require_fuse` on macOS **fails** unless `NETGET_FUSE_MACOS_CI=1`, which only
the `fuse-macos` pair job sets, on a throwaway VM; then it requires FUSE-T installed (`brew install
--cask macos-fuse-t/cask/fuse-t`). The two registry sweeps that would start the FUSE example
(`startup_examples_actually_start_test`, `examples`) skip `fuse` on macOS without the same
variable, saying why. To run anything else of this suite locally on a Mac, also export
`FUSE_NFSSRV_PATH=/nonexistent/go-nfsv4`: the dependency gate then refuses every FUSE start, so
nothing can mount even by mistake. On failure the macOS diagnostics print the mount table, the
last lines of FUSE-T's log (`~/Library/Logs/fuse-t/fuse-t.log`, where go-nfsv4 logs each mount,
its negotiated profile and each unmount) and any kernel panic report.

## `tree_test.rs` — the described tree, on every Unix

`src/server/described_tree.rs` without a kernel: a nested and lazy description served without
asking again (text, hex, fill, extents, failing regions, symlinks, owners, modes, times); broken
answers refused whole with nothing committed (duplicate, invalid and over-long names, unknown
kinds, size below its text, extents without a size, text and hex together, files over 1 GiB,
unknown errnos, empty symlink targets, mode bits past 07777); 4096 entries per directory and 16
MiB of described text and hex; the depth bound inline (63 nested directories allowed, 64 refused,
a 120-level bomb refused by the walk's count) and lazily (described one level per answer down to
64, refused below, mkdir refused below); three failed descriptions then EIO for good, a refused
one its errno; writes across pages over described bytes, overwriting a failing region, growth
with zero gaps, truncate shrinking then growing (inside a written page too), EFBIG; the overlay
cap (ENOSPC, rewriting a page costs nothing, a refused write and symlink change nothing, unlink
frees); create, rmdir, unlink and rename following POSIX (EEXIST, ENAMETOOLONG, ENOTEMPTY,
ENOTDIR, EISDIR, EINVAL into its own subtree, RENAME_NOREPLACE, replacing); an unlinked file
readable until its last release with no links left; FIFOs and device nodes; setattr changing only what it names; errno names round trip.

## `tree_links_test.rs` — hard links, xattrs, fallocate and exchange, on every Unix

The same tree without a kernel. Hard links: one inode under several names, a write through one
read through another, `nlink` across link, rename (one name moves, the count stays; a rename onto
another name of the same inode does nothing), unlink (the first name gives way to the next; the
inode goes with its last name), a rename replacing one name, the open-but-unlinked case with
every name gone (readable, `nlink` 0, no link back to it, gone at the last release); EPERM for a
directory, EEXIST, ENAMETOOLONG, ENOTDIR, symlinks and FIFOs linkable; `MAX_LINKS` (EMLINK) and
`MAX_HARD_LINKS` (ENOSPC); described hard links before and after their target, nested, and from
a later lazy description; broken ones refused whole (missing, undescribed, a directory, another
hard link, relative, `..`, extra keys, no target, 1025 names); `remove_subtree` keeping a file
linked from outside it. Exchange: file and directory, across directories, ENOENT, EINVAL into
its own subtree, two names of one inode, hard-linked names following the swap. Xattrs: described
on files, directories, symlinks and the root (top-level `xattrs`), shared by hard links;
XATTR_CREATE/XATTR_REPLACE; names (255 bytes, ERANGE past it, EOPNOTSUPP outside the three
namespaces, EINVAL empty); values (64 KiB, E2BIG past it); 128 per node (ENOSPC, replacing still
fine); the 16 MiB tree budget for sets and descriptions; removal and unlink freeing bytes;
broken descriptions refused whole. fallocate: the mode bits, allocate with and without
KEEP_SIZE (pages reserved, `st_blocks`, writes into them free), punch over described bytes
(zeroes, size kept, costs pages), over a failing region, past the end, over written pages (whole
pages given back), zero range with and without KEEP_SIZE, EFBIG, EINVAL, EISDIR, and the overlay
cap refusing each mode with nothing changed. And HDFS, which shares the tree: its own
description check refuses hard links and xattrs that the tree alone would take.

## `links_xattrs_test.rs` — ln, setfattr, fallocate and renameat2 through the kernel

One mount, the policy in `POLICY`. Hard links: a described hard link (`stat` shows one inode, two
links), `ln` (one `fuse_link` with `existing_path` and `links`), `find -samefile` listing all
three names, a write through one name read through the others, `mv` and `rm` of one name keeping
the inode and counting down, a refused `ln` (EPERM) adding nothing, `ln` of a directory and onto
an existing name refused by the kernel without a model call, and Python opening a file, removing
every name and reading it through the open descriptor with `st_nlink` 0. Xattrs: `getfattr -d
-e hex` of described attributes on a file, its hard link and the root (no model call to read);
`setfattr` set, replace (`replaces`), refused (EACCES) and removed (allowed, refused, and absent
without asking); `user.*` on a symlink refused by the kernel; Python's `os.setxattr` with
XATTR_CREATE (EEXIST the second time) and XATTR_REPLACE (ENODATA when missing) answered by the
tree without a model call, a 64 KiB value and a 255-byte name accepted, 64 KiB + 1 (E2BIG) and
256 bytes (ERANGE) refused by the kernel, a foreign namespace EOPNOTSUPP, libc `getxattr` and
`listxattr` through ctypes with a short buffer (ERANGE), a size query and a missing name
(ENODATA), and the 129th attribute on one file ENOSPC; `trusted.*` and `security.*` set where
the kernel lets this process (real root; root of the namespace owning the mount) and refused by
the kernel without a model call where it does not. fallocate: `fallocate` mode 0, `-n`, `-p`
over described bytes and `-z` with and without `-n` (the bytes compared, one `fuse_fallocate`
each with its operation, offset, length and keep_size), `-c` and `-i` EOPNOTSUPP, a refused one
(ENOSPC) allocating nothing, and Python's `os.posix_fallocate`. Exchange: Python `renameat2`
through ctypes swapping two files and a file with a directory, ENOENT, EEXIST with NOREPLACE,
a refused exchange (EACCES) changing nothing, RENAME_WHITEOUT (EINVAL from the tree, without asking the model)
and EXCHANGE|NOREPLACE (EINVAL from the kernel), one `fuse_rename` with `exchange` for
each that reached the tree.

## `tools_test.rs` — ordinary tools and Python

One mount, the policy in `POLICY`: `ls -la` (one description, for `/`), `stat` (size, mode,
type, mtime), `cat`, `dd` and `head -c` at offsets, `sha256sum` against the bytes the
description implies, a failing region (`head` reads the good page, `cat` gets EIO), `readlink`
and `cat` through a symlink, `find` (the lazy `/src` described when visited, the inline `/docs`
never asked about, the refused `/locked` asked once and refused every time after), and nothing
but descriptions asked while reading. Python's `os.walk`/`os.lstat`/`open`/`os.readlink` in a
separate process reads the same tree. Then the changes, each asserted on the tool's side and on
the model's: `cp` out byte for byte; `cp` in (one `fuse_create`, three 128 KiB `fuse_write`
decisions with offsets, lengths, hex previews, pid and process), `cmp` and `sha256sum` against
the source; `mv` (one `fuse_rename` with `new_path`); `mkdir`/`rmdir`; `ln -s`/`readlink`;
`chmod` (the mode in the event); `truncate` shrinking and growing; refused writes (EACCES on
an existing file, ENOSPC on a new one) leaving content, size and the overlay's free blocks
unchanged; `rm`; and stop unmounting.

## `bounds_test.rs` — failure, bounds and unmounting

| Test | What it pins |
|---|---|
| `an_unreachable_model_is_eio_promptly_and_three_attempts_at_most` | no handler and no backend: `ls` is EIO at once, five times, with three description attempts and then none; `stat` of the root needs no model; a change in a failed directory is EIO unasked; `decision=fail_closed_llm_error` |
| `a_slow_model_is_eio_at_the_deadline_and_changes_nothing` | a handler slower than `decision_timeout_secs` 2: a description and a write are EIO after about two seconds, the file unchanged, `decision=fail_closed_deadline` |
| `an_endless_tree_stops_at_the_depth_bound` | a static handler describing every directory with another inside: `find` finds 64 files and an EIO, nothing deeper than depth 64 is asked about, at most three attempts at the 65th |
| `too_many_entries_in_one_answer_are_refused_whole` | a 4097-entry answer is EIO, nothing from it visible |
| `the_overlay_cap_is_enospc_and_removal_frees_it` | `max_overlay_bytes` 1 MiB: `dd` of 2 MiB stops at exactly 1 MiB with ENOSPC, `stat -f` free blocks 0, one more byte refused, `rm` frees all 256 blocks, a new 512 KiB write succeeds |
| `fallocate_past_the_overlay_cap_is_enospc_and_changes_nothing` | `max_overlay_bytes` 1 MiB: `fallocate` of 2 MiB and a 2 MiB punch over described bytes are ENOSPC with no model call, the size, blocks and bytes unchanged; exactly 1 MiB fits, after which a write needing a new page is ENOSPC and a write inside the reserved range is not; `rm` frees it |
| `every_new_decision_fails_closed_without_a_model` | no handler for changes and no backend: `ln`, `setfattr`, `setfattr -x`, `fallocate` (allocate and punch) and a `renameat2` exchange are each EIO with nothing changed and `decision=fail_closed_llm_error` logged for each |
| `a_read_only_mount_refuses_changes_without_asking` | `read_only`: `cat` works; `touch`, `rm`, `mkdir` and a write are EROFS with no model call |
| `stop_unmounts_even_while_the_mount_is_busy` | a shell whose working directory is in the mount; stop unmounts (lazily) and the mount point is an empty directory again, its parent lists at once; a mount point the server created is removed |
| `a_killed_daemon_leaves_no_mount_behind` | `netget --server fuse` in a child process, SIGKILLed once mounted (death-tied through `child_guard` until then): the watchdog removes the mount within 20 s, `ls` of the parent answers at once, the mount point is an empty directory. On failure it prints the mount table, every fusermount3 and watchdog process, fusermount3's version, the dmesg tail and any AppArmor/FUSE journal lines, then lazily unmounts what was left |

## `macos_tools_test.rs` — BSD userland and Python through FUSE-T (CI only)

The Linux tools test's policy and tree, read and changed with what a Mac has: `ls -la`, `stat -f`
(size, mode, type, mtime), `cat`, `dd` and `head -c` at offsets, `shasum -a 256` against the
described bytes, `find` (the lazy `/src` described when visited, the inline `/docs` never asked
about, the refused `/locked` asked once), `readlink`, Python's `os.walk`; and that reading asked
nothing but descriptions. Attributes stand still: `stat -f '%i %z %m %c %l'` of files, a
directory and the root, three times a second apart, prints the same each time. Then the changes,
each asserted on the tool's side and the model's: `cp` out byte for byte; `cp` in (a create and
writes of at most 128 KiB adding up to the file, `cmp` and `shasum`, `uid` the caller's and `pid`
0, which is all NFS carries); `mv` (one rename, the inode kept); `mkdir`/`rmdir`; `ln -s`; `ln`
(one inode, two links, one `fuse_link`); `chmod`; `truncate` shrinking and growing; refused writes
(`dd` gets EACCES or ENOSPC — at `close`, when the client writes back — and each was one
decision; what `cat` shows afterwards is printed, not asserted, because it is the NFS client's
cache); `xattr -w` refused cleanly (EPERM or ENOTSUP) with no setxattr decision and no `._` create
reaching the model; `rm`; and stop unmounting. Differences from Linux it pins: a file with a
failing region is EIO for `cat` (the client reads 128 KiB at a time, so `head -c 4` cannot read the
good first page as on Linux).

## `macos_bounds_test.rs` — failure, read-only, stopping, dying, and FUSE-T missing

| Test | What it pins |
|---|---|
| `an_unreachable_model_is_eio_promptly_on_macos` (CI) | `ls` EIO at once, at most three description attempts, `stat` of the root needs no model, a change in a failed directory EIO unasked, `decision=fail_closed_llm_error` |
| `a_slow_model_is_eio_at_the_deadline_on_macos` (CI) | `decision_timeout_secs` 2: a description and a write (at `close`) EIO after about two seconds, `decision=fail_closed_deadline` |
| `a_read_only_mount_refuses_changes_without_asking_on_macos` (CI) | `touch`, `rm`, `mkdir` and an append are EROFS (FUSE-T's `-r`), no change put to the model |
| `stop_unmounts_even_while_the_mount_is_busy_on_macos` (CI) | a shell whose working directory is in the mount; stop unmounts within 20 s, the parent lists, the mount point the server made is gone |
| `a_killed_daemon_leaves_no_mount_behind_on_macos` (CI) | `netget --server fuse` SIGKILLed once mounted (death-tied through `child_guard`): the mount is gone within 45 s, `ls` of the parent answers at once, the mount point is an empty directory; on failure the mount table, FUSE-T's log and panic reports |
| `a_missing_fuse_t_is_refused_at_startup_naming_the_cask` (anywhere) | `FUSE_NFSSRV_PATH` at a file that does not exist: netget exits non-zero with `Cannot start FUSE server: Program … must be installed. Install FUSE-T: brew install --cask macos-fuse-t/cask/fuse-t`, nothing created, nothing mounted |

## `pjdfstest_test.rs` — the compliance suite

pjdfstest's C suite (pinned commit, `scripts/test-peers/build-pjdfstest.sh`), every test file run
with `prove -v` under its own two-minute deadline from inside a mount with `allow_other` and a
static allow-everything handler, as root. It prints the whole table with each failing file's first
`not ok` lines, and fails if a file hangs or any file of the floor that applies stops passing in
full: `MUST_PASS` (203 of 238, measured as root in a rootless container on Linux 7.2, where the
kernel refuses device nodes) everywhere, plus `MUST_PASS_WITH_DEVICE_NODES` (32 more: 235 of 238,
measured as real root in a rootful container) where a probe `mknod` of a block device outside the
mount succeeds, as it does under CI's sudo. See `src/server/fuse/AGENTS.md` for what the last
three fail on. It needs perl and openssl (`openssl md5` names its files).

On macOS (CI only, through FUSE-T, as root through sudo) the same test runs the suite and prints
the table and a `pjdfstest (macOS, FUSE-T): N/238 files pass in full` line; there is no macOS floor
until repeated runs show which files pass reliably, so it asserts only that the suite ran and that
no file hung.

## Mutation-checked

Each of these was broken on purpose and the suite went red: calling the model without
`timeout_at` (the slow-model test: `ls` hung 20 s and then succeeded); removing the description
walk's depth check (the depth tests, inline and endless); removing the overlay cap (both overlay
tests); dropping the guard's unmount (the stop test and the tools test's final stop); and
applying a write whatever the model answered (the refused writes in the tools test and the
deadline test); and not starting the unmount watchdog (the killed-daemon test, run as an
unprivileged user on Ubuntu 24.04's fuse3 3.14, where the mount outlived the process).

**macOS, in CI.** `scripts/test-peers/fuse-macos-mutation.sh` breaks one mechanism, runs the
test meant to catch it, requires it to fail and restores the file: the unmount on stop
(`no-unmount-on-stop`, the busy-stop test), a model refusal applied as an allow
(`refusal-ignored`, the tools test), a failed or late decision applied as an allow (`fail-open`,
the slow-model test), and the watchdog (`no-watchdog`, the killed-daemon test) — run
`--informational`, because go-nfsv4's own cleanup on its stream closing may unmount without it,
and whether it does is the finding. Locally, without mounting: dropping the `ProgramAt`
declaration from `get_dependencies` turns the missing-FUSE-T test red (the refusal then comes from
`spawn()`'s preflight in other words).

## Running

```bash
# The tree tests, anywhere:
./cargo-isolated.sh test --test server -- server::fuse::tree_test
# Everything, on Linux with fuse3 (pjdfstest as root, with NETGET_PJDFSTEST set):
cargo test --no-default-features --test server -- fuse:: --test-threads=4
```

In CI the `fuse` job in `.github/workflows/protocol-pairs.yml` runs the suite twice: as the
runner user (the unprivileged fusermount3 path, pjdfstest skipped) and as root (everything). The
`fuse-macos` job does the same on `macos-15` with FUSE-T 1.2.9 installed from its pinned package,
then the mutation checks, and prints FUSE-T's log, the mount table and any panic report at the
end.

```bash
# On a Mac, only what does not mount (the tree tests and the refusal), with every FUSE start refused:
FUSE_NFSSRV_PATH=/nonexistent/go-nfsv4 cargo test --no-default-features --test server -- \
  server::fuse::tree server::fuse::macos_bounds_test::a_missing_fuse_t
```
