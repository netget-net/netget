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
| `a_read_only_mount_refuses_changes_without_asking` | `read_only`: `cat` works; `touch`, `rm`, `mkdir` and a write are EROFS with no model call |
| `stop_unmounts_even_while_the_mount_is_busy` | a shell whose working directory is in the mount; stop unmounts (lazily) and the mount point is an empty directory again, its parent lists at once; a mount point the server created is removed |
| `a_killed_daemon_leaves_no_mount_behind` | `netget --server fuse` in a child process, SIGKILLed once mounted: fusermount3's auto_unmount removes the mount, `ls` of the parent answers at once, the mount point is an empty directory |

## `pjdfstest_test.rs` — the compliance suite

pjdfstest's C suite (pinned commit, `scripts/test-peers/build-pjdfstest.sh`), every test file run
with `prove -v` under its own two-minute deadline from inside a mount with `allow_other` and a
static allow-everything handler, as root. It prints the whole table with each failing file's first
`not ok` lines, and fails if a file hangs or any file in `MUST_PASS` stops passing in full —
198 of 238, measured in a rootless container on Linux 7.2; see `src/server/fuse/AGENTS.md` for
what the other 40 fail on. It needs perl and openssl (`openssl md5` names its files).

## Running

```bash
# The tree tests, anywhere:
./cargo-isolated.sh test --test server -- server::fuse::tree_test
# Everything, on Linux with fuse3 (pjdfstest as root, with NETGET_PJDFSTEST set):
cargo test --no-default-features --test server -- fuse:: --test-threads=4
```

In CI the `fuse` job in `.github/workflows/protocol-pairs.yml` runs the suite twice: as the
runner user (the unprivileged fusermount3 path, pjdfstest skipped) and as root (everything).
