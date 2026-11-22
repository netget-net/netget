# Building, the installed binary, and disk

> Moved out of the root `AGENTS.md` on 21 November 2026, which now holds only the rules and
> a pointer here. The text is as it was written, so "this file" and "this section" mean
> the root file as it then was; dated claims are dated for a reason — re-derive before
> trusting one.

Contents: `cargo-isolated.sh` and clippy · reclaiming disk from agent worktrees ·
`target/` filling the disk · the installed binary, the `gpu` crash, the panic log and the
crash restorer · system libraries.

`./cargo-isolated.sh` wraps cargo with sccache, disabled incremental, stable path remapping,
and automatic logging. Despite the name it now uses the **shared `target/` directory** —
concurrent runs from different sessions contend on the same lock, so serialize your builds.

Logs land in `./tmp/netget-<command>-<PPID>.log`; the path is printed on each run.

```bash
./cargo-isolated.sh --print-last                     # whole log
./cargo-isolated.sh --print-last | grep "error\[E"   # all compile errors at once
./cargo-isolated.sh --print-last | grep -B2 -A5 "^error:"
./cargo-isolated.sh --print-last | grep -A5 "FAILED"
```

**Fix every error in one pass.** Builds cost 10s-2min; rebuilding after each individual fix
wastes hours. Build once, extract the full error list from the log, fix all of it, rebuild once.

Every build compiles every protocol, so there is no faster single-protocol build. What
features change is the system libraries: `--no-default-features --features mcp-stdio,sqlite`
builds without libpcap, D-Bus, libusb, PC/SC, libsmbclient and llama.cpp (no cmake), which is
the build to use where those are not installed. Narrow a *test run* with filters
(`--test server -- server::tcp::`), not features.

Kill stuck builds with `./cargo-isolated-kill.sh`, never `pkill cargo`.

**Write the clippy lint groups qualified: `-D clippy::correctness`, not `-D correctness`.** The
bare form is deprecated and rustc says so:

```
warning: lint name `correctness` is deprecated and may not have an effect in the future
```

"May not have an effect" is the part that matters — a local check written the bare way can go
quiet without failing, and then a finding CI would block on reads as clean on the machine where
the code was written. CI already uses the qualified form in both its clippy jobs; this file's own
table did not, which is how several passes in this repository ran the deprecated one.

```bash
cargo clippy --all-targets -- -D clippy::correctness -D clippy::suspicious
```

`--all-targets` is not optional either: without it the ~200 test files are outside the gate.

## Reclaiming disk: agent worktrees are where the space is, and pruning them has a trap

`/Users/matus/dev/cargo-clean-all.sh` walks `~/dev`, runs `cargo clean` on every Rust project,
**and** reclaims `.claude/worktrees/*/target` — which is usually the bigger half. Measured
16 September 2026: 52 GiB across 23 worktrees in 8 repos, against which the top-level projects
were a rounding error. `--prune` additionally removes a worktree whose branch is merged.

Two things about that worth keeping:

- **`git worktree remove` keeps the branch.** Only the working copy goes, so nothing committed
  is lost and the commits stay reachable. That makes worktree directories the cheapest large
  reserve on the machine, and nobody reclaims them.
- **Check for a live process before removing one, not just that the branch is merged.** During a
  full-disk recovery a worktree was pruned while a `cargo fuzz` run from it was still going. The
  binary was already mapped, so it survived — orphaned at PPID 1, burning half a core for **five
  hours** against a corpus directory that no longer existed, while the same session was
  investigating load-sensitive test flakes on a machine it had quietly oversubscribed.

- **And `pgrep -f` on the path is not that check.** The script's `worktree_is_busy` used it
  alone, and it was measured on 16 September 2026 against **six agents demonstrably building in
  their worktrees**: it matched **none** of them. An agent runs `cargo` after cd-ing in, so the
  absolute path never appears in any command line, and a compile is mostly rustc children
  invoked with relative paths. The guard read as a safety net and was close to a no-op — which
  is the same class as the ratchets in this file that counted a token instead of the thing.

  It now also treats a worktree as busy when its own, its `target/`'s or its `.git`'s mtime is
  within `WORKTREE_ACTIVE_MINUTES` (default 60). Recency is what actually tracks activity. Two
  notes if you write the check by hand: `find -newermt '-60 minutes'` is **not** portable — BSD
  find does not parse the relative form and silently matches nothing, failing open — so compare
  `stat -f %m` (BSD) or `stat -c %Y` (GNU) against `date +%s`. And "merged" is trivially true of
  a branch with no commits on it, so a freshly created agent worktree reads as merged; only the
  recency signal distinguishes it from an abandoned one.

- **Err toward leaving it alone.** Being wrong in that direction costs disk. Being wrong the
  other way destroys work in progress, and the machine is routinely running half a dozen agents.

## `target/` will fill the disk, and it fails in a way that wastes an hour

**Watch `df` during any session that builds several different feature sets.** `target/debug/deps`
reached **130 GB in 27,587 files** in one session here — Cargo never garbage-collects test
binaries from feature permutations, and each `--all-features` test binary links the whole
136-protocol library. Pruning by age does not help: ~17,000 of those files were from that day.
`cargo clean --profile dev` is the remedy, and it keeps `target/release`.

Two things make this expensive rather than merely annoying:

- **It does not present as a disk problem.** The first symptom was a linker line buried in a
  19,000-line log — `ld: write() failed, errno=28 (No space left on device)` — after which the
  sweep reported `exit code 0` having run **zero** tests. An earlier sweep in the same session
  produced 18 "failures" that were pure artefacts. **A sweep that reports no `test result` lines
  did not run; check the log tail before believing any count.**
- **At literally zero bytes free you cannot recover in-session.** Every tool call needs to write
  its output file, so `df`, `ls` and `cargo clean` all fail with ENOSPC and the only way out is
  the operator freeing space by hand. Leave headroom rather than discovering the floor.

## The installed binary — `/Users/matus/bin/netget`

The maintainer's `netget` on `PATH` lives at `/Users/matus/bin/netget` and **must always have every
protocol compiled in.** That is the default feature set, release — **NOT `--all-features`** (see
the footgun below). After any change that adds a protocol or affects the compiled surface,
rebuild and reinstall:

```bash
./cargo-isolated.sh build --release && \
  cp target/release/netget /Users/matus/bin/.netget.new && \
  mv -f /Users/matus/bin/.netget.new /Users/matus/bin/netget   # atomic; safe if netget is running
```

**Check that the binary answers `--mcp`.** Until September 2026 this command built
`all-protocols` without `mcp-stdio`, which produced a binary answering `--mcp` with `Error: MCP
STDIO mode requires the 'mcp-stdio' feature` — exactly how the maintainer runs it. MCP is in the
default set now, but nothing would catch its removal: the build succeeds, the binary starts, and
only the one invocation that matters fails. Smoke-test the installed binary over its own MCP
surface rather than trusting `--version`:

```bash
printf '%s\n%s\n%s\n' \
 '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"smoke","version":"1"}}}' \
 '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
 '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"list_protocols","arguments":{}}}' \
 | timeout 45 /Users/matus/bin/netget --mcp 2>&1 | head -c 300
```

The atomic `mv` matters: the maintainer runs `netget --mcp` interactively, and overwriting the
file in place can fail with `ETXTBSY` while it is running. Rename swaps the inode instead — the
live process keeps the old image, the new binary takes effect on next launch. **Never kill the
running `netget` to install** — the rename never needs it stopped.

**`--all-features` vs the default — they are NOT interchangeable.** `--all-features` is a Cargo
built-in that turns on *every* feature in `Cargo.toml`: the default set plus **`gpu`** (GPU stats
via `gfxinfo`), `vendored-openssl` and the test-only `terminal-snapshot`. The default is the
curated "everything, and only things safe to run" set — it includes `embedded-llm` (dormant
unless `--embedded-model` is passed) but **not** `gpu`. Use `--all-features` for a compile check
(`cargo check --all-features`) and the default for a binary you run.

**The `gpu` crash this section used to describe is fixed, and the description of it was wrong in
every detail worth acting on.** It said the feature "initializes a Metal context at startup" that
crashes "the instant the TUI renders". It is not Metal and not startup: `gpu` pulls in `gfxinfo`,
whose macOS `MacGpuInfo::load_pct()` over-releases a `CFDictionary`, and the extra `CFRelease`
raises `EXC_BREAKPOINT`/SIGTRAP inside CoreFoundation. `SystemStatsMonitor::get_stats` is the only
caller and the since-removed rolling TUI was the only caller of *that*, on a one-second interval —
so the crash landed a second or two **after** the first paint, only there, and never in the
dashboard. `src/system_stats.rs` now compiles the `gfxinfo` call out on macOS
(`cfg(all(feature = "gpu", not(target_os = "macos")))`) and reports `N/A`, which is what the
operator saw anyway wherever the stat was unsupported. Linux and Windows are unaffected.

The stack is worth keeping because it is not catchable: the crash is inside a `Drop`, so there is
no fallible call to wrap and `catch_unwind` cannot see it. It surfaced only because
`tests/terminal_snapshot` is the one suite that *runs the TUI*, and only once those tests were
pointed at the rolling TUI — before that they exercised the dashboard and never touched the path.

**Every panic is logged, as of September 2026** (`src/panic_log.rs`), installed from
`init_logging` so it covers `--mcp`, `--mcp-http` and the non-interactive runner as
well as the TUI, and chaining to whatever hook it replaced so the dashboard's terminal-restore
still runs. Before it, a panic inside `tokio::spawn` was written **nowhere** — nothing awaits a
connection task's `JoinHandle`, so the `JoinError` carrying the panic was dropped, which is why
all three historical instances were found by reading code rather than by grepping. If you see
"the server stays Running and the peer hangs", `grep PANIC netget.log` now answers it.

The TUI installs a native-crash terminal restorer (`src/cli/crash_restore.rs`): a
SIGSEGV/SIGABRT/SIGTRAP from a C/ObjC library bypasses Rust's `Drop`/panic machinery, so without it
a crash leaves the shell wedged in raw mode. The handler restores cooked mode + cursor before the
process dies. It is a safety net, not a licence to ship a crashing binary — fix the crash too.

## System libraries, and what builds without them

Detect Claude Code for Web with `./am_i_claude_code_for_web.sh` or
`[ "$CLAUDE_CODE_REMOTE" = "true" ]`. The default features link five system libraries, each
behind a feature of its own; derive the current list from `[features]` rather than this copy:

| Feature | Library (Debian / Homebrew) | Protocols |
|---|---|---|
| `libpcap` | `libpcap-dev` / ships with macOS | `arp`, `datalink`, `isis`, `lldp`, `cdp`, `stp`, `eapol` |
| `bluetooth` | `libdbus-1-dev` / CoreBluetooth ships with macOS | all `bluetooth-ble*` |
| `pcsc` | `libpcsclite-dev` / ships with macOS | the NFC client |
| `libusb` | `libusb-1.0-0-dev` / `libusb` | the `usb-*` virtual devices |
| `libsmbclient` | `libsmbclient-dev` / `samba` | the SMB client |

`embedded-llm` (default) builds llama.cpp and needs `cmake`, a C++ compiler and libclang (bindgen;
`libclang-dev` / `clang-devel` / `clang`, Xcode's command-line tools on macOS). The protobuf
compiler is **not** a requirement any more: `build.rs` uses `protoc-bin-vendored` unless
`PROTOC` names one.

```bash
# Everything that needs no system library
./cargo-isolated.sh build --no-default-features --features mcp-stdio,mcp-http,sqlite
```
