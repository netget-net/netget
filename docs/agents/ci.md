# CI: what runs, what blocks, and what a green run does not say

> Moved out of the root `AGENTS.md` on 21 November 2026, which now holds only the rules and
> a pointer here. The text is as it was written, so "this file" and "this section" mean
> the root file as it then was; dated claims are dated for a reason — re-derive before
> trusting one.

`release.yml` builds every target's binaries on release tags and manual dispatch: macOS with the
`libpcap`, `bluetooth` and `pcsc` features (their libraries ship with the OS); plain glibc Linux,
musl and Windows with no system-library feature (these are what npm ships, so they must start on
a minimal system); and separate glibc Linux `-full` archives with those three features, built
after installing the `-dev` packages. A step asserts each glibc binary's linked libraries: the
plain ones nothing beyond glibc and zlib, the `-full` ones exactly those plus libpcap, libdbus-1
and libpcsclite.
`docs/guides/INSTALL.md` is the per-artifact table users read; keep it, the matrix and the
`Dockerfile` in step.
`ci.yml` runs on pull requests and on demand. **A push to `master` does not start CI.**
`fuzz.yml` remains an on-demand search.
`docker.yml` publishes the `Dockerfile` as the multi-arch image `ghcr.io/netget-net/netget` on
release tags (`X.Y.Z` and `latest`) and on manual dispatch (`-f tag=<tag>`, default `latest`):
amd64 and arm64 each build on a native runner and push by digest, a final job joins them with
`imagetools create`, checks both platforms are listed and runs `--version` on the pulled image.

**Local verification is the evidence for routine work.** Before pushing Rust changes, run
`cargo fmt --check`, relevant regressions and the affected server/client suites with their
required independent peers installed. A missing peer or zero matching tests is missing
evidence. Run clippy over all targets with qualified lint groups:

```bash
./cargo-isolated.sh clippy --locked --no-default-features \
  --features mcp-stdio,mcp-http,sqlite,terminal-snapshot --all-targets \
  -- -D clippy::correctness -D clippy::suspicious
```

For shared declarations or infrastructure, run the applicable whole-tree ratchets and
resource/lifecycle regressions from `.github/workflows/ci.yml`. Use `scripts/test_batches.sh`
for broader top-level sweeps so test executables do not fill the disk. Serialize local builds
as described below. Compile affected fuzz targets in their separate workspace. For browser
changes, run the wasm shim tests, `./web/build.sh`, the Node smoke tests, and the applicable
browser fixture. For site-only work use `site/AGENTS.md` checks. Report the commands and
results, including failures and checks not exercised; local native checks do not establish
Windows, Linux-kernel, or browser coverage they did not run.

Keep the normal commit, merge, and push flow. After a direct `master` push, absent CI is
expected: do not wait for a nonexistent automatic run or treat an older green SHA as evidence
for the new commit. Pushing does not authorize dispatching workflows.

**Run hosted validation only when the user requests it or as part of explicitly authorized
release validation.** Do not dispatch after every task to recreate the removed automatic
workload. The default manual run uses the core PR checks; `extended=true` also selects
`clippy-wide`, `registry-audit`, and `smb-evidence`. `clippy-wide` is advisory;
`registry-audit` and `smb-evidence` are blocking when selected (`registry-audit` keeps a
named set of advisory evidence groups inside it, described below the table). For automatic PR checks, inspect the run for the PR's current
head commit rather than an older green result. For an authorized hosted run, push the intended
commit, dispatch against its branch or tag, and verify the resulting run's `headSha` equals
that intended commit before using the result:

```bash
gh workflow run ci.yml --ref <branch> -f extended=false
gh run list --workflow ci.yml --event workflow_dispatch --branch <branch> \
  --json databaseId,headSha,status,conclusion,url
gh run view <run-id> --json headSha,status,conclusion,url
```

`protocol-pairs.yml` (the third-party interoperability jobs) runs only by hand or when
`release.yml` calls it before publishing; it no longer runs on every push or pull request.
Its `only` input runs a single job by id — `gh workflow run protocol-pairs.yml --ref <branch>
-f only=<job>` — which is how a requested check validates a new or changed pair without the
other hundred. The jobs marked *manual* below run only on a requested manual dispatch of
`ci.yml` with `extended=true`; a default manual dispatch runs the core PR checks.

| Job | Blocking | What it does |
|---|---|---|
| `lint` | yes | Formatting and correctness/suspicious clippy lints over the library and every compiled test target |
| `test` | yes | Six jobs: every top-level test target split five ways (`eval::probe_check::` skipped — it drives each eval protocol's real client), and the `CI_PROTOCOL_TESTS` suites (tcp, http, dns, udp, redis, finger) out of `tests/server` and `tests/client`; every protocol compiles, only those run |
| `ratchets` | yes | Whole-tree source checks, server/client Beta evidence declarations, fuzz target compilation |
| `smb-evidence` | yes, *manual* | The SMB server suite, including bounds, both independent clients, and the packet oracle |
| `wasm-web` | yes | Browser bundle build and smoke exchanges |
| `orphaned-tests` | yes | Fails if a test directory on disk is undeclared in `mod.rs` |
| `clippy-wide` | **no** (`continue-on-error`), *manual* | Clippy with the default features, the system-library protocols included |
| `registry-audit` | yes, *manual* (advisory evidence groups inside it) | Registry audits and all-feature real-client/server evidence, with their external peers installed |

`registry-audit` compiles `--all-features` once and runs everything from those binaries. The
registry audits, the evidence compilation, the **blocking evidence groups** and the Nostr
Chromium exchange fail the job. The **advisory evidence groups** run in a separate
`continue-on-error` step from the same binaries, each listed in `ci.yml` with the reason it
cannot block:

| Advisory group | Why |
|---|---|
| `redis::resp3_test`, `redis::pubsub_test`, `redis::cluster_test`, `redis::keys_oracle_test`, `client/redis::cluster_real_server_test` | Peer too old: ubuntu-22.04 ships Redis 6.0.16 (no `cluster-port`, a different `redis-cli -3` transcript). All five pass, blocking, in `Test (suites)` on ubuntu-24.04 with Redis 7 |

The split was measured: every blocking group, the audits and the browser exchange passed in
all 30 runs between 2026-10-15 and 2026-10-29 that reached the evidence loop, except
`client/nats::e2e_test` (26 of 30), whose failures were its own broker dying of SIGPIPE on a
closed stderr pipe; it starts `nats-server` through `RealServer` and blocks. Every group has
a five-minute limit and must run at least one passing test; a peer whose install step fails
surfaces as its group's failure. The Beta evidence table step is a report, not a verdict, and
stays `continue-on-error` (its blocking half is `--check` in `ratchets`). The summary step runs
after any failure or interruption, publishes both tiers and the blocking step outcomes, uploads
the logs as the `real-client-evidence` artifact, and fails the job when any blocking part did
not pass — including a blocking loop cut off before it finished. **A green `registry-audit` job
means every blocking group passed; it says nothing about the advisory groups**, which are in
the run summary. Promote an advisory group to the blocking list once its cause is fixed and it
has passed on the runner. SMB's Stable evidence has a separate blocking job.

Derive the current job list from `.github/workflows/ci.yml` instead of trusting a remembered
count (matrix shards create multiple job executions):

```bash
python3 -c "import yaml; d=yaml.safe_load(open('.github/workflows/ci.yml')); \
  [print(k, 'advisory' if v.get('continue-on-error') else 'BLOCKING') for k,v in d['jobs'].items()]"
```

**There is no per-feature build check any more, because there are no protocol features.** It
used to exist because a protocol that compiled only alongside others went unnoticed: `tor` did
not compile *at any feature set* in September 2026 while every CI run was green. With every
protocol in every build, `lint` and `test` compile all of them on PRs or authorized manual runs;
the system-library protocols are compiled by `clippy-wide` and `registry-audit`, which install
those libraries.

**Putting a check on a nightly cron is the wrong shape**, and the distinction generalises to
anything else you are tempted to move off the commit: `fuzz`, `nightly-soak` and
`nightly-eval` are *searches and measurements*, which return no verdict about any particular
commit and so suit a nightly cadence. A compile check is a *gate* — it answers yes or no about
the commit in front of it — so it belongs in local validation before pushing and in PR or
authorized CI checks.
Removing automatic master runs does not remove that local compilation requirement.

**In fact none of the three is on a cron any more**: `fuzz.yml`, `nightly-soak.yml` and
`nightly-eval.yml` are all `workflow_dispatch` only, so between dispatches nothing runs them at
all. Dispatch them only when requested, after changing the surface they cover. That is the right cadence for
a search, but it has a cost worth knowing, because `fuzz.yml`'s own header records paying it:
`coap_message.rs` stopped compiling hours after it was written and stayed broken for weeks,
while the Stable bar's "a fuzz target exists and has run clean" was being satisfied by a target
that could not build. The fix was not to put the search on a cron — it was to have `ratchets`
do `cargo check --manifest-path fuzz/Cargo.toml --all-targets` on every PR. **Separate the
search from the check it depends on, and gate the check.**
