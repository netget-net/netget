# Working beside other agents: the git incidents, and the git rules

> Moved out of the root `AGENTS.md` on 21 November 2026, which now holds only the rules and
> a pointer here. The text is as it was written, so "this file" and "this section" mean
> the root file as it then was; dated claims are dated for a reason — re-derive before
> trusting one.

## Multi-instance collaboration

Assume other agents work in this repo concurrently.

- **Never `git add -A`, `git add .`, `git add -u`, or `git commit -a`.** Stage explicit paths
  only — `git add <path> && git commit -m …`, listing every file. This is not style: a broad
  `git add` sweeps up whatever other agents have half-written, and a half-written change
  committed without its other half breaks `master` for everyone.

  It has happened three times. Twice it broke the build: once landing a caller without its
  callee (`CertificateCache::new` gaining a third argument in `proxy/mod.rs` while
  `proxy/cert_cache.rs` stayed uncommitted), once landing 24 import swaps without the module
  they imported. The third time, a `git add -u` intended for a documentation cleanup swept
  fourteen source files from five different agents into a commit titled "docs: remove 46
  one-off session and status reports" — it happened to compile, but the history now
  misattributes that work.

  **`git add -u` counts.** It stages every tracked modification in the tree, which during
  parallel work is everyone's. The `-u` flag reads as narrower than `-A` and is not.

- **Staging explicit paths is NOT enough — pass the paths to `git commit` too.** This is the
  fourth incident and the subtlest: `git add <paths> && git commit -m ...` stages what you
  listed and then commits **the whole index**, including anything another agent staged and had
  not yet committed. In August 2026 that swept a *deletion* of `src/server/usb/smartcard/crypto.rs`
  — staged by an agent mid-edit — into an unrelated BGP-client commit, leaving HEAD referencing
  a module whose file was gone. It took a follow-up revert to repair.

  Use the pathspec form, which commits only those paths regardless of what else is staged:

  ```bash
  git add <paths> && git commit <paths> -m "..."     # or: git commit -- <paths>
  ```

  And check before you commit, because the index is shared state:

  ```bash
  git diff --cached --name-only     # must list only your files
  ```

- **The pathspec form protects against a dirty INDEX, not a dirty WORKING TREE — and for a
  shared file that distinction is the whole problem.** `git commit <pathspec>` commits the
  *working-tree* content of those paths. So if another agent has `Cargo.toml` mid-edit and you
  name `Cargo.toml`, you commit **their uncommitted hunks along with yours**. Three agents hit
  this independently in one session, on `Cargo.toml`, both registries and both test `mod.rs`
  files. The rule above reads as complete protection and is not.

  For a file only you touched, the pathspec form is fine. For a **shared** file, rebuild its
  blob from `HEAD` plus only your own lines and stage that, leaving the working tree alone so
  the other agent's edits survive:

  ```bash
  # HEAD-based patch of just your hunks, applied to the index only
  git diff HEAD -- <shared-file> > /tmp/mine.patch   # then edit down to your hunks
  git apply --cached /tmp/mine.patch
  git diff --cached --name-only    # must list only your files
  git diff --cached -- <shared-file>   # must show only your lines
  git commit -m "..."              # no pathspec: the index is already exactly right
  ```

  `git hash-object` + `git update-index --cacheinfo` achieves the same thing when the file is
  easier to reconstruct than to patch. Either way, **verify `git diff --cached` before
  committing** — that is the only step that actually catches the mistake.

- **Even the patch-the-index method races, because the index is shared. Under heavy concurrency,
  commit through a PRIVATE index.** The fifth incident (August 2026, a wave of ~10 concurrent
  agents): three agents each staged only their own hunks correctly via `git apply --cached`, and
  were *still* swept — because in the window between their staging and their `git commit`, another
  agent's bare `git commit` (no pathspec) committed the whole shared index, carrying the first
  agent's staged files into the second agent's commit. `git diff --cached` was clean when they
  checked it; the race happened after. Several new protocols landed misattributed inside
  unrelated commits this way. It compiled and nothing was lost, but the branch ref also got
  rewound twice, orphaning commits.

  The shared `.git/index` is the contended resource. Give yourself a private one with
  `GIT_INDEX_FILE` so no other agent's commit can see or sweep your staging:

  ```bash
  export GIT_INDEX_FILE=$(mktemp /tmp/idx-<your-task>.XXXX)
  git read-tree HEAD                      # seed the private index from HEAD
  git add -- <your paths>                 # stages into the PRIVATE index only
  git diff --cached --name-only           # must list only your files
  T=$(git write-tree)
  C=$(git commit-tree "$T" -p HEAD -m "feat(x): ...")   # GPG: add -S
  git update-ref refs/heads/master "$C" HEAD            # CAS: fails if master moved — then retry
  unset GIT_INDEX_FILE
  ```

  Two cautions. (1) `commit-tree`+`update-ref` is the one legitimate use of `update-ref` — but it
  must be a compare-and-swap against the `HEAD` you built on (the third arg), so it *fails* rather
  than clobbering if master advanced; on failure, re-read HEAD and rebuild. Never `update-ref`
  without the old-value CAS argument — an unconditional one is the force-move that got flagged as a
  security violation. (2) This only serializes *your* commit's atomicity; it does not order you
  against other agents. When two agents both target `master`, the CAS makes the loser retry — which
  is correct. If your harness gives each agent its own **worktree** (separate `.git` index and
  working tree both), that is strictly better and none of this is needed — prefer it for any agent
  expected to commit under contention. But worktrees branched from a stale base still cost a
  re-apply for anything touching hot central files (`action_helper.rs`, the `CommonAction` enum,
  `executor.rs`), so isolation moves the cost from *corruption* to *merge*, it does not remove it.
- **Shared files** (`Cargo.toml`, both registries, `server/mod.rs`, `client/mod.rs`, both test
  `mod.rs` files, `state/server.rs`): use `Edit`, add incrementally, never overwrite wholesale.
- **Give scratchpad files a name unique to you.** Two agents independently wrote `mod.rs.bak`
  into the shared session scratchpad; one clobbered the other, and restoring "the" backup put
  one protocol's source into another protocol's file. Prefix every scratch file with your task.
- **Never revert a dirty working-tree file you did not demonstrably write** — no
  `git checkout -- <path>`, `git restore`, or overwrite to "tidy up" an edit that looks
  half-finished. You cannot tell your own abandoned work from another agent's work in progress,
  and the tree is routinely mid-edit for several agents at once. An unverified edit left in the
  tree is a far smaller problem than deleted work. This happened: a batch of subagents died
  mid-task leaving three modified files, and the reflex to restore a clean tree wiped edits that
  may not have been theirs. They survived only because `git diff > patch` had been run first.
  If you truly must clear a path, save `git diff -- <path>` to a uniquely named scratch file
  **first** and say so — but prefer leaving it alone and reporting it.
- **Don't fan out a large agent wave while the API is failing.** If agents start returning
  "stalled" or the tool-permission classifier times out, stop and wait instead of launching the
  next slice. Three waves were attempted during one degraded period and burned **~9.8M tokens to
  return 5 usable results**; the dead agents also left half-written files in the shared tree for
  someone else to trip over.

  Two diagnoses that looked obvious and were both **wrong**, recorded so they are not re-tried:
  (1) *a cold `target/` making agents queue on the build lock* — warming the cache first changed
  nothing; (2) *agents blocking >180s inside `cargo check` with no output* — a rewritten wave that
  forbade cargo entirely still lost 28 of 29 agents. The stall is in the agent infrastructure, not
  in what the agents were asked to do, so **rewriting the task does not rescue it — only waiting
  does.** The tell is uniformity: when nearly every agent dies with the same "no progress for
  180000ms" on all 6 retries while one or two trivial ones succeed, that is the platform, not the
  prompt.
- **Pause and report** if you hit an error in code you did not modify. It is almost always
  another agent mid-edit; retry rather than "fixing" their file.
- **Verify HEAD, not the working tree.** During parallel work the working tree is routinely
  mid-edit and its failures belong to nobody. Check the committed state in a throwaway
  worktree: `git worktree add --detach <tmp> HEAD && cargo check --all-features` with its own
  `CARGO_TARGET_DIR`. Remove the worktree afterwards.
- **`--ollama-lock` does nothing, and its plumbing is now gone.** The flag is parsed into
  `Args::ollama_lock` and **read by nothing**. It used to be threaded through six hops that each
  made it look implemented — `AppState::new_with_options`'s second parameter, the
  `ollama_lock_enabled` field, `get_ollama_lock_enabled()`, `create_llm_client(args,
  lock_enabled)` and `OllamaClient::new_with_options(url, lock_enabled)`, whose body was
  `Self::new(base_url)` under a comment saying locking is "handled at a different layer". Nothing
  in `src/` was that layer and no `ollama.lock` was ever created. All six are deleted; the flag
  stays accepted and inert so `--ollama-lock` in an existing script is not a hard clap error.
  The harness no longer passes it — it used to go to *every* spawned binary, which is why the
  whole e2e suite looked as though it serialised LLM access across processes. **Don't reason
  about concurrency from it**: `--llm-max-concurrent`, `--llm-queue-timeout` and
  `--llm-max-queued` are the real bounds. `tests/ollama_lock_is_a_noop_test.rs` fails if the old
  claims come back, if an `ollama.lock` appears, or if anything in `src/` reads the field again.
- Concurrent `git` work should use worktrees.
- **Do not run a full sweep while anything else is building.** `tests/examples` and
  `tests/terminal_snapshot` *spawn `target/debug/netget`*, and `target/` is shared with every
  other agent and with your own narrow-feature builds. A concurrent build replaces that binary
  mid-run, and the sweep then reports things like `Protocol 'SOCKS5' exists but is not compiled
  into this build` for protocols that are in fact compiled, or hangs a pty snapshot test. Those
  are contention artefacts, not regressions — check for other `cargo test` processes before
  believing a binary-spawning failure.
- Never `pkill cargo`; use `./cargo-isolated-kill.sh`.
- The user runs `netget --mcp` interactively. **Never kill netget processes.**

## Git

- Never `git stash`. Always merge with `--no-ff`. Never amend, rebase, or squash shared history.
- **Pushing to `origin` is pre-authorised in this repository — always push.** Do not stop to ask,
  and do not leave work sitting unpushed: an unpushed branch is invisible to requested CI runs, to cloud agents
  (which clone from GitHub, not from this machine), and to everyone else working here. This once
  reached **249 unpushed commits**, which silently made a scheduled cloud routine useless because
  the work it was sent to continue did not exist on the remote.
  Push after landing a logical change, i.e. at the same points "Commit as you go" describes:
  ```bash
  git push origin master
  ```
  The standing authorisation covers `master` and your own branches. It does **not** extend to
  force-pushing, deleting remote branches, or rewriting published history — those still need
  asking, because they destroy other people's work rather than publishing yours.
- Combine `git add` and `git commit` in one command chain.
- Commit as Matus Faro <matus@matus.io>, GPG-signed:
  ```bash
  git config user.name 'Matus Faro' && git config user.email 'matus@matus.io' && \
  git config commit.gpgsign true && git config user.signingkey matus@matus.io
  ```
- Conventional Commits, one logical change per commit. No co-author or bot attribution
  trailers of any kind.
- **Write the message to a file and use `git commit -F`, not `-m`.** The Bash tool runs zsh, so
  a backtick inside a `-m` string is command substitution: `` `checked` `` runs `checked`, the
  shell prints "command not found", **the commit still succeeds**, and the word is silently
  missing from the message. It happened once in September 2026 and is unfixable afterwards,
  because amending is forbidden here. Backticks are natural to reach for when naming a
  variable, which is exactly why this bites. A heredoc into a scratch file costs nothing:
  ```bash
  cat > /tmp/<your-task>-msg.txt <<'MSG'
  fix(x): ...
  MSG
  git add -- <paths> && git commit -S -F /tmp/<your-task>-msg.txt -- <paths>
  ```
  Note the quoted `<<'MSG'` delimiter — unquoted, the heredoc expands backticks too.
- **Commit as you go.** Land each logical change as soon as it is verified, rather than
  accumulating a large uncommitted tree and committing at the end. Other agents are editing this
  repo continuously: a big working tree is a merge hazard, it is what broad `git add` sweeps pick
  up, and an interrupted session loses all of it. Verify, commit, continue.
- **Verify against a clean baseline, not against "does it pass".** The suite has pre-existing
  failures, so a red run proves nothing on its own. Run the same suite at unmodified `HEAD` in a
  throwaway worktree and **diff the two failure sets** — only the difference is yours. This is
  what separates a real regression from the repo's existing red.
  **Cross-check any suspect failure by re-running it in isolation before calling it a
  regression.**

  **But do not stop there, because "load-flaky" is where real bugs hide.** Both suites are
  now green at `--test-threads=100` — client 299/0, server 799/0, several consecutive runs
  each — and every test that used to be on a list here of things that "only fail under load"
  is on it because of a defect that was found and fixed, not because the list was wrong to
  notice them. Passing in isolation told us the *deadline* was wrong; it did not tell us the
  code was fine, and three times it was not:

  - The four `doh` **client** tests failed every run at 100 threads and passed at 30. Not
    timing: raising the wait from 10s to 30s changed nothing. `Client::builder().build()`
    loads the platform root store, which on macOS reads the keychain through
    Security.framework — synchronously, serialised across processes. On the async runtime it
    parked a tokio worker long enough to stall the client's whole runtime. The tell was a
    configured 10s request timeout that never fired: a timeout that *cannot* fire means the
    future was never created.
  - `ServerForm::create` failing with "Address already in use" for `port: 0` — in zookeeper
    one run, cassandra the next. Different protocol each time, which is what gave it away:
    the shared startup path resolved port 0 by binding a probe listener and dropping it
    before the protocol bound for real.
  - Whole e2e suites waited with a fixed `sleep` and then verified. One second is enough
    alone and not when a hundred run together. `wait_for_any` and `wait_for_mocks` on the
    harnesses wait for the condition instead; every e2e suite now calls one before asserting.

  A protocol whose e2e test binds sockets and waits on a mocked model *is* timing-sensitive by
  construction, so a lone failure in a 100-thread run is still unproven until re-run. Re-run
  it — and if it reproduces at all, find the defect rather than labelling it.
